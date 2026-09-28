//! The AWS provider (#195, T7): the `aws` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent, the
//! same shape as the Hetzner module.
//!
//! Flow per ADR-0045 (mint-and-inject, Decision 1/6): mint the worker host
//! keypair coordinator-side → render the shared cloud-init template →
//! `run-instances` with that user-data (`--user-data file://`, the
//! authenticated API channel that carries the private half) → describe for
//! the public IPv4 → pin address + public half into the managed `workers`
//! block. The pin exists BEFORE first use; `ssh-keyscan` is never called.
//!
//! Spot (#195 scope, opt-in): `--spot` bids a `--max-price` cap through
//! `--instance-market-options`. The interruption behavior is pinned to
//! `terminate` and the type to `one-time` — an eviction is T5 WORKER LOSS
//! (ADR-0040 Amendment 1): the farm re-dispatches the lost job, and no
//! mid-flight migration exists or will exist here; `stop`/`hibernate`
//! would pretend a machine survives that does not. A
//! `shuttle-worker-spot` tag names the eviction class on the instance.
//! On-demand hourly (per-second billing) is the default; spot is for
//! eviction-tolerant lanes only (providers plan §1).
//!
//! Region discipline: provision's `--location` IS the region and rides
//! every create-path call as `--region`; destroy resolves the region from
//! the ambient aws CLI configuration (AWS_DEFAULT_REGION / profile),
//! because the destroy verb carries no location — run it under the same
//! region configuration the provision used (instance ids are
//! region-scoped).
//!
//! Order discipline (the Hetzner module's contract): dry-run and every
//! local refusal resolve before ANY API call — credentials ride the
//! environment (the aws CLI convention) and never enter argv, and no
//! partial state survives a failure: instances created before a later
//! failure are terminated, config is appended only after every instance
//! is up. No retries are named by the ticket: a failed step fails the
//! provision and tears the set down; the operator re-runs.

use std::path::Path;

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, mint_host_keypair, now_epoch_secs,
    render_user_data, stage_user_data, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams,
};

/// The worker presence tag shuttle stamps at create time — the key shared
/// with the #269 v2 TTL contract (Hetzner writer, cross-provider
/// vocabulary): presence marks the instance as a shuttle worker. The
/// value is `true` (presence semantics; expiry rides the TTL tag only).
pub const WORKER_TAG: &str = "shuttle-worker";

/// The TTL tag: expiry in EPOCH SECONDS UTC, set AT CREATE — the source
/// of truth of the #269 v2 contract (the in-guest marker is a fallback
/// COPY). The same decimal shape the `shuttle-worker-ttl` hcloud label
/// carries; the sweep's `is_epoch` parses decimal only.
pub const WORKER_TTL_TAG: &str = "shuttle-worker-ttl";

/// The spot tag, present (`true`) only on `--spot` instances: names the
/// eviction class (T5 worker loss, ADR-0040 Amendment 1) so operator-side
/// tooling can tell an interruptible lane from an on-demand one.
pub const WORKER_SPOT_TAG: &str = "shuttle-worker-spot";

/// The base image (providers plan §3, ADR-0046): the LATEST Ubuntu LTS —
/// the contract pins "latest LTS", never a codename — resolved through
/// Canonical's public SSM parameter (the documented EC2 path to the
/// current amd64 AMI for the release; no owner-account guessing, no
/// describe-images wildcard). Bumped on every new LTS, like the Hetzner
/// slug. The overlay is entirely in the shared cloud-init template: stock
/// provider image, no custom AMIs.
pub const UBUNTU_LTS_SSM_PARAMETER: &str =
    "/aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id";

pub struct AwsProvisioner<R: CommandRunner> {
    runner: R,
    /// Where AWS credentials would resolve from (the #271-analog worker
    /// account key, a named profile, or the CLI config file) — `None` is
    /// the no-credentials refusal path, checked before any API call.
    /// The credential itself never enters argv; the aws CLI inherits it.
    credentials: Option<String>,
    /// The pinned shuttle binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at the
    /// CLI boundary (`SHUTTLE_OPERATOR_KEY` / default key halves) so the
    /// core stays env-free under test.
    operator_key: String,
}

impl<R: CommandRunner> AwsProvisioner<R> {
    pub fn new(
        runner: R,
        credentials: Option<String>,
        binary_url: String,
        operator_key: String,
    ) -> Self {
        AwsProvisioner {
            runner,
            credentials,
            binary_url,
            operator_key,
        }
    }

    /// One aws CLI call. `region` rides `--region` when the caller has it
    /// (the create path, from `--location`); `None` (destroy) lets the
    /// CLI resolve the ambient region. Credentials ride the inherited
    /// environment — they never enter argv.
    fn aws(&self, region: Option<&str>, args: &[&str]) -> miette::Result<String> {
        let mut argv = vec!["aws".to_string()];
        if let Some(r) = region {
            argv.push("--region".to_string());
            argv.push(r.to_string());
        }
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("provision: cannot run the aws CLI (is it installed?): {e}")
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "provision: aws {} failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: CommandRunner> Provisioner for AwsProvisioner<R> {
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>> {
        // Local refusals first — every one of them API-free.
        validate_spot(req)?;

        // Local resolution: mint, template, TTL. All of it is API-free,
        // so the dry-run plan is the REAL plan.
        let expiry_epoch = now_epoch_secs()? + req.ttl_secs;
        let expiry_iso = iso8601_utc(expiry_epoch);
        let dir = tempfile::tempdir()
            .map_err(|e| miette::miette!("provision: cannot create the mint scratch dir: {e}"))?;
        let minted = mint_host_keypair(&self.runner, dir.path())?;
        let user_data = render_user_data(&UserDataParams {
            host_private_key: &minted.private_pem,
            host_public_key: &minted.public_line,
            operator_key: &self.operator_key,
            binary_url: &self.binary_url,
            ttl_expiry_epoch: expiry_epoch,
        });
        let user_data_sha256 = crate::oci::sha256_hex(user_data.as_bytes());

        if req.dry_run {
            // Deliberately BEFORE the credentials check: a plan needs no
            // credentials and must make no API call.
            print_plan(&ProvisionPlan {
                server_type: req.server_type.clone(),
                location: req.location.clone(),
                count: req.count,
                image: UBUNTU_LTS_SSM_PARAMETER.to_string(),
                ttl_secs: req.ttl_secs,
                ttl_expiry_iso: expiry_iso,
                binary_url: self.binary_url.clone(),
                spot_max_price: req.max_price.clone().filter(|_| req.spot),
                user_data_sha256,
            });
            return Ok(Vec::new());
        }

        // The aws CLI reads credentials from the inherited environment;
        // they never enter argv. Presence is checked before any API call.
        self.require_credentials()?;

        let user_data_file = stage_user_data(dir.path(), &user_data)?;

        // Resolve the pinned AMI, create + describe; every successfully
        // created instance id (and the address pinned for it) rides
        // `created` so any later failure terminates the whole set.
        let ami = self.resolve_ami(req)?;
        let name = worker_name();
        let tags = tag_spec(req, &name, expiry_epoch);
        let mut created: Vec<(String, String)> = Vec::new();
        let result = self.create_and_pin(
            req,
            &ami,
            &tags,
            &user_data_file,
            &minted.public_line,
            &mut created,
        );
        if let Err(e) = result {
            let mut torn_down = 0usize;
            let mut stuck: Vec<&str> = Vec::new();
            for (id, _) in &created {
                if self
                    .aws(
                        Some(&req.location),
                        &["ec2", "terminate-instances", "--instance-ids", id],
                    )
                    .is_ok()
                {
                    torn_down += 1;
                } else {
                    stuck.push(id);
                }
            }
            if stuck.is_empty() {
                return Err(miette::miette!(
                    "provision: {e:#} — terminated {torn_down} created instance(s), config untouched"
                ));
            }
            return Err(miette::miette!(
                "provision: {e:#} — terminated {torn_down} created instance(s), config untouched; \
                 FAILED to terminate {} — it is still running and billing; terminate it with \
                 'shuttle workers destroy' or by hand",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(id, address)| ProvisionedWorker {
                host_key: pin_with_comment(&minted.public_line, &id),
                name: id,
                address,
            })
            .collect())
    }

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool> {
        self.require_credentials()?;
        let ip = self.instance_public_ipv4(None, name)?;
        // The #269 v2 pre-delete check: attached volumes must not vanish
        // with the instance unnoticed.
        self.warn_attached_volumes(None, name)?;
        // Terminate first: if the call fails the worker is still live and
        // the config pin must stay.
        self.aws(
            None,
            &["ec2", "terminate-instances", "--instance-ids", name],
        )?;
        match evict_worker_entry(config, &address_for(&ip)) {
            Ok(true) => Ok(true),
            Ok(false) => {
                crate::output::warn(format!(
                    "destroy: instance '{name}' terminated, but no managed workers entry pins {} — \
                     config left untouched",
                    address_for(&ip)
                ));
                Ok(false)
            }
            Err(e) => Err(miette::miette!(
                "destroy: instance '{name}' terminated, but the config entry could not be \
                 evicted: {e:#}"
            )),
        }
    }
}

impl<R: CommandRunner> AwsProvisioner<R> {
    fn require_credentials(&self) -> miette::Result<()> {
        if self.credentials.is_none() {
            return Err(miette::miette!(
                "provision: no AWS credentials found (checked AWS_ACCESS_KEY_ID, AWS_PROFILE, \
                 ~/.aws/credentials) — set the dedicated worker-account key (the #271 analog), \
                 never a TOFU_INPUTS credential"
            ));
        }
        Ok(())
    }

    /// The pinned latest-Ubuntu-LTS AMI id from Canonical's public SSM
    /// parameter — fail-closed: anything that is not an `ami-` id is a
    /// named refusal, never a create with a guessed image.
    fn resolve_ami(&self, req: &ProvisionRequest) -> miette::Result<String> {
        let body = self.aws(
            Some(&req.location),
            &[
                "ssm",
                "get-parameter",
                "--name",
                UBUNTU_LTS_SSM_PARAMETER,
                "--query",
                "Parameter.Value",
                "--output",
                "text",
            ],
        )?;
        let ami = body.trim();
        if !ami.starts_with("ami-") {
            return Err(miette::miette!(
                "provision: the SSM parameter {UBUNTU_LTS_SSM_PARAMETER} did not resolve to an \
                 AMI id in {} (got '{ami}') — the region may not carry the parameter; pick a \
                 region that does",
                req.location
            ));
        }
        Ok(ami.to_string())
    }

    /// Create `count` instances, describe each for its public IPv4, then
    /// pin every entry as it is resolved. `tags` is the prebuilt
    /// `--tag-specifications` value (the contract stamps, resolved by the
    /// caller). Records every created instance id in `created` as
    /// teardown-on-failure state — pushed BEFORE the describe, so an
    /// instance that exists but fails its describe is still terminated.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        ami: &str,
        tags: &str,
        user_data_file: &Path,
        public_line: &str,
        created: &mut Vec<(String, String)>,
    ) -> miette::Result<()> {
        let count = req.count.to_string();
        let user_data_arg = format!("file://{}", user_data_file.display());
        let options = req
            .max_price
            .as_deref()
            .filter(|_| req.spot)
            .map(market_options);
        let mut args = vec![
            "ec2",
            "run-instances",
            "--image-id",
            ami,
            "--instance-type",
            &req.server_type,
            "--count",
            &count,
            "--user-data",
            user_data_arg.as_str(),
            "--tag-specifications",
            tags,
        ];
        if let Some(o) = &options {
            args.push("--instance-market-options");
            args.push(o.as_str());
        }
        let body = self.aws(Some(&req.location), &args)?;
        let ids = parse_instance_ids(&body)?;
        for id in &ids {
            // Teardown state FIRST: an instance that exists but fails its
            // describe must still be terminated.
            created.push((id.clone(), String::new()));
            let ip = self.instance_public_ipv4(Some(&req.location), id)?;
            let address = address_for(&ip);
            created.last_mut().expect("just pushed").1 = address.clone();
            append_worker_entry(&req.config, &address, &pin_with_comment(public_line, id))?;
        }
        Ok(())
    }

    /// The instance's public IPv4 from `describe-instances` (JSON via
    /// `--query`). Absent → named refusal with the subnet remedy: the
    /// create never pretends an unreachable worker was provisioned.
    fn instance_public_ipv4(&self, region: Option<&str>, id: &str) -> miette::Result<String> {
        let body = self.aws(
            region,
            &[
                "ec2",
                "describe-instances",
                "--instance-ids",
                id,
                "--query",
                "Reservations[0].Instances[0]",
                "--output",
                "json",
            ],
        )?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("provision: aws describe '{id}' is not JSON: {e}"))?;
        let ip = v["PublicIpAddress"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                miette::miette!(
                    "provision: instance '{id}' has no public IPv4 — the subnet must \
                     auto-assign public IPv4 addresses (or use a region whose default subnets \
                     do); nothing was pinned"
                )
            })?;
        Ok(ip.to_string())
    }

    /// `describe-volumes` filtered on the attachment MUST come back empty
    /// before a terminate. Anything attached gets a loud warning naming
    /// the count — termination does NOT delete volumes whose
    /// `DeleteOnTermination` is false (the root volume's default IS to
    /// delete) — and then the terminate proceeds anyway: the operator
    /// asked for the destruction, the warning exists so data loss is
    /// never silent.
    fn warn_attached_volumes(&self, region: Option<&str>, id: &str) -> miette::Result<()> {
        let body = self.aws(
            region,
            &[
                "ec2",
                "describe-volumes",
                "--filters",
                &format!("Name=attachment.instance-id,Values={id}"),
                "--query",
                "Volumes[].VolumeId",
                "--output",
                "json",
            ],
        )?;
        let v: Value = serde_json::from_str(&body).map_err(|e| {
            miette::miette!("destroy: aws describe-volumes for '{id}' is not JSON: {e}")
        })?;
        let attached = v.as_array().map(Vec::len).unwrap_or(0);
        if attached > 0 {
            crate::output::warn(format!(
                "destroy: instance '{id}' still has {attached} attached volume(s) — termination \
                 does NOT delete volumes with DeleteOnTermination=false; delete them by hand"
            ));
        }
        Ok(())
    }
}

// ── Local refusals and shape helpers ──

/// The spot/price-cap pairing rules (#195): a spot bid without a cap is
/// not a cap; a cap without `--spot` has nothing to cap; the cap itself
/// must parse as a positive finite hourly USD decimal. All API-free.
fn validate_spot(req: &ProvisionRequest) -> miette::Result<()> {
    match (req.spot, &req.max_price) {
        (true, None) => Err(miette::miette!(
            "provision: --spot requires --max-price — an uncapped spot bid is not a price cap; \
             name the hourly USD ceiling the lane may bid"
        )),
        (false, Some(_)) => Err(miette::miette!(
            "provision: --max-price requires --spot — on-demand has no bid to cap"
        )),
        (true, Some(cap)) => {
            let price: f64 = cap
                .trim()
                .parse()
                .map_err(|_| miette::miette!("--max-price must be a decimal USD/h, got '{cap}'"))?;
            if !price.is_finite() || price <= 0.0 {
                return Err(miette::miette!(
                    "--max-price must be a positive finite USD/h, got '{cap}'"
                ));
            }
            Ok(())
        }
        (false, None) => Ok(()),
    }
}

/// The instance `--tag-specifications` value: the Name, the
/// `shuttle-worker` presence tag, the `shuttle-worker-ttl` epoch-seconds
/// EXPIRY (the #269 v2 contract — the source of truth the sweep reads —
/// set AT CREATE), and `shuttle-worker-spot` on spot instances. One argv
/// element, no shell.
fn tag_spec(req: &ProvisionRequest, name: &str, expiry_epoch: u64) -> String {
    let mut tags = vec![
        format!("{{Key=Name,Value={name}}}"),
        format!("{{Key={WORKER_TAG},Value=true}}"),
        format!("{{Key={WORKER_TTL_TAG},Value={expiry_epoch}}}"),
    ];
    if req.spot {
        tags.push(format!("{{Key={WORKER_SPOT_TAG},Value=true}}"));
    }
    format!("ResourceType=instance,Tags=[{}]", tags.join(","))
}

/// The spot `--instance-market-options` value: `one-time` (no reuse wait)
/// and `terminate` on interruption — an eviction is T5 worker loss, never
/// a stop/hibernate that pretends the machine survives.
fn market_options(max_price: &str) -> String {
    serde_json::json!({
        "MarketType": "spot",
        "SpotOptions": {
            "MaxPrice": max_price,
            "SpotInstanceType": "one-time",
            "InstanceInterruptionBehavior": "terminate"
        }
    })
    .to_string()
}

/// `run-instances` (queried to `Instances[].InstanceId`) must answer with
/// the created instance ids; anything else is a named refusal — never an
/// empty success that would skip teardown state.
fn parse_instance_ids(body: &str) -> miette::Result<Vec<String>> {
    let v: Value = serde_json::from_str(body.trim())
        .map_err(|e| miette::miette!("provision: aws run-instances is not JSON: {e}"))?;
    let ids: Vec<String> = v
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() || ids.iter().any(|id| !id.starts_with("i-")) {
        return Err(miette::miette!(
            "provision: aws run-instances returned no readable instance ids ('{}')",
            body.trim()
        ));
    }
    Ok(ids)
}

/// The address shape every provisioned entry carries: the shared template
/// authorizes root (key-only, `PermitRootLogin prohibit-password`), so
/// the login is root on the stock Ubuntu image too, default SSH port.
fn address_for(ip: &str) -> String {
    format!("ssh://root@{ip}")
}

/// The pinned public half: `ssh-keygen`'s line with the instance id as the
/// single comment word (the pin grammar allows at most one) —
/// traceability from a known_hosts/`workers` line back to the EC2
/// resource.
fn pin_with_comment(public_line: &str, id: &str) -> String {
    let mut parts = public_line.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    let key = parts.next().unwrap_or_default();
    format!("{key_type} {key} {id}")
}

/// `shuttle-worker-<hex nanos>` — one batch identity (a `--count` run is
/// one name; the instance ids are the per-machine handles).
fn worker_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("shuttle-worker-{nanos:x}")
}

fn print_plan(plan: &ProvisionPlan) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         aws");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  region:           {}", plan.location));
    crate::output::info(format!("  base image:       {}", plan.image));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    if let Some(cap) = &plan.spot_max_price {
        crate::output::info(format!(
            "  spot max price:   {cap} USD/h (interruption: terminate)"
        ));
    } else {
        crate::output::info("  class:            on-demand");
    }
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  tags:             {WORKER_TAG} + {WORKER_TTL_TAG}=<ttl epoch>"
    ));
}
