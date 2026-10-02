//! The AWS provider (#195, T7): the `aws` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent, the
//! same shape as the Hetzner module.
//!
//! Flow per ADR-0045's amendment (#295): mint a one-time publish token
//! per instance + render the shared cloud-init template (guest-local
//! host keypair generation — NO private half ships) → `run-instances`
//! with that user-data (`--user-data file://`, the authenticated API
//! channel that now carries public material + the one-time bearer only)
//! → describe for the public IPv4 → pin the host CA fingerprint into the
//! managed `workers` block. The pin exists BEFORE first use;
//! `ssh-keyscan` is never called. EC2 user-data is immutable per
//! instance and the one-time token is per machine, so the batch create
//! becomes one `--count 1` create per instance — each with its own name,
//! token, and blob.
//!
//! Spot (#195 scope, opt-in): `--spot` bids a `--max-price` cap through
//! `--instance-market-options`. The interruption behavior is pinned to
//! `terminate` and the type to `one-time` — an eviction is T5 WORKER LOSS
//! (ADR-0040 Amendment 1): the farm re-dispatches the lost job, and no
//! mid-flight migration exists or will exist here; `stop`/`hibernate`
//! would pretend a machine survives that does not. A
//! `nau-worker-spot` tag names the eviction class on the instance.
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

use crate::provision::publish::PublishChannel;
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, now_epoch_secs, render_user_data,
    require_ca_pin, require_publish, PinPlan, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};
use nau_infra::command::{exit_code, CommandRunner};

/// The worker presence tag nau stamps at create time — the key shared
/// with the #269 v2 TTL contract (Hetzner writer, cross-provider
/// vocabulary): presence marks the instance as a nau worker. The
/// value is `true` (presence semantics; expiry rides the TTL tag only).
pub const WORKER_TAG: &str = "nau-worker";

/// The TTL tag: expiry in EPOCH SECONDS UTC, set AT CREATE — the source
/// of truth of the #269 v2 contract (the in-guest marker is a fallback
/// COPY). The same decimal shape the `nau-worker-ttl` hcloud label
/// carries; the sweep's `is_epoch` parses decimal only.
pub const WORKER_TTL_TAG: &str = "nau-worker-ttl";

/// The spot tag, present (`true`) only on `--spot` instances: names the
/// eviction class (T5 worker loss, ADR-0040 Amendment 1) so operator-side
/// tooling can tell an interruptible lane from an on-demand one.
pub const WORKER_SPOT_TAG: &str = "nau-worker-spot";

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
    /// The pinned nau binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at the
    /// CLI boundary (`NAU_OPERATOR_KEY` / default key halves) so the
    /// core stays env-free under test.
    operator_key: String,
    /// The client identity pinned into every workers entry (#298): the
    /// private-key path resolved at the CLI boundary beside
    /// `operator_key` — same env-free posture.
    identity_path: String,
    /// The coordinator publish channel (callback URL + ceremony home) —
    /// `None` is the no-channel refusal path for real runs; a dry run
    /// runs without.
    publish: Option<PublishChannel>,
}

impl<R: CommandRunner> AwsProvisioner<R> {
    pub fn new(
        runner: R,
        credentials: Option<String>,
        binary_url: String,
        operator_key: String,
        identity_path: String,
        publish: Option<PublishChannel>,
    ) -> Self {
        AwsProvisioner {
            runner,
            credentials,
            binary_url,
            operator_key,
            identity_path,
            publish,
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

        // Local resolution first: template, TTL. All of it is API-free,
        // so the dry-run plan is the REAL plan (with placeholder publish
        // slots — the real per-instance blob differs only in token + name).
        let expiry_epoch = now_epoch_secs()? + req.ttl_secs;
        let expiry_iso = iso8601_utc(expiry_epoch);
        let dir = tempfile::tempdir().map_err(|e| {
            miette::miette!("provision: cannot create the staging scratch dir: {e}")
        })?;
        let user_data = render_user_data(&UserDataParams {
            machine_identity: PLAN_MACHINE_IDENTITY,
            publish_url: PLAN_PUBLISH_URL,
            publish_token: PLAN_PUBLISH_TOKEN,
            operator_key: &self.operator_key,
            binary_url: &self.binary_url,
            ttl_expiry_epoch: expiry_epoch,
        });
        let user_data_sha256 = nau_core::cache_key::sha256_hex(user_data.as_bytes());

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
        // they never enter argv. Presence is checked before any API call
        // — the outermost gate, then the fail-closed coordinator-side
        // state: the publish channel (guest callback) and the CA pin the
        // entries will carry.
        self.require_credentials()?;
        let publish = require_publish(&self.publish)?;
        let ca_pin = require_ca_pin(req)?.to_string();
        let pin = PinPlan {
            publish,
            ca_pin: &ca_pin,
            identity: self.identity_path.clone(),
        };

        // Resolve the pinned AMI, create + describe; every successfully
        // created instance id (and the address pinned for it) rides
        // `created` so any later failure terminates the whole set.
        let ami = self.resolve_ami(req)?;
        let mut created: Vec<(String, String)> = Vec::new();
        let result = self.create_and_pin(req, &ami, dir.path(), expiry_epoch, &pin, &mut created);
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
                 'nau workers destroy' or by hand",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(id, address)| ProvisionedWorker {
                host_key: ca_pin.clone(),
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
                nau_infra::output::warn(format!(
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

    /// Create `count` instances — ONE `--count 1` create per instance,
    /// because EC2 user-data is immutable and the one-time publish token
    /// is per machine — describe each for its public IPv4, and pin every
    /// entry as it is resolved. Each instance gets its own machine
    /// identity (its own name), its own one-time publish token (recorded
    /// in the coordinator's registry BEFORE the create — the token must
    /// be enforceable by first boot), and its own user-data blob.
    /// Records every created instance id in `created` as
    /// teardown-on-failure state — pushed BEFORE the describe, so an
    /// instance that exists but fails its describe is still terminated.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        ami: &str,
        staging: &Path,
        expiry_epoch: u64,
        pin: &PinPlan<'_>,
        created: &mut Vec<(String, String)>,
    ) -> miette::Result<()> {
        // EC2 user-data is immutable and the one-time publish token is
        // per machine: every create is `--count 1` (one instance, one
        // name, one token, one blob), `req.count` times.
        let count = "1".to_string();
        let options = req
            .max_price
            .as_deref()
            .filter(|_| req.spot)
            .map(market_options);
        for _ in 0..req.count {
            let name = worker_name();
            let tags = tag_spec(req, &name, expiry_epoch);
            let user_data_file = crate::provision::stage_publishing_user_data(
                staging,
                pin.publish,
                &self.binary_url,
                &self.operator_key,
                &name,
                expiry_epoch,
            )?;
            let user_data_arg = format!("file://{}", user_data_file.display());
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
                tags.as_str(),
            ];
            if let Some(o) = &options {
                args.push("--instance-market-options");
                args.push(o.as_str());
            }
            let body = self.aws(Some(&req.location), &args)?;
            // The blob is served — the one-time bearer in it must not
            // linger on disk past its create call.
            let _ = std::fs::remove_file(&user_data_file);
            for id in parse_instance_ids(&body)? {
                // Teardown state FIRST: an instance that exists but fails
                // its describe must still be terminated.
                created.push((id.clone(), String::new()));
                let ip = self.instance_public_ipv4(Some(&req.location), &id)?;
                let address = address_for(&ip);
                created.last_mut().expect("just pushed").1 = address.clone();
                // The machine-identity linkage rides the pin — the
                // executor's @cert-authority pin binds the certificate
                // principal through it (#295 sub-task 4).
                crate::provision::publish::record_machine_link(&pin.publish.home, &name, &address)?;
                append_worker_entry(&req.config, &address, pin.ca_pin, &pin.identity)?;
            }
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
            nau_infra::output::warn(format!(
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
/// `nau-worker` presence tag, the `nau-worker-ttl` epoch-seconds
/// EXPIRY (the #269 v2 contract — the source of truth the sweep reads —
/// set AT CREATE), and `nau-worker-spot` on spot instances. One argv
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

/// `nau-worker-<hex nanos>` — one name per create; the instance ids
/// remain the per-machine handles (destroy verbs), while the name rides
/// the contract tags and doubles as the machine identity the one-time
/// publish token binds.
fn worker_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("nau-worker-{nanos:x}")
}

fn print_plan(plan: &ProvisionPlan) {
    nau_infra::output::info("provision plan (dry run — no API call was made):");
    nau_infra::output::info("  provider:         aws");
    nau_infra::output::info(format!("  type:             {}", plan.server_type));
    nau_infra::output::info(format!("  region:           {}", plan.location));
    nau_infra::output::info(format!("  base image:       {}", plan.image));
    nau_infra::output::info(format!("  count:            {}", plan.count));
    nau_infra::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    nau_infra::output::info(format!("  binary url:       {}", plan.binary_url));
    if let Some(cap) = &plan.spot_max_price {
        nau_infra::output::info(format!(
            "  spot max price:   {cap} USD/h (interruption: terminate)"
        ));
    } else {
        nau_infra::output::info("  class:            on-demand");
    }
    nau_infra::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    nau_infra::output::info(format!(
        "  tags:             {WORKER_TAG} + {WORKER_TTL_TAG}=<ttl epoch>"
    ));
}
