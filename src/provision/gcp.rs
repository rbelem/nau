//! The GCP provider (#196, T8): the `gcloud` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent, the
//! same shape as the Hetzner and AWS modules.
//!
//! Flow per ADR-0045 (mint-and-inject, Decision 1/6): mint the worker host
//! keypair coordinator-side → render the shared cloud-init template →
//! `instances create` with that user-data (`--metadata-from-file`, the
//! authenticated API channel that carries the private half) → describe for
//! the external NAT IP → pin address + public half into the managed
//! `workers` block. The pin exists BEFORE first use; `ssh-keyscan` is
//! never called.
//!
//! User-data channel (the one T8-text deviation, flagged for review): the
//! ticket's file list says `--metadata startup-script`, but the shared
//! template (#273) is a `#cloud-config` YAML — GCP's `startup-script`
//! metadata key is executed as a SHELL script by the guest environment,
//! where YAML would fail. Cloud-init on the GCE Ubuntu image consumes the
//! `user-data` metadata key, so the template rides
//! `--metadata-from-file user-data=<file>`: the same authenticated channel
//! that carries the private half, and a file hand-off (the blob never
//! enters argv). Same rule as the sibling providers — the shared template
//! is consumed, never forked, and lands on the provider's cloud-init
//! channel (hcloud `--user-datafile`, aws `file://`, gcloud `user-data`).
//!
//! Preemptible (#196, opt-in): `--preemptible` rides `instances create`.
//! An eviction is T5 WORKER LOSS (ADR-0040 Amendment 1): GCP stops the
//! VM, the farm re-dispatches the lost job, and no mid-flight migration
//! exists or will exist here. Preemptible pricing is fixed per machine
//! type — there is no bid to cap, so `--max-price` is refused (aws-only
//! vocabulary). A `shuttle-worker-preemptible` label names the eviction
//! class. On-demand is the default; preemptible is for eviction-tolerant
//! lanes only (providers plan §1).
//!
//! Zone discipline: provision's `--location` IS the zone and rides every
//! create-path call as `--zone`; destroy resolves the zone from the
//! ambient gcloud configuration (`CLOUDSDK_COMPUTE_ZONE` / gcloud config
//! `compute/zone`), because the destroy verb carries no location — run it
//! under the same zone configuration the provision used (instance names
//! are zone-scoped).
//!
//! Order discipline (the Hetzner module's contract): dry-run and every
//! local refusal resolve before ANY API call — credentials ride the
//! inherited environment (gcloud's ADC / `gcloud auth` store convention)
//! and never enter argv, and no partial state survives a failure:
//! instances created before a later failure are deleted, config is
//! appended only after every instance is up. No retries are named by the
//! ticket: a failed step fails the provision and tears the set down; the
//! operator re-runs.

use std::path::Path;

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, mint_host_keypair, now_epoch_secs,
    render_user_data, stage_user_data, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams,
};

/// The worker presence label shuttle stamps at create time — the key
/// shared with the #269 v2 TTL contract (Hetzner writer, cross-provider
/// vocabulary): presence marks the instance as a shuttle worker. The
/// value is `true` (presence semantics; expiry rides the TTL label only).
pub const WORKER_LABEL: &str = "shuttle-worker";

/// The TTL label: expiry in EPOCH SECONDS UTC, set AT CREATE — the source
/// of truth of the #269 v2 contract (the in-guest marker is a fallback
/// COPY). The same decimal shape the `shuttle-worker-ttl` hcloud label
/// carries; the sweep's `is_epoch` parses decimal only. (The sweep itself
/// is hcloud-only today — #287; the same gap applies to gcp.)
pub const WORKER_TTL_LABEL: &str = "shuttle-worker-ttl";

/// The preemptible label, present (`true`) only on `--preemptible`
/// instances: names the eviction class (T5 worker loss, ADR-0040
/// Amendment 1) so operator-side tooling can tell an interruptible lane
/// from an on-demand one.
pub const WORKER_PREEMPTIBLE_LABEL: &str = "shuttle-worker-preemptible";

/// The worker base image (providers plan §3, ADR-0046): the LATEST
/// Ubuntu LTS — the contract pins "latest LTS", never a codename — as the
/// `ubuntu-os-cloud` image FAMILY, bumped on every new LTS like the
/// Hetzner slug (26.04 at the 2026-09-27 decision; #273 reconciled the
/// stale 24.04 wording). The overlay is entirely in the shared cloud-init
/// template: stock provider image, no custom images.
pub const IMAGE_FAMILY: &str = "ubuntu-2604-lts-amd64";

/// The public image project that carries [`IMAGE_FAMILY`].
pub const IMAGE_PROJECT: &str = "ubuntu-os-cloud";

pub struct GcpProvisioner<R: CommandRunner> {
    runner: R,
    /// Where gcloud would resolve credentials from (the ADC key file or
    /// the `gcloud auth` config store) — `None` is the no-credentials
    /// refusal path, checked before any API call. The credential itself
    /// never enters argv; the gcloud CLI inherits it.
    credentials: Option<String>,
    /// The pinned shuttle binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at the
    /// CLI boundary (`SHUTTLE_OPERATOR_KEY` / default key halves) so the
    /// core stays env-free under test.
    operator_key: String,
}

impl<R: CommandRunner> GcpProvisioner<R> {
    pub fn new(
        runner: R,
        credentials: Option<String>,
        binary_url: String,
        operator_key: String,
    ) -> Self {
        GcpProvisioner {
            runner,
            credentials,
            binary_url,
            operator_key,
        }
    }

    /// One gcloud CLI call. `zone` rides `--zone` when the caller has it
    /// (the create path, from `--location`); `None` (destroy) lets the
    /// CLI resolve the ambient zone. Credentials ride the inherited
    /// environment — they never enter argv.
    fn gcp(&self, zone: Option<&str>, args: &[&str]) -> miette::Result<String> {
        let mut argv = vec!["gcloud".to_string()];
        if let Some(z) = zone {
            argv.push("--zone".to_string());
            argv.push(z.to_string());
        }
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("provision: cannot run the gcloud CLI (is it installed?): {e}")
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "provision: gcloud {} failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: CommandRunner> Provisioner for GcpProvisioner<R> {
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>> {
        // Local refusals first — every one of them API-free. GCP
        // preemptible pricing is fixed per machine type: there is no bid
        // a cap could name, so `--max-price` is refused either way rather
        // than silently ignored.
        if req.max_price.is_some() {
            return Err(miette::miette!(
                "provision: --max-price is not supported on gcp — preemptible instances are \
                 fixed-price (no bid to cap); use --preemptible without --max-price"
            ));
        }

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
            print_plan(
                &ProvisionPlan {
                    server_type: req.server_type.clone(),
                    location: req.location.clone(),
                    count: req.count,
                    image: format!("{IMAGE_FAMILY} (project {IMAGE_PROJECT})"),
                    ttl_secs: req.ttl_secs,
                    ttl_expiry_iso: expiry_iso,
                    binary_url: self.binary_url.clone(),
                    spot_max_price: None,
                    user_data_sha256,
                },
                req.spot,
            );
            return Ok(Vec::new());
        }

        // gcloud reads credentials from its inherited environment/config
        // store; they never enter argv. Presence is checked before any
        // API call.
        self.require_credentials()?;

        let user_data_file = stage_user_data(dir.path(), &user_data)?;

        // Create + describe; every successfully created name rides
        // `created` so any later failure tears the whole set down.
        let mut created: Vec<(String, String)> = Vec::new();
        let result = self.create_and_pin(
            req,
            &user_data_file,
            expiry_epoch,
            &minted.public_line,
            &mut created,
        );
        if let Err(e) = result {
            let mut torn_down = 0usize;
            let mut stuck: Vec<&str> = Vec::new();
            for (name, _) in &created {
                if self
                    .gcp(
                        Some(&req.location),
                        &["compute", "instances", "delete", name, "--quiet"],
                    )
                    .is_ok()
                {
                    torn_down += 1;
                } else {
                    stuck.push(name);
                }
            }
            if stuck.is_empty() {
                return Err(miette::miette!(
                    "provision: {e:#} — tore down {torn_down} created instance(s), config untouched"
                ));
            }
            return Err(miette::miette!(
                "provision: {e:#} — tore down {torn_down} created instance(s), config untouched; \
                 FAILED to delete {} — it is still running and billing; delete it with \
                 'shuttle workers destroy' or by hand",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(name, address)| ProvisionedWorker {
                host_key: pin_with_comment(&minted.public_line, &name),
                name,
                address,
            })
            .collect())
    }

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool> {
        self.require_credentials()?;
        // One describe serves both the address (the config pin's key) and
        // the #269 v2 pre-delete disk check.
        let doc = self.instance_doc(None, name)?;
        let ip = nat_ip_of(&doc, name)?;
        warn_surviving_disks(name, &doc);
        // Delete first: if the call fails the worker is still live and
        // the config pin must stay.
        self.gcp(None, &["compute", "instances", "delete", name, "--quiet"])?;
        match evict_worker_entry(config, &address_for(&ip)) {
            Ok(true) => Ok(true),
            Ok(false) => {
                crate::output::warn(format!(
                    "destroy: instance '{name}' deleted, but no managed workers entry pins {} — \
                     config left untouched",
                    address_for(&ip)
                ));
                Ok(false)
            }
            Err(e) => Err(miette::miette!(
                "destroy: instance '{name}' deleted, but the config entry could not be \
                 evicted: {e:#}"
            )),
        }
    }
}

impl<R: CommandRunner> GcpProvisioner<R> {
    fn require_credentials(&self) -> miette::Result<()> {
        if self.credentials.is_none() {
            return Err(miette::miette!(
                "provision: no GCP credentials found (checked GOOGLE_APPLICATION_CREDENTIALS, \
                 CLOUDSDK_CONFIG, ~/.config/gcloud) — run 'gcloud auth login' plus \
                 'gcloud auth application-default login', or set GOOGLE_APPLICATION_CREDENTIALS \
                 to the dedicated worker-project key (never a TOFU_INPUTS credential)"
            ));
        }
        Ok(())
    }

    /// Create `count` instances, describe each for its external NAT IP,
    /// then pin all entries in ONE config rewrite. Records every created
    /// name in `created` (name, address-so-far) as teardown-on-failure
    /// state — pushed BEFORE the describe, so an instance that exists but
    /// fails its describe is still deleted.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        user_data_file: &Path,
        expiry_epoch: u64,
        public_line: &str,
        created: &mut Vec<(String, String)>,
    ) -> miette::Result<()> {
        let mut pins: Vec<(String, String)> = Vec::new();
        for i in 0..req.count {
            let name = instance_name(i);
            let user_data_arg = format!("user-data={}", user_data_file.display());
            let labels_value = labels(req, expiry_epoch);
            // The zone rides the gcp() global (prepended) — never duplicated
            // in args, same discipline as the aws module's --region.
            let mut args = vec![
                "compute",
                "instances",
                "create",
                &name,
                "--machine-type",
                &req.server_type,
                "--image-family",
                IMAGE_FAMILY,
                "--image-project",
                IMAGE_PROJECT,
                "--metadata-from-file",
                &user_data_arg,
                "--labels",
                &labels_value,
            ];
            if req.spot {
                args.push("--preemptible");
            }
            self.gcp(Some(&req.location), &args)?;
            // Teardown state FIRST: an instance that exists but fails its
            // describe must still be deleted.
            created.push((name.clone(), String::new()));
            let doc = self.instance_doc(Some(&req.location), &name)?;
            let address = address_for(&nat_ip_of(&doc, &name)?);
            created.last_mut().expect("just pushed").1 = address.clone();
            pins.push((name, address));
        }
        // The pin transaction: all entries after every instance is up — a
        // provision that dies here leaves no config (and the caller's
        // teardown leaves no instance). Nothing unpinned survives.
        for (name, address) in &pins {
            append_worker_entry(&req.config, address, &pin_with_comment(public_line, name))?;
        }
        Ok(())
    }

    /// The full instance document from `gcloud compute instances describe
    /// --format json` — external IP (`networkInterfaces[0]`
    /// `.accessConfigs[0].natIP`) and the attached disks (the pre-delete
    /// check's input) in one read.
    fn instance_doc(&self, zone: Option<&str>, name: &str) -> miette::Result<Value> {
        let body = self.gcp(
            zone,
            &["compute", "instances", "describe", name, "--format", "json"],
        )?;
        serde_json::from_str(&body)
            .map_err(|e| miette::miette!("provision: gcloud describe '{name}' is not JSON: {e}"))
    }
}

/// The instance's external IPv4. Absent → named refusal with the VPC
/// remedy: the create never pretends an unreachable worker was
/// provisioned.
fn nat_ip_of(doc: &Value, name: &str) -> miette::Result<String> {
    doc["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            miette::miette!(
                "provision: instance '{name}' has no external IP — the VPC/subnet must grant \
                 an external address (ephemeral NAT IP) or the worker is unreachable; \
                 nothing was pinned"
            )
        })
}

/// The #269 v2 pre-delete check: disks that will NOT vanish with the
/// instance (`auto-delete` off) get a loud warning naming the count —
/// instance delete removes only auto-delete disks (the boot disk's
/// default IS auto-delete) — and then the delete proceeds anyway: the
/// operator asked for the destruction, the warning exists so lingering
/// storage bills are never silent.
fn warn_surviving_disks(name: &str, doc: &Value) {
    let attached = doc["disks"]
        .as_array()
        .map(|ds| ds.iter().filter(|d| d["autoDelete"] != true).count())
        .unwrap_or(0);
    if attached > 0 {
        crate::output::warn(format!(
            "destroy: instance '{name}' still has {attached} attached disk(s) that will NOT be \
             deleted with it (auto-delete off) — the storage keeps billing; delete them by hand"
        ));
    }
}

// ── Local shape helpers ──

/// The `--labels` value: the `shuttle-worker` presence label, the
/// `shuttle-worker-ttl` epoch-seconds EXPIRY (the #269 v2 contract — the
/// source of truth the sweep reads — set AT CREATE), and
/// `shuttle-worker-preemptible` on preemptible instances. One argv
/// element, no shell.
fn labels(req: &ProvisionRequest, expiry_epoch: u64) -> String {
    let mut l = vec![
        format!("{WORKER_LABEL}=true"),
        format!("{WORKER_TTL_LABEL}={expiry_epoch}"),
    ];
    if req.spot {
        l.push(format!("{WORKER_PREEMPTIBLE_LABEL}=true"));
    }
    l.join(",")
}

/// The address shape every provisioned entry carries: the shared template
/// authorizes root (key-only, `PermitRootLogin prohibit-password`), so
/// the login is root on the stock Ubuntu image too, default SSH port.
fn address_for(ip: &str) -> String {
    format!("ssh://root@{ip}")
}

/// The pinned public half: `ssh-keygen`'s line with the instance name as
/// the single comment word (the pin grammar allows at most one) —
/// traceability from a known_hosts/`workers` line back to the GCE
/// resource.
fn pin_with_comment(public_line: &str, name: &str) -> String {
    let mut parts = public_line.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    let key = parts.next().unwrap_or_default();
    format!("{key_type} {key} {name}")
}

/// `shuttle-worker-<hex nanos>-<NN>` — unique per project; the prefix
/// mirrors the label key, so name and label read as one identity.
fn instance_name(i: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("shuttle-worker-{nanos:x}-{:02}", i + 1)
}

fn print_plan(plan: &ProvisionPlan, preemptible: bool) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         gcp");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  zone:             {}", plan.location));
    crate::output::info(format!("  base image:       {}", plan.image));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    if preemptible {
        crate::output::info("  class:            preemptible (eviction: T5 worker loss)");
    } else {
        crate::output::info("  class:            on-demand");
    }
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  labels:           {WORKER_LABEL} + {WORKER_TTL_LABEL}=<ttl epoch>"
    ));
}
