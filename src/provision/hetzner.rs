//! The Hetzner Cloud provider (T6): the `hcloud` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent.
//!
//! Flow per ADR-0045's amendment (#295): mint a one-time publish token
//! per server + render the shared cloud-init template (guest-local host
//! keypair generation — NO private half ships) → create the server with
//! that user-data (`--user-datafile`, the authenticated API channel that
//! now carries public material + the one-time bearer only) → describe for
//! the IPv4 → pin the host CA fingerprint into the managed `workers`
//! block. The pin exists BEFORE first use; `ssh-keyscan` is never
//! called.
//!
//! Order discipline (ticket): dry-run and the token check both resolve
//! before ANY API call — the token never reaches argv (hcloud inherits
//! `HCLOUD_TOKEN` from the environment), and no partial state survives a
//! failure: servers created before a later failure are deleted, config is
//! appended only after every server is up.

use std::path::Path;

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::publish::PublishChannel;
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, now_epoch_secs, render_user_data,
    require_ca_pin, require_publish, PinPlan, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

/// The hcloud labels shuttle stamps at create time — the key names shared
/// with the #269 v2 TTL sweep (writer here, reader there):
/// `shuttle-worker` is the marker/presence key; `shuttle-worker-ttl`
/// carries the TTL expiry in EPOCH SECONDS UTC (label values reject `:`,
/// so ISO-8601 never rides a label; the in-guest marker copy carries the
/// same epoch-seconds shape — the sweep's `is_epoch` parses decimal
/// only).
pub const WORKER_LABEL: &str = "shuttle-worker";
pub const WORKER_TTL_LABEL: &str = "shuttle-worker-ttl";

/// The worker base image (providers plan §3, ADR-0046): the LATEST
/// Ubuntu LTS — the contract pins "latest LTS", never a codename — so
/// this slug is bumped on every new LTS (26.04 at the 2026-09-27
/// decision; #273 reconciled it from the stale 24.04 wording). The
/// overlay is entirely in the shared cloud-init template: stock provider
/// image, no custom images.
pub const IMAGE: &str = "ubuntu-26.04";

pub struct HetznerProvisioner<R: CommandRunner> {
    runner: R,
    /// The dedicated project token (#271 account, never TOFU_INPUTS) —
    /// `None` is the no-token refusal path, checked before any API call.
    token: Option<String>,
    /// The pinned shuttle binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at the
    /// CLI boundary (`SHUTTLE_OPERATOR_KEY` / default key halves) so the
    /// core stays env-free under test.
    operator_key: String,
    /// The coordinator publish channel (callback URL + ceremony home) —
    /// `None` is the no-channel refusal path for real runs; a dry run
    /// runs without.
    publish: Option<PublishChannel>,
}

impl<R: CommandRunner> HetznerProvisioner<R> {
    pub fn new(
        runner: R,
        token: Option<String>,
        binary_url: String,
        operator_key: String,
        publish: Option<PublishChannel>,
    ) -> Self {
        HetznerProvisioner {
            runner,
            token,
            binary_url,
            operator_key,
            publish,
        }
    }

    fn hcloud(&self, args: &[&str]) -> miette::Result<String> {
        let mut argv = vec!["hcloud".to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("provision: cannot run the hcloud CLI (is it installed?): {e}")
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "provision: hcloud {} failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: CommandRunner> Provisioner for HetznerProvisioner<R> {
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>> {
        // Hetzner has no spot product (providers plan §1): the flag is
        // refused, never silently ignored — an on-demand instance pretending
        // to be spot would lie about its eviction class.
        if req.spot {
            return Err(miette::miette!(
                "provision: --spot is not supported on hetzner — it has no spot product; \
                 on-demand hourly (capped at the monthly price) is the only class. Spot is an \
                 aws capability (eviction-tolerant lanes only, ADR-0040 Amendment 1)"
            ));
        }
        // Local resolution first: template, TTL. All of it is API-free,
        // so the dry-run plan is the REAL plan (with placeholder publish
        // slots — the real per-server blob differs only in token + name).
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
        let user_data_sha256 = crate::oci::sha256_hex(user_data.as_bytes());

        if req.dry_run {
            // Deliberately BEFORE the token check: a plan needs no
            // credentials and must make no API call.
            print_plan(&ProvisionPlan {
                server_type: req.server_type.clone(),
                location: req.location.clone(),
                count: req.count,
                image: IMAGE.to_string(),
                ttl_secs: req.ttl_secs,
                ttl_expiry_iso: expiry_iso,
                binary_url: self.binary_url.clone(),
                spot_max_price: None,
                user_data_sha256,
            });
            return Ok(Vec::new());
        }

        // hcloud reads the token from the inherited environment; it never
        // enters argv. Presence is checked before any API call — the
        // outermost gate, then the fail-closed coordinator-side state:
        // the publish channel (guest callback) and the CA pin the
        // entries will carry.
        self.require_token()?;
        let publish = require_publish(&self.publish)?;
        let ca_pin = require_ca_pin(req)?.to_string();
        let pin = PinPlan {
            publish,
            ca_pin: &ca_pin,
        };

        // Create + describe; every successfully created name rides
        // `created` so any later failure tears the whole set down.
        let mut created: Vec<(String, String)> = Vec::new();
        let result = self.create_and_pin(req, dir.path(), expiry_epoch, &pin, &mut created);
        if let Err(e) = result {
            let mut torn_down = 0usize;
            let mut stuck: Vec<&str> = Vec::new();
            for (name, _) in &created {
                if self.hcloud(&["server", "delete", name]).is_ok() {
                    torn_down += 1;
                } else {
                    stuck.push(name);
                }
            }
            if stuck.is_empty() {
                return Err(miette::miette!(
                    "provision: {e:#} — tore down {torn_down} created server(s), config untouched"
                ));
            }
            return Err(miette::miette!(
                "provision: {e:#} — tore down {torn_down} created server(s), config untouched; \
                 FAILED to delete {} — it is still billing; re-run 'shuttle workers destroy' \
                 or let the TTL sweep reclaim it",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(name, address)| ProvisionedWorker {
                host_key: ca_pin.clone(),
                name,
                address,
            })
            .collect())
    }

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool> {
        self.require_token()?;
        let ip = self.server_ipv4(name)?;
        // The #269 v2 pre-delete check: attached volumes must not vanish
        // with the server unnoticed.
        self.warn_attached_volumes(name)?;
        // Server first: if the delete fails the worker is still live and
        // the config pin must stay.
        self.hcloud(&["server", "delete", name])?;
        match evict_worker_entry(config, &address_for(&ip)) {
            Ok(true) => Ok(true),
            Ok(false) => {
                crate::output::warn(format!(
                    "destroy: server '{name}' deleted, but no managed workers entry pins {} — \
                     config left untouched",
                    address_for(&ip)
                ));
                Ok(false)
            }
            Err(e) => Err(miette::miette!(
                "destroy: server '{name}' deleted, but the config entry could not be \
                 evicted: {e:#}"
            )),
        }
    }
}

impl<R: CommandRunner> HetznerProvisioner<R> {
    fn require_token(&self) -> miette::Result<()> {
        if self.token.is_none() {
            return Err(miette::miette!(
                "provision: no Hetzner API token — set HCLOUD_TOKEN (the dedicated project \
                 token, never the TOFU_INPUTS credential)"
            ));
        }
        Ok(())
    }

    /// Create `count` servers, describe each for its IPv4, then pin all
    /// entries in ONE config rewrite. Each server gets its own machine
    /// identity, its own one-time publish token (recorded in the
    /// coordinator's registry BEFORE the create — the token must be
    /// enforceable by first boot), and its own user-data blob. Records
    /// every created name in `created` (name, address-so-far) as
    /// teardown-on-failure state.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        staging: &Path,
        expiry_epoch: u64,
        pin: &PinPlan<'_>,
        created: &mut Vec<(String, String)>,
    ) -> miette::Result<()> {
        let mut pins: Vec<(String, String)> = Vec::new();
        for i in 0..req.count {
            let name = server_name(i);
            let user_data_file = crate::provision::stage_publishing_user_data(
                staging,
                pin.publish,
                &self.binary_url,
                &self.operator_key,
                &name,
                expiry_epoch,
            )?;
            self.hcloud(&[
                "server",
                "create",
                "--name",
                &name,
                "--type",
                &req.server_type,
                "--location",
                &req.location,
                "--image",
                IMAGE,
                "--label",
                &format!("{WORKER_LABEL}={expiry_epoch}"),
                "--label",
                &format!("{WORKER_TTL_LABEL}={expiry_epoch}"),
                "--user-datafile",
                &user_data_file.display().to_string(),
                "--start-after-create",
            ])?;
            // The blob is served — the one-time bearer in it must not
            // linger on disk past its create call.
            let _ = std::fs::remove_file(&user_data_file);
            // Teardown state FIRST: a server that exists but fails its
            // describe must still be deleted.
            created.push((name.clone(), String::new()));
            let ip = self.server_ipv4(&name)?;
            let address = address_for(&ip);
            created.last_mut().expect("just pushed").1 = address.clone();
            pins.push((name, address));
        }
        // The pin transaction: all entries after every server is up — a
        // provision that dies here leaves no config (and the caller's
        // teardown leaves no server). Nothing unpinned survives.
        for (_, address) in &pins {
            append_worker_entry(&req.config, address, pin.ca_pin)?;
        }
        Ok(())
    }

    /// The server's primary IPv4 from `hcloud server describe -o json`.
    fn server_ipv4(&self, name: &str) -> miette::Result<String> {
        let body = self.hcloud(&["server", "describe", name, "-o", "json"])?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("provision: hcloud describe '{name}' is not JSON: {e}"))?;
        let ip = v["public_net"]["ipv4"]["ip"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                miette::miette!(
                    "provision: server '{name}' has no primary IPv4 in the describe document"
                )
            })?;
        Ok(ip.to_string())
    }

    /// `hcloud volume list --server <name>` MUST come back empty before a
    /// delete. Anything attached gets a loud warning naming the count —
    /// volumes are NOT deleted (or silently detached) by this command —
    /// and then the delete proceeds anyway: the operator asked for the
    /// destruction, the warning exists so data loss is never silent.
    fn warn_attached_volumes(&self, name: &str) -> miette::Result<()> {
        let body = self.hcloud(&["volume", "list", "--server", name, "-o", "json"])?;
        let v: Value = serde_json::from_str(&body).map_err(|e| {
            miette::miette!("destroy: hcloud volume list for '{name}' is not JSON: {e}")
        })?;
        let attached = v.as_array().map(Vec::len).unwrap_or(0);
        if attached > 0 {
            crate::output::warn(format!(
                "destroy: server '{name}' still has {attached} attached volume(s) — \
                 `shuttle workers destroy` does NOT delete them; the data goes with the \
                 volume, not the server"
            ));
        }
        Ok(())
    }
}

/// The address shape every provisioned entry carries: Hetzner Ubuntu
/// images log in as root, default SSH port.
fn address_for(ip: &str) -> String {
    format!("ssh://root@{ip}")
}

/// `shuttle-worker-<hex nanos>-<NN>` — unique per project; the prefix
/// mirrors the label key, so name and label read as one identity. The
/// name doubles as the machine identity the one-time publish token binds.
fn server_name(i: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("shuttle-worker-{nanos:x}-{:02}", i + 1)
}

fn print_plan(plan: &ProvisionPlan) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         hetzner");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  location:         {}", plan.location));
    crate::output::info(format!("  base image:       {}", plan.image));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    if let Some(cap) = &plan.spot_max_price {
        crate::output::info(format!("  spot max price:   {cap} USD/h"));
    }
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  label:            {WORKER_LABEL} + {WORKER_TTL_LABEL}=<ttl epoch>"
    ));
}
