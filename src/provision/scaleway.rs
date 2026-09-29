//! The Scaleway provider (#198, T10): the `scw` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent, the
//! same shape as the Hetzner/AWS/GCP/Azure modules.
//!
//! Flow per ADR-0045's amendment (#295): mint a one-time publish token
//! per server + render the shared cloud-init template (guest-local host
//! keypair generation — NO private half ships) → `server create` with
//! that user-data (`user-data.0.content=file://`, the authenticated API
//! channel that now carries public material + the one-time bearer only)
//! → `server get` for the flexible IP → pin the host CA fingerprint into
//! the managed `workers` block. The pin exists BEFORE first use;
//! `ssh-keyscan` is never called.
//!
//! User-data channel: the shared template (#273) is a `#cloud-config`
//! YAML, and Scaleway consumes it under the reserved `cloud-init` user-data
//! key. The blob is staged 0600 in the provision tempdir and handed off as
//! a `file://` reference — the same file hand-off discipline as the
//! sibling providers (hcloud `--user-datafile`, aws `file://`, gcloud
//! `user-data=<file>`, azure `@file`), so the one-time bearer never
//! enters argv. WIRE-FORM NOTE (flagged for review, the one T10-text
//! choice): the `user-data.0.content=` argument is the create-time
//! channel the scw CLI exposes; whether its `file://` indirection is read
//! client-side or needs inline content is exactly what the deferred live
//! lane (env-gated on Scaleway credentials) verifies first — a mismatch
//! fails the create and tears down cleanly, nothing is guessed.
//!
//! No spot product: Scaleway instances are on-demand fixed-price (like
//! Hetzner), so `--spot` is refused — an on-demand instance pretending to
//! be spot would lie about its eviction class — and `--max-price` is
//! refused either way (the GCP fixed-price pairing: there is no bid a cap
//! could name). On-demand hourly is the only class here.
//!
//! Zone discipline: provision's `--location` IS the Availability Zone
//! (e.g. fr-par-1) and rides every create-path call as the scw global
//! `-z`; destroy resolves the zone from the ambient scw configuration
//! (`SCW_ZONE` / the `scw init` default), because the destroy verb carries
//! no location — run it under the same zone configuration the provision
//! used (server ids are zone-scoped).
//!
//! Teardown truthfulness: create rides `ip=flexible` (a dynamic public IP,
//! deleted together with the server — no orphan IP class survives a
//! delete, unlike Azure's NICs), but block-storage volumes attached to the
//! server are only DETACHED by a delete and keep billing — the pre-delete
//! `server get` names them loudly (the #269 v2 residual warning, the Azure
//! deleteOption analog) before the delete proceeds. The #269 v2 contract
//! tags (`nau-worker` presence, `nau-worker-ttl` epoch-seconds
//! expiry) are stamped AT CREATE as server tags — Scaleway instance tags
//! are free-form strings, so the key=value vocabulary rides inside each
//! string. The TTL sweep itself is hcloud-only today — #287; the same gap
//! applies to scaleway.
//!
//! Order discipline (the Hetzner module's contract): dry-run and every
//! local refusal resolve before ANY API call — credentials ride the
//! inherited environment / scw's own config store (the `scw init`
//! convention) and never enter argv, and no partial state survives a
//! failure: servers created before a later failure are deleted, config is
//! appended only after every server is up. No retries are named by the
//! ticket: a failed step fails the provision and tears the set down; the
//! operator re-runs.

use std::path::Path;

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::publish::PublishChannel;
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, now_epoch_secs, render_user_data,
    require_ca_pin, require_publish, PinPlan, ProvisionPlan, ProvisionRequest, ProvisionedWorker,
    Provisioner, UserDataParams, PLAN_MACHINE_IDENTITY, PLAN_PUBLISH_TOKEN, PLAN_PUBLISH_URL,
};

/// The worker presence tag nau stamps at create time — the key
/// shared with the #269 v2 TTL contract (Hetzner writer, cross-provider
/// vocabulary): presence marks the server as a nau worker. The value
/// is `true` (presence semantics; expiry rides the TTL tag only). Scaleway
/// instance tags are free-form strings, so the pair rides as one
/// `key=value` string per tag.
pub const WORKER_TAG: &str = "nau-worker";

/// The TTL tag: expiry in EPOCH SECONDS UTC, set AT CREATE — the source
/// of truth of the #269 v2 contract (the in-guest marker is a fallback
/// COPY). The same decimal shape the `nau-worker-ttl` hcloud label
/// carries; the sweep's `is_epoch` parses decimal only. (The sweep itself
/// is hcloud-only today — #287; the same gap applies to scaleway.)
pub const WORKER_TTL_TAG: &str = "nau-worker-ttl";

/// The worker base image (providers plan §3, ADR-0046): the LATEST
/// Ubuntu LTS — the contract pins "latest LTS", never a codename — as the
/// marketplace image LABEL, bumped on every new LTS like the Hetzner slug
/// and the GCP family (26.04 at the 2026-09-27 decision; #273 reconciled
/// the stale 24.04 wording). Scaleway identifies images by label or UUID;
/// the label is the stable handle (a UUID pin would rot per-zone per-snap).
/// A stale/renamed label fails the create — a named provider error, never
/// a guessed image. The overlay is entirely in the shared cloud-init
/// template: stock provider image, no custom images.
pub const IMAGE_LABEL: &str = "ubuntu_2604";

/// The user-data key Scaleway's cloud-init integration consumes.
pub const CLOUD_INIT_KEY: &str = "cloud-init";

pub struct ScalewayProvisioner<R: CommandRunner> {
    runner: R,
    /// Where the scw CLI would resolve credentials from (the
    /// `SCW_ACCESS_KEY` + `SCW_SECRET_KEY` pair or the `scw init` config
    /// file) — `None` is the no-credentials refusal path, checked before
    /// any API call. The credential itself never enters argv; the scw CLI
    /// inherits it from its environment/config store.
    credentials: Option<String>,
    /// The pinned nau binary URL the template installs.
    binary_url: String,
    /// The operator's authorized public-key line (login), resolved at the
    /// CLI boundary (`NAU_OPERATOR_KEY` / default key halves) so the
    /// core stays env-free under test.
    operator_key: String,
    /// The coordinator publish channel (callback URL + ceremony home) —
    /// `None` is the no-channel refusal path for real runs; a dry run
    /// runs without.
    publish: Option<PublishChannel>,
}

impl<R: CommandRunner> ScalewayProvisioner<R> {
    pub fn new(
        runner: R,
        credentials: Option<String>,
        binary_url: String,
        operator_key: String,
        publish: Option<PublishChannel>,
    ) -> Self {
        ScalewayProvisioner {
            runner,
            credentials,
            binary_url,
            operator_key,
            publish,
        }
    }

    /// One scw CLI call. `zone` rides the global `-z` when the caller has
    /// it (the create path, from `--location`); `None` (destroy) lets the
    /// CLI resolve the ambient zone. Credentials ride the inherited
    /// environment / scw's config store — they never enter argv.
    fn scw(&self, zone: Option<&str>, args: &[&str]) -> miette::Result<String> {
        let mut argv = vec!["scw".to_string()];
        if let Some(z) = zone {
            argv.push("-z".to_string());
            argv.push(z.to_string());
        }
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("provision: cannot run the scw CLI (is it installed?): {e}")
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "provision: scw {} failed: {}",
                args.join(" "),
                out.stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl<R: CommandRunner> Provisioner for ScalewayProvisioner<R> {
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>> {
        // Local refusals first — every one of them API-free. Scaleway has
        // no spot product (on-demand fixed-price only), and there is no
        // bid a `--max-price` cap could name in any class.
        validate_flags(req)?;

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
            // Deliberately BEFORE the credentials check: a plan needs no
            // credentials and must make no API call.
            print_plan(&ProvisionPlan {
                server_type: req.server_type.clone(),
                location: req.location.clone(),
                count: req.count,
                image: IMAGE_LABEL.to_string(),
                ttl_secs: req.ttl_secs,
                ttl_expiry_iso: expiry_iso,
                binary_url: self.binary_url.clone(),
                spot_max_price: None,
                user_data_sha256,
            });
            return Ok(Vec::new());
        }

        // scw reads credentials from its inherited environment/config
        // store; they never enter argv. Presence is checked before any
        // API call — the outermost gate, then the fail-closed
        // coordinator-side state: the publish channel (guest callback)
        // and the CA pin the entries will carry.
        self.require_credentials()?;
        let publish = require_publish(&self.publish)?;
        let ca_pin = require_ca_pin(req)?.to_string();
        let pin = PinPlan {
            publish,
            ca_pin: &ca_pin,
        };

        // Create + describe; every successfully created server rides
        // `created` (id, name, address-so-far) so any later failure tears
        // the whole set down.
        let mut created: Vec<(String, String, String)> = Vec::new();
        let result = self.create_and_pin(req, dir.path(), expiry_epoch, &pin, &mut created);
        if let Err(e) = result {
            let mut torn_down = 0usize;
            let mut stuck: Vec<String> = Vec::new();
            for (id, name, _) in &created {
                if self
                    .scw(
                        Some(&req.location),
                        &["instance", "server", "delete", &format!("server-id={id}")],
                    )
                    .is_ok()
                {
                    torn_down += 1;
                } else {
                    stuck.push(format!("{name} ({id})"));
                }
            }
            if stuck.is_empty() {
                return Err(miette::miette!(
                    "provision: {e:#} — tore down {torn_down} created server(s), config untouched"
                ));
            }
            return Err(miette::miette!(
                "provision: {e:#} — tore down {torn_down} created server(s), config untouched; \
                 FAILED to delete {} — it is still running and billing; delete it with \
                 'nau workers destroy' or by hand",
                stuck.join(", ")
            ));
        }
        Ok(created
            .into_iter()
            .map(|(_, name, address)| ProvisionedWorker {
                host_key: ca_pin.clone(),
                name,
                address,
            })
            .collect())
    }

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool> {
        self.require_credentials()?;
        // The destroy verb carries no location: resolve the zone-scoped
        // server id from the listing, client-side (the operator-supplied
        // name never becomes a server-side filter expression). The zone
        // comes from the ambient scw configuration (SCW_ZONE / the `scw
        // init` default) — run destroy under the zone provision used.
        let id = self.resolve_server_id(name)?;
        // One describe serves both the address (the config pin's key) and
        // the pre-delete volume check.
        let doc = self.server_doc(None, &id)?;
        let ip = public_ip_of(&doc, name)?;
        warn_surviving_block_volumes(name, &doc);
        // Delete first: if the call fails the worker is still live and
        // the config pin must stay. The dynamic flexible IP rides
        // `ip=flexible` and is deleted together with the server.
        self.scw(
            None,
            &["instance", "server", "delete", &format!("server-id={id}")],
        )?;
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

impl<R: CommandRunner> ScalewayProvisioner<R> {
    fn require_credentials(&self) -> miette::Result<()> {
        if self.credentials.is_none() {
            return Err(miette::miette!(
                "provision: no Scaleway credentials found (checked SCW_ACCESS_KEY + \
                 SCW_SECRET_KEY, SCW_CONFIG_PATH, ~/.config/scw/config.yaml) — run 'scw init', \
                 or export the dedicated worker-project key pair (never a TOFU_INPUTS \
                 credential)"
            ));
        }
        Ok(())
    }

    /// Create `count` servers, describe each for its flexible IP, then
    /// pin all entries in ONE pass. Each server gets its own machine
    /// identity, its own one-time publish token (recorded in the
    /// coordinator's registry BEFORE the create — the token must be
    /// enforceable by first boot), and its own user-data blob. Records
    /// every created server in `created` (id, name, address-so-far) as
    /// teardown-on-failure state — pushed BEFORE the describe, so a
    /// server that exists but fails its describe is still deleted.
    fn create_and_pin(
        &self,
        req: &ProvisionRequest,
        staging: &Path,
        expiry_epoch: u64,
        pin: &PinPlan<'_>,
        created: &mut Vec<(String, String, String)>,
    ) -> miette::Result<()> {
        let mut pins: Vec<(String, String)> = Vec::new();
        for i in 0..req.count {
            let name = instance_name(i);
            let user_data_file = crate::provision::stage_publishing_user_data(
                staging,
                pin.publish,
                &self.binary_url,
                &self.operator_key,
                &name,
                expiry_epoch,
            )?;
            let user_data_arg = format!("user-data.0.content=file://{}", user_data_file.display());
            let id = {
                let body = self.scw(
                    Some(&req.location),
                    &[
                        "instance",
                        "server",
                        "create",
                        &format!("name={name}"),
                        &format!("type={}", req.server_type),
                        &format!("image={IMAGE_LABEL}"),
                        // A dynamic public IP, created with the server
                        // and deleted with it — the worker must be
                        // reachable and no orphan IP class may survive.
                        "ip=flexible",
                        "user-data.0.key=cloud-init",
                        &user_data_arg,
                        // The #269 v2 contract tags, stamped AT CREATE:
                        // presence + epoch-seconds TTL expiry. Free-form
                        // string tags — one `key=value` per element.
                        &format!("tags.0={WORKER_TAG}=true"),
                        &format!("tags.1={WORKER_TTL_TAG}={expiry_epoch}"),
                    ],
                )?;
                parse_created(&body, &name)?
            };
            // The blob is served — the one-time bearer in it must not
            // linger on disk past its create call.
            let _ = std::fs::remove_file(&user_data_file);
            // Teardown state FIRST: a server that exists but fails its
            // describe must still be deleted.
            created.push((id.clone(), name.clone(), String::new()));
            let doc = self.server_doc(Some(&req.location), &id)?;
            let address = address_for(&public_ip_of(&doc, &name)?);
            created.last_mut().expect("just pushed").2 = address.clone();
            pins.push((name, address));
        }
        // The pin transaction: all entries after every server is up — a
        // provision that dies here leaves no config (and the caller's
        // teardown leaves no server). Nothing unpinned survives. Each
        // address also records its machine-identity linkage — the
        // executor's @cert-authority pin binds the certificate principal
        // through it (#295 sub-task 4).
        for (name, address) in &pins {
            crate::provision::publish::record_machine_link(&pin.publish.home, name, address)?;
            append_worker_entry(&req.config, address, pin.ca_pin)?;
        }
        Ok(())
    }

    /// The full server document from `scw instance server get -o json` —
    /// the flexible IP (`public_ip.address`) and the attached volumes
    /// (the pre-delete check's input) in one read.
    fn server_doc(&self, zone: Option<&str>, id: &str) -> miette::Result<Value> {
        let body = self.scw(zone, &["instance", "server", "get", id, "-o", "json"])?;
        serde_json::from_str(&body)
            .map_err(|e| miette::miette!("provision: scw server get '{id}' is not JSON: {e}"))
    }

    /// The server id for `name`: one `scw instance server list -o json`,
    /// filtered client-side (the operator-supplied name never becomes a
    /// server-side filter). A miss is a named refusal.
    fn resolve_server_id(&self, name: &str) -> miette::Result<String> {
        let body = self.scw(None, &["instance", "server", "list", "-o", "json"])?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| miette::miette!("destroy: scw server list is not JSON: {e}"))?;
        for server in v["servers"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if server["name"].as_str() == Some(name) {
                return server["id"]
                    .as_str()
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        miette::miette!("destroy: scw server list has no id for '{name}'")
                    });
            }
        }
        Err(miette::miette!(
            "destroy: no server named '{name}' in this zone — names are printed by \
             provision; nothing was deleted"
        ))
    }
}

// ── Local refusals and shape helpers ──

/// Scaleway runs on-demand fixed-price instances only: `--spot` names a
/// class the provider does not sell, and `--max-price` names a bid there
/// is nothing to cap (the GCP fixed-price pairing). Both refusals are
/// API-free and name the provider-independent spelling so the operator can
/// re-run without editing intent.
fn validate_flags(req: &ProvisionRequest) -> miette::Result<()> {
    if req.spot {
        return Err(miette::miette!(
            "provision: --spot is not supported on scaleway — it has no spot product; \
             on-demand hourly fixed-price is the only class. Spot is an aws capability \
             (eviction-tolerant lanes only, ADR-0040 Amendment 1)"
        ));
    }
    if req.max_price.is_some() {
        return Err(miette::miette!(
            "provision: --max-price is not supported on scaleway — instances are fixed-price \
             (no bid to cap); drop --max-price"
        ));
    }
    Ok(())
}

/// The created server's id from the create document — fail-closed: no
/// readable id is a named refusal, never an empty success that would skip
/// teardown state.
fn parse_created(body: &str, name: &str) -> miette::Result<String> {
    let v: Value = serde_json::from_str(body.trim())
        .map_err(|e| miette::miette!("provision: scw server create '{name}' is not JSON: {e}"))?;
    v["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            miette::miette!(
                "provision: scw server create returned no readable server id for '{name}' \
                 ('{}')",
                body.trim()
            )
        })
}

/// The server's public IPv4 from the `server get` document (the flexible
/// IP created with `ip=flexible`). Absent → named refusal with the
/// remedy: the create never pretends an unreachable worker was
/// provisioned.
fn public_ip_of(doc: &Value, name: &str) -> miette::Result<String> {
    doc["public_ip"]["address"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            miette::miette!(
                "provision: server '{name}' has no public IP — the create requests a dynamic \
                 flexible IP (ip=flexible); if the zone or the account IP quota denied it, \
                 free an IP or pick another zone; the worker would be unreachable and \
                 nothing was pinned"
            )
        })
}

/// The pre-delete residual check (#269 v2, the Azure deleteOption analog):
/// block-storage volumes attached to the server are only DETACHED by a
/// delete and keep billing — a loud warning names the count BEFORE the
/// delete, and then the delete proceeds anyway: the operator asked for the
/// destruction, the warning exists so lingering storage bills are never
/// silent. Local volumes (the stock boot disk, `l_ssd`) die with the
/// server; the dynamic flexible IP does too.
fn warn_surviving_block_volumes(name: &str, doc: &Value) {
    let sbs = doc["volumes"]
        .as_object()
        .map(|v| {
            v.values()
                .filter(|d| d["volume_type"].as_str() == Some("sbs_volume"))
                .count()
        })
        .unwrap_or(0);
    if sbs > 0 {
        crate::output::warn(format!(
            "destroy: server '{name}' still has {sbs} block-storage volume(s) — a server \
             delete only DETACHES them and the storage keeps billing; delete them by hand"
        ));
    }
}

/// The address shape every provisioned entry carries: the shared template
/// authorizes root (key-only, `PermitRootLogin prohibit-password`), so
/// the login is root on the stock Ubuntu image too, default SSH port.
fn address_for(ip: &str) -> String {
    format!("ssh://root@{ip}")
}

/// `nau-worker-<hex nanos>-<NN>` — unique per project; the prefix
/// mirrors the tag key, so name and tags read as one identity. The name
/// doubles as the machine identity the one-time publish token binds.
fn instance_name(i: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("nau-worker-{nanos:x}-{:02}", i + 1)
}

fn print_plan(plan: &ProvisionPlan) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         scaleway");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  zone:             {}", plan.location));
    crate::output::info(format!("  base image:       {}", plan.image));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    crate::output::info("  class:            on-demand (no spot product on scaleway)");
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  tags:             {WORKER_TAG} + {WORKER_TTL_TAG}=<ttl epoch>"
    ));
}
