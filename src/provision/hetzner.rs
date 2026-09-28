//! The Hetzner Cloud provider (T6): the `hcloud` CLI driven through
//! [`CommandRunner`] — zero new crates, the avahi-fallback precedent.
//!
//! Flow per ADR-0045 (mint-and-inject, Decision 1/6): mint the worker host
//! keypair coordinator-side → render the shared cloud-init template →
//! create the server with that user-data (`--user-datafile`, the
//! authenticated API channel that carries the private half) → describe for
//! the IPv4 → pin address + public half into the managed `workers` block.
//! The pin exists BEFORE first use; `ssh-keyscan` is never called.
//!
//! Order discipline (ticket): dry-run and the token check both resolve
//! before ANY API call — the token never reaches argv (hcloud inherits
//! `HCLOUD_TOKEN` from the environment), and no partial state survives a
//! failure: servers created before a later failure are deleted, config is
//! appended only after every server is up.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::command::{exit_code, CommandRunner};
use crate::provision::{
    append_worker_entry, evict_worker_entry, iso8601_utc, mint_host_keypair, now_epoch_secs,
    render_user_data, ProvisionPlan, ProvisionRequest, ProvisionedWorker, Provisioner,
    UserDataParams,
};

/// The hcloud labels shuttle stamps at create time — the key names shared
/// with the #269 v2 TTL sweep (writer here, reader there):
/// `shuttle-worker` is the marker/presence key; `shuttle-worker-ttl`
/// carries the TTL expiry in EPOCH SECONDS UTC (label values reject `:`,
/// so ISO-8601 never rides a label — that shape lives only in the in-guest
/// marker file, which is a fallback COPY, not the source of truth).
pub const WORKER_LABEL: &str = "shuttle-worker";
pub const WORKER_TTL_LABEL: &str = "shuttle-worker-ttl";

/// The stock image the template assumes (providers plan: Ubuntu 24.04;
/// template/toolchain determinism is #276's scope).
const IMAGE: &str = "ubuntu-24.04";

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
}

impl<R: CommandRunner> HetznerProvisioner<R> {
    pub fn new(runner: R, token: Option<String>, binary_url: String, operator_key: String) -> Self {
        HetznerProvisioner {
            runner,
            token,
            binary_url,
            operator_key,
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
        // Local resolution first: mint, template, TTL. All of it is
        // API-free, so the dry-run plan is the REAL plan.
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
            ttl_expiry_iso: &expiry_iso,
        });
        let user_data_sha256 = crate::oci::sha256_hex(user_data.as_bytes());

        if req.dry_run {
            // Deliberately BEFORE the token check: a plan needs no
            // credentials and must make no API call.
            print_plan(&ProvisionPlan {
                server_type: req.server_type.clone(),
                location: req.location.clone(),
                count: req.count,
                ttl_secs: req.ttl_secs,
                ttl_expiry_iso: expiry_iso,
                binary_url: self.binary_url.clone(),
                user_data_sha256,
            });
            return Ok(Vec::new());
        }

        // hcloud reads the token from the inherited environment; it never
        // enters argv. Presence is checked before any API call.
        self.require_token()?;

        let user_data_file = write_user_data_file(&user_data)?;

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
            for (name, _) in &created {
                let _ = self.hcloud(&["server", "delete", name]);
            }
            return Err(miette::miette!(
                "provision: {e:#} — tore down {} created server(s), config untouched",
                created.len()
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

    fn destroy(&self, name: &str, config: &Path) -> miette::Result<()> {
        self.require_token()?;
        let ip = self.server_ipv4(name)?;
        // The #269 v2 pre-delete check: attached volumes must not vanish
        // with the server unnoticed.
        self.warn_attached_volumes(name)?;
        // Server first: if the delete fails the worker is still live and
        // the config pin must stay.
        self.hcloud(&["server", "delete", name])?;
        match evict_worker_entry(config, &address_for(&ip)) {
            Ok(true) => {}
            Ok(false) => crate::output::warn(format!(
                "destroy: server '{name}' deleted, but no managed workers entry pins {} — \
                 config left untouched",
                address_for(&ip)
            )),
            Err(e) => {
                return Err(miette::miette!(
                    "destroy: server '{name}' deleted, but the config entry could not be \
                     evicted: {e:#}"
                ))
            }
        }
        Ok(())
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
    /// entries in ONE config rewrite. Records every created name in
    /// `created` (name, address-so-far) as teardown-on-failure state.
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
            let name = server_name(i);
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
        for (name, address) in &pins {
            append_worker_entry(&req.config, address, &pin_with_comment(public_line, name))?;
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

/// The pinned public half: `ssh-keygen`'s line with the server name as the
/// single comment word (the pin grammar allows at most one) — traceability
/// from a known_hosts/`workers` line back to the hcloud resource.
fn pin_with_comment(public_line: &str, name: &str) -> String {
    let mut parts = public_line.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    let key = parts.next().unwrap_or_default();
    format!("{key_type} {key} {name}")
}

/// `shuttle-worker-<hex nanos>-<NN>` — unique per project; the prefix
/// mirrors the label key, so name and label read as one identity.
fn server_name(i: u32) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("shuttle-worker-{nanos:x}-{:02}", i + 1)
}

/// Stage the user-data blob for `hcloud --user-datafile`. The path is
/// content-addressed so concurrent provisions never overwrite each other;
/// the file holds only the worker HOST key (server-auth, blast radius one
/// machine per ADR-0045) and rides the OS temp cleaner.
fn write_user_data_file(user_data: &str) -> miette::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "shuttle-userdata-{}.yaml",
        crate::oci::sha256_hex(user_data.as_bytes())
            .get(..16)
            .unwrap_or("x")
    ));
    std::fs::write(&path, user_data)
        .map_err(|e| miette::miette!("provision: cannot write {}: {e}", path.display()))?;
    Ok(path)
}

fn print_plan(plan: &ProvisionPlan) {
    crate::output::info("provision plan (dry run — no API call was made):");
    crate::output::info("  provider:         hetzner");
    crate::output::info(format!("  type:             {}", plan.server_type));
    crate::output::info(format!("  location:         {}", plan.location));
    crate::output::info(format!("  count:            {}", plan.count));
    crate::output::info(format!(
        "  ttl:              {}s (expiry {})",
        plan.ttl_secs, plan.ttl_expiry_iso
    ));
    crate::output::info(format!("  binary url:       {}", plan.binary_url));
    crate::output::info(format!("  user-data sha256: {}", plan.user_data_sha256));
    crate::output::info(format!(
        "  label:            {WORKER_LABEL} + {WORKER_TTL_LABEL}=<ttl epoch>"
    ));
}
