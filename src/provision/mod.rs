//! The Provisioner seam (T6, ADR-0040 as rewritten by ADR-0045): turn a
//! cloud account into a pinned `workers` entry in the operator's
//! `shuttle.lua`, and take it back.
//!
//! Shape, fixed by the ratified host-key provenance decision (ADR-0045
//! Decision 1/6): provision MINTS the worker's SSH host keypair
//! coordinator-side, injects the private half through the provider's
//! cloud-init user-data (the same authenticated channel that can already
//! create and destroy machines), and pins the public half into the
//! appended workers entry in the SAME transaction — the pin exists before
//! first use, and `ssh-keyscan` is never called. A provision that fails
//! after servers exist tears them down: nothing survives unpinned.
//!
//! One provider module per cloud, each driving the provider's CLI through
//! [`crate::command::CommandRunner`] (the repo's subprocess convention —
//! zero new crates, the avahi-fallback precedent). The shared pieces live
//! here: the [`Provisioner`] trait, the mint step, the TTL vocabulary the
//! #269 sweep reads, and the shared cloud-init template.
//!
//! Secrets never enter `shuttle.lua`: the config carries only the public
//! pin (`host_key`) and the address. The private half rides user-data into
//! the guest and is scrubbed from the guest's user-data copy once `sshd`
//! is up.

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod hetzner;
pub mod scaleway;

use std::path::{Path, PathBuf};

use crate::cli::WorkersCommand;
use crate::command::CommandRunner;

/// The default shuttle binary URL the template installs: the project
/// release artifact for the running version. Override with
/// `SHUTTLE_WORKER_BINARY_URL` (e.g. a pod- or cache-pinned copy) until
/// release infra carries it.
fn default_binary_url() -> String {
    if let Ok(url) = std::env::var("SHUTTLE_WORKER_BINARY_URL") {
        if !url.trim().is_empty() {
            return url;
        }
    }
    format!(
        "https://github.com/rbelem/shuttle/releases/download/v{version}/shuttle-{arch}",
        version = env!("CARGO_PKG_VERSION"),
        arch = crate::snap::host_arch()
    )
}

/// `HCLOUD_TOKEN` (trimmed; empty = absent). Read at the CLI boundary so
/// the provisioner core stays env-free and hermetic under test.
fn token_from_env() -> Option<String> {
    std::env::var("HCLOUD_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Where the AWS CLI would resolve credentials from, without calling the
/// API: `AWS_ACCESS_KEY_ID` (the dedicated worker-account key, the #271
/// analog), else `AWS_PROFILE`, else `$HOME/.aws/credentials` on disk.
/// Read at the CLI boundary so the provider core stays env-free under
/// test; the aws CLI inherits the credential from the environment — it
/// never enters argv.
fn aws_credentials_source() -> Option<String> {
    if std::env::var("AWS_ACCESS_KEY_ID")
        .ok()
        .is_some_and(|k| !k.trim().is_empty())
    {
        return Some("AWS_ACCESS_KEY_ID".into());
    }
    if std::env::var("AWS_PROFILE")
        .ok()
        .is_some_and(|p| !p.trim().is_empty())
    {
        return Some("AWS_PROFILE".into());
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    if Path::new(&home).join(".aws").join("credentials").exists() {
        return Some("~/.aws/credentials".into());
    }
    None
}

/// Where the gcloud CLI would resolve credentials from, without calling
/// the API: `GOOGLE_APPLICATION_CREDENTIALS` (the ADC key file), else the
/// `CLOUDSDK_CONFIG` credential store (default `$HOME/.config/gcloud`, the
/// `gcloud auth login` state) on disk. Read at the CLI boundary so the
/// provider core stays env-free under test; the gcloud CLI inherits the
/// credential from the environment — it never enters argv.
fn gcp_credentials_source() -> Option<String> {
    if std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .ok()
        .is_some_and(|k| !k.trim().is_empty())
    {
        return Some("GOOGLE_APPLICATION_CREDENTIALS".into());
    }
    let base = match std::env::var("CLOUDSDK_CONFIG")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
    {
        Some(c) => c,
        None => format!(
            "{}/.config/gcloud",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        ),
    };
    if Path::new(&base).exists() {
        return Some(base);
    }
    None
}

/// Where the az CLI would resolve credentials from, without calling
/// the API: the service-principal environment triple
/// (`AZURE_CLIENT_ID` + `AZURE_TENANT_ID` + `AZURE_CLIENT_SECRET` or
/// `AZURE_CLIENT_CERTIFICATE_PATH`), else the `az login` token cache on
/// disk (`AZURE_CONFIG_DIR`, default `~/.azure`). Read at the CLI
/// boundary so the provider core stays env-free under test; the az CLI
/// inherits the credential — it never enters argv.
fn azure_credentials_source() -> Option<String> {
    let env_nonempty = |k: &str| std::env::var(k).ok().is_some_and(|v| !v.trim().is_empty());
    if env_nonempty("AZURE_CLIENT_ID")
        && env_nonempty("AZURE_TENANT_ID")
        && (env_nonempty("AZURE_CLIENT_SECRET") || env_nonempty("AZURE_CLIENT_CERTIFICATE_PATH"))
    {
        return Some("AZURE_CLIENT_ID + AZURE_TENANT_ID (service principal)".into());
    }
    let base = match std::env::var("AZURE_CONFIG_DIR")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
    {
        Some(c) => c,
        None => format!(
            "{}/.azure",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        ),
    };
    let base = Path::new(&base);
    if base.join("msal_token_cache.json").exists() || base.join("accessTokens.json").exists() {
        return Some(base.display().to_string());
    }
    None
}

/// Where the scw CLI would resolve credentials from, without calling the
/// API: the `SCW_ACCESS_KEY` + `SCW_SECRET_KEY` pair (the dedicated
/// worker-project key, the #271 analog), else the `scw init` config file
/// (`SCW_CONFIG_PATH` when set, else `~/.config/scw/config.yaml` — a
/// `SCW_CONFIGURATION` profile is a section inside that file, so the file
/// probe covers it). Read at the CLI boundary so the provider core stays
/// env-free under test; the scw CLI inherits the credential from its
/// environment/config store — it never enters argv.
fn scaleway_credentials_source() -> Option<String> {
    let env_nonempty = |k: &str| std::env::var(k).ok().is_some_and(|v| !v.trim().is_empty());
    if env_nonempty("SCW_ACCESS_KEY") && env_nonempty("SCW_SECRET_KEY") {
        return Some("SCW_ACCESS_KEY + SCW_SECRET_KEY".into());
    }
    if let Some(p) = std::env::var("SCW_CONFIG_PATH")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
    {
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    if Path::new(&home)
        .join(".config")
        .join("scw")
        .join("config.yaml")
        .exists()
    {
        return Some("~/.config/scw/config.yaml".into());
    }
    None
}

/// CLI entry for `shuttle workers provision` / `shuttle workers destroy`.
pub fn workers_main(command: WorkersCommand) -> miette::Result<()> {
    match command {
        WorkersCommand::Provision {
            provider,
            server_type,
            location,
            count,
            ttl,
            spot,
            max_price,
            preemptible,
            dry_run,
            file,
        } => {
            let provisioner = provider_for(&provider)?;
            let req = ProvisionRequest {
                server_type,
                location,
                count,
                ttl_secs: parse_ttl(&ttl)?,
                // `--preemptible` is the gcp spelling of the
                // provider-independent `--spot` bit: one request shape,
                // two flag spellings.
                spot: spot || preemptible,
                max_price,
                dry_run,
                config: PathBuf::from(&file),
            };
            let workers = provisioner.provision(&req)?;
            for w in &workers {
                crate::output::ok(format!(
                    "provisioned worker '{name}' — pinned {address} (host key {fingerprint}…)",
                    name = w.name,
                    address = w.address,
                    fingerprint = w.host_key.chars().take(24).collect::<String>()
                ));
            }
            Ok(())
        }
        WorkersCommand::Destroy {
            provider,
            name,
            file,
        } => {
            let provisioner = provider_for(&provider)?;
            let evicted = provisioner.destroy(&name, Path::new(&file))?;
            crate::output::ok(destroy_summary(&name, evicted));
            Ok(())
        }
    }
}

/// The destroy summary line. An absent managed entry is reported honestly:
/// the server is gone, but nothing was evicted from the config.
fn destroy_summary(name: &str, evicted: bool) -> String {
    if evicted {
        format!("destroyed worker '{name}' and evicted its config entry")
    } else {
        format!("destroyed worker '{name}' — not managed by shuttle — nothing evicted")
    }
}

/// Provider dispatch. One new provider = one module + one arm here. The
/// operator login key resolves at this boundary (refusal names what was
/// tried) so the provider core never reads the environment.
fn provider_for(provider: &str) -> miette::Result<Box<dyn Provisioner>> {
    match provider {
        "hetzner" => Ok(Box::new(hetzner::HetznerProvisioner::new(
            crate::command::RealRunner,
            token_from_env(),
            default_binary_url(),
            resolve_operator_key()?,
        ))),
        "aws" => Ok(Box::new(aws::AwsProvisioner::new(
            crate::command::RealRunner,
            aws_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
        ))),
        "gcp" => Ok(Box::new(gcp::GcpProvisioner::new(
            crate::command::RealRunner,
            gcp_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
        ))),
        "azure" => Ok(Box::new(azure::AzureProvisioner::new(
            crate::command::RealRunner,
            azure_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
        ))),
        "scaleway" => Ok(Box::new(scaleway::ScalewayProvisioner::new(
            crate::command::RealRunner,
            scaleway_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
        ))),
        other => Err(miette::miette!(
            "workers: unknown provider '{other}' (supported: hetzner, aws, gcp, azure, scaleway)"
        )),
    }
}

/// The operator's authorized public key: `SHUTTLE_OPERATOR_KEY` names a
/// file explicitly; otherwise the default id_ed25519/id_rsa public halves
/// under `$HOME/.ssh`. Refusal names everything that was tried.
pub fn resolve_operator_key() -> miette::Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let candidates: Vec<PathBuf> = match std::env::var("SHUTTLE_OPERATOR_KEY").ok() {
        Some(p) => vec![PathBuf::from(p)],
        None => vec![
            Path::new(&home).join(".ssh").join("id_ed25519.pub"),
            Path::new(&home).join(".ssh").join("id_rsa.pub"),
        ],
    };
    let mut tried = Vec::new();
    for c in &candidates {
        match std::fs::read_to_string(c) {
            Ok(content) => {
                let line = content.lines().next().unwrap_or("").trim();
                if !line.is_empty() {
                    return Ok(line.to_string());
                }
                tried.push(format!("{} (empty)", c.display()));
            }
            Err(e) => tried.push(format!("{} ({e})", c.display())),
        }
    }
    Err(miette::miette!(
        "workers provision: no operator SSH public key found (tried {}) — set \
         SHUTTLE_OPERATOR_KEY to the .pub file workers must trust for login",
        tried.join("; ")
    ))
}

/// The managed-block markers in `shuttle.lua`. Everything between them is
/// shuttle-owned text, regenerated on every provision/destroy; everything
/// outside them is the operator's and is never rewritten.
pub const BLOCK_BEGIN: &str =
    "-- BEGIN shuttle workers (machine-managed; `shuttle workers provision`/`destroy` own this block)";
pub const BLOCK_END: &str = "-- END shuttle workers";

/// One request to provision workers. Provider-independent; the provider
/// module maps it onto its CLI.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    /// Server SKU — operator-supplied (`--type`), never hardcoded: Hetzner
    /// repriced/renamed the lineup 2026-06-15, so classes are whatever the
    /// account sells today (CX23/CX33/CAX11/CAX21 at reprice time).
    pub server_type: String,
    /// Provider location (e.g. Hetzner `hel1`).
    pub location: String,
    /// How many servers to create.
    pub count: u32,
    /// Worker lifetime in seconds — `--ttl`. Two stamps (the #269 v2
    /// contract): the provider's `shuttle-worker-ttl` label/tag
    /// (epoch-seconds expiry — the SOURCE OF TRUTH the sweep reads) and
    /// the in-guest `/etc/shuttle/worker-ttl` marker (one decimal
    /// EPOCH-SECONDS line — the sweep's `is_epoch` parses decimal only —
    /// a fallback COPY).
    pub ttl_secs: u64,
    /// `--spot`: request a provider spot/preemptible instance. Opt-in;
    /// on-demand hourly is the default (providers plan §1: spot is for
    /// eviction-tolerant lanes, per ADR-0040 Amendment 1 a spot eviction
    /// is T5 worker loss — re-dispatched, never migrated). A provider
    /// without a spot product refuses this flag rather than ignoring it.
    pub spot: bool,
    /// `--max-price`: the hourly USD cap a `--spot` instance may bid.
    /// Required with `--spot` (an uncapped bid is not a cap); refused
    /// without it (on-demand has no bid). Validated by the spot-capable
    /// provider before any API call.
    pub max_price: Option<String>,
    /// Dry run: resolve everything, render the user-data, print the plan —
    /// and exit before ANY provider API call (including the token check).
    pub dry_run: bool,
    /// Path to the config file the workers entries are pinned into.
    pub config: PathBuf,
}

/// What a dry run reports: every value a real run would use, including the
/// user-data hash (the plan lane's shape check), before any API call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPlan {
    pub server_type: String,
    pub location: String,
    pub count: u32,
    /// The base image the workers boot — the latest-Ubuntu-LTS pin
    /// (ADR-0046, never a codename); the provider module's SKU mapping.
    pub image: String,
    pub ttl_secs: u64,
    pub ttl_expiry_iso: String,
    pub binary_url: String,
    /// The `--max-price` cap when the plan is a spot plan, `None` for
    /// on-demand — the plan must show the bid the real run would place.
    pub spot_max_price: Option<String>,
    /// SHA-256 of the exact user-data blob a real run would send.
    pub user_data_sha256: String,
}

/// One provisioned worker, as pinned into config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedWorker {
    /// The provider-side server name (the `shuttle workers destroy` handle).
    pub name: String,
    /// The `ssh://` address written into the workers entry.
    pub address: String,
    /// The pinned public half (ADR-0045 Decision 4 grammar).
    pub host_key: String,
}

/// One cloud provider backend.
pub trait Provisioner {
    /// Create servers, mint + inject + pin their host keys. All-or-nothing:
    /// any failure after servers exist tears them down and leaves config
    /// untouched.
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>>;

    /// Destroy one server by name and evict its config entry. `Ok(true)`
    /// when a managed entry was evicted; `Ok(false)` when no managed
    /// entry carried the server's address (the caller decides the
    /// wording).
    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool>;
}

// ── Mint (ADR-0045 Decision 1) ──

/// The minted worker host keypair: the private half rides user-data into
/// the guest; the public half becomes the pin. Both die with the tempdir
/// after injection — the coordinator never needs the private half again
/// (it is a server-auth key, not a login credential).
pub struct MintedHostKey {
    pub private_pem: String,
    pub public_line: String,
}

/// Mint an ed25519 host keypair via `ssh-keygen` through the command seam.
/// The keypair lives entirely in `dir` (a tempdir the caller owns).
pub fn mint_host_keypair(runner: &dyn CommandRunner, dir: &Path) -> miette::Result<MintedHostKey> {
    let seed = dir.join("worker_host_ed25519");
    let seed_str = seed.to_string_lossy().into_owned();
    let argv = vec![
        "ssh-keygen".to_string(),
        "-t".to_string(),
        "ed25519".to_string(),
        "-N".to_string(),
        String::new(),
        "-C".to_string(),
        "shuttle-worker-host-key".to_string(),
        "-f".to_string(),
        seed_str,
    ];
    let out = runner.run(&argv).map_err(|e| {
        miette::miette!("provision: cannot run ssh-keygen (is openssh-client installed?): {e}")
    })?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "provision: ssh-keygen failed: {}",
            out.stderr.trim()
        ));
    }
    let private_pem = std::fs::read_to_string(&seed)
        .map_err(|e| miette::miette!("provision: minted host key is unreadable: {e}"))?;
    let public_line = std::fs::read_to_string(seed.with_file_name("worker_host_ed25519.pub"))
        .map_err(|e| miette::miette!("provision: minted host public key is unreadable: {e}"))?;
    Ok(MintedHostKey {
        private_pem: private_pem.trim_end().to_string(),
        public_line: public_line.trim_end().to_string(),
    })
}

/// Stage the user-data blob for the provider's create call INSIDE the mint
/// tempdir (`dir`), mode 0600. The blob carries the minted private host
/// half (server-auth, blast radius one machine per ADR-0045), so it must
/// never sit at a fixed world-readable temp path: the per-run tempdir
/// keeps concurrent provisions isolated, 0600 keeps it private while it
/// exists, and it dies with the keypair when the tempdir drops.
pub fn stage_user_data(dir: &Path, user_data: &str) -> miette::Result<PathBuf> {
    let path = dir.join("user-data.yaml");
    std::fs::write(&path, user_data)
        .map_err(|e| miette::miette!("provision: cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| miette::miette!("provision: cannot chmod 0600 {}: {e}", path.display()))?;
    }
    Ok(path)
}

// ── TTL (the #269 sweep contract) ──

/// Parse a `--ttl` duration: `<n><s|m|h|d>`, one unit, n > 0.
pub fn parse_ttl(raw: &str) -> miette::Result<u64> {
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    let n: u64 = digits
        .parse()
        .map_err(|_| miette::miette!("--ttl must be <n><s|m|h|d> (e.g. 4h, 30m), got '{raw}'"))?;
    if n == 0 {
        return Err(miette::miette!(
            "--ttl must be greater than zero, got '{raw}'"
        ));
    }
    let secs = match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86400),
        _ => None,
    }
    .ok_or_else(|| miette::miette!("--ttl overflows, got '{raw}'"))?;
    Ok(secs)
}

/// Format epoch seconds as one ISO-8601 UTC line — HUMAN DISPLAY ONLY
/// (the dry-run plan). Every on-the-wire TTL stamp (the hcloud label AND
/// the `/etc/shuttle/worker-ttl` marker) is decimal epoch seconds; the
/// sweep's `is_epoch` parses decimal only.
pub fn iso8601_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86400) as i64;
    let rem = epoch_secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's civil_from_days
/// (public domain), no calendar crate.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Now, in epoch seconds — split out so tests can pin the clock via
/// [`iso8601_utc`] and the real run stays honest.
pub fn now_epoch_secs() -> miette::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| miette::miette!("provision: system clock is before the epoch: {e}"))
}

// ── The shared cloud-init template ──

// The worker tool pins (providers plan §3, ticket #273). Both are
// compile-time constants on purpose: the template, the dry-run plan, and
// the coordinator-side admission checks all read the SAME values, so a
// pin bump is one commit that moves template + admission together.

/// The pinned mksquashfs, built from source in the template (pin 1).
/// Every stable distro ships 4.6.1; ADR-0041's zstd defaults make
/// mksquashfs behavior part of artifact identity, so the fleet runs one
/// source-built 4.7.x. The preflight admission refuses any worker whose
/// resolved mksquashfs reports anything else.
pub const SQUASHFS_TOOLS_VERSION: &str = "4.7.4";

/// The release date baked into the pinned build's version string. The
/// codeload tarball otherwise builds as `4.7.4-<hash>`; the template
/// forces the clean release form so `discover_version` reads exactly
/// [`SQUASHFS_TOOLS_VERSION`] on every worker.
pub const SQUASHFS_TOOLS_RELEASE_DATE: &str = "2025-11-09";

/// The pinned source tarball (GitHub codeload, tag `4.7.4`). Verified by
/// sha256 IN the template before a single byte is built.
pub const SQUASHFS_TOOLS_TARBALL_URL: &str =
    "https://codeload.github.com/plougher/squashfs-tools/tar.gz/refs/tags/4.7.4";

/// sha256 of [`SQUASHFS_TOOLS_TARBALL_URL`]'s exact bytes.
pub const SQUASHFS_TOOLS_SHA256: &str =
    "91c49f9a1ed972ad00688a38222119e2baf49ba74cf5fda05729a79d7d59d335";

/// Everything the template needs. Nothing here is optional: a provision
/// without a pin, a login key, or a TTL is not a shuttle worker.
pub struct UserDataParams<'a> {
    /// The minted PRIVATE host key (ADR-0045 D1: injected through the
    /// provider's authenticated channel, written 0600, scrubbed after
    /// sshd starts).
    pub host_private_key: &'a str,
    /// The minted PUBLIC host key line.
    pub host_public_key: &'a str,
    /// The operator's authorized public-key line — how the operator logs
    /// in (never the host key).
    pub operator_key: &'a str,
    /// The pinned shuttle binary URL cloud-init installs.
    pub binary_url: &'a str,
    /// TTL expiry as DECIMAL EPOCH SECONDS — the exact shape the #269
    /// sweep's `is_epoch` accepts for the `/etc/shuttle/worker-ttl`
    /// marker (one line). ISO-8601 here would leave the sweep's
    /// marker fallback rule dead code.
    pub ttl_expiry_epoch: u64,
}

/// Render the shared cloud-init user-data (ADR-0045 D1): the minted host
/// keypair lands in `/etc/ssh` (0600) before the ssh module runs
/// (`ssh_deletekeys: false` keeps cloud-init from regenerating it), the
/// operator authorized key grants login, the TTL marker is stamped as the
/// in-guest fallback COPY of the `shuttle-worker-ttl` label (the sweep's
/// source of truth), the worker tool pins are installed (#273: distro
/// bwrap + ca-certificates + curl, then the pinned squashfs-tools built
/// from source to /usr/local/bin with its version asserted), the pinned
/// shuttle binary is installed, sshd is hardened (key-only, root login by
/// key), and the guest's copy of this very blob is scrubbed once sshd is
/// up — the metadata service keeps serving user-data indefinitely, so the
/// private half must not linger there.
pub fn render_user_data(p: &UserDataParams<'_>) -> String {
    let mut s = String::from("#cloud-config\n");
    // cloud-init's ssh module must not delete/regenerate the injected key.
    s.push_str("ssh_deletekeys: false\n");
    s.push_str("write_files:\n");
    write_file(
        &mut s,
        "/etc/ssh/ssh_host_ed25519_key",
        "0600",
        p.host_private_key,
    );
    write_file(
        &mut s,
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "0644",
        p.host_public_key,
    );
    write_file(&mut s, "/root/.ssh/authorized_keys", "0600", p.operator_key);
    write_file(
        &mut s,
        "/etc/shuttle/worker-ttl",
        "0644",
        &p.ttl_expiry_epoch.to_string(),
    );
    s.push_str("runcmd:\n");
    // Pin 2 first: the distro packages every later step needs — bwrap
    // (it ships its own AppArmor profile, so the current Ubuntu LTS
    // userns restriction does not break it; the hardening stays, and
    // `apparmor_restrict_unprivileged_userns` is NEVER touched here),
    // plus the toolchain pin 1 builds against.
    s.push_str("  - apt-get update\n");
    s.push_str(
        "  - DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         bubblewrap ca-certificates curl build-essential liblz4-dev libzstd-dev liblzma-dev \
         zlib1g-dev\n",
    );
    // Pin 1: the source-built mksquashfs, fetched+verified+installed as
    // one fail-together step.
    s.push_str(&format!("  - {}\n", squashfs_build_runcmd()));
    s.push_str(&format!(
        "  - curl -fsSL {url} -o /usr/local/bin/shuttle\n",
        url = p.binary_url
    ));
    s.push_str("  - chmod 0755 /usr/local/bin/shuttle\n");
    s.push_str(
        "  - printf 'PermitRootLogin prohibit-password\\nPasswordAuthentication no\\n' \
         > /etc/ssh/sshd_config.d/99-shuttle-worker.conf\n",
    );
    s.push_str("  - systemctl restart ssh || systemctl restart sshd\n");
    // ADR-0045 D1: scrub the user-data blob once sshd serves the injected
    // key. NOTE (ADR-0045 addendum, 2026-09-28): this removes only the local
    // copy — Hetzner's metadata service serves the create-time blob for the
    // life of the server and re-serves it on rebuild; the private half must
    // be assumed recoverable in-guest for the machine's lifetime. See the
    // ADR addendum and the generate-and-publish proposal (#283).
    s.push_str(
        "  - sh -c 'rm -f /var/lib/cloud/instances/*/user-data.txt /var/lib/cloud/instance/user-data.txt'\n",
    );
    s
}

fn write_file(s: &mut String, path: &str, mode: &str, content: &str) {
    s.push_str(&format!(
        "  - path: {path}\n    permissions: \"{mode}\"\n    content: |\n"
    ));
    for line in content.lines() {
        s.push_str(&format!("      {line}\n"));
    }
}

/// The single `sh -c` runcmd that installs pin 1 (providers plan §3):
/// fetch the pinned squashfs-tools tarball, verify its sha256 BEFORE
/// anything runs, build against lz4/zstd/xz with the release VERSION
/// forced (the codeload tarball otherwise bakes the commit hash into the
/// version string — the fleet pin must read exactly
/// [`SQUASHFS_TOOLS_VERSION`]), `make install` to /usr/local/bin
/// (PATH-precedence over the distro's 4.6.1), and fail the step unless
/// the built binary reports the pin. One step, because the tool pin
/// succeeds or fails as a unit in the cloud-init log; a worker that
/// missed it is refused at preflight by design (admission is
/// fail-closed).
fn squashfs_build_runcmd() -> String {
    let tarball = format!("squashfs-tools-{SQUASHFS_TOOLS_VERSION}.tar.gz");
    let srcdir = format!("squashfs-tools-{SQUASHFS_TOOLS_VERSION}");
    format!(
        "sh -c 'set -e; cd /tmp; \
         curl -fsSL {SQUASHFS_TOOLS_TARBALL_URL} -o {tarball}; \
         echo \"{SQUASHFS_TOOLS_SHA256}  {tarball}\" | sha256sum -c -; \
         tar -xzf {tarball}; \
         make -C {srcdir}/squashfs-tools XZ_SUPPORT=1 ZSTD_SUPPORT=1 LZ4_SUPPORT=1 LZO_SUPPORT=0 \
         RELEASE_VERSION={SQUASHFS_TOOLS_VERSION} RELEASE_DATE={SQUASHFS_TOOLS_RELEASE_DATE} \
         -j\"$(nproc)\"; \
         make -C {srcdir}/squashfs-tools install; \
         /usr/local/bin/mksquashfs -version | grep -q \"version {SQUASHFS_TOOLS_VERSION} \"; \
         rm -rf /tmp/{srcdir} /tmp/{tarball}'"
    )
}

// ── The managed `workers` block in shuttle.lua ──

/// Append (or replace, when the address is already pinned in the managed
/// block) one workers entry. The surrounding operator text is never
/// rewritten; an operator-owned entry at the same address is a refusal —
/// shuttle owns only its block.
pub fn append_worker_entry(config: &Path, address: &str, host_key: &str) -> miette::Result<()> {
    let text = read_config(config)?;
    let block = block_line_range(&text)?;
    if outside_block_contains(&text, block, &format!("address = {}", lua_quote(address))) {
        return Err(miette::miette!(
            "provision: {} already pins a worker at {address} outside the shuttle-managed \
             block — shuttle never rewrites operator text; remove or move the entry first",
            config.display()
        ));
    }
    let mut entries = parse_managed_entries(&text, block)?;
    entries.retain(|e| e.address != address);
    entries.push(ManagedEntry {
        address: address.to_string(),
        host_key: host_key.to_string(),
    });
    write_config(config, &rebuild(&text, block, &entries)?)?;
    Ok(())
}

/// Evict one managed entry by address. `Ok(false)` when no managed entry
/// carries it (the caller decides whether that is a warning).
pub fn evict_worker_entry(config: &Path, address: &str) -> miette::Result<bool> {
    let text = read_config(config)?;
    let block = block_line_range(&text)?;
    let mut entries = parse_managed_entries(&text, block)?;
    let before = entries.len();
    entries.retain(|e| e.address != address);
    if entries.len() == before {
        return Ok(false);
    }
    write_config(config, &rebuild(&text, block, &entries)?)?;
    Ok(true)
}

/// True when the config carries a MANAGED entry at `address` — the
/// idempotent re-provision check.
pub fn managed_entry_exists(config: &Path, address: &str) -> miette::Result<bool> {
    let text = read_config(config)?;
    let block = block_line_range(&text)?;
    Ok(parse_managed_entries(&text, block)?
        .iter()
        .any(|e| e.address == address))
}

/// One entry inside the managed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedEntry {
    pub address: String,
    pub host_key: String,
}

fn read_config(config: &Path) -> miette::Result<String> {
    std::fs::read_to_string(config).map_err(|e| {
        miette::miette!(
            "provision: cannot read the worker config {}: {e}",
            config.display()
        )
    })
}

/// Atomically replace `config` (tempfile + rename, the known_hosts-pin
/// pattern) so a crashed provision never leaves a torn config. The
/// operator's file mode survives: a NamedTempFile is 0600, and persisting
/// it as-is would silently tighten every rewritten shuttle.lua.
fn write_config(config: &Path, content: &str) -> miette::Result<()> {
    let dir = config.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| miette::miette!("provision: cannot stage {}: {e}", config.display()))?;
    use std::io::Write;
    tmp.write_all(content.as_bytes())
        .and_then(|_| tmp.flush())
        .map_err(|e| miette::miette!("provision: cannot write {}: {e}", config.display()))?;
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(config) {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(meta.permissions().mode()))
            .map_err(|e| {
                miette::miette!(
                    "provision: cannot preserve the mode of {}: {e}",
                    config.display()
                )
            })?;
    }
    tmp.persist(config).map_err(|e| {
        miette::miette!(
            "provision: cannot install {}: {}",
            config.display(),
            e.error
        )
    })?;
    Ok(())
}

/// Which managed-block marker a line carries.
enum Marker {
    None,
    Begin,
    End,
}

fn marker_kind(line: &str) -> Marker {
    match line.trim() {
        t if t == BLOCK_BEGIN => Marker::Begin,
        t if t == BLOCK_END => Marker::End,
        _ => Marker::None,
    }
}

/// The (begin, end) LINE indexes of the managed block, when present.
/// Two blocks, or an unpaired marker, is a corrupt file — refuse.
fn block_line_range(text: &str) -> miette::Result<Option<(usize, usize)>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut begin: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        match (marker_kind(line), begin) {
            (Marker::Begin, None) => begin = Some(i),
            (Marker::End, Some(b)) => return Ok(Some((b, i))),
            (Marker::None, _) => {}
            _ => {
                return Err(miette::miette!(
                    "the shuttle-managed workers block in this config is duplicated or \
                     unpaired — fix the block by hand (keep exactly one {}…{} pair)",
                    BLOCK_BEGIN,
                    BLOCK_END
                ))
            }
        }
    }
    Ok(None)
}

/// Parse every `table.insert(workers, ...)` line in the managed block.
/// Anything else non-empty inside the block is a hand edit — refuse rather
/// than silently rewriting operator bytes.
fn parse_managed_entries(
    text: &str,
    block: Option<(usize, usize)>,
) -> miette::Result<Vec<ManagedEntry>> {
    let mut entries = Vec::new();
    let Some((begin, end)) = block else {
        return Ok(entries);
    };
    for line in text.lines().skip(begin + 1).take(end - begin - 1) {
        if line.trim().is_empty() || line.trim_start().starts_with("--") {
            continue;
        }
        let trimmed = line.trim();
        // The generated `workers` guard is block boilerplate, not an entry.
        if trimmed == "workers = workers or {}" {
            continue;
        }
        let Some(inner) = trimmed
            .strip_prefix("table.insert(workers, ")
            .and_then(|s| s.strip_suffix(')'))
        else {
            return Err(miette::miette!(
                "unexpected line inside the shuttle-managed workers block: '{trimmed}' — \
                 the block is shuttle-owned; move hand edits outside it"
            ));
        };
        let address = extract_quoted_field(inner, "address").ok_or_else(|| {
            miette::miette!("managed workers entry has no readable 'address': '{trimmed}'")
        })?;
        let host_key = extract_quoted_field(inner, "host_key").ok_or_else(|| {
            miette::miette!("managed workers entry has no readable 'host_key': '{trimmed}'")
        })?;
        entries.push(ManagedEntry { address, host_key });
    }
    Ok(entries)
}

/// Extract one `key = "..."` field from a generated entry body (escape-aware).
fn extract_quoted_field(inner: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = ");
    let start = inner.find(&needle)? + needle.len();
    let rest = inner.get(start..)?;
    let quote = rest.chars().next()?;
    if quote != '"' {
        return None;
    }
    let mut out = String::new();
    let mut chars = rest.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                let (_, esc) = chars.next()?;
                out.push(match esc {
                    'n' => '\n',
                    't' => '\t',
                    other => other,
                });
            }
            '"' => return Some(out),
            _ => {
                out.push(c);
                let _ = i;
            }
        }
    }
    None
}

/// True when `needle` appears in any line OUTSIDE the managed block.
fn outside_block_contains(text: &str, block: Option<(usize, usize)>, needle: &str) -> bool {
    for (i, line) in text.lines().enumerate() {
        if let Some((b, e)) = block {
            if i > b && i < e {
                continue;
            }
        }
        if line.contains(needle) {
            return true;
        }
    }
    false
}

/// Rebuild the config text with the managed block holding exactly
/// `entries`. Insertion point for a fresh block: immediately before the
/// top-level `return` (a chunk cannot execute statements after it), else
/// EOF.
fn rebuild(
    text: &str,
    block: Option<(usize, usize)>,
    entries: &[ManagedEntry],
) -> miette::Result<String> {
    if let Some((begin, end)) = block {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = String::with_capacity(text.len() + block_text_len(entries));
        push_lines(&mut out, &lines[..begin]);
        if !entries.is_empty() {
            out.push_str(&render_block(entries));
            out.push('\n');
        }
        push_lines(&mut out, &lines[end + 1..]);
        return Ok(out);
    }
    if entries.is_empty() {
        return Ok(text.to_string());
    }
    let block_text = render_block(entries);
    match scan_top_level_return(text) {
        Some(off) => {
            let line_start = text[..off].rfind('\n').map(|i| i + 1).unwrap_or(0);
            if !text[line_start..off].trim().is_empty() {
                return Err(miette::miette!(
                    "cannot place the shuttle-managed workers block: this config has a \
                     top-level `return` sharing its line with other code — put the return \
                     on its own line and retry"
                ));
            }
            let mut out = String::with_capacity(text.len() + block_text.len() + 2);
            out.push_str(&text[..line_start]);
            out.push_str(&block_text);
            out.push('\n');
            out.push_str(&text[line_start..]);
            Ok(out)
        }
        None => {
            let mut out = String::from(text);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str(&block_text);
            out.push('\n');
            Ok(out)
        }
    }
}

fn block_text_len(entries: &[ManagedEntry]) -> usize {
    if entries.is_empty() {
        0
    } else {
        512
    }
}

/// The managed block itself: the markers, the `workers` guard (a config
/// with no workers declaration gets the global created), one
/// `table.insert` per entry.
fn render_block(entries: &[ManagedEntry]) -> String {
    let mut s = String::from(BLOCK_BEGIN);
    s.push('\n');
    s.push_str("workers = workers or {}\n");
    for e in entries {
        s.push_str(&format!(
            "table.insert(workers, {{ address = {addr}, host_key = {key} }})\n",
            addr = lua_quote(&e.address),
            key = lua_quote(&e.host_key)
        ));
    }
    s.push_str(BLOCK_END);
    s
}

fn push_lines(out: &mut String, lines: &[&str]) {
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
}

/// Lua short-string literal: escape `\` and `"` (the only bytes the entry
/// grammar can carry that would break the quoting).
fn lua_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Byte offset of the top-level `return` keyword — string/comment/bracket
/// aware, depth tracked over `(`/`[`/`{`. A Lua chunk can hold at most one
/// (the chunk is one block), so the first hit is the one that executes.
fn scan_top_level_return(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut i = 0usize;
    let mut depth: i64 = 0;
    while i < b.len() {
        match b[i] {
            b'-' if b.get(i + 1) == Some(&b'-') => {
                if let Some(level) = long_open(b, i + 2) {
                    i = skip_long_bracket(b, i + 2, level);
                } else {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
            }
            q @ (b'\'' | b'"') => {
                i = skip_short_string(b, i, q);
            }
            b'[' => match long_open(b, i) {
                Some(level) => i = skip_long_bracket(b, i, level),
                None => {
                    depth += 1;
                    i += 1;
                }
            },
            b'(' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'r' if depth == 0 && is_word_at(b, i, b"return") => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// `[==[` at `i` → Some(level) where level is the `=` count.
fn long_open(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'[') {
        return None;
    }
    let mut j = i + 1;
    while b.get(j) == Some(&b'=') {
        j += 1;
    }
    if b.get(j) == Some(&b'[') {
        Some(j - i - 1)
    } else {
        None
    }
}

/// From the opening `[`[=]*, return the index just past the matching
/// close. Unterminated → end of text.
fn skip_long_bracket(b: &[u8], open: usize, level: usize) -> usize {
    let close: Vec<u8> = std::iter::once(b']')
        .chain(std::iter::repeat_n(b'=', level))
        .chain(std::iter::once(b']'))
        .collect();
    let mut i = open;
    while i < b.len() {
        if b[i..].starts_with(&close) {
            return i + close.len();
        }
        i += 1;
    }
    b.len()
}

/// From the opening quote, past escapes, to the closing quote (or newline
/// — Lua rejects it, we just stop).
fn skip_short_string(b: &[u8], open: usize, quote: u8) -> usize {
    let mut i = open + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\n' => return i + 1,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

fn is_word_at(b: &[u8], i: usize, word: &[u8]) -> bool {
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    if !b[i..].starts_with(word) {
        return false;
    }
    if i > 0 && ident(b[i - 1]) {
        return false;
    }
    b.get(i + word.len()).is_none_or(|&c| !ident(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes the env-mutating tests (process-global state).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn ttl_parses_single_unit_durations() {
        assert_eq!(parse_ttl("4h").unwrap(), 14_400);
        assert_eq!(parse_ttl("24h").unwrap(), 86_400);
        assert_eq!(parse_ttl("30m").unwrap(), 1_800);
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("4x").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("-4h").is_err());
    }

    #[test]
    fn iso8601_utc_formats_the_human_display_shape() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(86_400), "1970-01-02T00:00:00Z");
        // Leap-year day (2024-02-29).
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn destroy_summary_reports_an_absent_entry_honestly() {
        assert_eq!(
            destroy_summary("shuttle-worker-x-01", true),
            "destroyed worker 'shuttle-worker-x-01' and evicted its config entry"
        );
        let absent = destroy_summary("shuttle-worker-x-01", false);
        assert!(absent.contains("not managed by shuttle"), "{absent}");
        assert!(absent.contains("nothing evicted"), "{absent}");
    }

    #[test]
    fn token_from_env_trims_and_treats_empty_as_absent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY (test-only): single-threaded under ENV_LOCK.
        std::env::remove_var("HCLOUD_TOKEN");
        assert!(token_from_env().is_none());
        std::env::set_var("HCLOUD_TOKEN", "   ");
        assert!(token_from_env().is_none());
        std::env::set_var("HCLOUD_TOKEN", " tok ");
        assert_eq!(token_from_env().as_deref(), Some("tok"));
        std::env::remove_var("HCLOUD_TOKEN");
    }

    #[test]
    fn operator_key_resolves_from_the_explicit_file() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("op.pub");
        std::fs::write(&key, "ssh-ed25519 AAAAoperator test@host\n").unwrap();
        std::env::set_var("SHUTTLE_OPERATOR_KEY", &key);
        assert_eq!(
            resolve_operator_key().unwrap(),
            "ssh-ed25519 AAAAoperator test@host"
        );
        std::env::remove_var("SHUTTLE_OPERATOR_KEY");
    }

    #[test]
    fn operator_key_refusal_names_what_was_tried() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // SAFETY (test-only): single-threaded under ENV_LOCK.
        std::env::set_var("SHUTTLE_OPERATOR_KEY", dir.path().join("absent.pub"));
        let err = format!("{}", resolve_operator_key().unwrap_err());
        std::env::remove_var("SHUTTLE_OPERATOR_KEY");
        assert!(err.contains("absent.pub"), "refusal names the file: {err}");
        assert!(err.contains("SHUTTLE_OPERATOR_KEY"), "{err}");
    }
}
