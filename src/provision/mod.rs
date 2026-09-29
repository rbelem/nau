//! The Provisioner seam (T6, ADR-0040 as rewritten by ADR-0045's
//! amendment): turn a cloud account into a pinned `workers` entry in the
//! operator's `nau.lua`, and take it back.
//!
//! Shape, fixed by the ratified amendment (#283 decided, #295 in
//! flight): the guest GENERATES its SSH host keypair locally on first
//! boot (cloud-init `ssh_genkey` — no private half is ever minted
//! coordinator-side or shipped through user-data), then publishes the
//! PUBLIC half to the coordinator over the one-time provisioning token
//! ([`publish`] — the same authenticated create-time channel, now
//! carrying public material only). Provision resolves before any API
//! call, pins the host CA's fingerprint into the appended workers entry
//! (the pin exists before first use — `@cert-authority` semantics land
//! with #295 sub-task 4), and `ssh-keyscan` is never called. A provision
//! that fails after servers exist tears them down: nothing survives
//! unpinned.
//!
//! One provider module per cloud, each driving the provider's CLI through
//! [`crate::command::CommandRunner`] (the repo's subprocess convention —
//! zero new crates, the avahi-fallback precedent). The shared pieces live
//! here: the [`Provisioner`] trait, the TTL vocabulary the #269 sweep
//! reads, and the shared cloud-init template.
//!
//! Secrets never enter `nau.lua`: the config carries only the CA
//! fingerprint pin and the address. Nothing secret rides user-data at
//! all — the one-time publish token is the only bearer it carries, and
//! it dies at the first accepted publish.
//!
//! **Epic #295 state (all five sub-tasks landed)**: the CA flow works
//! end to end and is the ONLY flow — guest gen → publish → issue →
//! pickup → cert served → the coordinator connects with a
//! `@cert-authority` pin built from the CA fingerprint (the machine
//! linkage under `ca/machines/` binds each pinned address to its
//! certificate principal). Mint-and-inject is retired: nothing here
//! ever mints or injects a host key, and config pins that predate the
//! amendment refuse at parse with the re-pin remedy.

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod hetzner;
pub mod publish;
pub mod scaleway;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::cli::WorkersCommand;

/// `--wait` cadence and default ceiling (#299): guests publish their host
/// key 1-4 min after server create (boot + binary download); ten minutes
/// covers a slow boot without hanging the operator's shell forever.
pub const ISSUE_WAIT_DEFAULT_TIMEOUT_SECS: u64 = 600;
pub const ISSUE_WAIT_POLL: Duration = Duration::from_secs(5);

/// The default nau binary URL the template installs: the project
/// release artifact for the running version. Override with
/// `NAU_WORKER_BINARY_URL` (e.g. a pod- or cache-pinned copy) until
/// release infra carries it.
fn default_binary_url() -> String {
    if let Ok(url) = std::env::var("NAU_WORKER_BINARY_URL") {
        if !url.trim().is_empty() {
            return url;
        }
    }
    format!(
        "https://github.com/rbelem/nau/releases/download/v{version}/nau-{arch}",
        version = env!("CARGO_PKG_VERSION"),
        arch = crate::snap::host_arch()
    )
}

/// The prebuilt mksquashfs/unsquashfs artifact base URL the template
/// installs (ticket #300): the pin's binaries ride the SAME publish
/// front as the worker binary (`/bin/mksquashfs`, `/bin/unsquashfs` —
/// scripts/build-mksquashfs-artifact.sh output). Override with
/// `NAU_MKSQUASHFS_ARTIFACT_URL` (e.g. the funnel host's `/bin`) until
/// release infra carries the artifact.
fn default_squashfs_artifact_url() -> String {
    if let Ok(url) = std::env::var("NAU_MKSQUASHFS_ARTIFACT_URL") {
        let trimmed = url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!(
        "https://github.com/rbelem/nau/releases/download/v{version}",
        version = env!("CARGO_PKG_VERSION"),
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

/// CLI entry for `nau workers provision` / `nau workers destroy` /
/// `nau workers receive-publish`.
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
                ca_fingerprint: run_ca_fingerprint(dry_run)?,
            };
            provision_main(&provider, req, run_publish_channel(dry_run)?)
        }
        WorkersCommand::Destroy {
            provider,
            name,
            file,
        } => {
            let provisioner = provider_for(&provider, None)?;
            let evicted = provisioner.destroy(&name, Path::new(&file))?;
            crate::output::ok(destroy_summary(&name, evicted));
            Ok(())
        }
        WorkersCommand::ReceivePublish => receive_publish_main(),
        WorkersCommand::Issue {
            home,
            identity,
            validity,
            force,
            json,
            wait,
            timeout,
        } => issue_main(
            home,
            identity.as_deref(),
            &validity,
            force,
            json,
            wait,
            timeout,
        ),
        WorkersCommand::Pickup { home } => pickup_main(home),
        WorkersCommand::Burst {
            provider,
            server_type,
            location,
            count,
            max,
            ttl,
            timeout,
            keep,
            file,
            command,
        } => burst_main(
            &provider,
            server_type,
            location,
            count,
            max,
            &ttl,
            timeout,
            keep,
            &file,
            command,
        ),
        WorkersCommand::Down { provider, file, .. } => down_all_managed_main(&provider, &file),
    }
}

/// The provision verb body: dispatch the provider, run it, report the
/// pins.
fn provision_main(
    provider: &str,
    req: ProvisionRequest,
    publish: Option<publish::PublishChannel>,
) -> miette::Result<()> {
    // The nudge below reads the pending store after the run, so the
    // channel clones into the provider (which stores it).
    let provisioner = provider_for(provider, publish.clone())?;
    let workers = provisioner.provision(&req)?;
    for w in &workers {
        crate::output::ok(format!(
            "provisioned worker '{name}' — pinned {address} (host CA {fingerprint}…)",
            name = w.name,
            address = w.address,
            fingerprint = w.host_key.chars().take(24).collect::<String>()
        ));
    }
    // The #299 race made visible: a pending entry visible NOW was
    // published during the run and is still unsigned — name the fix in
    // the summary instead of letting the operator discover the silent
    // no-op after the guests give up polling.
    if let Some(channel) = &publish {
        if let Some(nudge) = issue_wait_nudge(&channel.home) {
            crate::output::info(nudge);
        }
    }
    Ok(())
}

/// The publish channel a REAL provision runs with, resolved at this CLI
/// boundary (`None` for a dry run: a plan makes no API call, ships no
/// user-data, and pins nothing).
fn run_publish_channel(dry_run: bool) -> miette::Result<Option<publish::PublishChannel>> {
    if dry_run {
        return Ok(None);
    }
    Ok(Some(publish::resolve_publish_channel()?))
}

/// The host CA fingerprint a REAL provision pins (the workers entry's
/// mandatory `host_key` value under the amendment). `None` for a dry run.
fn run_ca_fingerprint(dry_run: bool) -> miette::Result<Option<String>> {
    if dry_run {
        return Ok(None);
    }
    Ok(Some(resolve_ca_fingerprint()?))
}

/// The host CA's ssh-keygen fingerprint, from the ceremony home
/// (`~/.config/nau/ca`): the workers pin IS this fingerprint under
/// the amendment, so a real provision without a ceremony is a named
/// refusal before any API call — fail-closed, never a pinless worker.
pub fn resolve_ca_fingerprint() -> miette::Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    match crate::ca::inspect(&crate::command::RealRunner, Path::new(&home))? {
        Some(info) => Ok(info.fingerprint),
        None => Err(miette::miette!(
            "workers provision: no host CA at {home}/.config/nau/ca — run 'nau ca \
             keygen' first; provision pins the CA fingerprint (ADR-0045 amendment) and \
             issuance signs with its private half"
        )),
    }
}

/// The `receive-publish` verb body: one guest publish from stdin, bearer
/// token in `NAU_PUBLISH_TOKEN`. This is the transport binding any
/// TLS-terminating front drives; the network listener itself is sub-task
/// 3's surface (issuance).
fn receive_publish_main() -> miette::Result<()> {
    use std::io::Read;
    let token = std::env::var("NAU_PUBLISH_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "receive-publish: no bearer token — set NAU_PUBLISH_TOKEN (the front \
                 that terminates the guest's POST extracts it from the Authorization header)"
            )
        })?;
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut payload = Vec::new();
    std::io::stdin()
        .read_to_end(&mut payload)
        .map_err(|e| miette::miette!("receive-publish: cannot read the payload on stdin: {e}"))?;
    let identity = publish::receive_publish(Path::new(&home), &token, &payload, now_epoch_secs()?)?;
    crate::output::ok(format!(
        "stored pending identity '{identity}' — run 'nau workers issue' to sign its \
         host certificate"
    ));
    Ok(())
}

/// The `issue` verb body: sign short-lived host certificates for pending
/// identities (all of them by default, one with `--identity`). Issued
/// identities leave the pending store into the issued record — the audit
/// trail — and their guests pick the certificates up through
/// [`pickup_main`].
fn issue_main(
    home: Option<String>,
    identity: Option<&str>,
    validity: &str,
    force: bool,
    json: bool,
    wait: bool,
    timeout_secs: u64,
) -> miette::Result<()> {
    crate::output::set_mode(json);
    let home = home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    let report = run_issue(&home, identity, validity, force, wait, timeout_secs)?;
    for issued in &report.issued {
        crate::output::ok(format!(
            "issued host certificate for '{id}' — principals [{principals}], validity \
             {validity}, CA {fingerprint}",
            id = issued.machine_identity,
            principals = issued.principals.join(","),
            validity = issued.validity,
            fingerprint = issued.ca_fingerprint
        ));
        crate::output::info(
            "the guest picks it up: GET the publish URL with its one-time token \
             (nau workers pickup)"
                .to_string(),
        );
    }
    for skipped in &report.skipped {
        crate::output::warn(format!(
            "skipped '{skipped}' — already issued (--force to re-issue; pickup serves the \
             certificate)"
        ));
    }
    if crate::output::is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "issued": report.issued.iter().map(|i| serde_json::json!({
                    "machine_identity": i.machine_identity,
                    "principals": i.principals,
                    "validity": i.validity,
                    "cert": i.cert,
                    "ca_fingerprint": i.ca_fingerprint,
                    "issued_at_epoch": i.issued_at_epoch,
                    "record": publish::issued_dir(&home).join(format!("issued-{}.json", i.machine_identity)).display().to_string(),
                })).collect::<Vec<_>>(),
                "skipped": report.skipped,
            }))
            .map_err(|e| miette::miette!("issue: cannot serialize the report: {e}"))?
        );
    }
    Ok(())
}

/// The issue run behind the report: one batch over the pending store, or
/// the `--wait` polling loop when the operator asked to wait publishes
/// out (#299).
fn run_issue(
    home: &Path,
    identity: Option<&str>,
    validity: &str,
    force: bool,
    wait: bool,
    timeout_secs: u64,
) -> miette::Result<publish::IssueReport> {
    // --wait waits for publishes that have not landed; --identity names
    // one that has. The combination has no single meaning — refuse it
    // rather than guess which window the operator meant.
    if wait && identity.is_some() {
        return Err(miette::miette!(
            "issue: --wait and --identity do not combine — --wait signs every identity \
             published during the window; name one machine only after its publish landed \
             (the pending store lists what is signable now)"
        ));
    }
    if wait {
        return issue_wait(
            &crate::command::RealRunner,
            home,
            validity,
            force,
            Duration::from_secs(timeout_secs),
            ISSUE_WAIT_POLL,
            now_epoch_secs()?,
        );
    }
    publish::issue_identities(
        &crate::command::RealRunner,
        home,
        identity,
        validity,
        force,
        now_epoch_secs()?,
    )
}

/// The `pickup` verb body: the GET half of the publish callback URL.
/// Bearer in `NAU_PUBLISH_TOKEN` (the same one-time token the guest
/// published under); the certificate goes to STDOUT — pure certificate
/// text, the artifact the guest installs — status lines to stderr. A
/// refusal is a nonzero exit, which the guest's bounded-retry loop
/// reads as "not yet / not ever".
fn pickup_main(home: Option<String>) -> miette::Result<()> {
    let token = std::env::var("NAU_PUBLISH_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "pickup: no bearer token — set NAU_PUBLISH_TOKEN (the front that \
                 terminates the guest's GET extracts it from the Authorization header)"
            )
        })?;
    let home = home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())));
    let issued = publish::pickup_certificate(&home, &token, now_epoch_secs()?)?;
    crate::output::ok(format!(
        "serving the host certificate for '{}'",
        issued.machine_identity
    ));
    println!("{}", issued.cert);
    Ok(())
}

/// The `--wait` polling loop (#299): sign every identity the guests
/// publish within the window. The pending store is re-read each poll, so
/// a publish that lands after the run started is still signed — that is
/// the provision→issue race. Exits once every identity observed so far is
/// resolved (signed, or deliberately skipped as already issued); the
/// timeout is a LOUD named failure naming the waited-for identities,
/// never a silent nothing-signed.
pub fn issue_wait(
    runner: &dyn crate::command::CommandRunner,
    home: &Path,
    validity: &str,
    force: bool,
    timeout: Duration,
    poll: Duration,
    now_epoch: u64,
) -> miette::Result<publish::IssueReport> {
    let deadline = Instant::now() + timeout;
    let mut report = publish::IssueReport::default();
    let mut seen: Vec<String> = Vec::new();
    loop {
        for entry in publish::pending_identities(home)? {
            if !seen.contains(&entry.machine_identity) {
                seen.push(entry.machine_identity);
            }
        }
        let batch = publish::issue_identities(runner, home, None, validity, force, now_epoch)?;
        report.issued.extend(batch.issued);
        report.skipped.extend(batch.skipped);
        if !seen.is_empty() && wait_all_resolved(&seen, &report) {
            return Ok(report);
        }
        if Instant::now() >= deadline {
            let waited = if seen.is_empty() {
                "no identity ever published".to_string()
            } else {
                format!("identities waited for: [{}]", seen.join(", "))
            };
            return Err(miette::miette!(
                "issue --wait: timed out after {secs}s — {waited}; the guest publish never \
                 landed in {dir} (guests publish 1-4 min after server create — check the \
                 guest's publish attempt and the front's receive-publish wiring)",
                secs = timeout.as_secs(),
                dir = publish::pending_dir(home).display()
            ));
        }
        std::thread::sleep(poll);
    }
}

/// True when every identity the wait observed is accounted for in the
/// report — signed, or skipped as already issued (`--force` not given).
fn wait_all_resolved(seen: &[String], report: &publish::IssueReport) -> bool {
    seen.iter().all(|name| {
        report.issued.iter().any(|i| i.machine_identity == *name)
            || report.skipped.iter().any(|s| s == name)
    })
}

/// The end-of-provision nudge (#299): when the pending store already
/// holds unsigned identities, name `nau workers issue --wait` in the
/// summary — the moment the operator still remembers the publish/issue
/// race exists. Best-effort: an unreadable store skips the line, because
/// issuance itself fails closed on the same corruption and the provision
/// pins are already durable.
pub fn issue_wait_nudge(home: &Path) -> Option<String> {
    let pending = publish::pending_identities(home).ok()?;
    let count = pending.len();
    (!pending.is_empty()).then(|| {
        format!(
            "{count} published host key(s) awaiting a signature — run \
             'nau workers issue --wait' to sign each as its publish lands"
        )
    })
}

// ── Burst + down (#301): the one-command build window ──

/// Per-worker `issue --wait` budget ADDED to the operator's ceiling:
/// each guest publishes 1-4 min after create, so the effective window
/// scales with the count and a big burst never times out on queueing
/// alone.
const BURST_ISSUE_WAIT_SECS_PER_WORKER: u64 = 180;

/// The SIGINT trap's target: the wrapped command's pid while it runs, 0
/// otherwise. Async-signal-safe by construction — one atomic read.
static BURST_CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn burst_forward_sigint(_: libc::c_int) {
    // Forward to the child: its death unblocks the parent's wait() into
    // the burst teardown, so cleanup fires on Ctrl-C exactly as on any
    // other command failure.
    let pid = BURST_CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGINT) };
    }
}

/// The `--max` guardrail: a count above it is a named refusal BEFORE any
/// API call — raising the guard is a deliberate act, never a typo.
pub fn refuse_burst_above_max(count: u32, max: u32) -> miette::Result<()> {
    if count > max {
        return Err(miette::miette!(
            "workers burst: count {count} exceeds --max {max} — each burst worker bills \
             hourly; raise --max only when the fleet really needs it"
        ));
    }
    Ok(())
}

/// The `burst` verb body: build the request exactly like `workers
/// provision`, resolve the real publish channel + provisioner, and run
/// the burst window. A nonzero wrapped-command exit code becomes the
/// process exit code — after the teardown has run.
#[allow(clippy::too_many_arguments)]
fn burst_main(
    provider: &str,
    server_type: String,
    location: String,
    count: u32,
    max: u32,
    ttl: &str,
    timeout_secs: u64,
    keep: bool,
    file: &str,
    command: Vec<String>,
) -> miette::Result<()> {
    refuse_burst_above_max(count, max)?;
    if command.is_empty() {
        // Unreachable through clap (`num_args(1..)`); kept fail-closed
        // for direct callers.
        return Err(miette::miette!(
            "workers burst: no wrapped command — give it after '--'"
        ));
    }
    let req = ProvisionRequest {
        server_type,
        location,
        count,
        ttl_secs: parse_ttl(ttl)?,
        spot: false,
        max_price: None,
        dry_run: false,
        config: PathBuf::from(file),
        ca_fingerprint: run_ca_fingerprint(false)?,
    };
    let channel = run_publish_channel(false)?;
    let publish_home = match &channel {
        Some(c) => c.home.clone(),
        None => {
            return Err(miette::miette!(
                "workers burst: no publish channel — a burst pins and issues like a \
                 real provision, never a dry run"
            ))
        }
    };
    let provisioner = provider_for(provider, channel)?;
    let code = run_burst(
        provisioner.as_ref(),
        &crate::command::RealRunner,
        &publish_home,
        &req,
        Duration::from_secs(timeout_secs.max(BURST_ISSUE_WAIT_SECS_PER_WORKER * u64::from(count))),
        keep,
        &command,
    )?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// The burst window (the testable core — provisioner, signer, and
/// publish home are injected). Order is fixed: provision → issue --wait
/// → run → destroy+evict. Everything after the provision runs under the
/// teardown, so a refused issue window or a failing command still
/// reclaims the workers unless `--keep` parks them.
pub fn run_burst(
    provisioner: &dyn Provisioner,
    signer: &dyn crate::command::CommandRunner,
    publish_home: &Path,
    req: &ProvisionRequest,
    issue_timeout: Duration,
    keep: bool,
    command: &[String],
) -> miette::Result<i32> {
    if command.is_empty() {
        return Err(miette::miette!(
            "workers burst: no wrapped command — give it after '--'"
        ));
    }
    // Same managed-block pinning as `workers provision` — the burst is
    // that verb plus a window and a teardown, nothing more.
    let workers = provisioner.provision(req)?;
    for w in &workers {
        crate::output::ok(format!(
            "burst worker '{name}' provisioned — pinned {address}",
            name = w.name,
            address = w.address
        ));
    }

    let window = || -> miette::Result<i32> {
        // Sign each host certificate as its publish lands (#299's loop —
        // the ceremony compression IS this verb's reason to exist).
        let report = issue_wait(
            signer,
            publish_home,
            publish::HOST_CERT_VALIDITY_DEFAULT,
            false,
            issue_timeout,
            ISSUE_WAIT_POLL,
            now_epoch_secs()?,
        )?;
        crate::output::ok(format!(
            "burst: {} host certificate(s) issued — the workers are green",
            report.issued.len()
        ));
        run_wrapped(command)
    };
    let outcome = window();

    if keep {
        crate::output::info(format!(
            "burst: keeping {} worker(s) — tear them down later with \
             'nau workers down --all-managed'",
            workers.len()
        ));
        return outcome;
    }

    let stuck = destroy_burst_workers(provisioner, &req.config, &workers);
    let code = outcome?;
    if !stuck.is_empty() {
        // A clean command with a leaked worker is still a failure: the
        // leak bills hourly until the TTL sweep or a manual destroy.
        return Err(miette::miette!(
            "burst: the command exited 0, but {stuck_n} worker(s) survived the teardown: \
             [{stuck}] — destroy them by hand or let the TTL sweep reclaim them",
            stuck_n = stuck.len(),
            stuck = stuck.join(", ")
        ));
    }
    Ok(code)
}

/// Destroy every worker of a burst (newest first), reporting each.
/// Individual failures never stop the sweep — the stuck names come back
/// for the caller's final verdict.
fn destroy_burst_workers(
    provisioner: &dyn Provisioner,
    config: &Path,
    workers: &[ProvisionedWorker],
) -> Vec<String> {
    let mut stuck = Vec::new();
    for w in workers.iter().rev() {
        match provisioner.destroy(&w.name, config) {
            Ok(evicted) => crate::output::ok(destroy_summary(&w.name, evicted)),
            Err(e) => {
                crate::output::warn(format!(
                    "burst teardown: worker '{}' survived: {e:#}",
                    w.name
                ));
                stuck.push(w.name.clone());
            }
        }
    }
    stuck
}

/// Run the wrapped command with inherited stdio under the SIGINT trap.
/// Returns the exit code to propagate (128+signal on a signal death).
fn run_wrapped(command: &[String]) -> miette::Result<i32> {
    let mut child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .map_err(|e| miette::miette!("burst: cannot run '{}': {e}", command.join(" ")))?;
    BURST_CHILD_PID.store(child.id() as i32, Ordering::SeqCst);
    // The trap lives exactly as long as the child: before it, the
    // default disposition ends the process (the TTL sweep reclaims
    // workers from an early Ctrl-C); after it, the teardown already ran.
    unsafe {
        libc::signal(
            libc::SIGINT,
            burst_forward_sigint as *const () as libc::sighandler_t,
        );
    }
    let status = child
        .wait()
        .map_err(|e| miette::miette!("burst: waiting on the wrapped command failed: {e}"))?;
    BURST_CHILD_PID.store(0, Ordering::SeqCst);
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    Ok(match status.code() {
        Some(code) => code,
        None => {
            use std::os::unix::process::ExitStatusExt;
            // Signal death: the conventional 128+signal the shell reports.
            128 + status.signal().unwrap_or(0)
        }
    })
}

/// The `down --all-managed` verb body: resolve the real publish channel
/// (the machine-linkage store names each pinned address's server) and
/// drain the block.
fn down_all_managed_main(provider: &str, file: &str) -> miette::Result<()> {
    let channel = run_publish_channel(false)?;
    let publish_home = match &channel {
        Some(c) => c.home.clone(),
        None => {
            return Err(miette::miette!(
                "workers down: no publish channel — the machine linkage that names each \
                 pinned server lives there"
            ))
        }
    };
    let provisioner = provider_for(provider, channel)?;
    run_down_all_managed(provisioner.as_ref(), &publish_home, Path::new(file))?;
    Ok(())
}

/// Drain the managed block (the testable core): resolve each entry's
/// server name through the machine linkage, destroy it, evict its pin.
/// An empty or absent block is a green no-op. Every entry is attempted
/// even when some fail — the run refuses only at the end, naming exactly
/// which addresses need a hand.
pub fn run_down_all_managed(
    provisioner: &dyn Provisioner,
    publish_home: &Path,
    config: &Path,
) -> miette::Result<usize> {
    let entries = managed_entries(config)?;
    if entries.is_empty() {
        crate::output::ok(format!(
            "{} carries no managed workers — nothing to destroy",
            config.display()
        ));
        return Ok(0);
    }
    let mut failed: Vec<String> = Vec::new();
    for entry in &entries {
        let outcome = publish::machine_link(publish_home, &entry.address)
            .and_then(|link| {
                link.map(|l| l.machine_identity)
                    .ok_or_else(|| miette::miette!("no machine linkage names this server"))
            })
            .and_then(|name| provisioner.destroy(&name, config).map(|_| name));
        match outcome {
            Ok(name) => crate::output::ok(format!(
                "destroyed managed worker '{name}' and evicted its config entry"
            )),
            Err(e) => {
                crate::output::warn(format!(
                    "down: entry {address} survived: {cause:#}",
                    address = entry.address,
                    cause = e
                ));
                failed.push(entry.address.clone());
            }
        }
    }
    if !failed.is_empty() {
        return Err(miette::miette!(
            "down: {failed_n} of {total} managed entries could not be destroyed: [{failed}] \
             — the rest are gone; destroy these by hand ('nau workers destroy <name>') and \
             re-run",
            failed_n = failed.len(),
            total = entries.len(),
            failed = failed.join(", ")
        ));
    }
    crate::output::ok(format!(
        "down: destroyed {} managed worker(s) — the block in {} is empty now",
        entries.len(),
        config.display()
    ));
    Ok(entries.len())
}

/// The destroy summary line. An absent managed entry is reported honestly:
/// the server is gone, but nothing was evicted from the config.
fn destroy_summary(name: &str, evicted: bool) -> String {
    if evicted {
        format!("destroyed worker '{name}' and evicted its config entry")
    } else {
        format!("destroyed worker '{name}' — not managed by nau — nothing evicted")
    }
}

/// Provider dispatch. One new provider = one module + one arm here. The
/// operator login key and the publish channel resolve at this boundary
/// (refusal names what was tried) so the provider core never reads the
/// environment.
fn provider_for(
    provider: &str,
    publish: Option<publish::PublishChannel>,
) -> miette::Result<Box<dyn Provisioner>> {
    match provider {
        "hetzner" => Ok(Box::new(hetzner::HetznerProvisioner::new(
            crate::command::RealRunner,
            token_from_env(),
            default_binary_url(),
            resolve_operator_key()?,
            resolve_operator_identity()?,
            publish,
        ))),
        "aws" => Ok(Box::new(aws::AwsProvisioner::new(
            crate::command::RealRunner,
            aws_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
            resolve_operator_identity()?,
            publish,
        ))),
        "gcp" => Ok(Box::new(gcp::GcpProvisioner::new(
            crate::command::RealRunner,
            gcp_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
            resolve_operator_identity()?,
            publish,
        ))),
        "azure" => Ok(Box::new(azure::AzureProvisioner::new(
            crate::command::RealRunner,
            azure_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
            resolve_operator_identity()?,
            publish,
        ))),
        "scaleway" => Ok(Box::new(scaleway::ScalewayProvisioner::new(
            crate::command::RealRunner,
            scaleway_credentials_source(),
            default_binary_url(),
            resolve_operator_key()?,
            resolve_operator_identity()?,
            publish,
        ))),
        other => Err(miette::miette!(
            "workers: unknown provider '{other}' (supported: hetzner, aws, gcp, azure, scaleway)"
        )),
    }
}

/// The operator's authorized public key: `NAU_OPERATOR_KEY` names a
/// file explicitly; otherwise the default id_ed25519/id_rsa public halves
/// under `$HOME/.ssh`. Refusal names everything that was tried.
pub fn resolve_operator_key() -> miette::Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let candidates: Vec<PathBuf> = match std::env::var("NAU_OPERATOR_KEY").ok() {
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
         NAU_OPERATOR_KEY to the .pub file workers must trust for login",
        tried.join("; ")
    ))
}

/// The operator's client identity: the PRIVATE half of the key
/// [`resolve_operator_key`] resolved — `NAU_OPERATOR_KEY` with its
/// `.pub` suffix stripped, else the same default candidates. Refuses,
/// naming what was tried, when no private half exists: provisioning
/// pins the identity into the workers entry (#298), so a provision
/// that cannot name its own login key must not create servers.
pub fn resolve_operator_identity() -> miette::Result<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let candidates: Vec<PathBuf> = match std::env::var("NAU_OPERATOR_KEY").ok() {
        Some(p) => vec![
            match PathBuf::from(&p).extension().and_then(|e| e.to_str()) {
                Some("pub") => PathBuf::from(&p).with_extension(""),
                _ => PathBuf::from(&p),
            },
        ],
        None => vec![
            Path::new(&home).join(".ssh").join("id_ed25519"),
            Path::new(&home).join(".ssh").join("id_rsa"),
        ],
    };
    let mut tried = Vec::new();
    for c in &candidates {
        if c.exists() {
            return Ok(c.display().to_string());
        }
        tried.push(format!("{} (absent)", c.display()));
    }
    Err(miette::miette!(
        "workers provision: no operator SSH private key found for the workers entries' \
         identity pin (tried {}) — the executor presents exactly the pinned key \
         (`IdentitiesOnly`, #298); set NAU_OPERATOR_KEY to the key workers must log in with",
        tried.join("; ")
    ))
}

/// The managed-block markers in `nau.lua`. Everything between them is
/// nau-owned text, regenerated on every provision/destroy; everything
/// outside them is the operator's and is never rewritten.
pub const BLOCK_BEGIN: &str =
    "-- BEGIN nau workers (machine-managed; `nau workers provision`/`destroy` own this block)";
pub const BLOCK_END: &str = "-- END nau workers";

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
    /// contract): the provider's `nau-worker-ttl` label/tag
    /// (epoch-seconds expiry — the SOURCE OF TRUTH the sweep reads) and
    /// the in-guest `/etc/nau/worker-ttl` marker (one decimal
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
    /// The host CA's fingerprint — the `host_key` value every provisioned
    /// workers entry carries under the amendment (the pin-before-first-use
    /// posture now pins the CA, not a minted public half). A real run
    /// requires it (`None` is a named refusal before any API call; the
    /// CLI resolves it from the ceremony home); a dry run runs without.
    pub ca_fingerprint: Option<String>,
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
    /// SHA-256 of the template-shape user-data blob a real run would
    /// send: rendered with the placeholder publish slots
    /// ([`PLAN_MACHINE_IDENTITY`], [`PLAN_PUBLISH_TOKEN`],
    /// [`PLAN_PUBLISH_URL`]) — the real per-server blob differs only in
    /// those three slots (a fresh one-time token + the server name ride
    /// each create), so the plan hash pins the template SHAPE, and a
    /// determinism break in it is a template drift, not token noise.
    pub user_data_sha256: String,
}

/// One provisioned worker, as pinned into config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedWorker {
    /// The provider-side server name (the `nau workers destroy` handle).
    pub name: String,
    /// The `ssh://` address written into the workers entry.
    pub address: String,
    /// The pinned value (ADR-0045 amendment grammar): the host CA's
    /// fingerprint — the same value for every worker of the operator,
    /// which is the point (one `@cert-authority` root, not per-worker
    /// pins).
    pub host_key: String,
}

/// One cloud provider backend.
pub trait Provisioner {
    /// Create servers, let them generate + publish their host keys
    /// guest-side, and pin the CA fingerprint. All-or-nothing: any
    /// failure after servers exist tears them down and leaves config
    /// untouched.
    fn provision(&self, req: &ProvisionRequest) -> miette::Result<Vec<ProvisionedWorker>>;

    /// Destroy one server by name and evict its config entry. `Ok(true)`
    /// when a managed entry was evicted; `Ok(false)` when no managed
    /// entry carried the server's address (the caller decides the
    /// wording).
    fn destroy(&self, name: &str, config: &Path) -> miette::Result<bool>;
}

// ── The amendment's shared helpers (no coordinator-side mint) ──

/// The dry-run placeholder for the per-server machine identity slot. The
/// real blob differs only in this slot (+ token + URL) — see
/// [`ProvisionPlan::user_data_sha256`].
pub const PLAN_MACHINE_IDENTITY: &str = "<server-name-minted-at-create>";

/// The dry-run placeholder for the one-time publish token slot.
pub const PLAN_PUBLISH_TOKEN: &str = "<one-time-publish-token-minted-at-create>";

/// The dry-run placeholder for the callback URL slot.
pub const PLAN_PUBLISH_URL: &str = "<publish-url>";

/// The CA pin every provisioned entry carries, fail-closed: a real run
/// with no resolved fingerprint is a named refusal BEFORE any API call —
/// never a pinless worker.
pub fn require_ca_pin(req: &ProvisionRequest) -> miette::Result<&str> {
    req.ca_fingerprint.as_deref().ok_or_else(|| {
        miette::miette!(
            "provision: no host CA fingerprint on the request — the workers pin IS the CA \
             fingerprint now (ADR-0045 amendment); run 'nau ca keygen' first"
        )
    })
}

/// The publish channel a real run uses, fail-closed: without it the
/// guest cannot publish and no certificate can ever issue.
pub fn require_publish(
    publish: &Option<publish::PublishChannel>,
) -> miette::Result<&publish::PublishChannel> {
    publish.as_ref().ok_or_else(|| {
        miette::miette!(
            "provision: no publish channel — a real provision needs NAU_PUBLISH_URL \
             (the coordinator endpoint the guest publishes its public host half to)"
        )
    })
}

/// The coordinator-side values every per-server create carries: the
/// publish channel (one-time token mint + registry home) and the CA pin
/// the workers entries get. One bundle, because the create paths hand
/// them through together.
pub struct PinPlan<'a> {
    pub publish: &'a publish::PublishChannel,
    pub ca_pin: &'a str,
    /// The client identity pinned into every workers entry (#298): the
    /// private-key path resolved at the CLI boundary, so a provisioned
    /// worker's login key is pinned by construction.
    pub identity: String,
}

/// One machine's publish prep + staged user-data, shared by every
/// provider: machine identity = the coordinator-assigned server name, a
/// fresh one-time publish token recorded in the coordinator's registry
/// BEFORE the create call (the token must be enforceable by first boot),
/// the blob rendered from the shared template and staged 0600 inside the
/// provision tempdir. Returns the staged path; the caller removes it once
/// its create call has served it — the one-time bearer must not linger
/// on disk past the create.
pub fn stage_publishing_user_data(
    staging: &Path,
    publish: &publish::PublishChannel,
    binary_url: &str,
    operator_key: &str,
    machine_identity: &str,
    ttl_expiry_epoch: u64,
) -> miette::Result<PathBuf> {
    let token = publish::mint_publish_token()?;
    publish::record_issue(&publish.home, &token, machine_identity, now_epoch_secs()?)?;
    let user_data = render_user_data(&UserDataParams {
        machine_identity,
        publish_url: &publish.url,
        publish_token: &token,
        operator_key,
        binary_url,
        ttl_expiry_epoch,
    });
    stage_user_data(staging, &user_data)
}

/// Stage the user-data blob for the provider's create call INSIDE the
/// provision tempdir (`dir`), mode 0600. No private half rides the blob
/// anymore — but the one-time publish token does, so the same hygiene
/// stays: the per-run tempdir keeps concurrent provisions isolated, 0600
/// keeps it private while it exists, and the staged file is removed
/// right after its create call.
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
/// the `/etc/nau/worker-ttl` marker) is decimal epoch seconds; the
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

/// The pinned mksquashfs, shipped as a prebuilt artifact (pin 1).
/// Every stable distro ships 4.6.1; ADR-0041's zstd defaults make
/// mksquashfs behavior part of artifact identity, so the fleet runs one
/// pinned 4.7.x artifact. The preflight admission refuses any worker
/// whose resolved mksquashfs reports anything else.
pub const SQUASHFS_TOOLS_VERSION: &str = "4.7.4";

/// The release date baked into the pinned build's version string. The
/// codeload tarball otherwise builds as `4.7.4-<hash>`; the template
/// forces the clean release form so `discover_version` reads exactly
/// [`SQUASHFS_TOOLS_VERSION`] on every worker.
pub const SQUASHFS_TOOLS_RELEASE_DATE: &str = "2025-11-09";

/// The pinned source tarball (GitHub codeload, tag `4.7.4`). Verified by
/// sha256 by scripts/build-mksquashfs-artifact.sh before a single byte is
/// built into the pinned prebuilt artifact.
pub const SQUASHFS_TOOLS_TARBALL_URL: &str =
    "https://codeload.github.com/plougher/squashfs-tools/tar.gz/refs/tags/4.7.4";

/// sha256 of [`SQUASHFS_TOOLS_TARBALL_URL`]'s exact bytes.
pub const SQUASHFS_TOOLS_SHA256: &str =
    "91c49f9a1ed972ad00688a38222119e2baf49ba74cf5fda05729a79d7d59d335";

/// sha256 of the prebuilt artifact `mksquashfs` binary (ticket #300) —
/// the scripts/build-mksquashfs-artifact.sh output served at the publish
/// front's /bin/ (same lane as the worker binary). Re-pinning is a
/// DELIBERATE act: one commit moves the artifact, its SHA256SUMS, and
/// this const together; no worker ever installs bytes this const does
/// not name (the runcmd gates on it BEFORE anything runs or installs).
pub const MKSQUASHFS_ARTIFACT_SHA256: &str =
    "b8b43077806da524d2e6b6be1bb1377f20c30e4107a5cd762ef76750994d13d6";

/// sha256 of the prebuilt artifact `unsquashfs` binary (see
/// [`MKSQUASHFS_ARTIFACT_SHA256`]).
pub const UNSQUASHFS_ARTIFACT_SHA256: &str =
    "6b97812c869c1254466e361732717d7c590c64cc89e6757d7f2e0d4039a4caf3";

/// Everything the template needs. Nothing here is optional: a provision
/// without a CA pin, a login key, a TTL, or a publish channel is not a
/// nau worker. NOTE: there is no host-key slot — the guest generates
/// its own keypair (ADR-0045 amendment); only public material and the
/// one-time bearer cross user-data.
pub struct UserDataParams<'a> {
    /// The coordinator-assigned machine identity (the provider-side
    /// server name) — the principal-binding name the pending store files
    /// the published key under.
    pub machine_identity: &'a str,
    /// The coordinator publish callback URL the guest POSTs to
    /// (single-line http(s), validated at the CLI boundary).
    pub publish_url: &'a str,
    /// The one-time publish token minted for THIS machine at create
    /// time — consumed by the first accepted publish, refused on replay
    /// ([`publish::receive_publish`]).
    pub publish_token: &'a str,
    /// The operator's authorized public-key line — how the operator logs
    /// in (never the host key; this flow is untouched by the amendment).
    pub operator_key: &'a str,
    /// The pinned nau binary URL cloud-init installs.
    pub binary_url: &'a str,
    /// TTL expiry as DECIMAL EPOCH SECONDS — the exact shape the #269
    /// sweep's `is_epoch` accepts for the `/etc/nau/worker-ttl`
    /// marker (one line). ISO-8601 here would leave the sweep's
    /// marker fallback rule dead code.
    pub ttl_expiry_epoch: u64,
}

/// The first-boot publish script the template drops at
/// `/etc/nau/publish-host-key.sh` (0700): read the GUEST-GENERATED
/// public half, embed it with the machine identity and the cloud-init
/// normalized instance-data document (the provider instance-identity
/// content the certificate principal binds — ADR-0045 Decision 3) into
/// one JSON payload, and POST it with the one-time bearer. Fire-and-
/// forget with bounded retries: a coordinator that is not (yet) up never
/// bricks the boot — it just means no issuance, and the TTL sweep
/// reclaims the worker (fail-closed: nothing pins a key that never
/// published).
const PUBLISH_SCRIPT: &str = r#"#!/bin/sh
# ADR-0045 amendment (#295): publish the guest-generated PUBLIC host half
# to the coordinator. Public material only; authenticated by the one-time
# token carried in publish.env. No private half ever exists off this
# machine.
set -eu
. /etc/nau/publish.env
PUB=$(tr -d '"\\' < /etc/ssh/ssh_host_ed25519_key.pub)
if [ ! -s /run/cloud-init/instance-data.json ]; then
  echo "publish-host-key: no cloud-init instance-data — the certificate principal would bind nothing; skipping publish (fail-closed)" >&2
  exit 0
fi
IID=$(cat /run/cloud-init/instance-data.json)
BODY=$(printf '{"machine_identity":"%s","public_key":"%s","instance_identity":%s}' "$MACHINE_IDENTITY" "$PUB" "$IID")
i=0
while [ "$i" -lt 10 ]; do
  if printf '%s' "$BODY" | curl -fsS -m 30 \
      -H "Authorization: Bearer $PUBLISH_TOKEN" \
      -H "Content-Type: application/json" \
      --data-binary @- "$PUBLISH_URL"; then
    exit 0
  fi
  i=$((i + 1))
  sleep 4
done
echo "publish-host-key: coordinator unreachable after 10 attempts — without the publish no certificate issues; the TTL sweep reclaims this worker" >&2
exit 0
"#;

/// The first-boot pickup script the template drops at
/// `/etc/nau/pickup-host-cert.sh` (0700, #295 sub-task 4): GET the
/// issued host certificate over the SAME one-time bearer channel the
/// publish used (`/etc/nau/publish.env` carries every slot the
/// pickup needs — URL, token). The certificate exists only after the
/// coordinator signs (`nau workers issue`), so the guest polls with
/// bounded retries until the token TTL closes the window
/// ([`crate::provision::publish::PUBLISH_TOKEN_TTL_SECS`] = 1440 × 60s).
/// On arrival the certificate is shape-checked (a cert line, not a
/// proxy's 200 page), installed ATOMICALLY as
/// `/etc/ssh/ssh_host_ed25519_key-cert.pub` beside the guest-generated
/// key (sshd serves `<key>-cert.pub` automatically), and sshd is
/// restarted to serve it. Fail-closed by construction: no certificate by
/// window end means sshd serves only the raw host key, and the
/// coordinator's `@cert-authority` pin refuses a raw key at host
/// verification (`No ED25519 host key is known ... strict checking` →
/// the preflight `ChannelLoss` names the worker) — the worker is
/// unreachable to the fleet until it is re-provisioned or re-issued.
const PICKUP_SCRIPT: &str = r#"#!/bin/sh
# ADR-0045 amendment (#295): pick up the coordinator-issued host
# certificate over the same one-time bearer the publish used. Public
# material only; the window closes at the publish-token TTL.
set -eu
. /etc/nau/publish.env
CERT=/etc/ssh/ssh_host_ed25519_key-cert.pub
TMP=$CERT.tmp
i=0
while [ "$i" -lt 1440 ]; do
  if curl -fsS -m 30 \
      -H "Authorization: Bearer $PUBLISH_TOKEN" \
      -o "$TMP" "$PUBLISH_URL" 2>/dev/null; then
    if head -n 1 "$TMP" | grep -q 'ssh-ed25519-cert-v01@openssh.com'; then
      chmod 0644 "$TMP"
      mv "$TMP" "$CERT"
      printf 'HostCertificate %s\n' "$CERT" > /etc/ssh/sshd_config.d/nau-host-cert.conf
      systemctl restart ssh || systemctl restart sshd
      exit 0
    fi
    rm -f "$TMP"
  fi
  i=$((i + 1))
  sleep 60
done
echo "pickup-host-cert: no certificate within the publish-token window (1440 x 60s) — the coordinator refuses this worker's raw host key (fail-closed); rebuild or re-provision to retry" >&2
exit 0
"#;

/// The oneshot unit that runs [`PICKUP_SCRIPT`] outside cloud-init: the
/// retry loop may legitimately run for the whole token window (the
/// certificate appears only when the coordinator signs), and a
/// cloud-init runcmd that long would hang the boot's final stage. The
/// unit is enabled by the last runcmd, after the publish runcmd has
/// already proven the channel up.
const PICKUP_UNIT: &str = r#"[Unit]
Description=nau: pick up the issued SSH host certificate (ADR-0045 amendment)
After=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=infinity
ExecStart=/etc/nau/pickup-host-cert.sh

[Install]
WantedBy=multi-user.target
"#;

/// The shell-sourceable env file the publish script reads (0600): the
/// three per-machine slots, single-quoted (the CLI boundary refuses
/// values that would break out of the quotes).
fn publish_env(p: &UserDataParams<'_>) -> String {
    format!(
        "MACHINE_IDENTITY='{id}'\nPUBLISH_URL='{url}'\nPUBLISH_TOKEN='{token}'\n",
        id = p.machine_identity,
        url = p.publish_url,
        token = p.publish_token
    )
}

/// Render the shared cloud-init user-data (ADR-0045 amendment): the guest
/// GENERATES its host keypair on first boot (`ssh_deletekeys: true` +
/// `ssh_genkey: true`, explicit — guest-local generation is the security
/// property, never a default relied on), the operator authorized key
/// grants login (untouched by the amendment), the TTL marker is stamped
/// as the in-guest fallback COPY of the `nau-worker-ttl` label (the
/// sweep's source of truth), the worker tool pins are installed (#273),
/// the pinned nau binary is installed, sshd is hardened (key-only,
/// root login by key) — the first-boot publish script drops the PUBLIC
/// half plus instance identity to the coordinator over the one-time
/// token, and the pickup unit (a oneshot service, not a runcmd) fetches
/// the issued certificate when the coordinator signs and serves it from
/// sshd (#295 sub-task 4). The old post-sshd user-data scrub is GONE: it
/// existed to scrub an injected private half; nothing sensitive ships
/// anymore (ADR-0045 amendment: the scrub step is dead code and is
/// removed).
pub fn render_user_data(p: &UserDataParams<'_>) -> String {
    let mut s = String::from("#cloud-config\n");
    // Guest-local generation, explicit: cloud-init's ssh module generates
    // a fresh ed25519 keypair on THIS machine at first boot. The private
    // half never exists coordinator-side and never crosses user-data.
    s.push_str("ssh_deletekeys: true\n");
    s.push_str("ssh_genkey: true\n");
    s.push_str("write_files:\n");
    write_file(&mut s, "/root/.ssh/authorized_keys", "0600", p.operator_key);
    write_file(
        &mut s,
        "/etc/nau/worker-ttl",
        "0644",
        &p.ttl_expiry_epoch.to_string(),
    );
    write_file(&mut s, "/etc/nau/publish.env", "0600", &publish_env(p));
    write_file(
        &mut s,
        "/etc/nau/publish-host-key.sh",
        "0700",
        PUBLISH_SCRIPT,
    );
    write_file(
        &mut s,
        "/etc/nau/pickup-host-cert.sh",
        "0700",
        PICKUP_SCRIPT,
    );
    write_file(
        &mut s,
        "/etc/systemd/system/nau-pickup-host-cert.service",
        "0644",
        PICKUP_UNIT,
    );
    s.push_str("runcmd:\n");
    // Pin 2 first: the distro packages every later step needs — bwrap
    // (it ships its own AppArmor profile, so the current Ubuntu LTS
    // userns restriction does not break it; the hardening stays, and
    // `apparmor_restrict_unprivileged_userns` is NEVER touched here),
    // curl for the pinned-binary installs, and build-essential for the
    // package builds jobs run. NO compressor -dev debs: their only
    // consumer was the per-worker source build, which #300 replaced —
    // the prebuilt artifact is self-contained.
    s.push_str("  - apt-get update\n");
    s.push_str(
        "  - DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         bubblewrap ca-certificates curl build-essential\n",
    );
    // Pin 1: the prebuilt mksquashfs artifact, fetched + hash-verified +
    // installed as one fail-together step.
    s.push_str(&format!("  - {}\n", squashfs_install_runcmd()));
    s.push_str(&format!(
        "  - curl -fsSL {url} -o /usr/local/bin/nau\n",
        url = p.binary_url
    ));
    s.push_str("  - chmod 0755 /usr/local/bin/nau\n");
    // The API-level create carries no --ssh-key (the operator key rides
    // user-data), so hcloud generates a root password with a forced
    // first-login change; PAM refuses even pubkey logins until it is
    // cleared — the coordinator could never reach the worker.
    s.push_str("  - chage -d -1 root\n");
    s.push_str(
        "  - printf 'PermitRootLogin prohibit-password\\nPasswordAuthentication no\\n' \
         > /etc/ssh/sshd_config.d/99-nau-worker.conf\n",
    );
    s.push_str("  - systemctl restart ssh || systemctl restart sshd\n");
    // The publish: last runcmd (final stage — after the ssh module has
    // generated the host keys and the network is up).
    s.push_str("  - /etc/nau/publish-host-key.sh\n");
    // The pickup: a oneshot unit (NOT a runcmd — its bounded-retry loop
    // may run for the whole token window) enabled after the publish has
    // proven the channel up; the guest installs the issued certificate
    // as /etc/ssh/ssh_host_ed25519_key-cert.pub and restarts sshd.
    s.push_str("  - systemctl enable --now nau-pickup-host-cert.service\n");
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

/// The single `sh -c` runcmd that installs pin 1 (#300): fetch the two
/// prebuilt binaries from the artifact URL, verify BOTH against the
/// COMPILED-IN hashes BEFORE anything runs or installs (the served
/// SHA256SUMS is never trusted — the gate is the const, same trust
/// shape the source build had, minus the compiler), `cp -a` to
/// /usr/local/bin (PATH-precedence over the distro's 4.6.1), and fail
/// the step unless the installed binary reports the EXACT pin — version
/// AND release date, proving the artifact is the pinned build and not a
/// codeload-hash build. One step, because the tool pin succeeds or fails
/// as a unit in the cloud-init log; a worker that missed it is refused
/// at preflight by design (admission is fail-closed).
fn squashfs_install_runcmd() -> String {
    format!(
        "sh -c 'set -e; cd /tmp; \
         curl -fsSL {url}/mksquashfs -o mksquashfs; \
         curl -fsSL {url}/unsquashfs -o unsquashfs; \
         printf \"%s  %s\\n%s  %s\\n\" {MKSQUASHFS_ARTIFACT_SHA256} mksquashfs \
         {UNSQUASHFS_ARTIFACT_SHA256} unsquashfs | sha256sum -c -; \
         cp -a mksquashfs unsquashfs /usr/local/bin/; \
         /usr/local/bin/mksquashfs -version | grep -q \"version {SQUASHFS_TOOLS_VERSION} ({SQUASHFS_TOOLS_RELEASE_DATE})\"; \
         rm -f /tmp/mksquashfs /tmp/unsquashfs'",
        url = default_squashfs_artifact_url()
    )
}

// ── The managed `workers` block in nau.lua ──

/// Append (or replace, when the address is already pinned in the managed
/// block) one workers entry. The surrounding operator text is never
/// rewritten; an operator-owned entry at the same address is a refusal —
/// nau owns only its block. `identity` rides the entry (#298): the
/// executor presents exactly this key (`IdentitiesOnly`), so a
/// provisioned worker's login is pinned by construction.
pub fn append_worker_entry(
    config: &Path,
    address: &str,
    host_key: &str,
    identity: &str,
) -> miette::Result<()> {
    let text = read_config(config)?;
    let block = block_line_range(&text)?;
    if outside_block_contains(&text, block, &format!("address = {}", lua_quote(address))) {
        return Err(miette::miette!(
            "provision: {} already pins a worker at {address} outside the nau-managed \
             block — nau never rewrites operator text; remove or move the entry first",
            config.display()
        ));
    }
    let mut entries = parse_managed_entries(&text, block)?;
    entries.retain(|e| e.address != address);
    entries.push(ManagedEntry {
        address: address.to_string(),
        host_key: host_key.to_string(),
        identity: Some(identity.to_string()),
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

/// Every entry currently pinned in the managed block — the `down
/// --all-managed` inventory. An absent block is an empty set, not an
/// error: nothing nau-owned to drain.
pub fn managed_entries(config: &Path) -> miette::Result<Vec<ManagedEntry>> {
    let text = read_config(config)?;
    let block = block_line_range(&text)?;
    parse_managed_entries(&text, block)
}

/// One entry inside the managed block. `identity` is `None` for entries
/// written before the client-identity pin (#298) — preserved verbatim,
/// never backfilled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedEntry {
    pub address: String,
    pub host_key: String,
    pub identity: Option<String>,
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
/// it as-is would silently tighten every rewritten nau.lua.
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
                    "the nau-managed workers block in this config is duplicated or \
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
                "unexpected line inside the nau-managed workers block: '{trimmed}' — \
                 the block is nau-owned; move hand edits outside it"
            ));
        };
        let address = extract_quoted_field(inner, "address").ok_or_else(|| {
            miette::miette!("managed workers entry has no readable 'address': '{trimmed}'")
        })?;
        let host_key = extract_quoted_field(inner, "host_key").ok_or_else(|| {
            miette::miette!("managed workers entry has no readable 'host_key': '{trimmed}'")
        })?;
        let identity = extract_quoted_field(inner, "identity");
        entries.push(ManagedEntry {
            address,
            host_key,
            identity,
        });
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
                    "cannot place the nau-managed workers block: this config has a \
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
        let identity = match &e.identity {
            Some(id) => format!(", identity = {}", lua_quote(id)),
            None => String::new(),
        };
        s.push_str(&format!(
            "table.insert(workers, {{ address = {addr}, host_key = {key}{identity} }})\n",
            addr = lua_quote(&e.address),
            key = lua_quote(&e.host_key),
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
            destroy_summary("nau-worker-x-01", true),
            "destroyed worker 'nau-worker-x-01' and evicted its config entry"
        );
        let absent = destroy_summary("nau-worker-x-01", false);
        assert!(absent.contains("not managed by nau"), "{absent}");
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
        std::env::set_var("NAU_OPERATOR_KEY", &key);
        assert_eq!(
            resolve_operator_key().unwrap(),
            "ssh-ed25519 AAAAoperator test@host"
        );
        std::env::remove_var("NAU_OPERATOR_KEY");
    }

    #[test]
    fn operator_key_refusal_names_what_was_tried() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // SAFETY (test-only): single-threaded under ENV_LOCK.
        std::env::set_var("NAU_OPERATOR_KEY", dir.path().join("absent.pub"));
        let err = format!("{}", resolve_operator_key().unwrap_err());
        std::env::remove_var("NAU_OPERATOR_KEY");
        assert!(err.contains("absent.pub"), "refusal names the file: {err}");
        assert!(err.contains("NAU_OPERATOR_KEY"), "{err}");
    }
}
