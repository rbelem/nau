//! The SSH transport (ADR-0040 Decisions 4–7, ADR-0045 Decision 4, T4):
//! [`SshExecutor`] drives one Worker over `ssh`/`scp` through the repo's
//! one subprocess seam ([`CommandRunner`]) — probe → dispatch → stream →
//! collect, every hop a bounded, non-interactive argv.
//!
//! Bounds ride the argv, the oci.rs curl convention: `-o ConnectTimeout`
//! bounds the TCP connect, `-o ServerAliveInterval` +
//! `-o ServerAliveCountMax` bound session liveness (a hung or vanished
//! host fails the run inside `interval × count`, the lost-worker liveness
//! ADR-0040 D4 requires), and `-o BatchMode=yes` turns every would-be
//! prompt into a failure. The build itself is bounded only by the
//! keepalive deadline — a real build may legitimately run long.
//!
//! Host keys are pinned, never learned (ADR-0045 Decision 4): the pin on
//! the `workers` entry is written to a shuttle-managed known_hosts file
//! for exactly this worker, and ssh runs with `StrictHostKeyChecking=yes`
//! against it, `GlobalKnownHostsFile` parked on `/dev/null` so no ambient
//! trust can leak in. There is no `ssh-keyscan` path anywhere; a worker
//! whose pin cannot be enforced (absent, or fingerprint-only) is a named
//! preflight refusal before any ssh runs.
//!
//! Content moves as content-addressed delta sync (ADR-0040 Decision 6):
//! the Worker reports which closure objects its object store already
//! holds, claimed objects are re-hashed before they are trusted (the
//! `pull_peer.rs` precedent), only the missing objects ship — one flat
//! tar bundle over the channel — arrival is hash-verified in a staging
//! directory before anything commits, and every returned artifact is
//! re-hashed coordinator-side before ingest. Ingest lands under the
//! job-manifest identity (`jm1:<sha256 of the canonical manifest bytes>`)
//! — a namespace deliberately distinct from the local `v4:` closure
//! cache, so a remote result can never silently substitute for a locally
//! keyed entry. A second dispatch of the same manifest is served from
//! that ingest record and transfers nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::command::{exit_code, CommandRunner};
use crate::lua::WorkerConfig;
use crate::worker::{CapabilityDoc, JobManifest, JobResult, WORKER_PROTOCOL_VERSION};

/// TCP connect bound for every ssh/scp hop (the curl `--connect-timeout`
/// convention: the bound rides the argv).
pub const CONNECT_TIMEOUT_SECS: u32 = 10;

/// Session-keepalive cadence: ssh probes the channel every
/// `SERVER_ALIVE_INTERVAL_SECS` and gives up after
/// [`SERVER_ALIVE_COUNT_MAX`] misses — a dead host fails the run inside
/// ~1 minute instead of hanging it (ADR-0040 D4).
pub const SERVER_ALIVE_INTERVAL_SECS: u32 = 15;
pub const SERVER_ALIVE_COUNT_MAX: u32 = 4;

/// The free-disk floor a bare preflight (no job attached) asserts.
pub const PREFLIGHT_MIN_FREE_DISK_BYTES: u64 = 1024 * 1024 * 1024;

/// Headroom added to the closure bytes for the per-job disk assertion:
/// stage, SquashFS temp, and the artifacts themselves live on the same
/// filesystem the object store reports free space for.
pub const WORKER_DISK_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Where the worker-side state lives, in the remote shell's `~`
/// (unquoted, so the remote shell expands it): the object store, the
/// staging areas, the incoming tar landings, and the job directories.
/// The coordinator is the only writer; the Worker stays stateless beyond
/// this cache (ADR-0040 Decision 2).
const REMOTE_BASE: &str = "~/.cache/shuttle/worker";

/// The remote verb: a compatible `shuttle` on the worker's PATH
/// (ADR-0040 Decision 2(b) — an operator duty preflight verifies through
/// the protocol assertion, not a path shuttle manages).
const REMOTE_SHUTTLE: &str = "shuttle";

/// Where the manifest's closure blobs live coordinator-side.
pub type PayloadDir = Path;

/// What a dispatch asserts about the worker before anything ships.
#[derive(Debug, Clone, Copy)]
pub struct PreflightChecks<'a> {
    /// Snap arch the worker must report: from the entry's declared `arch`
    /// triplet, or — undeclared and not cross-compiling — the job's own
    /// target. `None` accepts any worker arch.
    pub arch: Option<&'a str>,
    /// Minimum free disk (bytes) the worker must report.
    pub min_free_disk: u64,
}

/// One completed dispatch. `cache_hit` marks a result served from the
/// coordinator's manifest-identity ingest record — nothing crossed the
/// channel.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub cache_hit: bool,
    pub result: JobResult,
}

/// The parsed `ssh://[user@]host[:port]` worker address. Re-derived here
/// (the config boundary already validated it) so the executor holds the
/// argv-ready parts; the dash guards are re-asserted — the #189
/// injection posture is never trusted to a distant check.
#[derive(Debug, Clone)]
struct AddressParts {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

fn parse_address(addr: &str) -> miette::Result<AddressParts> {
    let rest = addr
        .strip_prefix("ssh://")
        .ok_or_else(|| miette::miette!("worker address must start with ssh://: '{addr}'"))?;
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, hp)) => (Some(u.to_string()), hp),
        None => (None, rest),
    };
    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        let (h, after) = bracketed.split_once(']').ok_or_else(|| {
            miette::miette!("worker address has an unterminated IPv6 bracket: '{addr}'")
        })?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().map_err(|_| {
                miette::miette!("worker address port must be an integer 1-65535: '{addr}'")
            })?),
            None if after.is_empty() => None,
            None => {
                return Err(miette::miette!(
                    "unexpected characters after the IPv6 bracket: '{addr}'"
                ))
            }
        };
        (h, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (
                h,
                Some(p.parse::<u16>().map_err(|_| {
                    miette::miette!("worker address port must be an integer 1-65535: '{addr}'")
                })?),
            ),
            None => (hostport, None),
        }
    };
    if host.is_empty() || host.starts_with('-') {
        return Err(miette::miette!(
            "worker host must be non-empty and must not start with '-': '{addr}'"
        ));
    }
    if port.is_some_and(|p| p == 0) {
        return Err(miette::miette!("worker port must be 1-65535: '{addr}'"));
    }
    if user
        .as_deref()
        .is_some_and(|u| u.is_empty() || u.starts_with('-'))
    {
        return Err(miette::miette!(
            "worker user must be non-empty and must not start with '-': '{addr}'"
        ));
    }
    Ok(AddressParts {
        user,
        host: host.to_string(),
        port,
    })
}

/// One Worker over one SSH channel. `R` is the command seam: production
/// passes [`RealRunner`](crate::command::RealRunner), hermetic tests
/// inject a loopback fake that plays the worker side.
pub struct SshExecutor<R: CommandRunner> {
    worker: WorkerConfig,
    runner: R,
    parts: AddressParts,
    /// Everything shuttle manages on disk for this worker: the
    /// known_hosts pin under `workers/known_hosts.d/`, remote ingest
    /// records under `remote/`.
    cache_dir: PathBuf,
    dispatches: AtomicUsize,
}

impl<R: CommandRunner> SshExecutor<R> {
    /// Build an executor for one `workers` entry. The shuttle-managed
    /// paths default to the cache convention (`$HOME/.cache/shuttle`).
    pub fn new(worker: &WorkerConfig, runner: R) -> miette::Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Self::with_cache_dir(
            worker,
            runner,
            &Path::new(&home).join(".cache").join("shuttle"),
        )
    }

    /// [`SshExecutor::new`] with the managed-disk root pinned — the test
    /// seam (and a future explicit-config seam, should one be wanted).
    pub fn with_cache_dir(
        worker: &WorkerConfig,
        runner: R,
        cache_dir: &Path,
    ) -> miette::Result<Self> {
        let parts = parse_address(&worker.address)?;
        Ok(SshExecutor {
            worker: worker.clone(),
            runner,
            parts,
            cache_dir: cache_dir.to_path_buf(),
            dispatches: AtomicUsize::new(0),
        })
    }

    pub fn address(&self) -> &str {
        &self.worker.address
    }

    /// The ingest directory for `manifest`: `<cache>/remote/<jm1_<hex>>/`
    /// — the job-manifest identity namespace (ADR-0040 Decision 6), never
    /// a `v4:` closure key. The slug is the identity with its `:`
    /// flattened so one name works as a local directory and inside scp's
    /// `host:path` spec.
    pub fn ingest_dir(&self, manifest: &JobManifest) -> miette::Result<PathBuf> {
        let id = crate::worker::manifest_identity(manifest)?;
        Ok(self.cache_dir.join("remote").join(identity_slug(&id)))
    }

    /// The known_hosts entry this worker's pin builds: the host pattern
    /// (OpenSSH form — `[host]:port` for non-default ports, bare
    /// otherwise) plus the key half of the pin, comment dropped. `None`
    /// when the pin cannot enforce a connection (absent, or
    /// fingerprint-only).
    fn known_hosts_line(&self) -> Option<String> {
        let pin = self.worker.host_key.as_deref()?.trim();
        let key: Vec<&str> = pin.split_whitespace().take(2).collect();
        if key.len() < 2 {
            return None;
        }
        let pattern = match self.parts.port {
            Some(port) => format!("[{}]:{port}", self.parts.host),
            None => self.parts.host.clone(),
        };
        Some(format!("{pattern} {}", key.join(" ")))
    }

    /// The preflight refusal for a worker whose pin cannot be enforced.
    /// Named by address (ADR-0045 D4: "refuses an unpinned worker by
    /// name").
    fn pin_refusal(&self) -> miette::Error {
        match self.worker.host_key.as_deref().map(str::trim) {
            None | Some("") => miette::miette!(
                "preflight host-key: worker '{}' is unpinned — every workers entry must carry \
                 host_key; shuttle never learns host keys (ADR-0045 Decision 4)",
                self.worker.address
            ),
            Some(pin) => miette::miette!(
                "preflight host-key: worker '{}' carries only the fingerprint pin '{pin}' — a \
                 fingerprint cannot enforce a connection; pin the full public key line \
                 ('ssh-ed25519 AAAA...'). shuttle never learns host keys (ADR-0045 Decision 4)",
                self.worker.address
            ),
        }
    }

    /// Write the shuttle-managed known_hosts for this worker: one file,
    /// one pinned line, written only when the content differs (atomic
    /// tempfile + persist, safe under the scheduler's concurrent
    /// dispatches to the same worker). Called before any ssh runs, so an
    /// unenforceable pin refuses with zero channel activity.
    fn ensure_known_hosts(&self) -> miette::Result<()> {
        let line = self.known_hosts_line().ok_or_else(|| self.pin_refusal())?;
        let dir = self.known_hosts_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| miette::miette!("cannot create {}: {e}", dir.display()))?;
        let file = dir.join(format!("wk{}", self.known_hosts_slug()));
        if std::fs::read_to_string(&file).is_ok_and(|c| c == line) {
            return Ok(());
        }
        let tmp = tempfile::NamedTempFile::new_in(&dir)
            .map_err(|e| miette::miette!("cannot stage the known_hosts pin: {e}"))?;
        std::fs::write(tmp.path(), &line)
            .map_err(|e| miette::miette!("cannot write the known_hosts pin: {e}"))?;
        tmp.persist(&file)
            .map_err(|e| miette::miette!("cannot install the known_hosts pin: {e}"))?;
        Ok(())
    }

    fn known_hosts_dir(&self) -> PathBuf {
        self.cache_dir.join("workers").join("known_hosts.d")
    }

    fn known_hosts_slug(&self) -> String {
        crate::oci::sha256_hex(self.worker.address.as_bytes())[..16].to_string()
    }

    /// The known_hosts path ssh is driven against — exposed for tests and
    /// diagnostics.
    pub fn known_hosts_path(&self) -> PathBuf {
        self.known_hosts_dir()
            .join(format!("wk{}", self.known_hosts_slug()))
    }

    /// The shared ssh/scp option block. Every bound and every pin rule
    /// lives here: non-interactive (`BatchMode=yes`), pin-only host keys
    /// (`StrictHostKeyChecking=yes` + the managed file, global trust
    /// parked on `/dev/null`), bounded connect and bounded session
    /// liveness.
    fn base_argv(&self, port_flag: &str) -> Vec<String> {
        let mut v = vec![
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            format!("UserKnownHostsFile={}", self.known_hosts_path().display()),
            "-o".to_string(),
            "GlobalKnownHostsFile=/dev/null".to_string(),
            "-o".to_string(),
            format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"),
            "-o".to_string(),
            format!("ServerAliveInterval={SERVER_ALIVE_INTERVAL_SECS}"),
            "-o".to_string(),
            format!("ServerAliveCountMax={SERVER_ALIVE_COUNT_MAX}"),
        ];
        if let Some(port) = self.parts.port {
            v.push(port_flag.to_string());
            v.push(port.to_string());
        }
        v
    }

    /// The ssh destination token.
    fn destination(&self) -> String {
        match &self.parts.user {
            Some(user) => format!("{user}@{}", self.parts.host),
            None => self.parts.host.clone(),
        }
    }

    /// The scp destination token: IPv6 hosts need the bracket form inside
    /// the remote file spec.
    fn scp_destination(&self) -> String {
        let host = if self.parts.host.contains(':') {
            format!("[{}]", self.parts.host)
        } else {
            self.parts.host.clone()
        };
        match &self.parts.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        }
    }

    /// Run one bounded remote command, returning its stdout.
    fn run_ssh(&self, remote_cmd: &str) -> miette::Result<String> {
        let mut argv = vec!["ssh".to_string()];
        argv.extend(self.base_argv("-p"));
        argv.push(self.destination());
        argv.push(remote_cmd.to_string());
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("ssh to '{}' cannot be spawned: {e}", self.worker.address)
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "ssh to '{}' failed (code {}): {}",
                self.worker.address,
                exit_code(&out),
                stderr_tail(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Push one local file onto the channel.
    fn scp_put(&self, local: &Path, remote_path: &str) -> miette::Result<()> {
        let remote = format!("{}:{remote_path}", self.scp_destination());
        self.scp(&local.to_string_lossy(), &remote)
    }

    /// Pull one remote file off the channel.
    fn scp_get(&self, remote_path: &str, local: &Path) -> miette::Result<()> {
        let remote = format!("{}:{remote_path}", self.scp_destination());
        self.scp(&remote, &local.to_string_lossy())
    }

    fn scp(&self, src: &str, dst: &str) -> miette::Result<()> {
        let mut argv = vec!["scp".to_string()];
        argv.extend(self.base_argv("-P"));
        argv.push(src.to_string());
        argv.push(dst.to_string());
        let out = self.runner.run(&argv).map_err(|e| {
            miette::miette!("scp to '{}' cannot be spawned: {e}", self.worker.address)
        })?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "scp with '{}' failed (code {}): {}",
                self.worker.address,
                exit_code(&out),
                stderr_tail(&out.stderr)
            ));
        }
        Ok(())
    }

    /// Probe → assert (ADR-0040 D8: every failure names its probe).
    /// Runs `__worker-cap` and refuses, by name, on reachability, an
    /// unparseable cap document, protocol version, arch, bwrap, the
    /// functioning-sandbox probe, mksquashfs, or free disk.
    pub fn preflight(&self, checks: PreflightChecks<'_>) -> miette::Result<CapabilityDoc> {
        // The pin refusal lands before any channel activity.
        self.ensure_known_hosts()?;
        let stdout = self
            .run_ssh(&format!("{REMOTE_SHUTTLE} __worker-cap"))
            .map_err(|e| miette::miette!("preflight reachability: {e:#}"))?;
        let cap: CapabilityDoc = serde_json::from_str(stdout.trim()).map_err(|e| {
            miette::miette!(
                "preflight cap: worker '{}' did not return a capability document: {e}",
                self.worker.address
            )
        })?;
        if cap.protocol != WORKER_PROTOCOL_VERSION {
            return Err(miette::miette!(
                "preflight protocol: worker '{}' speaks protocol {}, this coordinator speaks \
                 {WORKER_PROTOCOL_VERSION} — upgrade the worker's shuttle",
                self.worker.address,
                cap.protocol
            ));
        }
        if let Some(expected) = checks.arch {
            if cap.arch != expected {
                return Err(miette::miette!(
                    "preflight arch: worker '{}' reports '{}', expected '{expected}'",
                    self.worker.address,
                    cap.arch
                ));
            }
        }
        if !cap.bwrap {
            return Err(miette::miette!(
                "preflight bwrap: worker '{}' reports bwrap absent",
                self.worker.address
            ));
        }
        if !cap.sandbox {
            return Err(miette::miette!(
                "preflight sandbox: worker '{}' failed the functioning-sandbox probe \
                 (unprivileged user namespaces)",
                self.worker.address
            ));
        }
        if !cap.mksquashfs {
            return Err(miette::miette!(
                "preflight mksquashfs: worker '{}' reports mksquashfs absent",
                self.worker.address
            ));
        }
        if cap.free_disk_bytes < checks.min_free_disk {
            return Err(miette::miette!(
                "preflight disk: worker '{}' reports {} bytes free, the job needs at least {}",
                self.worker.address,
                cap.free_disk_bytes,
                checks.min_free_disk
            ));
        }
        Ok(cap)
    }

    /// A result already ingested under this manifest's identity — served
    /// without touching the channel. Stored artifacts are re-hashed
    /// before the record is trusted: a tampered or truncated entry
    /// rebuilds rather than poisons.
    pub fn cached_result(&self, manifest: &JobManifest) -> miette::Result<Option<JobResult>> {
        let dir = self.ingest_dir(manifest)?;
        let Ok(bytes) = std::fs::read(dir.join("result.json")) else {
            return Ok(None);
        };
        let Ok(result) = serde_json::from_slice::<JobResult>(&bytes) else {
            return Ok(None);
        };
        for art in &result.artifacts {
            match crate::oci::sha256_file(&dir.join(&art.filename)) {
                Ok(h) if h == art.sha256 => {}
                _ => return Ok(None),
            }
        }
        Ok(Some(result))
    }

    /// Probe → dispatch → stream → collect for one job manifest. The
    /// closure blobs named by the manifest live in `payload_dir`, named
    /// by their sha256 (the coordinator-side build outputs). A manifest
    /// already ingested under its identity returns the stored result with
    /// `cache_hit: true` and zero channel activity.
    pub fn dispatch(
        &self,
        manifest: &JobManifest,
        payload_dir: &PayloadDir,
    ) -> miette::Result<DispatchOutcome> {
        if let Some(result) = self.cached_result(manifest)? {
            return Ok(DispatchOutcome {
                cache_hit: true,
                result,
            });
        }
        // The remote paths carry the slug (the identity's `:` flattened —
        // scp's host:path split); refusals name the full identity.
        let id = identity_slug(&crate::worker::manifest_identity(manifest)?);

        // Arch expectation: the entry's declared triplet governs; a job
        // that does not cross-compile additionally requires the worker's
        // native arch to be the job target. A cross job (cross_target
        // set) runs on any sandboxed worker — `check_cross_build` rules
        // remotely.
        let declared: Option<String> = self
            .worker
            .arch
            .as_deref()
            .and_then(crate::snap::triplet_arch)
            .map(str::to_string);
        let target = (manifest.cross_target.is_none()).then_some(manifest.target.as_str());
        let arch_expect = match (&declared, target) {
            (Some(d), Some(t)) if d != t => {
                return Err(miette::miette!(
                    "dispatch: worker '{}' declares arch {d} but the job targets {t} — the entry's \
                     arch override and the job target disagree",
                    self.worker.address
                ));
            }
            (Some(d), _) => Some(d.as_str()),
            (None, Some(t)) => Some(t),
            (None, None) => None,
        };

        let closure_bytes: u64 = manifest.closure.iter().map(|o| o.size).sum();
        self.preflight(PreflightChecks {
            arch: arch_expect,
            min_free_disk: closure_bytes.saturating_add(WORKER_DISK_HEADROOM_BYTES),
        })?;

        self.delta_sync(manifest, payload_dir)?;
        self.prepare_job_dir(&id, manifest)?;

        let stdout = self
            .run_ssh(&format!(
                "{REMOTE_SHUTTLE} __worker-job {REMOTE_BASE}/jobs/{id}/job.json"
            ))
            .map_err(|e| {
                miette::miette!(
                    "dispatch failed on worker '{}' for job {id}: {e:#}",
                    self.worker.address
                )
            })?;
        let result: JobResult = serde_json::from_str(stdout.trim()).map_err(|e| {
            miette::miette!(
                "worker '{}' returned no result document for job {id}: {e} (stdout tail: {})",
                self.worker.address,
                stdout_tail(&stdout)
            )
        })?;
        if result.protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(miette::miette!(
                "result protocol: worker '{}' answered protocol {}, this coordinator speaks \
                 {WORKER_PROTOCOL_VERSION}",
                self.worker.address,
                result.protocol_version
            ));
        }
        if result.package != manifest.package {
            return Err(miette::miette!(
                "result identity: worker '{}' built '{}' but job {id} dispatched '{}'",
                self.worker.address,
                result.package,
                manifest.package
            ));
        }
        if result.target != manifest.target {
            return Err(miette::miette!(
                "result identity: worker '{}' built for '{}' but job {id} targets '{}'",
                self.worker.address,
                result.target,
                manifest.target
            ));
        }
        if !result.ok {
            return Err(miette::miette!(
                "job {id} failed on worker '{}': {}",
                self.worker.address,
                result.error.as_deref().unwrap_or("unspecified build error")
            ));
        }

        let outcome = self.collect_and_ingest(&id, manifest, result)?;
        // Best-effort job-dir cleanup — the object store (the worker's
        // cache) persists, the job scratch does not.
        let _ = self.run_ssh(&format!("rm -rf {REMOTE_BASE}/jobs/{id}"));
        Ok(outcome)
    }

    /// Content-addressed delta sync (ADR-0040 Decision 6): list held,
    /// re-hash claims, ship only the missing, verify on arrival, commit.
    fn delta_sync(&self, manifest: &JobManifest, payload_dir: &PayloadDir) -> miette::Result<()> {
        if manifest.closure.is_empty() {
            return Ok(());
        }
        let wanted: BTreeSet<String> = manifest.closure.iter().map(|o| o.sha256.clone()).collect();
        for sha in &wanted {
            if !is_sha256(sha) {
                return Err(miette::miette!(
                    "delta sync: closure object name '{sha}' is not a sha256 — refusing"
                ));
            }
        }
        let held = self.held_objects()?;
        let claimed: Vec<&str> = wanted.intersection(&held).map(String::as_str).collect();
        self.verify_claimed(&claimed)?;
        let missing: Vec<&str> = wanted.difference(&held).map(String::as_str).collect();
        if missing.is_empty() {
            return Ok(());
        }
        self.ship_missing(&missing, payload_dir)
    }

    /// What the worker's object store reports holding, filtered to
    /// sha256-shaped names (everything else is ignored, never shipped).
    fn held_objects(&self) -> miette::Result<BTreeSet<String>> {
        let stdout = self
            .run_ssh(&format!("ls {REMOTE_BASE}/objects 2>/dev/null || true"))
            .map_err(|e| miette::miette!("delta sync: cannot list the worker's objects: {e:#}"))?;
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|s| is_sha256(s))
            .map(str::to_string)
            .collect())
    }

    /// Claims are content-verified before they are trusted
    /// (`pull_peer.rs` precedent): one truncated blob from a partial
    /// transfer must not poison every later job that would have skipped
    /// it. A mismatch is a named refusal.
    fn verify_claimed(&self, claimed: &[&str]) -> miette::Result<()> {
        for chunk in claimed.chunks(256) {
            let stdout = self
                .run_ssh(&format!(
                    "cd {REMOTE_BASE}/objects && sha256sum {}",
                    chunk.join(" ")
                ))
                .map_err(|e| {
                    miette::miette!(
                        "delta sync: cannot re-hash the worker's claimed objects: {e:#}"
                    )
                })?;
            for line in stdout.lines() {
                let mut it = line.split_whitespace();
                let (Some(got), Some(name)) = (it.next(), it.next()) else {
                    continue;
                };
                let sha = name.rsplit('/').next().unwrap_or(name);
                if got != sha {
                    return Err(miette::miette!(
                        "delta sync: worker '{}' claims object {} but it hashes to {} — refusing \
                         (ADR-0040 Decision 6: claims are content-verified)",
                        self.worker.address,
                        short_sha(sha),
                        short_sha(got)
                    ));
                }
            }
        }
        Ok(())
    }

    /// Ship the missing objects: one flat tar bundle (members named by
    /// sha256) over the channel, extracted into a staging directory,
    /// hash-verified on arrival, then committed into the object store. A
    /// dead transfer leaves zero store entries.
    fn ship_missing(&self, missing: &[&str], payload_dir: &PayloadDir) -> miette::Result<()> {
        let nonce = self.next_nonce();
        let tar_path = tempfile::Builder::new()
            .prefix("shuttle-worker-sync-")
            .tempfile()
            .map_err(|e| miette::miette!("delta sync: cannot stage the payload bundle: {e}"))?;
        let mut argv = vec![
            "tar".to_string(),
            "-C".to_string(),
            payload_dir.to_string_lossy().into_owned(),
            "-cf".to_string(),
            tar_path.path().to_string_lossy().into_owned(),
        ];
        argv.extend(missing.iter().map(|s| s.to_string()));
        let out = self
            .runner
            .run(&argv)
            .map_err(|e| miette::miette!("delta sync: cannot build the payload bundle: {e}"))?;
        if exit_code(&out) != 0 {
            return Err(miette::miette!(
                "delta sync: cannot build the payload bundle from {}: {}",
                payload_dir.display(),
                stderr_tail(&out.stderr)
            ));
        }

        let incoming = format!("{REMOTE_BASE}/incoming/{nonce}.tar");
        // The landing directory exists before the first push — a fresh
        // worker holds nothing yet.
        self.run_ssh(&format!("mkdir -p {REMOTE_BASE}/incoming"))
            .map_err(|e| miette::miette!("delta sync: cannot prepare the landing area: {e:#}"))?;
        self.scp_put(tar_path.path(), &incoming)
            .map_err(|e| miette::miette!("delta sync: {e:#}"))?;

        let staging = format!("{REMOTE_BASE}/staging/{nonce}");
        let stdout = self
            .run_ssh(&format!(
                "mkdir -p {staging} && tar -C {staging} -xf {incoming} && cd {staging} && sha256sum {}",
                missing.join(" ")
            ))
            .map_err(|e| {
                miette::miette!("delta sync: arrival verification failed on '{}': {e:#}", self.worker.address)
            })?;
        verify_arrival(self, &stdout, missing)?;

        self.run_ssh(&format!(
            "mkdir -p {REMOTE_BASE}/objects && mv {staging}/* {REMOTE_BASE}/objects/ && rm -rf {staging} {incoming}"
        ))
        .map_err(|e| miette::miette!("delta sync: cannot commit the verified objects: {e:#}"))?;
        Ok(())
    }

    /// The remote job directory: `jobs/<identity>/{payload,out}` with the
    /// verified objects hardlinked into the payload (same filesystem, the
    /// worker's cache IS the store) and the canonical manifest bytes
    /// shipped as `job.json` — the bytes whose digest is the identity.
    fn prepare_job_dir(&self, id: &str, manifest: &JobManifest) -> miette::Result<()> {
        let job = format!("{REMOTE_BASE}/jobs/{id}");
        let payload = format!("{job}/payload");
        let out = format!("{job}/out");
        let link = if manifest.closure.is_empty() {
            String::new()
        } else {
            let sources: Vec<String> = manifest
                .closure
                .iter()
                .map(|o| format!("{REMOTE_BASE}/objects/{}", o.sha256))
                .collect();
            format!(" && ln -f {} {payload}", sources.join(" "))
        };
        self.run_ssh(&format!("mkdir -p {payload} {out}{link}"))
            .map_err(|e| {
                miette::miette!(
                    "dispatch: cannot prepare the job directory on '{}': {e:#}",
                    self.worker.address
                )
            })?;
        let stage = tempfile::tempdir()
            .map_err(|e| miette::miette!("dispatch: cannot stage the job file: {e}"))?;
        let job_file = crate::worker::write_job_file(stage.path(), manifest)?;
        self.scp_put(&job_file, &format!("{job}/job.json"))
            .map_err(|e| miette::miette!("dispatch: {e:#}"))?;
        Ok(())
    }

    /// Collect every artifact, hash-verify it against the worker's own
    /// claim (ADR-0040 D7: the coordinator verifies the claim about bytes
    /// the worker returned), then commit the ingest record under the
    /// manifest identity — artifacts first, `result.json` (the commit
    /// marker) last.
    fn collect_and_ingest(
        &self,
        id: &str,
        manifest: &JobManifest,
        result: JobResult,
    ) -> miette::Result<DispatchOutcome> {
        let stage = tempfile::tempdir()
            .map_err(|e| miette::miette!("collect: cannot stage artifacts: {e}"))?;
        for art in &result.artifacts {
            validate_remote_filename(&art.filename)?;
            let dst = stage.path().join(&art.filename);
            self.scp_get(
                &format!("{REMOTE_BASE}/jobs/{id}/out/{}", art.filename),
                &dst,
            )
            .map_err(|e| {
                miette::miette!("collect: cannot fetch artifact '{}': {e:#}", art.filename)
            })?;
            let got = crate::oci::sha256_file(&dst).map_err(|e| {
                miette::miette!("collect: cannot hash artifact '{}': {e}", art.filename)
            })?;
            if got != art.sha256 {
                return Err(miette::miette!(
                    "collect: artifact '{}' from worker '{}' hashes to {} but the result document \
                     claims {} — refusing ingest",
                    art.filename,
                    self.worker.address,
                    short_sha(&got),
                    short_sha(&art.sha256)
                ));
            }
            let size = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
            if size != art.size {
                return Err(miette::miette!(
                    "collect: artifact '{}' from worker '{}' is {} bytes but the result document \
                     claims {} — refusing ingest",
                    art.filename,
                    self.worker.address,
                    size,
                    art.size
                ));
            }
        }

        let dir = self.ingest_dir(manifest)?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| miette::miette!("collect: cannot create {}: {e}", dir.display()))?;
        for art in &result.artifacts {
            std::fs::copy(stage.path().join(&art.filename), dir.join(&art.filename)).map_err(
                |e| {
                    miette::miette!(
                        "collect: cannot ingest {}: {e}",
                        dir.join(&art.filename).display()
                    )
                },
            )?;
        }
        let marker = serde_json::to_vec_pretty(&result)
            .map_err(|e| miette::miette!("collect: cannot serialize the ingest record: {e}"))?;
        std::fs::write(dir.join("result.json"), marker)
            .map_err(|e| miette::miette!("collect: cannot write the ingest record: {e}"))?;
        Ok(DispatchOutcome {
            cache_hit: false,
            result,
        })
    }

    fn next_nonce(&self) -> String {
        format!(
            "{:016x}-{}",
            self.dispatches.fetch_add(1, Ordering::SeqCst),
            std::process::id()
        )
    }
}

/// Compare the arrival hash listing against the manifest's expectations:
/// every member must be present and hash exactly to its name. Anything
/// else refuses before anything commits (ADR-0040 Decision 6).
fn verify_arrival<R: CommandRunner>(
    exec: &SshExecutor<R>,
    stdout: &str,
    missing: &[&str],
) -> miette::Result<()> {
    let mut arrived: BTreeSet<&str> = BTreeSet::new();
    for line in stdout.lines() {
        let mut it = line.split_whitespace();
        let (Some(got), Some(name)) = (it.next(), it.next()) else {
            continue;
        };
        match missing.iter().find(|s| **s == name) {
            Some(&sha) if got == sha => {
                arrived.insert(name);
            }
            _ => {
                return Err(miette::miette!(
                    "delta sync: object {} arrived on worker '{}' hashing to {} — refusing \
                     before anything commits",
                    short_sha(name),
                    exec.worker.address,
                    short_sha(got)
                ));
            }
        }
    }
    if arrived.len() != missing.len() {
        let gone: Vec<String> = missing
            .iter()
            .copied()
            .filter(|s| !arrived.contains(s))
            .map(short_sha)
            .collect();
        return Err(miette::miette!(
            "delta sync: object(s) {} missing from the bundle the worker extracted — refusing",
            gone.join(", ")
        ));
    }
    Ok(())
}

/// A remote filename that can only be a plain name in the job's out
/// directory — path separators, shell metacharacters, and dotfiles are a
/// refusal, never an escaping guess.
fn validate_remote_filename(name: &str) -> miette::Result<()> {
    let ok = !name.is_empty()
        && name != ".."
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        return Ok(());
    }
    Err(miette::miette!(
        "collect: artifact filename '{name}' is not a plain name — refusing"
    ))
}

/// Lowercase-hex sha256 shape.
fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The filesystem-safe form of a `jm1:<hex>` identity: `jm1_<hex>`. The
/// `:` is legal in a Unix directory but collides with scp's `host:path`
/// split, so directory names — local ingest and remote job dirs alike —
/// carry the flattened form.
fn identity_slug(id: &str) -> String {
    id.replace(':', "_")
}

fn short_sha(sha: &str) -> String {
    sha.chars().take(16).collect()
}

/// The last line-bounded chunk of a stderr capture, for refusal text.
fn stderr_tail(stderr: &str) -> String {
    let tail: String = stderr
        .lines()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    let mut tail = tail;
    if tail.len() > 400 {
        tail.truncate(400);
    }
    tail
}

fn stdout_tail(stdout: &str) -> String {
    let mut tail: String = stdout.lines().last().unwrap_or("").to_string();
    if tail.len() > 200 {
        tail.truncate(200);
    }
    tail
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(user: Option<&str>, host: &str, port: Option<u16>) -> miette::Result<AddressParts> {
        let mut s = String::from("ssh://");
        if let Some(u) = user {
            s.push_str(u);
            s.push('@');
        }
        if host.contains(':') {
            s.push('[');
            s.push_str(host);
            s.push(']');
        } else {
            s.push_str(host);
        }
        if let Some(p) = port {
            s.push_str(&format!(":{p}"));
        }
        parse_address(&s)
    }

    #[test]
    fn parse_address_splits_user_host_port() {
        let a = addr(Some("op"), "nuci.local", None).unwrap();
        assert_eq!(a.user.as_deref(), Some("op"));
        assert_eq!(a.host, "nuci.local");
        assert_eq!(a.port, None);

        let a = addr(Some("op"), "nuci.local", Some(2222)).unwrap();
        assert_eq!(a.port, Some(2222));

        let a = addr(None, "::1", Some(22)).unwrap();
        assert_eq!(a.host, "::1");
        assert_eq!(a.port, Some(22));
    }

    #[test]
    fn parse_address_refuses_injection_shapes() {
        // The #189 guard posture, re-asserted at the executor boundary.
        assert!(addr(Some("op"), "-oProxyCommand=evil", None).is_err());
        assert!(parse_address("ssh://-oProxyCommand=x@h").is_err());
        assert!(parse_address("ssh://@h").is_err());
        assert!(parse_address("ssh://h:0").is_err());
        assert!(parse_address("ssh://h:99999").is_err());
        assert!(parse_address("http://h").is_err());
    }

    #[test]
    fn sha_shape_is_strict() {
        let hex = "a".repeat(64);
        assert!(is_sha256(&hex));
        assert!(!is_sha256(&"A".repeat(64)), "uppercase is not the shape");
        assert!(!is_sha256(&"a".repeat(63)));
    }

    #[test]
    fn remote_filenames_are_plain_names_only() {
        assert!(validate_remote_filename("htop_3.3.0_amd64.snap").is_ok());
        assert!(validate_remote_filename("a-b_c9.snap").is_ok());
        assert!(validate_remote_filename("../escape.snap").is_err());
        assert!(validate_remote_filename("dir/x.snap").is_err());
        assert!(validate_remote_filename(".hidden").is_err());
        assert!(validate_remote_filename("x;y.snap").is_err());
        assert!(validate_remote_filename("").is_err());
    }
}
