//! The SSH transport (T4, ADR-0040 Decisions 4–7 / ADR-0045 Decision 4),
//! driven through a loopback harness: the worker side is played in-process
//! by a scripted `CommandRunner` fake that runs the REAL verbs — the real
//! local tar, the real extraction, the real `__worker-job` execution for
//! the build-less hello fixture — so every byte the coordinator hashes,
//! ships, verifies, and ingests is real. `ssh://localhost` is the
//! address under test throughout; no network, no sshd, no keyscan.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nau::command::{CommandRunner, RealRunner, RunnerOutput};
use nau::lua::WorkerConfig;
use nau::ssh_exec::{DispatchOutcome, PreflightChecks, SshExecutor};
use nau::worker::{
    canonical_manifest_bytes, manifest_identity, write_job_file, Artifact, CapabilityDoc,
    ClosureObject, JobManifest, JobResult, WORKER_PROTOCOL_VERSION,
};
use sha2::{Digest, Sha256};

/// The RETIRED pin form: a shape-valid ed25519 public-key line, the
/// mint-and-inject pin. Kept only as the fixture the legacy-refusal
/// tests prove refused (#295 sub-task 5) — no test pins a worker with
/// it anymore.
const LEGACY_LINE_PIN: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3Ux loopback-pin";
const FINGERPRINT_PIN: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
/// The CA public half the ceremony fixture writes: the fake fingerprints
/// it to [`FINGERPRINT_PIN`] unless a test overrides the report.
const CA_PUB_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3Ux loopback-ca";
const CA_IDENTITY: &str = "nau-worker-ca-test-01";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn host_arch() -> String {
    nau::snap::host_arch().to_string()
}

/// Serializes the env-mutating identity tests (process-global state).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn flip_last(bytes: &mut [u8]) {
    let n = bytes.len();
    bytes[n - 1] ^= 0x01;
}

/// Flip one byte at `offset` (a data-area byte of a small tar).
fn flip_at(bytes: &mut [u8], offset: usize) {
    if bytes.len() > offset {
        bytes[offset] ^= 0x01;
    }
}

// ── The loopback worker ──

/// The fake worker: owns the "remote machine" tree (`~` = root) and
/// interprets the exact remote commands the executor emits. scp moves
/// real bytes between the coordinator's filesystem and the tree; ssh
/// routes to the real verbs where it matters.
struct LoopbackWorker {
    root: PathBuf,
    cap: CapabilityDoc,
    real_job: bool,
    scripted_result: Option<JobResult>,
    scripted_files: Vec<(String, Vec<u8>)>,
    corrupt_payload_push: bool,
    corrupt_artifact: Option<String>,
    /// What `ssh-keygen -lf` reports for any key file (the CA-form tests
    /// pin the ceremony's fingerprint; the mismatch test overrides it).
    reported_fingerprint: String,
    /// Script the ssh-side auth refusal on the cap probe — the
    /// Permission-denied shape the identity narrative rides (#298).
    deny_cap: bool,
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    /// Bytes of every scp push whose remote path ends in job.json, in
    /// push order — the shipped manifest's shape is a transport contract.
    pushed_job_files: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl LoopbackWorker {
    fn new(root: &Path) -> Self {
        LoopbackWorker {
            root: root.to_path_buf(),
            cap: cap_happy(),
            real_job: false,
            scripted_result: None,
            scripted_files: Vec::new(),
            corrupt_payload_push: false,
            corrupt_artifact: None,
            reported_fingerprint: FINGERPRINT_PIN.to_string(),
            deny_cap: false,
            calls: Arc::new(Mutex::new(Vec::new())),
            pushed_job_files: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn job_files_handle(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.pushed_job_files.clone()
    }

    fn calls_handle(&self) -> Arc<Mutex<Vec<Vec<String>>>> {
        self.calls.clone()
    }

    fn record(&self, argv: &[String]) {
        self.calls.lock().unwrap().push(argv.to_vec());
    }

    /// Count recorded invocations whose argv[0] is `program`.
    fn count_program(calls: &Arc<Mutex<Vec<Vec<String>>>>, program: &str) -> usize {
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|argv| argv[0] == program)
            .count()
    }

    fn any_call<F>(calls: &Arc<Mutex<Vec<Vec<String>>>>, pred: F) -> bool
    where
        F: Fn(&[String]) -> bool,
    {
        calls.lock().unwrap().iter().any(|argv| pred(argv))
    }

    fn set_cap(&mut self, mutate: impl FnOnce(&mut CapabilityDoc)) {
        mutate(&mut self.cap);
    }

    /// `"~/a/b"` → the fake machine's absolute path.
    fn remote_path(&self, token: &str) -> Option<PathBuf> {
        let rest = token.strip_prefix('~')?.trim_start_matches('/');
        Some(self.root.join(rest))
    }

    fn ok(stdout: String) -> RunnerOutput {
        RunnerOutput {
            code: 0,
            stdout: stdout.into_bytes(),
            stderr: String::new(),
        }
    }

    fn ssh(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        let Some(cmd) = argv.last() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty ssh argv",
            ));
        };
        if cmd.contains("__worker-cap") {
            if self.deny_cap {
                return Ok(RunnerOutput {
                    code: 255,
                    stdout: Vec::new(),
                    stderr: "Permission denied (publickey,password)".into(),
                });
            }
            return Ok(Self::ok(serde_json::to_string(&self.cap).unwrap()));
        }
        if cmd.contains("__worker-job") {
            return self.job(cmd);
        }
        if cmd.starts_with("rm -rf") {
            for token in cmd.split_whitespace().skip(2) {
                if let Some(p) = self.remote_path(token) {
                    let _ = std::fs::remove_dir_all(&p);
                    let _ = std::fs::remove_file(&p);
                }
            }
            return Ok(Self::ok(String::new()));
        }
        if cmd.starts_with("ls ") {
            let dir = cmd.split_whitespace().nth(1).unwrap();
            let mut names: Vec<String> = self
                .remote_path(dir)
                .and_then(|p| std::fs::read_dir(p).ok())
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            return Ok(Self::ok(names.join("\n")));
        }
        if cmd.contains(" -xf ") {
            return self.extract_and_hash(cmd);
        }
        if cmd.contains("sha256sum") {
            return self.hash_command(cmd);
        }
        if cmd.contains("ln -f") {
            return self.job_prep(cmd);
        }
        if cmd.contains(" mv ") {
            return self.commit(cmd);
        }
        if cmd.starts_with("mkdir -p") {
            for token in cmd.split_whitespace().skip(2) {
                if token == "&&" {
                    break;
                }
                std::fs::create_dir_all(self.remote_path(token).unwrap())?;
            }
            return Ok(Self::ok(String::new()));
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("loopback: unsupported remote command: {cmd}"),
        ))
    }

    /// `nau __worker-job <job.json>` — the real verb for the hello
    /// fixture, or the scripted document for transport-only scenarios.
    fn job(&self, cmd: &str) -> io::Result<RunnerOutput> {
        let job_file = self
            .remote_path(cmd.split_whitespace().last().unwrap())
            .expect("job file under ~");
        let manifest = nau::worker::load_manifest(&job_file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:#}")))?;
        let dir = job_file.parent().unwrap();
        if self.real_job {
            return match nau::worker::execute_job(
                &manifest,
                Some(&dir.join("payload")),
                &dir.join("out"),
            ) {
                Ok(result) => Ok(Self::ok(serde_json::to_string(&result).unwrap())),
                Err(e) => Ok(RunnerOutput {
                    code: 1,
                    stdout: Vec::new(),
                    stderr: format!("{e:#}"),
                }),
            };
        }
        std::fs::create_dir_all(dir.join("out"))?;
        for (name, bytes) in &self.scripted_files {
            std::fs::write(dir.join("out").join(name), bytes)?;
        }
        let doc = self.scripted_result.as_ref().expect("scripted result set");
        Ok(Self::ok(serde_json::to_string(doc).unwrap()))
    }

    /// `mkdir -p <staging> && tar -C <staging> -xf <incoming> && cd
    /// <staging> && sha256sum ...` — real extraction, real hashes.
    fn extract_and_hash(&self, cmd: &str) -> io::Result<RunnerOutput> {
        let toks: Vec<&str> = cmd.split_whitespace().collect();
        let mp = toks.iter().position(|t| *t == "-p").unwrap();
        let staging = self.remote_path(toks[mp + 1]).unwrap();
        std::fs::create_dir_all(&staging)?;
        let xf = toks.iter().position(|t| *t == "-xf").unwrap();
        let incoming = self.remote_path(toks[xf + 1]).unwrap();
        let st = RealRunner.run(&[
            "tar".to_string(),
            "-C".to_string(),
            staging.to_string_lossy().into_owned(),
            "-xf".to_string(),
            incoming.to_string_lossy().into_owned(),
        ])?;
        if st.code != 0 {
            return Ok(st);
        }
        let sum = toks.iter().position(|t| *t == "sha256sum").unwrap();
        self.hash_files(&staging, &toks[sum + 1..])
    }

    /// `cd <dir> && sha256sum <names...>` — the claimed-object re-hash.
    fn hash_command(&self, cmd: &str) -> io::Result<RunnerOutput> {
        let toks: Vec<&str> = cmd.split_whitespace().collect();
        let cd = toks.iter().position(|t| *t == "cd").unwrap();
        let dir = self.remote_path(toks[cd + 1]).unwrap();
        let sum = toks.iter().position(|t| *t == "sha256sum").unwrap();
        self.hash_files(&dir, &toks[sum + 1..])
    }

    fn hash_files(&self, dir: &Path, names: &[&str]) -> io::Result<RunnerOutput> {
        let mut out = String::new();
        let mut errs: Vec<String> = Vec::new();
        let mut code = 0;
        for name in names {
            let f = dir.join(name);
            match std::fs::read(&f) {
                Ok(bytes) => out.push_str(&format!("{}  {name}\n", sha256_hex(&bytes))),
                Err(_) => {
                    code = 1;
                    errs.push(format!("sha256sum: {name}: No such file or directory"));
                }
            }
        }
        Ok(RunnerOutput {
            code,
            stdout: out.into_bytes(),
            stderr: errs.join("\n"),
        })
    }

    /// `mkdir -p <payload> <out> && ln -f <objects...> <payload>` — the
    /// job-directory preparation with real hardlinks.
    fn job_prep(&self, cmd: &str) -> io::Result<RunnerOutput> {
        let toks: Vec<&str> = cmd.split_whitespace().collect();
        let mp = toks.iter().position(|t| *t == "-p").unwrap();
        let mut i = mp + 1;
        while i < toks.len() && toks[i] != "&&" {
            std::fs::create_dir_all(self.remote_path(toks[i]).unwrap())?;
            i += 1;
        }
        let ln = toks.iter().position(|t| *t == "-f").unwrap();
        let (dst, srcs) = toks[ln + 1..].split_last().unwrap();
        let dst_dir = self.remote_path(dst).unwrap();
        for src in srcs {
            let from = self.remote_path(src).unwrap();
            let name = Path::new(src).file_name().unwrap();
            std::fs::hard_link(&from, dst_dir.join(name))?;
        }
        Ok(Self::ok(String::new()))
    }

    /// `mkdir -p <objects> && mv <staging>/* <objects>/ && rm -rf
    /// <staging> <incoming>` — the verified-blob commit.
    fn commit(&self, cmd: &str) -> io::Result<RunnerOutput> {
        let toks: Vec<&str> = cmd.split_whitespace().collect();
        let mp = toks.iter().position(|t| *t == "-p").unwrap();
        std::fs::create_dir_all(self.remote_path(toks[mp + 1]).unwrap())?;
        let mv = toks.iter().position(|t| *t == "mv").unwrap();
        let staging = self
            .remote_path(toks[mv + 1].strip_suffix("/*").unwrap())
            .unwrap();
        let objects = self
            .remote_path(toks[mv + 2].trim_end_matches('/'))
            .unwrap();
        for entry in std::fs::read_dir(&staging)?.flatten() {
            let name = entry.file_name();
            std::fs::rename(entry.path(), objects.join(&name))?;
        }
        if let Some(rf) = toks.iter().position(|t| *t == "-rf") {
            for token in &toks[rf + 1..] {
                if let Some(p) = self.remote_path(token) {
                    let _ = std::fs::remove_dir_all(&p);
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        Ok(Self::ok(String::new()))
    }

    fn scp(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        let src = &argv[argv.len() - 2];
        let dst = &argv[argv.len() - 1];
        if src.contains(':') {
            // Pull: remote file → local path (real scp splits host:path
            // at the FIRST colon).
            let remote = src.split_once(':').unwrap().1;
            let from = self.remote_path(remote).expect("remote source under ~");
            let mut bytes = std::fs::read(&from)?;
            if self
                .corrupt_artifact
                .as_deref()
                .is_some_and(|n| from.to_string_lossy().ends_with(n))
            {
                flip_last(&mut bytes);
            }
            std::fs::write(dst, bytes)?;
        } else {
            // Push: local file → remote path.
            let Some(to) = dst
                .split_once(':')
                .and_then(|(_, remote)| self.remote_path(remote))
            else {
                panic!("scp push: unparsable destination {dst:?}");
            };
            let mut bytes = std::fs::read(src)?;
            if to.file_name().is_some_and(|n| n == "job.json") {
                self.pushed_job_files.lock().unwrap().push(bytes.clone());
            }
            std::fs::create_dir_all(to.parent().unwrap())?;
            // The intercepting wrapper corrupts the payload tar in
            // flight — a byte inside the first member's data, so the
            // extraction succeeds but the content is wrong.
            if self.corrupt_payload_push && to.to_string_lossy().contains("/incoming/") {
                flip_at(&mut bytes, 517);
            }
            std::fs::write(to, bytes)?;
        }
        Ok(Self::ok(String::new()))
    }
}

impl CommandRunner for LoopbackWorker {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        self.record(argv);
        match argv[0].as_str() {
            "ssh" => self.ssh(argv),
            "scp" => self.scp(argv),
            "tar" => RealRunner.run(argv),
            "ssh-keygen" => {
                // `-lf <path>`: report the configured fingerprint for
                // whichever key file the executor inspects (the CA-form
                // resolution seam).
                let Some(path) = argv
                    .iter()
                    .position(|a| a == "-lf")
                    .map(|i| argv[i + 1].clone())
                else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("loopback: unsupported ssh-keygen argv {argv:?}"),
                    ));
                };
                let _ = path;
                Ok(RunnerOutput {
                    code: 0,
                    stdout: format!("256 {} loopback-ca (ED25519)\n", self.reported_fingerprint)
                        .into_bytes(),
                    stderr: String::new(),
                })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("loopback: unexpected program {other}"),
            )),
        }
    }
}

// ── Fixtures ──

fn cap_happy() -> CapabilityDoc {
    CapabilityDoc {
        protocol: WORKER_PROTOCOL_VERSION,
        arch: host_arch(),
        nproc: 4,
        ram_bytes: 8_000_000_000,
        free_disk_bytes: 1024u64.pow(4),
        bwrap: true,
        mksquashfs: true,
        kvm: false,
        sandbox: true,
        mksquashfs_version: Some(nau::provision::SQUASHFS_TOOLS_VERSION.into()),
    }
}

fn worker_cfg(address: &str, pin: Option<&str>) -> WorkerConfig {
    WorkerConfig {
        address: address.to_string(),
        jobs: 2,
        arch: None,
        host_key: pin.map(str::to_string),
        identity: None,
    }
}

/// [`worker_cfg`] with a client identity pinned (#298).
fn worker_cfg_identity(address: &str, pin: Option<&str>, identity: &str) -> WorkerConfig {
    WorkerConfig {
        identity: Some(identity.to_string()),
        ..worker_cfg(address, pin)
    }
}

fn executor(fake: LoopbackWorker, cache: &Path) -> SshExecutor<LoopbackWorker> {
    // The pin is the CA fingerprint (the only form), so the helper rides
    // a hermetic ceremony fixture nested in the same tempdir root: the
    // CA public half on disk, the machine linkage for the address, and
    // the fake's default fingerprint report matching [`FINGERPRINT_PIN`].
    let ceremony = cache.join("ceremony");
    ca_ceremony(&ceremony);
    SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache,
        &ceremony,
    )
    .expect("executor builds")
}

fn hello_recipe() -> String {
    r#"
return {
    default = snap {
        name = "worker-hello",
        version = "1.0.0",
        summary = "ssh transport loopback fixture",
        description = "built by the transport loopback harness",
    },
}
"#
    .to_string()
}

fn hello_manifest() -> JobManifest {
    let mut map = std::collections::BTreeMap::new();
    map.insert("pkgs/w/worker-hello.lua".to_string(), hello_recipe());
    JobManifest {
        protocol_version: WORKER_PROTOCOL_VERSION,
        target: host_arch(),
        cross_target: None,
        source_date_epoch: Some(1700000000),
        package: "worker-hello".to_string(),
        recipes: map,
        pins: Vec::new(),
        closure: Vec::new(),
        payload_dir: None,
    }
}

/// A manifest carrying two `dep:` payload blobs, for the delta-sync
/// machinery, answered by the scripted result document.
fn blob_manifest(blobs: &[(&str, &str)]) -> JobManifest {
    let mut map = std::collections::BTreeMap::new();
    map.insert("pkgs/w/worker-hello.lua".to_string(), hello_recipe());
    JobManifest {
        protocol_version: WORKER_PROTOCOL_VERSION,
        target: host_arch(),
        cross_target: None,
        source_date_epoch: Some(1700000000),
        package: "worker-hello".to_string(),
        recipes: map,
        pins: Vec::new(),
        closure: blobs
            .iter()
            .map(|(sha, purpose)| ClosureObject {
                sha256: sha.to_string(),
                size: 16,
                purpose: purpose.to_string(),
            })
            .collect(),
        payload_dir: None,
    }
}

fn scripted_dispatch(outcome_artifact: &str, bytes: &[u8]) -> (JobResult, Vec<(String, Vec<u8>)>) {
    let result = JobResult {
        protocol_version: WORKER_PROTOCOL_VERSION,
        package: "worker-hello".to_string(),
        target: host_arch(),
        ok: true,
        artifacts: vec![Artifact {
            filename: outcome_artifact.to_string(),
            path: "~/.cache/nau/worker/jobs/x/out/x".to_string(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        }],
        error: None,
        stderr: None,
        build_ms: None,
    };
    (result, vec![(outcome_artifact.to_string(), bytes.to_vec())])
}

fn blob_pair() -> (String, Vec<u8>, String, Vec<u8>) {
    let a = b"payload-blob-01!".to_vec();
    let b = b"payload-blob-02!".to_vec();
    (sha256_hex(&a), a, sha256_hex(&b), b)
}

fn preseed_object(root: &Path, sha: &str, bytes: &[u8]) {
    // The fake machine's `~` is `root`; the object store lives at the
    // same remote path the real layout uses.
    let dir = root.join(".cache/nau/worker/objects");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(sha), bytes).unwrap();
}

// ── Preflight ──

#[test]
fn preflight_happy_and_the_pinned_bounded_argv() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = executor(fake, cache.path());

    let cap = ex
        .preflight(PreflightChecks {
            arch: Some("amd64"),
            min_free_disk: 1,
        })
        .expect("happy preflight");
    assert_eq!(cap.protocol, WORKER_PROTOCOL_VERSION);

    let ssh_hops = LoopbackWorker::count_program(&calls, "ssh");
    let calls = calls.lock().unwrap();
    // One coordinator-side `ssh-keygen -lf` (the fingerprint check)
    // precedes exactly one channel hop.
    assert_eq!(calls.len(), 2, "fingerprint check, then the dial");
    assert_eq!(calls[0][0], "ssh-keygen");
    assert_eq!(ssh_hops, 1, "exactly one channel hop");
    let argv = calls.iter().find(|a| a[0] == "ssh").expect("the ssh dial");
    assert_eq!(argv[argv.len() - 1], "nau __worker-cap");
    assert_eq!(argv[argv.len() - 2], "localhost");
    for opt in [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
    ] {
        assert!(
            argv.contains(&opt.to_string()),
            "argv missing {opt}: {argv:?}"
        );
    }
    let known = argv
        .iter()
        .find(|a| a.starts_with("UserKnownHostsFile="))
        .expect("managed known_hosts option");
    let known_path = known.strip_prefix("UserKnownHostsFile=").unwrap();
    let pinned = std::fs::read_to_string(known_path).expect("managed known_hosts written");
    let key_half = CA_PUB_LINE
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(pinned, format!("@cert-authority {CA_IDENTITY} {key_half}"));
}

// ── The client-identity pin (#298) ──

/// An executor whose entry pins `identity`, over a ceremony fixture.
fn identity_executor(
    cache: &Path,
    identity: &str,
    fake: LoopbackWorker,
) -> SshExecutor<LoopbackWorker> {
    let ceremony = cache.join("ceremony");
    ca_ceremony(&ceremony);
    SshExecutor::with_ceremony_home(
        &worker_cfg_identity("ssh://localhost", Some(FINGERPRINT_PIN), identity),
        fake,
        cache,
        &ceremony,
    )
    .expect("executor builds")
}

#[test]
fn entry_identity_rides_the_argv_as_identities_only() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let key = cache.path().join("lane-key");
    std::fs::write(&key, "private-bytes").unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = identity_executor(cache.path(), &key.to_string_lossy(), fake);
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("preflight with a pinned identity");
    let calls = calls.lock().unwrap();
    let argv = calls.iter().find(|a| a[0] == "ssh").expect("the ssh dial");
    let i = argv.iter().position(|a| a == "-i").expect("the -i pin");
    assert_eq!(argv[i + 1], key.to_string_lossy(), "exactly the pinned key");
    assert!(
        argv.contains(&"IdentitiesOnly=yes".to_string()),
        "auth is bound to the pinned key: {argv:?}"
    );
}

#[test]
fn missing_entry_identity_refuses_before_any_channel_activity() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let absent = cache.path().join("absent-key");
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = identity_executor(cache.path(), &absent.to_string_lossy(), fake);
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("a nonexistent pinned identity refuses");
    let text = format!("{err:#}");
    assert!(
        text.contains("preflight identity"),
        "the refusal names the probe: {text}"
    );
    assert!(
        text.contains("absent-key"),
        "the refusal names the path: {text}"
    );
    assert!(
        !LoopbackWorker::any_call(&calls, |a| a[0] == "ssh" || a[0] == "scp"),
        "zero channel activity before the refusal"
    );
}

#[test]
fn identity_resolution_prefers_entry_then_env_then_defaults() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY (test-only): single-threaded under ENV_LOCK.
    std::env::remove_var("NAU_SSH_IDENTITY");

    // The entry field beats the environment.
    let cache = tempfile::tempdir().unwrap();
    let entry_key = cache.path().join("entry-key");
    let env_key = cache.path().join("env-key");
    std::fs::write(&entry_key, "entry").unwrap();
    std::fs::write(&env_key, "env").unwrap();
    std::env::set_var("NAU_SSH_IDENTITY", &env_key);
    let fake = LoopbackWorker::new(cache.path());
    let calls = fake.calls_handle();
    let ex = identity_executor(cache.path(), &entry_key.to_string_lossy(), fake);
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("entry-field preflight");
    {
        let calls = calls.lock().unwrap();
        let argv = calls.iter().find(|a| a[0] == "ssh").expect("the ssh dial");
        let i = argv.iter().position(|a| a == "-i").expect("the -i pin");
        assert_eq!(argv[i + 1], entry_key.to_string_lossy());
    }

    // The environment beats the default candidates.
    let cache2 = tempfile::tempdir().unwrap();
    let fake2 = LoopbackWorker::new(cache2.path());
    let calls2 = fake2.calls_handle();
    let ex2 = {
        let ceremony = cache2.path().join("ceremony");
        ca_ceremony(&ceremony);
        SshExecutor::with_ceremony_home(
            &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
            fake2,
            cache2.path(),
            &ceremony,
        )
        .unwrap()
    };
    ex2.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("env-identity preflight");
    {
        let calls = calls2.lock().unwrap();
        let argv = calls.iter().find(|a| a[0] == "ssh").expect("the ssh dial");
        let i = argv.iter().position(|a| a == "-i").expect("the -i pin");
        assert_eq!(argv[i + 1], env_key.to_string_lossy());
    }
    std::env::remove_var("NAU_SSH_IDENTITY");

    // With no entry field and no env, the ceremony home's default key
    // half wins (the same candidates `resolve_operator_key` walks).
    let cache3 = tempfile::tempdir().unwrap();
    let ceremony3 = cache3.path().join("ceremony");
    ca_ceremony(&ceremony3);
    let default_key = ceremony3.join(".ssh").join("id_ed25519");
    std::fs::create_dir_all(default_key.parent().unwrap()).unwrap();
    std::fs::write(&default_key, "default").unwrap();
    let fake3 = LoopbackWorker::new(cache3.path());
    let calls3 = fake3.calls_handle();
    let ex3 = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake3,
        cache3.path(),
        &ceremony3,
    )
    .unwrap();
    ex3.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("default-identity preflight");
    let calls = calls3.lock().unwrap();
    let argv = calls.iter().find(|a| a[0] == "ssh").expect("the ssh dial");
    let i = argv.iter().position(|a| a == "-i").expect("the -i pin");
    assert_eq!(argv[i + 1], default_key.to_string_lossy());
}

#[test]
fn permission_denied_preflight_names_the_identity_sources_tried() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY (test-only): single-threaded under ENV_LOCK.
    std::env::remove_var("NAU_SSH_IDENTITY");

    // Nothing resolves: no entry field, no env, no default candidates
    // under the ceremony home. The auth refusal must carry the sources.
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let mut fake = LoopbackWorker::new(machine.path());
    fake.deny_cap = true;
    let ceremony = cache.path().join("ceremony");
    ca_ceremony(&ceremony);
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        &ceremony,
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("the scripted auth refusal");
    let text = format!("{err:#}");
    assert!(
        text.contains("Permission denied"),
        "the host's refusal rides the message: {text}"
    );
    assert!(
        text.contains("client identity: none resolved"),
        "the preflight names what was tried: {text}"
    );
    assert!(
        text.contains("entry identity unset")
            && text.contains("NAU_SSH_IDENTITY unset")
            && text.contains("id_ed25519")
            && text.contains("id_rsa"),
        "every source is named: {text}"
    );
}

#[test]
fn known_hosts_pattern_covers_the_non_default_port() {
    // Port-coverage semantics survive the CA form: a worker dialed on a
    // non-default port resolves its fingerprint pin the same way, and
    // the @cert-authority line scopes by CERTIFICATE PRINCIPAL (the
    // machine identity), not by an address pattern — so the pin covers
    // every port by construction. The port still rides the argv; the
    // HostKeyAlias (not a [host]:port known_hosts key) carries the
    // match.
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());
    nau::provision::publish::record_machine_link(
        ceremony.path(),
        CA_IDENTITY,
        "ssh://localhost:2222",
    )
    .unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost:2222", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("preflight with port");
    let pinned = std::fs::read_to_string(ex.known_hosts_path()).unwrap();
    let key_half = CA_PUB_LINE
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    // The pattern is the machine identity — the certificate principal —
    // never a [host]:port form; the principal pattern is port-blind.
    assert_eq!(pinned, format!("@cert-authority {CA_IDENTITY} {key_half}"));
    // The dial itself carries the port; the alias is verbatim.
    let ssh_argv = calls
        .lock()
        .unwrap()
        .iter()
        .find(|argv| argv[0] == "ssh")
        .expect("preflight probed the worker")
        .clone();
    assert!(
        ssh_argv.windows(2).any(|w| w[0] == "-p" && w[1] == "2222"),
        "ssh carries -p 2222: {ssh_argv:?}"
    );
    assert!(ssh_argv.contains(&format!("HostKeyAlias={CA_IDENTITY}")));
}

#[test]
fn unpinned_and_malformed_pins_refuse_before_any_channel_activity() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();

    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_cache_dir(&worker_cfg("ssh://localhost", None), fake, cache.path())
        .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("unpinned refuses");
    assert!(err.to_string().contains("localhost"), "{err:#}");
    assert!(err.to_string().contains("unpinned"), "{err:#}");
    assert_eq!(calls.lock().unwrap().len(), 0, "no channel activity");

    // A single unparseable token is not a pin in the (only) fingerprint
    // grammar — the retired-pin refusal names it and carries the remedy.
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_cache_dir(
        &worker_cfg("ssh://localhost", Some("not-a-pin")),
        fake,
        cache.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("non-fingerprint pin refuses");
    let err = err.to_string();
    assert!(err.contains("retired pin"), "{err}");
    assert!(err.contains("nau ca list"), "the remedy rides: {err}");
    assert!(err.contains("localhost"), "{err}");
    assert_eq!(calls.lock().unwrap().len(), 0, "no channel activity");
}

/// The amendment contract, executor side: a config still carrying the
/// retired mint-and-inject pin (a full public-key line) refuses at
/// preflight — by name, with the re-pin remedy, and with zero channel
/// activity. The fingerprint is the only pin form (#295 sub-task 5).
#[test]
fn legacy_public_key_line_pins_are_refused_with_the_re_pin_remedy() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_cache_dir(
        &worker_cfg("ssh://localhost", Some(LEGACY_LINE_PIN)),
        fake,
        cache.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("the retired pin form refuses");
    let err = err.to_string();
    assert!(err.contains("retired pin"), "{err}");
    assert!(
        err.contains("mint-and-inject"),
        "names the retired mechanism: {err}"
    );
    assert!(
        err.contains("re-pin with the CA fingerprint from `nau ca list`"),
        "the operator migration path rides: {err}"
    );
    assert!(err.contains("localhost"), "refused by name: {err}");
    assert_eq!(
        LoopbackWorker::count_program(&calls, "ssh"),
        0,
        "no channel activity"
    );
}

/// The ceremony fixture for the CA-form tests: the CA public half on
/// disk and the machine linkage recorded for `ssh://localhost` under
/// `ceremony` (the seam `with_ceremony_home` points the executor at).
fn ca_ceremony(ceremony: &Path) {
    let ca_dir = ceremony.join(".config/nau/ca");
    std::fs::create_dir_all(ca_dir.join("machines")).unwrap();
    std::fs::write(ca_dir.join("ca.pub"), format!("{CA_PUB_LINE}\n")).unwrap();
    nau::provision::publish::record_machine_link(ceremony, CA_IDENTITY, "ssh://localhost").unwrap();
}

/// An issued record for [`CA_IDENTITY`] with the given principals — the
/// pattern the @cert-authority line carries once issuance happened.
fn issue_record(ceremony: &Path, principals: &[&str]) {
    let record = nau::provision::publish::IssuedIdentity {
        machine_identity: CA_IDENTITY.to_string(),
        public_key: CA_PUB_LINE.to_string(),
        instance_identity: serde_json::json!({"instance_id": "i-abc"}),
        received_at_epoch: 1,
        token_sha256: "a".repeat(64),
        cert: "fake".to_string(),
        principals: principals.iter().map(|s| s.to_string()).collect(),
        validity: "+48h".to_string(),
        issued_at_epoch: 1,
        ca_fingerprint: FINGERPRINT_PIN.to_string(),
    };
    let dir = nau::provision::publish::issued_dir(ceremony);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("issued-{CA_IDENTITY}.json")),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
}

#[test]
fn ca_fingerprint_pin_builds_the_cert_authority_line_and_connects_under_the_machine_identity() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());

    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("the CA pin enforces: preflight runs");

    // ONE @cert-authority line; the pattern is the machine identity (no
    // issued record yet — the certificate binds the identity first, so
    // the pattern matches from the moment the coordinator signs).
    let pinned = std::fs::read_to_string(ex.known_hosts_path()).unwrap();
    let key_half = CA_PUB_LINE
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(pinned, format!("@cert-authority {CA_IDENTITY} {key_half}"));

    // The connection runs under the machine identity — the alias both
    // matches the pattern and is the name the host-cert principal check
    // runs against (ssh uses the alias verbatim, no [host]:port form).
    let ssh_argv = calls
        .lock()
        .unwrap()
        .iter()
        .find(|argv| argv[0] == "ssh")
        .expect("preflight probed the worker")
        .clone();
    let alias_at = ssh_argv
        .iter()
        .position(|a| a == "HostKeyAlias=nau-worker-ca-test-01")
        .expect("HostKeyAlias rides the argv");
    assert_eq!(
        ssh_argv[alias_at - 1],
        "-o",
        "the alias rides as -o HostKeyAlias=…"
    );
    // StrictHostKeyChecking stays yes — the posture is unchanged.
    assert!(ssh_argv.contains(&"StrictHostKeyChecking=yes".to_string()));
}

#[test]
fn ca_form_pattern_is_the_issued_principals_machine_identity_first() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());
    issue_record(
        ceremony.path(),
        &[
            CA_IDENTITY,
            "i-abc123",
            "aws",
            "eu-central-1",
            "eu-central-1a",
        ],
    );

    let fake = LoopbackWorker::new(machine.path());
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    ex.preflight(PreflightChecks {
        arch: None,
        min_free_disk: 0,
    })
    .expect("preflight runs");

    let pinned = std::fs::read_to_string(ex.known_hosts_path()).unwrap();
    let key_half = CA_PUB_LINE
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        pinned,
        format!("@cert-authority {CA_IDENTITY},i-abc123,aws,eu-central-1,eu-central-1a {key_half}"),
        "the pattern is the certificate's principal list, machine identity first"
    );
}

#[test]
fn ca_pin_refusals_name_the_gap_before_any_channel_activity() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();

    // ── the ceremony CA's public half is absent ──
    let ceremony = tempfile::tempdir().unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("absent CA refuses");
    let err = err.to_string();
    assert!(err.contains("ca.pub"), "{err}");
    assert!(err.contains("ca keygen"), "{err}");
    assert!(err.contains("localhost"), "{err}");
    assert_eq!(calls.lock().unwrap().len(), 0, "no subprocess ran at all");

    // ── the ceremony CA fingerprints to something else (rotated) ──
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());
    let mut fake = LoopbackWorker::new(machine.path());
    fake.reported_fingerprint = "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".into();
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("mismatched CA refuses");
    let err = err.to_string();
    assert!(err.contains(FINGERPRINT_PIN), "the pin is named: {err}");
    assert!(err.contains("fingerprints to"), "{err}");
    assert_eq!(
        LoopbackWorker::count_program(&calls, "ssh"),
        0,
        "no channel activity"
    );

    // ── no machine linkage for the address ──
    let ceremony = tempfile::tempdir().unwrap();
    let ca_dir = ceremony.path().join(".config/nau/ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join("ca.pub"), format!("{CA_PUB_LINE}\n")).unwrap();
    let fake = LoopbackWorker::new(machine.path());
    let calls = fake.calls_handle();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("unlinked address refuses");
    let err = err.to_string();
    assert!(err.contains("machine identity is linked"), "{err}");
    assert!(err.contains("machines"), "{err}");
    assert!(err.contains("localhost"), "{err}");
    assert_eq!(
        LoopbackWorker::count_program(&calls, "ssh"),
        0,
        "no channel activity"
    );

    // ── a malformed fingerprint shape ──
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());
    let fake = LoopbackWorker::new(machine.path());
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost", Some("SHA256:tooshort")),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();
    let err = ex
        .preflight(PreflightChecks {
            arch: None,
            min_free_disk: 0,
        })
        .expect_err("malformed fingerprint refuses");
    assert!(
        err.to_string().contains("malformed fingerprint pin"),
        "{err:#}"
    );
}

#[test]
fn preflight_refusals_name_the_probe() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();

    let cases: &[(&str, &dyn Fn(&mut LoopbackWorker))] = &[
        ("preflight protocol", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.protocol = 99)
        }),
        ("preflight arch", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.arch = "arm64".into())
        }),
        ("preflight bwrap", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.bwrap = false)
        }),
        ("preflight sandbox", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.sandbox = false)
        }),
        ("preflight mksquashfs", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.mksquashfs = false)
        }),
        ("preflight disk", &|f: &mut LoopbackWorker| {
            f.set_cap(|c| c.free_disk_bytes = 1)
        }),
    ];
    for (probe, mutate) in cases {
        let mut fake = LoopbackWorker::new(machine.path());
        (mutate)(&mut fake);
        let ex = executor(fake, cache.path());
        let err = ex
            .preflight(PreflightChecks {
                arch: Some("amd64"),
                min_free_disk: 1024 * 1024 * 1024,
            })
            .expect_err("must refuse");
        let text = format!("{err:#}");
        assert!(text.starts_with(probe), "probe '{probe}' not named: {text}");
    }
}

#[test]
fn preflight_refuses_an_mksquashfs_off_the_fleet_pin() {
    // The #273 pinned-mksquashfs admission: an off-pin version AND an
    // unreadable one both refuse, by name, with the pin in the message —
    // fail-closed, never a silent pass.
    for cap_version in [Some("4.6.1".to_string()), None] {
        let cache = tempfile::tempdir().unwrap();
        let machine = tempfile::tempdir().unwrap();
        let mut fake = LoopbackWorker::new(machine.path());
        let reported = cap_version.clone().unwrap_or_else(|| "<unreadable>".into());
        fake.set_cap(move |c| c.mksquashfs_version = cap_version.clone());
        let ex = executor(fake, cache.path());
        let err = ex
            .preflight(PreflightChecks {
                arch: None,
                min_free_disk: 0,
            })
            .expect_err("off-pin or unreadable mksquashfs refuses");
        let text = format!("{err:#}");
        assert!(
            text.starts_with("preflight mksquashfs version"),
            "probe not named: {text}"
        );
        assert!(
            text.contains(&reported),
            "names what the worker reported: {text}"
        );
        assert!(
            text.contains(nau::provision::SQUASHFS_TOOLS_VERSION),
            "names the fleet pin: {text}"
        );
    }
}

// ── Dispatch: the full loopback job (real build) ──

#[test]
fn dispatch_lands_the_artifact_in_the_coordinator_ingest() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let mut fake = LoopbackWorker::new(machine.path());
    fake.real_job = true;
    let ex = executor(fake, cache.path());

    let manifest = hello_manifest();
    let payload = tempfile::tempdir().unwrap();
    let outcome = ex
        .dispatch(&manifest, payload.path())
        .expect("loopback dispatch");
    assert!(!outcome.cache_hit);
    assert!(outcome.result.ok);

    let dir = ex.ingest_dir(&manifest).unwrap();
    let id_slug = manifest_identity(&manifest).unwrap().replace(':', "_");
    assert!(dir.join("result.json").exists(), "ingest record present");
    assert!(
        dir.to_string_lossy().contains(&id_slug),
        "ingest keyed under the manifest identity: {dir:?}"
    );
    assert!(!dir.to_string_lossy().contains("v4:"), "never v4-keyed");
    for art in &outcome.result.artifacts {
        let stored = dir.join(&art.filename);
        assert!(stored.exists(), "artifact ingested: {stored:?}");
        assert_eq!(
            nau::oci::sha256_file(&stored).unwrap(),
            art.sha256,
            "stored bytes hash to the verified claim"
        );
    }
}

#[test]
fn second_identical_dispatch_is_a_cache_hit_that_transfers_nothing() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let mut fake = LoopbackWorker::new(machine.path());
    fake.real_job = true;
    let calls = fake.calls_handle();
    let ex = executor(fake, cache.path());

    let manifest = hello_manifest();
    let payload = tempfile::tempdir().unwrap();
    let first = ex.dispatch(&manifest, payload.path()).expect("first run");
    assert!(!first.cache_hit);
    let after_first = calls.lock().unwrap().len();

    let second: DispatchOutcome = ex.dispatch(&manifest, payload.path()).expect("second run");
    assert!(second.cache_hit, "served from the ingest record");
    assert_eq!(
        calls.lock().unwrap().len(),
        after_first,
        "zero channel activity on the cache hit"
    );
    assert_eq!(second.result.artifacts.len(), first.result.artifacts.len());
    let (second_hashes, first_hashes) = (
        second
            .result
            .artifacts
            .iter()
            .map(|a| a.sha256.clone())
            .collect::<Vec<_>>(),
        first
            .result
            .artifacts
            .iter()
            .map(|a| a.sha256.clone())
            .collect::<Vec<_>>(),
    );
    assert_eq!(second_hashes, first_hashes);
}

// ── Delta sync (scripted transport scenarios) ──

#[test]
fn delta_sync_ships_only_the_missing_objects() {
    let (sha_a, blob_a, sha_b, blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let artifact_bytes = b"scripted snap artifact".to_vec();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", &artifact_bytes);
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    let calls = fake.calls_handle();
    let job_files = fake.job_files_handle();
    // The worker already holds blob A — exactly.
    preseed_object(machine.path(), &sha_a, &blob_a);
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    std::fs::write(payload.path().join(&sha_a), &blob_a).unwrap();
    std::fs::write(payload.path().join(&sha_b), &blob_b).unwrap();
    let manifest = blob_manifest(&[(&sha_a, "dep:dep-a"), (&sha_b, "dep:dep-b")]);

    let outcome = ex
        .dispatch(&manifest, payload.path())
        .expect("delta dispatch");
    assert!(!outcome.cache_hit);

    // The shipped job file names the transport-local payload dir — the
    // worker refuses a manifest with objects but no payload_dir, and
    // coordinator-side paths never cross the channel (the identity
    // strips this field).
    let shipped = job_files.lock().unwrap().clone();
    assert_eq!(shipped.len(), 1, "one job.json ships per dispatch");
    let job: serde_json::Value = serde_json::from_slice(&shipped[0]).expect("json");
    assert_eq!(
        job["payload_dir"], "payload",
        "the job file points at the staged payload dir, relative to itself"
    );
    assert_eq!(
        job["closure"].as_array().map(Vec::len),
        Some(2),
        "both objects ride the manifest"
    );

    // The tar bundle carried only the missing object.
    let tarred = LoopbackWorker::any_call(&calls, |argv| {
        argv[0] == "tar" && argv.iter().any(|a| a == &sha_b)
    });
    assert!(tarred, "the missing object shipped");
    let tarred_held = LoopbackWorker::any_call(&calls, |argv| {
        argv[0] == "tar" && argv.iter().any(|a| a == &sha_a)
    });
    assert!(!tarred_held, "the held object never shipped");

    // The worker's object store now holds both.
    let objects = machine.path().join(".cache/nau/worker/objects");
    assert!(objects.join(&sha_a).exists());
    assert!(objects.join(&sha_b).exists());

    // The artifact landed, hash-verified, under the manifest identity.
    let dir = ex.ingest_dir(&manifest).unwrap();
    let stored = dir.join("worker-hello_1.0_amd64.snap");
    assert_eq!(
        nau::oci::sha256_file(&stored).unwrap(),
        sha256_hex(&artifact_bytes)
    );
}

#[test]
fn all_objects_held_means_no_transfer_at_all() {
    let (sha_a, blob_a, sha_b, blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let artifact_bytes = b"scripted snap artifact".to_vec();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", &artifact_bytes);
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    let calls = fake.calls_handle();
    preseed_object(machine.path(), &sha_a, &blob_a);
    preseed_object(machine.path(), &sha_b, &blob_b);
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    let manifest = blob_manifest(&[(&sha_a, "dep:dep-a"), (&sha_b, "dep:dep-b")]);
    let outcome = ex
        .dispatch(&manifest, payload.path())
        .expect("zero-transfer dispatch");
    assert!(
        !outcome.cache_hit,
        "the JOB ran; only the transfer is skipped"
    );
    assert_eq!(LoopbackWorker::count_program(&calls, "tar"), 0, "no tar");
    let scp_count = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|argv| argv[0] == "scp")
        .count();
    assert_eq!(scp_count, 2, "job.json out, artifact back — no blob scp");
    let tar_landing = calls
        .lock()
        .unwrap()
        .iter()
        .any(|argv| argv.iter().any(|a| a.contains("/incoming/")));
    assert!(!tar_landing, "no blob landing ever appears on the channel");
    assert!(
        LoopbackWorker::any_call(&calls, |argv| argv
            .last()
            .is_some_and(|c| c.contains("__worker-job"))),
        "the job ran"
    );
}

#[test]
fn corrupt_claimed_object_refuses_before_anything_runs() {
    let (sha_a, blob_a, sha_b, _blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", b"artifact");
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    let calls = fake.calls_handle();
    // The worker CLAIMS to hold blob A but the bytes are truncated poison.
    let mut corrupt = blob_a.clone();
    flip_last(&mut corrupt);
    preseed_object(machine.path(), &sha_a, &corrupt);
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    let manifest = blob_manifest(&[(&sha_a, "dep:dep-a"), (&sha_b, "dep:dep-b")]);
    let err = ex
        .dispatch(&manifest, payload.path())
        .expect_err("poisoned claim refuses");
    let text = format!("{err:#}");
    assert!(text.contains("claims are content-verified"), "{text}");
    assert!(
        !LoopbackWorker::any_call(&calls, |argv| argv
            .last()
            .is_some_and(|c| c.contains("__worker-job"))),
        "nothing dispatched after a failed claim check"
    );
    assert_eq!(LoopbackWorker::count_program(&calls, "tar"), 0);
}

#[test]
fn corruption_in_flight_refuses_before_commit() {
    let (sha_a, blob_a, sha_b, blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", b"artifact");
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    fake.corrupt_payload_push = true; // the intercepting wrapper flips a byte
    let calls = fake.calls_handle();
    preseed_object(machine.path(), &sha_a, &blob_a);
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    std::fs::write(payload.path().join(&sha_b), &blob_b).unwrap();
    let manifest = blob_manifest(&[(&sha_a, "dep:dep-a"), (&sha_b, "dep:dep-b")]);
    let err = ex
        .dispatch(&manifest, payload.path())
        .expect_err("flipped byte refuses");
    let text = format!("{err:#}");
    assert!(
        text.contains("refusing") || text.contains("arrival verification failed"),
        "{text}"
    );
    assert!(
        !machine
            .path()
            .join(".cache/nau/worker/objects")
            .join(&sha_b)
            .exists(),
        "a dead transfer commits nothing"
    );
    assert!(
        !LoopbackWorker::any_call(&calls, |argv| argv
            .last()
            .is_some_and(|c| c.contains("__worker-job"))),
        "the job never ran"
    );
}

#[test]
fn corrupt_returned_artifact_refuses_ingest() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let artifact_bytes = b"scripted snap artifact".to_vec();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", &artifact_bytes);
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    fake.corrupt_artifact = Some("worker-hello_1.0_amd64.snap".to_string());
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    let manifest = hello_manifest();
    let err = ex
        .dispatch(&manifest, payload.path())
        .expect_err("corrupted artifact refuses");
    let text = format!("{err:#}");
    assert!(text.contains("refusing ingest"), "{text}");
    assert!(
        !ex.ingest_dir(&manifest).unwrap().exists(),
        "nothing ingested"
    );
}

#[test]
fn scp_rides_the_same_port_flag_shape() {
    let (sha_a, blob_a, _sha_b, _blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let (result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", b"artifact");
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    let calls = fake.calls_handle();
    preseed_object(machine.path(), &sha_a, &blob_a);
    let ceremony = tempfile::tempdir().unwrap();
    ca_ceremony(ceremony.path());
    nau::provision::publish::record_machine_link(
        ceremony.path(),
        CA_IDENTITY,
        "ssh://localhost:2222",
    )
    .unwrap();
    let ex = SshExecutor::with_ceremony_home(
        &worker_cfg("ssh://localhost:2222", Some(FINGERPRINT_PIN)),
        fake,
        cache.path(),
        ceremony.path(),
    )
    .unwrap();

    let payload = tempfile::tempdir().unwrap();
    std::fs::write(payload.path().join(&sha_a), &blob_a).unwrap();
    let manifest = blob_manifest(&[(sha_a.as_str(), "dep:dep-a")]);
    ex.dispatch(&manifest, payload.path())
        .expect("port dispatch");
    let scp = calls
        .lock()
        .unwrap()
        .iter()
        .find(|argv| argv[0] == "scp")
        .expect("scp used")
        .clone();
    assert!(
        scp.windows(2).any(|w| w[0] == "-P" && w[1] == "2222"),
        "scp carries -P 2222: {scp:?}"
    );
    assert!(
        scp.iter()
            .any(|a| a.starts_with("StrictHostKeyChecking=yes") || a == "-o"),
        "scp carries the pin options"
    );
}

// ── Transport-side manifest identity (src/worker.rs) ──

#[test]
fn manifest_identity_is_canonical_namespaced_and_transport_local_free() {
    let mut manifest = hello_manifest();
    let id = manifest_identity(&manifest).expect("identity");
    assert!(id.starts_with("jm1:"), "{id}");
    assert_eq!(id.len(), "jm1:".len() + 64);

    // Array order and the transport-local payload_dir cannot move it.
    let mut shuffled = hello_manifest();
    shuffled.payload_dir = Some("/somewhere/else".to_string());
    assert_eq!(manifest_identity(&shuffled).unwrap(), id);

    let mut with_pins = hello_manifest();
    with_pins.pins = vec![
        nau::worker::SourcePin {
            url: "https://a".into(),
            sha256: "a".repeat(64),
        },
        nau::worker::SourcePin {
            url: "https://b".into(),
            sha256: "b".repeat(64),
        },
    ];
    let forward = manifest_identity(&with_pins).unwrap();
    with_pins.pins.reverse();
    assert_eq!(manifest_identity(&with_pins).unwrap(), forward);

    let mut other = hello_manifest();
    other.package = "worker-hello-2".to_string();
    assert_ne!(manifest_identity(&other).unwrap(), id);

    // Canonical bytes are JSON, sorted-key, and strip payload_dir.
    let bytes = canonical_manifest_bytes(&manifest).expect("canonical bytes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["package"], "worker-hello");
    assert!(value.get("payload_dir").is_none());

    manifest.payload_dir = Some("local/only".into());
    let bytes2 = canonical_manifest_bytes(&manifest).unwrap();
    assert_eq!(bytes, bytes2, "payload_dir never enters the identity");
}

// ── Per-job phase timings (#302) ──

/// The result document's build_ms rides the dispatch: the scripted
/// worker reports an injected build wall and the coordinator reads it
/// back unchanged. A document WITHOUT the field — an older worker —
/// still parses, defaulted to None: the optional field never bumps the
/// protocol version. The dispatch walls themselves are plausible, not
/// asserted tightly: total covers sync and both are real time.
#[test]
fn result_document_build_ms_is_carried_and_stays_optional() {
    let (sha_a, blob_a, _sha_b, _blob_b) = blob_pair();
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let artifact_bytes = b"scripted snap artifact".to_vec();
    let (mut result, files) = scripted_dispatch("worker-hello_1.0_amd64.snap", &artifact_bytes);
    result.build_ms = Some(1500);
    let mut fake = LoopbackWorker::new(machine.path());
    fake.scripted_result = Some(result);
    fake.scripted_files = files;
    preseed_object(machine.path(), &sha_a, &blob_a);
    let ex = executor(fake, cache.path());

    let payload = tempfile::tempdir().unwrap();
    std::fs::write(payload.path().join(&sha_a), &blob_a).unwrap();
    let manifest = blob_manifest(&[(sha_a.as_str(), "dep:dep-a")]);
    let outcome = ex
        .dispatch(&manifest, payload.path())
        .expect("delta dispatch");
    assert_eq!(
        outcome.result.build_ms,
        Some(1500),
        "the worker-reported build wall arrives as carried"
    );
    assert!(
        outcome.total >= outcome.sync && outcome.total > std::time::Duration::ZERO,
        "the dispatch wall covers the sync phase and is real time: {outcome:?}"
    );

    // An older worker's document — no build_ms key — parses with the
    // serde default. No protocol bump for an optional field.
    let old = format!(
        r#"{{"protocol_version":{WORKER_PROTOCOL_VERSION},"package":"worker-hello","target":"amd64","ok":true}}"#
    );
    let parsed: JobResult = serde_json::from_str(&old).expect("an old document keeps parsing");
    assert_eq!(parsed.build_ms, None, "absent means unreported");
}

/// The REAL worker verb measures its build child: a loopback dispatch
/// running the actual `__worker-job` reports a build wall, and the
/// ingest record carries it for later runs.
#[test]
fn real_worker_job_reports_its_build_wall() {
    let cache = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let mut fake = LoopbackWorker::new(machine.path());
    fake.real_job = true;
    let ex = executor(fake, cache.path());

    let manifest = hello_manifest();
    let payload = tempfile::tempdir().unwrap();
    let outcome = ex
        .dispatch(&manifest, payload.path())
        .expect("loopback dispatch");
    assert!(
        outcome.result.build_ms.is_some(),
        "the worker measures its build child: {outcome:?}"
    );
    let record = ex.ingest_dir(&manifest).unwrap().join("result.json");
    let stored: JobResult =
        serde_json::from_slice(&std::fs::read(&record).expect("ingest record")).expect("json");
    assert_eq!(
        stored.build_ms, outcome.result.build_ms,
        "the ingest record keeps the build wall"
    );
}

#[test]
fn write_job_file_writes_exactly_the_identity_bytes() {
    let manifest = hello_manifest();
    let dir = tempfile::tempdir().unwrap();
    let path = write_job_file(dir.path(), &manifest).expect("job file");
    assert_eq!(path.file_name().unwrap(), "job.json");
    let bytes = std::fs::read(&path).unwrap();
    // The worker loads the file and recomputes the identity from the
    // loaded manifest — the file need not BE the canonical bytes, it
    // must ROUND-TRIP to them.
    let loaded: JobManifest = serde_json::from_slice(&bytes).expect("job file parses");
    assert_eq!(loaded, manifest, "the job file round-trips the manifest");
    assert_eq!(
        manifest_identity(&loaded).unwrap(),
        manifest_identity(&manifest).unwrap(),
        "the shipped job file digests to the manifest identity"
    );
}

/// A transport-local payload_dir rides the job FILE (the worker resolves
/// it against the file's own directory — a manifest naming closure
/// objects without it is refused fail-closed) while the identity still
/// digests the canonical form that strips it.
#[test]
fn write_job_file_carries_the_payload_dir_out_of_the_identity() {
    let mut manifest = hello_manifest();
    manifest.closure.push(nau::worker::ClosureObject {
        sha256: "ab".repeat(32),
        size: 42,
        purpose: "dep:dep-a".to_string(),
    });
    manifest.payload_dir = Some("payload".to_string());
    let dir = tempfile::tempdir().unwrap();
    let path = write_job_file(dir.path(), &manifest).expect("job file");
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("json");
    assert_eq!(
        value["payload_dir"], "payload",
        "the file routes the worker"
    );
    // The identity the worker recomputes from the loaded manifest strips
    // the field — coordinator-local paths never enter it.
    let id = manifest_identity(&manifest).unwrap();
    let canonical = canonical_manifest_bytes(&manifest).unwrap();
    assert_eq!(format!("jm1:{}", sha256_hex(&canonical)), id);
    assert!(!String::from_utf8_lossy(&canonical).contains("payload"));
}
