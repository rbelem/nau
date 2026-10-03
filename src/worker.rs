//! Build-farm worker verbs (ADR-0040 Decisions 2+6): `__worker-cap` and
//! `__worker-job` — the machine-side siblings of the process-side
//! `__eval-worker`/`__check-worker` pair.
//!
//! A Worker is a machine, not a process: these hidden verbs are the only
//! surface it exposes. `__worker-cap` prints one JSON capability document
//! and exits; `__worker-job <job-file>` executes exactly one job manifest —
//! materializes the recipe slice and pinned inputs, verifies EVERY payload
//! sha256 before anything runs, then drives the ordinary offline sandbox
//! path through `snap.rs::build_snap` and prints one JSON result document.
//!
//! The never-fetch invariant is mechanically enforced, not just validated:
//! the job sets `NAU_TOOL_CURL` (the documented per-tool override in
//! `tools.rs`, which beats every other resolution rule) to a generated shim
//! that serves ONLY the source bytes shipped in the job payload and refuses
//! every other URL. A source the manifest did not ship cannot be fetched —
//! the shim fails the fetch by name, before the sandbox starts.
//!
//! Refusals (bad manifest, wrong protocol version, any hash/size mismatch,
//! an unpinned or unshipped source) are named miette errors returned before
//! any build work: the verb prints NO result document on a refusal. Once
//! the job executes, it prints a result document and exits zero even when
//! the build itself failed — the outcome rides inside the document.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// The wire-protocol vocabulary moved DOWN into `nau_pool::worker`
// (issue #326 PR 9): the structs + canonicalization are the wire —
// byte-identical, digest-critical. Re-exported so every
// `crate::worker::` and `nau::worker::` path keeps resolving
// (tests/worker_job.rs, tests/ssh_exec.rs, tests/coordinator_farm.rs,
// the coordinator). The verb EXECUTION half (this file) consumes
// `validate_purpose`/`short_sha` from the same home.
pub use nau_pool::worker::{
    canonical_manifest_bytes, manifest_identity, write_job_file, Artifact, CapabilityDoc,
    ClosureObject, JobManifest, JobResult, SourcePin, WORKER_PROTOCOL_VERSION,
};
use nau_pool::worker::{short_sha, validate_purpose};

/// Build the capability document for THIS machine — the test seam; the
/// verb serializes whatever this returns.
pub fn capability_document() -> CapabilityDoc {
    let bwrap = tool_present(crate::tools::ToolName::Bwrap);
    let mksquashfs = crate::tools::resolve(crate::tools::ToolName::Mksquashfs).ok();
    // One extra exec on a one-shot verb, so admission can pin the exact
    // mksquashfs (ADR-0041: mksquashfs behavior is artifact identity).
    let mksquashfs_version = mksquashfs.as_ref().and_then(|resolved| {
        let path = match resolved {
            crate::tools::ResolvedTool::Provisioned { path, .. }
            | crate::tools::ResolvedTool::Path { path, .. } => path,
        };
        crate::tools::discover_version(path)
    });
    CapabilityDoc {
        protocol: WORKER_PROTOCOL_VERSION,
        arch: crate::snap::host_arch().to_string(),
        nproc: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        ram_bytes: total_ram_bytes(),
        free_disk_bytes: free_disk_bytes(&std::env::temp_dir()),
        bwrap,
        mksquashfs: mksquashfs.is_some(),
        kvm: crate::boot_test::kvm_available(),
        sandbox: bwrap && sandbox_probe_succeeds(),
        mksquashfs_version,
    }
}

/// Entry point for `nau __worker-cap`: print the capability document
/// as one JSON object on stdout, then exit.
pub fn cap_main() -> miette::Result<()> {
    let doc = capability_document();
    let json = serde_json::to_string_pretty(&doc)
        .map_err(|e| miette::miette!("worker-cap: cannot serialize capability document: {e}"))?;
    println!("{json}");
    Ok(())
}

fn tool_present(name: crate::tools::ToolName) -> bool {
    crate::tools::resolve(name).is_ok()
}

/// Minimal but real sandbox probe (ADR-0040 Decision 2(c)): a bwrap
/// invocation that creates user/network/IPC namespaces and read-only binds
/// the root. Proves unprivileged user namespaces actually work here —
/// `which bwrap` alone does not (kernel policy can disable them).
fn sandbox_probe_succeeds() -> bool {
    let Ok(resolved) = crate::tools::resolve(crate::tools::ToolName::Bwrap) else {
        return false;
    };
    let bwrap = match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path,
    };
    std::process::Command::new(bwrap)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-net",
            "--unshare-ipc",
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `/proc/meminfo` MemTotal, in bytes. 0 when unreadable (the cap document
/// reports the probe honestly; preflight decides what a 0 means).
fn total_ram_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                let kv = l.strip_prefix("MemTotal:")?;
                kib_field(kv)
            })
        })
        .unwrap_or(0)
}

/// The first integer field of a `/proc/meminfo` line body ("  16384 kB").
fn kib_field(body: &str) -> Option<u64> {
    let kib = body.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(kib * 1024)
}

/// Available-to-unprivileged bytes on `path`'s filesystem via statvfs.
/// 0 when unreadable.
fn free_disk_bytes(path: &Path) -> u64 {
    let Ok(c) = std::ffi::CString::new(path.to_string_lossy().as_bytes()) else {
        return 0;
    };
    // SAFETY: `c` outlives the call; `st` is a plain out-parameter the
    // syscall fully initializes on success.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) == 0 {
            st.f_bavail as u64 * st.f_frsize as u64
        } else {
            0
        }
    }
}

// ── __worker-job ──

/// Entry point for `nau __worker-job <job-file>`: load the manifest,
/// verify everything, execute one job, print one result document. The
/// built artifacts land in an `out/` directory beside the job file — they
/// must outlive the job's scratch, because the transport collects them by
/// the paths in the result document.
pub fn job_main(job_file: &str) -> miette::Result<()> {
    // The transport contract (ADR-0040 T3/T4): this verb's stdout carries
    // the result document and NOTHING else. Build children inherit fd 1
    // (mksquashfs's progress banner is .status()-spawned), and over the
    // ssh channel that inherited stdout corrupts the document the
    // coordinator parses — so the job runs with its process stdout
    // re-pointed at stderr, and the document goes to the saved original.
    use std::os::unix::io::FromRawFd;
    let saved_stdout = unsafe { libc::dup(1) };
    if saved_stdout < 0 {
        return Err(miette::miette!(
            "worker-job: cannot save the result stream (dup failed)"
        ));
    }
    unsafe { libc::dup2(2, 1) };
    let result = execute_job_manifest(PathBuf::from(job_file))?;
    let json = serde_json::to_string_pretty(&result)
        .map_err(|e| miette::miette!("worker-job: cannot serialize result document: {e}"))?;
    let mut out = unsafe { std::fs::File::from_raw_fd(saved_stdout) };
    use std::io::Write;
    writeln!(out, "{json}")
        .map_err(|e| miette::miette!("worker-job: cannot write the result document: {e}"))?;
    Ok(())
}

/// Load, execute, return — the testable core of [`job_main`]; the verb
/// wrapper owns the stdout contract.
fn execute_job_manifest(path: PathBuf) -> miette::Result<JobResult> {
    let manifest = load_manifest(&path)?;
    let payload_dir = resolve_payload_dir(&path, &manifest);
    let out_dir = path.parent().unwrap_or(Path::new(".")).join("out");
    execute_job(&manifest, payload_dir.as_deref(), &out_dir)
}

/// Parse the job manifest file. A missing or unparseable file is a named
/// refusal — the coordinator's dispatch is wrong, not the build.
pub fn load_manifest(path: &Path) -> miette::Result<JobManifest> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        miette::miette!(
            "worker-job: cannot read job manifest {}: {e}",
            path.display()
        )
    })?;
    serde_json::from_str(&content).map_err(|e| {
        miette::miette!(
            "worker-job: {} is not a valid job manifest: {e}",
            path.display()
        )
    })
}

/// Where the payload blobs live: the manifest's `payload_dir`, resolved
/// against the job file's directory when relative.
fn resolve_payload_dir(job_file: &Path, manifest: &JobManifest) -> Option<PathBuf> {
    let dir = manifest.payload_dir.as_deref()?;
    let p = Path::new(dir);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        job_file.parent().unwrap_or(Path::new(".")).join(p)
    })
}

/// Verified payload objects, keyed by purpose, ready to materialize.
struct PayloadSet {
    /// `source` blobs: the source URL each blob serves (from the pin
    /// slice) → the verified blob path.
    sources: BTreeMap<String, PathBuf>,
    /// `dep:<pkg>` blobs: package name → the verified `.snap` path.
    deps: Vec<(String, PathBuf)>,
    /// The `stage` blob (#310): the verified stage tarball a stage-only
    /// recipe packs — unpacked into the build stage before the pack.
    stage: Option<PathBuf>,
}

/// Process-global state a job mutates for its duration (CWD, a few env
/// vars, the child-stderr buffering flag). The lock serializes it so a
/// job's resolution universe (CWD-relative `pkgs/` lookup, tool overrides)
/// cannot be swapped under a concurrent job in the same process — one
/// worker process runs one job, so production never contends; the lock
/// exists for the in-process tests.
static PROCESS_STATE_LOCK: Mutex<()> = Mutex::new(());

/// Execute one verified manifest end to end (the `__worker-job` body,
/// minus file loading and result printing — the test seam).
///
/// Every refusal (protocol, shape, hash, size, missing blob, unpinned or
/// unshipped source) is a named error returned BEFORE any build work
/// starts. `payload_dir` holds the closure blobs named by their sha256;
/// `None` is valid only for an empty closure.
pub fn execute_job(
    manifest: &JobManifest,
    payload_dir: Option<&Path>,
    out_dir: &Path,
) -> miette::Result<JobResult> {
    validate_manifest(manifest)?;
    let payloads = verify_payloads(manifest, payload_dir)?;

    let _state = PROCESS_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = JobStateGuard::capture()?;
    run_job(manifest, &payloads, out_dir)
}

/// Process state a job mutates for its duration (CWD, a few env vars, the
/// child-stderr buffering flag). A Drop guard so a panicking job still
/// unwinds the state — the process (and the in-process tests) keep a sane
/// environment after one job fails.
struct JobStateGuard {
    cwd: PathBuf,
    epoch: Option<std::ffi::OsString>,
    curl: Option<std::ffi::OsString>,
}

impl JobStateGuard {
    fn capture() -> miette::Result<Self> {
        Ok(JobStateGuard {
            cwd: std::env::current_dir()
                .map_err(|e| miette::miette!("worker-job: cannot read current directory: {e}"))?,
            epoch: std::env::var_os("SOURCE_DATE_EPOCH"),
            curl: std::env::var_os("NAU_TOOL_CURL"),
        })
    }
}

impl Drop for JobStateGuard {
    fn drop(&mut self) {
        // Best-effort restore: the worker process exits after one job; the
        // restore exists so in-process tests keep a sane environment.
        std::env::set_current_dir(&self.cwd).ok();
        restore_var("SOURCE_DATE_EPOCH", self.epoch.as_deref());
        restore_var("NAU_TOOL_CURL", self.curl.as_deref());
        crate::snap::set_buffer_child_stderr(false);
    }
}

/// Execute the build inside the job's process state. All refusal checks
/// that need the materialized root run here, before `build_snap`. The job
/// root tempdir is dropped when this returns — every scratch file the job
/// materialized is cleaned up with it (artifacts were written to
/// `out_dir`, outside the root).
fn run_job(
    manifest: &JobManifest,
    payloads: &PayloadSet,
    out_dir: &Path,
) -> miette::Result<JobResult> {
    let root = materialize_root(manifest)?;
    std::env::set_current_dir(root.path())
        .map_err(|e| miette::miette!("worker-job: cannot enter job root: {e}"))?;
    if let Some(epoch) = manifest.source_date_epoch {
        std::env::set_var("SOURCE_DATE_EPOCH", epoch.to_string());
    }

    // The never-fetch enforcement point: every curl the build path
    // resolves (snap.rs source fetches go through `floor_tool(Curl)`,
    // which honors this override first) is the payload shim.
    let bin_dir = root.path().join(".worker-bin");
    let shim = write_curl_shim(&bin_dir, &payloads.sources)?;
    std::env::set_var("NAU_TOOL_CURL", &shim);

    // Recipe slice → meta through the ordinary resolution path. The eval
    // runs in the bounded `__eval-worker` subprocess (ADR-0010), whose
    // parent-side resolution uses this process's CWD — the job root.
    let mut meta = crate::deps::load_meta(&manifest.package)?;
    if meta.name != manifest.package {
        return Err(miette::miette!(
            "worker-job: manifest dispatches '{}' but the recipe slice resolves to '{}'",
            manifest.package,
            meta.name
        ));
    }
    if let Some(triplet) = &manifest.cross_target {
        meta.target = Some(triplet.clone());
    }
    let result = finish_job(manifest, &meta, payloads, out_dir);
    // `root` (the TempDir) drops here: the materialized recipe slice, the
    // shim, and the job's scratch all go away with the job.
    result
}

/// Unpack the coordinator's stage blob into the job's build stage
/// (#310). `tar::Archive::unpack` refuses traversal paths by default —
/// a hostile blob cannot write outside the stage.
fn extract_stage_blob(blob: &Path, stage: &Path) -> miette::Result<()> {
    let file = std::fs::File::open(blob)
        .map_err(|e| miette::miette!("worker-job: cannot open the stage blob: {e}"))?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(stage)
        .map_err(|e| miette::miette!("worker-job: cannot unpack the stage blob: {e}"))
}

/// The build half of `run_job`, after meta is loaded and checked.
fn finish_job(
    manifest: &JobManifest,
    meta: &crate::snap::SnapMeta,
    payloads: &PayloadSet,
    out_dir: &Path,
) -> miette::Result<JobResult> {
    refuse_unshipped_sources(manifest, meta, payloads)?;
    crate::snap::check_cross_build(&manifest.target, meta.target.as_deref())?;

    // Dep payloads merge into the ordinary build prefix (ADR-0018); the
    // prefix tempdir must outlive the build.
    let prefix = materialize_prefix(payloads)?;
    let scan_listings = match &prefix {
        Some(p) => crate::leak_scan::listings_for_build(meta, p)?,
        None => crate::leak_scan::PayloadListings::default(),
    };

    let stage =
        tempfile::tempdir().map_err(|e| miette::miette!("worker-job: cannot create stage: {e}"))?;
    // #310: a stage-only recipe's content rides the `stage` closure
    // object — unpacked into the otherwise-empty build stage before the
    // pack, because the recipe's (absent) build phase is what would have
    // populated it locally.
    if let Some(blob) = &payloads.stage {
        extract_stage_blob(blob, stage.path())?;
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette::miette!("worker-job: cannot create output dir: {e}"))?;

    // Machine verb: buffer the child stderr so it rides into the result
    // document instead of interleaving into the worker's own stderr
    // (issue #55 precedent).
    crate::snap::set_buffer_child_stderr(true);
    // The build child's own wall — the number the coordinator cannot
    // observe across the channel and the summary's `build` phase (#302).
    let build_started = std::time::Instant::now();
    let build = crate::snap::build_snap(
        meta,
        stage.path(),
        out_dir,
        &manifest.target,
        crate::snap::StagePolicy::Default,
        // No pod store, no interpreted-deps closure on a Worker job.
        None,
        None,
        prefix.as_ref().map(|p| p.path()),
        Some(&scan_listings),
        // Not a drift-observation point.
        false,
        Some(&crate::build_orch::SeamSourceFetcher),
    );
    let build_ms = Some(build_started.elapsed().as_millis() as u64);

    Ok(job_result(manifest, out_dir, build, build_ms))
}

/// Collect the result document: artifacts (path + hash + size) plus the
/// failure text and its buffered-output section on error. `build_ms` is
/// the worker-measured build wall (#302).
fn job_result(
    manifest: &JobManifest,
    out_dir: &Path,
    build: miette::Result<crate::snap::BuildResult>,
    build_ms: Option<u64>,
) -> JobResult {
    let mut result = JobResult {
        protocol_version: WORKER_PROTOCOL_VERSION,
        package: manifest.package.clone(),
        target: manifest.target.clone(),
        ok: build.is_ok(),
        artifacts: Vec::new(),
        error: None,
        stderr: None,
        build_ms,
    };
    match build {
        Ok(_) => {
            result.artifacts = collect_artifacts(out_dir);
        }
        Err(e) => {
            let text = format!("{e:#}");
            result.error = Some(text.clone());
            result.stderr = buffered_output_section(&text);
        }
    }
    result
}

/// Split the `--- build output (last N lines) ---` block snap.rs embeds in
/// a buffered failure into its own field.
fn buffered_output_section(error_text: &str) -> Option<String> {
    let marker = "--- build output";
    let idx = error_text.find(marker)?;
    let rest = &error_text[idx..];
    let body = rest.split_once(" ---\n").map(|(_, b)| b).unwrap_or(rest);
    (!body.trim().is_empty()).then(|| body.to_string())
}

/// Hash every `.snap` in the job's output directory.
fn collect_artifacts(out_dir: &Path) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return artifacts;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "snap") || !path.is_file() {
            continue;
        }
        let Ok(sha) = crate::oci::sha256_file(&path) else {
            continue;
        };
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        artifacts.push(Artifact {
            filename: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: path.to_string_lossy().into_owned(),
            sha256: sha,
            size,
        });
    }
    artifacts.sort_by(|a, b| a.filename.cmp(&b.filename));
    artifacts
}

// ── Refusals (all before any build work) ──

/// Shape + protocol + safety validation. Pure manifest checks — no
/// filesystem access.
fn validate_manifest(manifest: &JobManifest) -> miette::Result<()> {
    if manifest.protocol_version != WORKER_PROTOCOL_VERSION {
        return Err(miette::miette!(
            "worker-job: protocol version mismatch — manifest speaks {}, this worker speaks {}",
            manifest.protocol_version,
            WORKER_PROTOCOL_VERSION
        ));
    }
    if manifest.package.is_empty() {
        return Err(miette::miette!(
            "worker-job: manifest names no package to build"
        ));
    }
    if manifest.recipes.is_empty() {
        return Err(miette::miette!(
            "worker-job: manifest carries an empty recipe slice"
        ));
    }
    for key in manifest.recipes.keys() {
        let rel = Path::new(key);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(miette::miette!(
                "worker-job: recipe path '{key}' escapes the job root — refusing"
            ));
        }
    }
    for obj in &manifest.closure {
        validate_purpose(obj)?;
    }
    Ok(())
}

/// Verify EVERY closure object before anything runs (ADR-0040 Decision 6:
/// "claims are content-verified before they are trusted"): the blob file
/// must exist, match its declared size, and hash to its declared sha256.
/// Every failure names the file.
fn verify_payloads(
    manifest: &JobManifest,
    payload_dir: Option<&Path>,
) -> miette::Result<PayloadSet> {
    if manifest.closure.is_empty() {
        return Ok(PayloadSet {
            sources: BTreeMap::new(),
            deps: Vec::new(),
            stage: None,
        });
    }
    let Some(dir) = payload_dir else {
        return Err(miette::miette!(
            "worker-job: manifest lists {} payload object(s) but declares no payload_dir",
            manifest.closure.len()
        ));
    };

    // Pass 1: content-verify every blob.
    for obj in &manifest.closure {
        verify_blob(dir, obj)?;
    }

    // Pass 2: route the verified blobs to their purposes.
    let mut payloads = PayloadSet {
        sources: BTreeMap::new(),
        deps: Vec::new(),
        stage: None,
    };
    for obj in &manifest.closure {
        let blob = dir.join(&obj.sha256);
        if obj.purpose == "source" {
            route_source_blob(manifest, obj, &blob, &mut payloads.sources)?;
        } else if obj.purpose == "stage" {
            // One stage per job — a second is a dispatch bug, not
            // content to merge.
            if payloads.stage.is_some() {
                return Err(miette::miette!(
                    "worker-job: manifest carries more than one 'stage' blob — refusing"
                ));
            }
            payloads.stage = Some(blob);
        } else if let Some(pkg) = obj.purpose.strip_prefix("dep:") {
            payloads.deps.push((pkg.to_string(), blob));
        }
    }
    Ok(payloads)
}

/// Existence + size + sha256 for one blob, naming the file on every
/// failure path.
fn verify_blob(dir: &Path, obj: &ClosureObject) -> miette::Result<()> {
    let blob = dir.join(&obj.sha256);
    if !blob.is_file() {
        return Err(miette::miette!(
            "worker-job: payload blob {} (purpose '{}') is missing from {} — \
             refusing before anything runs",
            short_sha(&obj.sha256),
            obj.purpose,
            dir.display()
        ));
    }
    let size = std::fs::metadata(&blob)
        .map_err(|e| {
            miette::miette!(
                "worker-job: payload blob {} cannot be stat'd: {e}",
                blob.display()
            )
        })?
        .len();
    if size != obj.size {
        return Err(miette::miette!(
            "worker-job: payload blob {} (purpose '{}') size mismatch — \
             manifest says {} bytes, file has {}",
            blob.display(),
            obj.purpose,
            obj.size,
            size
        ));
    }
    let computed = crate::oci::sha256_file(&blob).map_err(|e| {
        miette::miette!(
            "worker-job: payload blob {} cannot be hashed: {e}",
            blob.display()
        )
    })?;
    if computed != obj.sha256 {
        return Err(miette::miette!(
            "worker-job: payload blob {} (purpose '{}') sha256 mismatch — \
             manifest says {}, file hashes to {} — refusing before anything runs",
            blob.display(),
            obj.purpose,
            short_sha(&obj.sha256),
            short_sha(&computed)
        ));
    }
    Ok(())
}

/// Map a verified source blob to the pin URLs it serves. A source blob
/// matching no pin URL is a named refusal — the worker would be holding
/// bytes nothing declared.
fn route_source_blob(
    manifest: &JobManifest,
    obj: &ClosureObject,
    blob: &Path,
    sources: &mut BTreeMap<String, PathBuf>,
) -> miette::Result<()> {
    let mut matched = false;
    for pin in &manifest.pins {
        if pin.sha256 == obj.sha256 {
            refuse_shell_meta_url(&pin.url)?;
            sources.insert(pin.url.clone(), blob.to_path_buf());
            matched = true;
        }
    }
    if !matched {
        return Err(miette::miette!(
            "worker-job: shipped source payload {} (purpose 'source') matches no pin \
             in the manifest's pin slice — refusing",
            short_sha(&obj.sha256)
        ));
    }
    Ok(())
}

/// A URL lands inside a generated shell `case` branch; shell metacharacters
/// in it are a refusal, never an escaping guess.
fn refuse_shell_meta_url(url: &str) -> miette::Result<()> {
    if url.contains(['"', '\\', '`', '$']) {
        return Err(miette::miette!(
            "worker-job: pin URL contains shell metacharacters — refusing: {url}"
        ));
    }
    Ok(())
}

/// The never-fetch gate over the loaded recipe: every URL source must be
/// sha256-pinned, must ship in the payload (its URL in the pin slice, its
/// blob verified), and the manifest's pin for that URL must agree with the
/// recipe's own pin (drift between the two is a dispatch bug — refuse it
/// by name instead of building either bytes).
fn refuse_unshipped_sources(
    manifest: &JobManifest,
    meta: &crate::snap::SnapMeta,
    payloads: &PayloadSet,
) -> miette::Result<()> {
    let check = |spec: &crate::snap::SourceSpec, label: &str| -> miette::Result<()> {
        let (url, expected) = match spec {
            crate::snap::SourceSpec::Pinned { url, sha256 } => (url, sha256),
            crate::snap::SourceSpec::Unverified(url) => {
                return Err(miette::miette!(
                    "worker-job: {label} source {url} is not sha256-pinned — \
                     workers never fetch upstream; the coordinator must ship a pinned source"
                ));
            }
        };
        let Some(blob) = payloads.sources.get(url) else {
            return Err(miette::miette!(
                "worker-job: {label} fetches {url} but the manifest ships no payload for it — \
                 workers never fetch upstream"
            ));
        };
        match manifest.pins.iter().find(|p| p.url == *url) {
            Some(pin) if pin.sha256 != *expected => {
                return Err(miette::miette!(
                    "worker-job: pin slice disagrees with the recipe pin for {url} — \
                     recipe says {}, manifest says {}",
                    short_sha(expected),
                    short_sha(&pin.sha256)
                ));
            }
            _ => {}
        }
        // Last belt: the shipped bytes themselves must hash to the recipe's
        // own pin (verified again by snap.rs, but here it is a refusal).
        let computed = crate::oci::sha256_file(blob)?;
        if computed != *expected {
            return Err(miette::miette!(
                "worker-job: shipped source payload for {url} does not match the recipe pin — \
                 expected {}, got {}",
                short_sha(expected),
                short_sha(&computed)
            ));
        }
        Ok(())
    };

    if let Some(spec) = &meta.source {
        check(spec, "the recipe")?;
    }
    if let Some(sources) = &meta.sources {
        for (name, spec) in sources {
            check(spec, &format!("sources['{name}']"))?;
        }
    }
    Ok(())
}

/// Write the recipe slice and the lockfile pin slice into a fresh job
/// root. Recipe bytes land at their manifest-relative paths; `nau.lock`
/// carries the pin slice.
fn materialize_root(manifest: &JobManifest) -> miette::Result<tempfile::TempDir> {
    let root = tempfile::tempdir()
        .map_err(|e| miette::miette!("worker-job: cannot create job root: {e}"))?;
    for (rel, source) in &manifest.recipes {
        let dest = root.path().join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                miette::miette!("worker-job: cannot create {}: {e}", parent.display())
            })?;
        }
        std::fs::write(&dest, source)
            .map_err(|e| miette::miette!("worker-job: cannot write {rel}: {e}"))?;
    }

    let mut lock = crate::lock::LockFile::empty();
    for pin in &manifest.pins {
        lock.sources.insert(
            pin.url.clone(),
            crate::lock::SourceLockEntry {
                sha256: pin.sha256.clone(),
                // A pin copy, not a fetch: the worker reproduces the
                // dispatcher's recorded pin and learns no validator.
                etag: None,
                validated_at: None,
            },
        );
    }
    lock.save(&root.path().join(crate::lock::LockFile::FILENAME))?;
    Ok(root)
}

/// Merge the verified `dep:<pkg>` blobs into the ordinary build prefix.
/// `None` when the job ships no dep payloads.
fn materialize_prefix(
    payloads: &PayloadSet,
) -> miette::Result<Option<crate::build_prefix::MergedPrefix>> {
    if payloads.deps.is_empty() {
        return Ok(None);
    }
    let deps: Vec<crate::build_prefix::Payload> = payloads
        .deps
        .iter()
        .map(|(pkg, snap)| crate::build_prefix::Payload {
            pkg: pkg.clone(),
            source: crate::build_prefix::PayloadSource::Snap(snap.clone()),
        })
        .collect();
    Ok(Some(crate::build_prefix::materialize_merged_prefix(&deps)?))
}

/// Generate the payload-serving curl shim (see the module docs for why
/// this seam): a POSIX `sh` script whose `case` maps each shipped source
/// URL to its verified blob file and refuses every other URL.
fn write_curl_shim(bin_dir: &Path, sources: &BTreeMap<String, PathBuf>) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(bin_dir)
        .map_err(|e| miette::miette!("worker-job: cannot create shim dir: {e}"))?;
    let mut script = String::from(
        "#!/bin/sh\n\
         # nau __worker-job payload shim (ADR-0040 Decision 6): serves\n\
         # ONLY the source bytes shipped in the job payload. Any other URL\n\
         # is a refused upstream fetch — workers never fetch upstream.\n\
         out=\"\"; url=\"\"; prev=\"\"\n\
         for arg in \"$@\"; do\n\
         \x20 if [ \"$prev\" = \"-o\" ]; then out=\"$arg\"; prev=\"\"; continue; fi\n\
         \x20 case \"$arg\" in\n\
         \x20   -o) prev=\"-o\" ;;\n\
         \x20   -*) ;;\n\
         \x20   *) if [ -z \"$url\" ]; then url=\"$arg\"; fi ;;\n\
         \x20 esac\n\
         done\n\
         case \"$url\" in\n",
    );
    for (url, blob) in sources {
        script.push_str(&format!(
            "  \"{url}\") cp \"{blob}\" \"$out\"; exit 0 ;;\n",
            blob = blob.display()
        ));
    }
    script.push_str(
        "esac\n\
         echo \"nau worker: refused upstream fetch of '${url:-<none>}' — workers never \
         fetch upstream; the source must ship in the job payload\" >&2\n\
         exit 1\n",
    );

    let shim = bin_dir.join("curl");
    std::fs::write(&shim, script)
        .map_err(|e| miette::miette!("worker-job: cannot write curl shim: {e}"))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| miette::miette!("worker-job: cannot chmod curl shim: {e}"))?;
    Ok(shim)
}

/// Restore an env var to its previous value (or remove it when unset).
fn restore_var(key: &str, saved: Option<&std::ffi::OsStr>) {
    match saved {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}
