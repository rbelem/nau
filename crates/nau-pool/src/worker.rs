//! The worker wire protocol (ADR-0040 Decisions 6+7, T4): everything
//! that crosses the coordinator↔Worker channel. The job manifest and
//! its canonical bytes (the `jm1:` identity digest input), the
//! capability document, the result document, and the closure-purpose
//! grammar both ends validate. The job-identity digest is WIRE-CRITICAL:
//! [`canonical_manifest_bytes`] and every serde field name must move —
//! and stay — byte-identical; a pure move behind the root re-export is
//! wire-invisible.
//!
//! The machine-side verb EXECUTION (`__worker-cap`/`__worker-job`
//! bodies: tool resolution, the sandbox probe, the never-fetch shim,
//! the build_snap drive) stays in the root package's `worker` module,
//! which re-exports every name here so `nau::worker::*` keeps
//! resolving.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Wire protocol version carried by the cap document, every job manifest,
/// and every result document (ADR-0040 Decision 7). A mismatch is a named
/// refusal at load time, never a runtime surprise.
///
/// History: 1 → 2 at ADR-0049 Decision 4 — the coordinator invokes
/// workers BY NAME over SSH, so the `__worker-cap`/`__worker-job` →
/// `pool probe`/`pool job` rename (#321) is wire-visible; the bump rolls
/// coordinator + workers in lockstep (the burst provision→teardown
/// lifecycle makes fleet rollover cheap).
pub const WORKER_PROTOCOL_VERSION: u32 = 2;

/// One payload blob the sandbox must see (ADR-0040 Decision 6 closure
/// entry). Content-addressed: the blob file is named by its sha256 in the
/// job's payload directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureObject {
    pub sha256: String,
    pub size: u64,
    /// What the blob is for: `source` (a pinned source tarball shipped in
    /// the payload), `dep:<package>` (a built dependency `.snap` merged
    /// into the build prefix), or `stage` (#310: the coordinator's
    /// resolved stage content for a stage-only recipe — the tarball the
    /// worker unpacks into its build stage before packing). Anything
    /// else is a named refusal.
    pub purpose: String,
}

/// One pinned source URL in the lockfile pin slice: the URL → sha256 map
/// the worker uses to route shipped source blobs to the URLs recipes
/// declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePin {
    pub url: String,
    pub sha256: String,
}

/// One job manifest (ADR-0040 Decision 6): everything the Worker needs to
/// build exactly one package with no upstream access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobManifest {
    pub protocol_version: u32,

    /// The snap architecture to build for (the `arch` argument of
    /// `snap::build_snap`, e.g. "amd64").
    pub target: String,

    /// Optional GNU cross triplet, applied to the loaded recipe exactly
    /// like `nau build --target` applies it coordinator-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_target: Option<String>,

    /// Reproducible SquashFS timestamp (Unix epoch seconds). Set into the
    /// worker process env — a Worker inherits nothing from the coordinator
    /// (ADR-0040 Decision 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_date_epoch: Option<i64>,

    /// The package to build: the snap `name` the recipe slice's first
    /// output must carry.
    pub package: String,

    /// The recipe slice: relative path inside the materialized job root
    /// (e.g. `pkgs/w/worker-hello.lua`) → recipe bytes (ADR-0040 Decision
    /// 6, own recipe bytes included per #172).
    pub recipes: BTreeMap<String, String>,

    /// The lockfile pin slice, written as the materialized root's
    /// `nau.lock` and used to route source blobs to their URLs.
    #[serde(default)]
    pub pins: Vec<SourcePin>,

    /// Every payload blob the sandbox must see.
    #[serde(default)]
    pub closure: Vec<ClosureObject>,

    /// Directory holding the payload blobs, named by their sha256. When
    /// relative, resolved against the job file's directory. Required when
    /// `closure` is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_dir: Option<String>,
}

/// One built artifact in a result document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub filename: String,
    /// Absolute path on the Worker.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// The result document `__worker-job` prints for every executed job
/// (ADR-0040 Decision 2): artifact paths + hashes + buffered stderr +
/// protocol version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub protocol_version: u32,
    pub package: String,
    pub target: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<Artifact>,
    /// The failure text when the build errored (the buffered child-output
    /// tail `snap.rs` attaches rides inside this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The buffered build-child stderr, split out of `error` when the
    /// failure carried one (the `--- build output ---` block).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    /// Worker-side wall time of the build child itself, in ms — the
    /// remote half of the run summary's phase split (#302). Optional and
    /// serde-default so an older worker's result document keeps parsing:
    /// an optional field never bumps the protocol version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_ms: Option<u64>,
}

// ── Transport side (ADR-0040 Decision 6, T4) ──

/// The canonical manifest bytes the job identity digests (ADR-0040
/// Decision 6): serde_json with sorted object keys plus the array members
/// sorted — pins by URL, closure by sha256 — so two coordinators produce
/// the same bytes for the same job. The transport-local `payload_dir` is
/// stripped: it names coordinator-side disk, not job content.
pub fn canonical_manifest_bytes(manifest: &JobManifest) -> miette::Result<Vec<u8>> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|e| miette::miette!("worker-job: cannot canonicalize the job manifest: {e}"))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("payload_dir");
        if let Some(pins) = obj.get_mut("pins").and_then(|v| v.as_array_mut()) {
            pins.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
        }
        if let Some(closure) = obj.get_mut("closure").and_then(|v| v.as_array_mut()) {
            closure.sort_by(|a, b| a["sha256"].as_str().cmp(&b["sha256"].as_str()));
        }
    }
    serde_json::to_vec(&value)
        .map_err(|e| miette::miette!("worker-job: cannot serialize the canonical manifest: {e}"))
}

/// The job-manifest identity (ADR-0040 Decision 6): `jm1:` + the SHA-256
/// of the canonical manifest bytes. Remote results ingest into the
/// coordinator under this namespace — deliberately distinct from the
/// local `v4:` closure cache, so a remote result can never silently
/// substitute for a locally keyed entry.
pub fn manifest_identity(manifest: &JobManifest) -> miette::Result<String> {
    Ok(format!(
        "jm1:{}",
        nau_core::cache_key::sha256_hex(&canonical_manifest_bytes(manifest)?)
    ))
}

/// Write the canonical job manifest as `job.json` into `dir` — the
/// transport-side half of the job-file surface: the coordinator ships
/// exactly these bytes, and their digest is the manifest identity.
/// Returns the written path.
pub fn write_job_file(dir: &Path, manifest: &JobManifest) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .map_err(|e| miette::miette!("worker-job: cannot create {}: {e}", dir.display()))?;
    let path = dir.join("job.json");
    // The job file serializes the manifest AS THE WORKER LOADS IT —
    // payload_dir included: the field is transport-local routing (the
    // worker resolves it against this file's directory), and a manifest
    // that names closure objects must name where they are or the worker
    // refuses fail-closed. The JOB IDENTITY still digests the canonical
    // bytes, which strip payload_dir — the worker recomputes it from the
    // loaded manifest, so a coordinator-local path never enters the
    // identity.
    std::fs::write(
        &path,
        serde_json::to_vec(manifest)
            .map_err(|e| miette::miette!("worker-job: cannot serialize the job manifest: {e}"))?,
    )
    .map_err(|e| miette::miette!("worker-job: cannot write {}: {e}", path.display()))?;
    Ok(path)
}

// ── Capability document ──

/// What a Worker advertises (ADR-0040 Decision 2): protocol version, arch,
/// nproc, RAM, free disk, tool presence with a *functioning* sandbox probe
/// (bwrap present AND a minimal unshared invocation succeeding — not
/// merely `which bwrap`), and KVM presence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDoc {
    pub protocol: u32,
    /// Snap-style machine arch (`snap::host_arch`, e.g. "amd64").
    pub arch: String,
    pub nproc: usize,
    /// Total RAM in bytes; 0 when unreadable.
    pub ram_bytes: u64,
    /// Free disk (available-to-unprivileged) in bytes on the temp
    /// filesystem; 0 when unreadable.
    pub free_disk_bytes: u64,
    pub bwrap: bool,
    pub mksquashfs: bool,
    pub kvm: bool,
    /// Functioning sandbox: the minimal unshared bwrap probe succeeded.
    pub sandbox: bool,
    /// The upstream version the RESOLVED mksquashfs reports (a
    /// `discover_version` exec), when readable — the pinned-mksquashfs
    /// half of the admission contract (#273): the fleet runs ONE pinned
    /// mksquashfs, and preflight refuses a worker whose version is
    /// unreadable (`None`) or off the pin
    /// ([`crate::provision::SQUASHFS_TOOLS_VERSION`]). `default` so an
    /// older worker's document still parses — into an admission refusal,
    /// never a silent pass.
    #[serde(default)]
    pub mksquashfs_version: Option<String>,
}

// ── Closure purpose grammar ──

/// Recognized purposes only; `dep:<pkg>` must name a package. The
/// wire-adjacent grammar both ends validate (the coordinator building a
/// manifest and the worker loading one); pub because the root execution
/// half's manifest validation consumes it after the PR-9 split.
pub fn validate_purpose(obj: &ClosureObject) -> miette::Result<()> {
    if obj.purpose == "source" || obj.purpose == "stage" {
        return Ok(());
    }
    if let Some(pkg) = obj.purpose.strip_prefix("dep:") {
        if !pkg.is_empty() {
            return Ok(());
        }
        return Err(miette::miette!(
            "worker-job: closure object {} declares purpose 'dep:' with no package name",
            short_sha(&obj.sha256)
        ));
    }
    Err(miette::miette!(
        "worker-job: closure object {} declares unknown purpose '{}' (expected 'source', \
         'dep:<package>', or 'stage')",
        short_sha(&obj.sha256),
        obj.purpose
    ))
}

/// First 16 hex chars of a sha256 — the refusal-message form. Pub for the
/// same reason as [`validate_purpose`]: the root execution half's refusal
/// paths format with it after the split.
pub fn short_sha(sha: &str) -> String {
    sha.chars().take(16).collect()
}
