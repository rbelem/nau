//! The build-farm worker verbs (ADR-0040 Decisions 2+6, T3): job manifest
//! round-trip, protocol + shape refusals, payload hash verification, the
//! never-fetch source gates, the capability document shape, and one full
//! loopback job through the ordinary offline sandbox build path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use serde_json::json;
use sha2::{Digest, Sha256};

use shuttle::worker::{
    capability_document, execute_job, load_manifest, CapabilityDoc, ClosureObject, JobManifest,
    SourcePin, WORKER_PROTOCOL_VERSION,
};

/// Serializes the env-mutating probe tests (process-global state).
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A mode-0755 stub binary: the tool-resolution override
/// (`SHUTTLE_TOOL_<NAME>`) routes the named tool's probes through it.
fn stub_tool(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("stub body");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("stub mode");
    }
    path
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn host_arch() -> &'static str {
    shuttle::snap::host_arch()
}

/// The directory a job's artifacts are written to. It must live outside
/// the job's scratch (the artifacts outlive the job root), so every
/// execute_job call in these tests owns one.
fn out_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("out tempdir")
}

fn hello_recipe() -> String {
    // A build-less snap: pure metadata. build_snap assembles snap.yaml and
    // packs it — the one recipe class that builds with no source fetch and
    // no sandbox command at all.
    r#"
return {
    default = snap {
        name = "worker-job-hello",
        version = "1.0.0",
        summary = "worker loopback job fixture",
        description = "built by __worker-job on a tempdir stage",
    },
}
"#
    .to_string()
}

fn hello_manifest() -> JobManifest {
    let mut recipes = BTreeMap::new();
    recipes.insert("pkgs/w/worker-job-hello.lua".to_string(), hello_recipe());
    JobManifest {
        protocol_version: WORKER_PROTOCOL_VERSION,
        target: host_arch().to_string(),
        cross_target: None,
        source_date_epoch: Some(1700000000),
        package: "worker-job-hello".to_string(),
        recipes,
        pins: Vec::new(),
        closure: Vec::new(),
        payload_dir: None,
    }
}

/// Write a manifest to `<dir>/job.json`.
fn write_manifest(dir: &Path, manifest: &JobManifest) -> PathBuf {
    let path = dir.join("job.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(manifest).expect("manifest serializes"),
    )
    .expect("write manifest");
    path
}

// ── Manifest round-trip ──

#[test]
fn manifest_round_trips_through_json_with_every_field() {
    let mut manifest = hello_manifest();
    manifest.closure.push(ClosureObject {
        sha256: "ab".repeat(32),
        size: 42,
        purpose: "source".to_string(),
    });
    manifest.closure.push(ClosureObject {
        sha256: "cd".repeat(32),
        size: 7,
        purpose: "dep:gmp".to_string(),
    });
    manifest.pins.push(SourcePin {
        url: "https://example.invalid/src.tar.xz".to_string(),
        sha256: "ab".repeat(32),
    });
    manifest.cross_target = Some("aarch64-linux-gnu".to_string());

    let json = serde_json::to_string(&manifest).expect("serialize");
    let back: JobManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.protocol_version, WORKER_PROTOCOL_VERSION);
    assert_eq!(back, manifest, "round-trip must be lossless");
}

#[test]
fn manifest_carries_the_documented_field_names() {
    let manifest = hello_manifest();
    let v: serde_json::Value = serde_json::to_value(&manifest).expect("to value");
    for field in [
        "protocol_version",
        "target",
        "source_date_epoch",
        "package",
        "recipes",
        "pins",
        "closure",
    ] {
        assert!(v.get(field).is_some(), "manifest field '{field}' missing");
    }
    // Optional-empty fields stay off the wire (canonical manifests stay
    // byte-stable for two coordinators building the same job).
    assert!(v.get("cross_target").is_none());
    assert!(v.get("payload_dir").is_none());
}

#[test]
fn load_manifest_names_the_file_on_bad_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("job.json");
    std::fs::write(&path, "{ not json").expect("write");
    let err = load_manifest(&path).expect_err("bad json is a refusal");
    let text = format!("{err:#}");
    assert!(text.contains("job.json"), "names the file: {text}");
}

// ── Protocol + shape refusals ──

#[test]
fn wrong_protocol_version_is_refused_by_name() {
    let mut manifest = hello_manifest();
    manifest.protocol_version = WORKER_PROTOCOL_VERSION + 1;
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("protocol mismatch refuses");
    let text = format!("{err:#}");
    assert!(text.contains("protocol version mismatch"), "{text}");
    assert!(
        text.contains(&WORKER_PROTOCOL_VERSION.to_string()),
        "names the worker's version: {text}"
    );
}

#[test]
fn package_missing_from_the_recipe_slice_is_refused() {
    let mut manifest = hello_manifest();
    manifest.package = "other-pkg".to_string();
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("missing package refuses");
    let text = format!("{err:#}");
    assert!(text.contains("other-pkg"), "names the package: {text}");
}

#[test]
fn empty_recipe_slice_is_refused() {
    let mut manifest = hello_manifest();
    manifest.recipes.clear();
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("empty slice refuses");
    assert!(
        format!("{err:#}").contains("empty recipe slice"),
        "names the empty slice"
    );
}

#[test]
fn recipe_path_escaping_the_job_root_is_refused() {
    let mut manifest = hello_manifest();
    manifest
        .recipes
        .insert("../escape.lua".to_string(), "-- nope".to_string());
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("path escape refuses");
    assert!(
        format!("{err:#}").contains("escapes the job root"),
        "names the escape"
    );
}

// ── Payload hash verification (before anything runs) ──

/// A payload dir with one verified blob + the manifest closure entry for it.
fn payload_fixture(dir: &Path, blob: &[u8]) -> ClosureObject {
    let sha = sha256_hex(blob);
    std::fs::write(dir.join(&sha), blob).expect("write blob");
    ClosureObject {
        sha256: sha,
        size: blob.len() as u64,
        purpose: "dep:libfoo".to_string(),
    }
}

#[test]
fn corrupt_payload_blob_is_refused_naming_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    // The in-flight corruption case: the file sits at the name the
    // manifest declared, but its bytes hash to something else.
    let real = b"original bytes";
    let declared = sha256_hex(b"different bytes");
    std::fs::write(blobs.join(&declared), real).expect("blob");
    let obj = ClosureObject {
        sha256: declared,
        size: real.len() as u64,
        purpose: "dep:libfoo".to_string(),
    };

    let mut manifest = hello_manifest();
    manifest.closure.push(obj);
    manifest.payload_dir = Some(blobs.to_string_lossy().into_owned());
    let out = out_dir();
    let err = execute_job(&manifest, Some(&blobs), out.path()).expect_err("corrupt blob refuses");
    let text = format!("{err:#}");
    assert!(text.contains("sha256 mismatch"), "{text}");
    assert!(text.contains("dep:libfoo"), "names the purpose: {text}");
}

#[test]
fn missing_payload_blob_is_refused_naming_the_hash() {
    let mut manifest = hello_manifest();
    manifest.closure.push(ClosureObject {
        sha256: "e3".repeat(32),
        size: 3,
        purpose: "dep:libbar".to_string(),
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    manifest.payload_dir = Some(blobs.to_string_lossy().into_owned());
    let out = out_dir();
    let err = execute_job(&manifest, Some(&blobs), out.path()).expect_err("missing blob refuses");
    let text = format!("{err:#}");
    assert!(text.contains("is missing"), "{text}");
    // The refusal shortens the hash for the message (16 hex chars).
    assert!(text.contains(&"e3".repeat(8)), "names the hash: {text}");
}

#[test]
fn wrong_payload_size_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    let mut obj = payload_fixture(&blobs, b"exactly the bytes");
    obj.size += 1; // manifest size disagrees with the file

    let mut manifest = hello_manifest();
    manifest.closure.push(obj);
    manifest.payload_dir = Some(blobs.to_string_lossy().into_owned());
    let out = out_dir();
    let err = execute_job(&manifest, Some(&blobs), out.path()).expect_err("size mismatch refuses");
    assert!(
        format!("{err:#}").contains("size mismatch"),
        "names the size: {err:#}"
    );
}

#[test]
fn closure_without_payload_dir_is_refused() {
    let mut manifest = hello_manifest();
    manifest.closure.push(ClosureObject {
        sha256: "ab".repeat(32),
        size: 1,
        purpose: "source".to_string(),
    });
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("no payload dir refuses");
    assert!(
        format!("{err:#}").contains("no payload_dir"),
        "names the missing dir"
    );
}

#[test]
fn unknown_purpose_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    let mut obj = payload_fixture(&blobs, b"bytes");
    obj.purpose = "treasure".to_string();

    let mut manifest = hello_manifest();
    manifest.closure.push(obj);
    manifest.payload_dir = Some(blobs.to_string_lossy().into_owned());
    let out = out_dir();
    let err =
        execute_job(&manifest, Some(&blobs), out.path()).expect_err("unknown purpose refuses");
    let text = format!("{err:#}");
    assert!(text.contains("unknown purpose"), "{text}");
    assert!(text.contains("treasure"), "names the purpose: {text}");
}

#[test]
fn bare_dep_purpose_is_refused() {
    let mut manifest = hello_manifest();
    manifest.closure.push(ClosureObject {
        sha256: "ab".repeat(32),
        size: 1,
        purpose: "dep:".to_string(),
    });
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("bare dep: refuses");
    assert!(
        format!("{err:#}").contains("no package name"),
        "names the empty package"
    );
}

// ── Never-fetch source gates ──

const SRC_URL: &str = "https://example.invalid/src.tar.xz";

/// One Lua `source = { url, sha256 }` line, brace-escaped once here so no
/// test hand-rolls format-string escaping.
fn source_line(url: &str, sha: &str) -> String {
    format!("source = {{ url = \"{url}\", sha256 = \"{sha}\" }},")
}

/// The legacy unpinned shape: bare URL, no pin.
fn unpinned_source_line(url: &str) -> String {
    format!("source = {{ url = \"{url}\" }},")
}

fn source_manifest(
    source_field: &str,
    pins: Vec<SourcePin>,
    closure: Vec<ClosureObject>,
    payload_dir: Option<String>,
) -> JobManifest {
    let recipe = format!(
        r#"
return {{
    default = snap {{
        name = "worker-src-job",
        version = "1.0.0",
        summary = "s",
        description = "d",
        {source_field}
    }},
}}
"#
    );
    let mut recipes = BTreeMap::new();
    recipes.insert("pkgs/w/worker-src-job.lua".to_string(), recipe);
    JobManifest {
        protocol_version: WORKER_PROTOCOL_VERSION,
        target: host_arch().to_string(),
        cross_target: None,
        source_date_epoch: None,
        package: "worker-src-job".to_string(),
        recipes,
        pins,
        closure,
        payload_dir,
    }
}

#[test]
fn unpinned_url_source_is_refused_before_anything_runs() {
    // No `sha256` inside the source table → Unverified → fetch would be
    // unverified. The worker refuses the recipe class outright.
    let manifest = source_manifest(&unpinned_source_line(SRC_URL), Vec::new(), Vec::new(), None);
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("unpinned source refuses");
    let text = format!("{err:#}");
    assert!(text.contains("never fetch upstream"), "{text}");
    assert!(text.contains("not sha256-pinned"), "{text}");
}

#[test]
fn source_url_without_a_shipped_payload_is_refused() {
    // Pinned in the recipe, absent from the closure: the worker would have
    // to fetch upstream. Refusal, by name.
    let manifest = source_manifest(
        &source_line(SRC_URL, &"ab".repeat(32)),
        vec![SourcePin {
            url: SRC_URL.to_string(),
            sha256: sha256_hex(b"tarball bytes"),
        }],
        Vec::new(),
        None,
    );
    let out = out_dir();
    let err = execute_job(&manifest, None, out.path()).expect_err("unshipped source refuses");
    let text = format!("{err:#}");
    assert!(text.contains("never fetch upstream"), "{text}");
    assert!(text.contains("ships no payload"), "{text}");
}

#[test]
fn pin_slice_disagreeing_with_the_recipe_pin_is_refused() {
    let bytes = b"tarball bytes";
    let sha = sha256_hex(bytes);
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    std::fs::write(blobs.join(&sha), bytes).expect("blob");

    // The pin slice routes the REAL bytes (so the blob verifies and
    // routes), but the RECIPE pins a different hash for the same URL:
    // a dispatch bug — refuse it by name instead of building either bytes.
    let drifted = format!("aa{}", &sha[..62]);
    let manifest = source_manifest(
        &source_line(SRC_URL, &drifted),
        vec![SourcePin {
            url: SRC_URL.to_string(),
            sha256: sha.clone(),
        }],
        vec![ClosureObject {
            sha256: sha,
            size: bytes.len() as u64,
            purpose: "source".to_string(),
        }],
        Some(blobs.to_string_lossy().into_owned()),
    );
    let out = out_dir();
    let err =
        execute_job(&manifest, Some(&blobs), out.path()).expect_err("pin disagreement refuses");
    let text = format!("{err:#}");
    assert!(text.contains("disagrees with the recipe pin"), "{text}");
    assert!(text.contains(SRC_URL), "names the URL: {text}");
}

#[test]
fn shipped_source_blob_matching_no_pin_is_refused() {
    let bytes = b"orphan bytes";
    let sha = sha256_hex(bytes);
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    std::fs::write(blobs.join(&sha), bytes).expect("blob");

    let manifest = source_manifest(
        &source_line(SRC_URL, &"ab".repeat(32)),
        Vec::new(),
        vec![ClosureObject {
            sha256: sha,
            size: bytes.len() as u64,
            purpose: "source".to_string(),
        }],
        Some(blobs.to_string_lossy().into_owned()),
    );
    let out = out_dir();
    let err = execute_job(&manifest, Some(&blobs), out.path()).expect_err("orphan blob refuses");
    let text = format!("{err:#}");
    assert!(text.contains("matches no pin"), "{text}");
}

#[test]
fn pin_url_with_shell_metacharacters_is_refused() {
    let bytes = b"tarball bytes";
    let sha = sha256_hex(bytes);
    let url = "https://example.invalid/$(rm -rf)/src.tar.xz";
    let dir = tempfile::tempdir().expect("tempdir");
    let blobs = dir.path().join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    std::fs::write(blobs.join(&sha), bytes).expect("blob");

    let manifest = source_manifest(
        &source_line(url, &sha),
        vec![SourcePin {
            url: url.to_string(),
            sha256: sha.clone(),
        }],
        vec![ClosureObject {
            sha256: sha,
            size: bytes.len() as u64,
            purpose: "source".to_string(),
        }],
        Some(blobs.to_string_lossy().into_owned()),
    );
    let out = out_dir();
    let err = execute_job(&manifest, Some(&blobs), out.path()).expect_err("hostile URL refuses");
    assert!(
        format!("{err:#}").contains("shell metacharacters"),
        "names the metacharacters"
    );
}

// ── Capability document shape ──

#[test]
fn capability_document_carries_every_probe() {
    let cap = shuttle::worker::capability_document();
    assert_eq!(cap.protocol, WORKER_PROTOCOL_VERSION);
    assert_eq!(cap.arch, host_arch());
    assert!(cap.nproc >= 1, "nproc is a real count");
    // The sandbox boolean never lies about bwrap absence.
    if !cap.bwrap {
        assert!(!cap.sandbox, "sandbox implies bwrap");
    }
    // Every probe field serializes under its documented name.
    let v = serde_json::to_value(&cap).expect("cap json");
    for field in [
        "protocol",
        "arch",
        "nproc",
        "ram_bytes",
        "free_disk_bytes",
        "bwrap",
        "mksquashfs",
        "kvm",
        "sandbox",
        "mksquashfs_version",
    ] {
        assert!(v.get(field).is_some(), "cap field '{field}' missing");
    }
    let doc: CapabilityDoc =
        serde_json::from_str(&serde_json::to_string(&cap).expect("cap json")).expect("round-trips");
    assert_eq!(doc, cap);
}

#[test]
fn sandbox_probe_passes_when_userns_works_and_fails_closed_when_broken() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    // bwrap present and a minimal unshared invocation succeeding (#273
    // verify-unit: the cap probe passes on a working sandbox).
    std::env::set_var(
        "SHUTTLE_TOOL_BWRAP",
        stub_tool(dir.path(), "bwrap-ok", "#!/bin/sh\nexit 0\n"),
    );
    let cap = capability_document();
    assert!(cap.bwrap, "the stub resolves as bwrap");
    assert!(
        cap.sandbox,
        "a working unprivileged sandbox passes the probe"
    );
    // bwrap present but the sandbox invocation failing — the shape a
    // userns-denied host produces (#273 verify-unit: the probe fails
    // CLOSED with userns deliberately broken). bwrap stays true; sandbox
    // goes false, and preflight refuses by design.
    std::env::set_var(
        "SHUTTLE_TOOL_BWRAP",
        stub_tool(dir.path(), "bwrap-broken", "#!/bin/sh\nexit 1\n"),
    );
    let cap = capability_document();
    assert!(cap.bwrap, "bwrap presence is reported honestly");
    assert!(!cap.sandbox, "a broken userns fails the probe closed");
    std::env::remove_var("SHUTTLE_TOOL_BWRAP");
}

#[test]
fn cap_reports_the_resolved_mksquashfs_version_for_admission() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    // The resolved mksquashfs answers the version probe in the upstream
    // shape; the document carries the parsed version so preflight can
    // pin the fleet to exactly it (#273).
    std::env::set_var(
        "SHUTTLE_TOOL_MKSQUASHFS",
        stub_tool(
            dir.path(),
            "mksquashfs",
            "#!/bin/sh\necho 'mksquashfs version 4.7.4 (2025-11-09)'\n",
        ),
    );
    let cap = capability_document();
    assert!(cap.mksquashfs, "the stub resolves as mksquashfs");
    assert_eq!(
        cap.mksquashfs_version.as_deref(),
        Some(shuttle::provision::SQUASHFS_TOOLS_VERSION),
        "the parsed version is exactly the fleet pin"
    );
    // A digit-less (unreadable) report stays None — and admission reads
    // None as a refusal, not a pass.
    std::env::set_var(
        "SHUTTLE_TOOL_MKSQUASHFS",
        stub_tool(dir.path(), "mksquashfs-mute", "#!/bin/sh\necho 'nothing'\n"),
    );
    let cap = capability_document();
    assert!(cap.mksquashfs);
    assert_eq!(cap.mksquashfs_version, None, "unreadable stays None");
    std::env::remove_var("SHUTTLE_TOOL_MKSQUASHFS");
}

// ── Result document shape on a failing build (offline) ──

#[test]
fn failed_build_prints_a_result_document_with_the_error() {
    // A `build` with no `source` fails inside build_snap before any
    // download or sandbox work — an offline, deterministic failure.
    let recipe = r#"
return {
    default = snap {
        name = "worker-job-doomed",
        version = "0.1.0",
        summary = "s",
        description = "d",
        build = "false",
    },
}
"#
    .to_string();
    let mut recipes = BTreeMap::new();
    recipes.insert("pkgs/w/worker-job-doomed.lua".to_string(), recipe);
    let manifest = JobManifest {
        protocol_version: WORKER_PROTOCOL_VERSION,
        target: host_arch().to_string(),
        cross_target: None,
        source_date_epoch: None,
        package: "worker-job-doomed".to_string(),
        recipes,
        pins: Vec::new(),
        closure: Vec::new(),
        payload_dir: None,
    };

    let out = out_dir();
    let result =
        execute_job(&manifest, None, out.path()).expect("execution succeeded; the BUILD failed");
    assert!(!result.ok, "the build failure rides in the document");
    let error = result.error.expect("failed build carries the error");
    assert!(
        error.contains("build is set but no source"),
        "the failure text is the build's own: {error}"
    );
    assert_eq!(result.protocol_version, WORKER_PROTOCOL_VERSION);
    assert!(result.artifacts.is_empty(), "no artifacts on failure");
}

// ── Loopback job: the full offline build path ──

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The loopback job needs the packing tool and (for the eval subprocess)
/// nothing else — a build-less snap never reaches bwrap.
fn loopback_tools_available() -> bool {
    has_tool("mksquashfs")
}

#[test]
fn loopback_job_builds_and_hashes_its_artifact() {
    if !loopback_tools_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }

    let manifest = hello_manifest();
    let out = out_dir();
    let result = execute_job(&manifest, None, out.path()).expect("job executes");
    assert!(
        result.ok,
        "build-less snap builds clean: {:?}",
        result.error
    );
    assert_eq!(result.artifacts.len(), 1, "one artifact");
    let artifact = &result.artifacts[0];
    assert!(
        artifact.filename.starts_with("worker-job-hello_1.0.0_"),
        "snap named name_version_arch: {}",
        artifact.filename
    );
    assert!(artifact.filename.ends_with(".snap"));
    // The artifact outlives the job (it was written outside the scratch).
    assert!(
        Path::new(&artifact.path).is_file(),
        "artifact exists on disk"
    );

    // The result hash must match the bytes on disk (the T3 lane-4 rule).
    let on_disk = std::fs::read(&artifact.path).expect("read artifact");
    assert_eq!(artifact.sha256, sha256_hex(&on_disk));
    assert_eq!(artifact.size as usize, on_disk.len());
}

/// The verb layer: `__worker-job` wires load → execute → result JSON, and
/// leaves the artifact beside the job file where the transport collects it.
#[test]
fn job_main_prints_the_result_document_for_a_valid_manifest() {
    if !loopback_tools_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }
    // stdout is captured by the test harness; the document shape is
    // asserted by execute_job's tests above — here the wiring is the unit.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_manifest(dir.path(), &hello_manifest());
    shuttle::worker::job_main(&path.to_string_lossy()).expect("job_main succeeds");
    let out = dir.path().join("out");
    let packed: Vec<_> = std::fs::read_dir(&out)
        .expect("out/ exists")
        .flatten()
        .collect();
    assert_eq!(packed.len(), 1, "one artifact beside the job file");
}

#[test]
fn job_main_refuses_a_bad_manifest_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = hello_manifest();
    manifest.protocol_version = 99;
    let path = write_manifest(dir.path(), &manifest);
    let err = shuttle::worker::job_main(&path.to_string_lossy()).expect_err("refused");
    assert!(
        format!("{err:#}").contains("protocol version mismatch"),
        "refusal names the version: {err:#}"
    );
}

// ── Manifest JSON edge: closure + payload_dir resolution ──

#[test]
fn relative_payload_dir_resolves_against_the_job_file() {
    // job at <tmp>/jobs/job.json, payloads at <tmp>/jobs/blobs/
    let dir = tempfile::tempdir().expect("tempdir");
    let jobs = dir.path().join("jobs");
    let blobs = jobs.join("blobs");
    std::fs::create_dir_all(&blobs).expect("layout");
    let bytes = b"payload";
    let sha = sha256_hex(bytes);
    std::fs::write(blobs.join(&sha), bytes).expect("blob");

    let mut manifest = hello_manifest();
    // A source-purpose blob: verified, routed through a pin, and never
    // unpacked (the hello recipe builds no source).
    manifest.closure.push(ClosureObject {
        sha256: sha.clone(),
        size: bytes.len() as u64,
        purpose: "source".to_string(),
    });
    manifest.pins.push(SourcePin {
        url: "https://example.invalid/hello.tar.xz".to_string(),
        sha256: sha,
    });
    manifest.payload_dir = Some("blobs".to_string());
    let path = write_manifest(&jobs, &manifest);

    // Round-trip through the real loader, then execute with the RESOLVED
    // dir (the resolution itself is the behavior under test — job_main
    // owns it in production).
    let loaded = load_manifest(&path).expect("loads");
    assert_eq!(loaded, manifest);
    let resolved = jobs.join(loaded.payload_dir.as_deref().expect("payload_dir"));
    let out = out_dir();
    let result = execute_job(&loaded, Some(&resolved), out.path()).expect("verified payloads");
    assert!(result.ok, "payload verifies: {:?}", result.error);
}

#[test]
fn manifest_json_accepts_minimal_jobs() {
    let minimal: JobManifest = serde_json::from_value(json!({
        "protocol_version": WORKER_PROTOCOL_VERSION,
        "target": "amd64",
        "package": "p",
        "recipes": { "pkgs/p/p.lua": "return {}" }
    }))
    .expect("optional fields default");
    assert!(minimal.pins.is_empty());
    assert!(minimal.closure.is_empty());
    assert!(minimal.source_date_epoch.is_none());
}
