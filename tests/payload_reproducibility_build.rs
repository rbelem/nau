//! A2 gate test, second unit: FULL-PIPELINE build determinism.
//!
//! The first unit (payload_reproducibility.rs) pins the PACKING layer
//! with hand-authored stages — `run_build`, ELF repair (#12), and
//! wrapper generation (#9) never execute there. The A2 root cause lived
//! precisely in the build phase (SnapMeta.apps serialization), so the
//! pod.rs:6404 restore condition demands the same-tree-twice proof
//! through `build_snap` itself: a real ELF binary (patchelf and the
//! launcher-wrapper steps engage — a `#!/bin/sh` payload would skip
//! them), fetched from a loopback server with a pinned sha256, built
//! twice with fresh stage mtimes, must produce identical sha3-384.
//!
//! With this green, the output-compare paths (install_batch no-op skip,
//! churn guard) are load-bearing again; the input-identity holds
//! (#113/#331 recipe stamps, ADR-0017 4a float holds) stay — they are
//! the cheaper zero-build path, not a workaround for instability.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use nau_build::snap::{build_snap, SourceSpec, StagePolicy};
use nau_core::snap_types::{SnapApp, SnapMeta};

/// Env mutation (SOURCE_DATE_EPOCH) is process-global; the gate may run
/// this file's tests in parallel threads.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

fn chain_available() -> bool {
    ["mksquashfs", "unsquashfs", "curl", "tar"]
        .iter()
        .all(|t| has_tool(t))
}

fn c_compiler() -> Option<&'static str> {
    ["cc", "gcc"].into_iter().find(|c| has_tool(c))
}

// ── Loopback source server (mirrors pod_refresh.rs — integration test
//    crates carry their own helpers) ──

fn serve_dir(dir: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = dir.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if serve_one(&mut stream, &root).is_err() {
                continue;
            }
        }
    });
    port
}

fn serve_one(stream: &mut TcpStream, root: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut data = Vec::new();
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let req = String::from_utf8_lossy(&data);
    let path = req.split_whitespace().nth(1).unwrap_or("/");
    let file = root.join(path.trim_start_matches('/'));
    let (status, body) = match std::fs::read(&file) {
        Ok(b) => ("200 OK", b),
        Err(_) => ("404 Not Found", b"not found".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

// ── Fixture: a real ELF binary so the post-build ELF-repair (#12) and
//    launcher-wrapper (#9) steps execute — the build-phase suspects. ──

fn compile_real_elf(dir: &Path) -> PathBuf {
    let cc = c_compiler().expect("no C compiler found");
    let src = dir.join("mini.c");
    std::fs::write(&src, "int main(void) { return 0; }\n").unwrap();
    let out = dir.join("tool");
    let status = Command::new(cc)
        .args(["-O0", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .expect("cc invocation failed");
    assert!(status.success(), "compiling the fixture ELF failed");
    out
}

fn make_source_tarball(server_dir: &Path, name: &str, elf: &Path) -> String {
    let top = server_dir.join(name);
    std::fs::create_dir_all(&top).unwrap();
    std::fs::copy(elf, top.join("tool")).unwrap();
    std::fs::write(top.join("README"), "full-pipeline determinism fixture\n").unwrap();
    let tarball = server_dir.join(format!("{name}.tar.gz"));
    let status = Command::new("tar")
        .args(["czf"])
        .arg(&tarball)
        .arg(name)
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
    format!("{name}.tar.gz")
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    use sha2::Digest;
    let d = sha2::Sha256::digest(&bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha3_384_hex(path: &Path) -> String {
    use sha2::Digest;
    let bytes = std::fs::read(path).unwrap();
    format!("{:x}", sha3::Sha3_384::digest(&bytes))
}

fn full_pipeline_meta(url: &str, sha256: &str) -> SnapMeta {
    SnapMeta {
        name: "repro-build".into(),
        version: "1.0".into(),
        summary: None,
        description: Some("same-tree-twice, full build_snap pipeline".into()),
        license: None,
        source: None,
        sources: Some(std::collections::BTreeMap::from([(
            "src0".to_string(),
            SourceSpec::Pinned {
                url: url.to_string(),
                sha256: sha256.to_string(),
            },
        )])),
        build: Some(
            "mkdir -p $STAGE/bin && cp $SRC/src0/tool $STAGE/bin/tool && \
             chmod +x $STAGE/bin/tool"
                .into(),
        ),
        parts: None,
        architectures: None,
        grade: "stable".into(),
        confinement: "strict".into(),
        type_: None,
        adopt_info: None,
        version_adopted: false,
        icon_source: None,
        icon: None,
        compression: None,
        compression_level: None,
        environment: None,
        layout: None,
        hooks: None,
        plugs: None,
        slots: None,
        aliases: vec![],
        requires: vec![],
        build_deps: vec![],
        leaks_ok: vec![],
        target: None,
        toolchain: None,
        inputs: None,
        confined: None,
        apps: std::collections::BTreeMap::from([(
            "tool".to_string(),
            SnapApp {
                command: "bin/tool".into(),
                daemon: None,
                plugs: None,
                slots: None,
                environment: None,
                desktop: None,
                interpreter: None,
                confined: None,
            },
        )]),
        services: std::collections::BTreeMap::new(),
        deps: None,
        floating: false,
        definition_dir: None,
    }
}

/// One full build: fresh stage (fresh mtimes — the production
/// condition), fresh output dir, real fetch over loopback. Returns the
/// payload digest and keeps the payload for a failure byte-diff.
fn build_full_pipeline_once(meta: &SnapMeta, run: usize) -> String {
    let work = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let stage = work.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let result = build_snap(
        meta,
        &stage,
        out.path(),
        "x86_64",
        StagePolicy::Default,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .unwrap();
    let payload = out.path().join(&result.snap_filename);
    let digest = sha3_384_hex(&payload);
    let keep = std::env::temp_dir().join(format!("nau-a2-build-{}-run{}", std::process::id(), run));
    let _ = std::fs::remove_dir_all(&keep);
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::copy(&payload, keep.join(&result.snap_filename)).unwrap();
    digest
}

/// THE restore condition (pod.rs POD_BUILD_EPOCH doc): the same source
/// tree built twice through the full build_snap pipeline — run_build,
/// ELF repair, launcher wrappers, packing — must yield identical
/// payload sha3-384. Mirrors the production pod-side entry condition by
/// pinning SOURCE_DATE_EPOCH (set_pod_build_epoch's value).
#[test]
fn same_tree_twice_builds_identical_payloads_through_full_pipeline() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
        return;
    }
    if c_compiler().is_none() {
        eprintln!("skipping: no C compiler for the fixture ELF");
        return;
    }
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Production pod-side builds stamp this (pod.rs set_pod_build_epoch).
    std::env::set_var("SOURCE_DATE_EPOCH", "946684800");

    let server = tempfile::tempdir().unwrap();
    let elf = compile_real_elf(server.path());
    let tarball_name = make_source_tarball(server.path(), "src0-1.0", &elf);
    let tarball_path = server.path().join(&tarball_name);
    let sha256 = sha256_file(&tarball_path);
    let port = serve_dir(server.path());

    let meta = full_pipeline_meta(&format!("http://127.0.0.1:{port}/{tarball_name}"), &sha256);
    let a = build_full_pipeline_once(&meta, 1);
    let b = build_full_pipeline_once(&meta, 2);
    assert_eq!(
        a, b,
        "full-pipeline builds diverged — the build phase still injects \
         variance; kept both payloads under /tmp/nau-a2-build-* for diff"
    );
}
