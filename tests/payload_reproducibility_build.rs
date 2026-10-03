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

// ── Large-tree arm ──
//
// The tiny-ELF fixture above leaves most of the build-phase machinery
// under-exercised at scale: the original A2 bistability only reproduced
// on hermes-agent-sized trees (payload_reproducibility.rs had to add a
// 4000-file arm even for the pack layer). This arm carries the same
// full-pipeline proof over a programmatically generated large source
// tree, so the fetch → extract → build → pack path sees realistic
// breadth.

/// Deterministic pseudo-random bytes from a seeded 64-bit LCG (Knuth's
/// constants). No RNG dependency; the same seed and length always
/// produce the same bytes, so the generated tree is byte-stable across
/// runs and across machines.
fn lcg_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Files generated in the nested `data/` subtree. 4000 mirrors the
/// pack-layer scale arm; shrunk only if the pair of full builds
/// outlives the ~90s budget.
const LARGE_TREE_FILES: u32 = 4000;

/// Build the large source tarball: the real fixture ELF at `tool` (the
/// build copies it to $STAGE/bin/tool, so ELF repair and wrapper
/// authoring see the same target as the tiny arm) plus copies under two
/// more names, then a generated tree of 4000 files in 20 nested module
/// directories with mixed LCG-filled sizes and 8 larger 256 KiB blobs.
fn make_large_source_tarball(server_dir: &Path, name: &str, elf: &Path) -> String {
    let top = server_dir.join(name);
    let _ = std::fs::remove_dir_all(&top);
    std::fs::create_dir_all(&top).unwrap();
    std::fs::copy(elf, top.join("tool")).unwrap();
    std::fs::copy(elf, top.join("tool-alt")).unwrap();
    std::fs::copy(elf, top.join("helper")).unwrap();
    let data = top.join("data");
    std::fs::create_dir_all(&data).unwrap();
    for i in 0..LARGE_TREE_FILES {
        let dir = data.join(format!("mod-{:02}", i % 20));
        std::fs::create_dir_all(&dir).unwrap();
        // Size varies with i so the pack sees mixed fragment content.
        let len = 512 + (i as usize % 4096);
        let body = lcg_bytes(0x9E37_79B9_7F4A_7C15 ^ (i as u64), len);
        std::fs::write(dir.join(format!("file-{i:05}.bin")), body).unwrap();
    }
    for j in 0..8u32 {
        let body = lcg_bytes(0xDEAD_BEEF_CAFE_F00D ^ (j as u64), 256 * 1024);
        std::fs::write(data.join(format!("big-{j}.bin")), body).unwrap();
    }
    std::fs::write(
        top.join("README"),
        "full-pipeline large-tree determinism fixture\n",
    )
    .unwrap();
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

/// Same meta shape as [`full_pipeline_meta`], but the build command also
/// copies the generated `data/` subtree into the stage — only staged
/// files reach the squashfs, so without this the 4000 files would never
/// enter the payload.
fn large_tree_pipeline_meta(url: &str, sha256: &str) -> SnapMeta {
    let mut meta = full_pipeline_meta(url, sha256);
    meta.name = "repro-build-large".into();
    meta.description = Some("same-tree-twice large-tree, full build_snap pipeline".into());
    meta.build = Some(
        "mkdir -p $STAGE/bin && \
         cp $SRC/src0/tool $STAGE/bin/tool && \
         cp $SRC/src0/tool-alt $STAGE/bin/tool-alt && \
         cp $SRC/src0/helper $STAGE/bin/helper && \
         chmod +x $STAGE/bin/tool $STAGE/bin/tool-alt $STAGE/bin/helper && \
         cp -r $SRC/src0/data $STAGE/data"
            .into(),
    );
    meta
}

/// The large-tree arm of the restore condition: the same full-pipeline
/// proof over a 4000-file source tree. Closes the gap the pack-layer
/// scale arm exposed — variance that only fires on large trees must not
/// sneak past a tiny-fixture-only gate. Both builds run with fresh stage
/// dirs (fresh mtimes, the production condition) and must yield
/// identical payload sha3-384.
#[test]
fn same_tree_twice_identical_payloads_large_tree() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
        return;
    }
    if c_compiler().is_none() {
        eprintln!("skipping: no C compiler for the fixture ELF");
        return;
    }
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SOURCE_DATE_EPOCH", "946684800");

    let server = tempfile::tempdir().unwrap();
    let elf = compile_real_elf(server.path());
    let tarball_name = make_large_source_tarball(server.path(), "src0-large-1.0", &elf);
    let tarball_path = server.path().join(&tarball_name);
    let sha256 = sha256_file(&tarball_path);
    let port = serve_dir(server.path());

    let meta =
        large_tree_pipeline_meta(&format!("http://127.0.0.1:{port}/{tarball_name}"), &sha256);
    let t0 = std::time::Instant::now();
    let a = build_full_pipeline_once(&meta, 3);
    let first = t0.elapsed();
    let b = build_full_pipeline_once(&meta, 4);
    let total = t0.elapsed();
    eprintln!(
        "large-tree arm: build 1 {first:?}, build 2 {:?}, total {total:?} ({} files)",
        total - first,
        LARGE_TREE_FILES
    );
    assert_eq!(
        a, b,
        "large-tree full-pipeline builds diverged — build-phase variance \
         fires at scale; kept both payloads under /tmp/nau-a2-build-*"
    );
}
