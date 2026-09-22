//! `shuttle pod add --snap` sideload integration tests (issue #116).
//!
//! The split that defines a sideload: a BUILDER pod resolves a package
//! from a real collection (loopback HTTP source, sandboxed build,
//! mksquashfs) and its built payload is copied out of the pod store's
//! downloads dir; a TARGET pod with an EMPTY project (no `pkgs/` at all)
//! then installs that payload via `pod add --snap --ack-unsigned`. The
//! target pod proves the collection-less path: the payload is the only
//! input, its sha3-384 the pin, `pod sync` holds it.
//!
//! All state (project dirs, pod roots) lives in tempdirs — never the
//! real home. Gated on the external toolchain (mksquashfs/unsquashfs/
//! curl/tar), same skip pattern as tests/pod_install.rs.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Gating ──

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

fn require_chain() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
    }
}

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            require_chain();
            if !chain_available() {
                return;
            }
            $($body)*
        }
    };
}

// ── Loopback source server ──

/// Serve the files of `dir` over 127.0.0.1 HTTP (one request per
/// connection). The thread lives as long as the test process.
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

// ── Fixtures ──

fn make_tarball(server_dir: &Path, name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("README"), "fixture source\n").unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            server_dir.join(format!("{name}.tar.gz")).to_str().unwrap(),
            name,
        ])
        .current_dir(server_dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");
}

/// Write a resolvable package that builds a real executable into
/// $STAGE/bin/<bin> and exposes it as the app `app`.
fn write_pkg_version(
    project: &Path,
    name: &str,
    app: &str,
    bin: &str,
    version: &str,
    marker: &str,
    port: u16,
    tarball: &str,
) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "{version}",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{bin} && echo 'echo {marker}' >> $STAGE/bin/{bin} && chmod +x $STAGE/bin/{bin}",
    apps = {{ {app} = {{ command = "bin/{bin}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// Build `name` in a BUILDER pod and copy the built payload out of the
/// pod's downloads dir into `dest_dir`, preserving the artifact
/// filename. Returns the copied payload's path.
fn build_payload(
    project: &Path,
    root: &Path,
    dest_dir: &Path,
    name: &str,
    app: &str,
    bin: &str,
    version: &str,
    marker: &str,
    port: u16,
    tarball: &str,
) -> PathBuf {
    write_pkg_version(project, name, app, bin, version, marker, port, tarball);
    let (code, _, stderr) = run(project, root, &["--name", "build", "add", name]);
    assert_eq!(code, Some(0), "builder pod add failed: {stderr}");
    let downloads = root.join("build").join("downloads");
    let built = std::fs::read_dir(&downloads)
        .unwrap_or_else(|e| panic!("downloads dir {}: {e}", downloads.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{name}_{version}_")))
        })
        .unwrap_or_else(|| panic!("no {name}_{version}_*.snap in {}", downloads.display()));
    std::fs::create_dir_all(dest_dir).unwrap();
    let dest = dest_dir.join(built.file_name().unwrap());
    std::fs::copy(&built, &dest).unwrap();
    dest
}

/// A fake payload from a bare `meta/snap.yaml` — no build, no shuttle
/// recipe, packed directly with mksquashfs.
fn fake_snap(dest: &Path, yaml: &str) {
    let stage = tempfile::tempdir().unwrap();
    let meta = stage.path().join("meta");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::write(meta.join("snap.yaml"), yaml).unwrap();
    let status = Command::new("mksquashfs")
        .args([
            stage.path().to_str().unwrap(),
            dest.to_str().unwrap(),
            "-noappend",
            "-no-xattrs",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "mksquashfs failed");
}

// ── Runners ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // Desktop launchers (issue #7) write to the user data home — keep
    // them inside the test's tempdir; pod activation off the host bus.
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("SHUTTLE_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run a non-`pod` subcommand (`shuttle deps ...`) against the same
/// redirected state as [`run`].
fn run_plain(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("SHUTTLE_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn shuttle");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

fn generation_count(root: &Path, pod: &str) -> usize {
    let gens = pod_dir(root, pod).join("generations");
    std::fs::read_dir(&gens)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().parse::<u64>().is_ok())
                .count()
        })
        .unwrap_or(0)
}

fn current_generation(root: &Path, pod: &str) -> u64 {
    let target = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    target
        .components()
        .rev()
        .nth(1)
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let link = pod_dir(root, pod).join("current");
    let target = std::fs::read_link(&link).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

fn lockfile(root: &Path, pod: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).unwrap())
        .unwrap()
}

/// The miette renderer line-wraps error text; assertions match on the
/// flattened form so a wrap never breaks a fragment.
fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── Acceptance: the sideload chain ──

// Happy sideload into a collection-less pod: install, farm, lockfile
// pins (packages + snaps), `pod list`, `pod sync` holds, identical
// re-add is a no-op, and `pod remove` drops both pins.
gated_test!(sideload_installs_sync_holds_and_readd_is_noop, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );

    // The target pod's project has NO pkgs/ — the payload is the only
    // input, proving no collection is consulted.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // Missing --ack-unsigned refuses with zero writes.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap()],
    );
    assert_ne!(code, Some(0));
    assert!(
        stderr.contains("--ack-unsigned"),
        "must name the acknowledgment gate: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "default").exists(),
        "the refusal must leave zero writes"
    );

    // The happy sideload.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("sideloaded 'hello' (1.0)"),
        "stderr: {stderr}"
    );
    assert_eq!(generation_count(root.path(), "default"), 1);
    assert_eq!(current_generation(root.path(), "default"), 1);

    // The farm exposes the app and it EXECUTES.
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("hello").exists(), "farm must expose the app");
    let out = Command::new("hello")
        .env("PATH", &farm)
        .output()
        .expect("spawn hello");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("sideload-ran"),
        "farm binary must execute: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // `pod list` shows the payload's meta/snap.yaml version, pinned.
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("hello"), "stderr: {stderr}");
    assert!(stderr.contains("1.0"), "stderr: {stderr}");

    // Both lockfile pins: packages (version) + snaps (revision 0 =
    // sideload sentinel, sha3-384 = the payload's).
    let lock = lockfile(root.path(), "default");
    assert_eq!(lock["packages"]["hello"]["version"], "1.0");
    assert_eq!(lock["snaps"]["hello"]["revision"], 0);
    let pinned_sha = lock["snaps"]["hello"]["sha3-384"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!pinned_sha.is_empty());

    // `pod sync` holds the blob pin: no new generation, held in the
    // report, generation chain untouched.
    let (code, _stdout, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("held 'hello'"),
        "sync must report the blob-pin hold: {stderr}"
    );
    assert_eq!(generation_count(root.path(), "default"), 1);

    // Identical re-add: a no-op, nothing written.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("nothing to do"), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    // Remove drops BOTH pins and the farm entry.
    let (code, _, stderr) = run(project.path(), root.path(), &["remove", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let lock = lockfile(root.path(), "default");
    assert!(lock["packages"].get("hello").is_none());
    assert!(lock["snaps"].get("hello").is_none());
    assert!(!current_farm(root.path(), "default").join("hello").exists());
});

// A byte-flipped re-add under the pinned name+version refuses
// fail-closed, naming the divergence — the generation chain is
// untouched.
gated_test!(tampered_payload_refused, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    // Tamper: flip one byte in the middle of a copy (a distinct file —
    // copying onto the source would truncate it).
    let tampered_dir = stage.path().join("tampered");
    std::fs::create_dir_all(&tampered_dir).unwrap();
    let tampered = tampered_dir.join(payload.file_name().unwrap());
    std::fs::copy(&payload, &tampered).unwrap();
    let mut bytes = std::fs::read(&tampered).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&tampered, &bytes).unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "add",
            "--snap",
            tampered.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_ne!(code, Some(0), "the tampered payload must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("does not match"),
        "must name the mismatch: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        1,
        "no generation may be created from tampered content"
    );
});

// Filename↔meta identity mismatches refuse fail-closed: a payload
// whose filename claims a different name or version than its
// meta/snap.yaml is never installed.
gated_test!(filename_meta_mismatch_refused, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // Name mismatch: hello content under a `world_` filename.
    let wrong_name = stage.path().join("world_1.0_amd64.snap");
    std::fs::copy(&payload, &wrong_name).unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "add",
            "--snap",
            wrong_name.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_ne!(code, Some(0));
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("filename says 'world'") && stderr.contains("says 'hello'"),
        "must name the mismatch: {stderr}"
    );
    assert!(!pod_dir(root.path(), "default").exists(), "zero writes");

    // Version mismatch: hello 1.0 content under a 9.9 filename.
    let wrong_version = stage.path().join("hello_9.9_amd64.snap");
    std::fs::copy(&payload, &wrong_version).unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "add",
            "--snap",
            wrong_version.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_ne!(code, Some(0));
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("filename says version 9.9") && stderr.contains("says 1.0"),
        "must name the mismatch: {stderr}"
    );
    assert!(!pod_dir(root.path(), "default").exists(), "zero writes");
});

// snapd infrastructure payloads (type: base/gadget/kernel/snapd) are
// refused; `type: store` payloads warn and install as inert records.
gated_test!(infrastructure_refused_store_warns, {
    let stage = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // Infrastructure: refused, zero writes.
    let base_snap = stage.path().join("base-core_1.0_amd64.snap");
    fake_snap(
        &base_snap,
        "name: base-core\nversion: \"1.0\"\ntype: base\n",
    );
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "add",
            "--snap",
            base_snap.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_ne!(code, Some(0));
    assert!(stderr.contains("infrastructure"), "stderr: {stderr}");
    assert!(
        !pod_dir(root.path(), "default")
            .join("shuttle.lock")
            .exists(),
        "the refusal must leave zero writes"
    );

    // Store type: warns, installs as an inert record.
    let store_snap = stage.path().join("store-thing_1.0_amd64.snap");
    fake_snap(
        &store_snap,
        "name: store-thing\nversion: \"1.0\"\ntype: store\n",
    );
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "add",
            "--snap",
            store_snap.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("records only"),
        "the inert-record note must be loud: {stderr}"
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("store-thing"), "stderr: {stderr}");
});

// A deliberate version move: re-adding a payload with a NEW version
// moves both pins and produces a new generation whose farm executes
// the new content.
gated_test!(new_version_blob_moves_pins, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let builder_root2 = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let v1 = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-one",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", v1.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);
    let v1_pin_sha = lockfile(root.path(), "default")["snaps"]["hello"]["sha3-384"]
        .as_str()
        .unwrap()
        .to_string();

    let v2 = build_payload(
        builder_project.path(),
        // A fresh builder root: the first pod declares hello already,
        // and `pod add` refuses a re-add.
        builder_root2.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "2.0",
        "sideload-two",
        port,
        "hello.tar.gz",
    );
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", v2.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("sideloaded 'hello' (2.0)"),
        "stderr: {stderr}"
    );
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(current_generation(root.path(), "default"), 2);

    let farm = current_farm(root.path(), "default");
    let out = Command::new("hello").env("PATH", &farm).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("sideload-two"));

    let lock = lockfile(root.path(), "default");
    assert_eq!(lock["packages"]["hello"]["version"], "2.0");
    assert_ne!(
        lock["snaps"]["hello"]["sha3-384"].as_str().unwrap(),
        v1_pin_sha,
        "the blob pin must move to the new content"
    );
});

// `pod update` skips blob-pinned packages with a named note — they
// never float and never re-resolve from the collection.
gated_test!(update_skips_sideloaded, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    let (code, _, stderr) = run(project.path(), root.path(), &["update"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("skipped 'hello'"),
        "update must name the skip: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        1,
        "a skipped-only update creates no generation"
    );
});

// Loading a pod that carries a blob-pinned package refuses, named,
// before any write (composition rebuilds from collection source; a
// sideloaded package has none).
gated_test!(loading_pod_with_blob_pin_refused, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );

    // Pod A (same root, same project — it needs the collection for its
    // own initial add? no: A is the SIDeload target, empty project).
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "--name",
            "base",
            "add",
            "--snap",
            payload.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Pod B loads A and declares its own collection package.
    let other_letter = project.path().join("pkgs").join("o");
    std::fs::create_dir_all(&other_letter).unwrap();
    std::fs::write(
        other_letter.join("other.lua"),
        format!(
            "return {{ default = snap {{ name = \"other\", version = \"1.0\", \
             source = \"http://127.0.0.1:{port}/hello.tar.gz\", \
             build = \"true\" }} }}\n"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(pod_dir(root.path(), "other")).unwrap();
    std::fs::write(
        pod_dir(root.path(), "other").join("pod.lua"),
        // `other` is NOT in packages yet — the add is what must refuse.
        "pod { loads = { \"base\" }, packages = {} }\n",
    )
    .unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "other", "add", "other"],
    );
    assert_ne!(code, Some(0), "the load must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("sideloaded package(s)") && stderr.contains("hello"),
        "must name the loaded pod and the pinned package: {stderr}"
    );
    assert!(
        stderr.contains("issue #116"),
        "must cite the issue: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "other").join("shuttle.lock").exists(),
        "the refusal must leave zero writes"
    );
});

// ── Council round 2 ──

// `deps fetch` skips blob-pinned packages (council round 2): a
// sideloaded package was never a collection package, so resolving its
// meta would die — fatally on the collection-less pod a sideload
// targets. The verb must succeed and name the skip.
gated_test!(deps_fetch_skips_sideloaded, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    // Collection-less target pod: no pkgs/ at all.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let (code, _, stderr) = run_plain(
        project.path(),
        root.path(),
        &["deps", "fetch", "--name", "default"],
    );
    assert_eq!(
        code,
        Some(0),
        "deps fetch must not die on a blob pin: {stderr}"
    );
    assert!(
        stderr.contains("skipped 'hello'") && stderr.contains("sideloaded"),
        "must name the sideload skip: {stderr}"
    );
});

// A no-op re-add still re-presents the pod (council round 2): a
// previous install whose follow-up sync failed leaves the farm stale
// while the generation already carries the sha — the re-add runs sync
// (idempotent), repairs the farm, and only then reports "nothing to
// do".
gated_test!(readd_repairs_stale_farm, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("hello").exists());

    // Simulate the stale presentation a failed follow-up sync leaves:
    // the farm lost the binary.
    std::fs::remove_file(farm.join("hello")).unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("nothing to do"),
        "the content is identical — a no-op: {stderr}"
    );
    let farm = current_farm(root.path(), "default");
    assert!(
        farm.join("hello").exists(),
        "the no-op re-add must have re-presented the farm"
    );
    assert_eq!(generation_count(root.path(), "default"), 1);
});

// Sideloading over a DECLARED collection package converts it to a blob
// pin — allowed, but loud: the same zero-writes prechecks as a new
// package run first, and a warning names the conversion (council
// round 2, ADR-0037 Decision 5 exception).
gated_test!(sideload_over_declared_collection_converts_loud, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // The target pod DECLARES hello (a collection package it never
    // managed to build — no collection here at all).
    let dir = pod_dir(root.path(), "default");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pod.lua"), "pod { packages = { \"hello\" } }\n").unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "the conversion is allowed: {stderr}");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("converted to a sideloaded blob pin"),
        "must warn about the trust-model flip: {stderr}"
    );
    let lock = lockfile(root.path(), "default");
    assert_eq!(lock["packages"]["hello"]["version"], "1.0");
    assert_eq!(lock["snaps"]["hello"]["revision"], 0);
    assert_eq!(generation_count(root.path(), "default"), 1);
});

// The hoisted prechecks refuse BEFORE any write: a pod that DECLARES
// the payload's name and LOADS a pod already carrying that blob pin
// cannot sideload over it (its load graph is invalid for a mutating
// verb — same refusal a plain `add` gets).
gated_test!(sideload_over_declared_in_loaded_pod_refused, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // Pod base carries the blob pin.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "--name",
            "base",
            "add",
            "--snap",
            payload.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Pod other declares hello AND loads base: the sideload must hit
    // the hoisted validate_loads and refuse with zero writes.
    let dir = pod_dir(root.path(), "other");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("pod.lua"),
        "pod { loads = { \"base\" }, packages = { \"hello\" } }\n",
    )
    .unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "--name",
            "other",
            "add",
            "--snap",
            payload.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_ne!(code, Some(0), "the hoisted precheck must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("sideloaded package(s)") && stderr.contains("hello"),
        "must name the loaded pod's blob pins: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "other").join("shuttle.lock").exists(),
        "the refusal must leave zero writes"
    );
});

// `pod rebuild` of a blob-pinned package HOLDS it at its pin and says
// so — never "rebuilt" (council round 2: the held-list is no longer
// discarded).
gated_test!(rebuild_sideloaded_reports_held, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let (code, _, stderr) = run(project.path(), root.path(), &["rebuild", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("held 'hello' at its pin"),
        "must surface the hold like sync does: {stderr}"
    );
    assert!(
        !stderr.contains("rebuilt"),
        "a held package must not be reported as rebuilt: {stderr}"
    );
    assert_eq!(generation_count(root.path(), "default"), 1);
});

// ── Issue #133 / #135: sideload hardening ──

/// The snap-arch vocabulary of the build host (the `crate::snap::host_arch`
/// mapping, mirrored here so fixtures name the arch the gate accepts).
fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

// Issue #133: a payload whose filename claims a foreign architecture
// refuses BEFORE any write — a foreign blob installs clean and fails
// only at exec, which is the failure the gate exists for. The control
// side proves the gate does not over-refuse: the same content under
// the host's arch installs.
gated_test!(foreign_arch_payload_refused, {
    let stage = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // Neither amd64 nor arm64: the refusal is host-arch-independent.
    let foreign = stage.path().join("hello_1.0_riscv64.snap");
    fake_snap(&foreign, "name: hello\nversion: \"1.0\"\n");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", foreign.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_ne!(code, Some(0), "a foreign-arch payload must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("arch riscv64") && stderr.contains("foreign-architecture"),
        "must name the arch mismatch: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "default")
            .join("shuttle.lock")
            .exists(),
        "the refusal must leave zero writes"
    );

    // Control: the same content under the HOST arch installs.
    let local = stage.path().join(format!("hello_1.0_{}.snap", host_arch()));
    std::fs::copy(&foreign, &local).unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", local.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(
        code,
        Some(0),
        "the host-arch payload must install: {stderr}"
    );
});

// Issue #135 (blob-pin polish): a sideloaded version that violates the
// declared `@constraint` refuses before any write — both the fresh
// conversion and the deliberate version move — instead of recording a
// packages pin that contradicts its own constraint.
gated_test!(constraint_violating_sideload_refused, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let builder_root2 = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let v1 = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-one",
        port,
        "hello.tar.gz",
    );
    let v2 = build_payload(
        builder_project.path(),
        builder_root2.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "2.0",
        "sideload-two",
        port,
        "hello.tar.gz",
    );

    // (a) Fresh conversion: the target DECLARES hello@2; sideloading
    // hello 1.0 would record version 1.0 under constraint 2. (The
    // constraint grammar is dotted-numeric prefix: `@1`, not `@1.x`.)
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let dir = pod_dir(root.path(), "default");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pod.lua"), "pod { packages = { \"hello@2\" } }\n").unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", v1.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_ne!(code, Some(0));
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("violates the declared constraint '@2'") && stderr.contains("version 1.0"),
        "must name the violated constraint: {stderr}"
    );
    assert!(
        !dir.join("shuttle.lock").exists(),
        "the refusal must leave zero writes"
    );

    // (b) Version move: hello@1 + sideloaded 1.0 installs; re-adding
    // 2.0 must refuse with the pins and generation untouched.
    let root2 = tempfile::tempdir().unwrap();
    let dir = pod_dir(root2.path(), "default");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pod.lua"), "pod { packages = { \"hello@1\" } }\n").unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root2.path(),
        &["add", "--snap", v1.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "1.0 matches '@1': {stderr}");
    assert_eq!(generation_count(root2.path(), "default"), 1);

    let (code, _, stderr) = run(
        project.path(),
        root2.path(),
        &["add", "--snap", v2.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_ne!(code, Some(0), "the constraint-violating move must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("violates the declared constraint '@1'") && stderr.contains("version 2.0"),
        "must name the violated constraint: {stderr}"
    );
    assert_eq!(
        generation_count(root2.path(), "default"),
        1,
        "no generation may move"
    );
    assert_eq!(
        lockfile(root2.path(), "default")["packages"]["hello"]["version"],
        "1.0",
        "the pin must stay at the constraint-honoring version"
    );
});

// Issue #135 (blob-pin polish, rollback trap): rolling back to a
// generation that predates a blob pin SUCCEEDS — and the report names
// the stranded pin and its recovery path, instead of leaving the next
// mutating verb to fail named without warning.
gated_test!(rollback_predating_blob_pin_names_recovery, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "apples");
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let apples = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "apples",
        "apples",
        "apples",
        "1.0",
        "marker-apples",
        port,
        "apples.tar.gz",
    );
    let hello = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "marker-hello",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // The target's project carries resolvable RECIPES for both packages
    // (never built — the payloads are the input): the second sideload's
    // collision precheck resolves the first package's declared claims
    // from the collection, which a collection-less pod cannot do
    // (pre-existing limitation, see PR notes).
    write_pkg_version(
        project.path(),
        "apples",
        "apples",
        "apples",
        "1.0",
        "marker-apples",
        port,
        "apples.tar.gz",
    );
    write_pkg_version(
        project.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "marker-hello",
        port,
        "hello.tar.gz",
    );

    // Two sideloads: apples is generation 1, hello is generation 2.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", apples.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", hello.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);

    // Roll back to the pre-hello generation: succeeds, warns.
    let (code, _, stderr) = run(project.path(), root.path(), &["rollback", "1"]);
    assert_eq!(code, Some(0), "the rollback itself must succeed: {stderr}");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("blob pin") && stderr.contains("hello"),
        "must name the stranded pin: {stderr}"
    );
    assert!(
        stderr.contains("add --snap"),
        "must name the recovery path: {stderr}"
    );

    // The trap: the next mutating verb fails named...
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_ne!(code, Some(0), "the stranded pin must fail sync");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("blob-pinned") && stderr.contains("does not carry its pinned content"),
        "must be the named bail: {stderr}"
    );

    // ...and the recovery the rollback named repairs it.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", hello.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "the re-add must repair: {stderr}");
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("held 'hello'"), "stderr: {stderr}");
});

// Issue #135 (blob-pin polish, repair test): hold_blob_pinned's named
// bail for the half-done state a failed `add --snap` install leaves —
// declaration + pins written, content never installed — and the named
// repair (re-add) that recovers from it.
gated_test!(pins_without_content_refuses_then_readd_repairs, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let pinned_sha = lockfile(root.path(), "default")["snaps"]["hello"]["sha3-384"]
        .as_str()
        .unwrap()
        .to_string();

    // Remove drops the declaration entry and both pins.
    let (code, _, stderr) = run(project.path(), root.path(), &["remove", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Hand-write the half-done state back: declaration + pins WITHOUT
    // installed content — exactly what `add --snap` leaves when its
    // install fails after the writes.
    let dir = pod_dir(root.path(), "default");
    std::fs::write(dir.join("pod.lua"), "pod { packages = { \"hello\" } }\n").unwrap();
    let lock_path = dir.join("shuttle.lock");
    let mut lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    lock["packages"]["hello"] = serde_json::json!({ "version": "1.0" });
    lock["snaps"]["hello"] = serde_json::json!({ "revision": 0, "sha3-384": pinned_sha });
    std::fs::write(&lock_path, serde_json::to_string_pretty(&lock).unwrap()).unwrap();

    // The next sync refuses, named.
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_ne!(code, Some(0), "pins without content must fail sync");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("blob-pinned") && stderr.contains("does not carry its pinned content"),
        "must be hold_blob_pinned's named bail: {stderr}"
    );

    // The named repair — re-run `pod add --snap` — reinstalls it.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "the re-add must repair: {stderr}");
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("held 'hello'"), "stderr: {stderr}");
});

// Issue #135 (blob-pin polish, loader-side brick): sideloading into a
// pod that ANOTHER pod loads succeeds — the sideload itself is
// legitimate — but warns, naming the loading pod whose mutating verbs
// will now refuse (and demonstrating exactly that).
gated_test!(sideload_into_loaded_pod_warns, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    let stage = tempfile::tempdir().unwrap();
    let payload = build_payload(
        builder_project.path(),
        builder_root.path(),
        stage.path(),
        "hello",
        "hello",
        "hello",
        "1.0",
        "sideload-ran",
        port,
        "hello.tar.gz",
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // Pod `other` loads `base` BEFORE the sideload lands.
    let other = pod_dir(root.path(), "other");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("pod.lua"),
        "pod { loads = { \"base\" }, packages = {} }\n",
    )
    .unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &[
            "--name",
            "base",
            "add",
            "--snap",
            payload.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_eq!(code, Some(0), "the sideload must succeed: {stderr}");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("loaded by pod 'other'"),
        "must name the loading pod: {stderr}"
    );

    // The brick is real: the loading pod's mutating verbs refuse.
    let (code, _, stderr) = run(project.path(), root.path(), &["--name", "other", "sync"]);
    assert_ne!(code, Some(0));
    assert!(
        flat(&stderr).contains("sideloaded package(s)"),
        "the loading pod must refuse named: {stderr}"
    );
});

// Issue #135 (blob-pin polish, farm seam): a payload whose app name is
// not a bare name must not produce a farm symlink outside the farm
// dir — the emit refuses named at the seam.
gated_test!(farm_link_refuses_non_bare_app_name, {
    let stage = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // A payload with a real bin/evil file and the app keyed "../evil".
    let evil = stage.path().join(format!("evil_1.0_{}.snap", host_arch()));
    let pkg_stage = stage.path().join("evil-stage");
    let meta = pkg_stage.join("meta");
    let bin = pkg_stage.join("bin");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        meta.join("snap.yaml"),
        "name: evil\nversion: \"1.0\"\napps:\n  \"../evil\":\n    command: bin/evil\n",
    )
    .unwrap();
    std::fs::write(bin.join("evil"), "#!/bin/sh\necho pwned\n").unwrap();
    let status = Command::new("mksquashfs")
        .args([
            pkg_stage.to_str().unwrap(),
            evil.to_str().unwrap(),
            "-noappend",
            "-no-xattrs",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "mksquashfs failed");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", evil.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_ne!(code, Some(0), "the non-bare app name must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("outside the bin farm") && stderr.contains("../evil"),
        "must name the app and the refusal: {stderr}"
    );
    // Nothing escaped the farm: `farm.join("../evil")` would land beside
    // the farm dir inside the generation.
    let gen1 = pod_dir(root.path(), "default")
        .join("generations")
        .join("1");
    assert!(
        !gen1.join("evil").exists(),
        "no symlink may exist outside the farm dir"
    );
});
