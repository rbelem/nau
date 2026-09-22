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
    harvest_payload(root, dest_dir, name, version)
}

/// Copy the built `{name}_{version}_*.snap` out of the builder pod's
/// downloads dir into `dest_dir`, preserving the artifact filename.
fn harvest_payload(builder_root: &Path, dest_dir: &Path, name: &str, version: &str) -> PathBuf {
    let downloads = builder_root.join("build").join("downloads");
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

/// Write a resolvable package that carries a `requires` edge (issue
/// #132) and builds a real executable into $STAGE/bin/<bin>. The
/// `requires` name rides meta/snap.yaml (issue #110 emission), which is
/// what the sideload pre-flight reads.
fn write_requires_pkg(
    project: &Path,
    name: &str,
    requires: &str,
    bin: &str,
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
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    requires = {{ "{requires}" }},
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{bin} && echo 'echo {marker}' >> $STAGE/bin/{bin} && chmod +x $STAGE/bin/{bin}",
    apps = {{ {bin} = {{ command = "bin/{bin}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// Build the requires-carrying `app` payload in a BUILDER pod (whose
/// project also carries the WORKING `libmember` recipe the build prefix
/// and closure consume) and copy the payload out. The source tarballs
/// land in `server_dir` (served on `port`).
fn build_requires_payload(
    builder_project: &Path,
    builder_root: &Path,
    server_dir: &Path,
    dest_dir: &Path,
    port: u16,
) -> PathBuf {
    make_tarball(server_dir, "appsrc");
    make_tarball(server_dir, "member");
    write_pkg_version(
        builder_project,
        "libmember",
        "memberlib",
        "memberlib",
        "1.0",
        "member-ran",
        port,
        "member.tar.gz",
    );
    write_requires_pkg(
        builder_project,
        "app",
        "libmember",
        "appbin",
        "app-ran",
        port,
        "appsrc.tar.gz",
    );
    let (code, _, stderr) = run(
        builder_project,
        builder_root,
        &["--name", "build", "add", "app"],
    );
    assert_eq!(code, Some(0), "builder pod add failed: {stderr}");
    harvest_payload(builder_root, dest_dir, "app", "1.0")
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
/// flattened form so a wrap never breaks a fragment. The `│` gutters
/// ride the wrapped lines (not whitespace), so they are stripped too.
fn flat(s: &str) -> String {
    s.split(|c: char| c.is_whitespace() || c == '│')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
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

// ── Requires-closure failure contract (issue #132, ADR-0037) ──

// The generation the store's `active` link points at (install-time
// activation) — distinct from `current_generation`, the farm link that
// only `present_active` flips.
fn active_generation_link(root: &Path, pod: &str) -> u64 {
    let target = std::fs::read_link(pod_dir(root, pod).join("active")).unwrap();
    target
        .components()
        .last()
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

// Zero-write pre-flight (issue #132): a requires-carrying payload
// whose closure cannot resolve on a collection-less machine refuses
// BEFORE any write — no declaration entry, no pins, no generation.
// The payload is the fake_snap shape: the pre-flight reads
// meta/snap.yaml only.
gated_test!(preflight_refuses_unresolvable_requires_zero_write, {
    let stage = tempfile::tempdir().unwrap();
    let payload = stage.path().join("app_1.0_amd64.snap");
    fake_snap(
        &payload,
        "name: app\nversion: \"1.0\"\nrequires:\n  - libmember\n",
    );
    // Collection-less target: no pkgs/ at all, so `libmember` cannot
    // resolve.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_ne!(code, Some(0), "the unresolvable closure must refuse");
    let stderr = flat(&stderr);
    assert!(
        stderr.contains("refusing to sideload 'app'") && stderr.contains("requires"),
        "must name the payload and the gate: {stderr}"
    );
    assert!(
        stderr.contains("libmember"),
        "must name the unresolvable member: {stderr}"
    );
    assert!(
        stderr.contains("provide the collection"),
        "must name the fix: {stderr}"
    );
    assert!(
        !pod_dir(root.path(), "default").exists(),
        "the refusal must leave zero writes"
    );
    assert_eq!(generation_count(root.path(), "default"), 0);
});

// Flagship: a requires-carrying payload whose closure RESOLVES
// sideloads end to end — the follow-up sync installs the closure into
// the generation, the farm exposes payload + closure, a follow-up sync
// holds, and an identical re-add stays a no-op.
gated_test!(requires_closure_resolves_sideload_completes, {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let stage = tempfile::tempdir().unwrap();
    let payload = build_requires_payload(
        builder_project.path(),
        builder_root.path(),
        server.path(),
        stage.path(),
        port,
    );

    // Target: carries the libmember recipe (the collection seam the
    // closure resolves through) but NOT the app recipe.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg_version(
        project.path(),
        "libmember",
        "memberlib",
        "memberlib",
        "1.0",
        "member-ran",
        port,
        "member.tar.gz",
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("sideloaded 'app' (1.0)"),
        "stderr: {stderr}"
    );
    // Generation 1 carries the payload; the follow-up sync installs
    // the closure member as generation 2.
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(current_generation(root.path(), "default"), 2);

    // The farm exposes payload AND closure; both execute.
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("appbin").exists(), "farm must expose the payload");
    assert!(
        farm.join("memberlib").exists(),
        "farm must expose the closure"
    );
    for (bin, marker) in [("appbin", "app-ran"), ("memberlib", "member-ran")] {
        let out = Command::new(bin).env("PATH", &farm).output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(marker),
            "{bin} must execute: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    let lock = lockfile(root.path(), "default");
    assert_eq!(lock["packages"]["app"]["version"], "1.0");
    assert_eq!(lock["snaps"]["app"]["revision"], 0);

    // Follow-up sync: the blob pin holds, the closure is carried —
    // no new generation.
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("held 'app'"), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);

    // Identical re-add: a no-op.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("nothing to do"), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);
});

/// The shared partial-state fixture for the residual tests (issue
/// #132): build the requires-carrying payload with a builder pod, and
/// set up a target pod whose only closure recipe (`libmember`)
/// RESOLVES — the pre-flight's Lua eval needs no fetch — but whose
/// source 404s, so the follow-up sync dies mid-closure-build after the
/// payload goes active. Returns (project, root, stage, server, payload,
/// port); the caller runs the failing add, and the target still carries
/// the broken recipe — the heal variants rewrite it at the working
/// tarball. The server (and its `member.tar.gz`) must stay alive for
/// the heal syncs.
fn partial_state_fixture() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
    PathBuf,
    u16,
) {
    let builder_project = tempfile::tempdir().unwrap();
    let builder_root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let stage = tempfile::tempdir().unwrap();
    let payload = build_requires_payload(
        builder_project.path(),
        builder_root.path(),
        server.path(),
        stage.path(),
        port,
    );
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // The broken member: resolves (pre-flight passes) but its fetch 404s.
    write_pkg_version(
        project.path(),
        "libmember",
        "memberlib",
        "memberlib",
        "1.0",
        "member-ran",
        port,
        "missing-member.tar.gz",
    );
    (project, root, stage, server, payload, port)
}

/// The collection-less add of the requires-carrying payload against the
/// fixture's broken member recipe: the pre-flight passes, the install
/// goes active, the follow-up sync fails. Returns the runner triple.
fn add_again_broken_closure(
    project: &tempfile::TempDir,
    root: &tempfile::TempDir,
    payload: &Path,
) -> (Option<i32>, String, String) {
    run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    )
}

// Residual tolerate-and-warn (issue #132): the pre-flight passes (the
// closure recipe resolves — resolution is a Lua eval, no fetch), the
// payload installs ACTIVE, and the follow-up sync dies mid-closure on
// the member's fetch. The add fails with ONE combined error — cause +
// partial-state note naming both recovery verbs — and leaves the
// DECLARED partial generation: payload active on the store, both pins,
// no rollback. Abandon tail: `pod remove` works collection-less, drops
// the declaration entry and both pins, and the pod syncs clean again.
gated_test!(
    closure_failure_after_install_leaves_declared_partial_state,
    {
        let (project, root, _stage, _server, payload, _port) = partial_state_fixture();

        let (code, _, stderr) = add_again_broken_closure(&project, &root, &payload);
        assert_ne!(code, Some(0));
        let stderr = flat(&stderr);
        assert!(
            stderr.contains("closure incomplete"),
            "must flag the residual: {stderr}"
        );
        assert!(
            stderr.contains("ACTIVE on generation 1"),
            "must name the active generation: {stderr}"
        );
        assert!(
            stderr.contains("failed to download http") && stderr.contains("404"),
            "the cause must name the failed fetch: {stderr}"
        );
        assert!(
            stderr.contains("`shuttle pod sync`") && stderr.contains("`shuttle pod remove app`"),
            "must name both recovery verbs: {stderr}"
        );
        assert!(stderr.contains("to abandon"), "stderr: {stderr}");

        // Partial state: the payload is ACTIVE on the store's generation 1
        // (the install flipped `active`), the farm was never re-presented
        // (no `current` link), the declaration entry and both pins stand.
        assert_eq!(generation_count(root.path(), "default"), 1);
        assert_eq!(active_generation_link(root.path(), "default"), 1);
        assert!(
            !pod_dir(root.path(), "default").join("current").exists(),
            "the failed sync must not have presented the farm"
        );
        let lock = lockfile(root.path(), "default");
        assert_eq!(lock["packages"]["app"]["version"], "1.0");
        assert_eq!(lock["snaps"]["app"]["revision"], 0);
        let decl_text =
            std::fs::read_to_string(pod_dir(root.path(), "default").join("pod.lua")).unwrap();
        assert!(
            decl_text.contains("app"),
            "the declaration must carry the payload: {decl_text}"
        );

        // Abandon: `pod remove` succeeds collection-less, drops decl +
        // both pins, and the pod syncs clean again.
        let (code, _, stderr) = run(project.path(), root.path(), &["remove", "app"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let lock = lockfile(root.path(), "default");
        assert!(lock["packages"].get("app").is_none());
        assert!(lock["snaps"].get("app").is_none());
        let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
        assert_eq!(code, Some(0), "the abandoned pod must sync clean: {stderr}");
    }
);

// Heal-in-place (issue #132): from the declared partial state,
// providing the collection lets a PLAIN `pod sync` complete the
// closure — no re-add needed.
gated_test!(heal_partial_state_with_plain_sync, {
    let (project, root, _stage, _server, payload, port) = partial_state_fixture();
    let (code, _, stderr) = add_again_broken_closure(&project, &root, &payload);
    assert_ne!(code, Some(0), "the partial-state add must fail: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    // Provide the missing member: the recipe now fetches the real tarball.
    write_pkg_version(
        project.path(),
        "libmember",
        "memberlib",
        "memberlib",
        "1.0",
        "member-ran",
        port,
        "member.tar.gz",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "the heal sync must complete: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(current_generation(root.path(), "default"), 2);
    let farm = current_farm(root.path(), "default");
    assert!(
        farm.join("memberlib").exists(),
        "the closure must be installed"
    );
    assert!(
        farm.join("appbin").exists(),
        "the payload must stay presented"
    );
    let out = Command::new("memberlib")
        .env("PATH", &farm)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("member-ran"),
        "the closure binary must execute: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
});

// Repair-by-re-add (issue #132): from the declared partial state,
// providing the collection and re-adding the IDENTICAL payload exits
// zero — the no-op re-add runs the follow-up sync and completes the
// closure.
gated_test!(repair_partial_state_by_readd, {
    let (project, root, _stage, _server, payload, port) = partial_state_fixture();
    let (code, _, stderr) = add_again_broken_closure(&project, &root, &payload);
    assert_ne!(code, Some(0), "the partial-state add must fail: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);

    write_pkg_version(
        project.path(),
        "libmember",
        "memberlib",
        "memberlib",
        "1.0",
        "member-ran",
        port,
        "member.tar.gz",
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("nothing to do"), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(current_generation(root.path(), "default"), 2);
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("memberlib").exists(), "stderr: {stderr}");
    assert!(farm.join("appbin").exists(), "stderr: {stderr}");
});
