//! `shuttle pod declare --file` integration tests (gate-pod gap 5).
//!
//! Drives the real binary end to end: a checked-in pod.lua is loaded,
//! validated, and made the pod's declaration (replacing whatever was
//! there — the file is the source of truth), then the pod reconciles
//! through the same path add/sync uses. Covers the three contracts:
//!
//! - declare initializes an unknown pod from a file (declaration,
//!   lockfile pin, generation, bin farm).
//! - declare replaces a divergent declaration and the farm follows
//!   (dropped package's binaries leave the farm, new ones materialize).
//! - an invalid file fails loud BEFORE any write — the pod is untouched.
//!
//! Mirrors tests/pod_install.rs: real builds over a loopback HTTP
//! source server, all state in tempdirs, gated on the external
//! toolchain (mksquashfs/unsquashfs/curl/tar). Stderr assertions use
//! short fragments — miette wraps messages at 80 columns.

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

/// A resolvable package that builds a real executable the farm exposes.
fn write_pkg(project: &Path, name: &str, bin: &str, marker: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{bin} && echo 'echo {marker}' >> $STAGE/bin/{bin} && chmod +x $STAGE/bin/{bin}",
    apps = {{ {name} = {{ command = "bin/{bin}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// A checked-in pod.lua declaring the given packages verbatim.
fn write_pod_file(project: &Path, file_name: &str, packages: &[&str]) -> PathBuf {
    let list = packages
        .iter()
        .map(|p| format!(r#""{p}""#))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!("-- checked in by hand\npod {{ packages = {{ {list} }} }}\n");
    let path = project.join(file_name);
    std::fs::write(&path, source).unwrap();
    path
}

// ── Runners ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // The desktop launcher surface (issue #7) writes to the user data
    // home — redirect it inside the test's tempdir, never the real home.
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (issue #66).
    cmd.env("SHUTTLE_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

fn pod_lua(root: &Path, pod: &str) -> PathBuf {
    pod_dir(root, pod).join("pod.lua")
}

fn pod_lock(root: &Path, pod: &str) -> PathBuf {
    pod_dir(root, pod).join("shuttle.lock")
}

fn current_link(root: &Path, pod: &str) -> PathBuf {
    pod_dir(root, pod).join("current")
}

/// The generation count (numeric entries under generations/).
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

/// The generation the pod's `current` link points at.
fn current_generation(root: &Path, pod: &str) -> u64 {
    let target = std::fs::read_link(current_link(root, pod)).unwrap();
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

/// The farm directory behind `current`.
fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let target = std::fs::read_link(current_link(root, pod)).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

fn snapshot(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ── Acceptance ──

gated_test!(declare_initializes_unknown_pod_from_file, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    write_pkg(project.path(), "hello", "hello", "pod-declare-hello", port);
    let checked_in = write_pod_file(project.path(), "pod-a.lua", &["hello"]);

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", checked_in.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    // Loud + short: the declare happened and the delta names the add.
    assert!(stderr.contains("declared"), "stderr: {stderr}");
    assert!(stderr.contains("added:"), "stderr: {stderr}");
    assert!(stderr.contains("hello"), "stderr: {stderr}");

    // The file's content IS the declaration — copied verbatim,
    // comments included.
    let declared = std::fs::read_to_string(pod_lua(root.path(), "default")).unwrap();
    let source = std::fs::read_to_string(&checked_in).unwrap();
    assert_eq!(declared, source, "pod.lua must carry the file verbatim");

    // The reconcile followed: pin, generation, farm.
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pod_lock(root.path(), "default")).unwrap())
            .unwrap();
    assert_eq!(lock["packages"]["hello"]["version"], "1.0");
    assert_eq!(current_generation(root.path(), "default"), 1);
    assert!(current_farm(root.path(), "default").join("hello").exists());

    // list reflects the declared set.
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("hello"),
        "list must show the declared package: {stderr}"
    );
});

gated_test!(declare_replaces_divergent_declaration_and_farm_follows, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    make_tarball(server.path(), "ibex");
    write_pkg(project.path(), "hello", "hello", "pod-div-hello", port);
    write_pkg(project.path(), "ibex", "ibex", "pod-div-ibex", port);
    let file_a = write_pod_file(project.path(), "pod-a.lua", &["hello"]);
    let file_b = write_pod_file(project.path(), "pod-b.lua", &["ibex"]);

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", file_a.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "seed declare failed: {stderr}");
    assert!(current_farm(root.path(), "default").join("hello").exists());

    // Replace with a divergent declaration: ibex in, hello out.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", file_b.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("added:"), "stderr: {stderr}");
    assert!(stderr.contains("removed:"), "stderr: {stderr}");
    assert!(stderr.contains("ibex"), "stderr: {stderr}");

    // The farm followed: hello's binary left, ibex's materialized.
    let farm = current_farm(root.path(), "default");
    assert!(
        !farm.join("hello").exists(),
        "dropped package leaves the farm"
    );
    assert!(farm.join("ibex").exists(), "new package joins the farm");
    // The replace reconciled onto a new generation (removal + install
    // may each bump — the exact count is the store's business; the
    // farm behind `current` is the contract).
    assert!(generation_count(root.path(), "default") >= 2);
    assert!(current_generation(root.path(), "default") >= 2);

    // The declaration itself was replaced wholesale.
    let declared = std::fs::read_to_string(pod_lua(root.path(), "default")).unwrap();
    assert!(
        declared.contains("ibex") && !declared.contains("hello"),
        "pod.lua must be the new file verbatim:\n{declared}"
    );

    // list reflects the new set only.
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("ibex"),
        "list must show the new package: {stderr}"
    );
    assert!(
        !stderr.contains("hello"),
        "list must not show the dropped package: {stderr}"
    );
});

gated_test!(declare_missing_file_fails_loud, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", "nowhere/pod.lua"],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("no such declaration file"),
        "error must name the missing file loudly: {stderr}"
    );
    assert!(
        !pod_lua(root.path(), "default").exists(),
        "no declaration on failure"
    );
    assert!(
        !pod_dir(root.path(), "default").exists(),
        "no pod directory on failure"
    );
});

gated_test!(declare_invalid_file_fails_loud_leaving_pod_untouched, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    write_pkg(project.path(), "hello", "hello", "pod-keep-hello", port);
    let good = write_pod_file(project.path(), "pod-a.lua", &["hello"]);

    // Seed the pod through the same verb, then try to replace it
    // with garbage.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", good.to_str().unwrap()],
    );
    assert_eq!(code, Some(0), "seed declare failed: {stderr}");

    let decl_before = snapshot(&pod_lua(root.path(), "default"));
    let lock_before = snapshot(&pod_lock(root.path(), "default"));

    let bad = project.path().join("bad.lua");
    std::fs::write(&bad, "this is not lua )(\n").unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["declare", "--file", bad.to_str().unwrap()],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("bad.lua"),
        "error must name the invalid file: {stderr}"
    );

    // Zero writes: the pod still carries the previous declaration
    // and its lockfile pin.
    assert_eq!(
        snapshot(&pod_lua(root.path(), "default")),
        decl_before,
        "pod.lua must be untouched on failure"
    );
    assert_eq!(
        snapshot(&pod_lock(root.path(), "default")),
        lock_before,
        "lockfile must be untouched on failure"
    );
});
