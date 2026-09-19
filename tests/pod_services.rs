//! `shuttle pod` services declarations (ADR-0032, issue #105).
//!
//! Drives the real binary end to end through the FULL chain: a package
//! declares `services = { … }`, `pod add` records it through the
//! build → install pipeline (services ride the payload's meta/snap.yaml),
//! and same-precedence duplicate service names are a hard error via the
//! shared collision classifier — zero writes. Pod-level `services`
//! overrides validate at reconcile: an unknown service name fails before
//! any mutation; a real override resolves with a warning naming winner
//! and loser. All state (project dir, pod root, data home) lives in
//! tempdirs — never the real home.
//!
//! Tests gate on the external toolchain (mksquashfs/unsquashfs/curl/tar),
//! same skip pattern as `pod_install.rs` / `pod_loads.rs`.

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

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            if !chain_available() {
                eprintln!("skipping: mksquashfs/unsquashfs/curl/tar unavailable");
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

/// A package that builds an echo-marker binary AND declares the service
/// `service`. The service reuses the built binary as its command; the
/// `enabled = false` default keeps it dormant (nothing starts — there is
/// no service emitter on this surface yet, ADR-0032 ticket #106).
fn write_service_pkg(project: &Path, name: &str, service: &str, marker: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{name} && echo 'echo {marker}' >> $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    apps = {{ ["{name}"] = {{ command = "bin/{name}" }} }},
    services = {{
        ["{service}"] = {{
            command = "bin/{name}",
            args = {{ "--port", "${{port}}" }},
            options = {{ enabled = false, port = 7001 }},
            environment = {{ QUIET = "yes" }},
        }},
    }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners ──

/// Run `shuttle pod [--name <pod>] <verb...>` against the project and
/// pod root. Pod names come BEFORE the verb by design (issue #4).
fn run_named(
    project: &Path,
    root: &Path,
    pod: &str,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod");
    if !pod.is_empty() {
        cmd.arg("--name").arg(pod);
    }
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
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

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    run_named(project, root, "", args)
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

fn snapshot(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ── Acceptance: a service-declaring package moves through the full chain ──

gated_test!(service_package_adds_end_to_end, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");

    // The declaring package builds, installs, and presents like any
    // other — the services entry rides the payload (the generation
    // manifest record is ticket #106 and is deliberately not asserted
    // here).
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root.path(), "default")
                .join("generations")
                .join("1")
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["packages"]["svc-a"]["version"], "1.0",
        "the declaring package must be installed and recorded"
    );

    // Idempotent: a second sync stays a no-op.
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "second sync failed: {stderr}");
    assert!(
        stderr.contains("no new generation"),
        "second sync must be a no-op: {stderr}"
    );
});

// ── Acceptance: same-precedence service-name collision is a hard error ──

gated_test!(same_precedence_service_collision_errors_with_zero_writes, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    // Two DISTINCT packages declaring the SAME service name, both Own.
    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");
    write_service_pkg(project.path(), "svc-b", "dup-svc", "b-ran", port);
    make_tarball(server.path(), "svc-b");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");
    let gens_before = generation_count(root.path(), "default");
    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));
    let current_before = snapshot(&pod_dir(root.path(), "default").join("current"));

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-b"]);
    assert_eq!(
        code,
        Some(1),
        "same-precedence service collision must error: {stderr}"
    );
    assert!(
        stderr.contains("dup-svc") && stderr.contains("svc-a") && stderr.contains("svc-b"),
        "error must name the service and both packages: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        gens_before,
        "collision must not bump the generation"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "collision must not write the lockfile"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("current")),
        current_before,
        "collision must not flip current"
    );
});

// ── Acceptance: pod{} service overrides validate and resolve ──

gated_test!(service_override_unknown_name_fails_before_any_mutation, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");
    let gens_before = generation_count(root.path(), "default");
    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));

    // A typo'd service name is a hard error at reconcile — the override
    // must reference a declared service (ADR-0032 Decision 3).
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        "packages = { \"svc-a\" },",
        "packages = { \"svc-a\" },\n    services = { [\"no-such-svc\"] = { enabled = true } },",
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(
        code,
        Some(1),
        "override of an unknown service must error: {stderr}"
    );
    assert!(
        stderr.contains("no-such-svc") && stderr.contains("no package declares"),
        "error must name the unknown service: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        gens_before,
        "failed validation must not bump the generation"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "failed validation must not write the lockfile"
    );
});

gated_test!(service_override_syncs_with_winner_loser_warning, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");

    // Enable the service from the pod declaration (explicit, per Decision
    // 7): the package default `enabled = false` is overridden — the
    // cross-layer override warns naming winner and loser.
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        "packages = { \"svc-a\" },",
        "packages = { \"svc-a\" },\n    services = { [\"dup-svc\"] = { enabled = true, port = 7002 } },",
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "sync with a valid override failed: {stderr}");
    assert!(
        stderr.contains("dup-svc")
            && stderr.contains("overrides")
            && stderr.contains("pod 'default'")
            && stderr.contains("the package default"),
        "cross-layer override must warn naming winner and loser: {stderr}"
    );
});
