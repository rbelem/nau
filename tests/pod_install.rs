//! `shuttle pod` install integration tests (issue #3: pod install).
//!
//! Drives the real binary end to end through the FULL chain: a declared
//! package in `pkgs/` is built with the normal snap build path (source
//! downloaded over HTTP from a loopback server the test itself serves,
//! build command run in the bwrap sandbox, packed with mksquashfs),
//! installed into the pod's runtime store, and exposed through the
//! generation bin farm. All state (project dir, pod root) lives in
//! tempdirs — never the real home.
//!
//! The tests gate on the external toolchain the chain needs
//! (mksquashfs/unsquashfs/curl/tar), same skip pattern as the runtime
//! store tests in `src/runtime.rs`.
//!
//! Issue #5 adds: `update` moves constrained packages to the newest
//! matching versions (repin + generation bump, held when the candidate
//! moves past the constraint); `rollback` flips ONLY the pod's
//! `current` link and farm (system state untouched); `gc --prune`
//! drops unreferenced pod generations and frees their exclusive blobs
//! while live generations keep theirs.

use std::collections::BTreeMap;
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
/// connection). The thread lives as long as the test process — test
/// servers are never shut down, their sockets die with the process.
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

/// Pack a tiny source tarball the fixture build downloads (content is
/// irrelevant to the build; the tarball is created ONCE per test so
/// every sync of that test serves identical bytes).
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
fn write_pkg(
    project: &Path,
    name: &str,
    app: &str,
    bin: &str,
    marker: &str,
    port: u16,
    tarball: &str,
) {
    write_pkg_version(project, name, app, bin, "1.0", marker, port, tarball);
}

/// [`write_pkg`] with an explicit declared version — the version feeds
/// meta/snap.yaml inside the payload, so a version move changes the
/// payload's content identity (which is what the no-op detector
/// compares).
#[allow(clippy::too_many_arguments)]
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

/// A package with an app whose command binary is never built — the
/// install must fail closed.
fn write_pkg_missing_binary(project: &Path, name: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.lua")),
        format!(
            "return {{ default = snap {{ name = \"{name}\", version = \"1.0\", apps = {{ {name} = {{ command = \"bin/missing\" }} }} }} }}\n"
        ),
    )
    .unwrap();
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
    let link = current_link(root, pod);
    let target = std::fs::read_link(&link).unwrap();
    // The link is relative to the pod dir.
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

/// Resolve a farm entry's link chain to its ABSOLUTE, normalized target
/// file.
fn farm_entry_target(farm: &Path, name: &str) -> PathBuf {
    std::fs::canonicalize(farm.join(name)).expect("farm entry must resolve to existing content")
}

// ── Acceptance: install + farm + PATH ──

gated_test!(add_installs_package_binary_reachable_through_farm, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    write_pkg(
        project.path(),
        "hello",
        "hello",
        "hello",
        "pod-hello-ran",
        port,
        "hello.tar.gz",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Generation 1 exists; `current` tracks it.
    assert_eq!(generation_count(root.path(), "default"), 1);
    assert_eq!(current_generation(root.path(), "default"), 1);

    // The farm exposes the app as a DIRECT symlink into the store.
    let farm = current_farm(root.path(), "default");
    assert!(
        farm.join("hello").exists(),
        "farm must expose the app: {farm:?}"
    );
    let target = farm_entry_target(&farm, "hello");
    let store_dir = std::fs::canonicalize(pod_dir(root.path(), "default").join("store")).unwrap();
    assert!(
        target.starts_with(&store_dir),
        "farm entry must resolve into the store, not a shim: {target:?}"
    );

    // The binary EXECUTES with the farm on PATH.
    let out = Command::new("hello")
        .env("PATH", &farm)
        .output()
        .expect("spawn hello");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("pod-hello-ran"),
        "farm binary must execute: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // The generation manifest records the app → store content mapping.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root.path(), "default").join("generations/1/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["packages"]["hello"]["apps"]["hello"],
        serde_json::json!(farm_entry_target(&farm, "hello")
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()),
        "manifest must record the app's store content"
    );
});

gated_test!(each_mutation_bumps_generation_and_current_tracks_latest, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    make_tarball(server.path(), "other");
    write_pkg(
        project.path(),
        "hello",
        "hello",
        "hello",
        "pod-hello-ran",
        port,
        "hello.tar.gz",
    );
    write_pkg(
        project.path(),
        "other",
        "otool",
        "otool",
        "pod-other-ran",
        port,
        "other.tar.gz",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(current_generation(root.path(), "default"), 1);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "other"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2, "add must bump");
    assert_eq!(current_generation(root.path(), "default"), 2);
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("hello").exists() && farm.join("otool").exists());

    let (code, _, stderr) = run(project.path(), root.path(), &["remove", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        generation_count(root.path(), "default"),
        3,
        "remove must bump"
    );
    assert_eq!(current_generation(root.path(), "default"), 3);
    let farm = current_farm(root.path(), "default");
    assert!(
        !farm.join("hello").exists(),
        "removed package's binaries must leave the farm"
    );
    assert!(farm.join("otool").exists(), "surviving binaries stay");
});

gated_test!(sync_without_changes_creates_no_new_generation, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    write_pkg(
        project.path(),
        "hello",
        "hello",
        "hello",
        "pod-hello-ran",
        port,
        "hello.tar.gz",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 1);
    let farm_before = current_farm(root.path(), "default");
    let link_before = std::fs::read_link(current_link(root.path(), "default")).unwrap();

    // Re-running the reconcile with no changes must be a no-op.
    for _ in 0..2 {
        let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("no new generation"),
            "no-change sync must report its no-op: {stderr}"
        );
        assert_eq!(
            generation_count(root.path(), "default"),
            1,
            "no-change sync must not bump the generation"
        );
        assert_eq!(
            std::fs::read_link(current_link(root.path(), "default")).unwrap(),
            link_before,
            "current link unchanged"
        );
        assert_eq!(current_farm(root.path(), "default"), farm_before);
    }
});

gated_test!(sync_reconciles_hand_edited_declaration, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    make_tarball(server.path(), "other");
    write_pkg(
        project.path(),
        "hello",
        "hello",
        "hello",
        "pod-hello-ran",
        port,
        "hello.tar.gz",
    );
    write_pkg(
        project.path(),
        "other",
        "otool",
        "otool",
        "pod-other-ran",
        port,
        "other.tar.gz",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "other"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Hand-edit pod.lua to drop `hello` (hand edits are allowed) —
    // sync must reconcile the store and farm.
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        r#"packages = { "hello", "other" }"#,
        r#"packages = { "other" }"#,
    );
    assert_ne!(edited, decl, "fixture must match the rendered declaration");
    std::fs::write(&decl_path, edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(current_generation(root.path(), "default"), 3);
    let farm = current_farm(root.path(), "default");
    assert!(
        !farm.join("hello").exists(),
        "dropped package leaves the farm"
    );
    assert!(farm.join("otool").exists());
});

gated_test!(named_pods_isolate_generations_and_farms, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "hello");
    write_pkg(
        project.path(),
        "hello",
        "hello",
        "hello",
        "pod-hello-ran",
        port,
        "hello.tar.gz",
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "hello"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Everything (generation, store, farm, current) lives under work/;
    // the default pod was never created.
    assert_eq!(generation_count(root.path(), "work"), 1);
    assert_eq!(current_generation(root.path(), "work"), 1);
    assert!(current_farm(root.path(), "work").join("hello").exists());
    assert!(
        !root.path().join("default").exists(),
        "named-pod add must not create the default pod"
    );

    // A second pod is fully independent.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "play", "add", "hello"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "play"), 1);
    assert_eq!(generation_count(root.path(), "work"), 1, "work untouched");
    assert_eq!(current_generation(root.path(), "work"), 1);

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "remove", "hello"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "work"), 2, "work bumped");
    assert_eq!(generation_count(root.path(), "play"), 1, "play untouched");
    assert!(
        !current_farm(root.path(), "work").join("hello").exists(),
        "work's farm must drop the removed binary"
    );
    assert!(
        current_farm(root.path(), "play").join("hello").exists(),
        "play's farm keeps its binary"
    );
});

gated_test!(add_with_missing_app_binary_fails_closed, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg_missing_binary(project.path(), "ghostbin");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "ghostbin"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("bin/missing"),
        "error must name the unresolvable command binary: {stderr}"
    );
    // Fail-closed: no generation, no farm, no current link — the
    // declaration half (pod.lua + lock) is written for the retry.
    assert_eq!(generation_count(root.path(), "default"), 0);
    assert!(!current_link(root.path(), "default").exists());
    assert!(pod_dir(root.path(), "default").join("pod.lua").exists());
});

gated_test!(degraded_mode_without_squashfs_tools_installs_nothing, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // No source needed: the degraded path must not even try to build.
    let letter_dir = project.path().join("pkgs").join("j");
    std::fs::create_dir_all(&letter_dir).unwrap();
    std::fs::write(
        letter_dir.join("jq.lua"),
        "return { default = snap { name = \"jq\", version = \"1.7.1\" } }\n",
    )
    .unwrap();

    // Strip the PATH so mksquashfs/unsquashfs are unfindable.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod")
        .args(["add", "jq"])
        .arg("--root")
        .arg(root.path());
    cmd.current_dir(project.path());
    cmd.env("PATH", "/nonexistent-empty-path");
    // Redirect the launcher surface into the test's tempdir (issue #7).
    cmd.env("SHUTTLE_DATA_HOME", root.path().join("data-home"));
    let out = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Fail closed (issue #16): a reconcile without the squashfs pair
    // must NOT report success (the old degraded path installed nothing
    // but still walked the removal phase) — it exits nonzero naming the
    // missing tools, while the declaration half (pod.lua + lock) is
    // written for the retry.
    assert_ne!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("mksquashfs"),
        "degraded reconcile must name the missing tools: {stderr}"
    );
    assert!(pod_dir(root.path(), "default").join("pod.lua").exists());
    assert_eq!(
        generation_count(root.path(), "default"),
        0,
        "nothing installed"
    );
    assert!(
        !current_link(root.path(), "default").exists(),
        "nothing exposed"
    );
});

// ── Issue #5: update ──

/// The version a package is pinned at in the pod's lockfile.
fn lock_pin(root: &Path, pod: &str, name: &str) -> Option<String> {
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).unwrap(),
    )
    .unwrap();
    lock["packages"][name]["version"]
        .as_str()
        .map(str::to_string)
}

/// Run the farm entry `name` and return its stdout (the fixture
/// binaries echo their marker).
fn farm_output(farm: &Path, name: &str) -> String {
    let out = Command::new(farm.join(name))
        .output()
        .expect("run farm binary");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

gated_test!(
    update_moves_constrained_package_to_newest_matching_version,
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let port = serve_dir(server.path());
        make_tarball(server.path(), "tool");
        // The package collection says 14.1; the pod declares `tool@14`.
        write_pkg_version(
            project.path(),
            "tool",
            "tool",
            "tool",
            "14.1",
            "tool-14.1-ran",
            port,
            "tool.tar.gz",
        );

        let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool@14"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(current_generation(root.path(), "default"), 1);
        assert_eq!(
            lock_pin(root.path(), "default", "tool").as_deref(),
            Some("14.1")
        );
        assert_eq!(
            farm_output(&current_farm(root.path(), "default"), "tool"),
            "tool-14.1-ran"
        );

        // Upstream moves: the package collection now says 14.4 — still a
        // 14.x, so `update` must adopt it (newest 14.x), repin, and bump.
        write_pkg_version(
            project.path(),
            "tool",
            "tool",
            "tool",
            "14.4",
            "tool-14.4-ran",
            port,
            "tool.tar.gz",
        );

        let (code, _, stderr) = run(project.path(), root.path(), &["update", "tool"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("updated 'tool'") && stderr.contains("14.1") && stderr.contains("14.4"),
            "update must report the version move: {stderr}"
        );
        assert_eq!(
            generation_count(root.path(), "default"),
            2,
            "update must bump the generation"
        );
        assert_eq!(current_generation(root.path(), "default"), 2);
        assert_eq!(
            lock_pin(root.path(), "default", "tool").as_deref(),
            Some("14.4")
        );
        assert_eq!(
            farm_output(&current_farm(root.path(), "default"), "tool"),
            "tool-14.4-ran",
            "farm must follow the newer content"
        );
    }
);

gated_test!(update_holds_when_newest_candidate_breaks_constraint, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(
        project.path(),
        "tool",
        "tool",
        "tool",
        "14.1",
        "tool-14.1-ran",
        port,
        "tool.tar.gz",
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool@14"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Upstream jumps the major: 15.0 is NOT a 14.x — `pkg@14` holds.
    write_pkg_version(
        project.path(),
        "tool",
        "tool",
        "tool",
        "15.0",
        "tool-15-ran",
        port,
        "tool.tar.gz",
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["update"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("held 'tool'") && stderr.contains("14"),
        "update must report the held package: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        1,
        "a held package must not bump the generation"
    );
    assert_eq!(
        lock_pin(root.path(), "default", "tool").as_deref(),
        Some("14.1")
    );
    assert_eq!(
        farm_output(&current_farm(root.path(), "default"), "tool"),
        "tool-14.1-ran",
        "held package keeps its installed content"
    );
});

gated_test!(update_bare_spec_moves_to_newest_and_noops_when_current, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(
        project.path(),
        "tool",
        "tool",
        "tool",
        "14.1",
        "tool-14.1-ran",
        port,
        "tool.tar.gz",
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Bare spec = newest available: 15.0 is adopted with no constraint.
    write_pkg_version(
        project.path(),
        "tool",
        "tool",
        "tool",
        "15.0",
        "tool-15-ran",
        port,
        "tool.tar.gz",
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["update"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("updated 'tool'"), "stderr: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(
        lock_pin(root.path(), "default", "tool").as_deref(),
        Some("15.0")
    );
    assert_eq!(
        farm_output(&current_farm(root.path(), "default"), "tool"),
        "tool-15-ran"
    );

    // Already current → a no-op with no new generation.
    let (code, _, stderr) = run(project.path(), root.path(), &["update"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("no new generation"),
        "already-current update must report its no-op: {stderr}"
    );
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert_eq!(current_generation(root.path(), "default"), 2);
});

// ── Issue #5: rollback ──

/// Recursively snapshot a directory tree: rel path → kind + content /
/// symlink target. Used to prove a directory was untouched.
fn snapshot_tree(path: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    fn walk(path: &Path, base: &Path, out: &mut BTreeMap<String, String>) {
        let rel = path
            .strip_prefix(base)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_symlink() {
            out.insert(
                rel,
                format!("link:{}", std::fs::read_link(path).unwrap().display()),
            );
            return;
        }
        if path.is_dir() {
            out.insert(rel, "dir".to_string());
            for entry in std::fs::read_dir(path).unwrap().filter_map(|e| e.ok()) {
                walk(&entry.path(), base, out);
            }
        } else {
            out.insert(rel, format!("file:{}", std::fs::read(path).unwrap().len()));
        }
    }
    walk(path, path, &mut out);
    out
}

gated_test!(
    rollback_flips_current_and_farm_leaving_system_state_untouched,
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let port = serve_dir(server.path());
        make_tarball(server.path(), "hello");
        make_tarball(server.path(), "other");
        write_pkg(
            project.path(),
            "hello",
            "hello",
            "hello",
            "pod-hello-ran",
            port,
            "hello.tar.gz",
        );
        write_pkg(
            project.path(),
            "other",
            "otool",
            "otool",
            "pod-other-ran",
            port,
            "other.tar.gz",
        );

        let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let (code, _, stderr) = run(project.path(), root.path(), &["add", "other"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(current_generation(root.path(), "default"), 2);
        let farm2 = current_farm(root.path(), "default");
        assert!(farm2.join("hello").exists() && farm2.join("otool").exists());

        // A fake system state root: generations, a store blob, and the
        // `active` link. The pod must never touch it.
        let system = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(system.path().join("generations/1")).unwrap();
        std::fs::write(system.path().join("generations/1/manifest.json"), "{}").unwrap();
        std::fs::create_dir_all(system.path().join("store/aa")).unwrap();
        std::fs::write(system.path().join("store/aa/systemblob"), b"system").unwrap();
        std::os::unix::fs::symlink("generations/1", system.path().join("active")).unwrap();
        let system_before = snapshot_tree(system.path());

        // Roll back: the pod's `current` flips to the previous generation.
        let (code, _, stderr) = run(project.path(), root.path(), &["rollback"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("2 -> 1"),
            "rollback must report the flip: {stderr}"
        );
        assert_eq!(
            generation_count(root.path(), "default"),
            2,
            "rollback must not create generations"
        );
        assert_eq!(current_generation(root.path(), "default"), 1);

        // The farm follows: the newer generation's `otool` disappears.
        let farm1 = current_farm(root.path(), "default");
        assert!(
            !farm1.join("otool").exists(),
            "binaries the newer generation added must be withdrawn"
        );
        assert!(farm1.join("hello").exists());
        assert_eq!(
            farm_output(&farm1, "hello"),
            "pod-hello-ran",
            "the rolled-back binary still executes"
        );

        // The pod's store `active` link flipped with `current` (they move
        // together), and the system state is byte-for-byte untouched.
        let active_target =
            std::fs::read_link(pod_dir(root.path(), "default").join("active")).unwrap();
        assert_eq!(active_target, Path::new("generations/1"));
        assert_eq!(
            snapshot_tree(system.path()),
            system_before,
            "bootable system state must be untouched by a pod rollback"
        );
    }
);

// ── Issue #5: gc ──

/// The store blob hash of one app binary in a generation's manifest.
fn manifest_apps_blob(root: &Path, pod: &str, gen: u64, pkg: &str, app: &str) -> String {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root, pod)
                .join("generations")
                .join(gen.to_string())
                .join("manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    manifest["packages"][pkg]["apps"][app]
        .as_str()
        .expect("manifest must record the app's store content")
        .to_string()
}

fn blob_path(root: &Path, pod: &str, hash: &str) -> PathBuf {
    pod_dir(root, pod).join("store").join(&hash[..2]).join(hash)
}

gated_test!(
    gc_prunes_unreferenced_generations_and_frees_exclusive_blobs,
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let port = serve_dir(server.path());
        make_tarball(server.path(), "hello");
        make_tarball(server.path(), "other");
        write_pkg(
            project.path(),
            "hello",
            "hello",
            "hello",
            "pod-hello-ran",
            port,
            "hello.tar.gz",
        );
        write_pkg(
            project.path(),
            "other",
            "otool",
            "otool",
            "pod-other-ran",
            port,
            "other.tar.gz",
        );

        // gen1: hello. gen2: hello+other. gen3: other (hello removed).
        // gen4: other + hello rebuilt with NEW content (re-added at a new
        // version) — so the old hello binary blob is exclusive to the
        // generations GC will prune.
        let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let (code, _, stderr) = run(project.path(), root.path(), &["add", "other"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let (code, _, stderr) = run(project.path(), root.path(), &["remove", "hello"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        write_pkg_version(
            project.path(),
            "hello",
            "hello",
            "hello",
            "14.2",
            "pod-hello-2-ran",
            port,
            "hello.tar.gz",
        );
        let (code, _, stderr) = run(project.path(), root.path(), &["add", "hello@14"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(generation_count(root.path(), "default"), 4);

        // The old hello binary blob: exclusive to gens 1+2 (pruned).
        let old_blob = manifest_apps_blob(root.path(), "default", 1, "hello", "hello");
        // The new hello + other blobs: referenced by live gens 3+4.
        let new_blob = manifest_apps_blob(root.path(), "default", 4, "hello", "hello");
        let other_blob = manifest_apps_blob(root.path(), "default", 3, "other", "otool");
        assert_ne!(old_blob, new_blob, "fixture must produce distinct content");
        assert!(blob_path(root.path(), "default", &old_blob).exists());
        assert!(blob_path(root.path(), "default", &new_blob).exists());
        assert!(blob_path(root.path(), "default", &other_blob).exists());

        // GC without --prune sweeps nothing: every blob is still
        // referenced by some generation manifest.
        let (code, _, stderr) = run(project.path(), root.path(), &["gc"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(generation_count(root.path(), "default"), 4);
        assert!(
            blob_path(root.path(), "default", &old_blob).exists(),
            "no-prune gc must keep referenced blobs"
        );

        // --prune drops gens 1+2 (beyond current + previous); the old
        // hello blob — exclusive to the pruned set — sweeps free, while
        // blobs of the live generations survive. Farm/current untouched.
        let (code, _, stderr) = run(project.path(), root.path(), &["gc", "--prune"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            stderr.contains("pruned generation(s): 1, 2"),
            "gc --prune must report the pruned generations: {stderr}"
        );
        assert_eq!(
            generation_count(root.path(), "default"),
            2,
            "current + previous survive"
        );
        assert_eq!(current_generation(root.path(), "default"), 4);
        let farm = current_farm(root.path(), "default");
        assert!(farm.join("hello").exists(), "live content stays exposed");
        assert!(farm.join("otool").exists());
        assert!(
            !blob_path(root.path(), "default", &old_blob).exists(),
            "exclusive blobs of the pruned generations must be freed: {old_blob}"
        );
        assert!(
            blob_path(root.path(), "default", &new_blob).exists(),
            "live content must survive"
        );
        assert!(
            blob_path(root.path(), "default", &other_blob).exists(),
            "blobs shared with live generations must survive"
        );
    }
);
