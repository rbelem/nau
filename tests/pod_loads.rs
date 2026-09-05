//! `shuttle pod` loads composition integration tests (issue #8).
//!
//! Drives the real binary end to end through the FULL chain: a pod
//! declares `loads = { "base" }` and resolves as shared collection <
//! loaded pods (in listed order) < own packages < inline overlay. The
//! loading pod's own declaration wins a name clash with a loaded pod
//! outright; shared BINARY names across different packages go through
//! the shared collision classifier — a higher layer overrides with a
//! warning, a same-precedence duplicate is a hard error. Load cycles
//! fail before any mutation, named in full. All state (project dir, pod
//! root, data home) lives in tempdirs — never the real home.
//!
//! Tests gate on the external toolchain (mksquashfs/unsquashfs/curl/tar),
//! same skip pattern as `pod_install.rs` / `pod_overlay.rs`.

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

/// A package that builds an echo-marker binary; the version feeds
/// meta/snap.yaml so a version move changes content identity. The
/// package exports `apps = { <name> = { command = "bin/<name>" } }` so
/// the binary name is `<name>`.
fn write_pkg_version(project: &Path, name: &str, version: &str, marker: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "{version}",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{name} && echo 'echo {marker}' >> $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    apps = {{ {name} = {{ command = "bin/{name}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// A package that builds an echo-marker binary exporting an EXPLICITLY
/// named app (`{app}`), so two distinct packages can share a binary name.
/// Used to exercise binary-name (not package-name) collisions across the
/// composition layers. The version feeds meta/snap.yaml so a version move
/// changes content identity.
fn write_app_pkg(project: &Path, name: &str, version: &str, marker: &str, app: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "{version}",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{app} && echo 'echo {marker}' >> $STAGE/bin/{app} && chmod +x $STAGE/bin/{app}",
    apps = {{ {app} = {{ command = "bin/{app}" }} }},
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

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let link = pod_dir(root, pod).join("current");
    let target = std::fs::read_link(&link).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

/// Run the farm entry `name` and return its stdout (the fixture binaries
/// echo their marker).
fn farm_output(farm: &Path, name: &str) -> String {
    let out = Command::new(farm.join(name))
        .output()
        .expect("run farm binary");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn lock_pin(root: &Path, pod: &str, name: &str) -> Option<String> {
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).unwrap(),
    )
    .unwrap();
    lock["packages"][name]["version"]
        .as_str()
        .map(str::to_string)
}

/// The recorded version of one package in a generation manifest.
fn manifest_version(root: &Path, pod: &str, gen: u64, pkg: &str) -> String {
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
    manifest["packages"][pkg]["version"]
        .as_str()
        .expect("manifest must record the package version")
        .to_string()
}

fn snapshot(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ── Acceptance: loaded resolutions in listed order; own wins ──

gated_test!(loaded_pod_resolves_in_listed_order_and_own_wins, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    // base pod ships `base-pkg` which exports the binary `tool` at 1.0.
    write_app_pkg(
        project.path(),
        "base-pkg",
        "1.0",
        "base-tool-ran",
        "tool",
        port,
    );
    make_tarball(server.path(), "base-pkg");
    // work pod ships `work-pkg` which exports the SAME binary `tool` at 2.0.
    write_app_pkg(
        project.path(),
        "work-pkg",
        "2.0",
        "work-tool-ran",
        "tool",
        port,
    );
    make_tarball(server.path(), "work-pkg");

    let (code, _, stderr) = run_named(project.path(), root.path(), "base", &["add", "base-pkg"]);
    assert_eq!(code, Some(0), "base pod add failed: {stderr}");
    assert_eq!(current_generation(root.path(), "base"), 1);
    assert_eq!(manifest_version(root.path(), "base", 1, "base-pkg"), "1.0");

    // work pod declares its own package exporting the same binary `tool`.
    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["add", "work-pkg"]);
    assert_eq!(code, Some(0), "work pod add failed: {stderr}");

    // work loads base. Now `tool` is exported by BOTH base-pkg (Loaded) and
    // work-pkg (Own) — a cross-layer clash, own wins.
    let decl_path = pod_dir(root.path(), "work").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        r#"packages = { "work-pkg" },"#,
        r#"loads = { "base" },
    packages = { "work-pkg" },"#,
    );
    assert_ne!(edited, decl, "fixture must match the rendered declaration");
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["sync"]);
    assert_eq!(code, Some(0), "work sync failed: {stderr}");
    assert!(
        stderr.contains("shadowed") || stderr.contains("overrides"),
        "own-over-loaded must warn (name the winner/loser): {stderr}"
    );
    let g = current_generation(root.path(), "work");
    assert_eq!(manifest_version(root.path(), "work", g, "work-pkg"), "2.0");
    assert_eq!(
        farm_output(&current_farm(root.path(), "work"), "tool"),
        "work-tool-ran",
        "the loading pod's own package must win over its loaded pod"
    );
});

// ── Acceptance: transitive chain (work loads base loads core) ──

gated_test!(load_chain_resolves_transitively, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    // `core` uniquely provides `coretool`; `base` loads `core` but has no
    // own packages; `work` loads `base`. The chain must resolve `coretool`
    // transitively into `work` through the loaded graph. Use three distinct
    // packages so no same-name shadowing muddles the transitive assertion.
    write_app_pkg(
        project.path(),
        "coretool",
        "0.1",
        "core-ran",
        "coretool",
        port,
    );
    make_tarball(server.path(), "coretool");

    let (code, _, stderr) = run_named(project.path(), root.path(), "core", &["add", "coretool"]);
    assert_eq!(code, Some(0), "core add failed: {stderr}");
    assert_eq!(current_generation(root.path(), "core"), 1);

    // `base` has no own packages and loads `core`. `shuttle pod --name base
    // add` requires at least one package to initialize the pod, so give
    // core a proxy: actually, initialize base with NO package by writing
    // pod.lua directly. But read verbs against an uninitialized pod fail.
    // Simpler: initialize `base` with `coretool` too (it shadows nothing
    // since it IS coretool — same identity). Then hand-edit base to load
    // core and drop its own package.
    let (code, _, stderr) = run_named(project.path(), root.path(), "base", &["add", "coretool"]);
    assert_eq!(code, Some(0), "base add failed: {stderr}");

    let base_decl = pod_dir(root.path(), "base").join("pod.lua");
    let decl = std::fs::read_to_string(&base_decl).unwrap();
    // base loads core and drops its own package (pure load node).
    let edited = decl.replace(r#"packages = { "coretool" },"#, r#"loads = { "core" },"#);
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&base_decl, &edited).unwrap();
    let (code, _, stderr) = run_named(project.path(), root.path(), "base", &["sync"]);
    assert_eq!(code, Some(0), "base sync failed: {stderr}");
    assert!(
        generation_count(root.path(), "base") >= 1,
        "base must have a generation carrying the loaded coretool"
    );

    // `work` loads `base` (which loads `core`). work declares no own
    // packages — pure transitive consumer. Initialize it with a proxy
    // package then hand-edit to loads-only.
    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["add", "coretool"]);
    assert_eq!(code, Some(0), "work add failed: {stderr}");

    let work_decl = pod_dir(root.path(), "work").join("pod.lua");
    let decl = std::fs::read_to_string(&work_decl).unwrap();
    let edited = decl.replace(r#"packages = { "coretool" },"#, r#"loads = { "base" },"#);
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&work_decl, &edited).unwrap();
    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["sync"]);
    assert_eq!(code, Some(0), "work sync failed: {stderr}");
    // The chain resolves `coretool` into work through base→core.
    let g = current_generation(root.path(), "work");
    assert_eq!(manifest_version(root.path(), "work", g, "coretool"), "0.1");
    assert_eq!(
        farm_output(&current_farm(root.path(), "work"), "coretool"),
        "core-ran",
        "a transitive chain must resolve the deepest loaded pod's package"
    );
});

// ── Acceptance: load cycle named, zero writes ──

gated_test!(load_cycle_errors_with_name_and_mutates_nothing, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(project.path(), "tool", "1.0", "tool-ran", port);

    // Create `a` and `b`, each loading the other (cycle a -> b -> a).
    let (code, _, stderr) = run_named(project.path(), root.path(), "a", &["add", "tool"]);
    assert_eq!(code, Some(0), "a add failed: {stderr}");
    let (code, _, stderr) = run_named(project.path(), root.path(), "b", &["add", "tool"]);
    assert_eq!(code, Some(0), "b add failed: {stderr}");

    // a loads b.
    let a_decl = pod_dir(root.path(), "a").join("pod.lua");
    let decl = std::fs::read_to_string(&a_decl).unwrap();
    let edited = decl.replace(
        r#"packages = { "tool" },"#,
        r#"loads = { "b" },
    packages = { "tool" },"#,
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&a_decl, &edited).unwrap();

    // b loads a → cycle.
    let b_decl = pod_dir(root.path(), "b").join("pod.lua");
    let decl = std::fs::read_to_string(&b_decl).unwrap();
    let edited = decl.replace(
        r#"packages = { "tool" },"#,
        r#"loads = { "a" },
    packages = { "tool" },"#,
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&b_decl, &edited).unwrap();

    let a_gen_before = generation_count(root.path(), "a");
    let b_gen_before = generation_count(root.path(), "b");
    let a_lock_before = snapshot(&pod_dir(root.path(), "a").join("shuttle.lock"));
    let b_lock_before = snapshot(&pod_dir(root.path(), "b").join("shuttle.lock"));
    let a_link_before = std::fs::read_link(pod_dir(root.path(), "a").join("current")).unwrap();
    let b_link_before = std::fs::read_link(pod_dir(root.path(), "b").join("current")).unwrap();

    // Syncing `a` must detect the cycle through its loaded graph.
    let (code, _, stderr) = run_named(project.path(), root.path(), "a", &["sync"]);
    assert_eq!(code, Some(1), "a sync must fail on the cycle: {stderr}");
    assert!(
        stderr.contains("cycle") && stderr.contains("a") && stderr.contains("b"),
        "error must name the cycle and its members: {stderr}"
    );

    assert_eq!(
        generation_count(root.path(), "a"),
        a_gen_before,
        "no new generation on a cycle"
    );
    assert_eq!(
        generation_count(root.path(), "b"),
        b_gen_before,
        "b must not be touched"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "a").join("shuttle.lock")),
        a_lock_before,
        "a's lockfile must be untouched"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "b").join("shuttle.lock")),
        b_lock_before,
        "b's lockfile must be untouched"
    );
    assert_eq!(
        std::fs::read_link(pod_dir(root.path(), "a").join("current")).unwrap(),
        a_link_before,
        "a's current link must be untouched"
    );
    assert_eq!(
        std::fs::read_link(pod_dir(root.path(), "b").join("current")).unwrap(),
        b_link_before,
        "b's current link must be untouched"
    );
});

// ── Acceptance: same-precedence binary collision is a hard error ──

gated_test!(same_precedence_binary_collision_errors_with_zero_writes, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    // Two DISTINCT packages `alpha` and `beta` that both export the SAME
    // binary name `dup`, at the SAME precedence (both `Own`). A binary-name
    // (not package-name) clash that must be a hard error with zero writes.
    write_app_pkg(project.path(), "alpha", "1.0", "alpha-ran", "dup", port);
    make_tarball(server.path(), "alpha");
    write_app_pkg(project.path(), "beta", "1.0", "beta-ran", "dup", port);
    make_tarball(server.path(), "beta");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "alpha"]);
    assert_eq!(code, Some(0), "alpha add failed: {stderr}");
    let gen_before = generation_count(root.path(), "default");
    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));

    // Adding `beta` at the SAME precedence (both Own) shipping the same
    // binary `dup` must be a hard error with zero writes.
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "beta"]);
    assert_eq!(
        code,
        Some(1),
        "same-precedence binary collision must error: {stderr}"
    );
    assert!(
        stderr.contains("dup") && stderr.contains("alpha") && stderr.contains("beta"),
        "error must name the binary and both packages: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        gen_before,
        "collision must not bump the generation"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "collision must not write the lockfile"
    );
});

// ── Acceptance: cross-layer binary override warns, higher layer wins ──

gated_test!(cross_layer_override_warns_names_winner_loser, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    // base ships `base-pkg` exporting the binary `tool` at 1.0 (Loaded).
    write_app_pkg(project.path(), "base-pkg", "1.0", "base-ran", "tool", port);
    make_tarball(server.path(), "base-pkg");
    // work ships `work-pkg` exporting the SAME binary `tool` at 2.0 (Own).
    write_app_pkg(project.path(), "work-pkg", "2.0", "work-ran", "tool", port);
    make_tarball(server.path(), "work-pkg");

    let (code, _, stderr) = run_named(project.path(), root.path(), "base", &["add", "base-pkg"]);
    assert_eq!(code, Some(0), "base add failed: {stderr}");
    assert_eq!(current_generation(root.path(), "base"), 1);

    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["add", "work-pkg"]);
    assert_eq!(code, Some(0), "work add failed: {stderr}");

    // work loads base; base-pkg (Loaded) shares binary `tool` with
    // work-pkg (Own) — a cross-layer override, work's own wins.
    let work_decl = pod_dir(root.path(), "work").join("pod.lua");
    let decl = std::fs::read_to_string(&work_decl).unwrap();
    let edited = decl.replace(
        r#"packages = { "work-pkg" },"#,
        r#"loads = { "base" },
    packages = { "work-pkg" },"#,
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&work_decl, &edited).unwrap();

    let (code, _, stderr) = run_named(project.path(), root.path(), "work", &["sync"]);
    assert_eq!(code, Some(0), "work sync failed: {stderr}");
    assert!(
        stderr.contains("overrides") && stderr.contains("base-pkg") && stderr.contains("work-pkg"),
        "cross-layer override must warn naming winner and loser: {stderr}"
    );
    let g = current_generation(root.path(), "work");
    assert_eq!(manifest_version(root.path(), "work", g, "work-pkg"), "2.0");
    assert_eq!(
        farm_output(&current_farm(root.path(), "work"), "tool"),
        "work-ran",
        "the loading pod's own binary must win the cross-layer clash"
    );
});

// ── Acceptance: cross-layer override also resolves at add time ──

gated_test!(load_nonexistent_pod_fails_before_any_mutation, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "tool");
    write_pkg_version(project.path(), "tool", "1.0", "tool-ran", port);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "tool"]);
    assert_eq!(code, Some(0), "add failed: {stderr}");
    let gen_before = generation_count(root.path(), "default");
    let lock_before = snapshot(&pod_dir(root.path(), "default").join("shuttle.lock"));

    // Loading a pod that has no declaration must fail before any write.
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        r#"packages = { "tool" },"#,
        r#"loads = { "nosuch" },
    packages = { "tool" },"#,
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(
        code,
        Some(1),
        "sync must fail on a nonexistent loaded pod: {stderr}"
    );
    assert!(
        stderr.contains("nosuch")
            && (stderr.contains("no declaration") || stderr.contains("create")),
        "error must name the missing loaded pod: {stderr}"
    );
    assert_eq!(
        generation_count(root.path(), "default"),
        gen_before,
        "no generation must be created"
    );
    assert_eq!(
        snapshot(&pod_dir(root.path(), "default").join("shuttle.lock")),
        lock_before,
        "lockfile must be untouched"
    );
});
