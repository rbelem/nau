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
///
/// `SHUTTLE_SERVICE_BACKEND=systemd` pins the service backend (ADR-0032
/// Decision 11 fail-closed selection); `XDG_CONFIG_HOME` redirects the
/// systemd user unit dir the emitter links enabled services into. Both
/// tempdirs live under the test root — never the real home.
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
    cmd.env("SHUTTLE_SERVICE_BACKEND", "systemd");
    cmd.env("XDG_CONFIG_HOME", root.join("config-home"));
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

// ── Issue #106: the generation manifest records the declaration, the
// emitter writes units.json + the unit artifact, and the user-level link
// follows `enabled` — dormant by default, explicit to enable, and
// rollback-revertible from the recorded units alone. ──

fn unit_link(root: &Path, pod: &str, svc: &str) -> PathBuf {
    root.join("config-home")
        .join("systemd")
        .join("user")
        .join(format!("shuttle-pod-{pod}-{svc}.service"))
}

fn services_dir(root: &Path, pod: &str, gen: u64) -> PathBuf {
    pod_dir(root, pod)
        .join("generations")
        .join(gen.to_string())
        .join("services")
}

fn set_override(root: &Path, pod: &str, override_lua: &str) {
    let decl_path = pod_dir(root, pod).join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        "packages = { \"svc-a\" },",
        &format!("packages = {{ \"svc-a\" }},\n    services = {{ {override_lua} }},"),
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();
}
gated_test!(service_unit_is_recorded_and_artifact_is_emitted_disabled, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");

    // The manifest records the declaration + the command blob hash (the
    // farm-link source).
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
    let svc = &manifest["packages"]["svc-a"]["services"]["dup-svc"];
    assert_eq!(svc["command"], "bin/svc-a", "the decl is recorded");
    assert_eq!(svc["daemon"], "simple");
    let bins = &manifest["packages"]["svc-a"]["service_bins"]["dup-svc"];
    assert!(
        bins.as_str().map(|h| h.len() == 64).unwrap_or(false),
        "service_bins records the command blob sha256: {bins}"
    );

    // units.json exists and the generation services/ dir holds the unit
    // file — but `enabled = false` (the package default) means NO
    // user-level link.
    let units_path = services_dir(root.path(), "default", 1).join("units.json");
    assert!(units_path.exists(), "units.json must exist");
    let units: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&units_path).unwrap()).unwrap();
    assert_eq!(units["units"][0]["name"], "dup-svc");
    assert_eq!(units["units"][0]["enabled"], false);
    assert!(units["units"][0]["text"]
        .as_str()
        .map(|t| t.contains("ExecStart=") && t.contains("WantedBy=default.target"))
        .unwrap_or(false));
    assert!(
        services_dir(root.path(), "default", 1)
            .join("shuttle-pod-default-dup-svc.service")
            .exists(),
        "the unit artifact is emitted inside the generation"
    );
    // The service's command binary rides the farm: a flat
    // `current/<svc>` link, exactly like an app binary.
    let farm_link = pod_dir(root.path(), "default")
        .join("current")
        .join("dup-svc");
    assert!(
        farm_link.exists(),
        "the service command binary must be farm-linked through current"
    );
    assert!(
        !unit_link(root.path(), "default", "dup-svc").exists(),
        "enabled = false must withhold the user-level link"
    );
});

gated_test!(pod_override_enablement_places_the_user_link, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");
    assert!(!unit_link(root.path(), "default", "dup-svc").exists());

    // Enable explicitly from the pod declaration: after sync the user
    // link appears, ExecStart baked through `current` (the flip seam).
    set_override(root.path(), "default", "[\"dup-svc\"] = { enabled = true }");
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "sync failed: {stderr}");

    let link = unit_link(root.path(), "default", "dup-svc");
    assert!(link.exists(), "an enabled service gets its user link");
    let text = std::fs::read_to_string(&link).unwrap();
    let current = pod_dir(root.path(), "default").join("current");
    assert!(
        text.contains(&format!("ExecStart='{}/dup-svc'", current.display())),
        "ExecStart must bake the absolute farm path through current: {text}"
    );
});

gated_test!(rollback_re_emits_the_target_generation_link_set, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    write_service_pkg(project.path(), "svc-a", "dup-svc", "a-ran", port);
    make_tarball(server.path(), "svc-a");
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-a"]);
    assert_eq!(code, Some(0), "svc-a add failed: {stderr}");

    // Gen 1 (re-)presented with the service ENABLED: link present.
    set_override(root.path(), "default", "[\"dup-svc\"] = { enabled = true }");
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "sync failed: {stderr}");
    assert!(unit_link(root.path(), "default", "dup-svc").exists());

    // Gen 2: flip enablement to false AND add a second package (a
    // generation-changing edit). Presenting gen 2 withdraws the link.
    write_service_pkg(project.path(), "svc-b", "other-svc", "b-ran", port);
    make_tarball(server.path(), "svc-b");
    let decl_path = pod_dir(root.path(), "default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        "enabled = true }",
        "enabled = false }, [\"other-svc\"] = { enabled = true }",
    );
    assert_ne!(edited, decl, "fixture must match");
    std::fs::write(&decl_path, &edited).unwrap();
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "svc-b"]);
    assert_eq!(code, Some(0), "svc-b add failed: {stderr}");
    assert_eq!(generation_count(root.path(), "default"), 2);
    assert!(
        !unit_link(root.path(), "default", "dup-svc").exists(),
        "presenting gen 2 (disabled) withdraws the link"
    );
    assert!(
        unit_link(root.path(), "default", "other-svc").exists(),
        "gen 2's other enabled service is linked"
    );

    // Rollback to gen 1: the link set is re-emitted from gen 1's
    // RECORDED units.json — enabled there, so the link comes back with
    // no follow-up sync. (Restarting the running daemon on the flip is
    // ticket #107.)
    let (code, _, stderr) = run(project.path(), root.path(), &["rollback", "1"]);
    assert_eq!(code, Some(0), "rollback failed: {stderr}");
    assert!(
        unit_link(root.path(), "default", "dup-svc").exists(),
        "rollback re-emits gen 1's recorded enabled link"
    );
    assert!(
        !unit_link(root.path(), "default", "other-svc").exists(),
        "rollback withdraws links gen 1 does not own"
    );

    // Forward again: gen 2's recorded link set is restored.
    let (code, _, stderr) = run(project.path(), root.path(), &["rollback", "2"]);
    assert_eq!(code, Some(0), "forward rollback failed: {stderr}");
    assert!(
        !unit_link(root.path(), "default", "dup-svc").exists(),
        "gen 2 recorded dup-svc disabled — the link disappears"
    );
    assert!(unit_link(root.path(), "default", "other-svc").exists());
});
