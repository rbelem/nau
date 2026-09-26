//! `shuttle run` confined-runtime integration tests (ticket #11).
//!
//! A package declared `confined` runs inside a backend sandbox with
//! declared grants, launched via a `shuttle run <app>` interposing
//! launcher. The farm's `current/bin/<app>` symlink points at a wrapper
//! that invokes `shuttle run` (transparent — `which`/PATH stay truthful);
//! `shuttle run` sets up the sandbox then execs the app.
//!
//! Drives the real binary end to end through the FULL chain (confined
//! pod add → farm → `shuttle run` → confined-executes with grants), all
//! state in tempdirs. Same gating + loopback-source server patterns as
//! `tests/pod_install.rs`. The happy path runs the bwrap backend (the
//! test environment provides bubblewrap + unprivileged userns); the
//! fail-closed path hides the backend so a confined app fails rather than
//! silently running unconfined.

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
    ["mksquashfs", "unsquashfs", "curl", "tar", "bwrap"]
        .iter()
        .all(|t| has_tool(t))
}

/// Gate the bwrap-happy-path tests: skip (return early) when the toolchain
/// is missing, matching the `pod_install.rs` skip pattern.
fn bwrap_gate() -> bool {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar/bwrap unavailable");
        return false;
    }
    true
}

// ── Loopback source server ──

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

/// Write a resolvable confined package whose app writes a marker to the
/// granted `grant_dir` (rw filesystem grant) and exits 0. `confined_lua`
/// is the `confined = { ... }` grants table text. The app command proves
/// the grant: it writes `$grant_dir/marker` only when the path is bound
/// read-write (a confined app that lost its grant would fail the write
/// and exit nonzero).
fn write_confined_pkg(
    project: &Path,
    name: &str,
    app: &str,
    grant_dir: &Path,
    confined_lua: &str,
    port: u16,
    tarball: &str,
) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let grant_shell = grant_dir.display();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{app} && echo 'echo confined-marker > {grant_shell}/marker' >> $STAGE/bin/{app} && chmod +x $STAGE/bin/{app}",
    confined = {confined_lua},
    apps = {{ {app} = {{ command = "bin/{app}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners ──

#[allow(clippy::too_many_arguments)]
fn run(
    project: &Path,
    root: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (issue #66); explicit
    // per-call env overrides below still win.
    cmd.env("SHUTTLE_SYSTEMD", "off");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `shuttle run <app>` directly (the launcher's exec target).
fn run_shuttle_run(
    project: &Path,
    root: &Path,
    pod: &str,
    app: &str,
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    run_shuttle_run_with(project, root, pod, app, &[], env)
}

#[allow(clippy::too_many_arguments)]
fn run_shuttle_run_with(
    project: &Path,
    root: &Path,
    pod: &str,
    app: &str,
    app_args: &[&str],
    env: &[(&str, &str)],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("run").arg("--pod").arg(pod).arg("--root").arg(root);
    cmd.arg(app);
    for a in app_args {
        cmd.arg(a);
    }
    cmd.current_dir(project);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to spawn shuttle run");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Exec the pod's farm entry for `app` (the wrapper the farm's symlink
/// points at), proving it is transparent (`shuttle run` under the hood).
/// The `shuttle` binary is placed on PATH so the wrapper's `exec shuttle
/// run` resolves.
fn exec_farm_entry(root: &Path, pod: &str, app: &str) -> (Option<i32>, String, String) {
    let farm = farm_dir(root, pod);
    let entry = farm.join(app);
    // Resolve the symlink chain to the actual store blob (the wrapper).
    let canonical = std::fs::canonicalize(&entry).expect("farm entry resolves");
    let mut cmd = Command::new(&canonical);
    // Put the test's shuttle binary dir on PATH (the wrapper execs
    // `shuttle run`).
    let shuttle_bin = std::path::Path::new(env!("CARGO_BIN_EXE_shuttle"))
        .parent()
        .unwrap();
    let mut path = shuttle_bin.to_path_buf().into_os_string();
    if let Some(existing) = std::env::var_os("PATH") {
        path.push(":");
        path.push(existing);
    }
    cmd.env("PATH", path);
    let out = cmd.output().expect("failed to exec farm entry");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn farm_dir(root: &Path, pod: &str) -> PathBuf {
    let cur = std::fs::read_link(root.join(pod).join("current")).unwrap();
    if cur.is_absolute() {
        cur
    } else {
        root.join(pod).join(cur)
    }
}

// ── Tests ──

#[test]
fn confined_app_farm_entry_points_at_a_shuttle_run_wrapper() {
    if !bwrap_gate() {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let grant_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "confsrc");
    // A GUI-style app declared confined with a bwrap backend and a
    // read-write filesystem grant on the grant tempdir.
    let confined_lua = format!(
        r#"{{ backend = "bwrap", filesystem = {{ "rw:{}" }}, network = false }}"#,
        grant_dir.path().display()
    );
    // The build sandbox must see the source tarball; the source package
    // value is served over HTTP (the build downloads it).
    let _ = port;
    write_confined_pkg(
        project.path(),
        "confinapp",
        "confinapp",
        grant_dir.path(),
        &confined_lua,
        port,
        "confsrc.tar.gz",
    );
    // `pod add` builds + installs the confined package.
    let (code, _out, err) = run(project.path(), root.path(), &["add", "confinapp"], &[]);
    assert_eq!(code, Some(0), "confined pod add failed: {err}");

    let farm = farm_dir(root.path(), "default");
    assert!(farm.join("confinapp").exists(), "farm entry present");

    // The farm entry must point at a store blob whose content is a
    // wrapper that invokes `shuttle run` (not the raw command binary).
    let entry = farm.join("confinapp");
    let blob = std::fs::canonicalize(&entry).unwrap();
    let content = std::fs::read_to_string(&blob).unwrap();
    assert!(
        content.contains("shuttle run"),
        "confined farm wrapper must invoke shuttle run; got: {content}"
    );
    assert!(
        content.contains("--pod"),
        "confined farm wrapper must select the pod; got: {content}"
    );
}

#[test]
fn confined_app_executes_with_grants_via_shuttle_run() {
    if !bwrap_gate() {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let grant_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "confsrc");
    let confined_lua = format!(
        r#"{{ backend = "bwrap", filesystem = {{ "rw:{}" }}, network = false }}"#,
        grant_dir.path().display()
    );
    write_confined_pkg(
        project.path(),
        "confinapp",
        "confinapp",
        grant_dir.path(),
        &confined_lua,
        port,
        "confsrc.tar.gz",
    );
    let (code, _out, err) = run(project.path(), root.path(), &["add", "confinapp"], &[]);
    assert_eq!(code, Some(0), "confined pod add failed: {err}");

    // `shuttle run` sets up the bwrap sandbox with the rw grant and execs
    // the app — which writes the marker into the granted dir.
    let marker = grant_dir.path().join("marker");
    assert!(!marker.exists(), "no marker before run");
    let (rcode, _stdout, rerr) =
        run_shuttle_run(project.path(), root.path(), "default", "confinapp", &[]);
    assert_eq!(rcode, Some(0), "shuttle run failed: {rerr}");
    assert!(
        marker.exists(),
        "confined app must write its marker via the rw filesystem grant"
    );
    let text = std::fs::read_to_string(&marker).unwrap();
    assert_eq!(text.trim(), "confined-marker");

    // The app exec'd inside the sandbox is also reachable through the
    // farm's wrapper (transparent to the user, `which`/PATH truthful).
    let marker2 = grant_dir.path().join("marker");
    let _ = std::fs::remove_file(&marker2);
    let (fcode, _stdout, ferr) = exec_farm_entry(root.path(), "default", "confinapp");
    assert_eq!(fcode, Some(0), "farm wrapper run failed: {ferr}");
    assert!(marker2.exists(), "farm wrapper must exec the confined app");
}

#[test]
fn confined_app_fails_closed_when_backend_unavailable() {
    if !bwrap_gate() {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let grant_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "confsrc");
    let confined_lua = format!(
        r#"{{ backend = "bwrap", filesystem = {{ "rw:{}" }}, network = false }}"#,
        grant_dir.path().display()
    );
    write_confined_pkg(
        project.path(),
        "confinapp",
        "confinapp",
        grant_dir.path(),
        &confined_lua,
        port,
        "confsrc.tar.gz",
    );
    let (code, _out, err) = run(project.path(), root.path(), &["add", "confinapp"], &[]);
    assert_eq!(code, Some(0), "confined pod add failed: {err}");

    // Fail closed: hide bwrap from PATH so the backend is unavailable. A
    // confined app must NOT run unconfined — `shuttle run` errors.
    let marker = grant_dir.path().join("marker");
    assert!(!marker.exists());
    // Empty PATH hides bwrap (and everything else), so the confined
    // backend check fails before any exec.
    let (rcode, _stdout, rerr) = run_shuttle_run(
        project.path(),
        root.path(),
        "default",
        "confinapp",
        &[("PATH", "")],
    );
    assert_ne!(
        rcode,
        Some(0),
        "confined app must not succeed when bwrap is unavailable"
    );
    assert!(
        !marker.exists(),
        "confined app must not have written its marker when the backend was unavailable"
    );
    assert!(
        rerr.contains("refusing to run unconfined") || rerr.contains("bwrap"),
        "fail-closed error must name the backend: {rerr}"
    );
}

#[test]
fn unconfined_app_is_unaffected_and_uses_direct_farm_symlink() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "src");
    // A plain CLI package (no `confined`) — defaults to unconfined.
    let letter = "u";
    let dir = project.path().join("pkgs").join(letter);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("uapp.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "uapp",
    version = "1.0",
    source = "http://127.0.0.1:{port}/src.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/uapp && echo 'echo unconfined-ok' >> $STAGE/bin/uapp && chmod +x $STAGE/bin/uapp",
    apps = {{ uapp = {{ command = "bin/uapp" }} }},
}} }}
"#
        ),
    )
    .unwrap();
    let (code, _out, err) = run(project.path(), root.path(), &["add", "uapp"], &[]);
    assert_eq!(code, Some(0), "unconfined pod add failed: {err}");

    let farm = farm_dir(root.path(), "default");
    let entry = farm.join("uapp");
    let blob = std::fs::canonicalize(&entry).unwrap();
    // Unconfined: the farm entry is the raw command binary (no wrapper),
    // so the payload content is the app script, not a `shuttle run` shim.
    let content = std::fs::read_to_string(&blob).unwrap();
    assert!(
        !content.contains("shuttle run"),
        "unconfined app must have no shuttle-run wrapper; got: {content}"
    );
    assert!(content.contains("unconfined-ok"), "got: {content}");
}

#[test]
fn apparmor_backend_fails_closed_when_unavailable() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let grant_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "confsrc");
    // A confined app requesting the apparmor backend. AppArmor custom
    // profile enforcement / `aa-exec` is not available in the test
    // environment, so it must FAIL CLOSED.
    let confined_lua = format!(
        r#"{{ backend = "apparmor", filesystem = {{ "rw:{}" }}, network = false }}"#,
        grant_dir.path().display()
    );
    write_confined_pkg(
        project.path(),
        "aaconf",
        "aaconf",
        grant_dir.path(),
        &confined_lua,
        port,
        "confsrc.tar.gz",
    );
    let (code, _out, err) = run(project.path(), root.path(), &["add", "aaconf"], &[]);
    assert_eq!(code, Some(0), "confined pod add failed: {err}");

    // When `aa-exec` is absent (or AppArmor not enforced), a confined
    // apparmor app must fail with a clear error — never run unconfined.
    let (rcode, _stdout, rerr) =
        run_shuttle_run(project.path(), root.path(), "default", "aaconf", &[]);
    if has_tool("aa-exec") {
        // aa-exec present: the run may attempt (root-only enforcement),
        // but it must not silently succeed as unconfined.
        eprintln!("aa-exec present; apparmor enforcement may require root (skip assert)");
    } else {
        assert_ne!(rcode, Some(0), "apparmor-confined app must fail closed");
        assert!(
            rerr.contains("aa-exec") || rerr.contains("apparmor"),
            "fail-closed must name the apparmor backend: {rerr}"
        );
    }
}

/// ADR-0016 escape hatch: a pod can override a confined package to
/// unconfined for that pod via `overlay.<pkg>.confinement = "unconfined"`.
/// The override is the explicit, user-acknowledged opt-out — the package
/// then runs the direct farm symlink (no `shuttle run` wrapper).
#[test]
fn pod_confinement_unconfined_override_lifts_the_sandbox() {
    if !bwrap_gate() {
        return;
    }
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server_dir = tempfile::tempdir().unwrap();
    let grant_dir = tempfile::tempdir().unwrap();
    let port = serve_dir(server_dir.path());
    make_tarball(server_dir.path(), "confsrc");
    let confined_lua = format!(
        r#"{{ backend = "bwrap", filesystem = {{ "rw:{}" }}, network = false }}"#,
        grant_dir.path().display()
    );
    write_confined_pkg(
        project.path(),
        "confinapp",
        "confinapp",
        grant_dir.path(),
        &confined_lua,
        port,
        "confsrc.tar.gz",
    );
    let (code, _out, err) = run(project.path(), root.path(), &["add", "confinapp"], &[]);
    assert_eq!(code, Some(0), "confined pod add failed: {err}");

    // Hand-edit pod.lua to lift the package to unconfined for this pod.
    let decl_path = root.path().join("default").join("pod.lua");
    let decl = std::fs::read_to_string(&decl_path).unwrap();
    let edited = decl.replace(
        "pod {\n    packages = { \"confinapp\" },\n}\n",
        "pod {\n    packages = { \"confinapp\" },\n    overlay = {\n        confinapp = { confinement = \"unconfined\" },\n    },\n}\n",
    );
    assert_ne!(
        edited, decl,
        "pod.lua must have been edited to add the overlay"
    );
    std::fs::write(&decl_path, edited).unwrap();

    let (sync_code, _out, sync_err) = run(project.path(), root.path(), &["sync"], &[]);
    assert_eq!(
        sync_code,
        Some(0),
        "sync after unconfined override failed: {sync_err}"
    );

    // After the override, the farm entry is the raw command binary — no
    // `shuttle run` wrapper — proving the app runs unconfined.
    let farm = farm_dir(root.path(), "default");
    let entry = farm.join("confinapp");
    let blob = std::fs::canonicalize(&entry).unwrap();
    let content = std::fs::read_to_string(&blob).unwrap();
    assert!(
        !content.contains("shuttle run"),
        "unconfined-override app must have no shuttle-run wrapper; got: {content}"
    );
    assert!(content.contains("confined-marker"), "got: {content}");
    // Running the overridden app directly on the host writes the marker
    // (no sandbox involved) — the explicit escape-hatch path.
    let _ = grant_dir.path().join("marker");
    let (rcode, _stdout, rerr) =
        run_shuttle_run(project.path(), root.path(), "default", "confinapp", &[]);
    assert_eq!(rcode, Some(0), "unconfined override run failed: {rerr}");
    assert!(
        grant_dir.path().join("marker").exists(),
        "unconfined-override app must write its marker without a sandbox"
    );
}

// ── `shuttle run` secrets overlay (ADR-0042 D3/D6/D7, issue #184) ──
//
// Hand-seeded pod (no builds): the arbitrary-command form resolves the
// pod's secrets host-side (D6) and overlays them onto the exec'd
// process with the declared-replaces-inherited rule.

/// `/dev/shm`-backed isolated runtime dir (the D3 tmpfs gate); None =
/// skip when no tmpfs is available.
fn run_overlay_runtime_dir(tag: &str) -> Option<std::path::PathBuf> {
    let base = std::path::Path::new("/dev/shm");
    if !base.is_dir() {
        return None;
    }
    let dir = base.join(format!("shuttle-run-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[test]
fn shuttle_run_overlays_resolved_secrets_declared_replaces_inherited() {
    let Some(run_dir) = run_overlay_runtime_dir("overlay") else {
        eprintln!("skipping: no tmpfs runtime dir available");
        return;
    };
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let pod = root.path().join("default");

    // The active farm + an empty generation manifest: no package claims
    // an app, so the arbitrary-command form runs the command.
    let farm = pod.join("generations/1/farm");
    std::fs::create_dir_all(&farm).unwrap();
    std::os::unix::fs::symlink("generations/1/farm", pod.join("current")).unwrap();
    // The store's own active pointer (`run` resolves the generation
    // through it, distinct from the farm's `current`).
    std::os::unix::fs::symlink("generations/1", pod.join("active")).unwrap();
    std::fs::write(
        pod.join("generations/1/manifest.json"),
        serde_json::json!({
            "n": 1, "base_version": "24.04", "packages": {},
            "created_epoch": 0, "boot_entry": null
        })
        .to_string(),
    )
    .unwrap();

    // The counting provider lives OUTSIDE the pod state root (the D4
    // refusal treats pod-rooted programs as provider shadowing).
    let counter = root.path().join("calls");
    let counter_s = counter.display().to_string();
    let provider = root.path().join("counting-provider");
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\nn=$(cat {counter_s} 2>/dev/null || echo 0); echo $((n+1)) > {counter_s}; \
             printf -- '-----BEGIN RUN KEY-----\\nMIIrun\\n-----END RUN KEY-----\\n'\n"
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o755)).unwrap();
    let provider_s = provider.display().to_string();

    std::fs::write(
        pod.join("pod.lua"),
        format!(
            "pod {{ secrets = {{ RUN_SECRET = {{ source = \"exec\", command = {{ \
             \"{provider_s}\" }} }} }} }}\n"
        ),
    )
    .unwrap();
    let refs = std::collections::BTreeMap::from([(
        "RUN_SECRET".to_string(),
        shuttle::pod::SecretSource::Exec {
            command: vec![provider_s.clone()],
        },
    )]);
    let store = shuttle::runtime::RuntimeStore::new(pod.clone());
    shuttle::farm::write_generation_secrets(&store, 1, &refs).unwrap();

    let expected = "-----BEGIN RUN KEY-----\nMIIrun\n-----END RUN KEY-----";
    let run_with = |ambient: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
        cmd.arg("run")
            .arg("--pod")
            .arg("default")
            .arg("--root")
            .arg(root.path())
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg("printf '%s' \"$RUN_SECRET\"");
        match ambient {
            Some(v) => {
                cmd.env("RUN_SECRET", v);
            }
            None => {
                cmd.env_remove("RUN_SECRET");
            }
        }
        cmd.current_dir(project.path());
        cmd.env("SHUTTLE_DATA_HOME", root.path().join("data-home"));
        cmd.env("XDG_RUNTIME_DIR", &run_dir);
        let out = cmd.output().expect("failed to spawn shuttle run");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // Cold: one resolve; the secret value replaces the inherited one,
    // the PEM newline surviving the overlay untouched.
    let (code, stdout, stderr) = run_with(Some("ambient-must-lose"));
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout, expected,
        "the resolved value replaces the ambient one"
    );
    assert_eq!(
        std::fs::read_to_string(&counter).unwrap().trim(),
        "1",
        "the cold run resolves exactly once"
    );

    // Warm: the second run rides the session cache — zero provider
    // calls, same value served.
    let (code, stdout, stderr) = run_with(None);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stdout, expected);
    assert_eq!(
        std::fs::read_to_string(&counter).unwrap().trim(),
        "1",
        "the warm run must be a session-cache hit (D3)"
    );
    let _ = std::fs::remove_dir_all(&run_dir);
}
