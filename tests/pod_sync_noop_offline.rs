//! `nau pod sync` no-op network elimination (issue #331).
//!
//! A fully-held sync — every package pinned, installed, and carried by
//! the active generation, own packages and loaded-subpod contributions
//! alike — must make ZERO network calls: a held pin IS the resolution,
//! so there is nothing to resolve and nowhere to probe. The measurement
//! seam is a counting `curl` shim prepended to PATH: every curl
//! invocation the sync spawns (store routes, source fetches, anything)
//! is logged; the fully-held sync must log nothing.
//!
//! Drives the real binary end to end: the first sync builds the
//! packages over a loopback HTTP server (the only network the test
//! allows), the second sync is the no-op under the shim. All state
//! (project dir, pod root, data home) lives in tempdirs — never the
//! real home. Gated on the external toolchain (mksquashfs/unsquashfs/
//! curl/tar), same skip pattern as `pod_install.rs`.

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
/// meta/snap.yaml, so the freshly built generation stamps the digest
/// the no-op sync's content hold compares against.
fn write_pkg(project: &Path, name: &str, marker: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{name}.tar.gz",
    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{name} && echo 'echo {marker}' >> $STAGE/bin/{name} && chmod +x $STAGE/bin/{name}",
    apps = {{ {name} = {{ command = "bin/{name}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

fn write_pod_lua(root: &Path, pod: &str, body: &str) {
    let dir = root.join(pod);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pod.lua"), format!("pod {{\n{body}}}\n")).unwrap();
}

// ── Runners ──

fn run(project: &Path, root: &Path, pod: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nau"));
    cmd.arg("pod");
    if !pod.is_empty() {
        cmd.arg("--name").arg(pod);
    }
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("NAU_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (issue #66).
    cmd.env("NAU_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn nau pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The absolute path of the host's real curl (the shim execs it).
fn real_curl() -> PathBuf {
    let out = Command::new("which").arg("curl").output().unwrap();
    assert!(out.status.success(), "curl must be on PATH (gated)");
    PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
}

/// A counting `curl` shim: logs every invocation's argv to
/// `$NAU_TEST_CURL_LOG`, then execs the real curl, so any call the
/// sync makes is BOTH counted and honestly served.
fn install_curl_shim(dir: &Path) -> (PathBuf, PathBuf) {
    let shim_dir = dir.join("curl-shim/bin");
    std::fs::create_dir_all(&shim_dir).unwrap();
    let log = dir.join("curl-calls.log");
    let shim = shim_dir.join("curl");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$NAU_TEST_CURL_LOG\"\nexec {} \"$@\"\n",
        real_curl().display()
    );
    std::fs::write(&shim, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (shim_dir, log)
}

/// Run a sync with the counting shim FIRST on PATH.
fn run_shimmed(
    project: &Path,
    root: &Path,
    pod: &str,
    shim_dir: &Path,
    log: &Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nau"));
    cmd.arg("pod");
    if !pod.is_empty() {
        cmd.arg("--name").arg(pod);
    }
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("NAU_DATA_HOME", root.join("data-home"));
    cmd.env("NAU_SYSTEMD", "off");
    let orig_path = std::env::var("PATH").unwrap_or_default();
    cmd.env("PATH", format!("{}:{}", shim_dir.display(), orig_path));
    cmd.env("NAU_TEST_CURL_LOG", log);
    let out = cmd.output().expect("failed to spawn nau pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every curl invocation the shimmed run made (empty when the log was
/// never written — the zero-network case).
fn curl_calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// The generation count (numeric entries under generations/).
fn generation_count(root: &Path, pod: &str) -> usize {
    let gens = root.join(pod).join("generations");
    std::fs::read_dir(&gens)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().parse::<u64>().is_ok())
                .count()
        })
        .unwrap_or(0)
}

/// Build a one-package pod project: loopback server, package recipe,
/// declaration, first (building) sync. Returns (project, root, port).
fn synced_pod(dir: &Path, pod: &str, pkg: &str) -> (PathBuf, PathBuf, u16) {
    let project = dir.join("project");
    let server_dir = dir.join("serve");
    let root = dir.join("pods");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&server_dir).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let port = serve_dir(&server_dir);
    make_tarball(&server_dir, pkg);
    write_pkg(&project, pkg, &format!("{pkg} marker"), port);
    write_pod_lua(&root, pod, &format!("    packages = {{ \"{}\" }},\n", pkg));
    let (code, _out, err) = run(&project, &root, pod, &["sync"]);
    assert_eq!(code, Some(0), "first (building) sync failed: {err}");
    (project, root, port)
}

// ── Tests ──

// A fully-held no-op sync of an own package makes ZERO curl calls:
// the pin is held, the generation carries the content, and nothing is
// resolved, probed, or fetched (issue #331).
gated_test!(noop_sync_of_fully_held_pod_makes_zero_curl_calls, {
    let dir = tempfile::tempdir().unwrap();
    let (project, root, _port) = synced_pod(dir.path(), "daily", "probetool");

    let (shim_dir, log) = install_curl_shim(dir.path());
    let (code, _out, err) = run_shimmed(&project, &root, "daily", &shim_dir, &log, &["sync"]);
    assert_eq!(code, Some(0), "no-op sync failed: {err}");
    assert!(
        err.contains("held 'probetool' at its pin"),
        "the sync must report the hold, not a silent rebuild: {err}"
    );
    let calls = curl_calls(&log);
    assert!(
        calls.is_empty(),
        "a fully-held sync must make zero curl calls, got {}: {calls:?}\n{err}",
        calls.len()
    );
    assert_eq!(
        generation_count(&root, "daily"),
        1,
        "a no-op sync must not bump the generation"
    );
});

// The same zero-network contract one composition layer up: a pod
// loading a synced subpod holds the loaded member without any curl
// call either (the loaded contribution rides the subpod's unchanged
// generation).
gated_test!(noop_sync_with_loaded_subpod_makes_zero_curl_calls, {
    let dir = tempfile::tempdir().unwrap();
    let (project, root, _port) = synced_pod(dir.path(), "base", "basetool");

    // The loading pod declares only the load; basetool arrives loaded.
    write_pod_lua(&root, "work", "    loads = { \"base\" },\n");
    let (code, _out, err) = run(&project, &root, "work", &["sync"]);
    assert_eq!(code, Some(0), "loading pod's first sync failed: {err}");

    let (shim_dir, log) = install_curl_shim(&dir.path().join("shim"));
    let (code, _out, err) = run_shimmed(&project, &root, "work", &shim_dir, &log, &["sync"]);
    assert_eq!(code, Some(0), "no-op sync failed: {err}");
    assert!(
        err.contains("held 'basetool' at its pin"),
        "the loaded member must hold, not rebuild: {err}"
    );
    let calls = curl_calls(&log);
    assert!(
        calls.is_empty(),
        "a fully-held sync (loaded subpod included) must make zero curl \
         calls, got {}: {calls:?}\n{err}",
        calls.len()
    );
});
