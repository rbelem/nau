//! Dependency-closure fetch for interpreted packages (ADR-0017, issue
//! #13) — integration tests through the real binary.
//!
//! Mirrors tests/pod_install.rs: a declared package in `pkgs/` is resolved,
//! its npm/pip dependency closure is fetched over loopback HTTP from a
//! server the test itself serves, and the package builds in the offline
//! bwrap sandbox against the hash-verified store entry, lands in the pod
//! store, and executes through the generation bin farm. No real network.
//!
//! Safety property under test (ADR-0017 Decision 2): the fetch phase is
//! download-only — a lifecycle script shipped inside a dependency tarball
//! must NEVER execute on the host (canary assertion in every test).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

// ── Gating (same skip pattern as pod_install.rs) ──

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

fn chain_available(extra: &[&str]) -> bool {
    ["mksquashfs", "unsquashfs", "curl", "tar"]
        .iter()
        .chain(extra.iter())
        .all(|t| has_tool(t))
}

macro_rules! gated_test {
    ($fn_name:ident, $extra:expr, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            let extra: &[&str] = $extra;
            if !chain_available(extra) {
                eprintln!("skipping: toolchain unavailable for {extra:?}");
                return;
            }
            $($body)*
        }
    };
}

// ── Loopback server with a request log ──

/// Serve the files of `dir` over 127.0.0.1 HTTP, recording every request
/// path. The thread lives as long as the test process.
fn serve_dir(dir: &Path) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    let root = dir.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if serve_one(&mut stream, &root, &log2).is_err() {
                continue;
            }
        }
    });
    (port, log)
}

fn serve_one(
    stream: &mut TcpStream,
    root: &Path,
    log: &Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
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
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
    log.lock().unwrap().push(path.clone());
    let mut file = root.join(path.trim_start_matches('/'));
    // Directory requests resolve to index.html (PEP 503 project pages).
    if file.is_dir() || path.ends_with('/') {
        file = file.join("index.html");
    }
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

fn requests_for(log: &Arc<Mutex<Vec<String>>>, prefix: &str) -> usize {
    log.lock()
        .unwrap()
        .iter()
        .filter(|p| p.starts_with(prefix))
        .count()
}

// ── Hash helpers (SRI + wheel pins for the fixtures) ──

fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn sri_sha512(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

fn tar_czf(dir: &Path, out_name: &str, input: &str) {
    let status = Command::new("tar")
        .args(["czf", out_name, input])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "tar czf failed");
}

// ── npm fixture ──

/// Write a tiny npm package tarball under `server/registry/ndep/-/` and
/// return its bytes (for the lockfile's integrity). `say` is what the
/// dependency's index.js returns at runtime — the closure's identity.
fn write_npm_dep(
    server: &Path,
    name: &str,
    version: &str,
    say: &str,
    native_rpath: Option<&str>,
) -> Vec<u8> {
    let pkg = server.join("registry/ndep/-/pkg");
    let _ = std::fs::remove_dir_all(&pkg);
    std::fs::create_dir_all(pkg.join("lib")).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}", "main": "lib/index.js" }}"#),
    )
    .unwrap();
    std::fs::write(
        pkg.join("lib/index.js"),
        format!("module.exports = {{ say: () => \"{say}\" }};\n"),
    )
    .unwrap();
    // A lifecycle script that must NEVER execute on the host (ADR-0017
    // Decision 2): if anything runs it, it drops a canary file in the CWD.
    std::fs::write(
        pkg.join("postinstall.js"),
        "require('fs').writeFileSync('HOST_CANARY_WAS_TOUCHED', 'x');\n",
    )
    .unwrap();
    if let Some(rpath) = native_rpath {
        // A prebuilt native addon with a nix-store RUNPATH baked in — the
        // build-time ELF repair (tickets #12/#13) must repoint it.
        std::fs::create_dir_all(pkg.join("native")).unwrap();
        std::fs::write(pkg.join("native/empty.c"), "void shuttle_marker(void) {}\n").unwrap();
        let status = Command::new("cc")
            .args(["-shared", "-o", "native/binding.node", "native/empty.c"])
            .arg(format!("-Wl,-rpath,{rpath}"))
            .current_dir(&pkg)
            .status()
            .expect("cc spawn");
        assert!(status.success(), "cc failed");
    }
    let tgz = server.join(format!("registry/ndep/-/{name}-{version}.tgz"));
    // Root the archive at `pkg/` — npm registry tarballs carry exactly
    // one root directory, which the fetcher strips on extraction.
    let status = Command::new("tar")
        .args(["czf"])
        .arg(&tgz)
        .args(["-C", &server.join("registry/ndep/-").to_string_lossy()])
        .arg("pkg")
        .status()
        .unwrap();
    assert!(status.success(), "tar czf failed");
    std::fs::read(&tgz).unwrap()
}

/// Write the interpreted package's source tarball (the lockfile ships
/// inside it) and the resolvable shuttle package. `say` flows into the
/// lockfile's dep tarball name; `floating` toggles float mode.
fn write_npm_pkg(project: &Path, server: &Path, name: &str, say: &str, port: u16, floating: bool) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();

    // Dependency tarball + its integrity (URL stays stable across float
    // moves; the bytes and the integrity move together).
    let dep_tgz = write_npm_dep(server, "ndep", "1.0.0", say, None);
    let integrity = sri_sha512(&dep_tgz);

    // App source tree: package-lock.json + the CLI script.
    let approot = server.join("approot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(&approot).unwrap();
    let lock = format!(
        r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "name": "{name}", "version": "1.0.0", "dependencies": {{ "ndep": "1.0.0" }} }},
    "node_modules/ndep": {{
      "version": "1.0.0",
      "resolved": "http://127.0.0.1:{port}/registry/ndep/-/ndep-1.0.0.tgz",
      "integrity": "{integrity}"
    }}
  }}
}}
"#
    );
    std::fs::write(approot.join("package-lock.json"), lock).unwrap();
    std::fs::write(
        approot.join("cli.js"),
        // The argv echo proves the build-time wrapper forwards the tool's
        // arguments through its single exec (issue #9).
        "const d = require(\"ndep\");\nconsole.log(d.say());\nconsole.log(process.argv.slice(2).join(\" \"));\n",
    )
    .unwrap();
    tar_czf(server, "app-src.tar.gz", "approot");

    let float_decl = if floating {
        "\n    floating = true,"
    } else {
        ""
    };
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/app-src.tar.gz",{float_decl}
    deps = {{ npm = {{ lock = "package-lock.json" }} }},
    build = "mkdir -p $STAGE/lib/node_modules/{name} && cp $SRC/cli.js $STAGE/lib/node_modules/{name}/cli.js && cp -r \"$SHUTTLE_DEPS_DIR/node_modules\" $STAGE/lib/node_modules/{name}/node_modules",
    apps = {{ {name} = {{ command = "lib/node_modules/{name}/cli.js", interpreter = "node" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── pip fixture ──

/// Write a minimal wheel (a zip) + its PEP 503 simple-index page under
/// `server`, and return the wheel's sha256 (the lock's pin).
fn write_pip_dep(server: &Path, say: &str) -> String {
    let build = server.join("wheelbuild");
    let _ = std::fs::remove_dir_all(&build);
    std::fs::create_dir_all(build.join("pcalc")).unwrap();
    std::fs::write(
        build.join("pcalc/__init__.py"),
        format!("def say():\n    return \"{say}\"\n"),
    )
    .unwrap();
    let wheel = server.join("wheels/pcalc-1.0-py3-none-any.whl");
    std::fs::create_dir_all(server.join("wheels")).unwrap();
    let _ = std::fs::remove_file(&wheel);
    let status = Command::new("python3")
        .arg("-m")
        .arg("zipfile")
        .arg("-c")
        .arg(&wheel)
        .arg("pcalc")
        .current_dir(&build)
        .status()
        .expect("python3 spawn");
    assert!(status.success(), "python3 -m zipfile -c failed");
    let wheel_bytes = std::fs::read(&wheel).unwrap();
    let hash = sha256_hex(&wheel_bytes);

    let index_dir = server.join("simple/pcalc");
    std::fs::create_dir_all(&index_dir).unwrap();
    std::fs::write(
        index_dir.join("index.html"),
        format!(
            "<html><body><a href=\"../../wheels/pcalc-1.0-py3-none-any.whl#sha256={hash}\">pcalc-1.0-py3-none-any.whl</a></body></html>\n"
        ),
    )
    .unwrap();
    hash
}

fn write_pip_pkg(project: &Path, server: &Path, name: &str, say: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let hash = write_pip_dep(server, say);

    let approot = server.join("pyapproot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(&approot).unwrap();
    std::fs::write(
        approot.join("requirements.lock"),
        format!("pcalc==1.0 --hash=sha256:{hash}\n"),
    )
    .unwrap();
    std::fs::write(
        approot.join("main.py"),
        "import os, sys\n\
         sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), \"site-packages\"))\n\
         import pcalc\n\
         print(pcalc.say())\n\
         print(\" \".join(sys.argv[1:]))\n",
    )
    .unwrap();
    tar_czf(server, "py-src.tar.gz", "pyapproot");

    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/py-src.tar.gz",
    deps = {{ pip = {{ lock = "requirements.lock", index = "http://127.0.0.1:{port}/simple" }} }},
    build = "mkdir -p $STAGE/lib/pymods/site-packages && python3 -m zipfile -e \"$SHUTTLE_DEPS_DIR/pcalc-1.0-py3-none-any.whl\" $STAGE/lib/pymods/site-packages && cp $SRC/main.py $STAGE/lib/pymods/main.py",
    apps = {{ {name} = {{ command = "lib/pymods/main.py", interpreter = "python3" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners (same shape as pod_install.rs) ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
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

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let link = pod_dir(root, pod).join("current");
    let target = std::fs::read_link(&link).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

/// Run the installed app with the farm FIRST on PATH (ahead of the host
/// tools a wrapper needs: readlink, dirname, the interpreter) — the
/// farm-executes acceptance criterion.
fn run_farm_app(farm: &Path, app: &str) -> String {
    run_farm_app_args(farm, app, &[])
}

/// Run a farm app with extra argv (issue #9: the wrapper must forward the
/// tool's arguments through its single exec).
fn run_farm_app_args(farm: &Path, app: &str, args: &[&str]) -> String {
    let host_path = std::env::var("PATH").unwrap_or_default();
    let out = Command::new(app)
        .args(args)
        .env("PATH", format!("{}:{}", farm.display(), host_path))
        .output()
        .expect("spawn farm app");
    assert!(
        out.status.success(),
        "farm app must execute: stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The deps pin recorded in the pod lockfile: (hash, fetched_at).
fn lock_deps_pin(root: &Path, pod: &str, pkg: &str) -> (String, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Lock {
        packages: std::collections::BTreeMap<String, Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        #[serde(default)]
        deps: Option<Pin>,
    }
    #[derive(serde::Deserialize)]
    struct Pin {
        deps_hash: String,
        #[serde(default)]
        fetched_at: Option<String>,
    }
    let text = std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).unwrap();
    let lock: Lock = serde_json::from_str(&text).unwrap();
    let pin = lock
        .packages
        .get(pkg)
        .and_then(|e| e.deps.as_ref())
        .expect("lock must record a deps pin");
    (pin.deps_hash.clone(), pin.fetched_at.clone())
}

fn assert_no_canary(dirs: &[&Path]) {
    for dir in dirs {
        let canary = dir.join("HOST_CANARY_WAS_TOUCHED");
        assert!(
            !canary.exists(),
            "a lifecycle script executed on the host: canary at {}",
            canary.display()
        );
    }
}

// ── Acceptance: Node closure fetch → offline build → farm executes ──

gated_test!(node_deps_fetch_build_and_farm_executes, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zndapp",
        "node-dep-ran",
        port,
        false,
    );

    // pod add auto-fetches the closure, builds offline, installs.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "zndapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    // The closure pin is recorded in the pod lockfile with fetched_at.
    let (hash, fetched_at) = lock_deps_pin(root.path(), "default", "zndapp");
    assert_eq!(hash.len(), 64, "deps_hash is a sha256 hex digest");
    assert!(fetched_at.is_some(), "first fetch records fetched_at");

    // The closure store entry exists, content-addressed by the pin.
    let blob = pod_dir(root.path(), "default")
        .join("store")
        .join(&hash[..2])
        .join(&hash);
    assert!(blob.exists(), "closure blob at {}", blob.display());

    // SAFETY: nothing executed the tarball's lifecycle script on the host.
    assert_no_canary(&[project.path(), root.path(), server.path()]);

    // The farm binary executes: interpreter wrapper + the fetched closure.
    let farm = current_farm(root.path(), "default");
    let out = run_farm_app(&farm, "zndapp");
    assert!(
        out.contains("node-dep-ran"),
        "node app must run its fetched dependency: {out:?}"
    );

    // Issue #9: the tree wrapper's single exec forwards the tool's args.
    let out = run_farm_app_args(&farm, "zndapp", &["--flag", "positional"]);
    assert!(
        out.contains("--flag positional"),
        "node farm app must receive forwarded arguments: {out:?}"
    );
});

// ── Acceptance: Python closure fetch → offline build → farm executes ──

gated_test!(pip_deps_fetch_build_and_farm_executes, &["python3"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_pip_pkg(
        project.path(),
        server.path(),
        "pycapp",
        "python-dep-ran",
        port,
    );

    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "pycapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    let (hash, _) = lock_deps_pin(root.path(), "default", "pycapp");
    assert_eq!(hash.len(), 64);

    assert_no_canary(&[project.path(), root.path(), server.path()]);

    let farm = current_farm(root.path(), "default");
    let out = run_farm_app(&farm, "pycapp");
    assert!(
        out.contains("python-dep-ran"),
        "python app must run its fetched dependency: {out:?}"
    );

    // Issue #9: the tree wrapper's single exec forwards the tool's args.
    let out = run_farm_app_args(&farm, "pycapp", &["--flag", "positional"]);
    assert!(
        out.contains("--flag positional"),
        "python farm app must receive forwarded arguments: {out:?}"
    );
});

// ── Locked packages do NOT re-fetch when the pin is cached ──

gated_test!(locked_package_does_not_refetch, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zndapp",
        "locked-dep",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zndapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let fetches_after_add = requests_for(&log, "/registry/");
    assert!(fetches_after_add >= 1, "add must fetch the closure");

    // Second sync: the pin is cached → zero registry GETs, no rebuild.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        requests_for(&log, "/registry/"),
        fetches_after_add,
        "locked + cached must not re-fetch"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("already matches its declaration"),
        "second sync must be a no-op: {combined}"
    );
});

// ── A tampered closure fails the build (hash mismatch) ──

gated_test!(tampered_closure_fails_build, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zndapp",
        "tamper-target",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zndapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Flip a byte inside the stored closure blob (same path, different
    // content) — the build-time verification must fail closed.
    let (hash, _) = lock_deps_pin(root.path(), "default", "zndapp");
    let blob = pod_dir(root.path(), "default")
        .join("store")
        .join(&hash[..2])
        .join(&hash);
    let mut bytes = std::fs::read(&blob).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&blob, &bytes).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_ne!(code, Some(0), "tampered closure must fail the build");
    assert!(
        stderr.contains("hash mismatch") || stderr.contains("corrupted"),
        "failure must name the hash mismatch: {stderr}"
    );
});

// ── Float mode: re-fetch on sync, new hash + fetched_at, marked, rollback ──

gated_test!(floating_refetch_marks_and_rolls_back, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zfapp",
        "float-dep-v1",
        port,
        true,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zfapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (hash_a, _) = lock_deps_pin(root.path(), "default", "zfapp");

    // Upstream moves: same URLs, new closure content.
    write_npm_pkg(
        project.path(),
        server.path(),
        "zfapp",
        "float-dep-v2",
        port,
        true,
    );

    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let sync_out = format!("{stdout}{stderr}");
    assert!(
        sync_out.contains("changed"),
        "sync must warn about the floating content change: {sync_out}"
    );
    let (hash_b, fetched_at) = lock_deps_pin(root.path(), "default", "zfapp");
    assert_ne!(hash_a, hash_b, "float sync records the new closure hash");
    assert!(fetched_at.is_some(), "float sync refreshes fetched_at");

    // Marked in pod list (status lines go to stderr).
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("(float)"),
        "pod list must mark floating packages: {combined}"
    );

    // The farm executes the NEW content.
    let out = run_farm_app(&current_farm(root.path(), "default"), "zfapp");
    assert!(out.contains("float-dep-v2"), "farm serves v2: {out:?}");

    // Rollback: the prior generation still holds ITS pinned content.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "rollback"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    let out = run_farm_app(&current_farm(root.path(), "default"), "zfapp");
    assert!(
        out.contains("float-dep-v1"),
        "rollback must serve the prior generation's closure: {out:?}"
    );
});

// ── `shuttle deps fetch` CLI: skip cached locked, re-resolve with --latest ──

gated_test!(
    deps_fetch_cli_skips_locked_and_latest_refetches,
    &["node"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, log) = serve_dir(server.path());
        write_npm_pkg(
            project.path(),
            server.path(),
            "zndapp",
            "cli-dep",
            port,
            false,
        );

        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zndapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let after_add = requests_for(&log, "/registry/");

        // Locked + cached: `deps fetch` skips without touching the network.
        let (code, _stdout, stderr) = run(project.path(), root.path(), &["deps", "fetch"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert_eq!(
            requests_for(&log, "/registry/"),
            after_add,
            "locked + cached must not re-fetch"
        );

        // --latest re-resolves even locked packages; identical upstream means
        // the closure content (and pin) stays put.
        let (hash_a, _) = lock_deps_pin(root.path(), "default", "zndapp");
        let (code, _stdout, stderr) =
            run(project.path(), root.path(), &["deps", "fetch", "--latest"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        assert!(
            requests_for(&log, "/registry/") > after_add,
            "--latest must re-fetch"
        );
        let (hash_b, _) = lock_deps_pin(root.path(), "default", "zndapp");
        assert_eq!(hash_a, hash_b, "unchanged upstream keeps the pin");
    }
);

// ── Prebuilt native addons in the closure get the ELF repair ──

gated_test!(
    native_addon_in_closure_gets_elf_repair,
    &["node", "cc", "patchelf"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, _log) = serve_dir(server.path());

        // Dependency tarball with a prebuilt .node carrying a nix-store RUNPATH.
        let pkg = server.path().join("registry/ndep/-/pkg");
        let _ = std::fs::remove_dir_all(&pkg);
        std::fs::create_dir_all(pkg.join("native")).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{ "name": "ndep", "version": "1.0.0" }"#,
        )
        .unwrap();
        std::fs::write(
            pkg.join("index.js"),
            "module.exports = { say: () => \"elf-ok\" };\n",
        )
        .unwrap();
        std::fs::write(pkg.join("native/empty.c"), "void shuttle_marker(void) {}\n").unwrap();
        let status = Command::new("cc")
            .args(["-shared", "-o", "native/binding.node", "native/empty.c"])
            .arg("-Wl,-rpath,/nix/store/0000000000000000000000000000-libfoo/lib")
            .current_dir(&pkg)
            .status()
            .expect("cc spawn");
        assert!(status.success(), "cc failed");
        // Root the archive at `pkg/` (one root dir — the fetcher strips it).
        let elf_tgz = server.path().join("registry/ndep/-/ndep-1.0.0.tgz");
        let status = Command::new("tar")
            .args(["czf"])
            .arg(&elf_tgz)
            .args([
                "-C",
                &server.path().join("registry/ndep/-").to_string_lossy(),
            ])
            .arg("pkg")
            .status()
            .unwrap();
        assert!(status.success(), "tar czf failed");
        let dep_tgz = std::fs::read(&elf_tgz).unwrap();
        let integrity = sri_sha512(&dep_tgz);

        // App source: package-lock + cli requiring the addon-bearing dep.
        let approot = server.path().join("elfapproot");
        let _ = std::fs::remove_dir_all(&approot);
        std::fs::create_dir_all(&approot).unwrap();
        let lock = format!(
            r#"{{
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "dependencies": {{ "ndep": "1.0.0" }} }},
    "node_modules/ndep": {{
      "version": "1.0.0",
      "resolved": "http://127.0.0.1:{port}/registry/ndep/-/ndep-1.0.0.tgz",
      "integrity": "{integrity}"
    }}
  }}
}}
"#
        );
        std::fs::write(approot.join("package-lock.json"), lock).unwrap();
        std::fs::write(
            approot.join("cli.js"),
            "const d = require(\"ndep\");\nconsole.log(d.say());\n",
        )
        .unwrap();
        tar_czf(server.path(), "elf-src.tar.gz", "elfapproot");

        let dir = project.path().join("pkgs/z");
        std::fs::create_dir_all(&dir).unwrap();
        let lua = format!(
            r#"return {{ default = snap {{
    name = "zelfapp",
    version = "1.0",
    source = "http://127.0.0.1:{port}/elf-src.tar.gz",
    deps = {{ npm = {{ lock = "package-lock.json" }} }},
    build = "mkdir -p $STAGE/lib/node_modules/zelfapp && cp $SRC/cli.js $STAGE/lib/node_modules/zelfapp/cli.js && cp -r \"$SHUTTLE_DEPS_DIR/node_modules\" $STAGE/lib/node_modules/zelfapp/node_modules",
    apps = {{ zelfapp = {{ command = "lib/node_modules/zelfapp/cli.js", interpreter = "node" }} }},
}} }}
"#
        );
        std::fs::write(dir.join("zelfapp.lua"), lua).unwrap();

        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zelfapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");

        // Find the built payload and inspect the shipped addon's RUNPATH.
        let downloads = pod_dir(root.path(), "default").join("downloads");
        let mut payload = None;
        for entry in std::fs::read_dir(&downloads).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("zelfapp_") && name.ends_with(".snap") {
                payload = Some(entry.path());
            }
        }
        let payload = payload.expect("built payload in pod downloads dir");
        let extract = tempfile::tempdir().unwrap();
        let status = Command::new("unsquashfs")
            .args(["-f", "-d"])
            .arg(extract.path())
            .arg(&payload)
            .status()
            .unwrap();
        assert!(status.success(), "unsquashfs failed");
        let binding = extract
            .path()
            .join("lib/node_modules/zelfapp/node_modules/ndep/native/binding.node");
        assert!(binding.exists(), "addon must ship in the payload");

        let out = Command::new("patchelf")
            .args(["--print-rpath"])
            .arg(&binding)
            .output()
            .unwrap();
        let rpath = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            !rpath.contains("/nix/store"),
            "addon RUNPATH must be repaired, got: {rpath}"
        );

        // And the package still executes.
        let out = run_farm_app(&current_farm(root.path(), "default"), "zelfapp");
        assert!(
            out.contains("elf-ok"),
            "farm serves the elf package: {out:?}"
        );
    }
);

// ── deps.npm.exclude: excluded lock keys are never fetched (issue #14) ──

/// Fixture for the npm `exclude` e2e: the app's lock has two deps, and
/// the declaration excludes one (`ndrop`) — its tarball must never be
/// requested, and the kept dep still builds and runs.
fn write_npm_exclude_pkg(project: &Path, server: &Path, port: u16) {
    let name = "znxapp";
    let dir = project.join("pkgs/z");
    std::fs::create_dir_all(&dir).unwrap();

    // Both tarballs exist on the registry server: a regression that
    // fetches the excluded one would succeed against a 200, and the
    // request log would catch it.
    let dep_tgz = write_npm_dep(server, "ndep", "1.0.0", "kept-dep-ran", None);
    let integrity = sri_sha512(&dep_tgz);
    let drop_tgz = write_npm_dep(server, "ndrop", "9.9.9", "dropped-dep-ran", None);
    let drop_integrity = sri_sha512(&drop_tgz);

    let approot = server.join("exapproot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(&approot).unwrap();
    let lock = format!(
        r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "name": "{name}", "version": "1.0.0", "dependencies": {{ "ndep": "1.0.0", "ndrop": "9.9.9" }} }},
    "node_modules/ndep": {{
      "version": "1.0.0",
      "resolved": "http://127.0.0.1:{port}/registry/ndep/-/ndep-1.0.0.tgz",
      "integrity": "{integrity}"
    }},
    "node_modules/ndrop": {{
      "version": "9.9.9",
      "resolved": "http://127.0.0.1:{port}/registry/ndep/-/ndrop-9.9.9.tgz",
      "integrity": "{drop_integrity}"
    }}
  }}
}}
"#
    );
    std::fs::write(approot.join("package-lock.json"), lock).unwrap();
    std::fs::write(
        approot.join("cli.js"),
        "const d = require(\"ndep\");\nconsole.log(d.say());\n",
    )
    .unwrap();
    tar_czf(server, "ex-src.tar.gz", "exapproot");

    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/ex-src.tar.gz",
    deps = {{ npm = {{ lock = "package-lock.json", exclude = {{ "node_modules/ndrop" }} }} }},
    build = "mkdir -p $STAGE/lib/node_modules/{name} && cp $SRC/cli.js $STAGE/lib/node_modules/{name}/cli.js && cp -r \"$SHUTTLE_DEPS_DIR/node_modules\" $STAGE/lib/node_modules/{name}/node_modules",
    apps = {{ {name} = {{ command = "lib/node_modules/{name}/cli.js", interpreter = "node" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

gated_test!(npm_exclude_never_fetches_the_excluded_tarball, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_npm_exclude_pkg(project.path(), server.path(), port);

    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "znxapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    // The excluded tarball was NEVER requested; the kept dep was.
    assert_eq!(
        requests_for(&log, "/registry/ndep/-/ndrop"),
        0,
        "excluded dep must never be fetched; requests: {:#?}",
        log.lock().unwrap()
    );
    assert!(
        requests_for(&log, "/registry/ndep/-/ndep-1.0.0.tgz") >= 1,
        "the kept dep must be fetched; requests: {:#?}",
        log.lock().unwrap()
    );

    // SAFETY: nothing executed a dependency lifecycle script on the host.
    assert_no_canary(&[project.path(), root.path(), server.path()]);

    // The build ran against the post-filter closure: the farm serves the
    // app with its kept dependency.
    let farm = current_farm(root.path(), "default");
    let out = run_farm_app(&farm, "znxapp");
    assert!(
        out.contains("kept-dep-ran"),
        "farm app must run the kept dep: {out:?}"
    );
});

// ── uv.lock dev-dependency split: dev wheels are never fetched (issue #14) ──

/// Write a minimal wheel (a zip) under `server/wheels/` and return its
/// sha256 (the uv.lock `hash` pin).
fn write_uv_wheel(server: &Path, name: &str, version: &str, say: &str) -> String {
    let build = server.join("uvwheelbuild");
    let _ = std::fs::remove_dir_all(&build);
    std::fs::create_dir_all(build.join(name)).unwrap();
    std::fs::write(
        build.join(format!("{name}/__init__.py")),
        format!("def say():\n    return \"{say}\"\n"),
    )
    .unwrap();
    std::fs::create_dir_all(server.join("wheels")).unwrap();
    let wheel = server.join(format!("wheels/{name}-{version}-py3-none-any.whl"));
    let _ = std::fs::remove_file(&wheel);
    let status = Command::new("python3")
        .arg("-m")
        .arg("zipfile")
        .arg("-c")
        .arg(&wheel)
        .arg(name)
        .current_dir(&build)
        .status()
        .expect("python3 spawn");
    assert!(status.success(), "python3 -m zipfile -c failed");
    sha256_hex(&std::fs::read(&wheel).unwrap())
}

/// Fixture for the uv dev-split e2e: an editable root with a prod dep
/// (`prod`) and a dev dep (`devtool`, transitively `devtrans`).
fn write_uv_devsplit_pkg(project: &Path, server: &Path, name: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();

    let prod_hash = write_uv_wheel(server, "prod", "1.0", "prod-dep-ran");
    let devtool_hash = write_uv_wheel(server, "devtool", "1.0", "devtool-ran");
    let devtrans_hash = write_uv_wheel(server, "devtrans", "1.0", "devtrans-ran");

    let approot = server.join("uvapproot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(&approot).unwrap();
    let lock = format!(
        r#"
version = 1
requires-python = ">=3.9"

[[package]]
name = "{name}"
version = "1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "prod" }}]
dev-dependencies = [{{ name = "devtool" }}]

[[package]]
name = "prod"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
    {{ url = "http://127.0.0.1:{port}/wheels/prod-1.0-py3-none-any.whl", hash = "sha256:{prod_hash}" }},
]

[[package]]
name = "devtool"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [{{ name = "devtrans" }}]
wheels = [
    {{ url = "http://127.0.0.1:{port}/wheels/devtool-1.0-py3-none-any.whl", hash = "sha256:{devtool_hash}" }},
]

[[package]]
name = "devtrans"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
    {{ url = "http://127.0.0.1:{port}/wheels/devtrans-1.0-py3-none-any.whl", hash = "sha256:{devtrans_hash}" }},
]
"#
    );
    std::fs::write(approot.join("uv.lock"), lock).unwrap();
    std::fs::write(
        approot.join("main.py"),
        "import os, sys\n\
         sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), \"site-packages\"))\n\
         import prod\n\
         print(prod.say())\n",
    )
    .unwrap();
    tar_czf(server, "uv-src.tar.gz", "uvapproot");

    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/uv-src.tar.gz",
    deps = {{ pip = {{ lock = "uv.lock", index = "http://127.0.0.1:{port}/simple" }} }},
    build = "mkdir -p $STAGE/lib/pymods/site-packages && python3 -m zipfile -e \"$SHUTTLE_DEPS_DIR/prod-1.0-py3-none-any.whl\" $STAGE/lib/pymods/site-packages && cp $SRC/main.py $STAGE/lib/pymods/main.py",
    apps = {{ {name} = {{ command = "lib/pymods/main.py", interpreter = "python3" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

gated_test!(uv_dev_split_never_fetches_dev_wheels, &["python3"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_uv_devsplit_pkg(project.path(), server.path(), "zuvapp", port);

    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "zuvapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    // Dev wheels (direct and transitive) were NEVER requested; the prod
    // wheel was.
    assert_eq!(
        requests_for(&log, "/wheels/devtool"),
        0,
        "dev wheel must never be fetched; requests: {:#?}",
        log.lock().unwrap()
    );
    assert_eq!(
        requests_for(&log, "/wheels/devtrans"),
        0,
        "transitive dev wheel must never be fetched; requests: {:#?}",
        log.lock().unwrap()
    );
    assert!(
        requests_for(&log, "/wheels/prod") >= 1,
        "the prod wheel must be fetched; requests: {:#?}",
        log.lock().unwrap()
    );

    // The build ran: the farm serves the app with its prod dependency.
    let farm = current_farm(root.path(), "default");
    let out = run_farm_app(&farm, "zuvapp");
    assert!(
        out.contains("prod-dep-ran"),
        "farm app must run the prod dep: {out:?}"
    );
});

// ── deps.pip `exclude` is a parse-time hard error (npm only) ──

gated_test!(pip_exclude_rejected_at_parse, &[], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_pip_pkg(project.path(), server.path(), "pyxapp", "x", port);

    // Amend the declaration to carry the unsupported option.
    let lua_path = project.path().join("pkgs/p/pyxapp.lua");
    let lua = std::fs::read_to_string(&lua_path).unwrap().replace(
        "lock = \"requirements.lock\"",
        "lock = \"requirements.lock\", exclude = { \"pcalc\" }",
    );
    std::fs::write(&lua_path, lua).unwrap();

    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "pyxapp"]);
    assert_ne!(code, Some(0), "pip exclude must be rejected: {stdout}");
    assert!(
        stderr.contains("'exclude' is not supported (npm only)"),
        "failure must name the unsupported option: {stderr}"
    );
    // The rejection is a parse-time hard error: nothing was fetched.
    assert_eq!(requests_for(&log, "/wheels/"), 0);
});

// ── cargo fixture (issue #36): crates served on the loopback, lock-pinned ──

/// Build a minimal `.crate` (gzipped tarball rooted at `pcrate-0.1.0/`)
/// and serve it at the crates.io download path the resolver fetches.
/// Returns the crate's sha256 — the checksum the fixture's Cargo.lock
/// pins. `say` is what the dependency returns at runtime: the closure's
/// identity.
fn write_cargo_dep_crate(server: &Path, say: &str) -> String {
    let build = server.join("cratebuild");
    let _ = std::fs::remove_dir_all(&build);
    let root = build.join("pcrate-0.1.0");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"pcrate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    // A build script that must NEVER execute on the host (ADR-0017
    // Decision 2) — same canary assertion as the npm postinstall
    // fixture. Inside the sandbox it legitimately runs (cargo build
    // scripts do) and its write lands on the read-only vendor mount,
    // which the `let _ =` tolerates: the build stays green, and a host
    // execution is still betrayed by the marker in the CWD.
    std::fs::write(
        root.join("build.rs"),
        "fn main() { let _ = std::fs::write(\"HOST_CANARY_WAS_TOUCHED\", \"x\"); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        format!("pub fn say() -> &'static str {{ \"{say}\" }}\n"),
    )
    .unwrap();
    let dl = server.join("api/v1/crates/pcrate/0.1.0");
    std::fs::create_dir_all(&dl).unwrap();
    let crate_path = dl.join("download");
    let _ = std::fs::remove_file(&crate_path);
    let status = Command::new("tar")
        .args(["czf"])
        .arg(&crate_path)
        .args(["-C"])
        .arg(&build)
        .arg("pcrate-0.1.0")
        .status()
        .unwrap();
    assert!(status.success(), "tar czf failed");
    sha256_hex(&std::fs::read(&crate_path).unwrap())
}

/// Write the cargo fixture: a single-crate app whose Cargo.lock pins
/// `pcrate` (loopback-served), plus the shuttle package building it
/// OFFLINE against the mounted vendor closure.
fn write_cargo_pkg(project: &Path, server: &Path, name: &str, say: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let checksum = write_cargo_dep_crate(server, say);

    let approot = server.join("cargoapproot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(approot.join("src")).unwrap();
    std::fs::write(
        approot.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\npcrate = \"0.1\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        approot.join("src/main.rs"),
        "fn main() {\n    println!(\"{}\", pcrate::say());\n    println!(\n        \"{}\",\n        std::env::args().skip(1).collect::<Vec<_>>().join(\" \")\n    );\n}\n",
    )
    .unwrap();
    // Hand-written v3 lock — the same registry-entry shape real locks
    // (v3 and v4) carry, pinned to the loopback crate's checksum.
    std::fs::write(
        approot.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\ndependencies = [\"pcrate\"]\n\n[[package]]\nname = \"pcrate\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
        ),
    )
    .unwrap();
    tar_czf(server, "cargo-src.tar.gz", "cargoapproot");

    let lua = r#"return { default = snap {
    name = "@NAME@",
    version = "1.0",
    source = "http://127.0.0.1:@PORT@/cargo-src.tar.gz",
    deps = { cargo = { lock = "Cargo.lock", index = "http://127.0.0.1:@PORT@/api/v1/crates" } },
    build = table.concat({
        "export CARGO_HOME=/tmp/shuttle-cargo-home CARGO_NET_OFFLINE=true",
        "mkdir -p \"$CARGO_HOME\"",
        "printf '[source.crates-io]\\nreplace-with = \"shuttle-vendored\"\\n\\n[source.shuttle-vendored]\\ndirectory = \"%s\"\\n' \"$SHUTTLE_DEPS_DIR/vendor\" > \"$CARGO_HOME/config.toml\"",
        "cargo install --path $SRC --root $STAGE",
    }, " && "),
    apps = { @NAME@ = { command = "bin/@NAME@" } },
} }
"#
    .replace("@NAME@", name)
    .replace("@PORT@", &port.to_string());
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Acceptance: cargo closure fetch → offline build → farm executes ──

gated_test!(
    cargo_deps_fetch_build_and_farm_executes,
    &["cargo", "rustc", "cc"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, log) = serve_dir(server.path());
        write_cargo_pkg(
            project.path(),
            server.path(),
            "zcrapp",
            "cargo-dep-ran",
            port,
        );

        // pod add auto-fetches the closure, builds offline, installs.
        let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "zcrapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

        // The closure pin is recorded in the pod lockfile with fetched_at.
        let (hash, fetched_at) = lock_deps_pin(root.path(), "default", "zcrapp");
        assert_eq!(hash.len(), 64, "deps_hash is a sha256 hex digest");
        assert!(fetched_at.is_some(), "first fetch records fetched_at");

        // The closure store entry exists, content-addressed by the pin.
        let blob = pod_dir(root.path(), "default")
            .join("store")
            .join(&hash[..2])
            .join(&hash);
        assert!(blob.exists(), "closure blob at {}", blob.display());

        // The fetch hit the crates.io download path on the loopback.
        assert!(
            requests_for(&log, "/api/v1/crates/pcrate/0.1.0/download") >= 1,
            "the resolver must fetch the pinned crate: {:#?}",
            log.lock().unwrap()
        );

        // SAFETY: nothing executed the dependency's build script on the host.
        assert_no_canary(&[project.path(), root.path(), server.path()]);

        // The farm binary executes — it linked the VENDORED dependency,
        // so printing `say()` proves the offline closure was consumed.
        let farm = current_farm(root.path(), "default");
        let out = run_farm_app(&farm, "zcrapp");
        assert!(
            out.contains("cargo-dep-ran"),
            "cargo app must run its vendored dependency: {out:?}"
        );

        // Native ELF: the single-exec wrapper story still forwards args.
        let out = run_farm_app_args(&farm, "zcrapp", &["--flag", "positional"]);
        assert!(
            out.contains("--flag positional"),
            "cargo farm app must receive forwarded arguments: {out:?}"
        );
    }
);

// ── A tampered cargo closure fails the build (hash mismatch) ──

gated_test!(
    tampered_cargo_closure_fails_build,
    &["cargo", "rustc", "cc"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, _log) = serve_dir(server.path());
        write_cargo_pkg(
            project.path(),
            server.path(),
            "ztampp",
            "tamper-target",
            port,
        );

        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "ztampp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");

        // Flip a byte inside the stored closure blob (same path, different
        // content) — the build-time verification must fail closed.
        let (hash, _) = lock_deps_pin(root.path(), "default", "ztampp");
        let blob = pod_dir(root.path(), "default")
            .join("store")
            .join(&hash[..2])
            .join(&hash);
        let mut bytes = std::fs::read(&blob).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&blob, &bytes).unwrap();

        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
        assert_ne!(code, Some(0), "tampered closure must fail the build");
        assert!(
            stderr.contains("hash mismatch") || stderr.contains("corrupted"),
            "failure must name the hash mismatch: {stderr}"
        );
    }
);

// ── A changed Cargo.lock moves the deps_hash (cache invalidation) ──

gated_test!(
    cargo_lock_change_moves_the_deps_hash,
    &["cargo", "rustc", "cc"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, log) = serve_dir(server.path());
        write_cargo_pkg(project.path(), server.path(), "zlkapp", "lock-v1", port);

        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zlkapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let (hash_a, _) = lock_deps_pin(root.path(), "default", "zlkapp");
        let fetches_after_add = requests_for(&log, "/api/v1/crates/");

        // Upstream moves: same crate URL, new bytes (new `say`) — the lock
        // pins the new checksum, so the closure content and its hash move.
        write_cargo_pkg(project.path(), server.path(), "zlkapp", "lock-v2", port);

        // --latest re-resolves the closure deliberately and moves the pin.
        let (code, stdout, stderr) = run(
            project.path(),
            root.path(),
            &["pod", "rebuild", "zlkapp", "--latest"],
        );
        assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
        assert!(
            requests_for(&log, "/api/v1/crates/") > fetches_after_add,
            "--latest must re-fetch the moved closure; requests: {:#?}",
            log.lock().unwrap()
        );
        let (hash_b, _) = lock_deps_pin(root.path(), "default", "zlkapp");
        assert_ne!(hash_a, hash_b, "a changed Cargo.lock moves the deps_hash");

        // The farm serves the NEW closure content.
        let out = run_farm_app(&current_farm(root.path(), "default"), "zlkapp");
        assert!(
            out.contains("lock-v2"),
            "farm serves the moved closure: {out:?}"
        );
    }
);

// ── go fixture (issue #40): modules served on the loopback, go.sum-pinned ──

/// Build a real Go module zip (the proxy archive shape, rooted at
/// `<module>@<version>/`) plus its `.mod`/`.info` under the loopback
/// server, and return the go.sum hash lines for the module's zip and
/// go.mod. `say` is what the dependency's exported function returns —
/// the closure's identity.
fn write_go_dep_module(server: &Path, module: &str, version: &str, say: &str) -> (String, String) {
    let escaped = module.replace('!', "!");
    let mdir = server.join(format!("{escaped}/@v"));
    let _ = std::fs::remove_dir_all(server.join(&escaped));
    std::fs::create_dir_all(&mdir).unwrap();
    let mod_text = format!("module {module}\n\ngo 1.21\n");
    let go_text = format!("package godep\n\nfunc Say() string {{ return \"{say}\" }}\n");
    // The archive root is `<module>@<version>/` per the proxy contract.
    let root = format!("{module}@{version}/");
    let zip_path = mdir.join(format!("{version}.zip"));
    let opts =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    {
        let mut zw = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        zw.start_file(format!("{root}go.mod"), opts).unwrap();
        zw.write_all(mod_text.as_bytes()).unwrap();
        zw.start_file(format!("{root}godep.go"), opts).unwrap();
        zw.write_all(go_text.as_bytes()).unwrap();
        zw.finish().unwrap();
    }
    std::fs::write(mdir.join(format!("{version}.mod")), &mod_text).unwrap();
    std::fs::write(
        mdir.join(format!("{version}.info")),
        format!(r#"{{"Version":"{version}","Time":"2026-01-01T00:00:00Z"}}"#),
    )
    .unwrap();
    // go.sum hash lines.
    let zip_h = go_dirhash_zip(&zip_path);
    let mod_h = go_dirhash_file(mod_text.as_bytes());
    (zip_h, mod_h)
}

/// The Go dirhash (`h1:`) over a module zip member list, exactly as the
/// resolver computes it — reimplemented here so the fixture's go.sum
/// matches what shuttle's fetch verifies.
fn go_dirhash_zip(zip_path: &Path) -> String {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip_path).unwrap()).unwrap();
    let mut hashes: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let mut m = archive.by_index(i).unwrap();
        if m.is_dir() {
            continue;
        }
        let name = m.name().to_string();
        let mut d = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = m.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            d.update(&buf[..n]);
        }
        let final_d = d.finalize();
        hashes.push((name, final_d.iter().map(|b| format!("{b:02x}")).collect()));
    }
    hashes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, sha) in &hashes {
        h.update(format!("{sha}  {name}\n").as_bytes());
    }
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    )
}

/// The single-file Go dirhash (`h1:`) over a go.mod's bytes.
fn go_dirhash_file(bytes: &[u8]) -> String {
    let inner = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut h = Sha256::new();
    h.update(format!("{inner}  go.mod\n").as_bytes());
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    )
}

/// Write the go fixture: a single-module app whose go.mod requires
/// `gdmodule` (loopback-served), plus the shuttle package building it
/// OFFLINE via a `file://` GOPROXY onto the mounted closure.
fn write_go_pkg(project: &Path, server: &Path, name: &str, say: &str, port: u16) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let (zip_h, mod_h) = write_go_dep_module(server, "shuttle.test/godep", "v1.0.0", say);

    let approot = server.join("goapproot");
    let _ = std::fs::remove_dir_all(&approot);
    std::fs::create_dir_all(&approot).unwrap();
    std::fs::write(
        approot.join("go.mod"),
        "module shuttle.test/app\n\ngo 1.21\n\nrequire shuttle.test/godep v1.0.0\n",
    )
    .unwrap();
    std::fs::write(
        approot.join("go.sum"),
        format!("shuttle.test/godep v1.0.0 {zip_h}\nshuttle.test/godep v1.0.0/go.mod {mod_h}\n"),
    )
    .unwrap();
    std::fs::write(
        approot.join("main.go"),
        "package main\n\nimport (\n\t\"fmt\"\n\t\"shuttle.test/godep\"\n)\n\nfunc main() {\n\tfmt.Println(godep.Say())\n}\n",
    )
    .unwrap();
    tar_czf(server, "go-src.tar.gz", "goapproot");

    let lua = r#"return { default = snap {
    name = "@NAME@",
    version = "1.0",
    source = "http://127.0.0.1:@PORT@/go-src.tar.gz",
    deps = { go = { mods = "go.mod", index = "http://127.0.0.1:@PORT@" } },
    build = table.concat({
        "export GOMODCACHE=/tmp/shuttle-go-cache GOPROXY=\"file://$SHUTTLE_DEPS_DIR/cache/download\"",
        "export GOFLAGS=-mod=mod GOSUMDB=off GOPATH=/tmp/shuttle-go-cache",
        "mkdir -p \"$GOMODCACHE\"",
        "go build -o $STAGE/@NAME@ .",
    }, " && "),
    apps = { @NAME@ = { command = "@NAME@" } },
} }
"#
    .replace("@NAME@", name)
    .replace("@PORT@", &port.to_string());
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Acceptance: go closure fetch → offline build → farm executes ──

gated_test!(go_deps_fetch_build_and_farm_executes, &["go"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_go_pkg(project.path(), server.path(), "zgoapp", "go-dep-ran", port);

    // pod add auto-fetches the closure, builds offline, installs.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "add", "zgoapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");

    // The closure pin is recorded in the pod lockfile with fetched_at.
    let (hash, fetched_at) = lock_deps_pin(root.path(), "default", "zgoapp");
    assert_eq!(hash.len(), 64, "deps_hash is a sha256 hex digest");
    assert!(fetched_at.is_some(), "first fetch records fetched_at");

    // The closure store entry exists, content-addressed by the pin.
    let blob = pod_dir(root.path(), "default")
        .join("store")
        .join(&hash[..2])
        .join(&hash);
    assert!(blob.exists(), "closure blob at {}", blob.display());

    // The fetch hit the proxy zip path on the loopback.
    assert!(
        requests_for(&log, "/shuttle.test/godep/@v/") >= 1,
        "the resolver must fetch the pinned module: {:#?}",
        log.lock().unwrap()
    );

    // The farm binary executes — it linked the module-cached
    // dependency, so printing `say()` proves the offline closure was
    // consumed.
    let farm = current_farm(root.path(), "default");
    let out = run_farm_app(&farm, "zgoapp");
    assert!(
        out.contains("go-dep-ran"),
        "go app must run its module dependency: {out:?}"
    );
});

// ── A tampered go closure fails the build (hash mismatch) ──

gated_test!(tampered_go_closure_fails_build, &["go"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_go_pkg(
        project.path(),
        server.path(),
        "zgotmp",
        "tamper-target",
        port,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zgotmp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Flip a byte inside the stored closure blob (same path, different
    // content) — the build-time verification must fail closed.
    let (hash, _) = lock_deps_pin(root.path(), "default", "zgotmp");
    let blob = pod_dir(root.path(), "default")
        .join("store")
        .join(&hash[..2])
        .join(&hash);
    let mut bytes = std::fs::read(&blob).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&blob, &bytes).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_ne!(code, Some(0), "tampered closure must fail the build");
    assert!(
        stderr.contains("hash mismatch") || stderr.contains("corrupted"),
        "failure must name the hash mismatch: {stderr}"
    );
});

// ── A changed go.sum moves the deps_hash (cache invalidation) ──

gated_test!(go_sum_change_moves_the_deps_hash, &["go"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_go_pkg(project.path(), server.path(), "zgolck", "lock-v1", port);

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zgolck"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (hash_a, _) = lock_deps_pin(root.path(), "default", "zgolck");
    let fetches_after_add = requests_for(&log, "/shuttle.test/godep/@v/");

    // Upstream moves: same module, new bytes (new `say`) — the go.sum
    // pins the new zip hash, so the closure content and its hash move.
    write_go_pkg(project.path(), server.path(), "zgolck", "lock-v2", port);

    // --latest re-resolves the closure deliberately and moves the pin.
    let (code, stdout, stderr) = run(
        project.path(),
        root.path(),
        &["pod", "rebuild", "zgolck", "--latest"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    assert!(
        requests_for(&log, "/shuttle.test/godep/@v/") > fetches_after_add,
        "--latest must re-fetch the moved closure; requests: {:#?}",
        log.lock().unwrap()
    );
    let (hash_b, _) = lock_deps_pin(root.path(), "default", "zgolck");
    assert_ne!(hash_a, hash_b, "a changed go.sum moves the deps_hash");

    // The farm serves the NEW closure content.
    let out = run_farm_app(&current_farm(root.path(), "default"), "zgolck");
    assert!(
        out.contains("lock-v2"),
        "farm serves the moved closure: {out:?}"
    );
});

// ── `pod rebuild` (issue #15): rebuild one package at its pins ──

/// The version pin recorded in the pod lockfile (None when absent).
fn lock_version_pin(root: &Path, pod: &str, pkg: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Lock {
        packages: std::collections::BTreeMap<String, Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        version: String,
    }
    let text = std::fs::read_to_string(pod_dir(root, pod).join("shuttle.lock")).ok()?;
    let lock: Lock = serde_json::from_str(&text).ok()?;
    lock.packages.get(pkg).map(|e| e.version.clone())
}

gated_test!(rebuild_reuses_cached_closure_without_refetch, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zrapp",
        "rebuild-dep",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let fetches_before = requests_for(&log, "/registry/");
    assert!(fetches_before >= 1, "add must fetch the closure");
    let (hash_before, _) = lock_deps_pin(root.path(), "default", "zrapp");

    // The rebuild must reuse the cached closure: zero registry GETs,
    // deps pin untouched.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "rebuild", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    assert_eq!(
        requests_for(&log, "/registry/"),
        fetches_before,
        "rebuild must not re-fetch the cached closure; requests: {:#?}",
        log.lock().unwrap()
    );
    let (hash_after, _) = lock_deps_pin(root.path(), "default", "zrapp");
    assert_eq!(hash_before, hash_after, "rebuild keeps the deps pin");

    // SAFETY: nothing executed a dependency lifecycle script on the host.
    assert_no_canary(&[project.path(), root.path(), server.path()]);
});

gated_test!(rebuild_latest_repins_moved_closure, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zrapp",
        "latest-dep-v1",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (hash_a, fetched_at_a) = lock_deps_pin(root.path(), "default", "zrapp");
    assert!(fetched_at_a.is_some(), "add records fetched_at");
    let fetches_after_add = requests_for(&log, "/registry/");

    // Upstream moves: same URL, new closure content (new tarball bytes
    // + integrity in the lockfile the re-resolve would fetch).
    write_npm_pkg(
        project.path(),
        server.path(),
        "zrapp",
        "latest-dep-v2",
        port,
        false,
    );

    // --latest re-resolves the closure deliberately and moves the pin.
    let (code, stdout, stderr) = run(
        project.path(),
        root.path(),
        &["pod", "rebuild", "zrapp", "--latest"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    assert!(
        requests_for(&log, "/registry/") > fetches_after_add,
        "--latest must re-fetch the closure; requests: {:#?}",
        log.lock().unwrap()
    );
    let (hash_b, fetched_at_b) = lock_deps_pin(root.path(), "default", "zrapp");
    assert_ne!(hash_a, hash_b, "a moved closure gets a new deps_hash");
    assert!(fetched_at_b.is_some(), "the moved pin keeps fetched_at");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("moved dependency closure"),
        "rebuild must report the moved pin: {combined}"
    );

    // The farm serves the NEW closure content.
    let out = run_farm_app(&current_farm(root.path(), "default"), "zrapp");
    assert!(
        out.contains("latest-dep-v2"),
        "farm serves the moved closure: {out:?}"
    );
});

gated_test!(rebuild_bypasses_hold_at_pinned_version, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zrapp",
        "hold-dep",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let fetches_before = requests_for(&log, "/registry/");

    // Collection drift: the package now resolves 2.0 while the pin
    // holds 1.0.
    let lua_path = project.path().join("pkgs/z/zrapp.lua");
    let lua = std::fs::read_to_string(&lua_path)
        .unwrap()
        .replace("version = \"1.0\"", "version = \"2.0\"");
    std::fs::write(&lua_path, lua).unwrap();

    // A plain sync HOLDS the package: no rebuild, no re-fetch, pin
    // untouched (a no-change reconcile is a no-op).
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    let sync_out = format!("{stdout}{stderr}");
    assert!(
        sync_out.contains("already matches its declaration"),
        "held sync must be a no-op: {sync_out}"
    );
    assert_eq!(
        lock_version_pin(root.path(), "default", "zrapp").as_deref(),
        Some("1.0"),
        "sync must hold the package at its pin"
    );
    assert_eq!(
        requests_for(&log, "/registry/"),
        fetches_before,
        "held sync must not re-fetch"
    );

    // The rebuild bypasses the hold AT THE PIN: success, still 1.0 —
    // rebuilt at the pinned version, not drifted to 2.0.
    let (code, stdout, stderr) = run(project.path(), root.path(), &["pod", "rebuild", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}\nstdout: {stdout}");
    assert_eq!(
        lock_version_pin(root.path(), "default", "zrapp").as_deref(),
        Some("1.0"),
        "rebuild must rebuild at the pinned version, not move to 2.0"
    );
    assert_eq!(
        requests_for(&log, "/registry/"),
        fetches_before,
        "rebuild at the pin must reuse the cached closure"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("(1.0)"),
        "rebuild reports the pinned version: {combined}"
    );
});

gated_test!(rebuild_unknown_package_fails_without_writes, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zrapp",
        "unknown-dep",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zrapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let lock_path = pod_dir(root.path(), "default").join("shuttle.lock");
    let before = std::fs::read(&lock_path).unwrap();

    let (code, stdout, stderr) = run(
        project.path(),
        root.path(),
        &["pod", "rebuild", "notdeclared"],
    );
    assert_ne!(
        code,
        Some(0),
        "rebuild of an undeclared package must fail: {stdout}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("is not in pod"),
        "error must name the undeclared package: {combined}"
    );
    let after = std::fs::read(&lock_path).unwrap();
    assert_eq!(
        before, after,
        "a failed rebuild must not write the lockfile"
    );
});

// ── Degraded reconcile (issue #16): fail closed + no wipe ──
//
// `pod sync`/`pod rebuild` without the squashfs pair used to run the
// removal phase against an EMPTY declared set, wiping every installed
// package generation by generation. Build-capable verbs must fail
// closed; the removal flow must keep working without the wipe.

/// Run shuttle with an EMPTY PATH: `find_on_path` resolves nothing, so
/// the reconcile runs degraded (no squashfs pair). The binary is
/// invoked by absolute path; degraded paths exec no external tools, so
/// the empty PATH is safe for the assertion phase.
fn run_degraded(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("PATH", "");
    let out = cmd.output().expect("failed to spawn shuttle");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The sorted entry names of the pod's active bin farm.
fn farm_listing(farm: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(farm)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The invariants a degraded verb must leave untouched: the
/// active-generation link, the farm listing, and the lockfile bytes.
fn snapshot_pod(root: &Path, pod: &str) -> (PathBuf, Vec<String>, Vec<u8>) {
    let link = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    let farm = farm_listing(&current_farm(root, pod));
    assert!(
        !farm.is_empty(),
        "fixture must be installed before degrading"
    );
    let lock = std::fs::read(pod_dir(root, pod).join("shuttle.lock")).unwrap();
    (link, farm, lock)
}

gated_test!(
    degraded_rebuild_fails_closed_leaving_generation_and_farm_intact,
    &["node"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, _log) = serve_dir(server.path());
        write_npm_pkg(
            project.path(),
            server.path(),
            "zdgapp",
            "degraded-a",
            port,
            false,
        );

        // Install with the full toolchain present.
        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdgapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        let (link, farm, lock) = snapshot_pod(root.path(), "default");
        let lock_path = pod_dir(root.path(), "default").join("shuttle.lock");

        // Degraded rebuild: must FAIL CLOSED, touching nothing.
        let (code, stdout, stderr) =
            run_degraded(project.path(), root.path(), &["pod", "rebuild", "zdgapp"]);
        assert_ne!(code, Some(0), "degraded rebuild must fail: {stdout}");
        let combined = format!("{stdout}{stderr}");
        assert!(
            combined.contains("mksquashfs"),
            "failure must name the missing squashfs tools: {combined}"
        );
        assert_eq!(
            std::fs::read_link(pod_dir(root.path(), "default").join("current")).unwrap(),
            link,
            "degraded rebuild must not move the active generation"
        );
        assert_eq!(
            farm_listing(&current_farm(root.path(), "default")),
            farm,
            "degraded rebuild must not churn the bin farm"
        );
        assert_eq!(
            std::fs::read(&lock_path).unwrap(),
            lock,
            "degraded rebuild must not write the lockfile"
        );

        // SAFETY: the degraded run execs nothing, least of all lifecycle scripts.
        assert_no_canary(&[project.path(), root.path(), server.path()]);
    }
);

gated_test!(degraded_sync_fails_closed_the_same_way, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());
    write_npm_pkg(
        project.path(),
        server.path(),
        "zdsapp",
        "degraded-s",
        port,
        false,
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdsapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (link, farm, lock) = snapshot_pod(root.path(), "default");
    let lock_path = pod_dir(root.path(), "default").join("shuttle.lock");

    // Degraded sync: the same fail-closed contract as rebuild.
    let (code, stdout, stderr) = run_degraded(project.path(), root.path(), &["pod", "sync"]);
    assert_ne!(code, Some(0), "degraded sync must fail: {stdout}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("mksquashfs"),
        "failure must name the missing squashfs tools: {combined}"
    );
    assert_eq!(
        std::fs::read_link(pod_dir(root.path(), "default").join("current")).unwrap(),
        link,
        "degraded sync must not move the active generation"
    );
    assert_eq!(
        farm_listing(&current_farm(root.path(), "default")),
        farm,
        "degraded sync must not churn the bin farm"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock,
        "degraded sync must not write the lockfile"
    );
});

gated_test!(degraded_remove_still_works_without_wiping, &["node"], {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let (port, _log) = serve_dir(server.path());

    // Two node fixture packages. The second fixture rewrites the shared
    // dep tarball, so install order matters: A's closure is already in
    // the content-addressed store (pin-verified) when B's fixture lands.
    write_npm_pkg(
        project.path(),
        server.path(),
        "zdaapp",
        "removed-a-ran",
        port,
        false,
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdaapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    write_npm_pkg(
        project.path(),
        server.path(),
        "zdbapp",
        "kept-b-ran",
        port,
        false,
    );
    let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdbapp"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let farm = current_farm(root.path(), "default");
    assert!(farm_listing(&farm).contains(&"zdaapp".to_string()));
    assert!(farm_listing(&farm).contains(&"zdbapp".to_string()));

    // Degraded remove: must succeed (removals never unpack) WITHOUT
    // wiping the still-declared package.
    let (code, stdout, stderr) =
        run_degraded(project.path(), root.path(), &["pod", "remove", "zdaapp"]);
    assert_eq!(code, Some(0), "degraded remove must work: {stderr}{stdout}");

    // The new generation dropped ONLY pkg-a: the farm no longer exposes
    // it, pkg-b is still exposed AND still executes through the farm.
    let farm = current_farm(root.path(), "default");
    let listing = farm_listing(&farm);
    assert!(
        !listing.contains(&"zdaapp".to_string()),
        "removed package must leave the farm: {listing:?}"
    );
    assert!(
        listing.contains(&"zdbapp".to_string()),
        "declared package must survive the degraded remove: {listing:?}"
    );
    let out = run_farm_app(&farm, "zdbapp");
    assert!(
        out.contains("kept-b-ran"),
        "surviving package must still execute: {out:?}"
    );
    // The active-generation link still resolves — the chain did not
    // collapse to an empty generation.
    assert!(pod_dir(root.path(), "default").join("current").exists());

    // SAFETY: nothing executed a dependency lifecycle script on the host.
    assert_no_canary(&[project.path(), root.path(), server.path()]);
});

gated_test!(
    degraded_remove_warns_only_for_uninstalled_declared,
    &["node"],
    {
        let project = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let server = tempfile::tempdir().unwrap();
        let (port, _log) = serve_dir(server.path());

        write_npm_pkg(
            project.path(),
            server.path(),
            "zdaapp",
            "a-ran",
            port,
            false,
        );
        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdaapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");
        write_npm_pkg(
            project.path(),
            server.path(),
            "zdbapp",
            "b-ran",
            port,
            false,
        );
        let (code, _, stderr) = run(project.path(), root.path(), &["pod", "add", "zdbapp"]);
        assert_eq!(code, Some(0), "stderr: {stderr}");

        // Hand-edit the declaration (allowed; malformed fails validation) to
        // declare a third package that was never installed — no fixture, no
        // build: the degraded path records declared names WITHOUT resolving.
        let pod_lua = pod_dir(root.path(), "default").join("pod.lua");
        std::fs::write(
        &pod_lua,
        "-- Pod declaration, maintained by `shuttle pod add/remove`.\npod {\n    packages = { \"zdaapp\", \"zdbapp\", \"zdcapp\" },\n}\n",
    )
    .unwrap();

        // Degraded remove of the installed zdaapp: exit 0, and the warning
        // names ONLY the genuinely-uninstalled zdcapp — zdbapp is installed
        // and must not be called out.
        let (code, stdout, stderr) =
            run_degraded(project.path(), root.path(), &["pod", "remove", "zdaapp"]);
        assert_eq!(code, Some(0), "degraded remove must work: {stderr}{stdout}");
        assert!(
            stderr.contains("declared but not installed: zdcapp"),
            "warning must name the missing package: {stderr}"
        );
        assert!(
            !stderr.contains("zdbapp"),
            "installed package must not be flagged missing: {stderr}"
        );

        let farm = current_farm(root.path(), "default");
        let listing = farm_listing(&farm);
        assert!(!listing.contains(&"zdaapp".to_string()), "{listing:?}");
        assert!(listing.contains(&"zdbapp".to_string()), "{listing:?}");
        let out = run_farm_app(&farm, "zdbapp");
        assert!(out.contains("b-ran"), "{out:?}");

        // SAFETY: nothing executed a dependency lifecycle script on the host.
        assert_no_canary(&[project.path(), root.path(), server.path()]);
    }
);
