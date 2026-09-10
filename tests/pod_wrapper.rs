//! `shuttle pod` build-time wrapper integration tests (issue #9).
//!
//! An interpreter-based package (its real entrypoint is a script, not a
//! standalone ELF) is exposed through the pod farm by a launcher wrapper
//! authored into the store payload at BUILD time — the nix
//! `makeWrapper`/`wrapProgram` analogy. The farm stays direct-symlink-only:
//! `current/bin/<tool>` symlinks to the wrapper blob, and running it
//! single-`exec`s the interpreter + script path. Native-ELF packages get no
//! wrapper.
//!
//! Drives the real binary end to end through the FULL chain (pod add →
//! farm → execute), with all state (project dir, pod root) in tempdirs —
//! never the real home. Same gating + loopback-source-server patterns as
//! `tests/pod_install.rs`.

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

/// Pack a tiny source tarball the fixture build downloads (content is
/// irrelevant to the build; created ONCE per test so every sync serves
/// identical bytes).
fn make_tarball(server_dir: &Path, name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("README"), "fixture source\n").unwrap();
    std::fs::write(
        pkg.join("hello.c"),
        "#include <stdio.h>\nint main(void){ printf(\"native-elf-ran\\n\"); return 0; }\n",
    )
    .unwrap();
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

/// Pack a source tree carrying an interpreter entrypoint script (so a build
/// can copy it from `$SRC` rather than embedding interpreter words in the
/// shell command, which the sandbox pre-flight would mistake for PATH tools).
fn make_interpreter_tarball(server_dir: &Path, name: &str, app: &str) {
    std::fs::create_dir_all(server_dir.join(name)).unwrap();
    std::fs::write(
        server_dir.join(name).join(app),
        "#!/usr/bin/env python3\nimport sys\nprint('py-tool-ran', *sys.argv[1:])\n",
    )
    .unwrap();
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

/// A "Python-style" package: `build` emits only a script entrypoint
/// (`bin/<bin>`), and the app declares an interpreter so the build-time
/// wrapper is authored (issue #9).
fn write_pkg_interpreter(project: &Path, name: &str, app: &str, port: u16, tarball: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin && cp $SRC/{app} $STAGE/bin/{app} && chmod +x $STAGE/bin/{app}",
    apps = {{ {app} = {{ command = "bin/{app}", interpreter = "python3" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

/// A native-ELF package: `build` compiles a tiny C program (links only the
/// system C library) into `$STAGE/bin/<bin>`. Even with an `interpreter`
/// declared, an ELF command binary must get NO wrapper (issue #9).
fn write_pkg_elf(project: &Path, name: &str, app: &str, port: u16, tarball: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin && gcc -o $STAGE/bin/{app} $SRC/hello.c && chmod +x $STAGE/bin/{app}",
    apps = {{ {app} = {{ command = "bin/{app}", interpreter = "python3" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners / helpers ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
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

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

/// The farm directory behind `current`.
fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let target = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

/// Resolve a farm entry's link chain to its ABSOLUTE, normalized target
/// file (the store blob the farm symlink points at).
fn farm_entry_target(farm: &Path, name: &str) -> PathBuf {
    std::fs::canonicalize(farm.join(name)).expect("farm entry must resolve to existing content")
}

/// Byte contents of a blob/string file.
fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

/// Extract the script store path from a wrapper's `exec "<interpreter>"
/// "<script>" "$@"` line (the second double-quoted argument).
fn extract_script_path(wrapper: &str, interpreter: &str) -> String {
    let exec_line = wrapper
        .lines()
        .find(|l| l.trim_start().starts_with("exec ") && l.contains(interpreter))
        .unwrap_or_else(|| panic!("no exec line for interpreter {interpreter} in: {wrapper}"));
    // Split on the quoted arguments and take the second double-quoted token.
    let quoted: Vec<&str> = exec_line
        .split('"')
        .enumerate()
        .filter(|(i, _)| *i % 2 == 1)
        .map(|(_, s)| s)
        .collect();
    assert!(
        quoted.len() >= 2,
        "wrapper exec line has too few args: {exec_line}"
    );
    quoted[1].to_string()
}

/// Run `farm/<name>` with the farm prepended to the current PATH (the
/// interpreter resolves through that PATH), returning stdout.
fn run_farm_binary(farm: &Path, name: &str, extra_args: &[&str]) -> String {
    let mut cmd = Command::new(farm.join(name));
    cmd.args(extra_args);
    let path = format!(
        "{}:{}",
        farm.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path);
    let out = cmd.output().expect("spawn farm entry");
    assert!(
        out.status.success(),
        "farm entry {name} must run successfully (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ── Acceptance: interpreter package → build-time wrapper → farm → execute ──

gated_test!(interpreter_package_builds_wrapper_and_farm_execs_it, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = project.path().join("server");
    make_interpreter_tarball(&server, "pytool", "pytool");
    let port = serve_dir(&server);
    write_pkg_interpreter(project.path(), "pytool", "pytool", port, "pytool.tar.gz");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "pytool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // The farm exposes the app as a DIRECT symlink into the store.
    let farm = current_farm(root.path(), "default");
    assert!(
        farm.join("pytool").exists(),
        "farm must expose the app: {farm:?}"
    );
    let target = farm_entry_target(&farm, "pytool");
    let store_dir = std::fs::canonicalize(pod_dir(root.path(), "default").join("store")).unwrap();
    assert!(
        target.starts_with(&store_dir),
        "farm entry must resolve into the store, not a shim: {target:?}"
    );

    // The blob the farm points at is the BUILD-TIME WRAPPER: a shell
    // launcher that single-`exec`s the interpreter with the script's store
    // path. (The wrapper was authored at build time into the payload; the
    // farm did NOT create it.)
    let wrapper = read_bytes(&target);
    let wrapper_text = String::from_utf8_lossy(&wrapper);
    assert!(
        wrapper_text.starts_with("#!/bin/sh"),
        "farm blob must be the launcher wrapper, got: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("exec \"python3\""),
        "wrapper must single-exec the interpreter: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("/store/"),
        "wrapper must reference the script's content-addressed store path: {wrapper_text:?}"
    );

    // Exactly ONE exec line — no lingering fork wrapper.
    assert_eq!(
        wrapper_text
            .lines()
            .filter(|l| l.trim_start().starts_with("exec "))
            .count(),
        1,
        "wrapper must contain exactly one exec: {wrapper_text:?}"
    );

    // The wrapper's baked script path must be a REAL store blob (the
    // original script, preserved in the payload and content-addressed).
    let script_store_path = extract_script_path(&wrapper_text, "python3");
    assert!(
        std::path::Path::new(&script_store_path).is_file(),
        "wrapper must reference an existing store script blob: {script_store_path:?}"
    );

    // The manifest records the app → store content mapping; the farm blob
    // it names is the wrapper (the SHA of the blob the farm symlink targets).
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            pod_dir(root.path(), "default").join("generations/1/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let app_hash = manifest["packages"]["pytool"]["apps"]["pytool"]
        .as_str()
        .unwrap();
    assert_eq!(
        app_hash,
        target.file_name().unwrap().to_str().unwrap(),
        "manifest must record the app's store content (the wrapper blob)"
    );

    // Running the farm binary executes the tool via the single exec — args
    // forwarded.
    let out = run_farm_binary(&farm, "pytool", &["alpha", "beta"]);
    assert!(
        out.contains("py-tool-ran alpha beta"),
        "farm binary must execute the interpreter tool with args forwarded: {out:?}"
    );
});

gated_test!(native_elf_package_gets_no_wrapper, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "elftool");
    write_pkg_elf(project.path(), "elftool", "elftool", port, "elftool.tar.gz");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "elftool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let farm = current_farm(root.path(), "default");
    assert!(farm.join("elftool").exists(), "farm must expose the app");
    let target = farm_entry_target(&farm, "elftool");

    // The farm blob is the REAL ELF binary (not a wrapper), even though the
    // app declares an interpreter.
    let bytes = read_bytes(&target);
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "native-ELF command binary must stay a real ELF, got magic: {:02x?}",
        &bytes[..4.min(bytes.len())]
    );

    // It EXECUTES as the real ELF (compiled from $SRC/hello.c) — not via a
    // wrapper.
    let out = run_farm_binary(&farm, "elftool", &[]);
    assert!(
        out.contains("native-elf-ran"),
        "native ELF farm binary must execute directly: {out:?}"
    );
});
