//! Toolchain-meta pod install tests (issue #38).
//!
//! The toolchain meta carries no payload of its own: its build stages
//! the merged build prefix (`requires` payloads, `/shuttle-build-prefix`)
//! into a self-contained subtree and exposes apps through root launcher
//! scripts, so the farm assembly (#37) carries the whole subtree beside
//! each launcher. These tests drive that machinery end to end at pod
//! scale — a tiny `dep` payload plays the toolchain pieces, a meta
//! stages it into `toolchain/` and declares a launcher app, and the pod
//! farm entry must execute the staged binary through the launcher —
//! plus the alias entry contract (`shuttle pod add <alias>` resolves a
//! re-export to the canonical package).
//!
//! Same gates and shape as `pod_install.rs`: real snap builds over a
//! loopback source server, tempdir pod root, host home untouched.

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

/// Pack a tiny tarball the fixture builds download (bytes never used).
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

// ── Fixtures ──

/// The dependency playing "toolchain pieces": a staged usr tree with a
/// runnable script in usr/bin and a data file in usr/lib — the shape a
/// merged prefix presents to a staging meta build.
fn write_dep_pkg(project: &Path, port: u16) {
    let dir = project.join("pkgs/d");
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "dep",
    version = "1.0",
    source = "http://127.0.0.1:{port}/dep.tar.gz",
    build = "mkdir -p $STAGE/usr/bin $STAGE/usr/lib && printf '#!/bin/sh\\necho staged-marker\\n' > $STAGE/usr/bin/hello && chmod +x $STAGE/usr/bin/hello && echo data > $STAGE/usr/lib/libhelper.a",
}} }}
"#
    );
    std::fs::write(dir.join("dep.lua"), lua).unwrap();
}

/// The toolchain-shaped meta: stages the merged prefix into
/// `toolchain/`, authors a launcher at the subtree root (the #37/#46
/// pattern — the assembly captures everything under the launcher's
/// directory), and exposes it as an app.
fn write_meta_pkg(project: &Path, port: u16) {
    let dir = project.join("pkgs/m");
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "metatool",
    version = "1.0",
    type = "meta",
    requires = {{ "dep" }},
    source = "http://127.0.0.1:{port}/dep.tar.gz",
    build = "mkdir -p $STAGE/toolchain && cp -a /shuttle-build-prefix/. $STAGE/toolchain/ && printf '#!/bin/sh\\np=$(readlink -f -- \"$0\") || exit 1\\nd=$(dirname -- \"$p\")\\nexec \"$d/usr/bin/hello\" \"$@\"\\n' > $STAGE/toolchain/hello && chmod +x $STAGE/toolchain/hello",
    apps = {{ hello = {{ command = "toolchain/hello" }} }},
}} }}
"#
    );
    std::fs::write(dir.join("metatool.lua"), lua).unwrap();
}

/// The alias entry: a thin re-export resolving to the canonical meta —
/// the `pkgs/t/toolchain.lua` contract at fixture scale.
fn write_alias_pkg(project: &Path) {
    let dir = project.join("pkgs/m");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("metatool-alias.lua"),
        "local canon = require(\"m/metatool\")\nreturn { default = canon.default }\n",
    )
    .unwrap();
}

// ── Runners ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("SHUTTLE_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn farm(root: &Path, pod: &str) -> PathBuf {
    root.join(pod).join("current")
}

/// Execute one farm entry and return its stdout (exit status asserted
/// by the caller when it matters).
fn run_farm_entry(root: &Path, pod: &str, entry: &str) -> (Option<i32>, String) {
    let out = Command::new(farm(root, pod).join(entry))
        .env("SHUTTLE_DATA_HOME", root.join("data-home"))
        .env("SHUTTLE_SYSTEMD", "off")
        .output()
        .expect("failed to run farm entry");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

// ── Tests ──

gated_test!(meta_staged_app_runs_from_farm, {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let root = tmp.path().join("podroot");
    std::fs::create_dir_all(&project).unwrap();

    let server_dir = tmp.path().join("srv");
    std::fs::create_dir_all(&server_dir).unwrap();
    make_tarball(&server_dir, "dep");
    let port = serve_dir(&server_dir);

    write_dep_pkg(&project, port);
    write_meta_pkg(&project, port);

    let (code, stdout, stderr) = run(&project, &root, &["--name", "t38", "add", "metatool"]);
    assert_eq!(code, Some(0), "pod add metatool failed: {stderr}");
    assert!(stdout.contains("metatool"), "{stdout}");

    // The farm entry is the launcher; running it must execute the
    // STAGED dependency binary the assembly carried beside it.
    let (run_code, out) = run_farm_entry(&root, "t38", "hello");
    assert_eq!(run_code, Some(0), "farm entry failed");
    assert_eq!(out, "staged-marker\n", "{out}");

    // The assembly subtree, not a bare store blob: the farm link must
    // point into the package's assembly area (multi-file app).
    let link = std::fs::read_link(farm(&root, "t38").join("hello")).unwrap();
    let link = link.to_string_lossy().into_owned();
    assert!(
        link.starts_with("../apps/metatool/"),
        "farm link should target the assembly subtree, got: {link}"
    );
});

gated_test!(alias_entry_resolves_to_canonical_package, {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let root = tmp.path().join("podroot");
    std::fs::create_dir_all(&project).unwrap();

    let server_dir = tmp.path().join("srv");
    std::fs::create_dir_all(&server_dir).unwrap();
    make_tarball(&server_dir, "dep");
    let port = serve_dir(&server_dir);

    write_dep_pkg(&project, port);
    write_meta_pkg(&project, port);
    write_alias_pkg(&project);

    // `add` through the alias: resolution, store payload, and farm all
    // come from the canonical package.
    let (code, _stdout, stderr) = run(
        &project,
        &root,
        &["--name", "alias", "add", "metatool-alias"],
    );
    assert_eq!(code, Some(0), "pod add metatool-alias failed: {stderr}");

    // The pod keeps the DECLARED spec (the alias), and the farm serves
    // the canonical payload's app. (`pod list` renders to stderr.)
    let (_, list_out, list_err) = run(&project, &root, &["--name", "alias", "list"]);
    let list = format!("{list_out}{list_err}");
    assert!(list.contains("metatool-alias"), "{list}");
    let (run_code, out) = run_farm_entry(&root, "alias", "hello");
    assert_eq!(run_code, Some(0), "farm entry via alias failed");
    assert_eq!(out, "staged-marker\n", "{out}");
});
