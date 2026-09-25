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

/// A CPython-shaped native-ELF package: like [`write_pkg_elf`] but the
/// build ALSO stages `lib/python3.10/` beside `bin/<bin>` — the
/// `stage_bundles_python_stdlib` trigger that routes the command into
/// `emit_elf_tree_wrapper` (the #210 gen-tree fallback under test).
fn write_pkg_elf_stdlib(project: &Path, name: &str, app: &str, port: u16, tarball: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/bin $STAGE/lib/python3.10 && gcc -o $STAGE/bin/{app} $SRC/hello.c && chmod +x $STAGE/bin/{app} && : > $STAGE/lib/python3.10/os.py",
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

/// Extract the script tree path from a wrapper's `TREE="$PODROOT/..."`
/// assignment — the primary target the #210 wrapper resolves (the exec
/// line carries the `$TREE` variable, not the literal path).
fn extract_script_path(wrapper: &str) -> String {
    let tree_line = wrapper
        .lines()
        .find(|l| l.trim_start().starts_with("TREE=\"$PODROOT"))
        .unwrap_or_else(|| panic!("no TREE assignment in wrapper: {wrapper}"));
    let quoted: Vec<&str> = tree_line.split('"').collect();
    assert!(
        quoted.len() >= 2,
        "TREE assignment has no quoted path: {tree_line}"
    );
    quoted[1].to_string()
}

/// Run `farm/<name>` with the farm prepended to the current PATH (the
/// interpreter resolves through that PATH), returning stdout.
fn run_farm_binary(farm: &Path, name: &str, extra_args: &[&str]) -> String {
    run_binary(&farm.join(name), extra_args)
}

/// Execute an arbitrary installed binary (farm entry or gen-tree wrapper)
/// with its own directory prepended to PATH, stdout on success.
fn run_binary(path: &Path, extra_args: &[&str]) -> String {
    let mut cmd = Command::new(path);
    cmd.args(extra_args);
    if let Some(dir) = path.parent() {
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
    }
    let out = cmd.output().expect("spawn binary");
    assert!(
        out.status.success(),
        "binary {} must run successfully (exit {:?}): {} {}",
        path.display(),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
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
        wrapper_text.contains("$PODROOT/active/extensions/pytool/usr/bin/pytool.real"),
        "wrapper must exec the script's extension-tree path (#94 tree \
         routing): {wrapper_text:?}"
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

    // The wrapper's baked script path must exist in the generation's
    // extension tree — the payload layout is mirrored there with the
    // preserved `.real` sibling beside the wrapper (#94 tree routing).
    // `$PODROOT` resolves to the pod state dir; `active` flips with
    // rollback, so assert through the same link the wrapper uses.
    let pod_root = pod_dir(root.path(), "default");
    let tree_script =
        extract_script_path(&wrapper_text).replace("$PODROOT", &pod_root.display().to_string());
    assert!(
        std::path::Path::new(&tree_script).is_file(),
        "wrapper must reference an existing extension-tree script: {tree_script:?}"
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

    // #210 regression: the SAME wrapper blob is hardlinked into the
    // generation tree at `generations/<n>/extensions/<pkg>/usr/bin/
    // <pkg>-<app>`. Invoked from there, the three-dirname PODROOT
    // derivation lands on the extension and the primary `$PODROOT/active`
    // target misses — the fallback must exec the payload root's own copy.
    let gen_wrapper = pod_dir(root.path(), "default")
        .join("generations/1/extensions/pytool/usr/bin/pytool-pytool");
    assert!(
        gen_wrapper.is_file(),
        "gen-tree wrapper must exist: {gen_wrapper:?}"
    );
    let out = run_binary(&gen_wrapper, &["alpha", "beta"]);
    assert!(
        out.contains("py-tool-ran alpha beta"),
        "gen-tree wrapper must execute the tool with args forwarded (#210): {out:?}"
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

// An ELF whose payload bundles a python stdlib tree takes the TREE
// wrapper (`emit_elf_tree_wrapper`, CPython stdlib self-located). The
// wrapper must run the real ELF from BOTH install sites: the farm's
// store blob (primary `$PODROOT/active` target) and the generation-tree
// hardlink (fallback to the payload root — #210, same gap the script
// tree wrapper closed).
gated_test!(elf_stdlib_tree_wrapper_resolves_gen_tree, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = project.path().join("server");
    make_tarball(&server, "pyelf");
    let port = serve_dir(&server);
    write_pkg_elf_stdlib(project.path(), "pyelf", "pyelf", port, "pyelf.tar.gz");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "pyelf"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let farm = current_farm(root.path(), "default");
    let target = farm_entry_target(&farm, "pyelf");
    let wrapper = read_bytes(&target);
    let wrapper_text = String::from_utf8_lossy(&wrapper);
    assert!(
        wrapper_text.starts_with("#!/bin/sh"),
        "stdlib-bundling ELF must take the tree wrapper: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("TREE=\"$PODROOT/active/extensions/pyelf/usr/bin/pyelf.real\""),
        "wrapper primary target must be the extension tree: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("[ -f \"$TREE\" ] || TREE="),
        "wrapper must carry the gen-tree fallback (#210): {wrapper_text:?}"
    );
    assert_eq!(
        wrapper_text
            .lines()
            .filter(|l| l.trim_start().starts_with("exec "))
            .count(),
        1,
        "wrapper must contain exactly one exec: {wrapper_text:?}"
    );

    // Farm path: the primary `$PODROOT/active/...` target resolves.
    let out = run_farm_binary(&farm, "pyelf", &[]);
    assert!(
        out.contains("native-elf-ran"),
        "farm tree wrapper must execute the real ELF: {out:?}"
    );

    // Gen-tree path: the primary misses, the fallback execs the payload
    // root's own `.real` copy (#210).
    let gen_wrapper =
        pod_dir(root.path(), "default").join("generations/1/extensions/pyelf/usr/bin/pyelf-pyelf");
    assert!(
        gen_wrapper.is_file(),
        "gen-tree wrapper must exist: {gen_wrapper:?}"
    );
    let out = run_binary(&gen_wrapper, &[]);
    assert!(
        out.contains("native-elf-ran"),
        "gen-tree wrapper must fall back to the payload root (#210): {out:?}"
    );
});
