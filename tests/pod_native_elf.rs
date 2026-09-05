//! `shuttle pod` native-ELF runtime-lib wrapper integration tests
//! (issue #10 part B) + the hermetic sandbox assertion (issue #10 part A).
//!
//! A package whose command binary is a native ELF that needs shared
//! libraries the payload itself ships (`libjq.so.1`, `libonig.so.5` for
//! jq) gets a build-time launcher wrapper (the #9 `makeWrapper` analogy,
//! extended to native ELF): the real ELF is preserved at a sibling
//! `.real` store blob and the command path is replaced by a wrapper that
//! sets `LD_LIBRARY_PATH` to the active generation's name-preserving lib
//! dir and single-`exec`s the real binary. Already-resolvable ELFs get NO
//! wrapper. The farm stays direct-symlink-only.
//!
//! Drives the real binary end to end through the FULL chain (pod add →
//! farm → execute), all state in tempdirs. Same gating + loopback-source
//! server patterns as `tests/pod_wrapper.rs`.

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
    ["mksquashfs", "unsquashfs", "curl", "tar", "gcc"]
        .iter()
        .all(|t| has_tool(t))
}

fn require_chain() {
    if !chain_available() {
        eprintln!("skipping: mksquashfs/unsquashfs/curl/tar/gcc unavailable");
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
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    data.extend_from_slice(&buf[..n]);
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

/// Host env vars to set on the shuttle invocation (to prove the hermetic
/// sandbox drops them).
#[derive(Default)]
struct RunOpts {
    env: Vec<(String, String)>,
}

/// Pack a source tarball carrying a tiny C app + a bundled shared library.
fn make_tarball(server_dir: &Path, name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("libfoo.c"), "int foo_value(void){ return 42; }\n").unwrap();
    std::fs::write(
        pkg.join("app.c"),
        "int foo_value(void);\nint main(void){return foo_value() == 42 ? 0 : 1;}\n",
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

/// A native-ELF package whose build emits `usr/bin/app` linking a bundled
/// `usr/lib/libfoo.so.1` (a separate store blob at runtime). Optional
/// `ldflags` is appended to the app link so a polluted `LDFLAGS` would
/// bake into the binary's RUNPATH were the sandbox not hermetic.
fn write_pkg(project: &Path, name: &str, port: u16, tarball: &str, ldflags: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
    build = "mkdir -p $STAGE/usr/lib $STAGE/usr/bin && gcc -shared -fPIC -Wl,-soname,libfoo.so.1 -o $STAGE/usr/lib/libfoo.so.1 $SRC/libfoo.c && cp $STAGE/usr/lib/libfoo.so.1 $STAGE/usr/lib/libfoo.so && gcc -o $STAGE/usr/bin/app $SRC/app.c -L$STAGE/usr/lib -lfoo {ldflags} && chmod +x $STAGE/usr/bin/app",
    apps = {{ app = {{ command = "usr/bin/app" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners / helpers ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    run_opts(project, root, args, &RunOpts::default())
}

fn run_opts(
    project: &Path,
    root: &Path,
    args: &[&str],
    opts: &RunOpts,
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
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

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let target = std::fs::read_link(pod_dir(root, pod).join("current")).unwrap();
    if target.is_absolute() {
        target
    } else {
        pod_dir(root, pod).join(target)
    }
}

fn farm_entry_target(farm: &Path, name: &str) -> PathBuf {
    std::fs::canonicalize(farm.join(name)).expect("farm entry must resolve to existing content")
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read file")
}

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

// ── Acceptance 1: native-ELF with bundled runtime libs → wrapper → farm → execute ──

gated_test!(native_elf_with_bundled_lib_builds_wrapper_and_farm_execs, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = project.path().join("server");
    make_tarball(&server, "nelf");
    let port = serve_dir(&server);
    write_pkg(project.path(), "nelf", port, "nelf.tar.gz", "");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "nelf"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let farm = current_farm(root.path(), "default");
    assert!(farm.join("app").exists(), "farm must expose the app");
    let target = farm_entry_target(&farm, "app");
    let store_dir = std::fs::canonicalize(pod_dir(root.path(), "default").join("store")).unwrap();
    assert!(
        target.starts_with(&store_dir),
        "farm entry must resolve into the store, not a shim: {target:?}"
    );

    // The farm blob is the BUILD-TIME WRAPPER (a shell launcher setting
    // LD_LIBRARY_PATH) — the real ELF is preserved as a `.real` sibling
    // store blob referenced by the wrapper's exec.
    let wrapper = read_bytes(&target);
    let wrapper_text = String::from_utf8_lossy(&wrapper);
    assert!(
        wrapper_text.starts_with("#!/bin/sh"),
        "native-ELF with bundled lib must be a launcher wrapper: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("LD_LIBRARY_PATH"),
        "wrapper must set LD_LIBRARY_PATH: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains("/active/extensions/nelf/usr/usr/lib"),
        "wrapper must point at the payload's name-preserving lib dir: {wrapper_text:?}"
    );
    assert!(
        wrapper_text.contains(".real") || wrapper_text.contains("/store/"),
        "wrapper must exec the real binary's store blob: {wrapper_text:?}"
    );

    // Run the farm binary — the wrapper's LD_LIBRARY_PATH lets the loader
    // find the bundled libfoo.so.1 store blob.
    let out = run_farm_binary(&farm, "app", &[]);
    // app.c exits 0 iff foo_value()==42; stdout empty is expected.
    assert!(out.is_empty(), "app should produce no output, got: {out:?}");
});

// ── Acceptance 2: already-resolvable native ELF gets NO wrapper ──

gated_test!(native_elf_without_bundled_lib_gets_no_wrapper, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    if !has_tool("sh") {
        eprintln!("skipping: /bin/sh not available");
        return;
    }
    // A tiny tarball so `$SRC` resolves (content unused by the build).
    std::fs::create_dir_all(server.path().join("emptytool")).unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            server.path().join("emptytool.tar.gz").to_str().unwrap(),
            "emptytool",
        ])
        .current_dir(server.path())
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");

    // A package whose build copies a system ELF (/bin/sh) — no bundled libs,
    // so it must get NO wrapper (issue #9 + #10: libs already resolvable).
    let dir = project.path().join("pkgs").join("e");
    std::fs::create_dir_all(&dir).unwrap();
    let lua = format!(
        r#"return {{ default = snap {{
    name = "etool",
    version = "1.0",
    source = "http://127.0.0.1:{port}/emptytool.tar.gz",
    build = "mkdir -p $STAGE/usr/bin && cp /bin/sh $STAGE/usr/bin/etool && chmod +x $STAGE/usr/bin/etool",
    apps = {{ etool = {{ command = "usr/bin/etool" }} }},
}} }}
"#
    );
    std::fs::write(dir.join("etool.lua"), lua).unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "etool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let farm = current_farm(root.path(), "default");
    let target = farm_entry_target(&farm, "etool");
    let bytes = read_bytes(&target);
    assert!(
        bytes.starts_with(b"\x7fELF"),
        "already-resolvable native ELF must stay a real ELF, got magic: {:02x?}",
        &bytes[..4.min(bytes.len())]
    );
    // No `<command>.real` sibling anywhere: the binary itself is the blob.
    assert!(
        !target.with_file_name("etool.real").is_file(),
        "no .real sibling for an already-resolvable ELF"
    );

    // It EXECUTES directly as the real ELF (a shell).
    let out = run_farm_binary(&farm, "etool", &["-c", "echo no-wrapper-ok"]);
    assert!(
        out.contains("no-wrapper-ok"),
        "native ELF farm binary must execute directly: {out:?}"
    );
});

// ── Acceptance 3: hermeticity — the sandbox drops inherited host env ──

gated_test!(hermetic_sandbox_drops_inherited_ldflags_pollution, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let server = project.path().join("server");
    make_tarball(&server, "nelf");
    let port = serve_dir(&server);
    // A hostile LDFLAGS pointing into a fake nix-shell-env; if the sandbox
    // inherited it, the linker would bake it into the app's RUNPATH.
    write_pkg(project.path(), "nelf", port, "nelf.tar.gz", "$LDFLAGS");
    let opts = RunOpts {
        env: vec![(
            "LDFLAGS".into(),
            "-Wl,-rpath,/nix/store/deadbeef-nix-shell-env/lib".into(),
        )],
    };

    let (code, _, stderr) = run_opts(project.path(), root.path(), &["add", "nelf"], &opts);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Find the real ELF (the `.real` store blob the wrapper execs) and
    // read its interpreter/RUNPATH — the inherited pollution must NOT be
    // present (env_clear dropped it).
    let farm = current_farm(root.path(), "default");
    let target = farm_entry_target(&farm, "app");
    let wrapper = String::from_utf8_lossy(&read_bytes(&target)).into_owned();
    let exec_line = wrapper
        .lines()
        .find(|l| l.trim_start().starts_with("exec \"") && l.contains("/store/"))
        .unwrap_or_else(|| panic!("no store exec line in wrapper: {wrapper}"));
    let real_blob = exec_line
        .split('"')
        .nth(1)
        .expect("wrapper exec line has a quoted real path");
    assert!(
        std::path::Path::new(real_blob).is_file(),
        "wrapper must exec an existing store blob: {real_blob:?}"
    );

    // Read the real ELF's dynamic section; the inherited deadbeef path must
    // not appear in RUNPATH, and the interpreter must not be the shell's
    // polluted nix-shell path.
    let out = Command::new("readelf")
        .args(["-d", real_blob])
        .output()
        .expect("readelf available");
    let dyn_text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !dyn_text.contains("deadbeef-nix-shell-env"),
        "built binary must not carry inherited LDFLAGS pollution: {dyn_text}"
    );
});
