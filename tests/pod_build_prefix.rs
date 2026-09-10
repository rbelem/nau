//! Pod build-path ADR-0018 wiring integration tests (issue #35).
//!
//! Two properties, both through the real binary with fully isolated
//! state (tempdir project for package resolution, tempdir `--root` pod
//! state, loopback-only HTTP — the established pod test patterns):
//!
//! 1. Merged build prefix + requires closure: a pod package whose
//!    `requires` name pool libraries builds against the merged
//!    `/usr`-like prefix (headers + link libs visible at
//!    `$SHUTTLE_BUILD_PREFIX`), and its transitive requires closure is
//!    resolved, built, and INSTALLED into the pod so the generation and
//!    the farm carry it. The dependency chain is two levels deep — the
//!    middle dependency itself builds against the prefix — proving the
//!    prefix machinery applies recursively to dep payloads too.
//!
//! 2. Leak scan on the pod build path (ADR-0018 Decision 3): a pod
//!    package that bakes a `/shuttle-build-prefix` RUNPATH into its
//!    binary FAILS `pod add`; declaring the hit in `leaks_ok` makes the
//!    build pass (visibly logged). Pod-built payloads carry no
//!    build-only references.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Gating (same skip pattern as the other pod integration tests) ──

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

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            if !chain_available() {
                eprintln!("skipping: mksquashfs/unsquashfs/curl/tar/gcc unavailable");
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

fn make_tarball(server_dir: &Path, files: &[(&str, &str)], name: &str) {
    let pkg = server_dir.join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    for (rel, content) in files {
        let p = pkg.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
    }
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

/// `libfoo`: leaf shared library + header. Nothing of its own to link.
fn write_libfoo(project: &Path, port: u16) {
    make_tarball(
        &project.join("srcs"),
        &[
            ("libfoo.c", "int foo_value(void){return 42;}\n"),
            ("libfoo.h", "int foo_value(void);\n"),
        ],
        "libfoo",
    );
    let dir = project.join("pkgs").join("l");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("libfoo.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "libfoo",
    version = "1.0",
    source = "http://127.0.0.1:{port}/libfoo.tar.gz",
    build = "mkdir -p $STAGE/usr/lib $STAGE/usr/include && gcc -shared -fPIC -Wl,-soname,libfoo.so.1 -o $STAGE/usr/lib/libfoo.so.1 $SRC/libfoo.c && cp $SRC/libfoo.h $STAGE/usr/include/ && ln -s libfoo.so.1 $STAGE/usr/lib/libfoo.so",
    architectures = {{ "amd64" }},
}} }}

"#,
        ),
    )
    .unwrap();
}

/// `libbar`: depends on libfoo at build time (its source includes
/// libfoo.h) and declares `requires = { "libfoo" }` — building it via the
/// pod path must materialize libfoo's payload into the merged prefix.
fn write_libbar(project: &Path, port: u16) {
    make_tarball(
        &project.join("srcs"),
        &[
            (
                "libbar.c",
                "#include \"libfoo.h\"\nint bar_value(void){return foo_value()+1;}\n",
            ),
            ("libbar.h", "int bar_value(void);\n"),
        ],
        "libbar",
    );
    let dir = project.join("pkgs").join("l");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("libbar.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "libbar",
    version = "1.0",
    source = "http://127.0.0.1:{port}/libbar.tar.gz",
    build = "mkdir -p $STAGE/usr/lib $STAGE/usr/include && gcc -shared -fPIC -Wl,-soname,libbar.so.1 -o $STAGE/usr/lib/libbar.so.1 $SRC/libbar.c -I$SHUTTLE_BUILD_PREFIX/usr/include -L$SHUTTLE_BUILD_PREFIX/usr/lib -lfoo && cp $SRC/libbar.h $STAGE/usr/include/ && ln -s libbar.so.1 $STAGE/usr/lib/libbar.so",
    architectures = {{ "amd64" }},
    requires = {{ "libfoo" }},
    -- The nix gcc wrapper bakes every -L path into RUNPATH (issue #22
    -- escape, same rationale as the lua/htop pool fixtures).
    leaks_ok = {{ "/shuttle-build-prefix/usr/lib", "/shuttle-build-prefix/usr/lib64" }},
}} }}

"#,
        ),
    )
    .unwrap();
}

/// `mytool`: the pod's declared package. Links both libraries via the
/// merged prefix and stages their `.so` files into its own payload so the
/// dynamic loader resolves them at pod runtime (the #10 wrapper story).
/// `requires = { "libbar" }` — transitive closure pulls libfoo.
fn write_mytool(project: &Path, port: u16) {
    make_tarball(
        &project.join("srcs"),
        &[(
            "main.c",
            "#include <stdio.h>\n#include \"libbar.h\"\nint main(void){printf(\"%d\\n\", bar_value());return 0;}\n",
        )],
        "mytool",
    );
    let dir = project.join("pkgs").join("m");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("mytool.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "mytool",
    version = "1.0",
    source = "http://127.0.0.1:{port}/mytool.tar.gz",
    build = "mkdir -p $STAGE/usr/bin $STAGE/usr/lib && gcc -o $STAGE/usr/bin/mytool $SRC/main.c -I$SHUTTLE_BUILD_PREFIX/usr/include -L$SHUTTLE_BUILD_PREFIX/usr/lib -lbar -lfoo && cp $SHUTTLE_BUILD_PREFIX/usr/lib/libbar.so.1 $SHUTTLE_BUILD_PREFIX/usr/lib/libfoo.so.1 $STAGE/usr/lib/",
    architectures = {{ "amd64" }},
    requires = {{ "libbar" }},
    -- The staged runtime copies carry libbar's nix-wrapper RUNPATH (see
    -- libbar; issue #22 escape, same rationale as the lua pool fixture).
    leaks_ok = {{ "/shuttle-build-prefix/usr/lib", "/shuttle-build-prefix/usr/lib64" }},
    apps = {{
        mytool = {{ command = "usr/bin/mytool" }},
    }},
}} }}

"#
        ),
    )
    .unwrap();
}

/// The leaking variant: links the build-only library but does NOT stage
/// it, so its `DT_NEEDED` soname resolves ONLY into a build-only payload
/// at runtime. (The RUNPATH vector is already defended on the pod path:
/// the #12 portability repair scrubs RUNPATH before the scan runs.) The
/// leak scan must fail the pod build. `leaks_ok` silences the hit by its
/// exact reference — the soname.
fn write_leaker(project: &Path, port: u16, leaks_ok: &[&str]) {
    make_tarball(
        &project.join("srcs"),
        &[(
            "main.c",
            "#include <stdio.h>\n#include \"libbar.h\"\nint main(void){printf(\"%d\\n\", bar_value());return 0;}\n",
        )],
        "leaker",
    );
    let leak_lines: String = if leaks_ok.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = leaks_ok.iter().map(|s| format!("{s:?}")).collect();
        format!("\n        leaks_ok = {{ {} }},", entries.join(", "))
    };
    let dir = project.join("pkgs").join("l");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("leaker.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "leaker",
    version = "1.0",
    source = "http://127.0.0.1:{port}/leaker.tar.gz",
    build = "mkdir -p $STAGE/usr/bin && gcc -o $STAGE/usr/bin/leaker $SRC/main.c -I$SHUTTLE_BUILD_PREFIX/usr/include -L$SHUTTLE_BUILD_PREFIX/usr/lib -lbar",
    architectures = {{ "amd64" }},
    build_deps = {{ "libbar" }},{leak_lines}
    apps = {{
        leaker = {{ command = "usr/bin/leaker" }},
    }},
}} }}

"#
        ),
    )
    .unwrap();
}

// ── Drivers ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // The desktop launcher surface writes to the user data home —
    // redirect it inside the test's tempdir, never the real home.
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    // Keep pod activation off the host systemd bus (no polkit prompt
    // locally, no silent "Access denied" on CI). Issue #66.
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

fn generation_dir(root: &Path, pod: &str, n: u64) -> PathBuf {
    pod_dir(root, pod).join("generations").join(n.to_string())
}

fn current_farm(root: &Path, pod: &str) -> PathBuf {
    let link = pod_dir(root, pod).join("current");
    let target = std::fs::read_link(&link).unwrap();
    if target.is_absolute() {
        target
    } else {
        link.parent().unwrap().join(target)
    }
}

fn run_farm_app(farm: &Path, app: &str) -> String {
    let out = Command::new(farm.join(app))
        .output()
        .expect("failed to run farm app");
    assert!(
        out.status.success(),
        "farm app '{app}' failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ── Tests ──

gated_test!(requires_closure_builds_installs_and_runs, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_libfoo(project.path(), port);
    write_libbar(project.path(), port);
    write_mytool(project.path(), port);

    // pod add: the declared package builds against the merged prefix (its
    // source includes libbar.h), the dep payloads build recursively the
    // same way (libbar includes libfoo.h), and the transitive requires
    // closure (libbar → libfoo) is resolved, built, and installed.
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "mytool"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("build prefix"),
        "the pod build must report the merged build prefix: {stderr}"
    );

    // The active generation carries the declared package AND both
    // closure members.
    let gen_tree = generation_dir(root.path(), "default", 1).join("extensions");
    for pkg in ["mytool", "libbar", "libfoo"] {
        assert!(
            gen_tree.join(pkg).exists(),
            "generation must contain closure member '{pkg}'"
        );
    }

    // The farm links the app; running it proves the build linked against
    // the prefix libs (bar_value = foo_value + 1 = 43).
    let farm = current_farm(root.path(), "default");
    assert!(farm.join("mytool").exists(), "farm must link mytool");
    assert_eq!(run_farm_app(&farm, "mytool"), "43");

    // A second sync is a no-op: closure members in the active generation
    // keep their store content — no new generation, no rebuild.
    let before = std::fs::read(pod_dir(root.path(), "default").join("shuttle.lock")).unwrap();
    let (code, _, stderr) = run(project.path(), root.path(), &["sync"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let after = std::fs::read(pod_dir(root.path(), "default").join("shuttle.lock")).unwrap();
    assert_eq!(before, after, "no-op sync must not touch the lockfile");
    let lock: serde_json::Value = serde_json::from_slice(&after).expect("valid JSON lockfile");
    assert!(
        lock["packages"].get("libbar").is_none() && lock["packages"].get("libfoo").is_none(),
        "closure members are not lockfile-pinned (lockfile semantics unchanged): {lock}"
    );
});

gated_test!(leak_scan_fails_leaking_pod_build, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_libfoo(project.path(), port);
    write_libbar(project.path(), port);
    write_leaker(project.path(), port, &[]);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "leaker"]);
    assert_ne!(code, Some(0), "a leaking pod build must fail");
    assert!(
        stderr.contains("libbar.so.1"),
        "the failure must name the leaking soname: {stderr}"
    );
    assert!(
        stderr.contains("libbar"),
        "the failure must name the build-only payload: {stderr}"
    );
});

gated_test!(leak_scan_leaks_ok_passes_pod_build, {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_libfoo(project.path(), port);
    write_libbar(project.path(), port);
    write_leaker(project.path(), port, &["libbar.so.1"]);

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "leaker"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("leak"),
        "the silenced leak must be visibly logged: {stderr}"
    );
});
