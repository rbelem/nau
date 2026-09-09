//! Post-build leak scan integration tests (ADR-0018 Decision 3, issue #22).
//!
//! Drives `shuttle build` over the real binary against a synthetic package
//! that links a library available only as a `build_dep` (and bakes a
//! `/shuttle-build-prefix` RUNPATH). The build fails with a precise message
//! naming the file, soname, and build-only payload; adding a `leaks_ok`
//! entry silences the hits (visibly logged) and the build passes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
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

// ── Fixtures ──

/// Pack `name`'s source into a tarball served over the loopback server.
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

/// Write a build-only dependency that stages `usr/lib/libfoo.so.1`.
fn write_libfoo(project: &Path, port: u16) {
    make_tarball(
        &project.join("srcs"),
        &[("libfoo.c", "int foo_value(void){return 42;}\n")],
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
    build = "mkdir -p $STAGE/usr/lib && gcc -shared -fPIC -Wl,-soname,libfoo.so.1 -o $STAGE/usr/lib/libfoo.so.1 $SRC/libfoo.c && ln -s libfoo.so.1 $STAGE/usr/lib/libfoo.so",
    architectures = {{ "amd64" }},
}} }}
"#
        ),
    )
    .unwrap();
}

/// Write the app package that links libfoo (build-only) and bakes a
/// `/shuttle-build-prefix` RUNPATH. `leaks_ok` lines optional.
fn write_app(project: &Path, port: u16, leaks_ok: &[&str]) {
    make_tarball(
        &project.join("srcs"),
        &[(
            "app.c",
            "int foo_value(void);\nint main(void){return foo_value()==42?0:1;}\n",
        )],
        "app",
    );
    let leak_lines: String = if leaks_ok.is_empty() {
        String::new()
    } else {
        let entries: Vec<String> = leaks_ok.iter().map(|s| format!("{s:?}")).collect();
        format!("\n        leaks_ok = {{ {} }},", entries.join(", "))
    };
    std::fs::write(
        project.join("app.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "app",
    version = "1.0",
    source = "http://127.0.0.1:{port}/app.tar.gz",
    build = "mkdir -p $STAGE/usr/bin && gcc -o $STAGE/usr/bin/app $SRC/app.c -L$SHUTTLE_BUILD_PREFIX/usr/lib -lfoo -Wl,-rpath,$SHUTTLE_BUILD_PREFIX/usr/lib",
    architectures = {{ "amd64" }},
    requires = {{}},
    build_deps = {{ "libfoo" }},{leak_lines}
    apps = {{
        app = {{ command = "usr/bin/app" }},
    }},
}} }}
"#
        ),
    )
    .unwrap();
}

fn run_build(project: &Path, output: &Path, stage: &Path) -> (Option<i32>, String, String) {
    std::fs::create_dir_all(output).unwrap();
    std::fs::create_dir_all(stage).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("build")
        .arg("--file")
        .arg("app.lua")
        .arg("--output")
        .arg(output)
        .arg("--stage")
        .arg(stage)
        .current_dir(project);
    let out = cmd.output().expect("failed to spawn shuttle build");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── Acceptance 1: build-only link → hard failure ──

gated_test!(
    build_linking_build_only_library_fails_with_precise_message,
    {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("srcs")).unwrap();
        let port = serve_dir(&project.path().join("srcs"));
        write_libfoo(project.path(), port);
        write_app(project.path(), port, &[]);

        let output = project.path().join("out");
        let stage = project.path().join("stg");
        let (code, _stdout, stderr) = run_build(project.path(), &output, &stage);

        assert_eq!(
            code,
            Some(1),
            "build with a build-only link must fail: {stderr}"
        );
        assert!(
            stderr.contains("libfoo.so.1"),
            "must name the soname: {stderr}"
        );
        assert!(
            stderr.contains("libfoo"),
            "must name the build-only payload: {stderr}"
        );
        assert!(
            stderr.contains("usr/bin/app"),
            "must name the leaking file: {stderr}"
        );
        assert!(
            stderr.contains("/shuttle-build-prefix"),
            "must name the merged build prefix marker: {stderr}"
        );
    }
);

// ── Acceptance 2: leaks_ok silences named hits, visibly logged ──

gated_test!(leaks_ok_silences_and_logs_then_build_passes, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_libfoo(project.path(), port);
    write_app(
        project.path(),
        port,
        &["/shuttle-build-prefix/usr/lib", "libfoo.so.1"],
    );

    let output = project.path().join("out");
    let stage = project.path().join("stg");
    let (code, _stdout, stderr) = run_build(project.path(), &output, &stage);

    assert_eq!(code, Some(0), "leaks_ok must allow the build: {stderr}");
    assert!(
        stderr.contains("leak scan: silenced"),
        "silenced hits are visibly logged: {stderr}"
    );
    assert!(
        stderr.contains("libfoo.so.1"),
        "the silenced entry names the soname: {stderr}"
    );
    assert!(
        output.join("app_1.0_amd64.snap").exists(),
        "the snap must have been produced"
    );
});

// Clean build (no build-only refs) emits the one success line.
gated_test!(clean_build_emits_success_line, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    // No build_deps, no prefix → nothing to leak.
    make_tarball(
        &project.path().join("srcs"),
        &[("app.c", "int main(void){return 0;}\n")],
        "app",
    );
    std::fs::write(
        project.path().join("app.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "app",
    version = "1.0",
    source = "http://127.0.0.1:{port}/app.tar.gz",
    build = "mkdir -p $STAGE/usr/bin && gcc -o $STAGE/usr/bin/app $SRC/app.c",
    architectures = {{ "amd64" }},
    apps = {{
        app = {{ command = "usr/bin/app" }},
    }},
}} }}
"#
        ),
    )
    .unwrap();

    let output = project.path().join("out");
    let stage = project.path().join("stg");
    let (code, _stdout, stderr) = run_build(project.path(), &output, &stage);

    assert_eq!(code, Some(0), "clean build must pass: {stderr}");
    assert!(
        stderr.contains("leak scan:"),
        "clean build emits the leak-scan line: {stderr}"
    );
    assert!(
        stderr.contains("0 build-only refs"),
        "0-build-only-refs success line present: {stderr}"
    );
});

// ── Acceptance: build_deps are pinned in the lockfile (ADR-0018 Decision 4) ──

gated_test!(build_records_build_dep_pin_in_lockfile, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_libfoo(project.path(), port);
    write_app(
        project.path(),
        port,
        &["/shuttle-build-prefix/usr/lib", "libfoo.so.1"],
    );

    let output = project.path().join("out");
    let stage = project.path().join("stg");
    let (code, _stdout, stderr) = run_build(project.path(), &output, &stage);
    assert_eq!(code, Some(0), "build must pass: {stderr}");

    // The lockfile records the build_dep pin (the lockfile IS the pin
    // record, ADR-0018 Decision 4).
    let lock_path = project.path().join("shuttle.lock");
    assert!(lock_path.exists(), "lockfile must be written");
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    assert!(
        lock.get("build_deps").is_some(),
        "lockfile must carry a build_deps section: {lock}"
    );
    assert!(
        lock["build_deps"].get("libfoo").is_some(),
        "lockfile must pin the libfoo build_dep: {lock}"
    );
    assert!(
        lock["build_deps"]["libfoo"]
            .get("pin")
            .map(|v| !v.is_null())
            .unwrap_or(false),
        "the build_dep pin records the resolved version: {lock}"
    );
});
