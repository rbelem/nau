//! Default-stage concurrency lock integration tests (gate-pod gap 6).
//!
//! Two lanes once shared the default `./stage/` and a watcher caught the
//! stage inode flipping mid-build. Now a default-stage build takes a
//! cross-process flock (`stage.lock` next to `stage/`): a second
//! concurrent default-stage build refuses loudly, pointing at `--stage`.
//! Drives `shuttle build` over the real binary against a synthetic
//! package, exactly like tests/leak_scan.rs.

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
    ["mksquashfs", "curl", "tar"].iter().all(|t| has_tool(t))
}

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            if !chain_available() {
                eprintln!("skipping: mksquashfs/curl/tar unavailable");
                return;
            }
            $($body)*
        }
    };
}

// ── Loopback source server ──

fn serve_dir(dir: &Path) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = dir.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            if stream.read(&mut buf).is_err() {
                continue;
            }
            data.extend_from_slice(&buf);
            let req = String::from_utf8_lossy(&data);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let file = root.join(path.trim_start_matches('/'));
            let body = std::fs::read(&file).unwrap_or_else(|_| b"not found".to_vec());
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    port
}

// ── Fixtures ──

/// One-package project whose build script sleeps, then stages a file —
/// the sleep keeps the default-stage lock held long enough for a
/// concurrent build to collide with it deterministically.
fn write_project(project: &Path, port: u16, sleep_secs: u32) {
    let srcs = project.join("srcs");
    std::fs::create_dir_all(&srcs).unwrap();
    std::fs::write(srcs.join("hello.c"), "int main(void){return 0;}\n").unwrap();
    let status = Command::new("tar")
        .args([
            "czf",
            srcs.join("hello.tar.gz").to_str().unwrap(),
            "hello.c",
        ])
        .current_dir(&srcs)
        .status()
        .unwrap();
    assert!(status.success(), "tar failed");

    std::fs::write(
        project.join("shuttle.lua"),
        format!(
            r#"return {{ default = snap {{
    name = "hello",
    version = "1.0",
    source = "http://127.0.0.1:{port}/hello.tar.gz",
    build = "sleep {sleep_secs} && mkdir -p $STAGE/usr/bin && echo hello > $STAGE/usr/bin/hello",
    architectures = {{ "amd64" }},
}} }}
"#
        ),
    )
    .unwrap();
}

/// Spawn `shuttle build` in `project`; `extra` carries --stage/--output.
/// Returns a handle so tests can run builds concurrently.
fn spawn_build(
    project: PathBuf,
    out: PathBuf,
    extra: Vec<String>,
) -> std::thread::JoinHandle<(Option<i32>, String, String)> {
    std::thread::spawn(move || {
        std::fs::create_dir_all(&out).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
        cmd.arg("build")
            .arg("--output")
            .arg(&out)
            .args(&extra)
            .current_dir(&project);
        let result = cmd.output().expect("failed to spawn shuttle build");
        (
            result.status.code(),
            String::from_utf8_lossy(&result.stdout).into_owned(),
            String::from_utf8_lossy(&result.stderr).into_owned(),
        )
    })
}

// ── Acceptance 1: two concurrent default-stage builds → exactly one ──

gated_test!(two_concurrent_default_stage_builds_conflict_loudly, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_project(project.path(), port, 5);

    // Both lanes build WITHOUT --stage: they share the default stage and
    // must not both proceed.
    let out1 = project.path().join("out1");
    let out2 = project.path().join("out2");
    let j1 = spawn_build(project.path().to_path_buf(), out1.clone(), vec![]);
    let j2 = spawn_build(project.path().to_path_buf(), out2.clone(), vec![]);
    let (code1, _, stderr1) = j1.join().unwrap();
    let (code2, _, stderr2) = j2.join().unwrap();

    let attempts = [(code1, &stderr1, &out1), (code2, &stderr2, &out2)];
    let winners: Vec<_> = attempts.iter().filter(|(c, _, _)| *c == Some(0)).collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent default-stage build may proceed: {stderr1} | {stderr2}"
    );
    let (_, loser_err, _) = attempts.iter().find(|(c, _, _)| *c != Some(0)).unwrap();
    assert!(
        loser_err.contains("held by another shuttle build"),
        "loser must refuse loudly naming the conflict: {loser_err}"
    );
    assert!(
        loser_err.contains("--stage"),
        "loser must be pointed at the --stage escape hatch: {loser_err}"
    );
    let snap = winners[0].2.join("hello_1.0_amd64.snap");
    assert!(snap.exists(), "the winning build must produce the snap");
});

// ── Acceptance 2: the lock is released when a build finishes ──

gated_test!(default_stage_lock_releases_after_build_finishes, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_project(project.path(), port, 1);

    let out1 = project.path().join("out1");
    let out2 = project.path().join("out2");
    let (code1, _, stderr1) = spawn_build(project.path().to_path_buf(), out1, vec![])
        .join()
        .unwrap();
    assert_eq!(code1, Some(0), "first build must pass: {stderr1}");

    // The first build dropped its lock: the next one must proceed (the
    // leftover stage.lock file must not wedge later builds).
    let (code2, _, stderr2) = spawn_build(project.path().to_path_buf(), out2, vec![])
        .join()
        .unwrap();
    assert_eq!(code2, Some(0), "second build must pass: {stderr2}");
});

// ── Acceptance 3: explicit --stage builds are unaffected ──

gated_test!(explicit_stage_builds_do_not_lock, {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("srcs")).unwrap();
    let port = serve_dir(&project.path().join("srcs"));
    write_project(project.path(), port, 3);

    // Two concurrent builds, each with its own explicit --stage: they
    // never share a stage, must not take the default-stage lock, and
    // both proceed.
    let j1 = spawn_build(
        project.path().to_path_buf(),
        project.path().join("out1"),
        vec![
            "--stage".into(),
            project.path().join("stg1").to_string_lossy().into_owned(),
        ],
    );
    let j2 = spawn_build(
        project.path().to_path_buf(),
        project.path().join("out2"),
        vec![
            "--stage".into(),
            project.path().join("stg2").to_string_lossy().into_owned(),
        ],
    );
    let (code1, _, stderr1) = j1.join().unwrap();
    let (code2, _, stderr2) = j2.join().unwrap();
    assert_eq!(
        code1,
        Some(0),
        "explicit-stage build 1 must pass: {stderr1}"
    );
    assert_eq!(
        code2,
        Some(0),
        "explicit-stage build 2 must pass: {stderr2}"
    );
    assert!(
        project.path().join("out1/hello_1.0_amd64.snap").exists(),
        "snap 1 must have been produced"
    );
    assert!(
        project.path().join("out2/hello_1.0_amd64.snap").exists(),
        "snap 2 must have been produced"
    );
});
