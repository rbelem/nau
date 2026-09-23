//! Recipe-closure drift for pods (issue #142) — integration tests
//! through the real binary.
//!
//! Mirrors tests/pod_snap_sideload.rs: a declared package in `pkgs/`
//! with a `requires` edge is resolved, built, and installed into a pod
//! over a loopback HTTP source. The pod lockfile pin carries a
//! `recipe_sha256` over the package's recipe-resolved requires closure;
//! editing a member's recipe (the #138 stranded-fix story: a recipe-only
//! change to an UNDECLARED member) must reach the installed pod on the
//! next `sync` even though every version pin is unchanged.
//!
//! All state (project dirs, pod roots) lives in tempdirs — never the
//! real home. Gated on the external toolchain (mksquashfs/unsquashfs/
//! curl/tar), same skip pattern as tests/pod_snap_sideload.rs.

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

/// Write (or rewrite — the rewrite IS the drift) a resolvable package
/// that builds a real executable echoing `marker`. `requires` adds the
/// runtime edge under test.
fn write_pkg(
    project: &Path,
    name: &str,
    requires: &[&str],
    bin: &str,
    marker: &str,
    port: u16,
    tarball: &str,
) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let requires_field = if requires.is_empty() {
        String::new()
    } else {
        format!(
            "    requires = {{ {} }},\n",
            requires
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
{requires_field}    build = "mkdir -p $STAGE/bin && echo '#!/bin/sh' > $STAGE/bin/{bin} && echo 'echo {marker}' >> $STAGE/bin/{bin} && chmod +x $STAGE/bin/{bin}",
    apps = {{ {bin} = {{ command = "bin/{bin}" }} }},
}} }}
"#
    );
    std::fs::write(dir.join(format!("{name}.lua")), lua).unwrap();
}

// ── Runners ──

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // Desktop launchers write to the user data home — keep them inside
    // the test's tempdir; pod activation off the host bus.
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("SHUTTLE_SYSTEMD", "off");
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

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

/// The pod lockfile as JSON — the pin record under test.
fn read_lock(root: &Path, pod: &str) -> serde_json::Value {
    let bytes = std::fs::read(root.join(pod).join("shuttle.lock")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn recipe_hash_of(lock: &serde_json::Value, name: &str) -> Option<String> {
    lock["packages"][name]["recipe_sha256"]
        .as_str()
        .map(str::to_string)
}

/// The standard fixture: `app` (requires `libmember`) at version 1.0,
/// synced into pod `name`. Returns (project, root). `server_dir` is the
/// loopback server's docroot — the drift edits rewrite recipes HERE.
fn sync_fixture_pod(server_dir: &Path, port: u16, name: &str) -> (PathBuf, PathBuf) {
    make_tarball(server_dir, "appsrc");
    make_tarball(server_dir, "member");
    let project = tempfile::tempdir().unwrap().keep();
    let root = tempfile::tempdir().unwrap().keep();
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-ran",
        port,
        "member.tar.gz",
    );
    write_pkg(
        &project,
        "app",
        &["libmember"],
        "appbin",
        "app-ran",
        port,
        "appsrc.tar.gz",
    );
    let (code, _, stderr) = run(&project, &root, &["--name", name, "add", "app"]);
    assert_eq!(code, Some(0), "first sync failed: {stderr}");
    (project, root)
}

// ── Tests ──

/// (a) Drift in a requires member's recipe → the next sync rebuilds the
/// declared root at its unchanged pin, names the drift, and restamps
/// the closure hash.
#[test]
fn sync_rebuilds_recipe_drifted_root() {
    require_chain();
    if !chain_available() {
        return;
    }
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");

    // First sync stamped the closure hash.
    let gens_before = generation_count(&root, "p");
    let first_hash =
        recipe_hash_of(&read_lock(&root, "p"), "app").expect("first sync must stamp recipe_sha256");
    assert_eq!(first_hash.len(), 64, "sha-256 hex");

    // Drift: the MEMBER's recipe changes (the #138 story — a recipe-only
    // fix to an undeclared closure member).
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let (code, stdout, stderr) = run(&project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "drift sync failed: {stderr}");
    assert!(
        stderr.contains("recipe drift: app (closure recipe changed)"),
        "drift must be named on the output; stdout={stdout} stderr={stderr}"
    );
    assert!(
        !stderr.contains("already matches its declaration"),
        "a drift sync is not a no-op; stderr={stderr}"
    );
    assert!(
        generation_count(&root, "p") > gens_before,
        "the drifted closure must land a new generation"
    );

    // The pin was restamped with the NEW closure digest.
    let second_hash = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();
    assert_ne!(second_hash, first_hash, "restamped after drift");

    // Convergence: a third sync holds everything — the drift was swept.
    let gens_after = generation_count(&root, "p");
    let (code, _, stderr3) = run(&project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0));
    assert!(
        stderr3.contains("already matches its declaration"),
        "post-drift sync must be a no-op; stderr={stderr3}"
    );
    assert_eq!(generation_count(&root, "p"), gens_after);
}

/// (b) Regression guard: no drift → sync stays a no-op (no generation
/// bump, no drift notice, hash untouched).
#[test]
fn sync_without_drift_stays_noop() {
    require_chain();
    if !chain_available() {
        return;
    }
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (_project, root) = sync_fixture_pod(server.path(), port, "p");
    let gens = generation_count(&root, "p");
    let hash = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();

    let (code, _stdout, stderr) = run(&_project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("recipe drift"),
        "no drift must be named; stderr={stderr}"
    );
    assert!(
        stderr.contains("already matches its declaration"),
        "no-drift sync stays a no-op; stderr={stderr}"
    );
    assert_eq!(generation_count(&root, "p"), gens);
    assert_eq!(
        recipe_hash_of(&read_lock(&root, "p"), "app").as_deref(),
        Some(hash.as_str())
    );
}

/// (c) Migration: a pre-#142 lockfile entry (no recipe_sha256) loads,
/// sync stamps it WITHOUT a rebuild.
#[test]
fn pre142_lockfile_stamped_without_rebuild() {
    require_chain();
    if !chain_available() {
        return;
    }
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (_project, root) = sync_fixture_pod(server.path(), port, "p");
    let stamped = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();

    // Roll the lockfile back to the pre-#142 shape: drop the field.
    let lock_path = root.join("p").join("shuttle.lock");
    let mut lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
    lock["packages"]["app"]
        .as_object_mut()
        .unwrap()
        .remove("recipe_sha256");
    std::fs::write(&lock_path, serde_json::to_string_pretty(&lock).unwrap()).unwrap();

    let gens = generation_count(&root, "p");
    let (code, _, stderr) = run(&_project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "{stderr}");
    // The stamp is LOUD now (round 5: the silent baseline swallowed
    // pre-baseline fixes forever) — it names the limit and the escape.
    assert!(
        stderr.contains("baseline recorded for 'app'"),
        "the migration stamp must be loud; stderr={stderr}"
    );
    assert!(
        stderr.contains("pod refresh"),
        "the baseline notice must name the escape hatch; stderr={stderr}"
    );
    assert!(
        !stderr.contains("no recorded closure digest — rebuilding"),
        "migration must not rebuild; stderr={stderr}"
    );
    assert_eq!(
        generation_count(&root, "p"),
        gens,
        "migration must not bump the generation"
    );
    assert_eq!(
        recipe_hash_of(&read_lock(&root, "p"), "app").as_deref(),
        Some(stamped.as_str()),
        "sync stamps the field silently"
    );
}

/// (d) Blob-pinned requires member: drift in ITS recipe does NOT
/// trigger a root rebuild — the pod holds the blob, the collection
/// recipe is not what executes.
#[test]
fn blob_pinned_member_drift_does_not_rebuild_root() {
    require_chain();
    if !chain_available() {
        return;
    }
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "member");

    // Builder pod: build libmember from the collection, harvest its
    // payload (same pattern as pod_snap_sideload.rs).
    let builder = tempfile::tempdir().unwrap().keep();
    let builder_root = tempfile::tempdir().unwrap().keep();
    write_pkg(
        &builder,
        "libmember",
        &[],
        "memberbin",
        "member-ran",
        port,
        "member.tar.gz",
    );
    let (code, _, stderr) = run(
        &builder,
        &builder_root,
        &["--name", "build", "add", "libmember"],
    );
    assert_eq!(code, Some(0), "builder add failed: {stderr}");
    let downloads = builder_root.join("build").join("downloads");
    let payload = std::fs::read_dir(&downloads)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("libmember_1.0_"))
        })
        .expect("harvest libmember payload");

    // Target pod: sideload libmember FIRST (blob pin), then declare app
    // whose requires closure resolves to that member's collection
    // recipe — the recipe the pod does NOT execute.
    let project = tempfile::tempdir().unwrap().keep();
    let root = tempfile::tempdir().unwrap().keep();
    make_tarball(server.path(), "appsrc");
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-ran",
        port,
        "member.tar.gz",
    );
    write_pkg(
        &project,
        "app",
        &["libmember"],
        "appbin",
        "app-ran",
        port,
        "appsrc.tar.gz",
    );
    let (code, _, stderr) = run(
        &project,
        &root,
        &[
            "--name",
            "t",
            "add",
            "--snap",
            payload.to_str().unwrap(),
            "--ack-unsigned",
        ],
    );
    assert_eq!(code, Some(0), "sideload failed: {stderr}");
    let (code, _, stderr) = run(&project, &root, &["--name", "t", "add", "app"]);
    assert_eq!(code, Some(0), "app add failed: {stderr}");

    let gens = generation_count(&root, "t");
    let app_hash = recipe_hash_of(&read_lock(&root, "t"), "app")
        .expect("app pin stamped even with an excluded closure");

    // Drift the SIDELoaded member's collection recipe.
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let (code, _stdout, stderr) = run(&project, &root, &["--name", "t", "sync"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("recipe drift"),
        "blob-pinned member drift must not force a rebuild; stderr={stderr}"
    );
    assert!(
        stderr.contains("already matches its declaration"),
        "the sync stays a no-op; stderr={stderr}"
    );
    assert_eq!(generation_count(&root, "t"), gens);
    assert_eq!(
        recipe_hash_of(&read_lock(&root, "t"), "app").as_deref(),
        Some(app_hash.as_str()),
        "the exclusion is baked into the pin: the digest ignores the blob-pinned member"
    );
}

/// (e) `pod rebuild` of the drifted declared package: rebuilds at its
/// pin and restamps the closure hash.
#[test]
fn rebuild_of_drifted_pod_restamps() {
    require_chain();
    if !chain_available() {
        return;
    }
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");
    let first_hash = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();
    let gens = generation_count(&root, "p");

    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "rebuild", "app"]);
    assert_eq!(code, Some(0), "rebuild failed: {stderr}");
    assert!(
        stderr.contains("recipe drift: app (closure recipe changed)"),
        "rebuild names the drift; stderr={stderr}"
    );
    assert!(
        generation_count(&root, "p") > gens,
        "the drifted closure lands a new generation"
    );
    assert_ne!(
        recipe_hash_of(&read_lock(&root, "p"), "app").as_deref(),
        Some(first_hash.as_str()),
        "rebuild restamps the closure hash"
    );
}
