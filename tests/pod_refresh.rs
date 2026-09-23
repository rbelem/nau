//! `pod refresh` and the issue #142 stamping contracts — integration
//! tests through the real binary.
//!
//! Mirrors tests/pod_recipe_drift.rs: a declared package in the
//! project's `pkgs/` with a `requires` edge is resolved, built, and
//! installed into a pod over a loopback HTTP source. Covers the round-5
//! negative finding's fixes:
//!
//! - `pod refresh <member…>` rebuilds an UNDECLARABLE closure member
//!   (the stranded #138 curl story) from its current recipe and exposes
//!   its farm entry (the closure-member claims gap).
//! - Refresh is churn-free when the rebuild comes back byte-identical.
//! - Recipe stamps persist per package as each build succeeds — a
//!   mid-sweep failure must not restart the whole sweep next sync.
//! - The migration stamp is LOUD and names the escape hatch.
//! - `sync --rebuild-unstamped` opts into the one-time rebuild sweep.
//! - A blob swap names the pin move, drops the stale deps pin, and
//!   warns at flip time that rollback strands the pin.
//!
//! All state (project dirs, pod roots) lives in tempdirs — never the
//! real home. Gated on the external toolchain (mksquashfs/unsquashfs/
//! curl/tar), same skip pattern as tests/pod_recipe_drift.rs.

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

/// A package whose build always fails — the mid-sweep failure.
fn write_failing_pkg(project: &Path, name: &str, requires: &[&str], port: u16, tarball: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let requires_field = format!(
        "    requires = {{ {} }},\n",
        requires
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let lua = format!(
        r#"return {{ default = snap {{
    name = "{name}",
    version = "1.0",
    source = "http://127.0.0.1:{port}/{tarball}",
{requires_field}    build = "exit 1",
    apps = {{ }},
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

fn pod_dir(root: &Path, pod: &str) -> PathBuf {
    root.join(pod)
}

fn generation_count(root: &Path, pod: &str) -> usize {
    let gens = pod_dir(root, pod).join("generations");
    std::fs::read_dir(&gens)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().parse::<u64>().is_ok())
                .count()
        })
        .unwrap_or(0)
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

fn farm_output(farm: &Path, bin: &str) -> String {
    let out = Command::new(bin).env("PATH", farm).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The pod lockfile as JSON — the pin record under test.
fn read_lock(root: &Path, pod: &str) -> serde_json::Value {
    let bytes = std::fs::read(root.join(pod).join("shuttle.lock")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn write_lock(root: &Path, pod: &str, lock: &serde_json::Value) {
    let path = root.join(pod).join("shuttle.lock");
    std::fs::write(&path, serde_json::to_string_pretty(lock).unwrap()).unwrap();
}

fn recipe_hash_of(lock: &serde_json::Value, name: &str) -> Option<String> {
    lock["packages"][name]["recipe_sha256"]
        .as_str()
        .map(str::to_string)
}

/// Drop every `recipe_sha256` field — the pre-#142 lockfile shape.
fn strip_recipe_hashes(lock: &mut serde_json::Value) {
    for (_, entry) in lock["packages"].as_object_mut().unwrap().iter_mut() {
        entry.as_object_mut().unwrap().remove("recipe_sha256");
    }
}

/// The standard fixture: `app` (requires `libmember`) at version 1.0,
/// synced into pod `name`. Returns (project, root).
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

/// Harvest a built payload from a pod's downloads dir (the builder-pod
/// pattern of tests/pod_recipe_drift.rs).
fn harvest_payload(downloads: &Path, prefix: &str) -> PathBuf {
    std::fs::read_dir(downloads)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .unwrap_or_else(|| panic!("harvest {prefix} payload from {}", downloads.display()))
}

// ── Tests ──

// `pod refresh` reaches an UNDECLARABLE closure member (the round-5
// curl story): sync can never sweep it, refresh rebuilds it from its
// current recipe, installs it, and its farm entry materializes (the
// closure-member claims gap).
gated_test!(refresh_rebuilds_undeclared_member_and_exposes_farm_entry, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");
    let gens_before = generation_count(&root, "p");
    let app_hash_before = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();

    // The member's recipe changes — sync's drift machinery WOULD sweep
    // it here, but refresh must reach it directly, without a plain
    // sync in between.
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let (code, stdout, stderr) = run(&project, &root, &["--name", "p", "refresh", "libmember"]);
    assert_eq!(code, Some(0), "refresh failed: {stderr}");
    assert!(
        stderr.contains("refreshed 'libmember'"),
        "refresh must name the member; stdout={stdout} stderr={stderr}"
    );
    assert!(
        generation_count(&root, "p") > gens_before,
        "a changed member must land a new generation"
    );

    // The farm entry MATERIALIZED (the 3685-3689 gap) and executes the
    // new content.
    let farm = current_farm(&root, "p");
    assert!(
        farm.join("memberbin").exists(),
        "the refreshed member's binary must reach the farm"
    );
    assert!(
        farm_output(&farm, "memberbin").contains("member-v2"),
        "the farm binary must execute the refreshed content"
    );

    // The refresh rode a full reconcile: the declared root's drift
    // fired too and its stamp was restamped with the new digest.
    let app_hash_after = recipe_hash_of(&read_lock(&root, "p"), "app").unwrap();
    assert_ne!(
        app_hash_after, app_hash_before,
        "the declared root's closure stamp must follow the refresh"
    );
});

// Refresh is churn-free when the rebuild comes back byte-identical:
// no generation, store content kept, and the verb still succeeds.
gated_test!(refresh_byte_identical_keeps_store_content, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");
    let gens = generation_count(&root, "p");

    // The undeclared member, recipe unchanged: the forced rebuild
    // produces identical bytes.
    let (code, _stdout, stderr) = run(&project, &root, &["--name", "p", "refresh", "libmember"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("byte-identical"),
        "an identical rebuild must say so; stderr={stderr}"
    );
    assert_eq!(
        generation_count(&root, "p"),
        gens,
        "a byte-identical refresh must not churn the store"
    );

    // Same for a DECLARED member (forced through the rebuild path).
    let (code, _stdout, stderr) = run(&project, &root, &["--name", "p", "refresh", "app"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("byte-identical"), "stderr={stderr}");
    assert_eq!(generation_count(&root, "p"), gens);
});

// Incremental stamping (issue #142): recipe stamps persist per
// package as each build succeeds — a later package's failure in the
// same sweep must not restart the whole sweep on the next sync.
gated_test!(incremental_stamps_survive_mid_reconcile_failure, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    make_tarball(server.path(), "appsrc");
    make_tarball(server.path(), "member");
    make_tarball(server.path(), "other");

    let project = tempfile::tempdir().unwrap().keep();
    let root = tempfile::tempdir().unwrap().keep();
    // Declaration order matters: app1 builds (and stamps) BEFORE app2
    // fails. app1 requires libmember; app2 requires libb.
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
        "libb",
        &[],
        "libbbin",
        "libb-ran",
        port,
        "other.tar.gz",
    );
    write_pkg(
        &project,
        "app1",
        &["libmember"],
        "app1bin",
        "app1-ran",
        port,
        "appsrc.tar.gz",
    );
    write_pkg(
        &project,
        "app2",
        &["libb"],
        "app2bin",
        "app2-ran",
        port,
        "appsrc.tar.gz",
    );
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "add", "app1"]);
    assert_eq!(code, Some(0), "{stderr}");
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "add", "app2"]);
    assert_eq!(code, Some(0), "{stderr}");
    let first1 = recipe_hash_of(&read_lock(&root, "p"), "app1").unwrap();
    let first2 = recipe_hash_of(&read_lock(&root, "p"), "app2").unwrap();

    // Drift app1's closure AND break app2's build. The sweep order is
    // declaration order: app1's build succeeds (its stamp must commit
    // NOW), then app2's build fails and aborts the reconcile.
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    write_failing_pkg(&project, "app2", &["libb"], port, "appsrc.tar.gz");
    let gens = generation_count(&root, "p");
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "sync"]);
    assert_ne!(
        code,
        Some(0),
        "the broken build must fail the sync: {stderr}"
    );

    // The failed reconcile installed NOTHING (pins-after-success)…
    assert_eq!(
        generation_count(&root, "p"),
        gens,
        "a failed sweep must not land a generation"
    );
    // …but app1's stamp PERSISTED — next sync will not redo its sweep.
    let after1 = recipe_hash_of(&read_lock(&root, "p"), "app1").unwrap();
    assert_ne!(
        after1, first1,
        "app1's stamp must commit incrementally, before the failure"
    );
    assert_eq!(
        recipe_hash_of(&read_lock(&root, "p"), "app2").unwrap(),
        first2,
        "the failed package's stamp must stay untouched"
    );

    // Repair app2: the next sync completes the sweep.
    write_pkg(
        &project,
        "app2",
        &["libb"],
        "app2bin",
        "app2-v2",
        port,
        "appsrc.tar.gz",
    );
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "repair sync failed: {stderr}");
    assert!(
        generation_count(&root, "p") > gens,
        "the repaired package must land a generation"
    );
});

// The migration stamp is LOUD (round 5): it names the baseline event,
// its limit, and the `pod refresh` escape hatch.
gated_test!(migration_stamp_is_loud_and_actionable, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");

    // Roll the lockfile back to the pre-#142 shape.
    let mut lock = read_lock(&root, "p");
    strip_recipe_hashes(&mut lock);
    write_lock(&root, "p", &lock);

    let gens = generation_count(&root, "p");
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("baseline recorded for 'app'"),
        "the baseline must be loud; stderr={stderr}"
    );
    assert!(
        stderr.contains("pod refresh"),
        "the baseline notice must name the escape hatch; stderr={stderr}"
    );
    assert_eq!(
        generation_count(&root, "p"),
        gens,
        "the default sync stamps without rebuilding"
    );
});

// `sync --rebuild-unstamped` opts into the one-time migration rebuild
// sweep; the default sync does NOT sweep (it only baselines).
gated_test!(rebuild_unstamped_sweeps_only_with_the_flag, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let (project, root) = sync_fixture_pod(server.path(), port, "p");

    // Drift the member, THEN strip the stamps — the round-5 shape: the
    // pod's baseline postdates the recipe fix, so plain sync would
    // swallow it forever.
    write_pkg(
        &project,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let mut lock = read_lock(&root, "p");
    strip_recipe_hashes(&mut lock);
    write_lock(&root, "p", &lock);

    // Default sync: baselines, no rebuild, stale content stays.
    let gens = generation_count(&root, "p");
    let (code, _, stderr) = run(&project, &root, &["--name", "p", "sync"]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("baseline recorded for 'app'"), "{stderr}");
    assert_eq!(generation_count(&root, "p"), gens);
    let farm = current_farm(&root, "p");
    assert!(
        farm_output(&farm, "memberbin").contains("member-ran"),
        "the default sync must NOT sweep the unstamped drift"
    );

    // Strip again (undo the baseline) and opt in: the sweep rebuilds.
    let mut lock = read_lock(&root, "p");
    strip_recipe_hashes(&mut lock);
    write_lock(&root, "p", &lock);
    let (code, _, stderr) = run(
        &project,
        &root,
        &["--name", "p", "sync", "--rebuild-unstamped"],
    );
    assert_eq!(code, Some(0), "rebuild-unstamped sync failed: {stderr}");
    assert!(
        stderr.contains("no recorded closure digest — rebuilding"),
        "the sweep must name what it rebuilds; stderr={stderr}"
    );
    assert!(
        generation_count(&root, "p") > gens,
        "the sweep must land the fixed content"
    );
    let farm = current_farm(&root, "p");
    assert!(
        farm_output(&farm, "memberbin").contains("member-v2"),
        "the swept member must execute the new content"
    );
});

// A blob swap names the pin move (distinguishable from a first
// install), drops the stale deps pin, and warns at flip time that
// rollback across the swap strands the pin.
gated_test!(swap_names_pin_move_drops_deps_pin_warns_rollback, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());

    // Builder pod: build the member payload, harvest it, rebuild it
    // with changed content under the SAME version (the swap).
    let builder = tempfile::tempdir().unwrap().keep();
    let builder_root = tempfile::tempdir().unwrap().keep();
    make_tarball(server.path(), "member");
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
        &["--name", "b", "add", "libmember"],
    );
    assert_eq!(code, Some(0), "builder add failed: {stderr}");
    let staging = tempfile::tempdir().unwrap().keep();
    let v1 = staging.join("v1.snap");
    std::fs::copy(
        harvest_payload(&builder_root.join("b").join("downloads"), "libmember_1.0_"),
        &v1,
    )
    .unwrap();
    write_pkg(
        &builder,
        "libmember",
        &[],
        "memberbin",
        "member-v2",
        port,
        "member.tar.gz",
    );
    let (code, _, stderr) = run(&builder, &builder_root, &["--name", "b", "sync"]);
    assert_eq!(code, Some(0), "builder rebuild failed: {stderr}");
    let v2 = staging.join("v2.snap");
    std::fs::copy(
        harvest_payload(&builder_root.join("b").join("downloads"), "libmember_1.0_"),
        &v2,
    )
    .unwrap();

    // Target pod: sideload v1 (first install), inject a deps pin, then
    // swap in v2.
    let project = tempfile::tempdir().unwrap().keep();
    let root = tempfile::tempdir().unwrap().keep();
    let (code, _, stderr) = run(
        &project,
        &root,
        &["add", "--snap", v1.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("sideloaded 'libmember' (1.0)"),
        "a first install must still print the sideloaded line; {stderr}"
    );
    let v1_pin = read_lock(&root, "default")["snaps"]["libmember"]["sha3-384"]
        .as_str()
        .unwrap()
        .to_string();

    let mut lock = read_lock(&root, "default");
    lock["packages"]["libmember"]["deps"] = serde_json::json!({
        "deps_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "fetched_at": "2026-01-01"
    });
    write_lock(&root, "default", &lock);

    let (code, _, stderr) = run(
        &project,
        &root,
        &["add", "--snap", v2.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "swap failed: {stderr}");
    assert!(
        stderr.contains("replaced 'libmember' (1.0): sha3-384"),
        "the swap must name the pin move; stderr={stderr}"
    );
    assert!(
        stderr.contains("→") && stderr.contains("generation 2"),
        "the swap output must name old → new and the generation; stderr={stderr}"
    );
    assert!(
        stderr.contains("rollback") && stderr.contains("realigns"),
        "the swap must warn at flip time that rollback strands the pin; \
         stderr={stderr}"
    );

    let lock = read_lock(&root, "default");
    let v2_pin = lock["snaps"]["libmember"]["sha3-384"].as_str().unwrap();
    assert_ne!(v2_pin, v1_pin, "the blob pin must move to the new content");
    assert!(
        lock["packages"]["libmember"]["deps"].is_null(),
        "a payload swap must drop the stale deps closure pin"
    );
    let farm = current_farm(&root, "default");
    assert!(
        farm_output(&farm, "memberbin").contains("member-v2"),
        "the farm must execute the swapped content"
    );
});

// A blob-pinned member refuses to refresh — the payload IS its
// content, there is no recipe — and the refusal is zero-write.
gated_test!(refresh_refuses_blob_pinned_member, {
    let server = tempfile::tempdir().unwrap();
    let port = serve_dir(server.path());
    let builder = tempfile::tempdir().unwrap().keep();
    let builder_root = tempfile::tempdir().unwrap().keep();
    make_tarball(server.path(), "member");
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
        &["--name", "b", "add", "libmember"],
    );
    assert_eq!(code, Some(0), "{stderr}");

    let project = tempfile::tempdir().unwrap().keep();
    let root = tempfile::tempdir().unwrap().keep();
    let payload = harvest_payload(&builder_root.join("b").join("downloads"), "libmember_1.0_");
    let (code, _, stderr) = run(
        &project,
        &root,
        &["add", "--snap", payload.to_str().unwrap(), "--ack-unsigned"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let gens = generation_count(&root, "default");

    let (code, _, stderr) = run(&project, &root, &["refresh", "libmember"]);
    assert_ne!(code, Some(0), "a blob-pinned member must refuse");
    assert!(
        stderr.contains("blob-pinned") && stderr.contains("no recipe to rebuild"),
        "the refusal must name the blob pin and the fix; stderr={stderr}"
    );
    assert_eq!(
        generation_count(&root, "default"),
        gens,
        "the refusal must be zero-write"
    );
});
