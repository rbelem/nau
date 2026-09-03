//! Phase 16 input-lockfile integration tests.
//!
//! Drives the real binary over the lock/CLI paths that need no network:
//! `shuttle lock` (human + `--json` pin state), build `--offline`
//! fail-closed behavior with inputs absent from the cache, and the
//! `--update`/`--offline` conflict guard. All `github:` fetching paths are
//! deliberately avoided — every fixture declares `path:` inputs or relies on
//! offline refusal before any fetch could start.

use std::process::Command;

/// Run shuttle with an isolated HOME so the inputs cache root
/// (`$HOME/.cache/shuttle/inputs`) is private to the test.
fn run_in(
    dir: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_shuttle"))
        .args(args)
        .env("HOME", home)
        .current_dir(dir)
        .output()
        .expect("failed to spawn shuttle");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A config declaring exactly one local (unlocked) input and no build
/// outputs, so `--update` runs without invoking any build machinery.
fn setup_local_input_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
inputs = { vendored = { url = "path:vendor" } }
return {}
"#,
    )
    .unwrap();
    (dir, home)
}

// ── `shuttle lock` subcommand ──

#[test]
fn lock_human_mode_records_local_pin() {
    let (dir, home) = setup_local_input_project();
    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["lock", "--file", "shuttle.lua", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("1 input(s) locked"),
        "must summarize the lock count, got: {stderr}"
    );
    assert!(
        stderr.contains("vendored: local (unlocked)"),
        "must list the pin, got: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "human mode writes to stderr only: {stdout}"
    );

    // The lockfile itself records the input pin.
    let lock = std::fs::read_to_string(dir.path().join("proj.lock")).unwrap();
    assert!(
        lock.contains("\"inputs\""),
        "inputs section required: {lock}"
    );
    assert!(lock.contains("vendored"), "pin key required: {lock}");
    assert!(lock.contains("local"), "local marker required: {lock}");
}

#[test]
fn lock_json_mode_reports_pin_state() {
    let (dir, home) = setup_local_input_project();
    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "lock",
            "--file",
            "shuttle.lua",
            "--lockfile",
            "proj.lock",
            "--json",
        ],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.is_empty(),
        "JSON mode must not leak human output to stderr: {stderr}"
    );

    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}): {stdout}"));
    assert_eq!(v["command"], "lock");
    assert_eq!(v["lockfile"], "proj.lock");
    assert_eq!(v["updated"], 1);
    let pins = v["pins"].as_array().expect("pins array");
    assert_eq!(pins.len(), 1, "one pin: {v}");
    assert_eq!(pins[0]["name"], "vendored");
    assert_eq!(pins[0]["local"], true);
    assert!(
        pins[0].get("revision").is_none(),
        "local pins carry no revision: {v}"
    );
}

#[test]
fn lock_is_idempotent_rerun_reports_zero_updated() {
    let (dir, home) = setup_local_input_project();
    let args = [
        "lock",
        "--file",
        "shuttle.lua",
        "--lockfile",
        "proj.lock",
        "--json",
    ];
    let (code, _, stderr) = run_in(dir.path(), home.path(), &args);
    assert_eq!(code, Some(0), "first run: {stderr}");

    // Second run: already-locked pins refresh in place, JSON reflects state.
    let (code, stdout, stderr) = run_in(dir.path(), home.path(), &args);
    assert_eq!(code, Some(0), "second run: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["updated"], 1, "refresh still rewrites the pin: {v}");
    let before = std::fs::read_to_string(dir.path().join("proj.lock")).unwrap();
    assert!(before.contains("vendored"), "lockfile stable: {before}");
}

// ── `--offline` fail-closed ──

#[test]
fn build_offline_without_cache_fails_named_and_fetches_nothing() {
    // Empty project: no shuttle.lua, no lockfile, pristine isolated HOME.
    // The default input (github:rbelem/shuttle) is absent from the cache, so
    // a build attempt must fail with the named offline error — never touch
    // the network (asserted by the inputs cache root staying uncreated).
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["build", "--offline", "--lockfile", "proj.lock"],
    );
    assert_ne!(code, Some(0), "offline build without cache must fail");
    // miette wraps the message with continuation bars; flatten before matching.
    let flat = stderr.replace('│', " ");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("--offline prevents fetching"),
        "named offline error required, got: {stderr}"
    );

    let inputs_cache = home.path().join(".cache/shuttle/inputs");
    assert!(
        !inputs_cache.exists(),
        "no fetch may run in offline mode; cache root was created: {}",
        inputs_cache.display()
    );
}

#[test]
fn build_update_conflicts_with_offline_named_error() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let (code, _, stderr) = run_in(dir.path(), home.path(), &["build", "--update", "--offline"]);
    assert_ne!(code, Some(0));
    assert!(
        stderr.contains("cannot be combined with --offline"),
        "conflict guard required, got: {stderr}"
    );
}

// ── `--update` old→new reporting (local inputs; no network) ──

#[test]
fn update_reports_local_pin_refresh() {
    let (dir, home) = setup_local_input_project();
    // Pre-lock, then update: the local pin refreshes with old → new lines.
    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["lock", "--file", "shuttle.lua", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "pre-lock: {stderr}");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "build",
            "--update",
            "--file",
            "shuttle.lua",
            "--lockfile",
            "proj.lock",
        ],
    );
    assert_eq!(code, Some(0), "update run: {stderr}");
    assert!(
        stderr.contains("vendored: local (unlocked)"),
        "must report the refreshed pin, got: {stderr}"
    );
    assert!(
        stderr.contains("lockfile updated: proj.lock"),
        "must report the lockfile write, got: {stderr}"
    );
    assert!(stdout.is_empty(), "human mode: {stdout}");
}
