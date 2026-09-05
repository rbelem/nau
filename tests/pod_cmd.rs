//! `shuttle pod` integration tests (issue #2: pod scaffold).
//!
//! Drives the real binary end to end with fully isolated state: the
//! project directory (package resolution source) and the pod state root
//! both live in tempdirs, so nothing is ever written to the real home.
//! Scope under test: add/remove/list round-tripping through the default
//! pod's `pod.lua` declaration + lockfile pins. No binaries, generations,
//! or activation — those are later tickets.

use std::path::Path;
use std::process::Command;

/// Run the real binary with `args` from `project` as cwd and `--root
/// <root>` appended (unless the args rely on SHUTTLE_POD_ROOT).
fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Same as `run`, but redirecting state via the SHUTTLE_POD_ROOT env var
/// instead of the `--root` flag.
fn run_env_root(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(args);
    cmd.env("SHUTTLE_POD_ROOT", root);
    cmd.current_dir(project);
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Create a resolvable package declaration in the project's `pkgs/` tree.
fn write_pkg(project: &Path, name: &str, version: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.lua")),
        format!("return {{ default = snap {{ name = \"{name}\", version = \"{version}\" }} }}\n"),
    )
    .unwrap();
}

fn pod_lua(root: &Path) -> std::path::PathBuf {
    root.join("default").join("pod.lua")
}

fn pod_lock(root: &Path) -> std::path::PathBuf {
    root.join("default").join("shuttle.lock")
}

/// Seed a pod.lua by hand (for malformed-declaration tests).
fn seed_pod_lua(root: &Path, source: &str) {
    std::fs::create_dir_all(root.join("default")).unwrap();
    std::fs::write(pod_lua(root), source).unwrap();
}

fn snapshot(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

// ── add: declaration + lockfile pin ──

#[test]
fn add_records_declaration_and_pins_resolved_version() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("jq") && stderr.contains("1.7.1"),
        "add must report the package and its resolved version: {stderr}"
    );

    // Declaration records the package.
    let decl = std::fs::read_to_string(pod_lua(root.path())).unwrap();
    assert!(
        decl.contains(r#"packages = { "jq" }"#),
        "pod.lua must record the package, got:\n{decl}"
    );

    // Lockfile pins the resolved version.
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pod_lock(root.path())).unwrap())
            .expect("valid JSON lockfile");
    assert_eq!(lock["packages"]["jq"]["version"], "1.7.1");

    // list shows name plus resolved version.
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("jq") && stderr.contains("1.7.1"),
        "list must show name plus resolved version: {stderr}"
    );
}

#[test]
fn add_with_version_constraint_records_spec_and_pin() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "ripgrep", "14.1.0");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "ripgrep@14"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let decl = std::fs::read_to_string(pod_lua(root.path())).unwrap();
    assert!(
        decl.contains(r#""ripgrep@14""#),
        "declaration must keep the constraint, got:\n{decl}"
    );
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pod_lock(root.path())).unwrap()).unwrap();
    assert_eq!(lock["packages"]["ripgrep"]["version"], "14.1.0");
    assert_eq!(lock["packages"]["ripgrep"]["constraint"], "14");
}

#[test]
fn add_is_repeatable_via_env_root_without_flag() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run_env_root(project.path(), root.path(), &["pod", "add", "jq"]);
    assert_eq!(
        code,
        Some(0),
        "SHUTTLE_POD_ROOT must redirect pod state: {stderr}"
    );
    assert!(
        pod_lua(root.path()).exists(),
        "declaration written under the env root"
    );
}

// ── add failure paths: no state mutation ──

#[test]
fn add_unknown_package_fails_and_writes_nothing() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "ghost"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("ghost"),
        "error must name the unresolvable package: {stderr}"
    );
    assert!(!pod_lua(root.path()).exists(), "no declaration on failure");
    assert!(!pod_lock(root.path()).exists(), "no lockfile on failure");
    assert!(
        !root.path().join("default").exists(),
        "no pod directory on failure"
    );
}

#[test]
fn add_unknown_package_leaves_existing_state_untouched() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    let (code, _, _) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0));

    let decl_before = snapshot(&pod_lua(root.path()));
    let lock_before = snapshot(&pod_lock(root.path()));

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "ghost"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert_eq!(
        snapshot(&pod_lua(root.path())),
        decl_before,
        "declaration must be untouched"
    );
    assert_eq!(
        snapshot(&pod_lock(root.path())),
        lock_before,
        "lockfile must be untouched"
    );
}

#[test]
fn add_duplicate_package_fails_without_rewriting() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    let (code, _, _) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0));

    let decl_before = snapshot(&pod_lua(root.path()));
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("already"),
        "error must explain the duplicate: {stderr}"
    );
    assert_eq!(snapshot(&pod_lua(root.path())), decl_before);
}

// ── remove ──

#[test]
fn remove_drops_declaration_and_lockfile_entries() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    write_pkg(project.path(), "ripgrep", "14.1.0");
    let (code, _, _) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0));
    let (code, _, _) = run(project.path(), root.path(), &["add", "ripgrep@14"]);
    assert_eq!(code, Some(0));

    let (code, _, stderr) = run(project.path(), root.path(), &["remove", "jq"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let decl = std::fs::read_to_string(pod_lua(root.path())).unwrap();
    assert!(decl.contains(r#""ripgrep@14""#), "got:\n{decl}");
    assert!(
        !decl.contains(r#""jq""#),
        "jq must be dropped, got:\n{decl}"
    );
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(pod_lock(root.path())).unwrap()).unwrap();
    assert!(
        lock["packages"].get("jq").is_none(),
        "lock pin dropped: {lock}"
    );
    assert_eq!(lock["packages"]["ripgrep"]["version"], "14.1.0");
}

#[test]
fn remove_unknown_package_fails() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    let (code, _, _) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0));

    let (code, _, stderr) = run(project.path(), root.path(), &["remove", "ghost"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("ghost"), "got: {stderr}");
}

// ── list ──

#[test]
fn list_on_fresh_pod_reports_empty() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, _) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(0));
}

// ── pod() validation ──

#[test]
fn malformed_declaration_unknown_field_fails_naming_field() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_pod_lua(root.path(), r#"pod { pkgs = { "jq" } }"#);

    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("pkgs"),
        "error must name the offending field: {stderr}"
    );
}

#[test]
fn malformed_declaration_wrong_type_names_field() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_pod_lua(root.path(), r#"pod { loads = "base" }"#);

    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("'loads'"),
        "error must name the offending field: {stderr}"
    );
}

#[test]
fn malformed_declaration_non_string_package_names_field() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_pod_lua(root.path(), r#"pod { packages = { 42 } }"#);

    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("'packages[1]'") && stderr.contains("string"),
        "error must name the offending field and element: {stderr}"
    );
}

#[test]
fn malformed_declaration_non_table_overlay_names_field() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_pod_lua(root.path(), r#"pod { overlay = { jq = "patch" } }"#);

    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("'overlay.jq'"),
        "error must name the offending overlay entry: {stderr}"
    );
}

#[test]
fn malformed_declaration_blocks_add_without_writes() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    write_pkg(project.path(), "ripgrep", "14.1.0");
    seed_pod_lua(root.path(), r#"pod { packages = { "jq", 42 } }"#);

    let decl_before = snapshot(&pod_lua(root.path()));
    let (code, _, stderr) = run(project.path(), root.path(), &["add", "ripgrep"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("'packages[2]'"),
        "validation error must name the offending element: {stderr}"
    );
    assert_eq!(
        snapshot(&pod_lua(root.path())),
        decl_before,
        "malformed declaration must block mutation"
    );
    assert!(!pod_lock(root.path()).exists(), "no lockfile on failure");
}

#[test]
fn missing_pod_call_fails() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_pod_lua(
        root.path(),
        "-- a valid Lua file that never calls pod()\nlocal x = 1\n",
    );

    let (code, _, _) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
}
