//! `shuttle pod` integration tests (issue #2: pod scaffold).
//!
//! Drives the real binary end to end with fully isolated state: the
//! project directory (package resolution source) and the pod state root
//! both live in tempdirs, so nothing is ever written to the real home.
//! Scope under test: add/remove/list round-tripping through a pod's
//! `pod.lua` declaration + lockfile pins — the default pod via bare verbs
//! and named pods via `--name` before the verb (issue #4). No binaries,
//! generations, or activation — those are later tickets.

use std::path::Path;
use std::process::Command;

/// Run the real binary with `args` from `project` as cwd and `--root
/// <root>` appended (unless the args rely on SHUTTLE_POD_ROOT).
fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    // The desktop launcher surface (issue #7) writes to the user data
    // home — redirect it inside the test's tempdir, never the real home.
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

/// Same as `run`, but redirecting state via the SHUTTLE_POD_ROOT env var
/// instead of the `--root` flag.
fn run_env_root(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.args(args);
    cmd.env("SHUTTLE_POD_ROOT", root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
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

fn named_pod_lua(root: &Path, pod: &str) -> std::path::PathBuf {
    root.join(pod).join("pod.lua")
}

fn named_pod_lock(root: &Path, pod: &str) -> std::path::PathBuf {
    root.join(pod).join("shuttle.lock")
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
fn list_on_unknown_pod_fails_with_clear_error() {
    // Read verbs do not initialize pods: `list` against a pod with no
    // declaration (fresh root, here the default pod) must fail naming it.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(project.path(), root.path(), &["list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("default") && stderr.contains("no declaration"),
        "error must name the pod and say it has no declaration: {stderr}"
    );
}

// ── named pods (`--name` before the verb, issue #4) ──

#[test]
fn named_pod_verb_targets_that_pod_exclusively() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "jq"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("work"),
        "add must report the named pod: {stderr}"
    );

    // The named pod got the declaration + lockfile; the default pod was
    // not created.
    let decl = std::fs::read_to_string(named_pod_lua(root.path(), "work")).unwrap();
    assert!(
        decl.contains(r#"packages = { "jq" }"#),
        "work's pod.lua must record the package, got:\n{decl}"
    );
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(named_pod_lock(root.path(), "work")).unwrap(),
    )
    .unwrap();
    assert_eq!(lock["packages"]["jq"]["version"], "1.7.1");
    assert!(
        !root.path().join("default").exists(),
        "named-pod add must not create the default pod"
    );

    // list and remove against the same name operate on the same state.
    let (code, _, stderr) = run(project.path(), root.path(), &["--name", "work", "list"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("jq") && stderr.contains("1.7.1"),
        "list must target the named pod: {stderr}"
    );

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "remove", "jq"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let decl = std::fs::read_to_string(named_pod_lua(root.path(), "work")).unwrap();
    assert!(
        !decl.contains(r#""jq""#),
        "remove must target the named pod, got:\n{decl}"
    );
}

#[test]
fn bare_verb_targets_default_pod_only() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(project.path(), root.path(), &["add", "jq"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        pod_lua(root.path()).exists(),
        "bare verb writes the default pod"
    );
    assert!(
        !root.path().join("work").exists(),
        "bare verb must not create any other pod"
    );
}

#[test]
fn mutations_in_one_pod_leave_every_other_pod_untouched() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    write_pkg(project.path(), "ripgrep", "14.1.0");

    // Seed both pods.
    let (code, _, _) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "jq"],
    );
    assert_eq!(code, Some(0));
    let (code, _, _) = run(project.path(), root.path(), &["add", "ripgrep@14"]);
    assert_eq!(code, Some(0));

    let default_decl_before = snapshot(&pod_lua(root.path()));
    let default_lock_before = snapshot(&pod_lock(root.path()));

    // Mutate `work`: add a package, remove one, and attempt a failed add.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "ripgrep"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "remove", "jq"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let (code, _, _) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "ghost"],
    );
    assert_eq!(code, Some(1));

    // `work` actually changed (otherwise the test proves nothing).
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(named_pod_lock(root.path(), "work")).unwrap(),
    )
    .unwrap();
    assert!(
        lock["packages"].get("jq").is_none(),
        "work's lockfile must have changed: {lock}"
    );
    assert_eq!(lock["packages"]["ripgrep"]["version"], "14.1.0");
    let decl = std::fs::read_to_string(named_pod_lua(root.path(), "work")).unwrap();
    assert!(
        !decl.contains(r#""jq""#) && decl.contains(r#""ripgrep""#),
        "work's declaration must reflect its mutations, got:\n{decl}"
    );

    // `default` is byte-identical across declaration and lockfile.
    assert_eq!(
        snapshot(&pod_lua(root.path())),
        default_decl_before,
        "default's declaration must be untouched by work's mutations"
    );
    assert_eq!(
        snapshot(&pod_lock(root.path())),
        default_lock_before,
        "default's lockfile must be untouched by work's mutations"
    );
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

// ── unknown pods (issue #4): add initializes, read verbs fail ──

#[test]
fn add_initializes_unknown_named_pod() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "fresh", "add", "jq"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        named_pod_lua(root.path(), "fresh").exists()
            && named_pod_lock(root.path(), "fresh").exists(),
        "add must create the named pod's declaration and lockfile"
    );
}

#[test]
fn list_on_unknown_named_pod_fails_with_clear_error() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(project.path(), root.path(), &["--name", "ghost", "list"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("ghost") && stderr.contains("no declaration"),
        "error must name the unknown pod: {stderr}"
    );
    assert!(
        !root.path().join("ghost").exists(),
        "read verbs must not initialize the pod"
    );
}

#[test]
fn remove_on_unknown_named_pod_fails_with_clear_error() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "ghost", "remove", "jq"],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("ghost") && stderr.contains("no declaration"),
        "error must name the unknown pod: {stderr}"
    );
    assert!(
        !root.path().join("ghost").exists(),
        "read verbs must not initialize the pod"
    );
}

// ── UX shape: `--name` belongs before the verb ──

#[test]
fn name_after_verb_is_rejected() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    // The agreed UX is `shuttle pod [--name X] <verb>`; `--name` is an
    // argument of the `pod` command itself, not of any verb.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "jq", "--name", "work"],
    );
    assert_ne!(code, Some(0), "--name after the verb must not be accepted");
    assert!(
        !root.path().join("work").exists() && !pod_lua(root.path()).exists(),
        "a rejected invocation must not write any state"
    );
    let _ = stderr;
}

#[test]
fn invalid_pod_name_is_rejected() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "../escape", "add", "jq"],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("path separators"),
        "error must explain the invalid pod name: {stderr}"
    );
    assert!(
        !root.path().join("escape").exists(),
        "invalid name must not create a directory outside the pod root"
    );
}

#[test]
fn explicit_default_name_matches_bare_verb() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "default", "add", "jq"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        pod_lua(root.path()).exists(),
        "--name default targets the default pod"
    );
}
