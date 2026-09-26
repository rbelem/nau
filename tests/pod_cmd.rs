//! `shuttle pod` integration tests (issue #2: pod scaffold).
//!
//! Drives the real binary end to end with fully isolated state: the
//! project directory (package resolution source) and the pod state root
//! both live in tempdirs, so nothing is ever written to the real home.
//! Scope under test: add/remove/list round-tripping through a pod's
//! `pod.lua` declaration + lockfile pins — the default pod via bare verbs
//! and named pods via `--name` before or after the verb (issue #4). No
//! binaries, generations, or activation — those are later tickets.

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
    // Keep pod activation off the host systemd bus (issue #66). This
    // helper was the one spawn site the #66 sweep missed: its `pod add`
    // reaches RuntimeStore::activate, which ran `systemctl daemon-reload`
    // on the host bus and raised a polkit prompt (and a ~25s auth stall)
    // on every test run.
    cmd.env("SHUTTLE_SYSTEMD", "off");
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

// ── UX shape: `--name` is accepted before or after the verb ──

#[test]
fn name_after_verb_is_accepted() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    // `--name` is accepted after the verb as well as before it: the
    // named pod is targeted either way (issue #4).
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["add", "jq", "--name", "work"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        named_pod_lua(root.path(), "work").exists() && named_pod_lock(root.path(), "work").exists(),
        "the named pod's declaration and lockfile must be written"
    );
    assert!(
        !pod_lua(root.path()).exists(),
        "the default pod must be untouched"
    );
}

#[test]
fn conflicting_name_positions_fail_closed() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    // Both positions given with DIFFERENT pods: hard error naming both
    // values — never a silent last-one-wins.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "alpha", "add", "jq", "--name", "beta"],
    );
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("alpha") && stderr.contains("beta"),
        "error must name both conflicting values: {stderr}"
    );
    assert!(
        !root.path().join("alpha").exists()
            && !root.path().join("beta").exists()
            && !pod_lua(root.path()).exists(),
        "a rejected invocation must not write any pod state"
    );
}

#[test]
fn same_name_in_both_positions_succeeds() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");

    // Both positions given with the SAME pod: fine.
    let (code, _, stderr) = run(
        project.path(),
        root.path(),
        &["--name", "work", "add", "jq", "--name", "work"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        named_pod_lua(root.path(), "work").exists() && named_pod_lock(root.path(), "work").exists(),
        "the named pod's declaration and lockfile must be written"
    );
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

// ── shellenv (issue #47) ──

/// Seed an ACTIVE pod farm by hand (no builds): one generation with a
/// farm and the pod's `current` link pointing at it, exactly the layout
/// the real emitter + flip produces.
fn seed_active_farm(root: &Path, pod: &str, generation: u64) {
    let pod_d = root.join(pod);
    let farm = pod_d
        .join("generations")
        .join(generation.to_string())
        .join("farm");
    std::fs::create_dir_all(&farm).unwrap();
    std::fs::write(farm.join("tool"), "#!/bin/sh\n").unwrap();
    std::os::unix::fs::symlink(
        format!("generations/{generation}/farm"),
        pod_d.join("current"),
    )
    .unwrap();
}

#[test]
fn shellenv_prints_an_export_line_for_the_farm() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);

    let (code, stdout, stderr) = run(project.path(), root.path(), &["shellenv"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    // Exactly one eval-able line: the farm prepended to the caller's
    // PATH, `current` kept as the link so rollback flips stay visible.
    let expected_farm = root.path().canonicalize().unwrap().join("default/current");
    assert_eq!(
        stdout,
        format!("export PATH=\"{}:$PATH\"\n", expected_farm.display()),
        "shellenv must print exactly one export line"
    );
    assert!(
        stdout.contains(&expected_farm.display().to_string()),
        "farm path must be absolute and point at current: {stdout}"
    );
    assert!(
        !stdout.contains("generations"),
        "the PATH entry must be the current link, never the generation: {stdout}"
    );
}

#[test]
fn shellenv_eval_puts_the_farm_on_path() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);

    let (_, stdout, _) = run(project.path(), root.path(), &["shellenv"]);
    // The acceptance run: eval the output in a real POSIX shell and
    // resolve a farm tool through the resulting PATH.
    let script = format!("{}\ncommand -v tool\n", stdout.trim_end());
    let sh = Command::new("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("failed to run sh");
    assert!(
        sh.status.success(),
        "eval'd shellenv must put the farm on PATH: {}",
        String::from_utf8_lossy(&sh.stderr)
    );
    let resolved = String::from_utf8_lossy(&sh.stdout);
    assert!(
        resolved.contains("default/current/tool"),
        "tool must resolve through the farm: {resolved}"
    );
}

#[test]
fn shellenv_json_reports_pod_farm_and_generation() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 7);

    let (code, stdout, stderr) = run(project.path(), root.path(), &["shellenv", "--json"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON on stdout");
    assert_eq!(v["pod"], "default");
    let farm = v["farm"].as_str().expect("farm is a string");
    assert!(
        farm.ends_with("default/current"),
        "farm must be the current link: {farm}"
    );
    assert_eq!(v["generation"], 7);
}

#[test]
fn shellenv_targets_the_named_pod() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);
    seed_active_farm(root.path(), "work", 4);

    let (code, stdout, stderr) = run(project.path(), root.path(), &["--name", "work", "shellenv"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("work/current"),
        "named pod's farm must be on PATH: {stdout}"
    );
    assert!(
        !stdout.contains("default/current"),
        "the default pod must not leak into a named shellenv: {stdout}"
    );
}

#[test]
fn shellenv_fails_on_unknown_pod() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run(project.path(), root.path(), &["shellenv"]);
    assert_eq!(code, Some(1));
    assert!(stdout.is_empty(), "a failed shellenv must print nothing");
    assert!(
        stderr.contains("pod 'default' has no state") && stderr.contains("add"),
        "error must name the pod and the verb that initializes it: {stderr}"
    );
}

#[test]
fn shellenv_fails_without_active_generation() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    // Declared but never synced: pod.lua exists, no `current`.
    seed_pod_lua(root.path(), "pod { packages = { \"jq\" } }");

    let (code, stdout, stderr) = run(project.path(), root.path(), &["shellenv"]);
    assert_eq!(code, Some(1));
    assert!(stdout.is_empty(), "a failed shellenv must print nothing");
    assert!(
        stderr.contains("no active generation") && stderr.contains("sync"),
        "error must point at syncing the pod: {stderr}"
    );
}

// ── shellenv secrets serve (ADR-0042 D3/D7/D8, issue #184) ──

const SECRET_SENTINEL: &str = "TOPSECRET-b184-VALUE";

/// An isolated tmpfs runtime dir for one test: the secrets session
/// cache lives under `$XDG_RUNTIME_DIR` and the D3 gate refuses anything
/// but tmpfs, so the tests use `/dev/shm` — never the real runtime dir.
/// Returns None when no tmpfs dir exists (skip, not fail).
fn secrets_runtime_dir(tag: &str) -> Option<std::path::PathBuf> {
    let base = std::path::Path::new("/dev/shm");
    if !base.is_dir() {
        return None;
    }
    let dir = base.join(format!("shuttle-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Run `shuttle pod <verb…>` with an isolated data home AND an isolated
/// tmpfs `$XDG_RUNTIME_DIR` (the secrets cache base).
fn run_with_runtime_dir(
    project: &Path,
    root: &Path,
    run_dir: &Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("SHUTTLE_DATA_HOME", root.join("data-home"));
    cmd.env("SHUTTLE_SYSTEMD", "off");
    cmd.env("XDG_RUNTIME_DIR", run_dir);
    let out = cmd.output().expect("failed to spawn shuttle pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A `+x` provider OUTSIDE the pod state root (the D4 refusal treats
/// pod-rooted programs as shadowing); prints its body's output.
fn write_provider(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.display().to_string()
}

/// The counting provider: one line appended per invocation; the line
/// count IS the invocation count. Prints a PEM-shaped secret.
fn write_counting_provider(dir: &Path, counter: &Path) -> String {
    let counter = counter.display();
    write_provider(
        dir,
        "counting-provider",
        &format!(
            "n=$(cat {counter} 2>/dev/null || echo 0); echo $((n+1)) > {counter}; \
             printf -- '-----BEGIN KEY-----\\nMIIb184\\n-----END KEY-----\\n'\n"
        ),
    )
}

fn provider_calls(counter: &Path) -> u32 {
    std::fs::read_to_string(counter)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Record the ACTIVE generation's secret references (the same
/// canonical bytes sync writes) via the library's own writer.
fn seed_generation_secrets(
    root: &Path,
    pod: &str,
    refs: &std::collections::BTreeMap<String, shuttle::pod::SecretSource>,
) {
    let store = shuttle::runtime::RuntimeStore::new(root.join(pod));
    shuttle::farm::write_generation_secrets(&store, 1, refs).unwrap();
}

fn exec_secret(command: &str) -> shuttle::pod::SecretSource {
    shuttle::pod::SecretSource::Exec {
        command: vec![command.to_string()],
    }
}

#[test]
fn shellenv_exports_resolved_secrets_after_env_lines_and_evals_safe() {
    let Some(run_dir) = secrets_runtime_dir("shellev") else {
        eprintln!("skipping: no tmpfs runtime dir available");
        return;
    };
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);

    // Declared env alongside, to pin the ordering rule; the counting
    // provider yields a PEM (newline-bearing) value.
    let counter = root.path().join("calls");
    let counting = write_counting_provider(root.path(), &counter);
    let static_p = write_provider(root.path(), "static-provider", "printf token123\\n");
    std::fs::write(
        pod_lua(root.path()),
        format!(
            "pod {{ env = {{ EDITOR = \"vi\" }}, secrets = {{ A_PEM = {{ source = \"exec\", \
             command = {{ \"{counting}\" }} }}, Z_TOKEN = {{ source = \"exec\", command = {{ \
             \"{static_p}\" }} }} }} }}\n"
        ),
    )
    .unwrap();
    let refs = std::collections::BTreeMap::from([
        ("A_PEM".to_string(), exec_secret(&counting)),
        ("Z_TOKEN".to_string(), exec_secret(&static_p)),
    ]);
    seed_generation_secrets(root.path(), "default", &refs);
    // The declared env rides the generation record (env.json) — write it
    // the way sync does, so SH_EDITOR is a real declared export, not an
    // ambient accident.
    let store = shuttle::runtime::RuntimeStore::new(root.path().join("default"));
    shuttle::farm::write_generation_env(
        &store,
        1,
        &[("SH_EDITOR".to_string(), "vi".to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();

    let (code, script, stderr) =
        run_with_runtime_dir(project.path(), root.path(), &run_dir, &["shellenv"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(provider_calls(&counter), 1, "cold serve resolves once");

    // Eval under `set -u`: every export readable, PEM newline intact.
    let eval = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "set -u\n{script}\nprintf '%s|%s' \"$EDITOR\" \"$A_PEM\""
        ))
        .output()
        .unwrap();
    assert!(
        eval.status.success(),
        "shellenv must eval clean under set -u: {}",
        String::from_utf8_lossy(&eval.stderr)
    );
    assert_eq!(
        String::from_utf8(eval.stdout).unwrap(),
        "vi|-----BEGIN KEY-----\nMIIb184\n-----END KEY-----",
        "env value then secret value verbatim (newline included)"
    );

    // Ordering: EVERY env export precedes EVERY secret export, secrets
    // sorted, POSIX single-quoted.
    let env_line = script.find("export SH_EDITOR='vi'").unwrap();
    let a = script.find("export A_PEM='").unwrap();
    let z = script.find("export Z_TOKEN='").unwrap();
    assert!(
        env_line < a && a < z,
        "env first, secrets sorted:\n{script}"
    );

    // The resolve warmed the session cache: a second shellenv is a hit
    // with zero provider calls.
    let (code, _, stderr) =
        run_with_runtime_dir(project.path(), root.path(), &run_dir, &["shellenv"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(
        provider_calls(&counter),
        1,
        "warm serve must make zero provider calls"
    );
    let _ = std::fs::remove_dir_all(&run_dir);
}

#[test]
fn shellenv_json_reports_secret_metadata_and_never_values() {
    let Some(run_dir) = secrets_runtime_dir("sheljson") else {
        eprintln!("skipping: no tmpfs runtime dir available");
        return;
    };
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);
    let provider = write_provider(
        root.path(),
        "sentinel-provider",
        &format!("echo {SECRET_SENTINEL}"),
    );
    std::fs::write(
        pod_lua(root.path()),
        format!(
            "pod {{ secrets = {{ K = {{ source = \"exec\", command = {{ \"{provider}\" }} }} }} }}\n"
        ),
    )
    .unwrap();
    let refs = std::collections::BTreeMap::from([("K".to_string(), exec_secret(&provider))]);
    seed_generation_secrets(root.path(), "default", &refs);

    let (code, stdout, stderr) = run_with_runtime_dir(
        project.path(),
        root.path(),
        &run_dir,
        &["shellenv", "--json"],
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let secret = v["secrets"]["K"]
        .as_object()
        .expect("secrets map carries K");
    assert_eq!(secret["source"], "exec");
    assert_eq!(secret["cache"], "hit");
    assert!(
        !stdout.contains(SECRET_SENTINEL),
        "--json must never carry a resolved value (D8): {stdout}"
    );
    assert!(
        !stdout.contains("secret_vars"),
        "the values map must not serialize at all: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&run_dir);
}

#[test]
fn shellenv_fails_loud_on_a_dead_provider_without_partial_exports() {
    let Some(run_dir) = secrets_runtime_dir("sheldead") else {
        eprintln!("skipping: no tmpfs runtime dir available");
        return;
    };
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    seed_active_farm(root.path(), "default", 1);
    let good = write_provider(root.path(), "good-provider", "echo partialvalue");
    let dead = write_provider(root.path(), "dead-provider", "exit 9");
    std::fs::write(
        pod_lua(root.path()),
        format!(
            "pod {{ secrets = {{ BAD = {{ source = \"exec\", command = {{ \"{dead}\" }} }}, \
             OK = {{ source = \"exec\", command = {{ \"{good}\" }} }} }} }}\n"
        ),
    )
    .unwrap();
    let refs = std::collections::BTreeMap::from([
        ("BAD".to_string(), exec_secret(&dead)),
        ("OK".to_string(), exec_secret(&good)),
    ]);
    seed_generation_secrets(root.path(), "default", &refs);

    let (code, stdout, stderr) =
        run_with_runtime_dir(project.path(), root.path(), &run_dir, &["shellenv"]);
    assert_ne!(code, Some(0), "a dead provider must fail the verb");
    assert!(
        stderr.contains("BAD") && stderr.contains("dead-provider"),
        "the failure names the var and provider: {stderr}"
    );
    assert!(
        !stdout.contains("export"),
        "no partial export set on stdout (D7): {stdout}"
    );
    assert!(
        !stdout.contains("partialvalue"),
        "even the healthy key's value must not leak: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&run_dir);
}
