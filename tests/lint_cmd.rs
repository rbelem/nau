//! `shuttle lint` integration tests (issue #53).
//!
//! Drives the real binary over the real eval path: the examples battery
//! must pass clean (no error findings), rejected declaration values must
//! surface as lint errors before any build, and warnings never gate the
//! exit code.

use std::path::Path;
use std::process::Command;

/// Repo root: the lint needs `package-index.json` in the CWD (the same
/// default the eval worker uses), and example paths are repo-relative.
fn repo_root() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn run_lint(cwd: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("lint").args(args).current_dir(cwd);
    let out = cmd.output().expect("failed to spawn shuttle lint");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn lint_file(cwd: &str, file: &str) -> (Option<i32>, String, String) {
    run_lint(cwd, &["--file", file])
}

/// Every example declaration lints with exit 0 — the battery reports no
/// error-level finding against any of them. (Warnings are allowed; they
/// never gate.)
#[test]
fn lint_examples_pass_clean() {
    let root = repo_root();
    let examples_dir = Path::new(root).join("examples");
    let mut files: Vec<_> = walk_lua(&examples_dir);
    files.sort();
    assert!(
        files.len() >= 10,
        "expected the example corpus, found {} files",
        files.len()
    );
    for file in &files {
        let rel = file.strip_prefix(root).unwrap_or(file);
        let (code, stdout, stderr) = lint_file(root, rel.to_str().unwrap());
        assert_eq!(
            code,
            Some(0),
            "example {rel:?} must lint clean (no error findings)\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

/// Collect every .lua file under `dir` (definitions only — the corpus is
/// tiny and fixed).
fn walk_lua(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "lua") {
                out.push(path);
            }
        }
    }
    out
}

/// A definition with a `bootloader.type` value validation rejects must
/// produce an ERROR finding and exit nonzero — before any build runs.
#[test]
fn lint_rejected_bootloader_type_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    rootfs = image {
        name = "bad-image",
        version = "1.0",
        base = pin("core22"),
        bootloader = { type = "grub", timeout = 5 },
    },
}
"#,
    )
    .unwrap();
    let file = dir.path().join("shuttle.lua");
    let (code, stdout, stderr) = lint_file(repo_root(), file.to_str().unwrap());
    assert_eq!(code, Some(1), "stdout: {stdout}\nstderr: {stderr}");
    let report = format!("{stdout}{stderr}");
    assert!(
        report.contains("bootloader-type") && report.contains("grub"),
        "the error must name the check and the rejected value: {report}"
    );
}

/// A warning-only finding (partition mount shadowing a system path) must
/// NOT gate the exit code.
#[test]
fn lint_warning_does_not_gate_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    rootfs = image {
        name = "shadowy",
        version = "1.0",
        base = pin("core22"),
        disk = {
            label = "gpt",
            partitions = {
                { name = "data", size = "1G", fs = "ext4", mount = "/etc" },
                { name = "root", size = "3G", fs = "ext4", mount = "/" },
            },
        },
    },
}
"#,
    )
    .unwrap();
    let file = dir.path().join("shuttle.lua");
    let (code, stdout, stderr) = lint_file(repo_root(), file.to_str().unwrap());
    assert_eq!(
        code,
        Some(0),
        "warnings must not fail lint\nstdout: {stdout}\nstderr: {stderr}"
    );
    let report = format!("{stdout}{stderr}");
    assert!(
        report.contains("shadow-mount") && report.contains("/etc"),
        "the warning must name the check and the path: {report}"
    );
}

/// `--json`: findings carry check, package, severity, message, hint; the
/// summary counts errors and warnings; `ok` mirrors "no errors".
#[test]
fn lint_json_report_shape() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    rootfs = image {
        name = "bad-image",
        version = "1.0",
        base = pin("core22"),
        bootloader = { type = "grub" },
    },
}
"#,
    )
    .unwrap();
    let file = dir.path().join("shuttle.lua");
    let (code, stdout, _) = run_lint(repo_root(), &["--file", file.to_str().unwrap(), "--json"]);
    assert_eq!(code, Some(1));
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--json must emit valid JSON ({e}): {stdout}"));
    assert_eq!(report["ok"], serde_json::Value::Bool(false));
    assert_eq!(report["errors"], 1);
    assert_eq!(report["warnings"], 0);
    let findings = report["findings"].as_array().expect("findings array");
    let bl = findings
        .iter()
        .find(|f| f["check"] == "bootloader-type")
        .expect("bootloader-type finding");
    assert_eq!(bl["package"], "rootfs");
    assert_eq!(bl["severity"], "error");
    assert!(
        bl["hint"].as_str().is_some_and(|h| !h.is_empty()),
        "every finding carries a fix hint: {bl}"
    );
}

/// An unreadable definition is a hard error, not an empty clean report.
#[test]
fn lint_missing_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("nope.lua");
    let (code, _, stderr) = lint_file(repo_root(), file.to_str().unwrap());
    assert_eq!(code, Some(1), "stderr: {stderr}");
}
