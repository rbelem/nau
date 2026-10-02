//! `nau chart versions` integration tests (ADR-0052 Decisions 1-2).
//!
//! Drives the real binary over the real versions-mode worker path: the
//! aligned table render, the `--json` shape, the named skip for snaps
//! without a versions method, and the `--output` filter. Runs offline —
//! the fixtures never call `fetch()`.

use std::process::Command;

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_versions(dir: &std::path::Path, extra: &[&str]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_nau"))
        .arg("chart")
        .arg("versions")
        .arg("nau.lua")
        .args(extra)
        .current_dir(dir)
        .output()
        .expect("failed to spawn nau chart versions");
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn write_def(dir: &std::path::Path, source: &str) {
    std::fs::write(dir.join("nau.lua"), source).unwrap();
}

const VERSIONED_DEF: &str = r#"
return {
    zeta = snap {
        name = "z-thing",
        version = "3.0.0",
        versions = function() return { "3.0.0", "2.9.1", "2.9.0" } end,
    },
    alpha = snap {
        name = "a-thing",
        version = "1.2.3",
        versions = function() return { "1.2.3", "1.2.2" } end,
    },
}
"#;

const UNVERSIONED_DEF: &str = r#"
return {
    default = snap {
        name = "plain-jane",
        version = "1.0",
    },
}
"#;

// ── Table render ──

#[test]
fn table_lists_outputs_versions_and_marks_latest() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), VERSIONED_DEF);
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    // Header + both outputs (sorted), versions in order, `latest` marker
    // on the recipe-resolved version only.
    assert!(
        out.stdout.contains("output")
            && out.stdout.contains("version")
            && out.stdout.contains("available"),
        "header missing: {}",
        out.stdout
    );
    assert!(out.stdout.contains("alpha"), "{}", out.stdout);
    assert!(out.stdout.contains("zeta"), "{}", out.stdout);
    assert!(out.stdout.contains("3.0.0 (latest)"), "{}", out.stdout);
    assert!(
        out.stdout.contains("2.9.1") && out.stdout.contains("2.9.0"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("1.2.3 (latest)"), "{}", out.stdout);
    // Older versions carry no marker.
    assert!(!out.stdout.contains("2.9.1 (latest)"), "{}", out.stdout);
}

#[test]
fn empty_listing_is_a_valid_table_row() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    default = snap {
        name = "quiet",
        version = "1.0",
        versions = function() return {} end,
    },
}
"#,
    );
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stdout.contains("(empty listing)"), "{}", out.stdout);
}

// ── Named skip ──

#[test]
fn snap_without_versions_method_is_a_named_skip_exit_zero() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), UNVERSIONED_DEF);
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("default") && out.stderr.contains("no versions method"),
        "skip must name the output, got: {}",
        out.stderr
    );
    assert!(
        out.stdout.is_empty(),
        "no table for a skipped output: {}",
        out.stdout
    );
}

#[test]
fn mixed_def_skips_one_and_lists_the_other() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    listed = snap {
        name = "listed",
        version = "2.0.0",
        versions = function() return { "2.0.0", "1.9.0" } end,
    },
    unlisted = snap { name = "unlisted", version = "1.0" },
}
"#,
    );
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(
        out.stdout.contains("listed") && out.stdout.contains("2.0.0 (latest)"),
        "{}",
        out.stdout
    );
    assert!(
        out.stderr.contains("unlisted") && out.stderr.contains("no versions method"),
        "{}",
        out.stderr
    );
}

// ── --output filter ──

#[test]
fn output_filter_lists_one_output_only() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), VERSIONED_DEF);
    let out = run_versions(dir.path(), &["--output", "zeta"]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    assert!(out.stdout.contains("zeta"), "{}", out.stdout);
    assert!(
        !out.stdout.contains("alpha"),
        "filter must exclude alpha: {}",
        out.stdout
    );
}

#[test]
fn unknown_output_name_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), VERSIONED_DEF);
    let out = run_versions(dir.path(), &["--output", "nope"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("no output 'nope'"),
        "got: {}",
        out.stderr
    );
}

// ── --json ──

#[test]
fn json_shape_carries_resolved_and_versions() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), VERSIONED_DEF);
    let out = run_versions(dir.path(), &["--json"]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON report");
    let alpha = &v["alpha"];
    assert_eq!(alpha["resolved"], "1.2.3");
    assert_eq!(alpha["versions"][0], "1.2.3");
    assert_eq!(alpha["versions"][1], "1.2.2");
    let zeta = &v["zeta"];
    assert_eq!(zeta["resolved"], "3.0.0");
    assert_eq!(zeta["versions"].as_array().map(Vec::len), Some(3));
}

#[test]
fn json_null_versions_for_a_named_skip() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), UNVERSIONED_DEF);
    let out = run_versions(dir.path(), &["--json"]);
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON report");
    assert_eq!(v["default"]["resolved"], "1.0");
    assert!(v["default"]["versions"].is_null());
}

#[test]
fn json_output_filter_applies() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), VERSIONED_DEF);
    let out = run_versions(dir.path(), &["--json", "--output", "alpha"]);
    assert_eq!(out.code, Some(0));
    let v: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON report");
    let obj = v.as_object().expect("top-level object");
    assert_eq!(obj.len(), 1, "only the filtered output: {v}");
    assert!(obj.contains_key("alpha"));
}

// ── Failed listings ──

#[test]
fn raising_versions_method_is_a_named_error_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    default = snap {
        name = "boomer",
        version = "1.0",
        versions = function() error("upstream gone") end,
    },
}
"#,
    );
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("default") && out.stderr.contains("upstream gone"),
        "got: {}",
        out.stderr
    );
}

#[test]
fn json_mode_also_fails_on_a_broken_listing() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    default = snap {
        name = "shaper",
        version = "1.0",
        versions = function() return "1.0" end,
    },
}
"#,
    );
    let out = run_versions(dir.path(), &["--json"]);
    assert_eq!(out.code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON report");
    assert!(v["default"]["versions"].is_null());
    assert!(
        v["default"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("must return an array"),
        "{}",
        v["default"]
    );
}

// ── DSL validation ──

#[test]
fn non_function_versions_field_is_a_named_schema_error() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return { default = snap { name = "x", version = "1", versions = "2.0" } }
"#,
    );
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("field 'versions'") && out.stderr.contains("must be a function"),
        "got: {}",
        out.stderr
    );
}

#[test]
fn missing_file_is_a_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_versions(dir.path(), &[]);
    assert_eq!(out.code, Some(1));
}
