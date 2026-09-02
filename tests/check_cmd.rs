//! `shuttle check` integration tests (ADR-0010 Decisions 2-3).
//!
//! Drives the real binary over the real subprocess-eval path: success
//! reporting, failing definitions (exit code + diagnostics), and the
//! `--json` report shape that the AI feedback loop consumes.

use std::process::Command;

fn run_check(dir: &std::path::Path, json: bool) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("check").arg("shuttle.lua").current_dir(dir);
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().expect("failed to spawn shuttle check");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_def(dir: &std::path::Path, source: &str) {
    std::fs::write(dir.join("shuttle.lua"), source).unwrap();
}

const GOOD_DEF: &str = r#"
return {
    default = snap {
        name = "checked-snap",
        version = "1.2.3",
    },
}
"#;

// ── Success ──

#[test]
fn check_success_exits_zero_and_lists_outputs() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), GOOD_DEF);
    let (code, stdout, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("ok: 1 output(s)") && stderr.contains("default"),
        "must report the output count and name, got: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "human mode writes to stderr only: {stdout}"
    );
}

#[test]
fn check_success_multi_output_lists_every_name() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    zeta = snap { name = "z", version = "1" },
    alpha = snap { name = "a", version = "1" },
}
"#,
    );
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("ok: 2 output(s)") && stderr.contains("zeta") && stderr.contains("alpha"),
        "got: {stderr}"
    );
}

// ── Failing definitions (human mode) ──

#[test]
fn check_schema_skip_exits_one_with_diagnostics() {
    // Eval succeeds but the Rust-side validation rejects one output:
    // warn-and-continue must surface as a diagnostic + exit 1, and the
    // valid output must still be reported.
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    good = snap { name = "fine", version = "1.0" },
    bad = "not-a-snap-table",
}
"#,
    );
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("bad") && stderr.contains("expected a table from snap(), got string"),
        "diagnostic must name the output and the problem, got: {stderr}"
    );
}

#[test]
fn check_hard_eval_failure_exits_one() {
    // snap() validates eagerly at eval time: name = 42 fails inside the
    // bounded subprocess and the error must come back as a diagnostic.
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"return { default = snap { name = 42, version = "1.0" } }"#,
    );
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("field 'name' must be a string"),
        "got: {stderr}"
    );
}

#[test]
fn check_syntax_error_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), "return { default = ");
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(!stderr.trim().is_empty(), "a diagnostic must be printed");
}

#[test]
fn check_missing_file_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("could not read shuttle.lua"),
        "got: {stderr}"
    );
}

// ── JSON mode ──

#[test]
fn check_json_success_shape() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), GOOD_DEF);
    let (code, stdout, _) = run_check(dir.path(), true);
    assert_eq!(code, Some(0));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(v["file"], "shuttle.lua");
    assert_eq!(v["ok"], true);
    assert_eq!(v["outputs"], serde_json::json!(["default"]));
    assert_eq!(v["diagnostics"], serde_json::json!([]));
}

#[test]
fn check_json_failure_shape_has_structured_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    good = snap { name = "fine", version = "1.0" },
    bad = "not-a-snap-table",
}
"#,
    );
    let (code, stdout, _) = run_check(dir.path(), true);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(v["file"], "shuttle.lua");
    assert_eq!(v["ok"], false);
    // The output that passed validation is still listed.
    assert_eq!(v["outputs"], serde_json::json!(["good"]));

    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["label"], "shuttle.lua");
    assert_eq!(diags[0]["key"], "bad");
    assert_eq!(diags[0]["expected"], serde_json::Value::Null);
    assert_eq!(diags[0]["actual"], serde_json::Value::Null);
    let msg = diags[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("expected a table from snap(), got string"),
        "{msg}"
    );
}

#[test]
fn check_json_hard_error_carries_diagnostic_with_null_key() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), "return 42");
    let (code, stdout, _) = run_check(dir.path(), true);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(v["ok"], false);
    assert_eq!(v["outputs"], serde_json::json!([]));
    let diags = v["diagnostics"].as_array().unwrap();
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["key"], serde_json::Value::Null);
    assert!(
        diags[0]["message"]
            .as_str()
            .unwrap()
            .contains("must return a table of outputs, got integer"),
        "got: {}",
        diags[0]["message"]
    );
}

// ── Analyzer gate (ADR-0010 Decision 2, stage 1 of `shuttle check`) ──

/// A `name = 42`-style type error against an explicit annotation: the
/// analyzer stage reports it with a 1-based span and fast-fails before the
/// eval stage runs (the eval schema error for the same problem never
/// appears).
const ANALYZER_TYPE_ERROR: &str = r#"
local meta: { name: string, version: string } = {
    name = 42,
    version = "1.0",
}
return { default = snap(meta) }
"#;

#[test]
fn check_analyzer_type_error_fast_fails_with_span_json() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), ANALYZER_TYPE_ERROR);
    let (code, stdout, _) = run_check(dir.path(), true);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    assert_eq!(v["ok"], false);
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(!diags.is_empty(), "analyzer must flag the type error: {v}");
    let span = &diags[0]["span"];
    assert!(
        !span.is_null(),
        "analyzer diagnostics carry spans: {}",
        diags[0]
    );
    assert_eq!(span["begin_line"], 2, "1-based line of the constructor");
    assert!(span["begin_col"].as_u64().unwrap() >= 1);
    let msg = diags[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("number") && msg.contains("string"),
        "spanned type error must mention the types: {msg}"
    );
}

#[test]
fn check_analyzer_type_error_fast_fails_before_eval_human() {
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), ANALYZER_TYPE_ERROR);
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("shuttle.lua:2:"),
        "human output must carry the 1-based span: {stderr}"
    );
    // Fast fail: the eval stage (which would report the same problem as a
    // schema error, "field 'name' must be a string") never ran.
    assert!(
        !stderr.contains("must be a string, got"),
        "eval stage must be skipped when the analyzer gate fails: {stderr}"
    );
}

#[test]
fn check_cross_module_require_type_error_is_spanned() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("pkg")).unwrap();
    std::fs::write(
        dir.path().join("pkg/apptpl.lua"),
        r#"
local M = {}
function M.app(opts: { command: string }): { command: string }
    return opts
end
return M
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("pkg/shuttle.lua"),
        r#"
local tpl = require("apptpl")

return {
    default = snap {
        name = tpl.app({ command = 42 }).command,
        version = "1.0",
    },
}
"#,
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("check").arg("pkg/shuttle.lua").arg("--json");
    let out = cmd.current_dir(dir.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert!(!diags.is_empty(), "type error must cross the boundary: {v}");
    let msg = diags[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("number") && msg.contains("string"),
        "cross-module type error: {msg}"
    );
    assert!(
        !diags[0]["span"].is_null(),
        "spanned at the definition side: {}",
        diags[0]
    );
}

#[test]
fn check_real_pkgs_file_passes_analyzer_gate() {
    // A real corpus definition must type-check cleanly against the typed
    // prelude (injected globals bound, require resolution live) — the
    // "no false positives" property of the gate.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shuttle"));
    cmd.arg("check").arg("pkgs/h/hello.lua").arg("--json");
    let out = cmd
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON");
    assert_eq!(v["ok"], true);
    assert_eq!(v["diagnostics"], serde_json::json!([]));
}

#[test]
fn check_unresolved_require_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"local x = require("nowhere") return { default = x }"#,
    );
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("Unknown require"),
        "gate fails closed on unresolvable requires: {stderr}"
    );
}

// ── Schema-stage spans (localization of post-eval validation errors) ──

#[test]
fn check_schema_diagnostic_carries_located_span_json() {
    // The schema error for output `bad` points at its declaration site:
    // `bad = "not-a-snap-table"` sits on line 4, column 5 of this source
    // (leading newline makes line 1 empty).
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    good = snap { name = "fine", version = "1.0" },
    bad = "not-a-snap-table",
}
"#,
    );
    let (code, stdout, _) = run_check(dir.path(), true);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON on stdout");
    let diags = v["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["key"], "bad");
    let span = &diags[0]["span"];
    assert!(
        !span.is_null(),
        "schema diagnostics for keyed outputs must localize: {}",
        diags[0]
    );
    assert_eq!(span["begin_line"], 4, "line of `bad = ...`: {span}");
    assert_eq!(span["begin_col"], 5, "column of `bad`: {span}");
}

#[test]
fn check_schema_diagnostic_prints_position_human() {
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        r#"
return {
    good = snap { name = "fine", version = "1.0" },
    bad = "not-a-snap-table",
}
"#,
    );
    let (code, _, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("shuttle.lua:4:5: [bad]"),
        "human output must point at the declaration site: {stderr}"
    );
}

// ── Hot-comment downgrade rejection (gate integrity, REPORT.md rec 3) ──

#[test]
fn check_hot_comment_downgrade_exits_one_with_named_diagnostic() {
    // Without the rejection this definition would pass the gate: nonstrict
    // mode does not flag unknown globals. The rejection must come from the
    // analyzer gate BEFORE eval, exit 1, and be the only diagnostic.
    let dir = tempfile::tempdir().unwrap();
    write_def(
        dir.path(),
        "--!nonstrict\nreturn { default = snp { name = \"x\" } }",
    );
    let (code, stdout, stderr) = run_check(dir.path(), false);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("--!nonstrict") && stderr.contains("host-controlled"),
        "diagnostic must name the offending comment, got: {stderr}"
    );
    // Fast fail: the eval stage never ran (it would have validated the snap
    // and reported `snp` differently or passed it).
    assert!(
        !stderr.contains("ok:"),
        "gate must fail, not fall through to eval: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "human mode writes to stderr only: {stdout}"
    );
}

// ── Analyzer wall-clock bound (fail closed) ──

#[test]
fn check_reports_timeout_diagnostic_and_exits_one() {
    // The production 10s bound cannot be tripped cheaply by a test source;
    // the bound's *mechanics* (abort + single `analysis timed out`
    // diagnostic, eval-grade partial results discarded) are exercised here
    // through the injected bound on the test-only in-process entry point —
    // the same normalization the `__check-worker` child applies for
    // `shuttle check` (see tests/attack_isolation.rs
    // `attack_worker_timeout_is_single_fail_closed_diagnostic` for the
    // subprocess-level contract).
    let source = "return { default = snap { name = \"t\", version = \"1\" } }";
    let diags = shuttle::analysis::check_definition_with_limit("timeout-test", source, Some(0.0));
    assert_eq!(diags.len(), 1, "partial results are discarded: {diags:?}");
    assert!(
        diags[0].message.contains("analysis timed out"),
        "got: {:?}",
        diags[0].message
    );
}

#[test]
fn check_wall_latency_stays_sub_second() {
    // The latency target for `shuttle check` is <100ms wall including the
    // eval subprocess (ADR-0010 Decision 8); measured manually on release
    // builds (see analyzer integration report). CI machines are noisy, so
    // this test is a coarse regression tripwire at 1s, not the target proof.
    let dir = tempfile::tempdir().unwrap();
    write_def(dir.path(), GOOD_DEF);
    let start = std::time::Instant::now();
    let (code, _, _) = run_check(dir.path(), false);
    let elapsed = start.elapsed();
    assert_eq!(code, Some(0));
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "check took {elapsed:?}; subprocess+analyzer path regressed"
    );
}
