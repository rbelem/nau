//! Subprocess eval bounding (ADR-0010 Decisions 4+5).
//!
//! Integration tests over the real `shuttle __eval-worker` subprocess + IPC
//! path: happy-path eval, require-over-IPC with parent-side root
//! allowlisting, and the adversarial suite ported from
//! `spike/src/gates.rs` to Luau (containment: <5s wall, under rlimits,
//! parent unaffected, clean diagnostics).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shuttle::isolate::{self, EvalRequest, WorkerOutcome};
use shuttle::lua::{evaluate_file, evaluate_string};

fn request(entry_label: &str, source: &str) -> EvalRequest {
    EvalRequest {
        prelude: shuttle::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: BTreeMap::new(),
        entry: source.to_string(),
        entry_label: entry_label.to_string(),
    }
}

fn eval_err(label: &str, source: &str) -> String {
    match evaluate_string(label, source) {
        Ok(_) => panic!("expected eval of {label} to fail"),
        Err(e) => format!("{e:#}"),
    }
}

// ── Happy paths ──

#[test]
fn happy_path_eval_through_subprocess() {
    let src = r#"
    return {
        default = snap {
            name = "sub-test",
            version = "1.2.3",
            summary = "evaluated in the worker",
            architectures = { "amd64", "arm64" },
        },
    }"#;
    let outputs = evaluate_string("inline-test", src)
        .expect("happy-path eval through the subprocess must succeed");
    assert_eq!(outputs.len(), 1);
    let meta = &outputs["default"];
    assert_eq!(meta.name, "sub-test");
    assert_eq!(meta.version, "1.2.3");
    assert_eq!(
        meta.architectures.as_deref(),
        Some(&["amd64".to_string(), "arm64".to_string()][..])
    );
}

#[test]
fn require_goes_over_ipc_and_resolves_from_entry_dir() {
    // Full path: parent reads the file, ships it to the worker; the
    // definition's require() crosses back over IPC and the parent resolves
    // it from the entry file's directory (allowlisted root).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
local base = require("base")
return { default = snap(merge(base, { name = "composed", version = "9.9.9" })) }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("base.lua"),
        r#"return { version = "0.1.0", summary = "from base" }"#,
    )
    .unwrap();

    let entry = dir.path().join("shuttle.lua");
    let outputs = evaluate_file(entry.to_str().unwrap())
        .expect("require over IPC must resolve the sibling module");
    assert_eq!(outputs["default"].name, "composed");
    // merge(): the entry overrides the module's version…
    assert_eq!(outputs["default"].version, "9.9.9");
    // …and the module-only field proves the require crossed the IPC boundary.
    assert_eq!(outputs["default"].summary.as_deref(), Some("from base"));
}

#[test]
fn preseeded_sources_load_without_filesystem() {
    let mut req = request("preseed-test", r#"return { v = require("libmod").v }"#);
    req.sources
        .insert("libmod".to_string(), "return { v = 7 }".to_string());
    let ok = isolate::run_eval(&req).expect("preseeded module must load");
    assert_eq!(ok.outputs["v"], 7);
}

#[test]
fn global_inputs_cross_back_as_data() {
    let src = r#"
inputs = { core = { url = "github:core/core22/main" } }
return { default = snap { name = "with-inputs", version = "1.0" } }
"#;
    let out = shuttle::lua::evaluate_string_with_inputs("inputs-test", src)
        .expect("inputs must be extracted through the subprocess");
    assert_eq!(out.outputs["default"].name, "with-inputs");
    assert_eq!(out.global_inputs["core"].url, "github:core/core22/main");
}

// ── Resolver policy (parent side) ──

#[test]
fn resolver_rejects_parent_traversal() {
    let src = r#"return { v = require("../secret").v }"#;
    let err = eval_err("resolver-traversal", src);
    assert!(
        err.contains("rejected"),
        "traversal must be rejected on the parent side, got: {err}"
    );
}

#[test]
fn resolver_rejects_absolute_path() {
    let src = r#"return { v = require("/etc/passwd") }"#;
    let err = eval_err("resolver-absolute", src);
    assert!(
        err.contains("rejected"),
        "absolute paths must be rejected on the parent side, got: {err}"
    );
}

#[test]
fn resolver_rejects_missing_module_outside_roots() {
    let src = r#"return { v = require("no-such-module-anywhere") }"#;
    let err = eval_err("resolver-missing", src);
    assert!(err.contains("not found in allowlisted roots"), "got: {err}");
}

// ── Adversarial suite (ported from spike/src/gates.rs) ──

/// Assert an adversarial run was contained: bounded wall time, no Ok
/// outcome, and (when the worker answered) a clean error diagnostic.
fn assert_contained(run: &isolate::EvalRun) {
    assert!(
        run.wall_ms < 5500.0,
        "case escaped the 5s wall-clock budget: {}ms, status {}",
        run.wall_ms,
        run.status.describe()
    );
    match &run.outcome {
        Some(WorkerOutcome::Ok(_)) => panic!("adversarial case must not succeed"),
        Some(WorkerOutcome::Err(err)) => {
            assert!(!err.diagnostics.is_empty(), "worker must send diagnostics");
        }
        None => {
            // Worker died before answering (rlimit kill): still contained,
            // the parent reports it as a clean failure.
        }
    }
}

#[test]
fn fuzz_deep_recursion_is_contained() {
    // Luau `let`/`local` is non-recursive: the self-application idiom
    // creates genuine unbounded recursion (`f f 100000000`).
    let src = r#"
local f = function(self, n)
    if n == 0 then return 0 else return 1 + self(self, n - 1) end
end
return { value = f(f, 100000000), name = "x", version = "1" }
"#;
    let run = isolate::run_eval_raw(&request("fuzz-deep-recursion", src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
    assert!(
        run.max_rss_kb < 512 * 1024,
        "worker stayed under the 512MB rlimit, peak was {}kB",
        run.max_rss_kb
    );
}

#[test]
fn fuzz_huge_string_growth_is_contained() {
    // Tiny source, exponential string doubling → allocation blowup.
    let mut src = String::from("local s0 = \"0123456789012345678901234567890123456789\"\n");
    for i in 1..=32 {
        let prev = i - 1;
        src.push_str(&format!("  local s{i} = s{prev} .. s{prev}\n"));
    }
    src.push_str("return { value = s32, name = \"x\", version = \"1\" }");

    let run = isolate::run_eval_raw(&request("fuzz-huge-literal", &src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
    assert!(
        run.max_rss_kb < 512 * 1024,
        "worker stayed under the 512MB rlimit, peak was {}kB",
        run.max_rss_kb
    );
}

#[test]
fn fuzz_deep_table_growth_is_contained() {
    let src = "local t = {}\nfor i = 1, 100000000 do t = { t } end\nreturn { value = t, name = \"x\", version = \"1\" }";
    let run = isolate::run_eval_raw(&request("fuzz-deep-table", src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
}

#[test]
fn fuzz_contract_violation_is_a_clean_fast_diagnostic() {
    // Contract-style type error: snap() validates eagerly and raises, so the
    // eval fails fast with a clean diagnostic (never a crash or a hang).
    let src = r#"return { default = snap { name = 42, version = "1.0" } }"#;
    let start = Instant::now();
    let err = eval_err("fuzz-contract", src);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "contained in {elapsed:?}");
    assert!(err.contains("field 'name' must be a string"), "got: {err}");
}

#[test]
fn fuzz_busy_loop_hits_wall_clock_deadline() {
    let src = "while true do end";
    let start = Instant::now();
    let err = eval_err("fuzz-busy-loop", src);
    let elapsed = start.elapsed();
    // The parent killed the worker at the deadline and reports a clean error.
    assert!(
        elapsed >= Duration::from_millis(4500),
        "deadline fired too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "parent took too long to regain control: {elapsed:?}"
    );
    assert!(
        err.contains("deadline") || err.contains("signalled") || err.contains("signal"),
        "timeout must be reported as a clean diagnostic, got: {err}"
    );
}

// ── StdLib narrowing (ADR-0010 Decision 4) ──

#[test]
fn worker_has_no_os_library_determinism() {
    let src = r#"return { t = os.time(), name = "x", version = "1" }"#;
    let err = eval_err("stdlib-os", src);
    assert!(
        err.to_lowercase().contains("nil"),
        "`os` must be absent in the worker VM, got: {err}"
    );
}

#[test]
fn worker_has_no_debug_library() {
    let src = r#"return { t = debug.traceback(), name = "x", version = "1" }"#;
    let err = eval_err("stdlib-debug", src);
    assert!(
        err.to_lowercase().contains("nil"),
        "`debug` must be absent in the worker VM, got: {err}"
    );
}

// ── Fatal-eval semantics preserved across the boundary ──

#[test]
fn non_table_result_fails_with_original_message() {
    let err = eval_err("non-table", "return 42");
    assert!(
        err.contains("must return a table of outputs, got integer"),
        "got: {err}"
    );
}

#[test]
fn broken_output_is_skipped_with_warning_not_silently_dropped() {
    let src = r#"
    return {
        good = snap { name = "good-snap", version = "1.0" },
        bad = "not-a-snap-table",
    }
    "#;
    let outputs = evaluate_string("test-broken", src)
        .expect("broken output should warn and be skipped, not fail the eval");
    assert_eq!(outputs.len(), 1, "only the valid output should be kept");
    assert!(outputs.contains_key("good"));
}

#[test]
fn composed_config_via_evaluate_file() {
    let result = evaluate_file("test-fixtures/composed.lua");
    assert!(
        result.is_ok(),
        "composed config should evaluate: {:?}",
        result.err()
    );

    let outputs = result.unwrap();
    assert!(outputs.contains_key("default"));

    let meta = &outputs["default"];
    assert_eq!(meta.name, "my-composed-app");
    assert_eq!(meta.version, "1.0.0");
    // From the base template via merge
    assert_eq!(meta.summary.as_deref(), Some("A snap built with shuttle"));
    assert_eq!(meta.grade, "stable");
    assert_eq!(meta.confinement, "strict");
}
