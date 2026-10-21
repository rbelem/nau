//! The eval worker's own bounds (ADR-0010 Decision 4, issue #12).
//!
//! Two mechanisms live inside the worker process, not in the parent:
//! the Luau VM interrupt hook, which aborts a runaway chunk inside the
//! wall-clock budget, and the Luau VM sandbox mode, which closes the
//! door a hostile chart opens before it blows the VM memory cap. Both
//! are driven through the real subprocess, so these tests exercise the
//! same path the operator hits.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nau::isolate::{self, EvalRequest};

fn request(entry_label: &str, source: &str) -> EvalRequest {
    EvalRequest {
        prelude: nau::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: BTreeMap::new(),
        entry: source.to_string(),
        entry_label: entry_label.to_string(),
        allow_fetch: false,
        constraint: None,
        versions_mode: false,
    }
}

fn eval_err(label: &str, source: &str) -> String {
    match isolate::run_eval(&request(label, source)) {
        Ok(_) => panic!("expected eval of {label} to fail"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn busy_loop_is_aborted_by_the_vm_interrupt_hook() {
    // The Luau VM interrupt hook is the mechanism: the worker aborts the
    // runaway chunk inside the budget and the operator gets a
    // diagnosable Lua error, not the parent's SIGKILL backstop. The
    // worker aborts at ~4.6s against the parent's 5s kill, so the margin
    // is ~380ms of wall clock.
    let start = Instant::now();
    let err = eval_err("fuzz-busy-loop-hook", "while true do end");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(4500),
        "the cooperative abort must not fire too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(5000),
        "the cooperative abort must beat the parent's wall-clock kill: {elapsed:?}"
    );
    assert!(
        err.contains("eval aborted") && err.contains("wall-clock deadline"),
        "the abort must reach the operator as a diagnosable Lua error, got: {err}"
    );
}

#[test]
fn worker_refuses_to_stop_the_collector() {
    // Luau VM sandbox mode: `collectgarbage("stop")` is the door a
    // hostile chart opens before it blows the VM memory cap. The
    // sandbox reduces collectgarbage to its `count` mode, so the door
    // is closed.
    let src =
        r#"return { ok = tostring(pcall(collectgarbage, "stop")), name = "x", version = "1" }"#;
    let ok = isolate::run_eval(&request("sandbox-gc", src)).expect("the chart must still evaluate");
    assert_eq!(
        ok.outputs["ok"], "false",
        "the worker must refuse to stop the collector"
    );
}
