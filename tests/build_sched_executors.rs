//! The `BuildExecutor` seam in the ready-set scheduler (ADR-0040
//! Decision 4, T2): pool sizing from the `workers` config, fan-out
//! through the executor, stop-the-world on first failure, and ready-set
//! ordering — all preserved from the pre-seam scheduler.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use shuttle::build_sched::{
    pool_budget, run_ready_set_with_executor, BuildExecutor, FailedBuilds, LocalExecutor,
    MAX_PARALLEL_BUILD_WORKERS,
};
use shuttle::lua::WorkersConfig;

fn graph(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(name, deps)| {
            (
                name.to_string(),
                deps.iter().map(|d| d.to_string()).collect(),
            )
        })
        .collect()
}

fn worker(address: &str, jobs: u32) -> shuttle::lua::WorkerConfig {
    shuttle::lua::WorkerConfig {
        address: address.to_string(),
        jobs,
        arch: None,
        host_key: None,
    }
}

fn sleep_ms(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

// ── Pool sizing ──

#[test]
fn empty_workers_budget_is_todays_fixed_parallelism() {
    let cfg = WorkersConfig::default();
    assert!(cfg.workers.is_empty());
    assert_eq!(
        pool_budget(&cfg),
        MAX_PARALLEL_BUILD_WORKERS,
        "no workers key = exactly today's fixed three"
    );
}

#[test]
fn budget_is_local_slots_plus_sum_of_worker_jobs() {
    let cfg = WorkersConfig {
        local_jobs: 1,
        workers: vec![worker("ssh://a", 2), worker("ssh://b", 3)],
    };
    assert_eq!(pool_budget(&cfg), 6, "1 local + 2 + 3");
}

#[test]
fn budget_follows_the_eval_payload() {
    let src = r#"
workers = {
  local_jobs = 5,
  { address = "ssh://rodrigo@nuci.local", jobs = 4 },
  { address = "ssh://build@edge01" },
}
return { default = snap { name = "pool-budget", version = "1.0" } }
"#;
    let out = shuttle::lua::evaluate_string_with_inputs("pool-budget-test", src)
        .expect("valid workers table must eval");
    assert_eq!(pool_budget(&out.workers), 11, "5 local + 4 + default 2");
}

// ── Dense/sparse index validation (pre-wiring for #191) ──

fn eval_err(workers_decl: &str) -> String {
    let src = format!(
        r#"
{workers_decl}
return {{ default = snap {{ name = "dense-idx", version = "1.0" }} }}
"#
    );
    shuttle::lua::evaluate_string_with_inputs("dense-idx-test", &src)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_else(|| panic!("expected a refusal, got green: {workers_decl}"))
}

#[test]
fn sparse_worker_indices_are_refused_by_name() {
    let err = eval_err(
        r#"workers = {
  { address = "ssh://a" },
  [3] = { address = "ssh://c" },
}"#,
    );
    assert!(err.contains("dense 1..n"), "{err}");
    assert!(
        err.contains("workers[3]"),
        "names the offending index: {err}"
    );
}

#[test]
fn index_sequence_not_starting_at_one_is_refused() {
    let err = eval_err(
        r#"workers = {
  [2] = { address = "ssh://b" },
  [3] = { address = "ssh://c" },
}"#,
    );
    assert!(
        err.contains("workers[2]"),
        "names the offending index: {err}"
    );
    assert!(err.contains("expected index 1"), "{err}");
}

#[test]
fn dense_mixed_key_spellings_are_accepted() {
    // ["1"] and [2] are the same dense 1..n sequence — Luau surfaces
    // array keys as string digits unpredictably; this must stay valid.
    let src = r#"
workers = {
  ["1"] = { address = "ssh://a" },
  [2] = { address = "ssh://b" },
}
return { default = snap { name = "dense-idx", version = "1.0" } }
"#;
    let out = shuttle::lua::evaluate_string_with_inputs("dense-idx-test", src)
        .expect("dense mixed key spellings must eval");
    assert_eq!(out.workers.workers.len(), 2);
    assert_eq!(out.workers.workers[0].address, "ssh://a");
}

// ── Fan-out through the executor ──

/// Shared event log + in-flight tracker, mirroring the scheduler's own
/// unit-test harness.
#[derive(Clone)]
struct Log {
    events: Arc<Mutex<Vec<String>>>,
    inflight: Arc<AtomicUsize>,
    max_inflight: Arc<AtomicUsize>,
}

impl Log {
    fn new() -> Self {
        Log {
            events: Arc::new(Mutex::new(Vec::new())),
            inflight: Arc::new(AtomicUsize::new(0)),
            max_inflight: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn start(&self, name: &str) {
        self.events.lock().unwrap().push(format!("start:{name}"));
        let n = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_inflight.fetch_max(n, Ordering::SeqCst);
    }

    fn end(&self, name: &str) {
        self.events.lock().unwrap().push(format!("end:{name}"));
        self.inflight.fetch_sub(1, Ordering::SeqCst);
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn position(&self, event: &str) -> usize {
        self.events()
            .iter()
            .position(|e| e == event)
            .unwrap_or_else(|| panic!("event {event} not in log {:?}", self.events()))
    }
}

#[test]
fn local_executor_fans_out_to_the_pool_budget() {
    // Budget 3 (2 local + 1 worker): six independent jobs, never more
    // than 3 in flight, and really 3 — not a serialized queue.
    let cfg = WorkersConfig {
        local_jobs: 2,
        workers: vec![worker("ssh://a", 1)],
    };
    let budget = pool_budget(&cfg);
    assert_eq!(budget, 3);

    let log = Log::new();
    let g = graph(&[
        ("j1", &[]),
        ("j2", &[]),
        ("j3", &[]),
        ("j4", &[]),
        ("j5", &[]),
        ("j6", &[]),
    ]);
    let l = log.clone();
    let executor = LocalExecutor::new(move |name| {
        l.start(name);
        sleep_ms(120);
        l.end(name);
        Ok(())
    });
    run_ready_set_with_executor(&g, &HashSet::new(), budget, &executor)
        .expect("independent jobs build clean");
    assert_eq!(
        log.max_inflight.load(Ordering::SeqCst),
        3,
        "fan-out must reach exactly the pool budget: {:?}",
        log.events()
    );
}

/// An executor that records every dispatch and cancel — proves the
/// scheduler really routes jobs through the seam.
#[derive(Default)]
struct RecordingExecutor {
    runs: Mutex<Vec<String>>,
    cancels: AtomicUsize,
    fail: AtomicBool,
}

impl RecordingExecutor {
    fn ran(&self) -> Vec<String> {
        self.runs.lock().unwrap().clone()
    }
}

impl BuildExecutor for RecordingExecutor {
    fn run(&self, name: &str) -> Result<(), String> {
        self.runs.lock().unwrap().push(name.to_string());
        if self.fail.load(Ordering::SeqCst) {
            Err(format!("{name} exploded"))
        } else {
            Ok(())
        }
    }

    fn cancel(&self) {
        self.cancels.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn every_ready_node_dispatches_through_the_executor() {
    let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
    let executor = RecordingExecutor::default();
    run_ready_set_with_executor(&g, &HashSet::new(), 3, &executor).expect("diamond builds clean");
    let mut ran = executor.ran();
    ran.sort();
    assert_eq!(
        ran,
        vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string()
        ],
        "every node runs exactly once, through the executor"
    );
    assert_eq!(
        executor.cancels.load(Ordering::SeqCst),
        0,
        "no failure, no cancel"
    );
}

// ── Stop-the-world ──

#[test]
fn executor_failure_trips_stop_the_world_and_cancel() {
    let g = graph(&[
        ("boom", &[]),
        ("dep", &["boom"]),
        ("j1", &[]),
        ("j2", &[]),
        ("j3", &[]),
    ]);
    let executor = RecordingExecutor::default();
    executor.fail.store(true, Ordering::SeqCst);

    let err = run_ready_set_with_executor(&g, &HashSet::new(), 1, &executor)
        .expect_err("first failure must fail the run");
    let FailedBuilds { failed, skipped } = err;
    assert_eq!(
        failed,
        vec![("boom".to_string(), "boom exploded".to_string())],
        "the failed set names the node and its error"
    );
    assert_eq!(
        skipped,
        vec![
            "dep".to_string(),
            "j1".to_string(),
            "j2".to_string(),
            "j3".to_string()
        ],
        "dependents and unstarted ready work are skipped, in declaration order"
    );
    assert_eq!(
        executor.ran(),
        vec!["boom".to_string()],
        "stop-the-world: exactly one job ever dispatched"
    );
    assert_eq!(
        executor.cancels.load(Ordering::SeqCst),
        1,
        "cancel fires once, at the stop-the-world trip"
    );
}

#[test]
fn local_failure_never_starts_dependents() {
    let log = Log::new();
    let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"]), ("solo", &[])]);
    let l = log.clone();
    let executor = LocalExecutor::new(move |name| {
        l.start(name);
        sleep_ms(30);
        if name == "a" {
            return Err("a exploded".to_string());
        }
        l.end(name);
        Ok(())
    });
    let err = run_ready_set_with_executor(&g, &HashSet::new(), 3, &executor)
        .expect_err("failed root must fail the run");
    assert_eq!(
        err.failed,
        vec![("a".to_string(), "a exploded".to_string())]
    );
    let events = log.events();
    assert!(!events.iter().any(|e| e == "start:b"), "{events:?}");
    assert!(!events.iter().any(|e| e == "start:c"), "{events:?}");
    assert!(events.iter().any(|e| e == "end:solo"), "{events:?}");
    assert_eq!(err.skipped, vec!["b".to_string(), "c".to_string()]);
}

// ── Ordering ──

#[test]
fn executor_preserves_ready_set_ordering() {
    // Linear chain: strict end-before-next-start. Diamond: d starts only
    // after BOTH b and c end, while b/c (ready together) overlap.
    let log = Log::new();
    let g = graph(&[
        ("a", &[]),
        ("b", &["a"]),
        ("c", &["a"]),
        ("d", &["b", "c"]),
        ("e", &["d"]),
    ]);
    let l = log.clone();
    let executor = LocalExecutor::new(move |name| {
        l.start(name);
        match name {
            "b" | "c" => sleep_ms(120),
            _ => sleep_ms(10),
        }
        l.end(name);
        Ok(())
    });
    run_ready_set_with_executor(&g, &HashSet::new(), 3, &executor)
        .expect("diamond chain builds clean");

    let events = log.events();
    assert!(
        log.position("end:a") < log.position("start:b"),
        "{events:?}"
    );
    assert!(
        log.position("end:b") < log.position("start:d"),
        "{events:?}"
    );
    assert!(
        log.position("end:c") < log.position("start:d"),
        "{events:?}"
    );
    assert!(
        log.position("end:d") < log.position("start:e"),
        "{events:?}"
    );
    assert!(
        log.max_inflight.load(Ordering::SeqCst) >= 2,
        "ready siblings must overlap: {events:?}"
    );
}
