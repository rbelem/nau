//! Inter-package build scheduling (issue #55, ADR-0022 Decision 3).
//!
//! Builds the READY set of the dependency graph concurrently: a node may
//! start as soon as its last in-graph dependency completes, up to
//! [`MAX_PARALLEL_BUILD_WORKERS`] concurrent builds. The graph layer
//! (`deps.rs`) is untouched — this module consumes the same node/edge
//! shape Kahn's algorithm orders and adds wake-on-completion scheduling.
//!
//! Concurrency model: a fixed pool of worker threads over a shared
//! ready-queue guarded by one Mutex + Condvar. A worker pops a ready node,
//! runs the build job OUTSIDE the lock, then marks completion — cascading
//! newly-ready dependents — or records failure.
//!
//! Failure semantics: stop-the-world on first failure. Running builds
//! finish inside their own containment (a mid-build kill would orphan
//! bwrap children); no NEW job is ever dispatched after a failure, so a
//! failed package's dependents never start. The outcome names both sets:
//! `failed` (built and errored) and `skipped` (never started because a
//! dependency failed or the node is unschedulable, i.e. cyclic).
//!
//! Isolation guarantees are per-build and unchanged (ADR-0004/0022): each
//! job gets its own tempdir stage, its own bwrap sandbox with `env_clear` +
//! explicit PATH, and the leak scan. The only shared mutable resources —
//! the binary pool cache and the output statics — are Mutex-protected or
//! scoped read-only for the whole phase (see the ADR-0022 addendum).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex};

/// Maximum number of concurrent inter-package builds (issue #55).
///
/// Deliberately a fixed constant, not `nproc`: every worker runs a full
/// toolchain invocation (compiler + mksquashfs), so RAM and I/O multiply
/// with concurrency. 3 saturates the ready sets of the current package
/// graph without exhausting a 15 GB build box.
pub const MAX_PARALLEL_BUILD_WORKERS: usize = 3;

/// Why a scheduled run stopped short of building every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedBuilds {
    /// Nodes whose build job ran and errored: (name, rendered error), in
    /// completion order.
    pub failed: Vec<(String, String)>,
    /// Nodes that never started: dependents of a failure and unschedulable
    /// (cyclic) nodes, in declaration order.
    pub skipped: Vec<String>,
}

/// Run `job` over the dependency graph once its ready, in parallel.
///
/// `graph` maps node name → declared dependency names. Edges to names not
/// in the graph (external/leaf deps, aliases that resolve outside the
/// closure) are ignored, mirroring `deps.rs::topological_sort`; self-edges
/// (the issue #33 self-host marker) are dropped — a self-loop would
/// otherwise be unschedulable. `pre_done` names nodes that are already
/// complete (e.g. fully cached): they are marked done before scheduling,
/// immediately releasing their dependents.
///
/// `max_workers` bounds concurrency (clamped to at least 1); jobs run on
/// scoped worker threads, so `F` must be `Sync` and may borrow the caller's
/// build context.
pub fn run_ready_set<F>(
    graph: &BTreeMap<String, Vec<String>>,
    pre_done: &HashSet<String>,
    max_workers: usize,
    job: F,
) -> Result<(), FailedBuilds>
where
    F: Fn(&str) -> Result<(), String> + Sync,
{
    let names: Vec<String> = graph.keys().cloned().collect();
    let index: HashMap<&str, usize> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();

    // Edge lists: deduplicated, self-edges and unknown targets dropped.
    let mut shared = Shared {
        remaining: vec![0; names.len()],
        dependents: vec![Vec::new(); names.len()],
        ready: VecDeque::new(),
        queued: vec![false; names.len()],
        done: vec![false; names.len()],
        running: 0,
        stop: false,
        failures: Vec::new(),
    };
    for (i, name) in names.iter().enumerate() {
        let mut seen: HashSet<&str> = HashSet::new();
        for dep in &graph[name] {
            if dep == name || !seen.insert(dep.as_str()) {
                continue;
            }
            if let Some(&j) = index.get(dep.as_str()) {
                shared.dependents[j].push(i);
                shared.remaining[i] += 1;
            }
        }
    }

    // Pre-done nodes complete before any worker exists; their dependents
    // join the initial ready set through the same cascade real completions
    // use. Then seed the queue with every node whose deps are already
    // satisfied (no in-graph deps, or all of them pre-done/external).
    for (i, name) in names.iter().enumerate() {
        if pre_done.contains(name) {
            mark_complete(&mut shared, i);
        }
    }
    for i in 0..names.len() {
        if !shared.done[i] && shared.remaining[i] == 0 && !shared.queued[i] {
            shared.queued[i] = true;
            shared.ready.push_back(i);
        }
    }

    let state = Mutex::new(shared);
    let cv = Condvar::new();
    let workers = max_workers.clamp(1, names.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                // Take a job or leave the pool — decision made under the
                // lock, the job itself runs outside it.
                let next = {
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    'take: loop {
                        if !s.stop {
                            while let Some(i) = s.ready.pop_front() {
                                s.queued[i] = false;
                                // A node marked done while it sat queued
                                // (pre-done cascade ordering) must not
                                // re-run.
                                if !s.done[i] {
                                    s.running += 1;
                                    break 'take Some(i);
                                }
                            }
                        }
                        // Stop-the-world, or nothing running and nothing
                        // ready: the pool is drained (nodes still holding
                        // remaining>0 are unschedulable or failed-over).
                        if s.stop || s.running == 0 {
                            break None;
                        }
                        s = cv.wait(s).unwrap_or_else(|e| e.into_inner());
                    }
                };
                let Some(i) = next else { break };
                let outcome = job(&names[i]);
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.running -= 1;
                match outcome {
                    Ok(()) => mark_complete(&mut s, i),
                    Err(err) => {
                        s.stop = true;
                        s.failures.push((i, err));
                    }
                }
                cv.notify_all();
            });
        }
    });

    let s = state.into_inner().unwrap_or_else(|e| e.into_inner());
    partition_outcome(&names, &s)
}

/// Shared scheduler state. `remaining[i]` counts not-yet-completed deps of
/// node i; `ready` holds nodes whose count reached 0 (`queued` guards
/// against double-queuing); `stop` is the fail-fast flag.
struct Shared {
    remaining: Vec<usize>,
    dependents: Vec<Vec<usize>>,
    ready: VecDeque<usize>,
    queued: Vec<bool>,
    done: Vec<bool>,
    running: usize,
    stop: bool,
    failures: Vec<(usize, String)>,
}

/// Record node `i` as built and release its dependents: every dependent's
/// remaining count drops by one, and nodes that just reached zero join the
/// ready queue.
fn mark_complete(s: &mut Shared, i: usize) {
    s.done[i] = true;
    for &d in &s.dependents[i] {
        s.remaining[d] = s.remaining[d].saturating_sub(1);
        if s.remaining[d] == 0 && !s.done[d] && !s.queued[d] {
            s.queued[d] = true;
            s.ready.push_back(d);
        }
    }
}

/// Split the drained state into Ok, or the named failed + skipped sets.
/// A run with no failure but unfinished nodes found a cycle the topo layer
/// did not reject — that is an error naming the unschedulable nodes, never
/// a silent skip.
fn partition_outcome(names: &[String], s: &Shared) -> Result<(), FailedBuilds> {
    if s.failures.is_empty() {
        let stuck: Vec<String> = names
            .iter()
            .enumerate()
            .filter(|(i, _)| !s.done[*i])
            .map(|(_, n)| n.clone())
            .collect();
        if stuck.is_empty() {
            return Ok(());
        }
        return Err(FailedBuilds {
            failed: Vec::new(),
            skipped: stuck,
        });
    }
    let failed: Vec<(String, String)> = s
        .failures
        .iter()
        .map(|(i, err)| (names[*i].clone(), err.clone()))
        .collect();
    let failed_names: HashSet<&str> = failed.iter().map(|(n, _)| n.as_str()).collect();
    let skipped: Vec<String> = names
        .iter()
        .enumerate()
        .filter(|(i, n)| !s.done[*i] && !failed_names.contains(n.as_str()))
        .map(|(_, n)| n.clone())
        .collect();
    Err(FailedBuilds { failed, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    /// Event log shared between the fake builder and the test.
    #[derive(Clone)]
    struct Log {
        events: std::sync::Arc<Mutex<Vec<String>>>,
        inflight: std::sync::Arc<AtomicUsize>,
        max_inflight: std::sync::Arc<AtomicUsize>,
    }

    impl Log {
        fn new() -> Self {
            Log {
                events: std::sync::Arc::new(Mutex::new(Vec::new())),
                inflight: std::sync::Arc::new(AtomicUsize::new(0)),
                max_inflight: std::sync::Arc::new(AtomicUsize::new(0)),
            }
        }

        fn record(&self, event: String) {
            self.events.lock().unwrap().push(event);
        }

        /// Record `start:<name>` and bump the in-flight counter. The job
        /// calls [`Log::end`] when its work is done.
        fn start(&self, name: &str) {
            self.record(format!("start:{name}"));
            let n = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_inflight.fetch_max(n, Ordering::SeqCst);
        }

        fn end(&self, name: &str) {
            self.record(format!("end:{name}"));
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

    fn sleep_ms(ms: u64) {
        thread::sleep(Duration::from_millis(ms));
    }

    /// Diamond a→(b,c)→d: d must start only after BOTH b and c finished,
    /// and b/c (ready together) must actually overlap.
    #[test]
    fn ready_set_wakes_dependents_on_completion() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])]);
        let l = log.clone();
        run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            match name {
                "b" | "c" => sleep_ms(120),
                _ => sleep_ms(10),
            }
            l.end(name);
            Ok(())
        })
        .expect("diamond builds clean");

        let events = log.events();
        // b and c overlapped (two jobs in flight while the cap is 3).
        assert!(
            log.max_inflight.load(Ordering::SeqCst) >= 2,
            "ready siblings must overlap: {events:?}"
        );
        // d wakes only after both siblings end.
        let d_start = log.position("start:d");
        assert!(log.position("end:b") < d_start, "{events:?}");
        assert!(log.position("end:c") < d_start, "{events:?}");
    }

    /// Linear chain: every node starts strictly after its dep ends.
    #[test]
    fn ready_set_orders_linear_chain() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let l = log.clone();
        run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            sleep_ms(30);
            l.end(name);
            Ok(())
        })
        .expect("chain builds clean");
        assert!(log.position("end:a") < log.position("start:b"));
        assert!(log.position("end:b") < log.position("start:c"));
    }

    /// Worker cap: 6 independent jobs on 2 workers — never more than 2 in
    /// flight, and really 2 (not a serialized queue).
    #[test]
    fn worker_cap_bounds_concurrency() {
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
        run_ready_set(&g, &HashSet::new(), 2, move |name| {
            l.start(name);
            sleep_ms(60);
            l.end(name);
            Ok(())
        })
        .expect("independent jobs build clean");
        assert_eq!(log.max_inflight.load(Ordering::SeqCst), 2);
    }

    /// A failed node fails its dependents fast: they never start, the
    /// failed set is named with its error, and unrelated completed nodes
    /// are not reported as skipped.
    #[test]
    fn failure_never_starts_dependents() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"]), ("solo", &[])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 3, move |name| {
            l.start(name);
            sleep_ms(30);
            if name == "a" {
                // "a" fails without recording a clean end.
                return Err("a exploded".to_string());
            }
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("failed root must fail the run");
        assert_eq!(
            err.failed,
            vec![("a".to_string(), "a exploded".to_string())]
        );
        // Dependents never started; unrelated "solo" is done, not skipped.
        let events = log.events();
        assert!(!events.iter().any(|e| e == "start:b"), "{events:?}");
        assert!(!events.iter().any(|e| e == "start:c"), "{events:?}");
        assert!(events.iter().any(|e| e == "end:solo"), "{events:?}");
        assert_eq!(err.skipped, vec!["b".to_string(), "c".to_string()]);
    }

    /// Stop-the-world: with 1 worker and an early failure, ready-but-
    /// unstarted nodes are skipped, not built.
    #[test]
    fn failure_stops_unstarted_ready_work() {
        let log = Log::new();
        let g = graph(&[("j1", &[]), ("j2", &[]), ("j3", &[]), ("j4", &[])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 1, move |name| {
            l.start(name);
            if name == "j1" {
                return Err("j1 exploded".to_string());
            }
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("first failure must fail the run");
        assert_eq!(err.failed.len(), 1);
        assert_eq!(err.skipped, vec!["j2", "j3", "j4"]);
        // Exactly one job ever started.
        assert_eq!(
            log.events()
                .iter()
                .filter(|e| e.starts_with("start:"))
                .count(),
            1
        );
    }

    /// Pre-done (cached) nodes complete before scheduling and release
    /// their dependents immediately.
    #[test]
    fn pre_done_releases_dependents_immediately() {
        let log = Log::new();
        let g = graph(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]);
        let pre: HashSet<String> = ["a".to_string(), "b".to_string()].into();
        let l = log.clone();
        run_ready_set(&g, &pre, 3, move |name| {
            l.start(name);
            l.end(name);
            Ok(())
        })
        .expect("pre-done cascade builds clean");
        let events = log.events();
        assert_eq!(events, vec!["start:c".to_string(), "end:c".to_string()]);
    }

    /// Edges to unknown targets and duplicate/self edges are ignored, and
    /// a cycle is reported as unschedulable instead of hanging.
    #[test]
    fn unknown_and_self_edges_are_dropped_and_cycles_are_named() {
        let log = Log::new();
        let g = graph(&[("a", &["a", "ghost", "a", "b"]), ("b", &["b", "a"])]);
        let l = log.clone();
        let out = run_ready_set(&g, &HashSet::new(), 2, move |name| {
            l.start(name);
            l.end(name);
            Ok(())
        });
        let err = out.expect_err("a cycle cannot be scheduled");
        assert!(err.failed.is_empty());
        assert_eq!(err.skipped, vec!["a".to_string(), "b".to_string()]);
    }
}
