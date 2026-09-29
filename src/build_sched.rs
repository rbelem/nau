//! Inter-package build scheduling (issue #55, ADR-0022 Decision 3,
//! executor seam per ADR-0040 Decision 4).
//!
//! Builds the READY set of the dependency graph concurrently: a node may
//! start as soon as its last in-graph dependency completes, up to
//! [`pool_budget`] concurrent builds — the coordinator's own slots plus
//! every declared worker's job allowance (with no `workers` table, that
//! is [`MAX_PARALLEL_BUILD_WORKERS`], today's fixed three). The graph
//! layer (`deps.rs`) is untouched — this module consumes the same
//! node/edge shape Kahn's algorithm orders and adds wake-on-completion
//! scheduling.
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
//!
//! The farm pool (T5): with a declared `workers` table the same ready
//! set schedules across the coordinator's slots and one SSH channel per
//! worker ([`run_ready_set_farm`], [`RemoteExecutor`]). Placement is
//! capability match, then a worker already holding the node's known
//! closure objects (#303 — a warm store saves a payload ship), then
//! ready-set order; failure classes split per
//! ADR-0040 Amendment 1 — a build failure stops the world named, a lost
//! worker's job re-dispatches to any eligible executor (local slots
//! included) and stops the run only when no eligible executor remains.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// The coordinator's default build-slot count (issue #55), also the
/// default of the `workers.local_jobs` config key (ADR-0040 Decision 3):
/// the pool is config-driven now, and this constant is only the value
/// an absent `workers` table falls back to.
///
/// Deliberately a fixed constant, not `nproc`: every worker runs a full
/// toolchain invocation (compiler + mksquashfs), so RAM and I/O multiply
/// with concurrency (the ADR-0022 sizing caveat — this bound exists so a
/// 15 GB build box is not exhausted). 3 saturates the ready sets of the
/// current package graph; raising it via `local_jobs`/`jobs` multiplies
/// RAM and I/O the same way, so size the pool to the box.
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

/// Where a scheduled job runs (ADR-0040 Decision 4). The scheduler owns
/// ready-set ordering and stop-the-world; an executor only answers "run
/// this node's build job" — T2 ships the local implementation, the SSH
/// executor arrives with the transport work.
pub trait BuildExecutor {
    /// Run one build job for node `name`, blocking until it finishes.
    /// `Err` fails the run and trips stop-the-world, exactly as the
    /// pre-seam job closure did.
    fn run(&self, name: &str) -> Result<(), String>;

    /// Best-effort abandon of in-flight work, called once when the
    /// scheduler trips stop-the-world. The local pool never kills jobs —
    /// a mid-build kill would orphan bwrap children — running builds
    /// finish inside their own containment, so [`LocalExecutor`] treats
    /// this as a documented no-op.
    fn cancel(&self);
}

/// The local executor: today's in-process path. Jobs run on the
/// scheduler's scoped worker threads through the caller's job closure —
/// a behavior-preserving wrap of the pre-seam scheduler, not a rewrite.
pub struct LocalExecutor<F> {
    job: F,
}

impl<F> LocalExecutor<F>
where
    F: Fn(&str) -> Result<(), String>,
{
    /// Wrap the per-package build job that runs on the worker threads.
    pub fn new(job: F) -> Self {
        LocalExecutor { job }
    }
}

impl<F> BuildExecutor for LocalExecutor<F>
where
    F: Fn(&str) -> Result<(), String>,
{
    fn run(&self, name: &str) -> Result<(), String> {
        (self.job)(name)
    }

    fn cancel(&self) {
        // Deliberate no-op: no NEW job is dispatched after stop-the-world
        // and in-flight local jobs must finish their containment (see the
        // module docs) — killing them mid-build would orphan bwrap
        // children.
    }
}

// ── The farm pool (T5, ADR-0040 Decisions 4 + 8, Amendment 1) ──
//
// When `workers` is declared, the ready-set scheduler spreads jobs
// across executors: the coordinator's own slots plus one SSH channel
// per worker, each bounded by that worker's `jobs`. Placement is
// capability match first (arch is a per-job property on multi-arch
// runs; speed-weighted placement stays a recorded revisit trigger —
// ADR-0040 D8), then ready-set order. Failure classes are split per
// Amendment 1 (ticket #268): a build failure stops the world named;
// a lost worker re-dispatches its job to any eligible executor —
// local slots included — and only a job with no eligible executor
// left stops the run.

/// Per-job phase timings, the run summary's answer to "where did the
/// wall time go" (#302 — the sizing work scraped these by hand,
/// docs/worker-pool-sizing.md). `sync` and `total` are coordinator-side
/// walls ([`crate::ssh_exec::DispatchOutcome`]); `build` is the
/// worker-reported build child's wall, carried by an optional
/// result-document field — `None` when an older worker did not report
/// it.
#[derive(Debug, Clone)]
pub struct JobTiming {
    /// The scheduled node.
    pub node: String,
    /// The executor's display name (`nuci.local`).
    pub worker: String,
    /// Delta-sync channel wall (object transfer).
    pub sync: Duration,
    /// The remote build child's wall, when reported.
    pub build: Option<Duration>,
    /// Dispatch start → result parsed + artifacts ingested.
    pub total: Duration,
    /// Artifact bytes returned (the summary's size column).
    pub artifact_bytes: u64,
}

impl JobTiming {
    /// The timing suffix the ✓ attribution line and the end-of-run block
    /// share: `sync 0.4s build 12.3s total 13.1s 1.2 MiB`.
    pub fn line_suffix(&self) -> String {
        let mut s = format!("sync {} ", secs(self.sync));
        if let Some(build) = self.build {
            s.push_str(&format!("build {} ", secs(build)));
        }
        s.push_str(&format!(
            "total {} {}",
            secs(self.total),
            human_bytes(self.artifact_bytes)
        ));
        s
    }
}

/// Seconds with one decimal, the summary's duration form (47.9s).
fn secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

/// Human bytes, the summary's size form.
fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KIB * KIB * KIB {
        format!("{:.1} GiB", b / (KIB * KIB * KIB))
    } else if b >= KIB * KIB {
        format!("{:.1} MiB", b / (KIB * KIB))
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// The end-of-run per-job block, in the run summary's line style: one
/// line per dispatched job, completion order.
pub fn render_farm_timings(timings: &[JobTiming]) -> String {
    let mut out = String::from("── farm phase timings ──\n");
    for t in timings {
        out.push_str(&format!(
            "  {} on {} — {}\n",
            t.node,
            t.worker,
            t.line_suffix()
        ));
    }
    out
}

/// Why one scheduled job failed (ADR-0040 Amendment 1, ticket #268):
/// the two classes the farm scheduler treats differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobFailure {
    /// The job ran and failed — locally, or on a worker that answered
    /// with a failure result. Stop-the-world: no new job is dispatched,
    /// in-flight jobs finish, dependents never start. The text names
    /// the worker and the job.
    Build(String),
    /// The executor was lost — connection dropped, host vanished,
    /// keepalive deadline. The job re-dispatches to any eligible
    /// executor, local slots included; stop-the-world only when no
    /// eligible executor remains. The text names the worker.
    Lost(String),
}

/// What farm placement matches on (ADR-0040 Decision 4: arch is a
/// per-job property on multi-arch runs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobCaps {
    /// Every arch the job builds (the `resolve_archs` output).
    pub archs: Vec<String>,
    /// True when the job cross-compiles (a `--target` triplet applies).
    pub cross: bool,
    /// True when the job cannot be dispatched to a worker at all (a
    /// multi-arch job, or a plan the v1 manifest shape cannot carry) —
    /// only the coordinator's own slots take it, exactly as it built
    /// before the farm existed.
    pub local_only: bool,
    /// The closure objects placement KNOWS at schedule time (#303): the
    /// pinned source blobs, whose hashes resolve at plan time. Dep
    /// payload hashes do not exist until their deps build (the payload
    /// is hashed from the built snap), so they stay outside this set —
    /// it aims placement only, and delta_sync at dispatch remains the
    /// correctness authority. Empty = nothing to hold: every worker
    /// qualifies vacuously (today's behavior).
    pub objects: BTreeSet<String>,
}

/// How the scheduler sees one pool member. Placement rules read the
/// kind; dispatch goes through the [`FarmJob`].
#[derive(Debug, Clone)]
pub enum ExecutorKind {
    /// The coordinator's own build slots.
    Local,
    /// One SSH worker. `declared_arch` is the entry's `arch` triplet,
    /// when the operator declared one.
    Worker { declared_arch: Option<String> },
}

/// One pool member: the dispatch side plus how placement sees it.
pub struct FarmExecutor<'a> {
    pub job: &'a dyn FarmJob,
    pub kind: ExecutorKind,
}

/// The dispatch side of one pool member. A [`FarmJob`] runs one ready
/// node to completion; `Err(JobFailure)` carries the failure class.
/// The pre-seam [`BuildExecutor`] stays untouched — the local-only
/// path (no `workers` table) keeps its exact shape.
pub trait FarmJob: Sync {
    fn run(&self, name: &str) -> Result<(), JobFailure>;

    /// Best-effort abandon of in-flight work at the stop-the-world
    /// trip — a documented no-op for executors whose jobs must finish
    /// their containment (local bwrap children, in-flight remote jobs
    /// that the ADR lets finish and ingest).
    fn cancel(&self) {}

    /// The attribution name in scheduler lines and the run summary:
    /// `local`, or the worker's short host name.
    fn display_name(&self) -> &str {
        "local"
    }

    /// Concurrent jobs this member takes.
    fn slots(&self) -> usize {
        1
    }

    /// The per-job phase timings this member recorded, for the
    /// end-of-run summary (#302). Default: none — the local executor's
    /// jobs are not phase-timed (nothing changed for them).
    fn job_timings(&self) -> Vec<JobTiming> {
        Vec::new()
    }

    /// The store listing this member's preflight learned (#303): `None`
    /// = store unknown — placement cannot prefer the member. The default
    /// keeps the local slots out of holder consideration (they read the
    /// coordinator's own store; placement leaves local exactly as it
    /// was) and store-blind test fakes on today's behavior.
    fn store_held(&self) -> Option<BTreeSet<String>> {
        None
    }
}

impl<F> FarmJob for LocalExecutor<F>
where
    F: Fn(&str) -> Result<(), String> + Sync,
{
    fn run(&self, name: &str) -> Result<(), JobFailure> {
        // A local job that errored is a build failure: there is no
        // "losing" the coordinator's own process.
        (self.job)(name).map_err(JobFailure::Build)
    }
}

/// One [`FarmJob`] with an explicit slot count and display name — the
/// adapter that places e.g. the local executor at `local_jobs` slots
/// inside the farm pool.
pub struct Slotted<E> {
    pub exec: E,
    pub slots: usize,
    pub display: String,
}

impl<E: FarmJob> FarmJob for Slotted<E> {
    fn run(&self, name: &str) -> Result<(), JobFailure> {
        self.exec.run(name)
    }
    fn cancel(&self) {
        self.exec.cancel();
    }
    fn display_name(&self) -> &str {
        &self.display
    }
    fn slots(&self) -> usize {
        self.slots
    }
}

/// The farm run's outcome: the scheduler verdict plus the workers lost
/// along the way — reported even on an `Ok` run whose re-dispatch
/// absorbed the loss, because the escape hatch for a flaky worker is
/// removing it from config, and the operator can only do that if the
/// summary names it.
#[derive(Debug, Clone)]
pub struct FarmOutcome {
    pub result: Result<(), FailedBuilds>,
    /// Display names of executors lost mid-run, in loss order.
    pub workers_lost: Vec<String>,
}

/// Does pool member `e` take node `node`? The placement rule: every
/// member scans the ready queue front-to-back (ready-set order), so
/// this predicate decides capability match only.
fn farm_eligible(
    farm: &[FarmExecutor<'_>],
    alive: &[bool],
    caps: &[JobCaps],
    e: usize,
    node: usize,
) -> bool {
    if !alive[e] {
        return false;
    }
    let caps = &caps[node];
    // A job the v1 manifest shape cannot carry (multi-arch, or a plan
    // that refused to resolve) never leaves the coordinator.
    if caps.local_only {
        return matches!(farm[e].kind, ExecutorKind::Local);
    }
    match &farm[e].kind {
        ExecutorKind::Local => {
            if caps.cross {
                // A cross job goes local only when no alive worker is
                // declared for its arch — the re-dispatch path includes
                // local slots (Amendment 1), and a worker that can take
                // the job must take it before the coordinator tries a
                // toolchain it may not have.
                !farm.iter().enumerate().any(|(x, fe)| {
                    alive[x]
                        && matches!(&fe.kind,
                            ExecutorKind::Worker { declared_arch: Some(d) }
                            if crate::snap::triplet_arch(d)
                                .is_some_and(|da| caps.archs.iter().any(|a| a == da)))
                })
            } else {
                true
            }
        }
        ExecutorKind::Worker { declared_arch } => {
            match declared_arch.as_deref().and_then(crate::snap::triplet_arch) {
                // A declared worker takes only jobs that match its
                // arch, or cross jobs — the remote side re-checks
                // everything at dispatch preflight. ("all" jobs are
                // metadata-only, but T4's dispatch compares the
                // declared triplet against the job target directly, so
                // a declared worker refuses them — placement respects
                // that and routes them to undeclared workers and the
                // local slots.)
                Some(d) => caps.cross || caps.archs.iter().any(|a| a == d),
                // An undeclared worker takes anything; the dispatch
                // preflight is the arch check, and a mismatch refuses
                // there, named.
                None => true,
            }
        }
    }
}

/// Schedule the graph across the farm: local slots plus one channel
/// per declared worker, bounded per member by [`FarmJob::slots`].
///
/// Readiness, ready-set ordering, and the stop-the-world sets are the
/// single-executor scheduler's, unchanged. Placement adds the
/// capability match of [`farm_eligible`] and, inside it, the holder
/// preference (#303): a member takes an eligible node it already holds
/// over an unheld one — a warm store saves a payload ship; when nobody
/// holds everything, nobody is preferred, and ready-set order rules as
/// before. Failure classes per
/// ADR-0040 Amendment 1: `JobFailure::Build` stops the world named;
/// `JobFailure::Lost` marks the executor dead, re-queues its job at
/// the front, and stops the world only when no alive executor is
/// eligible for an orphaned job. A re-dispatched job never cycles: it
/// visits each pool member at most once, and a job every member has
/// tried stops the run named.
pub fn run_ready_set_farm(
    graph: &BTreeMap<String, Vec<String>>,
    pre_done: &HashSet<String>,
    farm: &[FarmExecutor<'_>],
    caps: &HashMap<String, JobCaps>,
) -> FarmOutcome {
    let names: Vec<String> = graph.keys().cloned().collect();
    let index: HashMap<&str, usize> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();

    let node_caps: Vec<JobCaps> = names
        .iter()
        .map(|n| caps.get(n).cloned().unwrap_or_default())
        .collect();

    let mut shared = FarmShared {
        remaining: vec![0; names.len()],
        dependents: vec![Vec::new(); names.len()],
        ready: VecDeque::new(),
        queued: vec![false; names.len()],
        done: vec![false; names.len()],
        running: 0,
        stop: false,
        failures: Vec::new(),
        lost: Vec::new(),
        alive: vec![true; farm.len()],
        redispatches: vec![0; names.len()],
        held: farm.iter().map(|fe| fe.job.store_held()).collect(),
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
    for (i, name) in names.iter().enumerate() {
        if pre_done.contains(name) {
            farm_mark_complete(&mut shared, i);
        }
    }
    for i in 0..names.len() {
        if !shared.done[i] && shared.remaining[i] == 0 && !shared.queued[i] {
            shared.queued[i] = true;
            shared.ready.push_back(i);
        }
    }

    let state = std::sync::Arc::new(Mutex::new(shared));
    let cv = std::sync::Arc::new(Condvar::new());
    let names = std::sync::Arc::new(names);
    let node_caps = std::sync::Arc::new(node_caps);
    // Executors with zero slots never spawn threads — placement must
    // not count them as able to run a stuck job, or the pool waits
    // forever on a member that cannot wake.
    let has_threads: Vec<bool> = farm.iter().map(|fe| fe.job.slots() > 0).collect();
    let has_threads = std::sync::Arc::new(has_threads);

    std::thread::scope(|scope| {
        for (e, fe) in farm.iter().enumerate() {
            // Zero slots (a worker-only farm's local member) spawns no
            // threads; a positive slot count never exceeds the node
            // count (extra threads could never take a job).
            let slots = fe.job.slots().min(names.len().max(1));
            for _ in 0..slots {
                // Per-lane captures: the executor index (Copy) plus the
                // shared handles (Arc); `farm` rides as a Copy reference.
                let state = state.clone();
                let cv = cv.clone();
                let names = names.clone();
                let node_caps = node_caps.clone();
                let has_threads = has_threads.clone();
                scope.spawn(move || loop {
                    let next = {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        'take: loop {
                            if !s.stop {
                                // Placement: holder preference inside the
                                // eligibility gate, ready-set order breaking
                                // every tie (#303). The split borrow lets
                                // pick_ready prune the queue and read the
                                // held set in one call.
                                let sref = &mut *s;
                                if let Some((k, i)) = pick_ready(
                                    farm,
                                    &sref.alive,
                                    &node_caps,
                                    e,
                                    sref.held[e].as_ref(),
                                    &mut sref.ready,
                                    &sref.done,
                                ) {
                                    s.ready.remove(k);
                                    s.queued[i] = false;
                                    s.running += 1;
                                    break 'take Some(i);
                                }
                            }
                            if s.stop {
                                break None;
                            }
                            if s.running == 0 {
                                // Drain: nothing runs anywhere. A pending
                                // node no runnable member is eligible for
                                // stops the run named (no executor
                                // remains); otherwise the pool is done —
                                // except a thread must NOT exit while any
                                // pending node is runnable by SOME member:
                                // a lost declared worker makes a cross job
                                // eligible for the local slots, and the
                                // job's recovery needs a live waiter. The
                                // last member to see an empty drained
                                // queue exits.
                                let stuck = s.ready.iter().copied().find(|&n| {
                                    !s.done[n]
                                        && !(0..farm.len()).any(|x| {
                                            has_threads[x]
                                                && farm_eligible(farm, &s.alive, &node_caps, x, n)
                                        })
                                });
                                if let Some(n) = stuck {
                                    let lost_list = render_lost(&s.lost, farm);
                                    s.stop = true;
                                    s.failures.push((
                                        n,
                                        format!(
                                            "no executor remains for '{}' — workers lost: {}",
                                            names[n], lost_list
                                        ),
                                    ));
                                    continue;
                                }
                                if s.ready.iter().all(|&n| s.done[n]) {
                                    break None;
                                }
                                s = cv.wait(s).unwrap_or_else(|e| e.into_inner());
                                continue;
                            }
                            s = cv.wait(s).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    let Some(i) = next else {
                        break;
                    };
                    let outcome = farm[e].job.run(&names[i]);
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    s.running -= 1;
                    match outcome {
                        Ok(()) => {
                            farm_mark_complete(&mut s, i);
                            // The dispatch just left the node's objects in
                            // this worker's store (#303): keep placement
                            // current — matters when a later node re-queues
                            // after a loss and this worker already holds the
                            // shared objects.
                            if let Some(h) = s.held[e].as_mut() {
                                h.extend(node_caps[i].objects.iter().cloned());
                            }
                        }
                        Err(JobFailure::Build(err)) => {
                            // Stop-the-world: name the failure, let
                            // in-flight jobs finish, never dispatch anew.
                            s.stop = true;
                            s.failures.push((i, err));
                            for fe in farm {
                                fe.job.cancel();
                            }
                        }
                        Err(JobFailure::Lost(err)) => {
                            let first_loss = !s.lost.contains(&e);
                            if first_loss {
                                s.lost.push(e);
                            }
                            s.alive[e] = false;
                            // The store died with the channel (#303):
                            // never prefer this member again (alive already
                            // gates eligibility; the reset keeps the held
                            // set honest).
                            s.held[e] = None;
                            if first_loss {
                                // The loss reason is operator-visible the
                                // moment it happens: a re-dispatch can
                                // absorb the loss, and the escape hatch
                                // is removing the worker from config.
                                crate::output::warn(format!(
                                    "worker lost: {err} — affected jobs re-dispatch to the \
                                     surviving executors"
                                ));
                            }
                            if !s.stop {
                                // Re-dispatch: the job rejoins the ready
                                // set at the front, now eligible for the
                                // surviving members (local included).
                                s.redispatches[i] += 1;
                                if s.redispatches[i] > farm.len() {
                                    // Every member had its shot — no
                                    // executor can run this job.
                                    let lost_list = render_lost(&s.lost, farm);
                                    s.stop = true;
                                    s.failures.push((
                                        i,
                                        format!(
                                            "no executor remains for '{}' — workers lost: {}",
                                            names[i], lost_list
                                        ),
                                    ));
                                } else {
                                    s.queued[i] = true;
                                    s.ready.push_front(i);
                                    // A pending job whose every runnable
                                    // executor just died stops the run.
                                    let orphan = s.ready.iter().copied().find(|&n| {
                                        !s.done[n]
                                            && !(0..farm.len()).any(|x| {
                                                has_threads[x]
                                                    && farm_eligible(
                                                        farm, &s.alive, &node_caps, x, n,
                                                    )
                                            })
                                    });
                                    if let Some(n) = orphan {
                                        let lost_list = render_lost(&s.lost, farm);
                                        s.stop = true;
                                        s.failures.push((
                                            n,
                                            format!(
                                                "no executor remains for '{}' — workers lost: {}",
                                                names[n], lost_list
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    cv.notify_all();
                });
            }
        }
    });

    let s = std::sync::Arc::try_unwrap(state)
        .ok()
        .expect("all scheduler threads joined; the state Arc has no other owners")
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    // The farm run's end-of-run timing summary (#302): every dispatched
    // job's phases, in completion order. Members without timings (the
    // local slots) record none, so a worker-less run prints nothing.
    let timings: Vec<JobTiming> = farm.iter().flat_map(|fe| fe.job.job_timings()).collect();
    if !timings.is_empty() && !crate::output::is_json() {
        eprint!("{}", render_farm_timings(&timings));
    }
    FarmOutcome {
        result: partition_outcome(&names, &s),
        workers_lost: s
            .lost
            .iter()
            .map(|&m| farm[m].job.display_name().to_string())
            .collect(),
    }
}
/// The farm scheduler's shared state — the single-executor fields plus
/// the loss bookkeeping.
struct FarmShared {
    remaining: Vec<usize>,
    dependents: Vec<Vec<usize>>,
    ready: VecDeque<usize>,
    queued: Vec<bool>,
    done: Vec<bool>,
    running: usize,
    stop: bool,
    failures: Vec<(usize, String)>,
    /// Member indices of executors that returned [`JobFailure::Lost`],
    /// loss order, deduplicated. Keyed by member index — not display
    /// name — so two same-short-name workers (nuci.local:22,
    /// nuci.local:2222) each record their own loss; display names render
    /// at the outcome (#193 review F4).
    lost: Vec<usize>,
    alive: Vec<bool>,
    /// Re-dispatch counts per node — the no-cycle cap (a job visits
    /// each pool member at most once).
    redispatches: Vec<usize>,
    /// Each member's known store, learned at preflight (#303):
    /// `None` = unknown, never preferred. Kept current within the run:
    /// a completed dispatch leaves the node's objects in the worker's
    /// store; a lost worker's store died with its channel.
    held: Vec<Option<BTreeSet<String>>>,
}

/// Which ready node member `e` takes, front-to-back: among ELIGIBLE
/// nodes, the first whose known objects `e` fully holds beats queue
/// order (#303 — a warm store saves a payload ship); none fully held,
/// the first eligible as before. Eligibility ([`farm_eligible`]) stays
/// the gate — the preference only reorders what a member picks, never
/// whether a node can run somewhere. Done entries met along the scan
/// drop out of the queue.
fn pick_ready(
    farm: &[FarmExecutor<'_>],
    alive: &[bool],
    node_caps: &[JobCaps],
    e: usize,
    held: Option<&BTreeSet<String>>,
    ready: &mut VecDeque<usize>,
    done: &[bool],
) -> Option<(usize, usize)> {
    let mut fallback: Option<(usize, usize)> = None;
    let mut k = 0;
    while k < ready.len() {
        let i = ready[k];
        if done[i] {
            ready.remove(k);
            continue;
        }
        if farm_eligible(farm, alive, node_caps, e, i) {
            if fallback.is_none() {
                fallback = Some((k, i));
            }
            // The non-empty gate keeps a vacuous set (∅ ⊆ anything) from
            // reading as "held by everyone" — an empty placement set gets
            // the fallback, never a fake store hit (#307).
            if held.is_some_and(|h| {
                !node_caps[i].objects.is_empty()
                    && node_caps[i].objects.iter().all(|o| h.contains(o))
            }) {
                return Some((k, i));
            }
        }
        k += 1;
    }
    fallback
}

/// The blindness clause for the placement banner (#307): a WORKER
/// whose store is Unknown at scheduling time (`store_held` `None` —
/// the probe failed or never ran) gets no holder preference, silently.
/// The banner names such members so the fail-open is visible. Not
/// blind: the local slots (their `None` is the trait default — locals
/// sit outside holder consideration by design) and a known-empty store
/// (`Some(empty)` — a fresh worker legitimately holds nothing). Empty
/// string on the happy path: every store known renders no clause.
pub fn placement_blind_clause(farm: &[FarmExecutor<'_>]) -> String {
    let blind: Vec<&str> = farm
        .iter()
        .filter(|fe| matches!(fe.kind, ExecutorKind::Worker { .. }))
        .filter(|fe| fe.job.store_held().is_none())
        .map(|fe| fe.job.display_name())
        .collect();
    if blind.is_empty() {
        String::new()
    } else {
        format!(
            " (store unknown: {} — no holder preference for them)",
            blind.join(", ")
        )
    }
}

/// The short attribution name for a worker address: the host token
/// (`ssh://op@nuci.local:22` → `nuci.local`), the only identity the
/// v1 config carries for line prefixes.
pub fn short_worker_name(address: &str) -> String {
    let s = address.strip_prefix("ssh://").unwrap_or(address);
    let s = match s.rsplit_once('@') {
        Some((_, h)) => h,
        None => s,
    };
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            return s[1..end].to_string();
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => s.to_string(),
    }
}

/// Render the lost member indices as their display names, loss order —
/// two same-short-name workers each render (the loss was per member, so
/// the summary names every member the run lost, however they collide
/// textually).
fn render_lost(lost: &[usize], farm: &[FarmExecutor<'_>]) -> String {
    lost.iter()
        .map(|&m| farm[m].job.display_name().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The coordinator-side assembly feeding one worker's dispatches:
/// the manifest for a scheduled node, the payload staged for it, and
/// where successful results land.
pub trait ManifestSource: Sync {
    /// Build the job manifest for `name` — pure and network-free, so a
    /// manifest-identity cache hit (a re-run of a completed job) skips
    /// every payload and channel cost.
    fn manifest_for(&self, name: &str) -> miette::Result<crate::worker::JobManifest>;

    /// Materialize the manifest's payload directory: the closure blobs
    /// named by their sha256 — dep payloads hardlinked from the run's
    /// outputs, pinned sources fetched and hash-verified. The staging
    /// lives until the returned guard drops.
    fn stage_payload(
        &self,
        manifest: &crate::worker::JobManifest,
    ) -> miette::Result<tempfile::TempDir>;

    /// Place a successful dispatch where the rest of the build finds
    /// it (the run's output directory, the JSON events). `artifacts_in`
    /// is the executor's ingest directory (the manifest-identity
    /// record); `display` is the worker label for attribution.
    fn ingest(
        &self,
        name: &str,
        outcome: &crate::ssh_exec::DispatchOutcome,
        artifacts_in: &std::path::Path,
        display: &str,
    ) -> miette::Result<()>;
}

impl<T: ManifestSource + Send + ?Sized> ManifestSource for std::sync::Arc<T> {
    fn manifest_for(&self, name: &str) -> miette::Result<crate::worker::JobManifest> {
        (**self).manifest_for(name)
    }
    fn stage_payload(
        &self,
        manifest: &crate::worker::JobManifest,
    ) -> miette::Result<tempfile::TempDir> {
        (**self).stage_payload(manifest)
    }
    fn ingest(
        &self,
        name: &str,
        outcome: &crate::ssh_exec::DispatchOutcome,
        artifacts_in: &std::path::Path,
        display: &str,
    ) -> miette::Result<()> {
        (**self).ingest(name, outcome, artifacts_in, display)
    }
}

/// One worker's dispatch lane inside the farm: the landed T4
/// [`SshExecutor`](crate::ssh_exec::SshExecutor) plus the assembly
/// that feeds it. Attribution lines mirror the local executor's
/// `▶ [name slot/total]` shapes, prefixed by the worker's short host.
pub struct RemoteExecutor<R: crate::command::CommandRunner + Sync, S: ManifestSource> {
    exec: crate::ssh_exec::SshExecutor<R>,
    source: S,
    display: String,
    slots: usize,
    total: usize,
    dispatch: AtomicUsize,
    /// One entry per completed dispatch, completion order — the
    /// end-of-run summary's source (`job_timings` reads it).
    timings: Mutex<Vec<JobTiming>>,
}

impl<R: crate::command::CommandRunner + Sync, S: ManifestSource> RemoteExecutor<R, S> {
    /// Wrap one worker's executor. `slots` is the entry's `jobs`; the
    /// worker's short host name attributes its lines.
    pub fn new(
        exec: crate::ssh_exec::SshExecutor<R>,
        source: S,
        slots: usize,
        total: usize,
    ) -> Self {
        let display = short_worker_name(exec.address());
        RemoteExecutor {
            exec,
            source,
            display,
            slots: slots.max(1),
            total,
            dispatch: AtomicUsize::new(0),
            timings: Mutex::new(Vec::new()),
        }
    }
}

impl<R: crate::command::CommandRunner + Sync, S: ManifestSource> FarmJob for RemoteExecutor<R, S> {
    fn run(&self, name: &str) -> Result<(), JobFailure> {
        let slot = self.dispatch.fetch_add(1, Ordering::SeqCst) + 1;
        if !crate::output::is_json() {
            eprintln!("▶ [{} {slot}/{}] {name}", self.display, self.total);
        }
        let manifest = self
            .source
            .manifest_for(name)
            .map_err(|e| JobFailure::Build(format!("{e:#}")))?;
        // Manifest-identity cache first (a re-run of a completed job
        // crosses no channel and stages no payload), then the full
        // probe → sync → job → collect dispatch.
        let outcome = match self.exec.cached_result(&manifest) {
            Ok(Some(result)) => Ok(crate::ssh_exec::DispatchOutcome {
                cache_hit: true,
                result,
                sync: Duration::ZERO,
                total: Duration::ZERO,
            }),
            Ok(None) => {
                let stage = self
                    .source
                    .stage_payload(&manifest)
                    .map_err(|e| JobFailure::Build(format!("{e:#}")))?;
                self.exec
                    .dispatch(&manifest, stage.path())
                    .map_err(|e| classify_transport(&e))
            }
            Err(e) => Err(JobFailure::Build(format!("{e:#}"))),
        };
        match outcome {
            Ok(o) => {
                if o.cache_hit {
                    if !crate::output::is_json() {
                        eprintln!(
                            "✓ [{} {slot}/{}] {name} (manifest cache)",
                            self.display, self.total
                        );
                    }
                } else {
                    // The dispatch's own telemetry records regardless of
                    // output mode; only the human line is suppressed.
                    let timing = JobTiming {
                        node: name.to_string(),
                        worker: self.display.clone(),
                        sync: o.sync,
                        build: o.result.build_ms.map(Duration::from_millis),
                        total: o.total,
                        artifact_bytes: o.result.artifacts.iter().map(|a| a.size).sum(),
                    };
                    self.timings
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(timing.clone());
                    if !crate::output::is_json() {
                        eprintln!(
                            "✓ [{} {slot}/{}] {name} — {}",
                            self.display,
                            self.total,
                            timing.line_suffix()
                        );
                    }
                }
                let artifacts_in = self
                    .exec
                    .ingest_dir(&manifest)
                    .map_err(|e| JobFailure::Build(format!("{e:#}")))?;
                self.source
                    .ingest(name, &o, &artifacts_in, &self.display)
                    .map_err(|e| JobFailure::Build(format!("{e:#}")))
            }
            Err(e) => Err(e),
        }
    }

    fn display_name(&self) -> &str {
        &self.display
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn job_timings(&self) -> Vec<JobTiming> {
        self.timings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn store_held(&self) -> Option<BTreeSet<String>> {
        self.exec.store_held()
    }
}

/// Transport loss vs build failure (ADR-0040 Amendment 1). A worker is
/// LOST when the channel itself died: ssh/scp could not be spawned,
/// exited nonzero (connection refused, dropped session, keepalive
/// deadline), or the reachability probe failed — re-dispatch is the
/// recovery. Everything else — a failed result document, a protocol,
/// identity, or hash refusal, a capability preflight refusal — is a
/// BUILD failure: re-dispatch cannot fix it, and stop-the-world names
/// it. The class keys on the typed
/// [`ChannelLoss`](crate::ssh_exec::ChannelLoss) payload the transport's
/// leaf errors carry, found through the error's source chain — never on
/// message wording, which a reword or a hostile remote stderr could
/// otherwise flip (#193 review F3).
fn classify_transport(err: &miette::Error) -> JobFailure {
    let text = format!("{err:#}");
    if channel_loss_in(err) {
        JobFailure::Lost(text)
    } else {
        JobFailure::Build(text)
    }
}

/// Does this error's chain carry the transport's typed channel-loss
/// payload? The leaf sits under any number of `wrap_err` contexts, and
/// the chain walk starts at the error itself.
fn channel_loss_in(err: &miette::Error) -> bool {
    err.chain()
        .any(|c| c.downcast_ref::<crate::ssh_exec::ChannelLoss>().is_some())
}

/// The pool budget (ADR-0040 Decision 4): the coordinator's own slots
/// plus the sum of every declared worker's job allowance. An absent or
/// empty `workers` table yields today's fixed parallelism — the default
/// `local_jobs` and no workers.
pub fn pool_budget(workers: &crate::lua::WorkersConfig) -> usize {
    workers.local_jobs as usize
        + workers
            .workers
            .iter()
            .map(|w| w.jobs as usize)
            .sum::<usize>()
}

/// Run `job` over the dependency graph once its ready, in parallel,
/// through the local executor — the pre-seam entry point, preserved for
/// callers that just want today's behavior.
///
/// See [`run_ready_set_with_executor`] for the shape this delegates to.
pub fn run_ready_set<F>(
    graph: &BTreeMap<String, Vec<String>>,
    pre_done: &HashSet<String>,
    max_workers: usize,
    job: F,
) -> Result<(), FailedBuilds>
where
    F: Fn(&str) -> Result<(), String> + Sync,
{
    run_ready_set_with_executor(graph, pre_done, max_workers, &LocalExecutor::new(job))
}

/// Schedule the graph through `executor` (ADR-0040 Decision 4).
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
/// scoped worker threads calling `executor.run`, so `E` must be `Sync`.
/// Ready-set ordering, stop-the-world, and the `FailedBuilds` outcome are
/// identical to the pre-seam scheduler: only where a job executes changed.
pub fn run_ready_set_with_executor<E>(
    graph: &BTreeMap<String, Vec<String>>,
    pre_done: &HashSet<String>,
    max_workers: usize,
    executor: &E,
) -> Result<(), FailedBuilds>
where
    E: BuildExecutor + Sync,
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
                let outcome = executor.run(&names[i]);
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.running -= 1;
                match outcome {
                    Ok(()) => mark_complete(&mut s, i),
                    Err(err) => {
                        s.stop = true;
                        s.failures.push((i, err));
                        // Stop-the-world: the executor may abandon what it
                        // can (a no-op for the local pool). No NEW job is
                        // dispatched either way.
                        executor.cancel();
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

/// [`mark_complete`] over the farm state — same cascade, plus the loss
/// bookkeeping the farm carries beside these fields.
fn farm_mark_complete(s: &mut FarmShared, i: usize) {
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
/// a silent skip. Shared by the single-executor and farm schedulers, which
/// differ only in the loss bookkeeping around these two fields.
trait OutcomeFields {
    fn failures(&self) -> &[(usize, String)];
    fn done(&self) -> &[bool];
}

impl OutcomeFields for Shared {
    fn failures(&self) -> &[(usize, String)] {
        &self.failures
    }
    fn done(&self) -> &[bool] {
        &self.done
    }
}

impl OutcomeFields for FarmShared {
    fn failures(&self) -> &[(usize, String)] {
        &self.failures
    }
    fn done(&self) -> &[bool] {
        &self.done
    }
}

fn partition_outcome<S: OutcomeFields>(names: &[String], s: &S) -> Result<(), FailedBuilds> {
    if s.failures().is_empty() {
        let stuck: Vec<String> = names
            .iter()
            .enumerate()
            .filter(|(i, _)| !s.done()[*i])
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
        .failures()
        .iter()
        .map(|(i, err)| (names[*i].clone(), err.clone()))
        .collect();
    let failed_names: HashSet<&str> = failed.iter().map(|(n, _)| n.as_str()).collect();
    let skipped: Vec<String> = names
        .iter()
        .enumerate()
        .filter(|(i, n)| !s.done()[*i] && !failed_names.contains(n.as_str()))
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

    /// The loss/build class keys on the typed ChannelLoss payload found
    /// through the error chain — never on message wording (#193 review
    /// F3). Pinned here beside [`classify_transport`]:
    ///
    /// * the exact leaf shape `run_ssh` emits for a dead channel, under
    ///   the contexts `dispatch` wraps it in, classifies LOST;
    /// * a build refusal whose text MIMICS the old channel-death wording
    ///   (remote-controlled result error — the injection the previous
    ///   string match allowed) stays BUILD;
    /// * a capability preflight refusal stays BUILD.
    #[test]
    fn transport_class_keys_on_the_typed_channel_loss_not_wording() {
        let dead_channel = miette::Error::new(crate::ssh_exec::ChannelLoss(
            "ssh to 'nuci.local' failed (code 255): Connection closed by remote host".to_string(),
        ))
        .wrap_err("preflight reachability")
        .wrap_err("dispatch failed on worker 'nuci.local' for job jm1_dead");
        assert!(
            matches!(classify_transport(&dead_channel), JobFailure::Lost(_)),
            "a typed channel death classifies LOST: {dead_channel:#}"
        );

        let injected = miette::miette!(
            "job jm1_x failed on worker 'evil': ssh to 'evil' failed (code 255): \
             not actually a channel death"
        );
        assert!(
            matches!(classify_transport(&injected), JobFailure::Build(_)),
            "wording alone cannot fake a channel death: {injected:#}"
        );

        let build_refusal = miette::miette!(
            "dispatch: worker 'nuci.local' declares arch arm64 but the job targets amd64 — \
             the entry's arch override and the job target disagree"
        );
        assert!(matches!(
            classify_transport(&build_refusal),
            JobFailure::Build(_)
        ));
    }
}
