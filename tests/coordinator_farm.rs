//! The farm coordinator (T5, ADR-0040 Decision 4 + Amendment 1): the
//! ready-set scheduler spread across local slots and SSH workers —
//! placement (capability match, then ready-set order), per-worker slot
//! bounds, the failure-class split (a build failure stops the world
//! named; a lost worker's job re-dispatches and only a job with no
//! eligible executor left stops the run), and one loopback dispatch
//! through the landed T4 transport — `ssh://localhost`, a scripted
//! in-process worker fake, no network, no sshd.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nau::build_sched::{
    placement_blind_clause, run_ready_set_farm, short_worker_name, ExecutorKind, FarmExecutor,
    FarmJob, JobCaps, JobFailure, ManifestSource, RemoteExecutor,
};
use nau::command::{CommandRunner, RunnerOutput};
use nau::coordinator::{farm_build_result, preflight_farm_workers, FarmSource, NodeJobPlan};
use nau::lock::LockFile;
use nau::lua::WorkerConfig;
use nau::snap::{SnapMeta, SourceSpec};
use nau::ssh_exec::{DispatchOutcome, SshExecutor};
use nau::worker::{Artifact, CapabilityDoc, JobManifest, JobResult, WORKER_PROTOCOL_VERSION};
use sha2::{Digest, Sha256};

// ── Shared helpers ──

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

fn caps(archs: &[&str], cross: bool) -> JobCaps {
    JobCaps {
        archs: archs.iter().map(|a| a.to_string()).collect(),
        cross,
        local_only: false,
        objects: BTreeSet::new(),
    }
}

/// [`caps`] with the node's placement-known objects (#303).
fn caps_holding(archs: &[&str], cross: bool, objects: &[&str]) -> JobCaps {
    JobCaps {
        objects: objects.iter().map(|o| o.to_string()).collect(),
        ..caps(archs, cross)
    }
}

fn no_caps() -> HashMap<String, JobCaps> {
    HashMap::new()
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

// ── The fake farm member ──

/// A scripted pool member: records `start:<display>:<name>` /
/// `end:<display>:<name>` events, bounds its concurrency, and fails or
/// dies exactly where the test says.
#[derive(Clone)]
struct FakeMember {
    display: &'static str,
    slots: usize,
    kind_is_local: bool,
    declared_arch: Option<String>,
    /// Nodes this member fails with [`JobFailure::Build`].
    fail_build: Vec<&'static str>,
    /// The 1-based call count on which the member reports
    /// [`JobFailure::Lost`] (0 = never dies). The member stays dead.
    lose_on_call: usize,
    /// The store listing the member's preflight "learned" (#303):
    /// `None` = store unknown (never preferred).
    store: Option<BTreeSet<String>>,
    events: Arc<Mutex<Vec<String>>>,
    calls: Arc<AtomicUsize>,
    running: Arc<AtomicUsize>,
    max_running: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
}

impl FakeMember {
    fn local(slots: usize, events: Arc<Mutex<Vec<String>>>) -> Self {
        FakeMember {
            display: "local",
            slots,
            kind_is_local: true,
            declared_arch: None,
            fail_build: Vec::new(),
            lose_on_call: 0,
            store: None,
            events,
            calls: Arc::new(AtomicUsize::new(0)),
            running: Arc::new(AtomicUsize::new(0)),
            max_running: Arc::new(AtomicUsize::new(0)),
            dead: Arc::new(AtomicBool::new(false)),
        }
    }

    fn worker(
        display: &'static str,
        slots: usize,
        declared_arch: Option<&str>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        FakeMember {
            display,
            slots,
            kind_is_local: false,
            declared_arch: declared_arch.map(str::to_string),
            fail_build: Vec::new(),
            lose_on_call: 0,
            store: None,
            events,
            calls: Arc::new(AtomicUsize::new(0)),
            running: Arc::new(AtomicUsize::new(0)),
            max_running: Arc::new(AtomicUsize::new(0)),
            dead: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Preconfigure the member's store (#303): the shas its preflight
    /// "listed" — `Some` even when empty (a known-empty store), `None`
    /// meaning unknown stays the constructor default.
    fn holds(mut self, shas: &[&str]) -> Self {
        self.store = Some(
            shas.iter()
                .map(|s| s.to_string())
                .collect::<BTreeSet<String>>(),
        );
        self
    }

    fn fails_build(mut self, names: &[&'static str]) -> Self {
        self.fail_build = names.to_vec();
        self
    }

    fn dies_on(mut self, call: usize) -> Self {
        self.lose_on_call = call;
        self
    }

    fn started(&self, name: &str) -> usize {
        self.events()
            .iter()
            .filter(|e| e.as_str() == format!("start:{}:{name}", self.display))
            .count()
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl FarmJob for FakeMember {
    fn run(&self, name: &str) -> Result<(), JobFailure> {
        if self.dead.load(Ordering::SeqCst) {
            // A dead member's slots never take jobs — the scheduler
            // must never call again after a Lost.
            panic!("{} was dispatched after being lost", self.display);
        }
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.events
            .lock()
            .unwrap()
            .push(format!("start:{}:{name}", self.display));
        let n = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_running.fetch_max(n, Ordering::SeqCst);
        sleep_ms(40);
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.events
            .lock()
            .unwrap()
            .push(format!("end:{}:{name}", self.display));
        if self.fail_build.contains(&name) {
            return Err(JobFailure::Build(format!(
                "job '{name}' failed on worker '{}': build exploded",
                self.display
            )));
        }
        if self.lose_on_call != 0 && call >= self.lose_on_call {
            self.dead.store(true, Ordering::SeqCst);
            return Err(JobFailure::Lost(format!(
                "ssh to '{}' failed (code 255): Connection closed",
                self.display
            )));
        }
        Ok(())
    }

    fn display_name(&self) -> &str {
        self.display
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn store_held(&self) -> Option<BTreeSet<String>> {
        self.store.clone()
    }
}

fn farm<'a>(members: &'a [FakeMember]) -> Vec<FarmExecutor<'a>> {
    members
        .iter()
        .map(|m| FarmExecutor {
            job: m,
            kind: if m.kind_is_local {
                ExecutorKind::Local
            } else {
                ExecutorKind::Worker {
                    declared_arch: m.declared_arch.clone(),
                }
            },
        })
        .collect()
}

// ── Placement: capability match, then ready-set order ──

#[test]
fn capability_match_routes_the_arch_job_off_local() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // One declared arm worker plus the local slots. The arm job must
    // land on the worker (the local slots would fail its cross build);
    // host-arch jobs go wherever a slot is free.
    let arm = FakeMember::worker("armbox", 2, Some("aarch64-linux-gnu"), events.clone());
    let local = FakeMember::local(2, events.clone());
    let members = vec![arm, local];
    let mut caps_map = no_caps();
    caps_map.insert("arm-pkg".to_string(), caps(&["arm64"], true));
    caps_map.insert("host-pkg".to_string(), caps(&["amd64"], false));

    let g = graph(&[("arm-pkg", &[]), ("host-pkg", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    assert_eq!(
        members[0].started("arm-pkg"),
        1,
        "the arm job runs on the declared worker: {events:?}"
    );
    assert_eq!(
        members[1].started("arm-pkg"),
        0,
        "local never takes a cross job a declared worker can run: {events:?}"
    );
    assert_eq!(members[1].started("host-pkg"), 1, "{events:?}");
}

#[test]
fn local_only_jobs_never_reach_a_worker() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let w = FakeMember::worker("box", 2, None, events.clone());
    let local = FakeMember::local(2, events.clone());
    let members = vec![w, local];
    let mut caps_map = no_caps();
    caps_map.insert(
        "sticky".to_string(),
        JobCaps {
            archs: vec!["amd64".to_string()],
            cross: false,
            local_only: true,
            objects: BTreeSet::new(),
        },
    );
    let g = graph(&[("sticky", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    assert_eq!(
        members[0].calls(),
        0,
        "the worker takes nothing: {events:?}"
    );
    assert_eq!(members[1].started("sticky"), 1, "{events:?}");
}

#[test]
fn worker_slots_bound_their_concurrency() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let w = FakeMember::worker("box", 2, None, events.clone());
    let local = FakeMember::local(0, events.clone());
    let members = vec![w, local];
    let g = graph(&[
        ("j1", &[]),
        ("j2", &[]),
        ("j3", &[]),
        ("j4", &[]),
        ("j5", &[]),
    ]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &no_caps());
    outcome.result.expect("farm builds clean");
    assert_eq!(
        members[0].max_running.load(Ordering::SeqCst),
        2,
        "jobs=2 bounds the worker: {events:?}"
    );
    assert_eq!(
        members[1].calls(),
        0,
        "zero local slots never dispatch: {events:?}"
    );
    for j in ["j1", "j2", "j3", "j4", "j5"] {
        assert_eq!(members[0].started(j), 1, "{events:?}");
    }
}

// ── Failure classes (ADR-0040 Amendment 1) ──

#[test]
fn build_failure_stops_the_world_and_names_the_worker() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // Declared archs route deterministically: "boom" (arm64) can only
    // run on badbox, "solo" (amd64) only on goodbox.
    let bad = FakeMember::worker("badbox", 1, Some("aarch64-linux-gnu"), events.clone())
        .fails_build(&["boom"]);
    let good = FakeMember::worker("goodbox", 1, Some("x86_64-linux-gnu"), events.clone());
    let members = vec![bad, good];
    // "boom" fails on badbox; "solo" runs on goodbox and must finish;
    // "dep" depends on boom and must never start.
    let g = graph(&[("boom", &[]), ("dep", &["boom"]), ("solo", &[])]);
    let mut caps_map = no_caps();
    caps_map.insert("boom".to_string(), caps(&["arm64"], false));
    caps_map.insert("dep".to_string(), caps(&["arm64"], false));
    caps_map.insert("solo".to_string(), caps(&["amd64"], false));
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    let err = outcome.result.expect_err("a build failure fails the run");
    assert_eq!(members[0].started("boom"), 1, "{events:?}");
    assert!(
        err.failed[0].0 == "boom" && err.failed[0].1.contains("badbox"),
        "the failure names the worker and the job: {:?}",
        err.failed
    );
    assert_eq!(err.skipped, vec!["dep".to_string()], "{events:?}");
    assert_eq!(
        members[1].started("solo"),
        1,
        "the in-flight job on the survivor finishes: {events:?}"
    );
    assert!(
        members[0].started("dep") == 0 && members[1].started("dep") == 0,
        "dependents never start: {events:?}"
    );
    assert!(
        outcome.workers_lost.is_empty(),
        "a build failure loses no worker: {:?}",
        outcome.workers_lost
    );
}

#[test]
fn worker_loss_redispatches_the_job_to_a_survivor() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let flaky = FakeMember::worker("flaky", 1, None, events.clone()).dies_on(1);
    let steady = FakeMember::worker("steady", 2, None, events.clone());
    let members = vec![flaky, steady];
    let g = graph(&[("j1", &[]), ("j2", &[]), ("j3", &[])]);
    let caps_map: HashMap<String, JobCaps> = ["j1", "j2", "j3"]
        .iter()
        .map(|n| (n.to_string(), caps(&["amd64"], false)))
        .collect();
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome
        .result
        .expect("a lost worker's jobs re-dispatch; the run survives");
    assert_eq!(
        outcome.workers_lost,
        vec!["flaky".to_string()],
        "the summary names the worker the run lost"
    );
    assert_eq!(
        members[0].calls(),
        1,
        "the lost worker is never dispatched again: {events:?}"
    );
    for j in ["j1", "j2", "j3"] {
        assert!(
            members[1].started(j) >= 1,
            "{j} completed on the survivor: {events:?}"
        );
    }
    // Three jobs completed plus exactly one lost attempt: whichever
    // job the flaky worker died holding ran twice in total.
    let total_attempts: usize = members.iter().map(|m| m.calls()).sum();
    assert_eq!(
        total_attempts, 4,
        "three jobs plus exactly one re-dispatched attempt: {events:?}"
    );
}

#[test]
fn worker_loss_without_any_eligible_executor_stops_the_world_named() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // A worker-only pool (no local slots): the one worker dies with a
    // job in hand — nothing eligible remains, stop-the-world, named.
    let only = FakeMember::worker("onlybox", 2, None, events.clone()).dies_on(1);
    let members = vec![only];
    let g = graph(&[("solo", &[]), ("dep", &["solo"])]);
    let caps_map: HashMap<String, JobCaps> = ["solo", "dep"]
        .iter()
        .map(|n| (n.to_string(), caps(&["amd64"], false)))
        .collect();
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    let err = outcome.result.expect_err("no executor remains");
    assert_eq!(
        outcome.workers_lost,
        vec!["onlybox".to_string()],
        "the summary names the lost worker"
    );
    let (name, msg) = &err.failed[0];
    assert_eq!(name, "solo", "{:?}", err.failed);
    assert!(
        msg.contains("no executor remains") && msg.contains("onlybox") && msg.contains("solo"),
        "the failure names the trigger and the lost worker: {msg}"
    );
    assert_eq!(err.skipped, vec!["dep".to_string()], "{events:?}");
}

#[test]
fn a_lost_cross_job_falls_back_to_local() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // The declared arm worker dies holding the cross job; the local
    // slots become the re-dispatch target (Amendment 1: local slots
    // included) once no declared worker remains.
    let arm = FakeMember::worker("armbox", 1, Some("aarch64-linux-gnu"), events.clone()).dies_on(1);
    let local = FakeMember::local(2, events.clone());
    let members = vec![arm, local];
    let g = graph(&[("arm-pkg", &[])]);
    let mut caps_map = no_caps();
    caps_map.insert("arm-pkg".to_string(), caps(&["arm64"], true));
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome
        .result
        .expect("the cross job re-dispatches to the local slots");
    assert_eq!(members[1].started("arm-pkg"), 1, "{events:?}");
    assert_eq!(outcome.workers_lost, vec!["armbox".to_string()]);
}

// ── Store-aware placement (#303) ──

/// The benchmark's anomaly, inverted. Live (two ccx workers, ~6 MB/s
/// uplink): the warm rerun sent farm-dep — whose 300MB object one
/// worker already held — to the OTHER worker while the holder built
/// farm-dep2 locally; the object re-shipped and the warm run cost the
/// same as cold. Placement now asks the store: the member holding a
/// node's known objects takes it over queue order.
#[test]
fn warm_rerun_sends_the_job_to_its_holder() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let holder = FakeMember::worker("62.238.62.155", 1, None, events.clone()).holds(&["sha-dep2"]);
    let local = FakeMember::local(1, events.clone());
    let members = vec![holder, local];
    let mut caps_map = no_caps();
    caps_map.insert(
        "farm-dep".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep"]),
    );
    caps_map.insert(
        "farm-dep2".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep2"]),
    );
    let g = graph(&[("farm-dep", &[]), ("farm-dep2", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    // Deterministic in both thread-arrival orders: the holder's scan
    // skips unheld farm-dep and takes farm-dep2; local takes farm-dep.
    assert_eq!(
        members[0].started("farm-dep2"),
        1,
        "the job rides its holder: {events:?}"
    );
    assert_eq!(
        members[0].started("farm-dep"),
        0,
        "the holder never takes a node it does not hold: {events:?}"
    );
    assert_eq!(
        members[1].started("farm-dep"),
        1,
        "the unheld node builds local — no re-ship: {events:?}"
    );
    assert_eq!(
        members[1].started("farm-dep2"),
        0,
        "local never steals a node a member holds: {events:?}"
    );
}

/// A cold run — both stores known and empty — cannot prefer anyone:
/// placement is today's, the ready set fills whichever member is free,
/// and every node still builds.
#[test]
fn cold_run_with_empty_stores_keeps_todays_placement() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let x = FakeMember::worker("box", 1, None, events.clone()).holds(&[]);
    let local = FakeMember::local(1, events.clone());
    let members = vec![x, local];
    let mut caps_map = no_caps();
    caps_map.insert(
        "farm-dep".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep"]),
    );
    caps_map.insert(
        "farm-dep2".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep2"]),
    );
    let g = graph(&[("farm-dep", &[]), ("farm-dep2", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    assert_eq!(members[0].calls(), 1, "each member takes one: {events:?}");
    assert_eq!(members[1].calls(), 1, "each member takes one: {events:?}");
    assert_eq!(
        members[0].started("farm-dep") + members[1].started("farm-dep"),
        1
    );
    assert_eq!(
        members[0].started("farm-dep2") + members[1].started("farm-dep2"),
        1
    );
}

/// An unknown store (the preflight listing failed) falls back cleanly:
/// the member is never preferred but never stalls either — placement
/// reads it exactly like a cold store.
#[test]
fn unknown_store_falls_back_cleanly() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // store: None — the constructor default — is the unknown store.
    let x = FakeMember::worker("box", 1, None, events.clone());
    let local = FakeMember::local(1, events.clone());
    let members = vec![x, local];
    let mut caps_map = no_caps();
    caps_map.insert(
        "farm-dep".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep"]),
    );
    caps_map.insert(
        "farm-dep2".to_string(),
        caps_holding(&["amd64"], false, &["sha-dep2"]),
    );
    let g = graph(&[("farm-dep", &[]), ("farm-dep2", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    assert_eq!(
        members[0].calls(),
        1,
        "the unknown store did not stall: {events:?}"
    );
    assert_eq!(members[1].calls(), 1, "{events:?}");
}

// ── Placement-banner blindness clause (#307) ──

/// The banner names a WORKER whose store is Unknown (#307): the probe
/// failed or never ran, so holder preference cannot bind for it and
/// placement fails open — silently, which is how #303 hid in window 4.
/// Not named: a populated store, and the local slots (their `None` is
/// the trait default — locals sit outside holder consideration).
#[test]
fn blind_banner_names_only_the_store_unknown_worker() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let blind = FakeMember::worker("nuci.local", 1, None, events.clone());
    let known = FakeMember::worker("ccx23", 1, None, events.clone()).holds(&["sha-dep2"]);
    let local = FakeMember::local(1, events.clone());
    let members = vec![blind, known, local];
    assert_eq!(
        placement_blind_clause(&farm(&members)),
        " (store unknown: nuci.local — no holder preference for them)",
        "exactly the unknown worker is named"
    );
}

/// A known store — populated or empty — never renders the clause: a
/// fresh worker legitimately holds nothing, and the happy path stays
/// silent (#307).
#[test]
fn blind_banner_silent_when_stores_are_known() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let empty = FakeMember::worker("box", 1, None, events.clone()).holds(&[]);
    let populated = FakeMember::worker("ccx23", 1, None, events.clone()).holds(&["sha-dep2"]);
    let local = FakeMember::local(1, events.clone());
    let members = vec![empty, populated, local];
    assert_eq!(
        placement_blind_clause(&farm(&members)),
        "",
        "empty-but-known is not blindness; no clause, no noise"
    );
}

/// A multi-worker mix renders each blind member exactly once, in pool
/// order; known members and the local slots stay unnamed (#307).
#[test]
fn blind_banner_renders_each_blind_member_once() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let blind_a = FakeMember::worker("nuci.local", 1, None, events.clone());
    let known = FakeMember::worker("ccx23", 1, None, events.clone()).holds(&[]);
    let blind_b = FakeMember::worker("worker-b", 1, None, events.clone());
    let local = FakeMember::local(1, events.clone());
    let members = vec![blind_a, known, blind_b, local];
    assert_eq!(
        placement_blind_clause(&farm(&members)),
        " (store unknown: nuci.local, worker-b — no holder preference for them)",
        "each blind member once, pool order"
    );
}
#[test]
fn holder_preference_never_overrides_eligibility() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // Declared amd64, yet "holding" the arm job's object — an
    // impossible store in practice, exactly the case the gate must
    // refuse.
    let x = FakeMember::worker("amdbox", 1, Some("x86_64-linux-gnu"), events.clone())
        .holds(&["sha-arm"]);
    let arm = FakeMember::worker("armbox", 1, Some("aarch64-linux-gnu"), events.clone());
    let members = vec![x, arm];
    let mut caps_map = no_caps();
    caps_map.insert(
        "arm-job".to_string(),
        caps_holding(&["arm64"], false, &["sha-arm"]),
    );
    caps_map.insert(
        "host-job".to_string(),
        caps_holding(&["amd64"], false, &["sha-host"]),
    );
    let g = graph(&[("arm-job", &[]), ("host-job", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome.result.expect("farm builds clean");
    assert_eq!(
        members[0].started("arm-job"),
        0,
        "holding an object never buys eligibility: {events:?}"
    );
    assert_eq!(
        members[1].started("arm-job"),
        1,
        "the capable member takes the arm job: {events:?}"
    );
    assert_eq!(
        members[0].started("host-job"),
        1,
        "each node has exactly one eligible member: {events:?}"
    );
}

/// A lost worker's job re-dispatches and the survivor's WITHIN-RUN
/// learning aims it: the survivor built the sibling first, so it holds
/// the shared source object when the re-queued (or dependent) node
/// comes around — no re-ship after the loss.
#[test]
fn loss_redispatch_lands_on_the_survivor_that_learned_the_store() {
    let events = Arc::new(Mutex::new(Vec::new()));
    // Y dies on its first call; X starts cold (known-empty store).
    let x = FakeMember::worker("survivor", 1, None, events.clone()).holds(&[]);
    let y = FakeMember::worker("doomed", 1, None, events.clone()).dies_on(1);
    let members = vec![x, y];
    // Both nodes share one source object; whichever Y grabbed dies
    // with it, re-queues, and X builds it — learning the object —
    // before the second node comes around.
    let mut caps_map = no_caps();
    caps_map.insert(
        "farm-dep".to_string(),
        caps_holding(&["amd64"], false, &["sha-shared"]),
    );
    caps_map.insert(
        "farm-dep2".to_string(),
        caps_holding(&["amd64"], false, &["sha-shared"]),
    );
    let g = graph(&[("farm-dep", &[]), ("farm-dep2", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome
        .result
        .expect("the loss is absorbed by the survivor");
    assert_eq!(members[0].calls(), 2, "X builds both nodes: {events:?}");
    assert_eq!(
        members[1].calls(),
        1,
        "Y died on its first and only dispatch: {events:?}"
    );
    assert_eq!(outcome.workers_lost, vec!["doomed".to_string()]);
}

/// The real preflight plumbing: the store listing rides the loopback
/// channel (one `ls` hop), lands in the executor, and surfaces through
/// the farm member placement sees ([`RemoteExecutor`] wraps the same
/// executor). The placement RULE over these sets is proven by the
/// FakeMember tests above.
#[test]
fn preflight_store_learning_reaches_the_farm_member() {
    let tmp = tempfile::tempdir().expect("tmp");
    let machine = tmp.path().join("machine");
    let sha = format!("{:x}", {
        use sha2::Digest as _;
        let mut h = Sha256::new();
        h.update(b"the warm 300MB object");
        h.finalize()
    });
    let objects = machine.join(".cache/nau/worker/objects");
    std::fs::create_dir_all(&objects).unwrap();
    std::fs::write(objects.join(&sha), b"obj").unwrap();
    std::fs::write(objects.join("junk-name"), b"junk").unwrap();

    let cfg = WorkerConfig {
        address: "ssh://localhost:2228".into(),
        jobs: 1,
        arch: None,
        host_key: Some(FINGERPRINT_PIN.to_string()),
        identity: None,
    };
    let ceremony = tmp.path().join("ceremony");
    ca_ceremony(&ceremony, "ssh://localhost:2228");
    let exec = SshExecutor::with_ceremony_home(
        &cfg,
        LoopbackWorker::new(&machine),
        &tmp.path().join("cache"),
        &ceremony,
    )
    .expect("executor builds");
    assert_eq!(exec.store_held(), None, "nothing learned before preflight");
    preflight_farm_workers(std::slice::from_ref(&exec)).expect("preflight passes");
    assert_eq!(
        exec.store_held(),
        Some(BTreeSet::from([sha.clone()])),
        "the listing learns the sha-named object, filtering junk"
    );

    // The learning rides the executor into the farm member.
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let remote = RemoteExecutor::new(exec, Arc::new(FakeSource { out_dir }), 1, 1);
    assert_eq!(
        FarmJob::store_held(&remote),
        Some(BTreeSet::from([sha])),
        "placement sees the worker's store through the farm member"
    );
}

/// The caps' objects come from the plan's source pins, resolved exactly
/// like dispatch's `source_pin` (lockfile pin first, then the recipe's
/// declared one); unpinned sources contribute nothing — dispatch
/// refuses them, named. A node whose plan cannot resolve carries no
/// objects, and needs none: it never leaves the coordinator.
#[test]
fn plan_objects_resolve_the_source_pins_like_dispatch() {
    let declared = sha256_hex(b"the recipe-declared hash");
    let plan = plan_for(
        "warm",
        &[],
        vec![SourceSpec::Pinned {
            url: "https://example.test/srv.tgz".into(),
            sha256: declared.clone(),
        }],
    );
    // No lockfile entry: the declared pin stands.
    assert_eq!(
        nau::coordinator::plan_objects(&plan, &empty_lockfile()),
        BTreeSet::from([declared.clone()]),
        "the declared pin is the placement-known object"
    );
    // A lockfile pin overrides the declared hash.
    let mut pinned = empty_lockfile();
    pinned.sources.insert(
        "https://example.test/srv.tgz".to_string(),
        nau::lock::SourceLockEntry {
            sha256: sha256_hex(b"the hash the lockfile saw"),
        },
    );
    assert_eq!(
        nau::coordinator::plan_objects(&plan, &pinned),
        BTreeSet::from([sha256_hex(b"the hash the lockfile saw")]),
        "the lockfile pin wins — the same resolution dispatch applies"
    );
    // An unpinned source contributes nothing to placement.
    let unverified = plan_for(
        "warm",
        &[],
        vec![SourceSpec::Unverified("https://example.test/x.tgz".into())],
    );
    assert!(
        nau::coordinator::plan_objects(&unverified, &pinned).is_empty(),
        "an unpinned source is dispatch's refusal, not placement's guess"
    );
    // A node whose plan cannot resolve carries no objects.
    let plans = nau::coordinator::precompute_farm_plans(
        &BTreeMap::from([("meta-only".to_string(), bare_meta("meta-only", "1.0.0"))]),
        &[],
        &empty_lockfile(),
    )
    .expect("a build-less plan precomputes");
    assert!(
        plans.caps["meta-only"].objects.is_empty(),
        "a plan-less node carries no objects"
    );
}

// ── The loopback dispatch (T4 transport under the T5 pool) ──

/// The workers-entry pin is the host CA's fingerprint (the only pin
/// form, #295); the ceremony fixture below writes the CA public half
/// the fake fingerprints to it.
const FINGERPRINT_PIN: &str = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfG";
const CA_PUB_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkvsDFv9XrohqXsJvKK8dFbGFe5vN3fGcLgoW8cR3Ux loopback-ca";
const CA_IDENTITY: &str = "nau-worker-farm-test-01";

/// The ceremony fixture the CA-form pin resolves against: the CA public
/// half on disk plus the machine linkage for `address`, under `home`
/// (the seam `with_ceremony_home` points the executor at).
fn ca_ceremony(home: &Path, address: &str) {
    let ca_dir = home.join(".config/nau/ca");
    std::fs::create_dir_all(ca_dir.join("machines")).unwrap();
    std::fs::write(ca_dir.join("ca.pub"), format!("{CA_PUB_LINE}\n")).unwrap();
    nau::provision::publish::record_machine_link(home, CA_IDENTITY, address).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn host_arch() -> String {
    nau::snap::host_arch().to_string()
}

/// The scripted worker side of the SSH channel: real file moves for
/// scp, real extraction of nothing (the fixture closure is empty), the
/// cap document, and one scripted job result. `dies` makes every ssh
/// exit 255 — a connection the keepalive deadline would kill.
struct LoopbackWorker {
    root: PathBuf,
    dies: bool,
    cap: CapabilityDoc,
    /// What `ssh-keygen -lf` reports for any key file — the CA-form pin
    /// resolution seam (must match the pinned fingerprint).
    reported_fingerprint: String,
    /// Sleep injected into the `__worker-job` handler — a known remote
    /// build wall the timing assertions bound loosely (#302).
    job_delay_ms: u64,
    /// The build_ms the scripted result document reports — the injected
    /// duration a test asserts propagates (#302).
    result_build_ms: Option<u64>,
}

impl LoopbackWorker {
    fn new(root: &Path) -> Self {
        LoopbackWorker {
            root: root.to_path_buf(),
            dies: false,
            reported_fingerprint: FINGERPRINT_PIN.to_string(),
            job_delay_ms: 0,
            result_build_ms: None,
            cap: CapabilityDoc {
                protocol: WORKER_PROTOCOL_VERSION,
                arch: host_arch(),
                nproc: 2,
                ram_bytes: 4_000_000_000,
                free_disk_bytes: 1024u64.pow(4),
                bwrap: true,
                mksquashfs: true,
                kvm: false,
                sandbox: true,
                mksquashfs_version: Some(nau::provision::SQUASHFS_TOOLS_VERSION.into()),
            },
        }
    }

    fn remote_path(&self, token: &str) -> Option<PathBuf> {
        let rest = token.strip_prefix('~')?.trim_start_matches('/');
        Some(self.root.join(rest))
    }

    fn ssh(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        if self.dies {
            return Ok(RunnerOutput {
                code: 255,
                stdout: Vec::new(),
                stderr: "ssh_exchange_identification: Connection closed by remote host".into(),
            });
        }
        let Some(cmd) = argv.last() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
        };
        if cmd.contains("__worker-cap") {
            return Ok(RunnerOutput {
                code: 0,
                stdout: serde_json::to_vec(&self.cap).unwrap(),
                stderr: String::new(),
            });
        }
        if cmd.contains("__worker-job") {
            return self.job(cmd);
        }
        if cmd.starts_with("rm -rf") {
            for token in cmd.split_whitespace().skip(2) {
                if let Some(p) = self.remote_path(token) {
                    let _ = std::fs::remove_dir_all(&p);
                    let _ = std::fs::remove_file(&p);
                }
            }
            return Ok(RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            });
        }
        if cmd.starts_with("ls ") {
            let dir = cmd.split_whitespace().nth(1).unwrap();
            let mut names: Vec<String> = self
                .remote_path(dir)
                .and_then(|p| std::fs::read_dir(p).ok())
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            return Ok(RunnerOutput {
                code: 0,
                stdout: names.join("\n").into_bytes(),
                stderr: String::new(),
            });
        }
        if cmd.starts_with("mkdir -p") {
            for token in cmd.split_whitespace().skip(2) {
                if token == "&&" {
                    break;
                }
                std::fs::create_dir_all(self.remote_path(token).unwrap())?;
            }
            return Ok(RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            });
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("loopback: unsupported remote command: {cmd}"),
        ))
    }

    /// `nau __worker-job <job.json>`: write the scripted artifact
    /// into the job's out dir and print the result document.
    fn job(&self, cmd: &str) -> io::Result<RunnerOutput> {
        if self.job_delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(self.job_delay_ms));
        }
        let job_file = self
            .remote_path(cmd.split_whitespace().last().unwrap())
            .expect("job file under ~");
        let manifest: JobManifest = serde_json::from_str(
            &std::fs::read_to_string(&job_file).expect("coordinator shipped the job file"),
        )
        .expect("valid manifest");
        let out_dir = job_file.parent().unwrap().join("out");
        std::fs::create_dir_all(&out_dir)?;
        let artifact = format!("{}_1.0.0_{}.snap", manifest.package, host_arch());
        let bytes = format!("snap bytes of {}", manifest.package).into_bytes();
        let out_path = out_dir.join(&artifact);
        std::fs::write(&out_path, &bytes)?;
        let result = JobResult {
            protocol_version: WORKER_PROTOCOL_VERSION,
            package: manifest.package,
            target: manifest.target,
            ok: true,
            artifacts: vec![Artifact {
                filename: artifact,
                path: out_path.to_string_lossy().into_owned(),
                sha256: sha256_hex(&bytes),
                size: bytes.len() as u64,
            }],
            error: None,
            stderr: None,
            build_ms: self.result_build_ms,
        };
        Ok(RunnerOutput {
            code: 0,
            stdout: serde_json::to_string(&result).unwrap().into_bytes(),
            stderr: String::new(),
        })
    }

    fn scp(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        let src = &argv[argv.len() - 2];
        let dst = &argv[argv.len() - 1];
        if src.contains(':') {
            // Pull: remote → local.
            let remote = src.split_once(':').unwrap().1;
            let from = self.remote_path(remote).expect("remote source under ~");
            std::fs::write(dst, std::fs::read(&from)?)?;
        } else {
            // Push: local → remote.
            let to = dst
                .split_once(':')
                .and_then(|(_, remote)| self.remote_path(remote))
                .expect("remote destination under ~");
            std::fs::create_dir_all(to.parent().unwrap())?;
            std::fs::write(&to, std::fs::read(src)?)?;
        }
        Ok(RunnerOutput {
            code: 0,
            stdout: Vec::new(),
            stderr: String::new(),
        })
    }
}

impl CommandRunner for LoopbackWorker {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        match argv[0].as_str() {
            "ssh" => self.ssh(argv),
            "scp" => self.scp(argv),
            "ssh-keygen" => {
                // `-lf <path>`: report the configured fingerprint for
                // whichever key file the executor inspects (the CA-form
                // resolution seam).
                Ok(RunnerOutput {
                    code: 0,
                    stdout: format!("256 {} loopback-ca (ED25519)\n", self.reported_fingerprint)
                        .into_bytes(),
                    stderr: String::new(),
                })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("loopback: unexpected program {other}"),
            )),
        }
    }
}

/// The assembly seam: one manifest per node (no sources, no deps), no
/// payload to stage, artifacts placed into the run's output dir.
struct FakeSource {
    out_dir: PathBuf,
}

impl ManifestSource for FakeSource {
    fn manifest_for(&self, name: &str) -> miette::Result<JobManifest> {
        let mut recipes = BTreeMap::new();
        let first = name.chars().next().unwrap_or('x').to_ascii_lowercase();
        recipes.insert(
            format!("pkgs/{first}/{name}.lua"),
            format!("return {{ default = snap {{ name = \"{name}\" }} }}"),
        );
        Ok(JobManifest {
            protocol_version: WORKER_PROTOCOL_VERSION,
            target: host_arch(),
            cross_target: None,
            source_date_epoch: Some(1700000000),
            package: name.to_string(),
            recipes,
            pins: Vec::new(),
            closure: Vec::new(),
            payload_dir: None,
        })
    }

    fn stage_payload(&self, _manifest: &JobManifest) -> miette::Result<tempfile::TempDir> {
        tempfile::tempdir().map_err(|e| miette::miette!("stage: {e}"))
    }

    fn ingest(
        &self,
        _name: &str,
        outcome: &DispatchOutcome,
        artifacts_in: &Path,
        _display: &str,
    ) -> miette::Result<()> {
        for art in &outcome.result.artifacts {
            std::fs::copy(
                artifacts_in.join(&art.filename),
                self.out_dir.join(&art.filename),
            )
            .map_err(|e| miette::miette!("ingest copy: {e}"))?;
        }
        Ok(())
    }
}

/// The real T4 transport under the T5 pool, in three deterministic
/// stages: a worker-only pool whose one channel is dead (the run stops
/// the world, named — the death classifies as worker loss, not build
/// failure); a worker-only pool whose channel serves (dispatch,
/// collect, and ingest land the artifact); then both together (the run
/// succeeds — direct if the live channel wins the ready race, via
/// re-dispatch if the dead one does; both orders are correct). No
/// network, no sshd — `ssh://localhost` against scripted in-process
/// fakes.
#[test]
fn loopback_farm_dispatch_and_worker_loss() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source = Arc::new(FakeSource {
        out_dir: out_dir.clone(),
    });

    let ceremony = tmp.path().join("ceremony");
    let make_worker = |port: u16, dies: bool, root: &Path| {
        let mut fake = LoopbackWorker::new(root);
        fake.dies = dies;
        let address = format!("ssh://localhost:{port}");
        ca_ceremony(&ceremony, &address);
        let cfg = WorkerConfig {
            address,
            jobs: 1,
            arch: None,
            host_key: Some(FINGERPRINT_PIN.to_string()),
            identity: None,
        };
        let cache = tmp.path().join(format!("cache-{port}"));
        let exec = SshExecutor::with_ceremony_home(&cfg, fake, &cache, &ceremony)
            .expect("executor builds");
        RemoteExecutor::new(exec, Arc::clone(&source), 1, 1)
    };

    // Stage 1 — the only channel is dead: worker loss with no eligible
    // executor left stops the run, naming the worker and the job.
    let dead = make_worker(2222, true, &tmp.path().join("machine-a"));
    let stage1: Vec<FarmExecutor<'_>> = vec![
        FarmExecutor {
            job: &dead,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &LocalNothing,
            kind: ExecutorKind::Local,
        },
    ];
    let g = graph(&[("worker-hello", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &stage1, &no_caps());
    let err = outcome
        .result
        .expect_err("a worker-only farm with one dead channel fails");
    assert_eq!(outcome.workers_lost, vec!["localhost"]);
    let (name, msg) = &err.failed[0];
    assert_eq!(name, "worker-hello");
    assert!(
        msg.contains("no executor remains") && msg.contains("localhost"),
        "the stop names the job and the lost worker: {msg}"
    );
    // The shape itself is the classification evidence: a channel death
    // misread as a build failure would report the ssh text directly and
    // leave workers_lost empty — instead the loss is recorded and the
    // scheduler reports no executor remaining.

    // Stage 2 — the only channel serves: full dispatch, collect, ingest.
    let alive = make_worker(2223, false, &tmp.path().join("machine-b"));
    let stage2: Vec<FarmExecutor<'_>> = vec![
        FarmExecutor {
            job: &alive,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &LocalNothing,
            kind: ExecutorKind::Local,
        },
    ];
    let outcome = run_ready_set_farm(&g, &Default::default(), &stage2, &no_caps());
    outcome
        .result
        .expect("the farm dispatches through the live channel");
    assert!(outcome.workers_lost.is_empty());
    assert_ingested(&tmp.path().join("cache-2223"), &out_dir);

    // Stage 3 — both channels: the run succeeds whichever wins the
    // ready race; a dead winner re-dispatches to the survivor.
    let dead2 = make_worker(2224, true, &tmp.path().join("machine-c"));
    let alive2 = make_worker(2225, false, &tmp.path().join("machine-d"));
    let stage3: Vec<FarmExecutor<'_>> = vec![
        FarmExecutor {
            job: &dead2,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &alive2,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &LocalNothing,
            kind: ExecutorKind::Local,
        },
    ];
    let outcome = run_ready_set_farm(&g, &Default::default(), &stage3, &no_caps());
    outcome
        .result
        .expect("the run survives whichever channel wins");
    assert!(
        outcome.workers_lost.len() <= 1,
        "at most one loss, named: {:?}",
        outcome.workers_lost
    );
    assert_ingested(&tmp.path().join("cache-2225"), &out_dir);
}

/// The worker-only pools' zero-slot local member: placement sees the
/// Local kind, but zero slots spawn no thread, so nothing ever
/// dispatches to the coordinator itself.
struct LocalNothing;

impl FarmJob for LocalNothing {
    fn run(&self, _name: &str) -> Result<(), JobFailure> {
        panic!("zero-slot local member must never dispatch");
    }
    fn slots(&self) -> usize {
        0
    }
}

/// The run's artifact reached the output dir, served from the
/// manifest-identity ingest record — `jm1_<hex>`, never a v4 key.
fn assert_ingested(cache: &Path, out_dir: &Path) {
    let artifact = format!("worker-hello_1.0.0_{}.snap", host_arch());
    assert!(
        out_dir.join(&artifact).exists(),
        "the artifact reached the output dir"
    );
    let ingest_root = cache.join("remote");
    let mut records: Vec<String> = std::fs::read_dir(&ingest_root)
        .expect("ingest records exist")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    records.sort();
    assert_eq!(records.len(), 1, "one manifest identity: {records:?}");
    assert!(
        records[0].starts_with("jm1_"),
        "ingest keys are jm1 identities: {records:?}"
    );
}

// ── Transport classification + JSON fields ──

#[test]
fn short_worker_name_strips_to_the_host() {
    assert_eq!(short_worker_name("ssh://op@nuci.local"), "nuci.local");
    assert_eq!(short_worker_name("ssh://op@nuci.local:2222"), "nuci.local");
    assert_eq!(short_worker_name("ssh://nuci.local"), "nuci.local");
    assert_eq!(short_worker_name("ssh://[::1]:22"), "::1");
}

#[test]
fn json_events_carry_executor_and_worker() {
    let local = nau::output::BuildResultJson {
        name: "tree".into(),
        version: "2.3.2".into(),
        arch: "amd64".into(),
        filename: "tree_2.3.2_amd64.snap".into(),
        sha256: None,
        sources: None,
        executor: "local".into(),
        worker: None,
    };
    let v = serde_json::to_value(&local).unwrap();
    assert_eq!(v["executor"], "local");
    assert!(v.get("worker").is_none(), "local events omit the worker");

    let farm = nau::output::BuildResultJson {
        worker: Some("nuci.local".into()),
        executor: "ssh".into(),
        ..local
    };
    let v = serde_json::to_value(&farm).unwrap();
    assert_eq!(v["executor"], "ssh");
    assert_eq!(v["worker"], "nuci.local");
}

// ── The coordinator assembly (#282 F1, F2, F4, F5) ──

/// Bare SnapMeta with every optional field empty (mirrors the bare_meta
/// helper in snap.rs's unit tests).
fn bare_meta(name: &str, version: &str) -> SnapMeta {
    SnapMeta {
        name: name.into(),
        version: version.into(),
        summary: None,
        description: None,
        license: None,
        source: None,
        sources: None,
        build: None,
        parts: None,
        architectures: None,
        grade: "stable".into(),
        confinement: "strict".into(),
        type_: None,
        adopt_info: None,
        version_adopted: false,
        icon_source: None,
        icon: None,
        compression: None,
        compression_level: None,
        environment: None,
        layout: None,
        hooks: None,
        plugs: None,
        slots: None,
        aliases: vec![],
        requires: vec![],
        build_deps: vec![],
        leaks_ok: vec![],
        target: None,
        toolchain: None,
        inputs: None,
        confined: None,
        apps: HashMap::new(),
        services: BTreeMap::new(),
        deps: None,
        floating: false,
        definition_dir: None,
    }
}

fn empty_lockfile() -> LockFile {
    LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    }
}

fn plan_for(package: &str, deps: &[&str], sources: Vec<SourceSpec>) -> NodeJobPlan {
    NodeJobPlan {
        recipe_key: format!(
            "pkgs/{}/{package}.lua",
            package.chars().next().unwrap_or('x').to_ascii_lowercase()
        ),
        recipe: format!("return {{ default = snap {{ name = \"{package}\" }} }}"),
        arch: "amd64".into(),
        cross_target: None,
        package: package.into(),
        deps: deps.iter().map(|d| d.to_string()).collect(),
        sources,
    }
}

/// A curl fake: writes the canned body to the `-o` destination and
/// exits 0 — the network convention `fetch_pinned_source` drives.
struct FakeCurl {
    body: &'static [u8],
}

impl CommandRunner for FakeCurl {
    fn run(&self, argv: &[String]) -> io::Result<RunnerOutput> {
        assert_eq!(argv[0], "curl");
        let dest = argv.iter().position(|a| a == "-o").unwrap() + 1;
        std::fs::write(&argv[dest], self.body)?;
        Ok(RunnerOutput {
            code: 0,
            stdout: Vec::new(),
            stderr: String::new(),
        })
    }
}

/// The fetch phase: a downloaded body that hashes to something other
/// than the pin refuses the stage — nothing ships, and the refusal
/// names both hashes (#282 F2: pin-verification-before-ship, pinned by
/// test against the real assembly).
#[test]
fn farm_source_refuses_a_stale_pin_before_shipping() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let lockfile = empty_lockfile();

    let url = "https://example.test/srv.tgz";
    let source = FarmSource {
        plans: HashMap::from([(
            "srv".to_string(),
            plan_for(
                "srv",
                &[],
                vec![SourceSpec::Pinned {
                    url: url.into(),
                    sha256: sha256_hex(b"the bytes the lockfile saw"),
                }],
            ),
        )]),
        dep_metas: HashMap::new(),
        dep_closures: HashMap::new(),
        lockfile: &lockfile,
        output_dir: &out_dir,
        pkg_cache: None,
        json: false,
        epoch: None,
        runner: FakeCurl {
            body: b"the bytes upstream serves today",
        },
    };

    let manifest = source
        .manifest_for("srv")
        .expect("a pinned source pins fine");
    let err = source
        .stage_payload(&manifest)
        .expect_err("the served body hashes to something else");
    let text = format!("{err:#}");
    assert!(
        text.contains("hashes to") && text.contains("refusing to ship"),
        "the mismatch refusal names both hashes: {text}"
    );
}

/// An unpinned source (no lockfile entry, no declared sha256) refuses
/// at manifest time — a worker never fetches upstream (ADR-0040
/// Decision 6).
#[test]
fn farm_source_refuses_an_unpinned_source() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let lockfile = empty_lockfile();

    let source = FarmSource {
        plans: HashMap::from([(
            "srv".to_string(),
            plan_for(
                "srv",
                &[],
                vec![SourceSpec::Unverified(
                    "https://example.test/srv.tgz".into(),
                )],
            ),
        )]),
        dep_metas: HashMap::new(),
        dep_closures: HashMap::new(),
        lockfile: &lockfile,
        output_dir: &out_dir,
        pkg_cache: None,
        json: false,
        epoch: None,
        runner: FakeCurl { body: b"" },
    };

    let err = source
        .manifest_for("srv")
        .expect_err("an unpinned source refuses");
    let text = format!("{err:#}");
    assert!(
        text.contains("is unpinned"),
        "the refusal names the source and the pin duty: {text}"
    );
}

/// The dep-payload closure: the manifest hashes each dep payload once
/// (name, size, purpose), and staging hardlinks the payload under THAT
/// manifest-carried hash — a second read+hash would be the double
/// dispatch cost #282 F5 removes.
#[test]
fn farm_source_hashes_dep_payload_once_and_stages_under_that_hash() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let lockfile = empty_lockfile();

    let payload = b"dep1 snap bytes for the closure";
    std::fs::write(out_dir.join("dep1_1.0.0_amd64.snap"), payload).unwrap();

    let mut dep_metas = HashMap::new();
    dep_metas.insert("dep1".to_string(), bare_meta("dep1", "1.0.0"));
    let source = FarmSource {
        plans: HashMap::from([("app".to_string(), plan_for("app", &["dep1"], vec![]))]),
        dep_metas,
        dep_closures: HashMap::new(),
        lockfile: &lockfile,
        output_dir: &out_dir,
        pkg_cache: None,
        json: false,
        epoch: Some(1700000000),
        runner: FakeCurl { body: b"" },
    };

    let manifest = source
        .manifest_for("app")
        .expect("the dep payload resolves");
    assert_eq!(manifest.closure.len(), 1, "one closure object: the dep");
    assert_eq!(manifest.closure[0].sha256, sha256_hex(payload));
    assert_eq!(manifest.closure[0].size, payload.len() as u64);
    assert_eq!(manifest.closure[0].purpose, "dep:dep1");

    let stage = source
        .stage_payload(&manifest)
        .expect("the stage assembles");
    let staged: Vec<String> = std::fs::read_dir(stage.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        staged,
        vec![sha256_hex(payload)],
        "the payload is staged under the manifest's hash, named by sha256"
    );
    // The stage entry IS the run output's inode — a hardlink under the
    // manifest-carried hash, not a second read+hash copy.
    {
        use std::os::unix::fs::MetadataExt;
        let out_ino = std::fs::metadata(out_dir.join("dep1_1.0.0_amd64.snap"))
            .unwrap()
            .ino();
        let stage_ino = std::fs::metadata(stage.path().join(sha256_hex(payload)))
            .unwrap()
            .ino();
        assert_eq!(
            out_ino, stage_ino,
            "staged by hardlink from the run output — no second read+hash"
        );
    }
}

/// The JSON event a farm dispatch emits: executor `ssh`, worker
/// attributed, the version parsed from the artifact filename's stem —
/// the "0" placeholder when the stem does not parse.
#[test]
fn farm_ingest_builds_the_json_event_shape() {
    let outcome = |filename: &str| DispatchOutcome {
        cache_hit: false,
        sync: std::time::Duration::ZERO,
        total: std::time::Duration::ZERO,
        result: JobResult {
            protocol_version: WORKER_PROTOCOL_VERSION,
            package: "app".into(),
            target: "amd64".into(),
            ok: true,
            artifacts: vec![Artifact {
                filename: filename.into(),
                path: "/remote/out/x".into(),
                sha256: sha256_hex(b"app bytes"),
                size: 9,
            }],
            error: None,
            stderr: None,
            build_ms: None,
        },
    };

    let event = farm_build_result("app", &outcome("app_2.3.2_amd64.snap"), "nuci.local")
        .expect("an artifact builds an event");
    let v = serde_json::to_value(&event).unwrap();
    assert_eq!(v["executor"], "ssh");
    assert_eq!(v["worker"], "nuci.local");
    assert_eq!(v["name"], "app");
    assert_eq!(v["version"], "2.3.2", "the stem parses to the version");
    assert_eq!(v["arch"], "amd64");
    assert_eq!(v["filename"], "app_2.3.2_amd64.snap");
    assert_eq!(v["sha256"], sha256_hex(b"app bytes"));

    let odd = farm_build_result("app", &outcome("mystery.snap"), "nuci.local")
        .expect("an artifact builds an event");
    assert_eq!(
        serde_json::to_value(&odd).unwrap()["version"],
        "0",
        "an unparseable stem keeps the placeholder identity"
    );
}

/// Pre-run preflight passes the entry's DECLARED arch (#282 F1): a
/// worker reporting an arch its config contradicts refuses the run at
/// preflight — named by worker and probe — before anything dispatches;
/// zero jobs cross the channel.
#[test]
fn preflight_refuses_a_declared_arch_mismatch_before_any_dispatch() {
    let tmp = tempfile::tempdir().expect("tmp");
    let machine = tmp.path().join("machine");
    std::fs::create_dir_all(&machine).unwrap();

    let reported = host_arch();
    let declared = if reported == "amd64" {
        "aarch64-linux-gnu"
    } else {
        "x86_64-linux-gnu"
    };
    let cfg = WorkerConfig {
        address: "ssh://localhost:2226".into(),
        jobs: 1,
        arch: Some(declared.into()),
        host_key: Some(FINGERPRINT_PIN.to_string()),
        identity: None,
    };
    let ceremony = tmp.path().join("ceremony");
    ca_ceremony(&ceremony, "ssh://localhost:2226");
    let exec = SshExecutor::with_ceremony_home(
        &cfg,
        LoopbackWorker::new(&machine),
        &tmp.path().join("cache"),
        &ceremony,
    )
    .expect("executor builds");
    let err = preflight_farm_workers(&[exec])
        .expect_err("the declared arch contradicts the worker's report");
    let text = format!("{err:#}");
    assert!(
        text.contains("preflight arch") && text.contains("expected"),
        "the refusal names the probe and the expectation: {text}"
    );
    assert!(
        !machine.join(".cache/nau/worker/jobs").exists(),
        "zero dispatches: the job never crossed the channel"
    );

    // The undeclared case passes the same probe (the worker's report is
    // trusted — the mismatch duty is on the config's declaration).
    let ok_cfg = WorkerConfig {
        address: "ssh://localhost:2227".into(),
        arch: None,
        ..cfg
    };
    ca_ceremony(&ceremony, "ssh://localhost:2227");
    let exec = SshExecutor::with_ceremony_home(
        &ok_cfg,
        LoopbackWorker::new(&machine),
        &tmp.path().join("cache2"),
        &ceremony,
    )
    .expect("executor builds");
    preflight_farm_workers(&[exec]).expect("an undeclared arch takes the worker's report");
}

/// Two workers whose short names collide (nuci.local:22,
/// nuci.local:2222 — both render "nuci.local") each record their own
/// loss (#282 F4): the lost set is keyed by member, not display name,
/// so the second loss is neither merged away nor silenced.
#[test]
fn duplicate_short_names_each_record_their_loss() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let a = FakeMember::worker("nuci.local", 1, None, events.clone()).dies_on(1);
    let b = FakeMember::worker("nuci.local", 1, None, events.clone()).dies_on(1);
    let local = FakeMember::local(2, events.clone());
    let members = vec![a, b, local];
    let g = graph(&[("j1", &[]), ("j2", &[]), ("j3", &[]), ("j4", &[])]);
    let caps_map: HashMap<String, JobCaps> = ["j1", "j2", "j3", "j4"]
        .iter()
        .map(|n| (n.to_string(), caps(&["amd64"], false)))
        .collect();
    let outcome = run_ready_set_farm(&g, &Default::default(), &farm(&members), &caps_map);
    outcome
        .result
        .expect("both losses re-dispatch to the local slots");
    let mut lost = outcome.workers_lost.clone();
    lost.sort();
    assert_eq!(
        lost,
        vec!["nuci.local".to_string(), "nuci.local".to_string(),],
        "two same-short-name workers each record (and warn) their loss — \
         no display-name merge: {:?}",
        outcome.workers_lost
    );
}

/// A metadata-only job (no declared architectures → resolve_archs yields
/// `["all"]`) can never run on a real worker: the worker always reports a
/// concrete arch and the dispatch preflight refuses `all`. The caps
/// computation must therefore mark it local_only, or placement routes it
/// to an undeclared worker and the run dies at dispatch (found live: the
/// first ccx13 cloud worker refused both fixtures exactly this way).
#[test]
fn metadata_only_all_jobs_are_local_only() {
    let mut metas = BTreeMap::new();
    metas.insert("meta-only".to_string(), bare_meta("meta-only", "1.0.0"));
    let plans = nau::coordinator::precompute_farm_plans(&metas, &[], &empty_lockfile())
        .expect("a build-less plan precomputes");
    let caps = plans
        .caps
        .get("meta-only")
        .expect("the node's caps are computed");
    assert!(
        caps.local_only,
        "an `all` job must never leave the coordinator: {caps:?}"
    );
}

// ── Per-job phase timings (#302) ──

/// A loopback farm run records one JobTiming per dispatched job and the
/// numbers are the ones the fakes injected: the scripted result's
/// build_ms propagates EXACTLY (it is carried, not measured), the known
/// job delay bounds the total wall loosely, total covers sync, and the
/// artifact bytes are the shipped artifact's size. The end-of-run block
/// renders the same numbers.
#[test]
fn dispatch_timings_reach_the_run_summary() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let source = Arc::new(FakeSource {
        out_dir: out_dir.clone(),
    });

    let ceremony = tmp.path().join("ceremony");
    let address = "ssh://localhost:2228";
    ca_ceremony(&ceremony, address);
    let mut fake = LoopbackWorker::new(&tmp.path().join("machine"));
    fake.job_delay_ms = 150;
    fake.result_build_ms = Some(1500);
    let cfg = WorkerConfig {
        address: address.to_string(),
        jobs: 1,
        arch: None,
        host_key: Some(FINGERPRINT_PIN.to_string()),
        identity: None,
    };
    let exec = SshExecutor::with_ceremony_home(&cfg, fake, &tmp.path().join("cache"), &ceremony)
        .expect("executor builds");
    let alive = RemoteExecutor::new(exec, Arc::clone(&source), 1, 1);

    let stage: Vec<FarmExecutor<'_>> = vec![
        FarmExecutor {
            job: &alive,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &LocalNothing,
            kind: ExecutorKind::Local,
        },
    ];
    let g = graph(&[("worker-hello", &[])]);
    let outcome = run_ready_set_farm(&g, &Default::default(), &stage, &no_caps());
    outcome.result.expect("the dispatch completes");

    let timings = alive.job_timings();
    assert_eq!(timings.len(), 1, "one dispatched job, one timing entry");
    let t = &timings[0];
    assert_eq!(t.node, "worker-hello");
    assert_eq!(t.worker, "localhost");
    assert_eq!(
        t.build,
        Some(std::time::Duration::from_millis(1500)),
        "the result document's build_ms propagates as carried"
    );
    assert!(
        t.total >= std::time::Duration::from_millis(150),
        "the known job delay bounds the dispatch wall: {t:?}"
    );
    assert!(
        t.total >= t.sync,
        "total (dispatch start → ingest) covers the sync phase: {t:?}"
    );
    assert_eq!(
        t.artifact_bytes,
        "snap bytes of worker-hello".len() as u64,
        "the artifact's size rides the timing entry"
    );

    let block = nau::build_sched::render_farm_timings(&timings);
    assert!(
        block.contains("worker-hello on localhost"),
        "the block attributes the job: {block}"
    );
    assert!(
        block.contains("sync") && block.contains("build 1.5s") && block.contains("total"),
        "the phases render with the injected build number: {block}"
    );
    assert!(block.contains("26 B"), "the artifact bytes render: {block}");
}

/// A manifest-cache hit crosses no channel and records no second timing
/// entry — the summary counts dispatched work, and the ✓ line keeps its
/// `(manifest cache)` marker instead.
#[test]
fn cache_hit_records_no_timing_entry() {
    let tmp = tempfile::tempdir().expect("tmp");
    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let source = Arc::new(FakeSource { out_dir });

    let ceremony = tmp.path().join("ceremony");
    let address = "ssh://localhost:2229";
    ca_ceremony(&ceremony, address);
    let fake = LoopbackWorker::new(&tmp.path().join("machine"));
    let cfg = WorkerConfig {
        address: address.to_string(),
        jobs: 1,
        arch: None,
        host_key: Some(FINGERPRINT_PIN.to_string()),
        identity: None,
    };
    let exec = SshExecutor::with_ceremony_home(&cfg, fake, &tmp.path().join("cache"), &ceremony)
        .expect("executor builds");
    let alive = RemoteExecutor::new(exec, Arc::clone(&source), 1, 1);

    let stage: Vec<FarmExecutor<'_>> = vec![
        FarmExecutor {
            job: &alive,
            kind: ExecutorKind::Worker {
                declared_arch: None,
            },
        },
        FarmExecutor {
            job: &LocalNothing,
            kind: ExecutorKind::Local,
        },
    ];
    let g = graph(&[("worker-hello", &[])]);
    run_ready_set_farm(&g, &Default::default(), &stage, &no_caps())
        .result
        .expect("first dispatch lands");
    run_ready_set_farm(&g, &Default::default(), &stage, &no_caps())
        .result
        .expect("the re-run is served from the ingest record");
    assert_eq!(
        alive.job_timings().len(),
        1,
        "the cache hit adds no timing entry"
    );
}
