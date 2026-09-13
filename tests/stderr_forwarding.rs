//! End-to-end probes for the worker stderr forwarder (issue #76). The
//! forwarder must stay a containment-neutral piece of plumbing:
//!
//! * the forwarded stream is capped at [`shuttle::isolate`]'s documented
//!   cap and DRAINED (discarded) past it, so a print() flood cannot stall
//!   the child or balloon the parent;
//! * a parent stderr sink that stops reading cannot hold the parent past
//!   the wall-clock deadline that bounds the worker.

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shuttle::isolate::{self, EvalRequest, RunStatus, WorkerOutcome};

fn request(label: &str, source: &str) -> EvalRequest {
    EvalRequest {
        prelude: shuttle::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: BTreeMap::new(),
        entry: source.to_string(),
        entry_label: label.to_string(),
    }
}

fn out_str(run: &isolate::EvalRun, key: &str) -> String {
    match &run.outcome {
        Some(WorkerOutcome::Ok(ok)) => ok
            .outputs
            .get(key)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("<{key} missing>")),
        Some(WorkerOutcome::Err(e)) => format!("<ERR: {}>", e.diagnostics.join("; ")),
        None => format!("<no outcome; status {}>", run.status.describe()),
    }
}

/// Both tests below dup2 the process-wide stderr (fd 2), so they serialize
/// on this lock; anything else in this binary that races would only lose
/// some output into the redirected fd, never an assertion.
static FD2: Mutex<()> = Mutex::new(());

/// Redirect fd 2 to `target` and restore the original on drop (panic-safe).
struct Fd2Guard {
    saved: libc::c_int,
}

impl Fd2Guard {
    fn hijack(target: libc::c_int) -> Fd2Guard {
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0, "dup(2) failed");
        assert_eq!(unsafe { libc::dup2(target, 2) }, 2, "dup2 onto fd 2 failed");
        Fd2Guard { saved }
    }
}

impl Drop for Fd2Guard {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved, 2);
            libc::close(self.saved);
        }
    }
}

// ── Flood: past the cap the forwarder must drain-and-discard, not stop ──
// Stopping the drain would fill the child's stderr pipe and stall it into
// the wall-clock kill; draining keeps the run clean and on time.
#[test]
fn stderr_flood_past_the_cap_is_drained_and_run_completes_on_time() {
    let _serial = FD2.lock().unwrap_or_else(|e| e.into_inner());
    // /dev/null sink keeps the forwarded prefix out of the test log.
    let devnull = std::fs::File::create("/dev/null").unwrap();
    let _guard = Fd2Guard::hijack(devnull.as_raw_fd());
    drop(devnull);

    // 400 * 100 KiB ≈ 40 MiB of print() — far past the 1 MiB forwarded cap.
    let src = r#"
for i = 1, 400 do
  print(string.rep("x", 100 * 1024))
end
return { marker = "survived-flood", name = "x", version = "1" }
"#;
    let start = Instant::now();
    let r = isolate::run_eval_raw(&request("stderr-flood", src))
        .expect("PARENT MUST SURVIVE the print flood");
    let elapsed = start.elapsed();
    assert_eq!(
        out_str(&r, "marker"),
        "survived-flood",
        "a 40MiB stderr flood must not corrupt the run or the outcome"
    );
    assert!(
        matches!(r.status, RunStatus::Ok),
        "{:?}",
        r.status.describe()
    );
    assert!(
        elapsed < Duration::from_secs(9),
        "drain-to-discard must keep the child unblocked: {elapsed:?}"
    );
    eprintln!("[PASS] stderr flood capped+drained; wall={elapsed:?}");
}

// ── Wedged sink: a stderr nobody reads cannot outlive the deadline ──
#[test]
fn wedged_stderr_sink_cannot_outlive_the_containment_deadline() {
    let _serial = FD2.lock().unwrap_or_else(|e| e.into_inner());
    // A pipe nobody ever reads: any write past its buffer blocks forever.
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe() failed");
    let _guard = Fd2Guard::hijack(fds[1]);
    unsafe { libc::close(fds[1]) };
    // fds[0] stays open and unread for the whole test — the wedge.

    // ~80 KiB of print(): more than one pipe buffer, so the forwarder
    // genuinely wedges in write_all, but under the combined child-pipe +
    // sink-pipe budget, so the child still finishes and reports cleanly
    // instead of being deadline-killed.
    let src = r#"
for i = 1, 640 do
  print(string.rep("w", 128))
end
return { marker = "clean-exit", name = "x", version = "1" }
"#;
    let start = Instant::now();
    let r = isolate::run_eval_raw(&request("wedged-sink", src))
        .expect("PARENT MUST SURVIVE a wedged stderr sink");
    let elapsed = start.elapsed();

    // The child finished and reported: the forwarder's drain kept its
    // stderr pipe empty the whole time.
    assert_eq!(
        out_str(&r, "marker"),
        "clean-exit",
        "the child must complete normally even with a wedged sink"
    );
    assert!(
        matches!(r.status, RunStatus::Ok),
        "{:?}",
        r.status.describe()
    );
    // The forwarder was (or soon became) wedged on the unread sink; the
    // parent must still return, bounded by the containment deadline.
    assert!(
        elapsed < isolate::WALL_DEADLINE + Duration::from_secs(2),
        "a wedged stderr sink must not hold the parent past the \
         containment deadline: {elapsed:?}"
    );

    // Prove the forwarder really wrote into the wedge before blocking.
    unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
    let mut total = 0usize;
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    unsafe { libc::close(fds[0]) };
    assert!(
        total >= 16 * 1024,
        "the forwarder must have filled the unread sink before wedging: \
         only {total} bytes landed"
    );
    eprintln!("[PASS] wedged sink detached in time; wall={elapsed:?}, sunk={total}B");
}
