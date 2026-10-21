use super::*;

/// Selects the probe mode in the re-exec'd child: "plain" (no
/// sandbox) or "sandbox" (Luau VM sandbox mode on).
const MEM_LIMIT_PROBE_ENV: &str = "NAU_MEM_LIMIT_PROBE";
/// Small enough to fail fast, large enough to hold the VM's own
/// baseline allocations.
const PROBE_MEMORY_LIMIT: usize = 32 * 1024 * 1024;
/// Allocate past the cap with the collector stopped: the hostile shape
/// is a chart that stops the GC and then blows the cap.
const PROBE_ALLOC_CHUNK: &str = r#"
        local t = {}
        local i = 1
        while true do
            t[i] = string.rep("x", 1024 * 1024)
            i = i + 1
        end
    "#;

fn resolver_with_root(dir: &std::path::Path) -> SourceResolver {
    SourceResolver {
        roots: vec![dir.canonicalize().unwrap()],
    }
}

/// Build a versions-mode request evaluating `entry` through the full
/// in-process worker VM (prelude, narrowed stdlib, IPC require).
fn versions_worker(entry: &str) -> WorkerOk {
    let req = EvalRequest {
        prelude: crate::dsl::prelude(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: Default::default(),
        entry: entry.to_string(),
        entry_label: "versions-test".into(),
        allow_fetch: false,
        constraint: None,
        versions_mode: true,
    };
    match run_worker(&req) {
        WorkerOutcome::Ok(ok) => ok,
        WorkerOutcome::Err(e) => panic!("worker failed: {}", e.diagnostics.join("; ")),
    }
}

/// A sink that always fails, like a closed parent stderr.
struct DeadSink;
impl Write for DeadSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(libc::EPIPE))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink that never accepts a byte: the wedged-sink scenario.
struct WedgedSink;
impl Write for WedgedSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        std::thread::park(); // never woken
        unreachable!("park without a token never returns")
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

mod versions_mode;
mod vm_memory;
