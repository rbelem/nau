//! Subprocess eval bounding (ADR-0010 Decisions 4+5, ported from the Nickel
//! spike `spike/src/isolate.rs`).
//!
//! Untrusted definitions never evaluate in-process: the parent spawns a
//! short-lived worker (`nau chart eval-worker`, the revealed ADR-0049
//! spelling of the hidden `__eval-worker` alias), ships ALL eval inputs
//! (prelude, index data, pre-seeded sources, the entry source) as one JSON
//! request on the child's stdin, and serves `require()` requests from
//! allowlisted roots. The child sets rlimits before eval, runs Luau with a
//! narrowed stdlib (no `os`, no `debug`, no filesystem `package`), and
//! replies with a single JSON outcome line. The child's cwd is an empty
//! temp dir and it opens no project files.
//!
//! The parent is the import-policy authority: it resolves `require()` names
//! only from allowlisted roots and rejects everything else before the source
//! ever crosses the boundary.
//!
//! The strict-analyzer stage of `nau check` runs the same way: the
//! parent spawns `nau chart check-worker` (the revealed spelling of
//! `__check-worker`), ships the definition plus every
//! parent-resolved module source as one JSON request, and reads one JSON
//! diagnostics array back. The analyzer never runs on untrusted sources
//! in-process; timeouts (wall-clock kill or the in-worker analyzer bound)
//! reach the caller as a single fail-closed diagnostic.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const WALL_DEADLINE: Duration = Duration::from_secs(5);
const RLIMIT_AS_BYTES: u64 = 512 * 1024 * 1024;
const RLIMIT_CPU_SECS: u64 = 5;
/// VM-level memory limit: the Luau "not enough memory" error must be able to
/// fire before RLIMIT_AS kills the process, so the cap sits 128MB BELOW
/// RLIMIT_AS (512MB). At equality the Rust/C++ base memory plus a full VM
/// heap tripped the rlimit first and the clean-VM-error path was dead code.
const VM_MEMORY_LIMIT: usize = 384 * 1024 * 1024;
/// Max nesting depth accepted when serializing outputs to JSON.
const MAX_JSON_DEPTH: usize = 128;
/// Module names at or over PATH_MAX can never resolve on Linux; capping the
/// check keeps a hostile giant `require()` name from burning unbounded
/// parent CPU/memory per request. (The wall-clock deadline bounds the child,
/// not the parent's per-request resolve work.)
const MAX_MODULE_NAME_LEN: usize = 4096;
/// Max bytes of worker stderr the parent forwards to its own stderr.
///
/// Worker `print()` output is untrusted: without a cap, a definition looping
/// on print() makes the parent forward an unbounded stream (syscall
/// amplification, and a forwarder thread that lives as long as the sink
/// keeps draining). Past the cap the forwarder keeps DRAINING the pipe to
/// EOF and discards — it must never stop reading, because a full stderr
/// pipe would stall the child mid-record, which is exactly what piping
/// stderr exists to prevent (see [`forward_worker_stderr`]).
const MAX_FORWARDED_STDERR_BYTES: u64 = 1024 * 1024;
/// Versions-mode cap (ADR-0052 Decision 1): a listing longer than this is
/// an error, never a truncation — a silently-clipped listing is worse than
/// a named refusal.
const MAX_VERSIONS_ENTRIES: usize = 1000;
/// Versions-mode cap on one version string, in bytes.
const MAX_VERSIONS_LEN: usize = 128;

// ── Protocol types (newline-delimited JSON on the child's stdio) ──

/// Parent → child: the complete eval input set. One line on the child's stdin.
#[derive(Serialize, Deserialize, Debug)]
pub struct EvalRequest {
    /// DSL prelude source (evaluated before the entry source).
    pub prelude: String,
    /// The package index as JSON (`index()` is backed by this, not the fs).
    pub index_data: Value,
    /// Architecture for `index()` pin lookups.
    pub arch: String,
    /// Modules pre-seeded into the require cache (no IPC needed to load).
    pub sources: BTreeMap<String, String>,
    /// The definition source to evaluate.
    pub entry: String,
    /// Display name of the definition (chunk name / diagnostic context).
    pub entry_label: String,
    /// Whether the `fetch()` global may reach the network. Opt-in: the
    /// normal eval path enables it (definitions may resolve floating
    /// upstream versions, e.g. opencode-bin); hermetic contexts
    /// (attack-isolation tests, `--offline`) leave it off and `fetch()`
    /// refuses with a named error. Deliberately non-deterministic — that
    /// is its purpose; reproducibility stays the source pin's job.
    #[serde(default)]
    pub allow_fetch: bool,
    /// The version line a pod spec selected, exposed to the recipe as the
    /// `constraint` global (nil when unconstrained) — ADR-0047 Decision 4:
    /// `@constraint` graduates from pod-package filter to recipe-selection
    /// input. Version-lined recipes (node.lua) read it to pick their
    /// `lines` entry; selection must stay reproducible from the lockfile
    /// pin, so it rides the eval like every other input — never a network
    /// read (`fetch()` at selection is banned by the ADR).
    #[serde(default)]
    pub constraint: Option<String>,
    /// Versions-mode (ADR-0052 Decision 1): after the chunk evaluates,
    /// each snap output's `versions()` function is called IN-PROCESS and
    /// the listings come back alongside the resolved versions. Functions
    /// cannot cross the worker's JSON output boundary — that is the whole
    /// reason this mode exists. Normal eval leaves it false and never
    /// calls the listing (listing-only: it never feeds build resolution).
    #[serde(default)]
    pub versions_mode: bool,
}

/// Child → parent: request for one require-able source.
#[derive(Serialize, Deserialize)]
#[serde(tag = "req")]
enum ChildRequest {
    Source { name: String },
}

/// Parent → child: the complete strict-analyzer input set for one
/// definition (`__check-worker`, the analyzer-stage twin of
/// [`EvalRequest`]). One line on the child's stdin; the child opens no
/// files — every required module's source is pre-resolved by the parent and
/// shipped in `sources`.
#[derive(Serialize, Deserialize, Debug)]
pub struct CheckRequest {
    /// Display name of the definition (chunk name / diagnostic context).
    pub label: String,
    /// The definition source to type-check.
    pub entry: String,
    /// Modules pre-resolved by the parent (require() visibility in the
    /// analyzer; same allowlisted-root policy as the eval resolver).
    pub sources: BTreeMap<String, String>,
    /// Per-module analyzer bound in seconds handed to upstream's
    /// `moduleTimeLimitSec`. Production always sends
    /// [`crate::analysis::ANALYZER_TIME_LIMIT_SECS`]; `None` means no
    /// in-worker bound (the parent's wall-clock killer still bounds the
    /// child). `Some(0.0)` expires immediately — the deterministic hook
    /// tests use.
    pub time_limit_secs: Option<f64>,
}

/// Parent → child: reply to a source request.
#[derive(Serialize, Deserialize)]
struct ParentReply {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Child → parent: successful eval result.
#[derive(Serialize, Deserialize, Debug)]
pub struct WorkerOk {
    /// Eval result table, each output serialized to JSON.
    pub outputs: BTreeMap<String, Value>,
    /// The global `inputs` table, serialized to JSON.
    pub global_inputs: Value,
    /// The global `workers` table, serialized to JSON. Shape validation
    /// happens in the parent's re-extraction, so both eval paths share
    /// one parser (the `inputs` precedent).
    #[serde(default = "serde_json::Value::default")]
    pub workers: Value,
    /// The global `servers` table (ADR-0052 Decision 6), serialized to
    /// JSON. Shape validation happens in the parent's re-extraction —
    /// the `workers` precedent, byte-identical outcome line when absent.
    #[serde(default = "serde_json::Value::default")]
    pub servers: Value,
    /// Warn-and-continue diagnostics (per-output extraction skips).
    pub diagnostics: Vec<String>,
    /// Per-output upstream version listings (ADR-0052 Decision 1),
    /// populated only in versions-mode. Skipped from serialization when
    /// empty so a normal eval's outcome line stays byte-identical.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub versions: BTreeMap<String, VersionListing>,
    /// Output keys whose snap table declared a `versions` function,
    /// recorded in EVERY mode (the listing itself is versions-mode-only;
    /// `nau lint`'s missing-versions check needs the declaration fact).
    /// Skipped from serialization when empty for the same byte-identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions_declared: Vec<String>,
}

/// One output's upstream version listing (ADR-0052 Decision 1):
/// `resolved` is the snap's own `version`, `versions` the listing its
/// `versions()` returned — `None` when the output has no such method.
/// A listing that failed to produce a valid answer (raise, wrong shape,
/// cap breach) carries `error` and `versions: None`; extraction never
/// aborts the eval for it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionListing {
    pub resolved: String,
    pub versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Child → parent: failed eval with diagnostics.
#[derive(Serialize, Deserialize, Debug)]
pub struct WorkerErr {
    pub diagnostics: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum WorkerOutcome {
    Ok(WorkerOk),
    Err(WorkerErr),
}

// ── Parent-side status ──

pub enum RunStatus {
    Ok,
    TimedOut,
    Signalled(String),
    Exit(i32),
    BrokenPipe(String),
}

impl RunStatus {
    pub fn describe(&self) -> String {
        match self {
            RunStatus::Ok => "ok".into(),
            RunStatus::TimedOut => "killed by parent wall-clock deadline".into(),
            RunStatus::Signalled(s) => format!("signalled: {s}"),
            RunStatus::Exit(c) => format!("exit {c}"),
            RunStatus::BrokenPipe(e) => format!("stdio broken: {e}"),
        }
    }
}

/// Full parent-side result of one isolated run (used by tests for
/// containment measurements).
pub struct EvalRun {
    pub status: RunStatus,
    pub wall_ms: f64,
    pub max_rss_kb: u64,
    pub outcome: Option<WorkerOutcome>,
}

// ── Resolver: the parent-side import-policy point ──

/// Resolves `require()` module names for the eval worker from allowlisted
/// roots only. Anything else — absolute paths, `..` traversal, files outside
/// the roots — is rejected before the source crosses the boundary.
pub struct SourceResolver {
    roots: Vec<PathBuf>,
}

impl SourceResolver {
    /// Roots for a build: the entry definition's own directory (the composable
    /// `require("template")` case), the project `pkgs/` dir, and the
    /// already-resolved input cache dirs.
    pub fn for_build(entry_label: &str) -> Self {
        let mut roots = Vec::new();
        let mut push_root = |p: PathBuf| {
            if let Ok(canon) = p.canonicalize() {
                if !roots.contains(&canon) {
                    roots.push(canon);
                }
            }
        };
        if let Some(parent) = std::path::Path::new(entry_label).parent() {
            push_root(parent.to_path_buf());
            // The entry's enclosing `pkgs` tree: charts require shared
            // modules from the tree root (`lib/cli`, `lib/daemon` —
            // ADR-0032). The CWD-derived root below misses every caller
            // whose cwd is not the recipes root (the farm drain's cwd is
            // the farm dir, not the repo), so anchor the tree on the
            // entry itself. Containment unchanged: the surface is still
            // this entry's own project tree, never an ambient dir.
            let mut dir: &std::path::Path = parent;
            loop {
                if dir.file_name().map(|n| n == "pkgs").unwrap_or(false) {
                    push_root(dir.to_path_buf());
                    break;
                }
                match dir.parent() {
                    Some(d) if d != dir => dir = d,
                    _ => break,
                }
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            push_root(cwd.join("pkgs"));
        }
        for dir in crate::pkg_source::resolver_roots() {
            push_root(dir.join("pkgs"));
            push_root(dir);
        }
        SourceResolver { roots }
    }

    /// Resolve a module name to source content, enforcing the allowlist.
    /// Errors are strings because they cross the pipe as JSON.
    pub fn resolve(&self, name: &str) -> Result<String, String> {
        match self.lookup(name) {
            Ok(src) => Ok(src),
            // ADR-0032 spelling: `require("pkgs.lib.daemon")` names the
            // module an allowlisted `pkgs/` root serves as `lib.daemon`
            // (the root IS the pkgs dir; the unaliased dotted spelling
            // would double it to pkgs/pkgs/lib/…). Aliased as a FALLBACK
            // only, so entry-relative roots that really do contain a
            // `pkgs/` subtree keep resolving first (issue #109).
            Err(e) if name.starts_with("pkgs.") => {
                let alias = name.strip_prefix("pkgs.").unwrap_or(name);
                self.lookup(alias).map_err(|_| e)
            }
            Err(e) => Err(e),
        }
    }

    /// The allowlist-enforcing lookup proper: every check on `name`
    /// (size, absolute, traversal, dot-to-slash synthesis) applies to
    /// the aliased spelling too, because [`Self::resolve`] delegates
    /// here.
    fn lookup(&self, name: &str) -> Result<String, String> {
        if name.is_empty() {
            return Err("resolver: rejected empty module name".into());
        }
        if name.len() > MAX_MODULE_NAME_LEN {
            return Err(format!(
                "resolver: rejected oversized module name ({} bytes): outside allowlisted roots",
                name.len()
            ));
        }
        if name.starts_with('/') {
            return Err(format!(
                "resolver: rejected absolute path {name:?}: outside allowlisted roots"
            ));
        }
        if name.split('/').any(|seg| seg == "..") {
            return Err(format!(
                "resolver: rejected traversal path {name:?}: outside allowlisted roots"
            ));
        }
        let rel = name.replace('.', "/");
        // The mapping must stay relative: `root.join` replaces its base with
        // an absolute segment, so a name whose dot-to-slash result begins
        // with '/' (e.g. "...." → "////") synthesizes an absolute candidate.
        // Reject with the same named error as the explicit '/' check instead
        // of relying on the downstream canonicalize+prefix check.
        if rel.starts_with('/') {
            return Err(format!(
                "resolver: rejected absolute path {name:?}: outside allowlisted roots"
            ));
        }
        for root in &self.roots {
            for cand in [
                root.join(format!("{rel}.lua")),
                root.join(&rel).join("init.lua"),
            ] {
                // Canonicalize defuses symlinks; the prefix check keeps the
                // resolved path inside the root even then.
                let Ok(canon) = cand.canonicalize() else {
                    continue;
                };
                if !canon.starts_with(root) {
                    continue;
                }
                if let Ok(src) = std::fs::read_to_string(&canon) {
                    return Ok(src);
                }
            }
        }
        Err(format!(
            "resolver: source {name:?} not found in allowlisted roots"
        ))
    }
}

// ── Worker executable discovery ──

/// Path of the binary to re-exec as the eval worker. Production re-executes
/// itself (`current_exe`); integration tests get the real nau binary via
/// cargo's `CARGO_BIN_EXE_nau`. No env override and no PATH fallback:
/// anything able to influence the parent's env/PATH must not get to choose
/// which binary receives the eval request.
pub fn worker_exe() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_nau") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::current_exe().expect("failed to locate the nau binary (current_exe)")
}

// ── Parent side ──

fn write_line<W: Write>(w: &mut W, v: &impl Serialize) -> std::io::Result<()> {
    let mut s = serde_json::to_string(v).map_err(std::io::Error::other)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Max bytes accepted for ONE protocol line from the child. Legit traffic is
/// tiny (a require name, an eval outcome); refusing over-long lines keeps a
/// hostile child from making the parent buffer/parse up to its own 512MB
/// address-space cap per line.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Read one newline-terminated line, refusing lines over `cap` bytes.
/// `Ok(None)` = clean EOF with no pending bytes.
fn read_line_capped<R: BufRead>(r: &mut R, cap: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            break;
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                buf.extend_from_slice(&available[..pos]);
                r.consume(pos + 1);
                return Ok(Some(buf));
            }
            None => {
                let len = available.len();
                buf.extend_from_slice(available);
                r.consume(len);
            }
        }
        if buf.len() > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "protocol line too long",
            ));
        }
    }
    if buf.is_empty() {
        Ok(None)
    } else {
        Ok(Some(buf))
    }
}

/// Spawn the worker, ship the request, serve require requests, enforce the
/// wall-clock deadline. The parent survives every child death and returns a
/// clean error instead.
pub fn run_eval(req: &EvalRequest) -> miette::Result<WorkerOk> {
    let run = run_eval_raw(req)?;
    match run.outcome {
        Some(WorkerOutcome::Ok(ok)) => Ok(ok),
        Some(WorkerOutcome::Err(err)) => Err(miette::miette!(
            "{}: {}",
            req.entry_label,
            err.diagnostics.join("; ")
        )),
        None => Err(miette::miette!(
            "{}: eval worker failed: {}",
            req.entry_label,
            run.status.describe()
        )),
    }
}

/// Drain a worker's stderr on a background thread, forwarding it to the
/// parent's own stderr. Returns a one-shot completion receiver — NOT a join
/// handle; the parent must never wait unconditionally on this thread (see
/// [`wait_stderr_forwarder`]).
///
/// The worker runs with `RLIMIT_FSIZE = 0` ([`set_rlimits`]) because it must
/// never write to a regular file, and `print()` is routed to stderr so it
/// cannot corrupt the stdout protocol channel. Inheriting the parent's stderr
/// makes those two rules collide: the child's fd is then whatever the caller
/// had, and a caller that redirected its own stderr into a log file — an
/// ordinary `nau build > build.log 2>&1`, or `devbox run -- check > log` —
/// turns the child's first `print()` into an immediate `SIGXFSZ` (signal 25)
/// death, before it can report any outcome. Piping the child's stderr
/// decouples the child's fd kind from the caller's environment; this forwarder
/// preserves the output for the user.
///
/// Two bounds keep the forwarder from becoming a containment leak of its own
/// (issue #76):
///
/// * At most [`MAX_FORWARDED_STDERR_BYTES`] are forwarded ([`forward_capped`]);
///   past the cap the pipe is still drained to EOF, only discarded.
/// * The parent waits for completion only until the containment deadline. A
///   stderr sink that stops draining (`nau build 2>&1 | stalled-reader`)
///   would otherwise wedge `write_all` forever and hold the parent past the
///   wall-clock deadline that exists to bound the run.
///
/// Call after `spawn` and before the parent blocks reading stdout: a full
/// stderr pipe buffer would otherwise stall the child mid-record.
fn forward_worker_stderr(child: &mut std::process::Child) -> std::sync::mpsc::Receiver<()> {
    let mut src = child.stderr.take().expect("child stderr is piped");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut dst = std::io::stderr();
        forward_capped(&mut src, &mut dst, MAX_FORWARDED_STDERR_BYTES);
        // The parent waits on this with a timeout; if it has already given
        // up on the wedged forwarder, a dropped receiver is fine.
        let _ = done_tx.send(());
    });
    done_rx
}

/// Copy at most `cap` bytes from `src` to `dst`, then keep reading to EOF
/// and discard. Never stops reading early: the child's stderr pipe must
/// keep emptying, or the child stalls mid-record with a full pipe.
///
/// A sink that stops draining blocks in `write_all` HERE — but in aggregate
/// at most `cap` bytes are ever written, and the parent bounds the wait with
/// [`wait_stderr_forwarder`]. A write error (closed parent stderr, say)
/// switches the rest of the stream to discard: the child's output handling
/// must never be the thing that blocks the child.
fn forward_capped(src: &mut dyn Read, dst: &mut dyn Write, cap: u64) {
    let mut buf = [0u8; 8192];
    let mut forwarded = 0u64;
    let mut sink_ok = true;
    loop {
        match src.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if sink_ok && forwarded < cap {
                    let take = n.min((cap - forwarded) as usize);
                    if dst.write_all(&buf[..take]).is_err() {
                        sink_ok = false;
                    }
                    forwarded += take as u64;
                }
                // Past the cap, or the sink died: drain and discard.
            }
            Err(_) => return,
        }
    }
}

/// Wait for the stderr forwarder to finish, but never past `deadline`.
///
/// Normally the forwarder reaches EOF the instant the child is reaped (its
/// stderr write end closes with the process). The one wedge that survives
/// child reaping is a parent stderr sink that stopped draining: the
/// forwarder then sits in `write_all` forever, and joining it
/// unconditionally would let a stuck reader hold the parent past the
/// wall-clock deadline that exists to bound the whole run. On timeout the
/// thread is left detached — it cannot block the parent, and the capped
/// forward loop keeps its footprint to one bounded pipe buffer.
fn wait_stderr_forwarder(done: &std::sync::mpsc::Receiver<()>, deadline: Instant) {
    let now = Instant::now();
    if now < deadline {
        let _ = done.recv_timeout(deadline - now);
    }
}

/// Like [`run_eval`] but returns the full run (status, wall time, peak RSS)
/// for containment evidence and tests.
pub fn run_eval_raw(req: &EvalRequest) -> miette::Result<EvalRun> {
    let start = Instant::now();
    // cwd is an empty scratch dir: even if something escaped the require
    // override, relative file access would find nothing here.
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create eval scratch dir: {e}"))?;
    let mut child = Command::new(worker_exe())
        // The revealed spelling (ADR-0049, #321). Discovery stays
        // current_exe() self-re-exec — no env override, no PATH fallback
        // (ADR-0010). The hidden `__eval-worker` alias keeps parsing for
        // one migration window.
        .arg("chart")
        .arg("eval-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(scratch.path())
        .spawn()
        .map_err(|e| {
            miette::miette!(
                "failed to spawn eval worker at '{}': {e}",
                worker_exe().display()
            )
        })?;
    let pid = child.id();

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr_forwarder = forward_worker_stderr(&mut child);

    if let Err(e) = write_line(&mut stdin, req) {
        // Reap the child so a failed ship can't leave a zombie behind.
        let _ = child.kill();
        let _ = child.wait();
        wait_stderr_forwarder(&stderr_forwarder, start + WALL_DEADLINE);
        return Err(miette::miette!(
            "failed to ship eval request to worker: {e}"
        ));
    }

    // Wall-clock enforcer: the only real termination bound.
    let killer_child = Arc::new(Mutex::new(child));
    let killer = {
        let killer_child = Arc::clone(&killer_child);
        std::thread::spawn(move || {
            let deadline = Instant::now() + WALL_DEADLINE;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    if let Ok(mut c) = killer_child.lock() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    break;
                }
                if let Ok(mut c) = killer_child.lock() {
                    if c.try_wait().ok().flatten().is_some() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20).min(deadline - now));
            }
        })
    };

    // RSS sampler for containment evidence.
    let rss_child = {
        let killer_child = Arc::clone(&killer_child);
        std::thread::spawn(move || {
            let mut max = 0u64;
            loop {
                if let Ok(mut c) = killer_child.lock() {
                    if c.try_wait().ok().flatten().is_some() {
                        break;
                    }
                }
                let status =
                    std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                for line in status.lines() {
                    if let Some(kb) = line.strip_prefix("VmHWM:") {
                        let kb: u64 = kb
                            .trim()
                            .trim_end_matches(" kB")
                            .trim()
                            .parse()
                            .unwrap_or(0);
                        max = max.max(kb);
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            max
        })
    };

    // Serve requests until the outcome line or EOF.
    let resolver = SourceResolver::for_build(&req.entry_label);
    let mut outcome = None;
    let mut status = RunStatus::Ok;
    {
        let mut reader = BufReader::new(stdout);
        loop {
            let line = match read_line_capped(&mut reader, MAX_LINE_BYTES) {
                Ok(Some(line)) => line,
                // Clean EOF: no status here — fall through to the exit-status
                // classification below (exit code / signal / wall-clock).
                Ok(None) => break,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    status = RunStatus::BrokenPipe(
                        "protocol violation: eval worker sent an over-long line".into(),
                    );
                    break;
                }
                Err(_) => {
                    status = RunStatus::BrokenPipe("read failed (child died mid-request?)".into());
                    break;
                }
            };
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(child_req) = serde_json::from_str::<ChildRequest>(line) {
                let ChildRequest::Source { name } = child_req;
                let reply = match resolver.resolve(&name) {
                    Ok(content) => ParentReply {
                        ok: true,
                        content: Some(content),
                        error: None,
                    },
                    Err(e) => ParentReply {
                        ok: false,
                        content: None,
                        error: Some(e),
                    },
                };
                if write_line(&mut stdin, &reply).is_err() {
                    status = RunStatus::BrokenPipe("write failed (child died mid-request)".into());
                    break;
                }
                continue;
            }
            if let Ok(oc) = serde_json::from_str::<WorkerOutcome>(line) {
                outcome = Some(oc);
                break;
            }
            status =
                RunStatus::BrokenPipe(format!("unexpected line from eval worker: {:.120}", line));
            break;
        }
    }
    drop(stdin);

    if outcome.is_none() && matches!(status, RunStatus::Ok) {
        let mut c = killer_child
            .lock()
            .map_err(|_| miette::miette!("eval worker bookkeeping failed (mutex poisoned)"))?;
        match c.wait() {
            Ok(st) if st.code().is_some() => status = RunStatus::Exit(st.code().unwrap()),
            Ok(st) => {
                use std::os::unix::process::ExitStatusExt as _;
                let sig = st
                    .signal()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".into());
                status = if start.elapsed() >= WALL_DEADLINE - Duration::from_millis(200) {
                    RunStatus::TimedOut
                } else {
                    RunStatus::Signalled(format!(
                        "signal {sig} before deadline (child died on its own)"
                    ))
                };
            }
            Err(e) => status = RunStatus::BrokenPipe(format!("wait: {e}")),
        }
    }
    let max_rss_kb = rss_child.join().unwrap_or(0);
    killer.join().unwrap_or(());
    // The child is reaped, so its stderr write end is closed and the
    // forwarder has normally reached EOF. A stderr sink that stopped
    // draining can still hold it in write_all forever — bound the wait by
    // the containment deadline and detach past it (issue #76).
    wait_stderr_forwarder(&stderr_forwarder, start + WALL_DEADLINE);

    // A child death at/after the deadline IS the timeout, whatever the pipe
    // reported first: the wall-clock SIGKILL closes the pipe, so the reader can
    // observe EOF/BrokenPipe before the deadline classification runs. Deadline
    // evidence beats pipe evidence (same 200ms margin as the signal path above).
    if outcome.is_none()
        && !matches!(status, RunStatus::Ok)
        && start.elapsed() >= WALL_DEADLINE - Duration::from_millis(200)
    {
        status = RunStatus::TimedOut;
    }

    if matches!(status, RunStatus::Ok) && outcome.is_none() {
        status = RunStatus::BrokenPipe("child produced no outcome".into());
    }

    Ok(EvalRun {
        status,
        wall_ms: start.elapsed().as_secs_f64() * 1000.0,
        max_rss_kb,
        outcome,
    })
}

// ── Child side ──

/// Worker stdlib mask (ADR-0010 Decision 4): base/string/table/math/bit32/utf8
/// plus coroutine. `OS` and `DEBUG` excluded (determinism — no os.time/clock),
/// and `PACKAGE` excluded so mlua never installs its filesystem `require` /
/// `package` table in the first place.
fn worker_stdlib() -> mlua::StdLib {
    mlua::StdLib::COROUTINE
        | mlua::StdLib::TABLE
        | mlua::StdLib::STRING
        | mlua::StdLib::UTF8
        | mlua::StdLib::BIT
        | mlua::StdLib::MATH
}

fn set_rlimits(cpu_secs: u64) -> Result<(), String> {
    use libc::{rlimit, setrlimit, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE};
    let mem = rlimit {
        rlim_cur: RLIMIT_AS_BYTES,
        rlim_max: RLIMIT_AS_BYTES,
    };
    let cpu = rlimit {
        rlim_cur: cpu_secs,
        rlim_max: cpu_secs,
    };
    let fsize = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let nofile = rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    // Applied in the child before eval — process bounds are the real guarantee.
    unsafe {
        if setrlimit(RLIMIT_AS, &mem) != 0 {
            return Err("setrlimit(RLIMIT_AS) failed".into());
        }
        if setrlimit(RLIMIT_CPU, &cpu) != 0 {
            return Err("setrlimit(RLIMIT_CPU) failed".into());
        }
        if setrlimit(RLIMIT_FSIZE, &fsize) != 0 {
            return Err("setrlimit(RLIMIT_FSIZE) failed".into());
        }
        if setrlimit(RLIMIT_NOFILE, &nofile) != 0 {
            return Err("setrlimit(RLIMIT_NOFILE) failed".into());
        }
    }
    Ok(())
}

/// Child → parent: ask for one source over the newline-JSON channel.
fn request_source(name: &str) -> mlua::Result<String> {
    let req = serde_json::json!({ "req": "Source", "name": name });
    {
        let mut out = std::io::stdout().lock();
        write_line(&mut out, &req)
            .map_err(|e| mlua::Error::runtime(format!("require {name:?}: ipc write: {e}")))?;
    }
    let mut line = String::new();
    {
        let mut inp = std::io::stdin().lock();
        inp.read_line(&mut line)
            .map_err(|e| mlua::Error::runtime(format!("require {name:?}: ipc read: {e}")))?;
    }
    if line.is_empty() {
        return Err(mlua::Error::runtime(format!(
            "require {name:?}: parent closed the pipe"
        )));
    }
    let reply: ParentReply = serde_json::from_str(line.trim())
        .map_err(|e| mlua::Error::runtime(format!("require {name:?}: bad parent reply: {e}")))?;
    if reply.ok {
        Ok(reply.content.unwrap_or_default())
    } else {
        Err(mlua::Error::runtime(reply.error.unwrap_or_else(|| {
            format!("require {name:?}: refused by parent")
        })))
    }
}

/// Install the IPC-backed `require` and pre-seed the module cache.
///
/// The `PACKAGE` stdlib bit is off, so mlua's filesystem `require` was never
/// installed — the only `require` in this VM is ours: it either hits the
/// pre-seeded cache or asks the parent (which enforces the root allowlist).
fn install_require(lua: &mlua::Lua, sources: &BTreeMap<String, String>) -> miette::Result<()> {
    // mlua::Value is !Send (no "send" feature) → Rc, not Arc. Borrows are
    // always scoped: the loading set must NOT be held across load_module,
    // or a nested require would self-deadlock.
    let loaded: Rc<RefCell<HashMap<String, mlua::Value>>> = Rc::new(RefCell::new(HashMap::new()));
    let loading: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));

    preseed_sources(lua, sources, &loaded)?;

    let loaded_fn = Rc::clone(&loaded);
    let loading_fn = Rc::clone(&loading);
    let require_fn = lua
        .create_function(move |lua, name: String| -> mlua::Result<mlua::Value> {
            if let Some(v) = loaded_fn.borrow().get(&name) {
                return Ok(v.clone());
            }
            let is_cycle = !loading_fn.borrow_mut().insert(name.clone());
            if is_cycle {
                return Err(mlua::Error::runtime(format!(
                    "circular require of {name:?}"
                )));
            }
            let result = load_module(lua, &name, &loaded_fn);
            loading_fn.borrow_mut().remove(&name);
            result
        })
        .map_err(|e| miette::miette!("failed to create require(): {e}"))?;

    lua.globals()
        .set("require", require_fn)
        .map_err(|e| miette::miette!("failed to install require(): {e}"))
}

/// Compile + execute pre-seeded sources into the module cache.
fn preseed_sources(
    lua: &mlua::Lua,
    sources: &BTreeMap<String, String>,
    loaded: &RefCell<HashMap<String, mlua::Value>>,
) -> miette::Result<()> {
    for (name, content) in sources {
        let func = lua
            .load(content.as_str())
            .set_name(format!("={name}"))
            .into_function()
            .map_err(|e| miette::miette!("preloaded source {name:?}: {e}"))?;
        let v: mlua::Value = func
            .call(())
            .map_err(|e| miette::miette!("preloaded source {name:?}: {e}"))?;
        loaded.borrow_mut().insert(name.clone(), v);
    }
    Ok(())
}

/// Fetch, compile, and run one module over IPC, caching the result.
fn load_module(
    lua: &mlua::Lua,
    name: &str,
    loaded: &RefCell<HashMap<String, mlua::Value>>,
) -> mlua::Result<mlua::Value> {
    let content = request_source(name)?;
    let func = lua
        .load(content.as_str())
        .set_name(format!("={name}"))
        .into_function()?;
    let v: mlua::Value = func.call(())?;
    loaded.borrow_mut().insert(name.to_string(), v.clone());
    Ok(v)
}

/// The child VM: narrowed stdlib, VM memory cap, DSL prelude, data-backed
/// `index()`, stderr `print`, IPC `require`.
fn build_worker_lua(req: &EvalRequest) -> miette::Result<mlua::Lua> {
    let lua = mlua::Lua::new_with(worker_stdlib(), mlua::LuaOptions::default())
        .map_err(|e| miette::miette!("failed to create worker Luau VM: {e}"))?;
    lua.set_memory_limit(VM_MEMORY_LIMIT)
        .map_err(|e| miette::miette!("failed to set VM memory limit: {e}"))?;

    // mlua 0.12 unconditionally injects `loadstring` into every Luau VM
    // (configure_luau; changelog "Added loadstring function to Luau") — an
    // arbitrary-code/bytecode escape hatch the worker must never expose
    // (ADR-0010: untrusted definitions get no loaders). Remove it before the
    // prelude runs so even init code can't reach it.
    lua.globals()
        .set("loadstring", mlua::Value::Nil)
        .map_err(|e| miette::miette!("failed to remove loadstring: {e}"))?;

    lua.load(req.prelude.as_str())
        .set_name("=init.lua".to_string())
        .exec()
        .map_err(|e| miette::miette!("failed to initialize nau DSL: {e}"))?;

    // index() backed by the shipped index data — no filesystem access.
    let index: crate::index::PackageIndex = serde_json::from_value(req.index_data.clone())
        .map_err(|e| miette::miette!("bad index data from parent: {e}"))?;
    let arch = req.arch.clone();
    let index_fn = lua
        .create_function(move |lua, name: String| {
            let entry = index.find_by_name_or_alias(&name).ok_or_else(|| {
                mlua::Error::external(miette::miette!("snap '{name}' not found in package index"))
            })?;
            crate::index::index_entry_to_lua_table(entry, &arch, lua)
        })
        .map_err(|e| miette::miette!("failed to create index(): {e}"))?;
    lua.globals()
        .set("index", index_fn)
        .map_err(|e| miette::miette!("failed to set index global: {e}"))?;

    // Definitions may call print(); the child's stdout is the IPC channel,
    // so route print to stderr. The parent pipes that stderr and forwards it
    // (see `forward_worker_stderr`): the child's stderr fd must NOT be an
    // inherited regular file, because `RLIMIT_FSIZE = 0` would make this
    // very call fatal (SIGXFSZ) instead of merely noisy.
    let print_fn = lua
        .create_function(|_, args: mlua::MultiValue| {
            let strs: Vec<String> = args
                .into_iter()
                .map(|v| match &v {
                    mlua::Value::String(s) => s.to_string_lossy(),
                    other => other.type_name().to_string(),
                })
                .collect();
            eprintln!("{}", strs.join("\t"));
            Ok(())
        })
        .map_err(|e| miette::miette!("failed to create print(): {e}"))?;
    lua.globals()
        .set("print", print_fn)
        .map_err(|e| miette::miette!("{e}"))?;

    // The MATH stdlib is loaded, but `math.random` is seeded from the wall
    // clock by the Luau VM — a manifest that calls it produces nondeterministic
    // recipe data that flows into cache keys. Remove both doors (ADR-0010
    // Decision 4 determinism; `os` is already excluded by the stdlib mask).
    if let Ok(math) = lua.globals().get::<mlua::Table>("math") {
        math.set("random", mlua::Value::Nil)
            .map_err(|e| miette::miette!("failed to remove math.random: {e}"))?;
        math.set("randomseed", mlua::Value::Nil)
            .map_err(|e| miette::miette!("failed to remove math.randomseed: {e}"))?;
    }

    install_require(&lua, &req.sources)?;

    // fetch(): one eval-time HTTP GET, for definitions that resolve a
    // floating upstream version (opencode-bin reads the v2 update API).
    // Always installed so disabled contexts fail with a named error
    // instead of "attempt to call a nil value". curl is already a hard
    // dependency (source downloads); the body crosses a pipe, so the
    // worker's RLIMIT_FSIZE=0 never applies to it, and the worker's
    // wall-clock deadline plus curl's --max-time bound the wait.
    let allow_fetch = req.allow_fetch;
    let fetch_fn = lua
        .create_function(move |_, url: String| -> mlua::Result<String> {
            if !allow_fetch {
                return Err(mlua::Error::runtime(
                    "fetch() is disabled for this eval (--offline or hermetic context)",
                ));
            }
            if !url.starts_with("https://") && !url.starts_with("http://") {
                return Err(mlua::Error::runtime(
                    "fetch(): only http(s) URLs are supported",
                ));
            }
            let curl = match nau_infra::tools::ensure(nau_infra::tools::ToolName::Curl) {
                Ok(resolved) => match resolved {
                    nau_infra::tools::ResolvedTool::Provisioned { path, .. }
                    | nau_infra::tools::ResolvedTool::Path { path, .. } => path,
                },
                Err(e) => return Err(mlua::Error::runtime(format!("fetch(): {e}"))),
            };
            let out = std::process::Command::new(&curl)
                .args(["-fsSL", "--max-time", "30", "--", &url])
                .output()
                .map_err(|e| mlua::Error::runtime(format!("fetch(): curl spawn failed: {e}")))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let tail = stderr.lines().last().unwrap_or("").trim().to_string();
                return Err(mlua::Error::runtime(format!(
                    "fetch(): curl failed for {url}: {tail}"
                )));
            }
            const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
            if out.stdout.len() > MAX_BODY_BYTES {
                return Err(mlua::Error::runtime(format!(
                    "fetch(): response from {url} exceeds the {MAX_BODY_BYTES}-byte cap"
                )));
            }
            String::from_utf8(out.stdout)
                .map_err(|_| mlua::Error::runtime("fetch(): response is not valid UTF-8"))
        })
        .map_err(|e| miette::miette!("failed to create fetch(): {e}"))?;
    lua.globals()
        .set("fetch", fetch_fn)
        .map_err(|e| miette::miette!("failed to set fetch global: {e}"))?;

    // The eval-context constraint (ADR-0047 Decision 4): the pod spec's
    // `@constraint`, exposed as a global the recipe reads for line
    // selection. Always set — nil when unconstrained — so a recipe can
    // distinguish "no constraint" from a constraint naming no line and
    // refuse the latter instead of silently pinning a default.
    lua.globals()
        .set("constraint", req.constraint.clone())
        .map_err(|e| miette::miette!("failed to set constraint global: {e}"))?;

    Ok(lua)
}

/// Extract the global `inputs` table to JSON, mirroring the in-process
/// `extract_inputs_from_lua` semantics (including error messages).
fn extract_inputs_json(lua: &mlua::Lua) -> Result<Value, String> {
    let value: mlua::Value = lua.globals().get("inputs").unwrap_or(mlua::Value::Nil);
    match value {
        mlua::Value::Nil => Ok(serde_json::json!({})),
        mlua::Value::Table(t) => {
            let mut map = serde_json::Map::new();
            for pair in t.pairs::<String, mlua::Value>() {
                let (name, val) = pair.map_err(|e| format!("inputs entry: {e}"))?;
                match val {
                    mlua::Value::Table(input_table) => {
                        let url: String = input_table
                            .get("url")
                            .map_err(|_| format!("inputs['{name}']: missing 'url'"))?;
                        let mut obj = serde_json::Map::new();
                        obj.insert("url".into(), Value::String(url));
                        // `submodules` (issue #43) rides through verbatim —
                        // shape validation happens in the parent's
                        // re-extraction, so both paths share one parser.
                        if let Ok(sub) = input_table.get::<mlua::Value>("submodules") {
                            if !matches!(sub, mlua::Value::Nil) {
                                let json = lua_to_json(&sub)
                                    .map_err(|e| format!("inputs['{name}'].submodules: {e}"))?;
                                obj.insert("submodules".into(), json);
                            }
                        }
                        map.insert(name, Value::Object(obj));
                    }
                    other => {
                        return Err(format!(
                            "inputs['{name}'] must be a table, got {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(Value::Object(map))
        }
        other => Err(format!(
            "'inputs' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Extract the global `workers` table to JSON, mirroring the in-process
/// `extract_workers_from_lua` semantics (including error messages). The
/// mixed shape (array part = worker entries, `local_jobs` hash key = the
/// coordinator's own slot count) rides through verbatim; shape
/// validation happens in the parent's re-extraction, so both eval paths
/// share one parser.
fn extract_workers_json(lua: &mlua::Lua) -> Result<Value, String> {
    let value: mlua::Value = lua.globals().get("workers").unwrap_or(mlua::Value::Nil);
    match value {
        mlua::Value::Nil => Ok(serde_json::json!([])),
        mlua::Value::Table(t) => lua_to_json(&mlua::Value::Table(t)),
        other => Err(format!(
            "'workers' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Extract the global `servers` table (ADR-0052 Decision 6) to JSON —
/// the `workers` twin: raw table rides through verbatim, shape
/// validation happens in the parent's re-extraction, and absence is an
/// empty array so a servers-less eval's outcome line stays unchanged.
fn extract_servers_json(lua: &mlua::Lua) -> Result<Value, String> {
    let value: mlua::Value = lua.globals().get("servers").unwrap_or(mlua::Value::Nil);
    match value {
        mlua::Value::Nil => Ok(serde_json::json!([])),
        mlua::Value::Table(t) => lua_to_json(&mlua::Value::Table(t)),
        other => Err(format!(
            "'servers' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Serialize an mlua value to JSON. Tables must be array-shaped (1..=n
/// integer keys) or string-keyed maps; functions/userdata and cycles are
/// errors (they become per-output "skipping" diagnostics).
pub fn lua_to_json(v: &mlua::Value) -> Result<Value, String> {
    fn table_entries(t: &mlua::Table) -> Result<Vec<(mlua::Value, mlua::Value)>, String> {
        let mut entries = Vec::new();
        for pair in t.pairs::<mlua::Value, mlua::Value>() {
            let (k, val) = pair.map_err(|e| e.to_string())?;
            match k {
                mlua::Value::String(_) | mlua::Value::Integer(_) => {}
                other => {
                    return Err(format!("unsupported table key type {}", other.type_name()));
                }
            }
            entries.push((k, val));
        }
        Ok(entries)
    }

    fn is_array(entries: &[(mlua::Value, mlua::Value)]) -> bool {
        !entries.is_empty()
            && entries
                .iter()
                .enumerate()
                .all(|(i, (k, _))| matches!(k, mlua::Value::Integer(n) if *n == i as i64 + 1))
    }

    fn go(v: &mlua::Value, depth: usize, seen: &[mlua::Value]) -> Result<Value, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("table nesting too deep".into());
        }
        match v {
            mlua::Value::Nil => Ok(Value::Null),
            mlua::Value::Boolean(b) => Ok(Value::Bool(*b)),
            mlua::Value::Integer(i) => Ok(Value::from(*i)),
            mlua::Value::Number(n) => serde_json::Number::from_f64(*n)
                .map(Value::Number)
                .ok_or_else(|| "non-finite number".into()),
            mlua::Value::String(s) => Ok(Value::String(s.to_string_lossy())),
            mlua::Value::Table(t) => {
                if seen.iter().any(|s| s == v) {
                    return Err("circular table reference".into());
                }
                let mut seen2 = seen.to_vec();
                seen2.push(v.clone());
                let entries = table_entries(t)?;
                if is_array(&entries) {
                    let mut arr = Vec::with_capacity(entries.len());
                    for (_, val) in &entries {
                        arr.push(go(val, depth + 1, &seen2)?);
                    }
                    Ok(Value::Array(arr))
                } else {
                    let mut map = serde_json::Map::new();
                    for (k, val) in &entries {
                        let key = match k {
                            mlua::Value::String(s) => s.to_string_lossy(),
                            mlua::Value::Integer(i) => i.to_string(),
                            _ => unreachable!("key type filtered by table_entries"),
                        };
                        map.insert(key, go(val, depth + 1, &seen2)?);
                    }
                    Ok(Value::Object(map))
                }
            }
            other => Err(format!("unsupported value type {}", other.type_name())),
        }
    }
    go(v, 0, &[])
}

/// Evaluate the request's entry source and build the outcome.
fn run_worker(req: &EvalRequest) -> WorkerOutcome {
    let fatal = |diags: Vec<String>| WorkerOutcome::Err(WorkerErr { diagnostics: diags });

    let lua = match build_worker_lua(req) {
        Ok(lua) => lua,
        Err(e) => return fatal(vec![e.to_string()]),
    };

    let result: mlua::Result<mlua::Value> = lua
        .load(req.entry.as_str())
        .set_name(req.entry_label.clone())
        .eval();
    let result = match result {
        Ok(v) => v,
        Err(e) => return fatal(vec![e.to_string()]),
    };

    let inputs = match extract_inputs_json(&lua) {
        Ok(v) => v,
        Err(e) => return fatal(vec![e.to_string()]),
    };

    let workers = match extract_workers_json(&lua) {
        Ok(v) => v,
        Err(e) => return fatal(vec![e.to_string()]),
    };

    let servers = match extract_servers_json(&lua) {
        Ok(v) => v,
        Err(e) => return fatal(vec![e.to_string()]),
    };

    let mlua::Value::Table(table) = &result else {
        return fatal(vec![format!(
            "must return a table of outputs, got {}",
            result.type_name()
        )]);
    };

    // Versions-mode (ADR-0052 Decision 1): call each snap output's
    // versions() BEFORE output serialization — functions cannot cross the
    // JSON boundary, which is exactly why this mode runs in the child.
    let versions = if req.versions_mode {
        extract_versions(table)
    } else {
        BTreeMap::new()
    };
    // Which outputs declare a versions function, in every mode: the
    // listing is versions-mode-only (listing-only, ADR-0052 — a plain
    // build must never call it), but the missing-versions lint needs the
    // declaration fact. Empty for every existing recipe, so the normal
    // mode's outcome line stays byte-identical.
    let versions_declared = versions_declared_keys(table);

    // Warn-and-continue: a broken output becomes a diagnostic, remaining
    // outputs keep flowing (ADR-0010 Decision 3, silent-drop fix).
    let mut outputs = BTreeMap::new();
    let mut diagnostics = Vec::new();
    for pair in table.pairs::<String, mlua::Value>() {
        let (key, value) = match pair {
            Ok(p) => p,
            Err(e) => {
                diagnostics.push(format!("skipping output from {}: {e}", req.entry_label));
                break;
            }
        };
        // A listing-only `versions` function cannot cross the JSON
        // boundary (lua_to_json rejects functions); strip it before
        // serialization. In versions-mode the listing was already
        // extracted above; in normal mode it is none of the build's
        // business. Today no shipped recipe declares the field, so this
        // strip changes no existing bytes — it only keeps a recipe that
        // ADDS the field from losing its whole output to a skip
        // diagnostic.
        if let mlua::Value::Table(t) = &value {
            if matches!(
                t.get::<mlua::Value>("versions"),
                Ok(mlua::Value::Function(_))
            ) {
                let _ = t.set("versions", mlua::Value::Nil);
            }
        }
        match lua_to_json(&value) {
            Ok(json) => {
                outputs.insert(key, json);
            }
            Err(e) => {
                diagnostics.push(format!(
                    "skipping output '{key}' from {}: {e}",
                    req.entry_label
                ));
            }
        }
    }

    WorkerOutcome::Ok(WorkerOk {
        outputs,
        global_inputs: inputs,
        workers,
        servers,
        diagnostics,
        versions,
        versions_declared,
    })
}

/// Versions-mode extraction (ADR-0052 Decision 1): walk the outputs
/// table and, for each snap output (`name` + `version` string fields)
/// carrying a `versions` function, call it error-bounded and enforce the
/// listing shape. The listing runs with fetch allowed as usual — a
/// listing may resolve its own upstream data. Failures (raise, wrong
/// shape, cap breach) land in `VersionListing.error`; extraction never
/// aborts the eval and never truncates a listing.
fn extract_versions(table: &mlua::Table) -> BTreeMap<String, VersionListing> {
    let mut out = BTreeMap::new();
    for pair in table.pairs::<String, mlua::Value>() {
        let (key, value) = match pair {
            Ok(p) => p,
            Err(_) => break, // same walk-abort as the serialization loop
        };
        let mlua::Value::Table(t) = &value else {
            continue; // not snap-shaped; the serialization loop handles it
        };
        let (Ok(name), Ok(version)) = (t.get::<String>("name"), t.get::<String>("version")) else {
            continue; // node/image/other outputs carry no snap identity
        };
        let _ = name; // the snap's own name; the map is keyed by output key
        let vf: mlua::Value = t.get("versions").unwrap_or(mlua::Value::Nil);
        let listing = match &vf {
            mlua::Value::Function(f) => {
                // pcall-equivalent: the Rust-side call captures the Lua
                // error as a value, so a raising listing cannot kill the
                // worker mid-record.
                let versions = f
                    .call::<mlua::Value>(())
                    .map_err(|e| e.to_string())
                    .and_then(|v| listing_from_value(&v));
                match versions {
                    Ok(list) => VersionListing {
                        resolved: version,
                        versions: Some(list),
                        error: None,
                    },
                    Err(e) => VersionListing {
                        resolved: version,
                        versions: None,
                        error: Some(e),
                    },
                }
            }
            _ => VersionListing {
                resolved: version,
                versions: None,
                error: None,
            },
        };
        out.insert(key, listing);
    }
    out
}

/// Output keys whose table declares `versions` as a function (ADR-0052).
fn versions_declared_keys(table: &mlua::Table) -> Vec<String> {
    let mut keys = Vec::new();
    for pair in table.pairs::<String, mlua::Value>() {
        let (key, value) = match pair {
            Ok(p) => p,
            Err(_) => break,
        };
        if let mlua::Value::Table(t) = &value {
            if matches!(
                t.get::<mlua::Value>("versions"),
                Ok(mlua::Value::Function(_))
            ) {
                keys.push(key);
            }
        }
    }
    keys
}

/// Enforce the versions() answer shape: a dense 1..n Lua array of
/// strings, at most [`MAX_VERSIONS_ENTRIES`] entries of at most
/// [`MAX_VERSIONS_LEN`] bytes each — an over-cap listing errors, it is
/// never truncated. An empty array is a valid answer (ADR-0052).
fn listing_from_value(v: &mlua::Value) -> Result<Vec<String>, String> {
    let mlua::Value::Table(t) = v else {
        return Err(format!(
            "versions() must return an array of version strings, got {}",
            v.type_name()
        ));
    };
    let mut entries: Vec<(i64, String)> = Vec::new();
    for pair in t.pairs::<mlua::Value, mlua::Value>() {
        let (k, val) = pair.map_err(|e| format!("versions() result: {e}"))?;
        let idx = match k {
            mlua::Value::Integer(i) => i,
            mlua::Value::Number(n) if n.fract() == 0.0 => n as i64,
            other => {
                return Err(format!(
                    "versions() must return an array (key type {} is not an integer index)",
                    other.type_name()
                ));
            }
        };
        let s = match &val {
            mlua::Value::String(s) => s.to_string_lossy(),
            other => {
                return Err(format!(
                    "versions() entries must be strings, got {}",
                    other.type_name()
                ));
            }
        };
        entries.push((idx, s));
    }
    entries.sort_by_key(|a| a.0);
    for (pos, (idx, _)) in entries.iter().enumerate() {
        if *idx != pos as i64 + 1 {
            return Err("versions() must return a dense 1..n array of version strings".into());
        }
    }
    if entries.len() > MAX_VERSIONS_ENTRIES {
        return Err(format!(
            "versions() returned {} entries — over the {MAX_VERSIONS_ENTRIES}-entry cap",
            entries.len()
        ));
    }
    for (idx, s) in &entries {
        if s.len() > MAX_VERSIONS_LEN {
            return Err(format!(
                "versions()[{idx}] is {} chars — over the {MAX_VERSIONS_LEN}-char cap",
                s.len()
            ));
        }
    }
    Ok(entries.into_iter().map(|(_, s)| s).collect())
}

/// Entry point for `nau chart eval-worker` (the hidden `__eval-worker`
/// alias keeps parsing for the migration window). Reads one JSON request from
/// stdin, evaluates, writes one JSON outcome to stdout, exits.
pub fn worker_main() -> miette::Result<()> {
    if let Err(e) = set_rlimits(RLIMIT_CPU_SECS) {
        eprintln!("eval worker: {e}");
        std::process::exit(1);
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .into_diagnostic()
        .wrap_err("eval worker: failed to read request")?;
    let req: EvalRequest = serde_json::from_str(line.trim())
        .map_err(|e| miette::miette!("eval worker: bad request: {e}"))?;

    let outcome = run_worker(&req);
    let mut out = std::io::stdout().lock();
    write_line(&mut out, &outcome)
        .map_err(|e| miette::miette!("eval worker: failed to write outcome: {e}"))?;
    Ok(())
}

use miette::{IntoDiagnostic as _, WrapErr as _};

// ── Check worker (strict-analyzer stage subprocess) ──

/// Wall-clock bound on the `__check-worker` child. Sits above
/// [`crate::analysis::ANALYZER_TIME_LIMIT_SECS`] (10s) so the analyzer's own
/// bound normally fires first with the clean `analysis timed out after 10s`
/// diagnostic; the killer is the backstop for a child the in-worker bound
/// cannot stop (e.g. wedged in the parser).
pub const CHECK_WALL_DEADLINE: Duration = Duration::from_secs(12);
/// CPU rlimit for the check worker. The analyzer is CPU-bound and allowed
/// 10s of solver time, so the CPU cap (15s) sits above the wall-clock
/// deadline: the wall-clock killer and the in-worker 10s bound are the
/// operative limits, and SIGKILL-by-rlimit only fires if the killer thread
/// itself failed.
const CHECK_RLIMIT_CPU_SECS: u64 = 15;

/// Child → parent: the check outcome (the worker's diagnostics array,
/// already normalized by `check_bounded` — a fired analyzer time limit
/// comes back as the single `analysis timed out` diagnostic).
pub type CheckOutcome = Vec<crate::analysis::Diagnostic>;

/// Full parent-side result of one check-worker run (containment evidence
/// and tests).
pub struct CheckRun {
    pub status: RunStatus,
    pub wall_ms: f64,
    pub outcome: Option<CheckOutcome>,
}

/// Spawn the check worker, ship the request, enforce the wall-clock
/// deadline. Mirrors [`run_eval_raw`] minus the require-serving loop: the
/// check worker receives every module source in the request and opens no
/// files, so the protocol is strictly one request line in, one outcome line
/// out. The parent survives every child death and returns a clean error
/// instead.
pub fn run_check_raw(req: &CheckRequest) -> miette::Result<CheckRun> {
    let start = Instant::now();
    // cwd is an empty scratch dir — same hygiene as the eval worker.
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create check scratch dir: {e}"))?;
    let mut child = Command::new(worker_exe())
        // The revealed spelling (ADR-0049, #321); same discovery ruling
        // as the eval worker above.
        .arg("chart")
        .arg("check-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(scratch.path())
        .spawn()
        .map_err(|e| {
            miette::miette!(
                "failed to spawn check worker at '{}': {e}",
                worker_exe().display()
            )
        })?;

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr_forwarder = forward_worker_stderr(&mut child);

    if let Err(e) = write_line(&mut stdin, req) {
        // Reap the child so a failed ship can't leave a zombie behind.
        let _ = child.kill();
        let _ = child.wait();
        wait_stderr_forwarder(&stderr_forwarder, start + CHECK_WALL_DEADLINE);
        return Err(miette::miette!(
            "failed to ship check request to worker: {e}"
        ));
    }
    // The child reads exactly one line and answers once.
    drop(stdin);

    // Wall-clock enforcer: identical pattern to the eval worker's killer.
    let killer_child = Arc::new(Mutex::new(child));
    let killer = {
        let killer_child = Arc::clone(&killer_child);
        std::thread::spawn(move || {
            let deadline = Instant::now() + CHECK_WALL_DEADLINE;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    if let Ok(mut c) = killer_child.lock() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    break;
                }
                if let Ok(mut c) = killer_child.lock() {
                    if c.try_wait().ok().flatten().is_some() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20).min(deadline - now));
            }
        })
    };

    // Read the single outcome line.
    let mut outcome = None;
    let mut status = RunStatus::Ok;
    {
        let mut reader = BufReader::new(stdout);
        match read_line_capped(&mut reader, MAX_LINE_BYTES) {
            Ok(Some(line)) => match serde_json::from_slice::<CheckOutcome>(&line) {
                Ok(diags) => outcome = Some(diags),
                Err(_) => {
                    status = RunStatus::BrokenPipe(
                        "unexpected line from check worker (protocol violation)".into(),
                    );
                }
            },
            // Clean EOF: no outcome here — classify via exit status below.
            Ok(None) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                status = RunStatus::BrokenPipe(
                    "protocol violation: check worker sent an over-long line".into(),
                );
            }
            Err(_) => {
                status = RunStatus::BrokenPipe("read failed (child died mid-request?)".into());
            }
        }
    }

    if outcome.is_none() && matches!(status, RunStatus::Ok) {
        let mut c = killer_child
            .lock()
            .map_err(|_| miette::miette!("check worker bookkeeping failed (mutex poisoned)"))?;
        match c.wait() {
            Ok(st) if st.code().is_some() => status = RunStatus::Exit(st.code().unwrap()),
            Ok(st) => {
                use std::os::unix::process::ExitStatusExt as _;
                let sig = st
                    .signal()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".into());
                status = if start.elapsed() >= CHECK_WALL_DEADLINE - Duration::from_millis(200) {
                    RunStatus::TimedOut
                } else {
                    RunStatus::Signalled(format!(
                        "signal {sig} before deadline (child died on its own)"
                    ))
                };
            }
            Err(e) => status = RunStatus::BrokenPipe(format!("wait: {e}")),
        }
    }
    killer.join().unwrap_or(());
    // Child reaped ⇒ the stderr write end is closed and the forwarder has
    // normally reached EOF. A wedged sink holds it in write_all — same
    // deadline-bounded detach as the eval worker (issue #76).
    wait_stderr_forwarder(&stderr_forwarder, start + CHECK_WALL_DEADLINE);

    // A child death at/after the deadline IS the timeout, whatever the pipe
    // reported first (same 200ms margin as the eval worker).
    if outcome.is_none()
        && !matches!(status, RunStatus::Ok)
        && start.elapsed() >= CHECK_WALL_DEADLINE - Duration::from_millis(200)
    {
        status = RunStatus::TimedOut;
    }

    Ok(CheckRun {
        status,
        wall_ms: start.elapsed().as_secs_f64() * 1000.0,
        outcome,
    })
}

/// Run one strict-analyzer check in the worker. The parent always survives:
/// contained child failures (wall-clock timeout, crash, protocol garbage)
/// come back as fail-closed diagnostics, never as a panic or an Err. Only
/// parent-side infrastructure failures (spawn, bookkeeping) return Err.
pub fn run_check(req: &CheckRequest) -> miette::Result<CheckOutcome> {
    let run = run_check_raw(req)?;
    if let Some(diags) = run.outcome {
        return Ok(diags);
    }
    let message = if matches!(run.status, RunStatus::TimedOut) {
        format!(
            "analysis timed out after {}s (check worker killed at the wall-clock deadline; partial results discarded)",
            CHECK_WALL_DEADLINE.as_secs()
        )
    } else {
        format!(
            "analyzer worker failed ({}); the definition is not verified",
            run.status.describe()
        )
    };
    Ok(vec![crate::analysis::Diagnostic {
        begin_line: 1,
        begin_col: 1,
        end_line: 1,
        end_col: 0,
        message,
    }])
}

/// The child-side check: gate-integrity last line, seed the parent-resolved
/// modules, run the bounded strict check.
fn run_check_worker(req: &CheckRequest) -> CheckOutcome {
    // A check worker must never analyze a source whose mode hot-comments
    // downgrade the gate, even if a future parent-side caller forgets the
    // pre-spawn scan — same shared rejection as [`crate::analysis::check_inputs`].
    if let Some(d) = crate::analysis::mode_downgrade_diagnostic(&req.entry) {
        return vec![d];
    }
    let mut checker = crate::analysis::Checker::for_definitions_with_limit(req.time_limit_secs);
    for (name, source) in &req.sources {
        checker.seed_module(name, source);
    }
    checker.check_bounded(&req.label, &req.entry)
}

/// Entry point for `nau chart check-worker` (the strict-analyzer stage
/// subprocess). One JSON request on stdin, one JSON diagnostics array on
/// stdout, exit.
pub fn check_worker_main() -> miette::Result<()> {
    if let Err(e) = set_rlimits(CHECK_RLIMIT_CPU_SECS) {
        eprintln!("check worker: {e}");
        std::process::exit(1);
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .into_diagnostic()
        .wrap_err("check worker: failed to read request")?;
    let req: CheckRequest = serde_json::from_str(line.trim())
        .map_err(|e| miette::miette!("check worker: bad request: {e}"))?;

    let outcome = run_check_worker(&req);
    let mut out = std::io::stdout().lock();
    write_line(&mut out, &outcome)
        .map_err(|e| miette::miette!("check worker: failed to write outcome: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_memory_limit_stays_128mb_below_rlimit_as() {
        // Regression: at VM_MEMORY_LIMIT == RLIMIT_AS the Rust/C++ base
        // memory plus a full VM heap tripped RLIMIT_AS first, so the clean
        // Luau "not enough memory" error path was dead code. The VM cap
        // must leave headroom under the rlimit.
        assert_eq!(VM_MEMORY_LIMIT, 384 * 1024 * 1024);
        assert_eq!(RLIMIT_AS_BYTES - VM_MEMORY_LIMIT as u64, 128 * 1024 * 1024);
        // The check worker's wall-clock deadline must sit above the
        // analyzer's own bound so the clean in-worker timeout normally wins.
        assert!(
            CHECK_WALL_DEADLINE
                > std::time::Duration::from_secs_f64(crate::analysis::ANALYZER_TIME_LIMIT_SECS),
            "wall-clock killer must be the backstop, not the primary bound"
        );
    }

    fn resolver_with_root(dir: &std::path::Path) -> SourceResolver {
        SourceResolver {
            roots: vec![dir.canonicalize().unwrap()],
        }
    }

    #[test]
    fn test_resolver_serves_module_inside_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("common.lua"), "return {}").unwrap();
        let resolver = resolver_with_root(dir.path());
        assert!(resolver.resolve("common").is_ok());
    }

    #[test]
    fn test_resolver_serves_init_lua() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("mod")).unwrap();
        std::fs::write(dir.path().join("mod/init.lua"), "return {}").unwrap();
        let resolver = resolver_with_root(dir.path());
        assert!(resolver.resolve("mod").is_ok());
        assert!(resolver.resolve("mod.init").is_ok());
    }

    #[test]
    fn test_resolver_rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        let err = resolver.resolve("../escape").unwrap_err();
        assert!(err.contains("rejected"), "got: {err}");
        assert!(resolver.resolve("a/../../b").is_err());
    }

    #[test]
    fn test_resolver_aliases_the_adr_pkgs_prefix() {
        // Issue #109: the ADR-0032 spelling `require("pkgs.lib.daemon")`
        // must resolve against an allowlisted pkgs root (which IS the
        // pkgs dir) instead of doubling to pkgs/pkgs/lib/…, as a
        // FALLBACK behind the unaliased spelling.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("lib/daemon.lua"), "return 'aliased'").unwrap();
        let resolver = resolver_with_root(dir.path());
        assert!(resolver.resolve("lib.daemon").is_ok());
        assert_eq!(
            resolver.resolve("pkgs.lib.daemon").unwrap(),
            "return 'aliased'"
        );
        // A real pkgs/pkgs/… subtree under the root wins over the alias.
        std::fs::create_dir_all(dir.path().join("pkgs/lib")).unwrap();
        std::fs::write(dir.path().join("pkgs/lib/daemon.lua"), "return 'direct'").unwrap();
        assert_eq!(
            resolver.resolve("pkgs.lib.daemon").unwrap(),
            "return 'direct'"
        );
        // The alias cannot conjure files that do not exist, and the
        // safety checks apply to the aliased spelling too.
        assert!(resolver.resolve("pkgs.lib.nope").is_err());
        assert!(resolver.resolve("pkgs...").is_err());
    }

    #[test]
    fn test_resolver_rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        let err = resolver.resolve("/etc/passwd").unwrap_err();
        assert!(err.contains("rejected"), "got: {err}");
    }

    #[test]
    fn test_resolver_rejects_dot_to_slash_absolute_synthesis() {
        // Regression: `name.replace('.', "/")` can synthesize an absolute
        // candidate ("...." → "////"), and `root.join` replaces its base
        // with an absolute segment. A dot-to-slash result that starts with
        // '/' must be rejected at the same layer as the explicit '/' check,
        // not left to the downstream canonicalize+prefix check.
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        for hostile in ["....", "...", ".", "..hidden"] {
            let err = resolver.resolve(hostile).unwrap_err();
            assert!(
                err.contains("rejected absolute path") && err.contains(hostile),
                "name {hostile:?}: got: {err}"
            );
        }
        // Normal dotted names still resolve through the same mapping.
        std::fs::create_dir_all(dir.path().join("foo/bar")).unwrap();
        std::fs::write(dir.path().join("foo/bar/baz.lua"), "return {}").unwrap();
        std::fs::write(dir.path().join("top.lua"), "return {}").unwrap();
        assert!(resolver.resolve("foo.bar.baz").is_ok());
        assert!(resolver.resolve("top").is_ok());
    }

    #[test]
    fn test_resolver_rejects_empty_name() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        assert!(resolver.resolve("").is_err());
    }

    #[test]
    fn test_resolver_rejects_oversized_name() {
        // Regression: a hostile giant require() name must be refused in O(1),
        // not amplified into parent-side CPU/memory work (wall-clock bounds
        // the child, not the parent's resolve path).
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        let giant = "a".repeat(32 * 1024 * 1024);
        let err = resolver.resolve(&giant).unwrap_err();
        assert!(err.contains("oversized"), "got: {err}");
        assert!(err.len() < 200, "error must not embed the name");
    }

    #[test]
    fn test_read_line_capped() {
        let mut r: &[u8] = b"one\ntwo\n\nlast";
        assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"one");
        assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"two");
        assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"");
        assert_eq!(read_line_capped(&mut r, 100).unwrap().unwrap(), b"last");
        assert!(read_line_capped(&mut r, 100).unwrap().is_none());

        let mut r: &[u8] = &[b'x'; 64];
        assert!(
            read_line_capped(&mut r, 8).is_err(),
            "over-long line must error"
        );
    }

    #[test]
    fn test_resolver_miss_is_not_found_error() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        let err = resolver.resolve("missing").unwrap_err();
        assert!(err.contains("not found in allowlisted roots"), "got: {err}");
    }

    #[test]
    fn test_lua_to_json_shapes() {
        let lua = mlua::Lua::new();
        let v: mlua::Value = lua
            .load(r#"return { name = "x", tags = { "a", "b" }, n = 1.5, ok = true }"#)
            .eval()
            .unwrap();
        let json = lua_to_json(&v).unwrap();
        assert_eq!(json["name"], "x");
        assert_eq!(json["tags"][0], "a");
        assert_eq!(json["tags"][1], "b");
        assert_eq!(json["n"], 1.5);
        assert_eq!(json["ok"], true);
    }

    #[test]
    fn test_lua_to_json_rejects_functions_and_cycles() {
        let lua = mlua::Lua::new();
        let v: mlua::Value = lua.load(r#"return { f = print }"#).eval().unwrap();
        assert!(lua_to_json(&v).is_err());

        let v: mlua::Value = lua
            .load("local t = {} t.self = t return { x = t }")
            .eval()
            .unwrap();
        assert!(lua_to_json(&v).is_err());
    }

    // ── Versions-mode extraction (ADR-0052 Decision 1) ──

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

    #[test]
    fn versions_mode_extracts_listing_and_resolved() {
        let ok = versions_worker(
            r#"
            return {
                default = snap {
                    name = "probe",
                    version = "2.0.21",
                    versions = function() return { "2.0.21", "2.0.20", "2.0.19" } end,
                },
            }
            "#,
        );
        let l = ok.versions.get("default").expect("listing recorded");
        assert_eq!(l.resolved, "2.0.21");
        assert_eq!(
            l.versions.as_deref().unwrap(),
            [
                "2.0.21".to_string(),
                "2.0.20".to_string(),
                "2.0.19".to_string()
            ]
        );
        assert!(l.error.is_none());
        assert_eq!(ok.versions_declared, vec!["default".to_string()]);
    }

    #[test]
    fn versions_mode_reports_absent_method_as_null() {
        let ok = versions_worker(
            r#"
            return { default = snap { name = "plain", version = "1.0" } }
            "#,
        );
        let l = ok.versions.get("default").expect("entry recorded for skip");
        assert_eq!(l.resolved, "1.0");
        assert!(l.versions.is_none());
        assert!(l.error.is_none());
        assert!(ok.versions_declared.is_empty());
    }

    #[test]
    fn versions_mode_names_non_snap_outputs_nowhere() {
        // A raw (non-snap-shaped) output carries no name+version pair and
        // must not appear in the listing map at all.
        let ok = versions_worker(r#"return { cfg = { some = "data" } }"#);
        assert!(ok.versions.is_empty());
    }

    #[test]
    fn versions_mode_captures_a_raising_listing() {
        let ok = versions_worker(
            r#"
            return {
                default = snap {
                    name = "boom",
                    version = "1.0",
                    versions = function() error("upstream gone") end,
                },
            }
            "#,
        );
        let l = ok.versions.get("default").unwrap();
        assert!(l.versions.is_none());
        let err = l.error.as_deref().expect("the raise must be captured");
        assert!(err.contains("upstream gone"), "got: {err}");
    }

    #[test]
    fn versions_mode_rejects_wrong_shapes_by_name() {
        // Non-table return.
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return "2.0.0" end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("must return an array"), "got: {err}");

        // Non-string entries.
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { "1.0", 42 } end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("entries must be strings"), "got: {err}");

        // Non-array table (string keys).
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { latest = "1.0" } end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("key type"), "got: {err}");

        // Sparse array (a hole breaks the 1..n run).
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1",
                versions = function() local t = {} t[1] = "1.0" t[3] = "0.9" return t end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("dense 1..n"), "got: {err}");
    }

    #[test]
    fn versions_mode_caps_are_errors_not_truncations() {
        // 1001 entries — one past the cap.
        let ok = versions_worker(
            r#"
            local t = {}
            for i = 1, 1001 do t[i] = "1.0." .. i end
            return { d = snap { name = "x", version = "1", versions = function() return t end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("1001") && err.contains("cap"), "got: {err}");

        // A version string 129 bytes long.
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1",
                versions = function() return { string.rep("v", 129) } end } }
            "#,
        );
        let err = ok.versions["d"].error.as_deref().unwrap();
        assert!(err.contains("128-char cap"), "got: {err}");

        // Exactly at both caps is still valid.
        let ok = versions_worker(
            r#"
            local t = {}
            for i = 1, 999 do t[i] = "1.0." .. i end
            t[1000] = string.rep("v", 128)
            return { d = snap { name = "x", version = "1", versions = function() return t end } }
            "#,
        );
        let l = ok.versions["d"].clone();
        assert!(
            l.error.is_none(),
            "at-cap listing must be valid: {:?}",
            l.error
        );
        assert_eq!(l.versions.as_ref().map(Vec::len), Some(1000));
    }

    #[test]
    fn versions_mode_empty_listing_is_a_valid_answer() {
        let ok = versions_worker(
            r#"
            return { d = snap { name = "x", version = "1", versions = function() return {} end } }
            "#,
        );
        let l = ok.versions["d"].clone();
        assert_eq!(l.versions.as_deref(), Some(&[][..]));
        assert!(l.error.is_none());
    }

    #[test]
    fn normal_mode_still_ships_outputs_carrying_a_versions_fn() {
        // Regression guard for the pre-serialization strip: today a
        // function field makes lua_to_json skip the WHOLE output; the
        // strip keeps the output flowing instead, with no listing call.
        let req = EvalRequest {
            prelude: crate::dsl::prelude(),
            index_data: serde_json::json!({ "version": 1, "snaps": [] }),
            arch: "amd64".into(),
            sources: Default::default(),
            entry: r#"
                return {
                    default = snap {
                        name = "probe",
                        version = "2.0.21",
                        versions = function() error("must never be called") end,
                    },
                }
            "#
            .into(),
            entry_label: "normal-mode-test".into(),
            allow_fetch: false,
            constraint: None,
            versions_mode: false,
        };
        let ok = match run_worker(&req) {
            WorkerOutcome::Ok(ok) => ok,
            WorkerOutcome::Err(e) => panic!("worker failed: {}", e.diagnostics.join("; ")),
        };
        assert!(
            ok.outputs.contains_key("default"),
            "the output must not be skipped: {:?}",
            ok.diagnostics
        );
        assert!(ok.diagnostics.is_empty(), "{:?}", ok.diagnostics);
        // The listing was never called and never shipped — listing-only.
        assert!(ok.versions.is_empty());
        assert_eq!(ok.versions_declared, vec!["default".to_string()]);
        // The stripped field must not reach the JSON.
        assert!(ok.outputs["default"].get("versions").is_none());
    }

    #[test]
    fn normal_mode_outcome_line_stays_byte_identical() {
        // The additive fields must vanish from the serialization when
        // empty — every recipe shipped today has no versions field, so
        // the worker's outcome bytes cannot move.
        let req = EvalRequest {
            prelude: crate::dsl::INIT_LUA.to_string(),
            index_data: serde_json::json!({ "version": 1, "snaps": [] }),
            arch: "amd64".into(),
            sources: Default::default(),
            entry: r#"return { default = snap { name = "p", version = "1" } }"#.into(),
            entry_label: "bytes-test".into(),
            allow_fetch: false,
            constraint: None,
            versions_mode: false,
        };
        let ok = match run_worker(&req) {
            WorkerOutcome::Ok(ok) => ok,
            WorkerOutcome::Err(e) => panic!("worker failed: {}", e.diagnostics.join("; ")),
        };
        let line = serde_json::to_string(&ok).unwrap();
        assert!(
            !line.contains("\"versions\""),
            "empty versions maps must not serialize: {line}"
        );
    }

    // ── stderr forwarder: cap + deadline (issue #76) ──

    #[test]
    fn for_build_allowlists_the_entrys_pkgs_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let entry = dir.path().join("pkgs/v/valkey/init.lua");
        std::fs::create_dir_all(entry.parent().unwrap()).expect("mkdirs");
        std::fs::write(&entry, "return {}").expect("write");
        let r = SourceResolver::for_build(entry.to_str().unwrap());
        let pkgs = dir.path().join("pkgs").canonicalize().expect("canon");
        assert!(
            r.roots.contains(&pkgs),
            "roots must contain the entry's own pkgs tree, got {:?}",
            r.roots
        );
        // Containment: a sibling tree the entry does not belong to stays out.
        let other = dir.path().join("other-tree/pkgs");
        std::fs::create_dir_all(&other).expect("mkdirs");
        assert!(!r.roots.contains(&other.canonicalize().unwrap()));
    }

    #[test]
    fn forward_capped_below_cap_forwards_everything() {
        let src = b"hello stderr".to_vec();
        let mut reader = std::io::Cursor::new(src.clone());
        let mut dst = Vec::new();
        forward_capped(&mut reader, &mut dst, 1024);
        assert_eq!(dst, src, "below the cap forwarding must be unchanged");
        assert_eq!(
            reader.position(),
            src.len() as u64,
            "source must be drained to EOF"
        );
    }

    #[test]
    fn forward_capped_truncates_at_cap_and_drains_rest() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 3000]);
        let mut dst = Vec::new();
        forward_capped(&mut reader, &mut dst, 1000);
        assert_eq!(dst.len(), 1000, "forwarding must stop at the cap");
        assert!(dst.iter().all(|&b| b == b'x'));
        assert_eq!(
            reader.position(),
            3000,
            "past the cap the stream must still drain to EOF (a stopped \
             drain would fill the child's stderr pipe and stall it)"
        );
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

    #[test]
    fn forward_capped_dead_sink_switches_to_discard_not_early_exit() {
        let mut reader = std::io::Cursor::new(vec![b'y'; 4096]);
        let mut dst = DeadSink;
        forward_capped(&mut reader, &mut dst, 1024);
        assert_eq!(
            reader.position(),
            4096,
            "a dead sink must not stop the drain; the child's stderr pipe \
             has to keep emptying"
        );
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

    #[test]
    fn wait_stderr_forwarder_detaches_a_wedged_sink_at_deadline() {
        let mut reader = std::io::Cursor::new(vec![0u8; 8192]);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sink = WedgedSink;
            forward_capped(&mut reader, &mut sink, 1024);
            let _ = done_tx.send(());
        });
        let start = Instant::now();
        wait_stderr_forwarder(&done_rx, start + Duration::from_millis(150));
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(140) && waited < Duration::from_secs(2),
            "the wait must be bounded by the deadline, not by the wedged \
             sink: {waited:?}"
        );
    }
}
