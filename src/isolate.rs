//! Subprocess eval bounding (ADR-0010 Decisions 4+5, ported from the Nickel
//! spike `spike/src/isolate.rs`).
//!
//! Untrusted definitions never evaluate in-process: the parent spawns a
//! short-lived worker (`shuttle __eval-worker`), ships ALL eval inputs
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
//! The strict-analyzer stage of `shuttle check` runs the same way: the
//! parent spawns `shuttle __check-worker`, ships the definition plus every
//! parent-resolved module source as one JSON request, and reads one JSON
//! diagnostics array back. The analyzer never runs on untrusted sources
//! in-process; timeouts (wall-clock kill or the in-worker analyzer bound)
//! reach the caller as a single fail-closed diagnostic.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
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
    /// Warn-and-continue diagnostics (per-output extraction skips).
    pub diagnostics: Vec<String>,
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
/// itself (`current_exe`); integration tests get the real shuttle binary via
/// cargo's `CARGO_BIN_EXE_shuttle`. No env override and no PATH fallback:
/// anything able to influence the parent's env/PATH must not get to choose
/// which binary receives the eval request.
pub fn worker_exe() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_shuttle") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::current_exe().expect("failed to locate the shuttle binary (current_exe)")
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

/// Like [`run_eval`] but returns the full run (status, wall time, peak RSS)
/// for containment evidence and tests.
pub fn run_eval_raw(req: &EvalRequest) -> miette::Result<EvalRun> {
    let start = Instant::now();
    // cwd is an empty scratch dir: even if something escaped the require
    // override, relative file access would find nothing here.
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create eval scratch dir: {e}"))?;
    let mut child = Command::new(worker_exe())
        .arg("__eval-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
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

    if let Err(e) = write_line(&mut stdin, req) {
        // Reap the child so a failed ship can't leave a zombie behind.
        let _ = child.kill();
        let _ = child.wait();
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

    lua.load(req.prelude.as_str())
        .set_name("=init.lua".to_string())
        .exec()
        .map_err(|e| miette::miette!("failed to initialize shuttle DSL: {e}"))?;

    // index() backed by the shipped index data — no filesystem access.
    let index: crate::index::PackageIndex = serde_json::from_value(req.index_data.clone())
        .map_err(|e| miette::miette!("bad index data from parent: {e}"))?;
    let arch = req.arch.clone();
    let index_fn = lua
        .create_function(move |lua, name: String| {
            let entry = index.find_by_name_or_alias(&name).ok_or_else(|| {
                mlua::Error::external(miette::miette!("snap '{name}' not found in package index"))
            })?;
            crate::index::PackageIndex::entry_to_lua_table(entry, &arch, lua)
        })
        .map_err(|e| miette::miette!("failed to create index(): {e}"))?;
    lua.globals()
        .set("index", index_fn)
        .map_err(|e| miette::miette!("failed to set index global: {e}"))?;

    // Definitions may call print(); the child's stdout is the IPC channel,
    // so route print to stderr.
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

    install_require(&lua, &req.sources)?;

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
                        map.insert(name, serde_json::json!({ "url": url }));
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
                .all(|(i, (k, _))| matches!(k, mlua::Value::Integer(n) if *n == i as i32 + 1))
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
        Err(e) => return fatal(vec![format!("{e}")]),
    };

    let mlua::Value::Table(table) = &result else {
        return fatal(vec![format!(
            "must return a table of outputs, got {}",
            result.type_name()
        )]);
    };

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
        diagnostics,
    })
}

/// Entry point for `shuttle __eval-worker`. Reads one JSON request from
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
        .arg("__check-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
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

    if let Err(e) = write_line(&mut stdin, req) {
        // Reap the child so a failed ship can't leave a zombie behind.
        let _ = child.kill();
        let _ = child.wait();
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

/// Entry point for `shuttle __check-worker` (the strict-analyzer stage
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
    fn test_resolver_rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = resolver_with_root(dir.path());
        let err = resolver.resolve("/etc/passwd").unwrap_err();
        assert!(err.contains("rejected"), "got: {err}");
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
}
