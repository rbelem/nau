//! Subprocess bounding (ADR-0009 Decision 5): untrusted eval runs in a
//! short-lived child with an rlimit applied in the child before eval and a
//! wall-clock kill in the parent. ALL eval inputs (prelude, index, definition)
//! cross the parent<->child pipe; the child never reads the repo or store.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const WALL_DEADLINE: Duration = Duration::from_secs(5);
const RLIMIT_AS_BYTES: u64 = 512 * 1024 * 1024;
const RLIMIT_CPU_SECS: u64 = 5;

/// What the child asks the parent for (newline-delimited JSON on stdio).
#[derive(Serialize, Deserialize)]
#[serde(tag = "req")]
enum ChildRequest {
    Source { name: String },
    Index,
}

#[derive(Serialize, Deserialize)]
struct ParentReply {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChildHeader {
    /// Store package name (e.g. "jq") — served as `<name>.ncl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkg: Option<String>,
    /// Inline source (adversarial suite) — evaluated directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChildOk {
    pub result: String, // "ok"
    pub value: Value,
    pub fetch_ms: f64,
    pub eval_ms: f64,
    pub ipc: Vec<IpcTiming>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcTiming {
    pub what: String,
    pub ms: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChildErr {
    pub result: String, // "error"
    pub diagnostics_json: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ChildOutcomeLine {
    Ok(ChildOk),
    Err(ChildErr),
}

/// Full parent-side outcome of one isolated run.
pub struct IsolatedRun {
    pub status: RunStatus,
    pub wall_ms: f64,
    pub max_rss_kb: u64,
    pub outcome: Option<ChildOutcomeLine>,
    pub ipc: Vec<IpcTiming>,
}

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
    pub fn contained(&self) -> bool {
        !matches!(self, RunStatus::BrokenPipe(_))
    }
}

/// Store simulation on the parent side: a directory acting as the store.
/// Only paths that resolve inside this directory are ever served.
pub struct Store {
    pub dir: std::path::PathBuf,
}

impl Store {
    pub fn read_source(&self, name: &str) -> Result<String> {
        if name.starts_with('/') || name.starts_with("..") || name.contains("..") {
            anyhow::bail!("store: rejected non-store path {name:?}");
        }
        let path = self.dir.join(name);
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !canonical.starts_with(&self.dir) {
            anyhow::bail!("store: rejected path outside store: {name:?}");
        }
        std::fs::read_to_string(&canonical)
            .with_context(|| format!("store: source {name:?} not found"))
    }
}

fn write_line<W: Write>(w: &mut W, v: &impl Serialize) -> Result<()> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Spawn the child, serve its requests, enforce the deadline, return the outcome.
pub fn run_isolated(child_exe: &std::path::Path, header: &ChildHeader, store: &Store) -> Result<IsolatedRun> {
    let start = Instant::now();
    let mut child = Command::new(child_exe)
        .arg("__child")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // cwd is an empty scratch dir: even if something escaped the inmem
        // rewrite, relative imports would find nothing here.
        .current_dir(std::env::temp_dir())
        .spawn()
        .context("spawning eval child")?;
    let pid = child.id();

    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");

    // Parent-side policy: inline (adversarial) sources get the same import
    // rewrite as served store sources.
    let mut header = header.clone();
    if let Some(src) = &header.inline_source {
        header.inline_source = Some(crate::nickel::rewrite_imports(src));
    }
    write_line(&mut stdin, &header)?;

    // Wall-clock enforcer: this is the only real termination bound.
    let killer_child = Arc::new(Mutex::new(child));
    let killer = {
        let killer_child = Arc::clone(&killer_child);
        std::thread::spawn(move || {
            let deadline = Instant::now() + WALL_DEADLINE;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    let mut c = killer_child.lock().unwrap();
                    let _ = c.kill();
                    let _ = c.wait();
                    break;
                }
                // Wake early if the child already exited.
                {
                    let mut c = killer_child.lock().unwrap();
                    if let Some(_st) = c.try_wait().ok().flatten() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(20).min(deadline - now));
            }
        })
    };

    // RSS sampler for the memory evidence.
    let rss_child = {
        let killer_child = Arc::clone(&killer_child);
        std::thread::spawn(move || {
            let mut max = 0u64;
            loop {
                {
                    let mut c = killer_child.lock().unwrap();
                    if c.try_wait().ok().flatten().is_some() {
                        break;
                    }
                }
                let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                for line in status.lines() {
                    if let Some(kb) = line.strip_prefix("VmHWM:") {
                        let kb: u64 = kb.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
                        max = max.max(kb);
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            max
        })
    };

    // Serve requests until the outcome line or EOF.
    let mut ipc = Vec::new();
    let mut outcome = None;
    let mut status_out = RunStatus::Ok;
    {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let Ok(line) = line else {
                status_out = RunStatus::BrokenPipe("read failed (child died mid-request?)".into());
                break;
            };
            if let Ok(req) = serde_json::from_str::<ChildRequest>(&line) {
                let t0 = Instant::now();
                let reply = match &req {
                    ChildRequest::Source { name } => match store.read_source(name) {
                        // The parent is the import-policy authority: rewrite
                        // every served source to the inmem channel before it
                        // crosses the boundary.
                        Ok(content) => ParentReply {
                            ok: true,
                            content: Some(crate::nickel::rewrite_imports(&content)),
                            error: None,
                        },
                        Err(e) => ParentReply { ok: false, content: None, error: Some(e.to_string()) },
                    },
                    ChildRequest::Index => match store.read_source("package-index.json") {
                        Ok(content) => ParentReply { ok: true, content: Some(content), error: None },
                        Err(e) => ParentReply { ok: false, content: None, error: Some(e.to_string()) },
                    },
                };
                ipc.push(IpcTiming {
                    what: match &req {
                        ChildRequest::Source { name } => format!("source:{name}"),
                        ChildRequest::Index => "index".into(),
                    },
                    ms: t0.elapsed().as_secs_f64() * 1000.0,
                });
                if write_line(&mut stdin, &reply).is_err() {
                    status_out = RunStatus::BrokenPipe("write failed (child died mid-request)".into());
                    break;
                }
                continue;
            }
            if let Ok(oc) = serde_json::from_str::<ChildOutcomeLine>(&line) {
                outcome = Some(oc);
                break;
            }
        }
    }
    drop(stdin);

    if outcome.is_none() && matches!(status_out, RunStatus::Ok) {
        let mut c = killer_child.lock().unwrap();
        match c.wait() {
            Ok(st) if st.code().is_some() => status_out = RunStatus::Exit(st.code().unwrap()),
            Ok(st) => {
                // Killed (SIGKILL) at the wall-clock deadline == the timeout path.
                use std::os::unix::process::ExitStatusExt as _;
                let sig = st.signal().map(|s| s.to_string()).unwrap_or_else(|| "unknown".into());
                status_out = if start.elapsed() >= WALL_DEADLINE - Duration::from_millis(200) {
                    RunStatus::TimedOut
                } else {
                    RunStatus::Signalled(format!("signal {sig} before deadline (child died on its own)"))
                };
            }
            Err(e) => status_out = RunStatus::BrokenPipe(format!("wait: {e}")),
        }
    }
    let max_rss_kb = rss_child.join().unwrap_or(0);
    killer.join().unwrap();

    if matches!(status_out, RunStatus::Ok) && outcome.is_none() {
        // Child exited 0 without an outcome line: treat as timeout-shaped failure.
        status_out = RunStatus::BrokenPipe("child produced no outcome".into());
    }

    Ok(IsolatedRun {
        status: status_out,
        wall_ms: start.elapsed().as_secs_f64() * 1000.0,
        max_rss_kb,
        outcome,
        ipc,
    })
}

// ---------------- child side ----------------

fn set_rlimits() -> Result<()> {
    use libc::{rlimit, setrlimit, RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE};
    let mem = rlimit { rlim_cur: RLIMIT_AS_BYTES, rlim_max: RLIMIT_AS_BYTES };
    let cpu = rlimit { rlim_cur: RLIMIT_CPU_SECS, rlim_max: RLIMIT_CPU_SECS };
    let fsize = rlimit { rlim_cur: 0, rlim_max: 0 };
    let nofile = rlimit { rlim_cur: 64, rlim_max: 64 };
    // Applied in the child before eval — Decision 5's "memory rlimit applied in the child".
    unsafe {
        if setrlimit(RLIMIT_AS, &mem) != 0 {
            anyhow::bail!("setrlimit(RLIMIT_AS) failed");
        }
        if setrlimit(RLIMIT_CPU, &cpu) != 0 {
            anyhow::bail!("setrlimit(RLIMIT_CPU) failed");
        }
        if setrlimit(RLIMIT_FSIZE, &fsize) != 0 {
            anyhow::bail!("setrlimit(RLIMIT_FSIZE) failed");
        }
        if setrlimit(RLIMIT_NOFILE, &nofile) != 0 {
            anyhow::bail!("setrlimit(RLIMIT_NOFILE) failed");
        }
    }
    Ok(())
}

fn request<W: Write, R: BufRead>(stdin: &mut W, stdout: &mut R, req: &ChildRequest) -> Result<String> {
    write_line(stdin, req)?;
    let mut line = String::new();
    if stdout.read_line(&mut line)? == 0 {
        anyhow::bail!("parent closed the pipe");
    }
    let reply: ParentReply = serde_json::from_str(&line)?;
    if reply.ok {
        Ok(reply.content.unwrap_or_default())
    } else {
        anyhow::bail!(reply.error.unwrap_or_else(|| "parent error".into()))
    }
}

fn fetch_source<W: Write, R: BufRead>(
    stdout: &mut W,
    reader: &mut R,
    name: &str,
    ipc: &mut Vec<IpcTiming>,
) -> Result<String> {
    let t0 = Instant::now();
    let r = request(stdout, reader, &ChildRequest::Source { name: name.to_string() });
    ipc.push(IpcTiming { what: format!("source:{name}"), ms: t0.elapsed().as_secs_f64() * 1000.0 });
    r
}

fn fetch_all_inputs<W: Write, R: BufRead>(
    stdout: &mut W,
    reader: &mut R,
    header: &ChildHeader,
    ipc: &mut Vec<IpcTiming>,
) -> Result<crate::nickel::NickelInputs> {
    let prelude_raw = fetch_source(stdout, reader, "prelude.ncl", ipc)?;

    let t0 = Instant::now();
    let index_raw = request(stdout, reader, &ChildRequest::Index)?;
    ipc.push(IpcTiming { what: "index".into(), ms: t0.elapsed().as_secs_f64() * 1000.0 });
    let index_json: Value = serde_json::from_str(&index_raw)?;
    let prelude = crate::nickel::prelude_with_index(
        &prelude_raw,
        &crate::nickel::index_entries_for_arch(&index_json, "amd64"),
    );

    let (pkg_name, pkg_src) = match (&header.pkg, &header.inline_source) {
        (Some(pkg), _) => {
            let name = format!("{pkg}.ncl");
            let src = fetch_source(stdout, reader, &name, ipc)?;
            (name, src)
        }
        (None, Some(src)) => (
            header.display_name.clone().unwrap_or_else(|| "inline.ncl".into()),
            src.clone(),
        ),
        (None, None) => anyhow::bail!("child header: neither pkg nor inline_source"),
    };

    // Transitive store imports: request each from the parent over IPC (more
    // cross-boundary resolutions, each timed) and seed them in-memory. A parent
    // rejection (path outside the store) leaves the name unseeded — the import
    // then fails at eval with a structured diagnostic instead of aborting.
    let mut extra_seeds = Vec::new();
    for dep in crate::nickel::referenced_store_names(&pkg_src) {
        if dep == crate::nickel::PRELUDE_NAME.to_string() {
            continue;
        }
        if let Ok(src) = fetch_source(stdout, reader, &dep, ipc) {
            extra_seeds.push((dep, src));
        }
    }

    Ok(crate::nickel::NickelInputs { prelude, pkg_name, pkg_src, extra_seeds })
}

/// Child entry: rlimits first, then IPC-only sourcing, then bounded eval.
pub fn child_main() -> Result<()> {
    set_rlimits()?;
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout().lock();

    let mut header_line = String::new();
    reader.read_line(&mut header_line)?;
    let header: ChildHeader = serde_json::from_str(&header_line)?;

    let mut ipc = Vec::new();
    let inputs = fetch_all_inputs(&mut stdout, &mut reader, &header, &mut ipc)?;

    // NOTE: the parent rewrote imports to %inmem_src%: before serving, so the
    // eval process below can never open a file for imports.
    let t0 = Instant::now();
    let eval_result = crate::nickel::eval_inprocess(&inputs);
    let eval_ms = t0.elapsed().as_secs_f64() * 1000.0;

    match eval_result {
        Ok(ok) => write_line(
            &mut stdout,
            &ChildOk { result: "ok".into(), value: ok.value, fetch_ms: 0.0, eval_ms, ipc },
        )?,
        Err((diagnostics_json, _files)) => write_line(
            &mut stdout,
            &ChildErr { result: "error".into(), diagnostics_json },
        )?,
    }
    Ok(())
}
