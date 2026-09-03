//! Adversarial probes for the isolation boundaries (eval + analyzer
//! subprocesses). Every test asserts the same core property: the PARENT
//! survives and fails closed.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shuttle::isolate::{self, CheckRequest, EvalRequest, SourceResolver, WorkerOutcome};

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

fn run(label: &str, src: &str) -> isolate::EvalRun {
    isolate::run_eval_raw(&request(label, src)).expect("PARENT MUST SURVIVE every attack")
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

fn dotted_abs(p: &std::path::Path) -> String {
    p.canonicalize()
        .unwrap()
        .to_string_lossy()
        .replace('/', ".")
}

// ── Attack 1: leading-dot require name → absolute candidate path ──
// resolver turns '.' into '/'; a LEADING dot makes the candidate ABSOLUTE,
// so root.join() discards the root. The decoy file EXISTS at that absolute
// path — the prefix check must be what saves us, and this proves it.
#[test]
fn attack_dot_prefix_name_cannot_reach_absolute_decoy() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.lua");
    std::fs::write(&secret, "return { leaked = 'PASSWORD' }").unwrap();
    let dotted = dotted_abs(&secret); // "/tmp/.tmpXXX/secret.lua" -> ".tmp.tmpXXX.secret.lua"
    assert!(dotted.starts_with('.'), "probe precondition: {dotted}");

    // Entry lives in a different dir, so `outside` is NOT an allowlisted root.
    let entry_dir = tempfile::tempdir().unwrap();
    let label = entry_dir
        .path()
        .join("shuttle.lua")
        .to_str()
        .unwrap()
        .to_string();

    let src = format!(
        r#"
local ok, err = pcall(require, "{dotted}")
return {{ leaked = tostring(ok), err = tostring(err):sub(1, 120), name = "x", version = "1" }}
"#
    );
    let r = run(&label, &src);
    assert_eq!(out_str(&r, "leaked"), "false", "MUST NOT load the decoy");
    let err = out_str(&r, "err");
    assert!(
        err.contains("rejected absolute path"),
        "absolute decoy must be rejected at the policy layer, got: {err}"
    );
    eprintln!("[PASS] dot-prefix absolute candidate rejected: {err}");
}

// ── Attack 2: symlinks inside an allowlisted root pointing outside ──
#[test]
fn attack_symlink_escape_from_inside_root() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.lua");
    std::fs::write(&secret, "return { leaked = 'PASSWORD' }").unwrap();
    let outside_canon = outside.path().canonicalize().unwrap();

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("real.lua"), "return { ok = true }").unwrap();
    // file symlink escaping the root
    std::os::unix::fs::symlink(&secret, root.path().join("kaputt.lua")).unwrap();
    // directory symlink escaping the root
    std::os::unix::fs::symlink(&outside_canon, root.path().join("linkdir")).unwrap();

    let label = root
        .path()
        .join("shuttle.lua")
        .to_str()
        .unwrap()
        .to_string();
    let src = r#"
local results = {}
local function try(n)
  local ok, e = pcall(require, n)
  results[#results+1] = n .. "=" .. tostring(ok) .. ":" .. tostring(e):sub(1, 60)
end
try("kaputt")         -- symlinked FILE to outside secret
try("linkdir.secret") -- through symlinked DIR to outside secret
try("real")           -- control: inside root, must succeed
return { r = table.concat(results, " | "), name = "x", version = "1" }
"#;
    let r = run(&label, src);
    let report = out_str(&r, "r");
    eprintln!("[INFO] symlink attack report: {report}");
    assert!(
        report.contains("kaputt=false"),
        "file symlink escape must fail: {report}"
    );
    assert!(
        report.contains("linkdir.secret=false"),
        "dir symlink escape must fail: {report}"
    );
    assert!(
        report.contains("real=true"),
        "legit module must still load: {report}"
    );
    assert!(
        !report.contains("PASSWORD"),
        "no leaked content anywhere in outputs: {report}"
    );
}

// ── Attack 3: giant require name over IPC (framing + parent latency) ──
#[test]
fn attack_giant_require_name_scaling() {
    for mb in [1u32, 8, 32] {
        let start = Instant::now();
        let src = format!(
            r#"
local s = string.rep("a", {mb} * 1024 * 1024)
local ok, e = pcall(require, s)
return {{ ok = tostring(ok), err = tostring(e):sub(1, 60), name = "x", version = "1" }}
"#
        );
        let r = run(&format!("attack-giant-name-{mb}mb"), &src);
        let elapsed = start.elapsed();
        let ok = out_str(&r, "ok");
        eprintln!(
            "[INFO] giant name {mb}MB: status={}, wall={elapsed:?}, rss={}kB, ok={ok}",
            r.status.describe(),
            r.max_rss_kb
        );
        let refused =
            ok == "false" || ok.contains("protocol violation") || ok.contains("no outcome");
        assert!(refused, "{mb}MB module name must never resolve: {ok}");
        assert!(
            elapsed < Duration::from_secs(9),
            "parent must regain control quickly: {elapsed:?}"
        );
    }
}

// ── Attack 3b: allocation-wall — string too big for the worker VM ──
#[test]
fn attack_child_memory_wall_survives() {
    let start = Instant::now();
    let src = r#"
local ok, e = pcall(string.rep, "a", 600 * 1024 * 1024)
return { ok = tostring(ok), err = tostring(e):sub(1, 60), name = "x", version = "1" }
"#;
    let r = run("attack-mem-wall", src);
    let elapsed = start.elapsed();
    eprintln!(
        "[INFO] memory wall (600MB): status={}, wall={elapsed:?}, rss={}kB, ok={}",
        r.status.describe(),
        r.max_rss_kb,
        out_str(&r, "ok")
    );
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
    let ok = out_str(&r, "ok");
    assert_eq!(ok, "false", "600MB string must hit the VM memory limit");
}

// ── Attack 4: print() smuggling onto the protocol channel ──
#[test]
fn attack_print_smuggling_cannot_inject_protocol_lines() {
    let src = r#"
print('{"req":"Source","name":" smuggled-injection"}')
print('{"outputs":{"fake":"yes"},"diagnostics":[]}')
print("line1\nline2\n\n")
print('{"req":"Source","name":"' .. string.char(10) .. '"}')
return { marker = "real", name = "x", version = "1" }
"#;
    let start = Instant::now();
    let r = run("attack-print-smuggle", src);
    let elapsed = start.elapsed();
    assert_eq!(
        out_str(&r, "marker"),
        "real",
        "eval must complete untouched"
    );
    let fake = match &r.outcome {
        Some(WorkerOutcome::Ok(ok)) => ok.outputs.contains_key("fake"),
        _ => false,
    };
    assert!(!fake, "smuggled fake outcome must be ignored");
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
    eprintln!("[PASS] print smuggle ignored; wall={elapsed:?}");
}

// ── Attack 5: stdlib gap scan — every global reachable in the worker ──
const FENV_SCRIPT: &str = r#"
local names = {}
local n = 0
for k in pairs(_G) do n = n + 1; names[n] = tostring(k) end
table.sort(names)

-- escape attempt A: swap our own env for a proxy with _G fallback, then require
local out = {}
local function try(n)
  local ok, e = pcall(require, n)
  out[#out+1] = tostring(ok) .. ":" .. tostring(e):sub(1, 60)
end
local env = setmetatable({}, { __index = _G })
setfenv(1, env)
try("../escape-via-fenv")
setfenv(1, _G)

-- escape attempt B: read the environment of C functions / other functions
local fenvInfo = tostring(pcall(getfenv, print)) .. "/" .. tostring(pcall(getfenv, 0))

-- escape attempt C: string metatable abuse
local smt = getmetatable("")
local smtKeys = {}
if type(smt) == "table" then for k in pairs(smt) do smtKeys[#smtKeys+1] = tostring(k) end end

return {
  globals = table.concat(names, ","),
  fenv_attempts = table.concat(out, " | "),
  fenv_info = fenvInfo,
  smt = table.concat(smtKeys, ","),
  name = "x", version = "1",
}
"#;

#[test]
fn attack_globals_enumeration_and_fenv_escape_attempts() {
    let r = run("attack-globals", FENV_SCRIPT);
    let globals = out_str(&r, "globals");
    let fenv_attempts = out_str(&r, "fenv_attempts");
    eprintln!("[INFO] worker globals: {globals}");
    eprintln!("[INFO] fenv escape attempts: {fenv_attempts}");
    eprintln!(
        "[INFO] getfenv(print)/getfenv(0): {}",
        out_str(&r, "fenv_info")
    );
    eprintln!("[INFO] string metatable keys: {}", out_str(&r, "smt"));
    assert_absent_globals(&globals);
    assert_present_globals(&globals);
    // The fenv env-swap must not unlock anything: traversal still refused.
    assert!(
        fenv_attempts.contains("false:") && fenv_attempts.contains("rejected"),
        "fenv-swapped require must still be refused parent-side: {fenv_attempts}"
    );
    assert!(
        !fenv_attempts.contains("| true") && !fenv_attempts.starts_with("true"),
        "no fenv-based require may succeed: {fenv_attempts}"
    );
}

fn contains_name(globals: &str, name: &str) -> bool {
    globals.split(',').any(|g| g == name)
}

fn assert_absent_globals(globals: &str) {
    for banned in [
        "io",
        "os",
        "package",
        "debug",
        "dofile",
        "loadfile",
        "load",
        "loadstring",
    ] {
        assert!(
            !contains_name(globals, banned),
            "global `{banned}` must not exist in the worker VM (globals: {globals})"
        );
    }
}

fn assert_present_globals(globals: &str) {
    for required in ["require", "string", "table", "math", "pcall", "pairs"] {
        assert!(
            contains_name(globals, required),
            "global `{required}` should exist (globals: {globals})"
        );
    }
}

// ── Attack 6: colluding requires — second request crafted from first result ──
#[test]
fn attack_colluding_requires_cannot_extract_outside_content() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.lua");
    std::fs::write(&secret, "return { leaked = 'PASSWORD' }").unwrap();

    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("collud.lua"),
        r#"return { evil = "../secret", evil2 = "." .. "./secret", evil3 = string.char(46,46,47) .. "secret" }"#,
    )
    .unwrap();
    let label = root
        .path()
        .join("shuttle.lua")
        .to_str()
        .unwrap()
        .to_string();

    let src = r#"
local c = require("collud")           -- legitimate in-root require, returns attacker data
local results = {}
local function try(n)
  local ok, e = pcall(require, n)
  results[#results+1] = tostring(ok) .. ":" .. tostring(e):sub(1, 50)
end
try(c.evil)    -- "../secret" built from a loaded module
try(c.evil2)   -- "././secret" (dot trick)
try(c.evil3)   -- runtime-concatenated "../secret"
return { r = table.concat(results, " | "), name = "x", version = "1" }
"#;
    let r = run(&label, src);
    let report = out_str(&r, "r");
    eprintln!("[INFO] collusion report: {report}");
    assert_eq!(
        report.matches("false:").count(),
        3,
        "all three crafted requests must be refused: {report}"
    );
    assert!(
        !report.contains("PASSWORD"),
        "no outside content may cross the boundary: {report}"
    );
}

// ── Attack 7: weird names — empty, whitespace, newline, NUL, dots ──
#[test]
fn attack_weird_names_all_refused_or_clean() {
    let src = r#"
local names = { "", " ", "\n", "\t", string.char(0), "a\nb", ".", "..", "a/..", "..a", "%2e%2e%2f", "a//b", "x." }
local results = {}
for i = 1, #names do
  local ok, e = pcall(require, names[i])
  results[#results+1] = i .. "=" .. tostring(ok)
end
return { r = table.concat(results, ","), name = "x", version = "1" }
"#;
    let start = Instant::now();
    let r = run("attack-weird-names", src);
    let elapsed = start.elapsed();
    let report = out_str(&r, "r");
    eprintln!("[INFO] weird names: {report} (wall {elapsed:?})");
    assert!(
        !report.contains("true"),
        "NONE of the weird names may resolve (all should be false): {report}"
    );
    assert!(elapsed < Duration::from_secs(9), "{elapsed:?}");
}

// ── Attack 8: parent-side observation — cwd, argv, rlimits of the worker ──
#[test]
fn attack_worker_process_observations() {
    let repo = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let observed: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let sampler = {
        let observed = std::sync::Arc::clone(&observed);
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for e in entries.flatten() {
                        let pid = e.file_name().to_string_lossy().to_string();
                        if !pid.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
                            continue;
                        }
                        let Ok(cmd) = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                        else {
                            continue;
                        };
                        let parts: Vec<String> = cmd
                            .split('\0')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        if !parts.iter().any(|p| p == "__eval-worker") {
                            continue;
                        }
                        let cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))
                            .unwrap_or_default();
                        // /proc guard: the pid must still be the same worker
                        // process by the time limits were read (guards against
                        // pid reuse between the three reads).
                        let cmd_again = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                            .unwrap_or_default();
                        let parts_again: Vec<String> = cmd_again
                            .split('\0')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();
                        if parts_again != parts {
                            continue; // pid recycled mid-sample; discard
                        }
                        let mut row = format!("cwd={cwd}; argv={parts:?}");
                        for line in limits.lines() {
                            let l = line.trim();
                            for key in [
                                "Max address space",
                                "Max cpu time",
                                "Max file size",
                                "Max open files",
                            ] {
                                if let Some(rest) = l.strip_prefix(key) {
                                    row.push_str(&format!("; {key}={}", rest.trim()));
                                }
                            }
                        }
                        observed.lock().unwrap().push(row);
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };

    let r = run("attack-observe", "while true do end");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    sampler.join().unwrap();

    let rows = observed.lock().unwrap().clone();
    eprintln!(
        "[INFO] observed worker process state ({} samples):",
        rows.len()
    );
    for row in rows.iter().take(2) {
        eprintln!("  {row}");
    }
    assert!(!rows.is_empty(), "sampler must catch the live worker");
    for row in &rows {
        let mut fields = row.split("; ");
        let cwd = fields
            .next()
            .unwrap_or("")
            .strip_prefix("cwd=")
            .unwrap_or("");
        assert!(
            cwd.starts_with(std::env::temp_dir().to_str().unwrap()),
            "worker cwd must be a temp scratch dir, got {row}"
        );
        assert!(
            !cwd.contains(&repo),
            "worker cwd must never be the repo: {row}"
        );
        // /proc pads with runs of spaces, and the row embeds key=value pairs —
        // normalize both before value checks.
        let norm = row
            .replace('=', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            norm.contains("Max address space 536870912 536870912 bytes"),
            "RLIMIT_AS 512MB must be applied: {row}"
        );
        assert!(
            norm.contains("Max file size 0 0 bytes"),
            "RLIMIT_FSIZE 0 must be applied: {row}"
        );
        assert!(
            norm.contains("Max cpu time 5 5 seconds"),
            "RLIMIT_CPU 5s must be applied: {row}"
        );
        assert!(
            norm.contains("Max open files 64 64 files"),
            "RLIMIT_NOFILE 64 must be applied: {row}"
        );
    }
    assert!(
        !matches!(&r.outcome, Some(WorkerOutcome::Ok(_))),
        "busy loop must be killed at the deadline"
    );
    assert!(r.wall_ms < 8000.0, "killer must fire: {}ms", r.wall_ms);
}

// ── Attack 9: direct protocol abuse — hand-crafted lines to __eval-worker ──
#[test]
fn attack_raw_protocol_via_stdin() {
    let bin = std::env::var("CARGO_BIN_EXE_shuttle").expect("cargo-provided binary");
    let scratch = tempfile::tempdir().unwrap();

    let req = serde_json::json!({
        "prelude": "return {}",
        "index_data": { "version": 1, "snaps": [] },
        "arch": "amd64",
        "sources": {},
        "entry": "return { v = tostring(io) .. tostring(os) .. tostring(require) }",
        "entry_label": "raw-probe",
    });

    let mut child = std::process::Command::new(&bin)
        .arg("__eval-worker")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .current_dir(scratch.path())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let mut sin = child.stdin.take().unwrap();
        sin.write_all(req.to_string().as_bytes()).unwrap();
        sin.write_all(b"\n").unwrap();
        // Trailing garbage after the request line must be ignored or fatal, never executed.
        sin.write_all(b"{} extra junk not json\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    eprintln!(
        "[INFO] raw protocol: exit={:?}, stdout={stdout:?}",
        out.status.code()
    );
    assert!(
        stdout.contains("nilnilfunction"),
        "worker VM must report io==nil and os==nil over raw stdin: {stdout}"
    );
    assert!(
        stdout.contains("\"diagnostics\""),
        "worker must speak the line protocol: {stdout}"
    );
}

// ── Attack 10: resolver unit probes (dot-trick + hostile names) ──
#[test]
fn attack_resolver_hostile_names() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.lua");
    std::fs::write(&secret, "return { leaked = 'PASSWORD' }").unwrap();

    let root = tempfile::tempdir().unwrap();
    let label = root
        .path()
        .join("shuttle.lua")
        .to_str()
        .unwrap()
        .to_string();
    let resolver = SourceResolver::for_build(&label);

    let abs_dotted = dotted_abs(&secret);
    let res = resolver.resolve(&abs_dotted);
    eprintln!("[INFO] absolute-dotted resolve({abs_dotted}): {res:?}");
    assert!(
        res.is_err(),
        "absolute-dot trick must not resolve the decoy"
    );
    assert!(res.unwrap_err().contains("rejected absolute path"));

    for bad in [
        "a\0b",
        "a\nb",
        "   ",
        "..",
        "../x",
        "/etc/passwd",
        ".",
        "..a",
        "a\\..\\..\\etc",
    ] {
        let res = resolver.resolve(bad);
        assert!(res.is_err(), "name {bad:?} must not resolve");
        eprintln!("[INFO] resolve({bad:?}) = {:?}", res.unwrap_err());
    }
}

// ── Analyzer-stage probes (`__check-worker`) ──

fn check_request(label: &str, source: &str) -> CheckRequest {
    CheckRequest {
        label: label.to_string(),
        entry: source.to_string(),
        sources: BTreeMap::new(),
        time_limit_secs: Some(shuttle::analysis::ANALYZER_TIME_LIMIT_SECS),
    }
}

/// A deep local-variable nesting chain: Luau's complexity guard must reject
/// it with a diagnostic, quickly, without wedging or OOM-ing either side.
#[test]
fn attack_analyzer_nesting_bomb_is_contained() {
    let depth = 20_000;
    let mut src = String::with_capacity(depth * 20);
    src.push_str("local t0 = {}\n");
    for i in 1..depth {
        src.push_str(&format!("local t{i} = {{ t{} }}\n", i - 1));
    }
    src.push_str(&format!("return {{ v = t{} ~= nil }}\n", depth - 1));

    let start = Instant::now();
    let run = isolate::run_check_raw(&check_request("attack-type-bomb", &src))
        .expect("PARENT MUST SURVIVE the analyzer nesting bomb");
    let elapsed = start.elapsed();
    eprintln!(
        "[INFO] nesting bomb: status={}, wall={elapsed:?}, diags={}",
        run.status.describe(),
        run.outcome.as_ref().map(|d| d.len()).unwrap_or(0)
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "parent must regain control quickly, took {elapsed:?}"
    );
    let diags = run
        .outcome
        .expect("worker must answer (or the killer must classify) — never hang");
    assert!(
        !diags.is_empty(),
        "fail closed: a nesting bomb must yield a diagnostic, never a pass"
    );
}

/// A source that genuinely burns analyzer-solver time (hundreds of thousands
/// of field assignments): with an injected 0.5s per-module bound, the
/// in-worker `moduleTimeLimitSec` must abort it mid-flight and the parent
/// must see exactly one fail-closed timeout diagnostic — no partial results.
#[test]
fn attack_analyzer_time_bomb_abort_mid_flight() {
    let n = 400_000;
    let mut src = String::with_capacity(n * 20 + 32);
    src.push_str("local t = {}\n");
    for i in 0..n {
        src.push_str(&format!("t.f{i} = '{i}'\n"));
    }
    src.push_str("return { v = t.f0 ~= nil }\n");

    let mut req = check_request("attack-time-bomb", &src);
    // 0.5s << the ~9s this source needs on the reference debug build, so the
    // in-worker bound (not the parent killer) fires on any plausible machine.
    req.time_limit_secs = Some(0.5);

    let start = Instant::now();
    let diags = isolate::run_check(&req).expect("PARENT MUST SURVIVE the analyzer time bomb");
    let elapsed = start.elapsed();
    eprintln!(
        "[INFO] time bomb aborted in {elapsed:?} with {} diag(s)",
        diags.len()
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "parent must regain control quickly, took {elapsed:?}"
    );
    assert_eq!(
        diags.len(),
        1,
        "partial results must be discarded for one timeout diagnostic: {diags:?}"
    );
    assert!(
        diags[0].message.contains("analysis timed out after 0.5s"),
        "got: {:?}",
        diags[0].message
    );
}

/// The in-worker immediate-expiry bound through the real subprocess: the
/// timeout reaches the parent as ONE diagnostic and nothing else.
#[test]
fn attack_worker_timeout_is_single_fail_closed_diagnostic() {
    let mut req = check_request("attack-check-timeout", "return { v = 1 }");
    req.time_limit_secs = Some(0.0);
    let diags = isolate::run_check(&req).expect("parent must survive");
    assert_eq!(diags.len(), 1, "exactly one diagnostic: {diags:?}");
    assert!(
        diags[0].message.contains("analysis timed out after 0s"),
        "got: {:?}",
        diags[0].message
    );
}

/// A hot-comment downgrade attempt must be rejected by the worker itself
/// (the child-side last-line check), even when the request arrives without
/// the parent-side pre-spawn scan.
#[test]
fn attack_hot_comment_downgrade_rejected_through_worker() {
    let diags = isolate::run_check(&check_request(
        "attack-hot-comment",
        "--!nonstrict\nreturn { default = snap { name = \"x\", version = \"1\" } }",
    ))
    .expect("parent must survive");
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("nonstrict") && diags[0].message.contains("host-controlled"),
        "got: {:?}",
        diags[0].message
    );
}

/// Regression (resolver-root containment): an embedded package's definition
/// is materialized into a fresh private tempdir, and that dir — never /tmp —
/// must be the only allowlisted resolver root derived from it. A decoy world-
/// writable file sitting in /tmp must NOT be require()-able.
#[test]
fn attack_embedded_pkg_resolver_root_is_private_tmpdir_not_tmp() {
    let label = shuttle::pkg_source::materialize_embedded(
        "return { default = snap { name = \"embedded\", version = \"1\" } }",
    )
    .expect("embedded materialization must succeed");
    let label = label.to_str().unwrap();
    let parent = std::path::Path::new(label)
        .parent()
        .expect("definition must live inside the private tempdir");
    assert!(
        parent.starts_with(std::env::temp_dir()),
        "materialization lives under the system temp dir: {label}"
    );
    assert_ne!(
        parent.canonicalize().unwrap(),
        std::env::temp_dir().canonicalize().unwrap(),
        "the resolver root must be a private dir, NEVER /tmp itself"
    );

    let resolver = SourceResolver::for_build(label);

    // The private tempdir IS the root: a sibling module resolves.
    std::fs::write(parent.join("helper.lua"), "return { v = 7 }").unwrap();
    assert!(
        resolver.resolve("helper").is_ok(),
        "sibling modules inside the private tempdir must resolve"
    );

    // /tmp is NOT a root: a world-writable decoy sitting there must not be
    // reachable, even though it exists and the name is well-formed.
    let stem = format!("zzz-embedded-decoy-{}", std::process::id());
    std::fs::write(
        std::env::temp_dir().join(format!("{stem}.lua")),
        "return { leaked = 'PASSWORD' }",
    )
    .unwrap();
    let err = resolver
        .resolve(&stem)
        .expect_err("/tmp itself must not be an allowlisted root for embedded packages");
    assert!(
        err.contains("not found in allowlisted roots"),
        "decoy must fall through the allowlist, got: {err}"
    );
}
