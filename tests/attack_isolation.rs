//! THROWAWAY adversarial probes for the eval-isolation implementation.
//! Run with: cargo test --test attack_tmp -- --nocapture
//! Deleted after the audit; NOT part of the suite.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shuttle::isolate::{self, EvalRequest, SourceResolver, WorkerOutcome};

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
        err.contains("not found in allowlisted roots"),
        "absolute decoy must fall through the allowlist, got: {err}"
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
    assert!(res.unwrap_err().contains("not found"));

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
