//! ADR-0010 migration step 5 — dual-eval consistency gate over the whole
//! definition corpus (`docs/adr/0010-package-language-luau.md` Decision 8,
//! Migration step 5).
//!
//! Every definition under `pkgs/**/*.lua` plus every root example
//! (`examples/**/*.lua`) is evaluated through BOTH backends:
//!
//! - **Luau** (production): the real bounded subprocess path —
//!   `isolate::run_eval` spawning `shuttle __eval-worker` with the exact
//!   production request shape (prelude = `dsl::prelude()`, index data,
//!   arch, IPC require).
//! - **Lua 5.4** (reference): the locked devbox interpreter
//!   (`lua54Packages.lua@5.4.7`, present in CI) driving
//!   `tests/parity/luau54_driver.lua`, which mirrors the worker environment
//!   (prelude, index() callback port, stderr print, allowlisted-roots
//!   require, lua_to_json semantics) on the 5.4 VM.
//!
//! The gate exists because mlua cannot compile the `lua54` and `luau`
//! backends into one binary (mlua-sys flat-reexports both), so an in-process
//! dual-eval is impossible; the historical in-tree `lua54` backend was
//! hard-removed in `44d13ff` without the ADR's transitional feature flag.
//!
//! Comparison altitude: the post-eval structures the worker reports —
//! `WorkerOk.outputs` and `WorkerOk.global_inputs` as JSON data — never
//! rendered text. Numbers are canonicalized through f64 (Luau has a single
//! double type; 5.4 has an integer subtype; `serde_json` treats
//! `Number(2)` and `Number(2.0)` as unequal). Diagnostic strings are NOT
//! compared: VM error formatting differs and is not part of the parity
//! contract.
//!
//! Hermeticity: definition eval is pure computation (source URLs are data,
//! never fetched; index() reads shipped JSON), so the network skip list is
//! empty by construction. Both sides run under a wall-clock deadline.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use shuttle::index::{PackageIndex, DEFAULT_INDEX};
use shuttle::isolate::{self, EvalRequest};

/// Driver + interpreter wall-clock bound; sits just above the production
/// worker deadline (`isolate::WALL_DEADLINE`, 5s) so both sides classify a
/// runaway definition the same way.
const DRIVER_DEADLINE: Duration = Duration::from_millis(5200);

const DRIVER_SRC: &str = include_str!("parity/luau54_driver.lua");

/// Definitions that must be skipped on network grounds. None: eval never
/// fetches — inputs/source URLs cross as data and are resolved by the
/// runtime, not the evaluator. Kept as an explicit (printed) constant so the
/// contract stays visible.
const NETWORK_SKIPS: &[&str] = &[];

// ── Corpus enumeration ──

fn collect_lua_files(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let base = Path::new(root);
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("lua") {
                if let Some(rel) = path.strip_prefix(base).ok().map(|p| p.to_string_lossy()) {
                    out.push(format!("{root}/{rel}"));
                }
            }
        }
    }
    out.sort();
    out
}

// ── Lua 5.4 reference interpreter ──

/// Locate a Lua 5.4 interpreter (the devbox shell provides `lua`; distros
/// often name it `lua5.4`). Returns the program name plus its version
/// banner. Hard failure when absent: the gate must not silently no-op —
/// run the suite through devbox, which guarantees the interpreter.
fn find_lua54() -> (String, String) {
    for program in ["lua5.4", "lua"] {
        if let Ok(out) = Command::new(program).arg("-v").output() {
            let banner = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if banner.contains("5.4") {
                return (program.to_string(), banner.trim().to_string());
            }
        }
    }
    panic!(
        "parity gate: no Lua 5.4 interpreter on PATH (looked for lua5.4, lua). \
         Run the suite via `devbox run -- cargo test` — devbox provides the \
         locked lua54Packages.lua@5.4.7 reference interpreter."
    );
}

// ── serde_json → Lua literal (driver request files) ──

fn lua_string_lit(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn lua_literal(v: &Value) -> String {
    match v {
        Value::Null => "nil".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else {
                // `{:?}` prints the shortest round-tripping form.
                format!("{:?}", n.as_f64().unwrap_or_default())
            }
        }
        Value::String(s) => lua_string_lit(s),
        Value::Array(items) => {
            let elems: Vec<String> = items.iter().map(lua_literal).collect();
            format!("{{{}}}", elems.join(","))
        }
        Value::Object(map) => {
            let elems: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("[{}]={}", lua_string_lit(k), lua_literal(v)))
                .collect();
            format!("{{{}}}", elems.join(","))
        }
    }
}

// ── Production request construction (mirrors lua.rs eval_request env) ──

fn production_request(prelude: &str, index_data: Value, label: &str, source: &str) -> EvalRequest {
    let arch = std::env::var("SHUTTLE_ARCH").unwrap_or_else(|_| "amd64".into());
    EvalRequest {
        prelude: prelude.to_string(),
        index_data,
        arch,
        sources: Default::default(),
        entry: source.to_string(),
        entry_label: label.to_string(),
    }
}

// ── Luau side: the real production subprocess path ──

fn eval_luau(req: &EvalRequest) -> Result<(Value, Value), String> {
    match isolate::run_eval(req) {
        Ok(ok) => {
            let outputs =
                serde_json::to_value(&ok.outputs).map_err(|e| format!("outputs serialize: {e}"))?;
            Ok((outputs, ok.global_inputs))
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

// ── Lua 5.4 side: the reference interpreter driver ──

fn eval_lua54(
    program: &str,
    driver_path: &Path,
    request_path: &Path,
    cwd: &Path,
) -> Result<(Value, Value), String> {
    let mut child = Command::new(program)
        .arg(driver_path)
        .arg(request_path)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {program}: {e}"))?;

    // Drain stdout/stderr concurrently: image-heavy definitions produce
    // outcome lines larger than the 64KB pipe buffer, and a join-after-exit
    // read would deadlock the child against a full pipe.
    let stdout = child.stdout.take().expect("driver stdout");
    let stderr = child.stderr.take().expect("driver stderr");
    let read_all = |r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let mut r = BufReader::new(r);
            let _ = r.read_to_string(&mut s);
            s
        })
    };
    let out_reader = read_all(Box::new(stdout));
    let err_reader = read_all(Box::new(stderr));

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if start.elapsed() >= DRIVER_DEADLINE {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("driver wait: {e}")),
        }
    };

    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();

    if status.is_none() {
        return Err("driver timed out (wall clock)".to_string());
    }

    let line = stdout
        .lines()
        .find(|l| l.starts_with("RESULT:"))
        .ok_or_else(|| {
            format!(
                "driver produced no outcome (exit {:?}): {}",
                status.map(|s| s.code().unwrap_or(-1)),
                truncate(&stderr, 300)
            )
        })?;

    let outcome: Value = serde_json::from_str(&line["RESULT:".len()..])
        .map_err(|e| format!("driver outcome not JSON: {e}: {line}"))?;

    if outcome["ok"] != Value::Bool(true) {
        return Err(format!(
            "eval failed on Lua 5.4: {}",
            truncate(&stderr, 300)
        ));
    }

    let outputs = outcome.get("outputs").cloned().unwrap_or_default();
    let inputs = outcome.get("global_inputs").cloned().unwrap_or_default();
    Ok((outputs, inputs))
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= max {
        s
    } else {
        format!("{}…", &s[..max])
    }
}

// ── Comparison ──

/// Normalize every number through f64: Luau surfaces integral doubles as
/// integers (mlua), 5.4 has a real integer subtype, and serde_json treats
/// `Number(2) != Number(2.0)`. Values, not representations, are the parity
/// contract.
fn canonicalize_numbers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or_default();
            if let Some(canonical) = serde_json::Number::from_f64(f) {
                *v = Value::Number(canonical);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(canonicalize_numbers),
        Value::Object(map) => map.values_mut().for_each(canonicalize_numbers),
        _ => {}
    }
}

/// First structural difference between the two post-eval values, as
/// (path, luau-side, lua54-side) for the divergence table.
fn first_diff(luau: &Value, lua54: &Value, path: &str) -> Option<(String, String, String)> {
    match (luau, lua54) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let sub = format!("{path}.{key}");
                match (a.get(key), b.get(key)) {
                    (Some(av), Some(bv)) => {
                        if let Some(d) = first_diff(av, bv, &sub) {
                            return Some(d);
                        }
                    }
                    (Some(av), None) => {
                        return Some((sub, truncate(&av.to_string(), 80), "<absent>".into()))
                    }
                    (None, Some(bv)) => {
                        return Some((sub, "<absent>".into(), truncate(&bv.to_string(), 80)))
                    }
                    (None, None) => unreachable!(),
                }
            }
            None
        }
        (Value::Array(a), Value::Array(b)) => {
            for i in 0..a.len().max(b.len()) {
                let sub = format!("{path}[{i}]");
                match (a.get(i), b.get(i)) {
                    (Some(av), Some(bv)) => {
                        if let Some(d) = first_diff(av, bv, &sub) {
                            return Some(d);
                        }
                    }
                    (Some(av), None) => {
                        return Some((sub, truncate(&av.to_string(), 80), "<absent>".into()))
                    }
                    (None, Some(bv)) => {
                        return Some((sub, "<absent>".into(), truncate(&bv.to_string(), 80)))
                    }
                    (None, None) => unreachable!(),
                }
            }
            None
        }
        (a, b) if a == b => None,
        (a, b) => Some((
            path.to_string(),
            truncate(&a.to_string(), 80),
            truncate(&b.to_string(), 80),
        )),
    }
}

// ── The gate ──

#[test]
fn corpus_dual_eval_parity() {
    let (program, banner) = find_lua54();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut defs = collect_lua_files("pkgs");
    let example_count;
    {
        let examples = collect_lua_files("examples");
        example_count = examples.len();
        defs.extend(examples);
    }
    assert!(
        defs.len() >= 100,
        "parity gate: corpus enumeration found only {} definitions — the \
         pkgs//examples walk is broken",
        defs.len()
    );

    // Shared driver + request scratch dir (per-definition request files).
    let scratch = tempfile::tempdir().expect("parity scratch dir");
    let driver_path = scratch.path().join("luau54_driver.lua");
    std::fs::write(&driver_path, DRIVER_SRC).expect("write driver");

    // Index data exactly as the production parent ships it
    // (lua.rs eval_request: SHUTTLE_INDEX_PATH or DEFAULT_INDEX).
    let index_path = std::env::var("SHUTTLE_INDEX_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_INDEX));
    let index =
        PackageIndex::load_or_default(&index_path).expect("load package index for parity gate");
    let index_data = serde_json::to_value(&index).expect("serialize index");
    let prelude = shuttle::dsl::prelude();

    let mut pass = Vec::new();
    let mut both_fail = Vec::new();
    let mut divergences = Vec::new();

    for def in &defs {
        if NETWORK_SKIPS.contains(&def.as_str()) {
            println!("SKIP      {def} (network skip list)");
            continue;
        }
        let Ok(source) = std::fs::read_to_string(manifest_dir.join(def)) else {
            divergences.push(format!("{def}: unreadable definition file"));
            continue;
        };

        let req = production_request(&prelude, index_data.clone(), def, &source);

        // Ship the identical inputs to the 5.4 driver.
        let entry_dir = Path::new(def)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut roots: Vec<String> = Vec::new();
        if !entry_dir.is_empty() {
            roots.push(entry_dir);
        }
        roots.push("pkgs".to_string());
        let request_lua = format!(
            "return {{\n  prelude = {},\n  entry = {},\n  entry_label = {},\n  arch = {},\n  roots = {{{}}},\n  index_data = {},\n}}\n",
            lua_string_lit(&req.prelude),
            lua_string_lit(&source),
            lua_string_lit(def),
            lua_string_lit(&req.arch),
            roots
                .iter()
                .map(|r| lua_string_lit(r))
                .collect::<Vec<_>>()
                .join(", "),
            lua_literal(&index_data),
        );
        let idx = pass.len() + both_fail.len() + divergences.len();
        let request_path = scratch.path().join(format!("req_{idx}.lua"));
        std::fs::write(&request_path, request_lua).expect("write driver request");

        let luau = eval_luau(&req);
        let lua54 = eval_lua54(&program, &driver_path, &request_path, &manifest_dir);

        match (luau, lua54) {
            (Ok((mut l_out, mut l_in)), Ok((mut r_out, mut r_in))) => {
                canonicalize_numbers(&mut l_out);
                canonicalize_numbers(&mut l_in);
                canonicalize_numbers(&mut r_out);
                canonicalize_numbers(&mut r_in);
                if let Some((path, a, b)) = first_diff(&l_out, &r_out, "outputs")
                    .or_else(|| first_diff(&l_in, &r_in, "global_inputs"))
                {
                    divergences.push(format!(
                        "{def}: field mismatch at {path}: luau={a} | lua54={b}"
                    ));
                } else {
                    pass.push(def.clone());
                    println!("PASS      {def}");
                }
            }
            (Err(lu), Err(l5)) => {
                both_fail.push(def.clone());
                println!(
                    "BOTH-FAIL {def} (backends agree on failure)\n    luau:  {}\n    lua54: {}",
                    truncate(&lu, 160),
                    truncate(&l5, 160)
                );
            }
            (Ok(_), Err(l5)) => divergences.push(format!("{def}: luau=ok | lua54=FAILED — {l5}")),
            (Err(lu), Ok(_)) => divergences.push(format!(
                "{def}: luau=FAILED — {} | lua54=ok",
                truncate(&lu, 200)
            )),
        }
    }

    // ── Gate report ──
    println!("\n=== ADR-0010 dual-eval parity gate ===");
    println!("interpreter: {banner}");
    println!(
        "corpus: {} definitions (pkgs: {}, examples: {example_count})",
        defs.len(),
        defs.len() - example_count
    );
    println!("skip list (network): {} entries", NETWORK_SKIPS.len());
    println!(
        "pass: {} | both-fail (agreed): {} | divergences: {}",
        pass.len(),
        both_fail.len(),
        divergences.len()
    );
    if !both_fail.is_empty() {
        println!("both-fail definitions: {}", both_fail.join(", "));
    }

    assert!(
        divergences.is_empty(),
        "\n\ndual-eval parity gate FAILED — {} divergence(s):\n  {}\n",
        divergences.len(),
        divergences.join("\n  ")
    );
}
