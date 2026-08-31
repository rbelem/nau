//! ADR-0009 Nickel embed spike — gate runner.
//!
//! Subcommands: bakeoff | contracts | parity | adversarial | imports | latency | all
//! Hidden: `__child` (subprocess eval entry used by the isolation gates).

mod gates;
mod golden;
mod isolate;
mod nickel;
mod schema;

use anyhow::Result;
use gates::Report;
use nickel::eval_inprocess;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "all".into());
    match cmd.as_str() {
        "__child" => isolate::child_main(),
        "__try" => try_eval_file(&args.next().unwrap()),
        "bakeoff" => bakeoff(),
        "contracts" => contracts(),
        "parity" => parity(),
        "adversarial" => adversarial(),
        "imports" => imports(),
        "latency" => latency(),
        "all" => {
            bakeoff()?;
            contracts()?;
            parity()?;
            adversarial()?;
            imports()?;
            latency()
        }
        other => {
            eprintln!("unknown subcommand {other:?}");
            std::process::exit(2);
        }
    }
}

fn try_eval_file(path: &str) -> Result<()> {
    let src = std::fs::read_to_string(path)?;
    let inputs = gates::inputs_for_inline(&src, "try.ncl")?;
    match eval_inprocess(&inputs) {
        Ok(v) => println!("OK: {}", v.value),
        Err((d, _files)) => println!("{d}"),
    }
    Ok(())
}

fn bakeoff() -> Result<()> {    let mut r = Report::new();
    r.say("=== Crate bake-off (Decision 1) ===");
    r.say("\n-- candidate: nickel-lang (stable) 2.2.0 --");
    match nickel::stable_probe::probe() {
        Ok((p, json_ok)) => {
            r.say(format!(
                "eval_deep + Expr::to_serde: OK ({p:?}); Error::format(ErrorFormat::Json): {json_ok}"
            ));
            r.say("host function/data registration: NOT EXPOSED (no add_source/extend-env/AST access in public API)");
            r.say("custom import resolution: NOT EXPOSED (only with_added_import_paths = filesystem search)");
        }
        Err(e) => r.say(format!("stable probe FAILED: {e}")),
    }
    r.say("\n-- candidate: nickel-lang-core 0.18.0 --");
    r.say("ProgramBuilder::add_source_string + build::<CacheImpl>() + eval_full_for_export: used by every gate below");
    r.say("serde extraction: serde_json::Value::deserialize(NickelValue) (Deserializer impl, compile-proven in parity gate)");
    r.say("JSON diagnostics: error::report::report_with(.., ErrorFormat::Json) (compile-proven in contracts gate)");
    r.say("host data: not_exported in-memory inputs + host-owned index record (imports gate)");
    r.say("import interception: %inmem_src%: channel + host-side import rewrite (imports gate)");
    r.say("\nCHOICE: nickel-lang-core 0.18.0 — pinned via =0.18.0 in spike/Cargo.toml (lockfile records it)");
    r.flush();
    Ok(())
}

fn contracts() -> Result<()> {
    let mut r = Report::new();
    r.say("=== Contract wrap (Decision 2) ===");

    // Schema-valid extraction first.
    let ok_src = r#"{ default = snap { name = "x", version = "1.0", requires = ["glibc"] } }"#;
    let inputs = gates::inputs_for_inline(ok_src, "ok-contract.ncl")?;
    match eval_inprocess(&inputs) {
        Ok(v) => r.say(format!("valid definition extracts: {}", v.value)),
        Err((d, _files)) => r.gate(false, "valid definition passes schema", &d),
    }

    for (name, src) in [
        ("wrong field type (name = 42)", r#"{ default = snap { name = 42, version = "1.0" } }"#),
        ("missing required field (version)", r#"{ default = snap { name = "x" } }"#),
        ("invalid enum (type = \"bogus\")", r#"{ default = snap { name = "x", version = "1", type = "bogus" } }"#),
        ("requires must be array of strings", r#"{ default = snap { name = "x", version = "1", requires = [42] } }"#),
        ("apps entries must satisfy App contract", r#"{ default = snap { name = "x", version = "1", apps = { main = { plugs = ["home"] } } } }"#),
    ] {
        let inputs = gates::inputs_for_inline(src, "bad.ncl")?;
        match eval_inprocess(&inputs) {
            Ok(v) => r.gate(
                false,
                &format!("contract rejects: {name}"),
                &format!("evaluated instead: {}", v.value),
            ),
            Err((nickel_json, files)) => match gates::to_diagnostics(&nickel_json, &files) {
                Ok(set) if !set.diagnostics.is_empty() => {
                    let d0 = &set.diagnostics[0];
                    let spanned = d0.span.byte_end > d0.span.byte_start;
                    r.gate(
                        spanned,
                        &format!("contract rejects: {name}"),
                        &format!(
                            "message={:?} span={:?}@{}:{} expected={:?} actual={:?}",
                            trunc(&d0.message, 110),
                            d0.span.byte_start..d0.span.byte_end,
                            d0.span.line_start,
                            d0.span.col_start,
                            d0.expected,
                            d0.actual
                        ),
                    );
                }
                Ok(_) => r.gate(
                    false,
                    &format!("contract rejects: {name}"),
                    &format!("no usable diagnostics; raw={}", trunc(&nickel_json, 300)),
                ),
                Err(e) => r.gate(false, &format!("contract rejects: {name}"), &format!("diag mapping: {e}")),
            },
        }
    }
    r.flush();
    Ok(())
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.into()
    } else {
        format!("{}…", &s[..n])
    }
}

fn parity() -> Result<()> {
    let mut r = Report::new();
    r.say("=== Golden parity (Decision 8) ===");
    for (pkg, rel) in [
        ("hello", "pkgs/h/hello.lua"),
        ("jq", "pkgs/j/jq/init.lua"),
        ("system-base", "pkgs/s/system-base.lua"),
    ] {
        match gates::parity_for(pkg, rel) {
            Ok(p) => {
                if p.diffs.is_empty() {
                    r.gate(true, &format!("parity: {pkg} (Lua == Nickel, field-level)"), "0 diffs");
                } else {
                    r.gate(false, &format!("parity: {pkg}"), &format!("{} diffs", p.diffs.len()));
                    for d in p.diffs.iter().take(20) {
                        r.say(format!("       - {d}"));
                    }
                    r.say(format!("       lua:     {}", &p.lua_json));
                    r.say(format!("       nickel:  {}", &p.nickel_json));
                }
            }
            Err(e) => r.gate(false, &format!("parity: {pkg}"), &format!("{e:#}")),
        }
    }

    // Decision 3: typed serde extraction on the Nickel path.
    let inputs = gates::inputs_for_pkg("hello")?;
    match eval_inprocess(&inputs) {
        Ok(v) => {
            let pkg: schema::PackageDef = serde_json::from_value(v.value["default"].clone())?;
            r.gate(
                true,
                "serde extraction into PackageDef struct",
                &format!("name={} version={} grade={:?}", pkg.name, pkg.version, pkg.grade),
            );
        }
        Err((e, _)) => r.gate(false, "serde extraction into PackageDef struct", &e),
    }

    // prelude defaults fire when fields are absent (Lua snap() parity).
    let defaults_src = r#"{ default = snap { name = "x", version = "1" } }"#;
    match eval_inprocess(&gates::inputs_for_inline(defaults_src, "defaults.ncl")?) {
        Ok(v) => {
            let pkg: schema::PackageDef = serde_json::from_value(v.value["default"].clone())?;
            r.gate(
                pkg.grade.as_deref() == Some("stable") && pkg.confinement.as_deref() == Some("strict"),
                "prelude defaults (grade/confinement) match Lua snap()",
                &format!("grade={:?} confinement={:?}", pkg.grade, pkg.confinement),
            );
        }
        Err((e, _)) => r.gate(false, "prelude defaults", &e),
    }
    r.flush();
    Ok(())
}

fn adversarial() -> Result<()> {
    let mut r = Report::new();
    r.say("=== Adversarial suite (Decision 8) — subprocess bounds: 5s wall + RLIMIT_AS 512MB + RLIMIT_CPU 5s ===");
    for case in gates::adversarial_cases() {
        let run = gates::run_isolated_source(&case.source, case.name)?;
        let contained = contained_outcome(&run);
        let outcome_desc = match &run.outcome {
            Some(isolate::ChildOutcomeLine::Ok(ok)) => format!(
                "evaluated ok (eval_ms={:.1}) — contained within bounds",
                ok.eval_ms
            ),
            Some(isolate::ChildOutcomeLine::Err(e)) => format!(
                "diagnostic returned: {}",
                trunc(&e.diagnostics_json.replace('\n', " "), 140)
            ),
            None => run.status.describe(),
        };
        r.gate(
            contained,
            &format!("adversarial: {}", case.name),
            &format!(
                "wall={:.0}ms max_rss={}kB status={} → {outcome_desc}",
                run.wall_ms, run.max_rss_kb, run.status.describe()
            ),
        );
    }
    r.say("(host unaffected: parent alive and serving after every case — it printed this line)");
    r.flush();
    Ok(())
}

/// TimedOut cases: the kill is issued at the 5s deadline; teardown adds a few
/// ms of wait/scheduling lag — allow a small margin and report both numbers.
fn contained_outcome(run: &isolate::IsolatedRun) -> bool {
    run.status.contained()
        && (run.wall_ms < 5000.0
            || (matches!(run.status, isolate::RunStatus::TimedOut) && run.wall_ms < 5500.0))
}

fn describe_run(run: &isolate::IsolatedRun) -> String {    match &run.outcome {
        Some(isolate::ChildOutcomeLine::Err(e)) => trunc(&e.diagnostics_json.replace('\n', " "), 200),
        Some(_) => "evaluated(!)".into(),
        None => run.status.describe(),
    }
}

fn rejected(run: &isolate::IsolatedRun) -> bool {
    matches!(&run.outcome, Some(isolate::ChildOutcomeLine::Err(_)))
}

fn imports() -> Result<()> {
    let mut r = Report::new();
    r.say("=== Import interception (Decision 5/7/8) ===");

    // 1. Store import resolves through the host-controlled in-memory channel.
    let run = gates::run_isolated_pkg("jq")?;
    let ipc_desc = run
        .ipc
        .iter()
        .map(|t| format!("{}={:.2}ms", t.what, t.ms))
        .collect::<Vec<_>>()
        .join(", ");
    r.say(format!("cross-boundary IPC resolutions (parent-served): [{ipc_desc}]"));
    match &run.outcome {
        Some(isolate::ChildOutcomeLine::Ok(ok)) => r.gate(
            true,
            "store import (lib.ncl) + index resolved through the subprocess IPC path",
            &format!("eval_ms={:.1}", ok.eval_ms),
        ),
        Some(isolate::ChildOutcomeLine::Err(e)) => {
            r.gate(false, "store import via IPC", &trunc(&e.diagnostics_json, 200))
        }
        None => r.gate(false, "store import via IPC", &run.status.describe()),
    }

    // 2. Direct filesystem imports are rejected: rewritten to unseeded inmem names.
    let leak = r#"{ x = import "/etc/passwd" } "#.to_string();
    let run2 = gates::run_isolated_source(&leak, "leak-attempt.ncl")?;
    // Evidence: the attempted path never reached the filesystem — the resolver
    // looked for the rewritten inmem name instead.
    let rejected_leak = match &run2.outcome {
        Some(isolate::ChildOutcomeLine::Err(e)) => e.diagnostics_json.contains("%inmem_src%"),
        _ => false,
    };
    r.gate(rejected_leak, "direct file import rejected (import \"/etc/passwd\")", &describe_run(&run2));

    // 3. Canary: a real file next to an empty-cwd child must be unreachable.
    let canary = std::env::temp_dir().join("shoot-spike-canary.ncl");
    std::fs::write(&canary, "{ canary = true }\n")?;
    let canary_src = format!("{{ x = import {:?} }}", canary.to_string_lossy());
    let run3 = gates::run_isolated_source(&canary_src, "canary.ncl")?;
    r.gate(rejected(&run3), "absolute-path import of existing file rejected (canary)", &describe_run(&run3));
    let _ = std::fs::remove_file(&canary);

    // 4. Parent-relative traversal attempt.
    let run4 = gates::run_isolated_source(r#"{ x = import "../store/package-index.json" }"#, "traversal.ncl")?;
    r.gate(rejected(&run4), "relative traversal import rejected", &describe_run(&run4));

    // 5. In-process: same firewall without a subprocess (embedded mode feasibility).
    let no_seed = eval_inprocess(&gates::inputs_for_inline(&leak, "leak.ncl")?);
    r.gate(
        no_seed.is_err(),
        "in-process: unseeded direct import rejected by the same rewrite",
        &match no_seed {
            Err((d, _)) => trunc(&d.replace('\n', " "), 200),
            Ok(v) => format!("evaluated(!): {}", v.value),
        },
    );
    r.flush();
    Ok(())
}

fn latency() -> Result<()> {
    let mut r = Report::new();
    r.say("=== Latency (Decision 8): parse+typecheck+eval+extract, subprocess spawn+IPC included ===");
    let mut walls = Vec::new();
    let mut evals = Vec::new();
    for i in 0..7 {
        let run = gates::run_isolated_pkg("hello")?;
        if let Some(isolate::ChildOutcomeLine::Ok(ok)) = &run.outcome {
            r.say(format!(
                "  run {i}: wall={:.1}ms eval={:.1}ms (median reported below)",
                run.wall_ms, ok.eval_ms
            ));
            walls.push(run.wall_ms);
            evals.push(ok.eval_ms);
        } else {
            r.gate(false, &format!("latency run {i}"), &run.status.describe());
        }
    }
    walls.sort_by(|a, b| a.partial_cmp(b).unwrap());
    evals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_wall = walls.get(walls.len() / 2).copied().unwrap_or(f64::INFINITY);
    let median_eval = evals.get(evals.len() / 2).copied().unwrap_or(f64::INFINITY);
    r.gate(
        median_wall < 100.0,
        "shoot check < 100ms including subprocess spawn",
        &format!("median wall={median_wall:.1}ms (eval-only={median_eval:.1}ms, spawn+IPC={:.1}ms)", median_wall - median_eval),
    );

    // In-process comparison (informs the Decision 5 worker-pool fallback).
    let mut inproc = Vec::new();
    for _ in 0..7 {
        let t0 = std::time::Instant::now();
        let res = eval_inprocess(&gates::inputs_for_pkg("hello")?);
        inproc.push(t0.elapsed().as_secs_f64() * 1000.0);
        if let Err((e, _)) = res {
            r.gate(false, "in-process latency run", &e);
            break;
        }
    }
    inproc.sort_by(|a, b| a.partial_cmp(b).unwrap());
    r.say(format!(
        "  in-process median (no subprocess): {:.1}ms — per-eval overhead of isolation = {:.1}ms",
        inproc[inproc.len() / 2],
        median_wall - inproc[inproc.len() / 2],
    ));
    r.flush();
    Ok(())
}
