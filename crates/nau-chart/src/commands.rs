//! The chart-side command handlers (issue #326): the `nau check/lint/
//! audit/lock/deps/search` bodies plus their reporters, moved verbatim
//! from the root `commands.rs`. The binary dispatches via the root's
//! re-exports, so `nau::commands::cmd_check(…)` and friends resolve
//! unchanged. Handlers whose bodies orchestrate OTHER domains
//! (`cmd_deps_fetch` -> pod, `cmd_lint`'s pod branch, `cmd_eval` ->
//! sign, `cmd_index` -> store resolution) stay root-side, where those
//! domains live (ADR-0051 dependency direction).

use std::collections::HashMap;
use std::path::Path;

use nau_core::snap_types::PackageInput;

use crate::lock::LockFile;
use crate::pkg_source::{default_input_map, pin_update_line};

pub fn cmd_deps(
    package: String,
    recursive: bool,
    tree: bool,
    flat: bool,
    json: bool,
) -> miette::Result<()> {
    crate::pkg_source::init_global_inputs(&HashMap::new())?;
    let names = vec![package.clone()];
    let nodes = crate::deps::resolve_deps(&names, recursive)?;

    if nodes.is_empty() {
        if json {
            return Ok(());
        }
        eprintln!("No dependencies found for '{}'", package);
        return Ok(());
    }

    if json {
        report_deps_json(&nodes);
    } else {
        report_deps_human(&package, &nodes, tree, recursive, flat)?;
    }

    Ok(())
}

/// JSON-mode dependency report.
fn report_deps_json(nodes: &[crate::deps::DepNode]) {
    let seen: std::collections::HashSet<&str> = nodes
        .iter()
        .flat_map(|n| n.requires.iter().chain(&n.build_deps))
        .map(|s| s.as_str())
        .collect();
    for node in nodes {
        let kind = if seen.contains(node.name.as_str()) {
            "direct"
        } else {
            "transitive"
        };
        nau_infra::output::record_dep_result(nau_infra::output::DepResultJson {
            name: node.name.clone(),
            requires: node.requires.clone(),
            build_deps: node.build_deps.clone(),
            kind: kind.to_string(),
        });
    }
}

/// Text-mode dependency report (tree / flat / direct-requires views).
fn report_deps_human(
    package: &str,
    nodes: &[crate::deps::DepNode],
    tree: bool,
    recursive: bool,
    flat: bool,
) -> miette::Result<()> {
    if tree && recursive {
        eprintln!("Dependency tree for '{}':", package);
        let names = vec![package.to_string()];
        let tree_str = crate::deps::format_tree(&names, true)?;
        eprintln!("{}", tree_str);
    } else if flat {
        let names_only: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        eprintln!("Build order for '{}':", package);
        for (i, name) in names_only.iter().enumerate() {
            eprintln!("  {}. {}", i + 1, name);
        }
    } else if let Some(pkg) = nodes.first() {
        eprintln!("{} v1.0: {}", package, pkg.name);
        if pkg.requires.is_empty() && pkg.build_deps.is_empty() {
            eprintln!("  No dependencies");
        } else {
            eprintln!("  Requires:");
            for dep in &pkg.requires {
                eprintln!("    - {}", dep);
            }
            if !pkg.build_deps.is_empty() {
                eprintln!("  Build deps:");
                for dep in &pkg.build_deps {
                    eprintln!("    - {}", dep);
                }
            }
            if recursive {
                eprintln!("  (use --tree or --flat for full transitive resolution)");
            }
        }
    }

    Ok(())
}

// ── Image command ──

#[allow(clippy::too_many_arguments)]
/// Pin the build epoch when the flag carries one (the env form is
/// already exported — the release gate requires one or the other).
pub fn cmd_check(file: &str, json: bool) -> miette::Result<()> {
    // Stage 1 — analyzer gate. A definition that does not type-check never
    // reaches the eval stage.
    let analyzer_diagnostics = crate::analysis::check_definition_file(file);
    let mut diagnostics: Vec<crate::lua::CheckDiagnostic> = analyzer_diagnostics
        .into_iter()
        .map(|d| crate::lua::CheckDiagnostic::from_analyzer(file, d))
        .collect();

    // Stage 2 — bounded subprocess eval + Rust-side validation (unchanged
    // path; the analyzer is check-only). `None` when stage 1 failed fast.
    let checked = if diagnostics.is_empty() {
        Some(crate::lua::check_file_with_inputs(file))
    } else {
        None
    };

    if let Some(checked) = &checked {
        diagnostics.extend(checked.diagnostics.clone());
        // A hard eval failure is a diagnostic too, so both output modes carry
        // the complete problem list in one shape.
        if let Some(err) = &checked.error {
            diagnostics.push(crate::lua::CheckDiagnostic {
                label: file.to_string(),
                key: None,
                expected: None,
                actual: None,
                message: err.clone(),
                span: None,
            });
        }
    }
    let ok = checked.as_ref().is_some_and(|c| c.error.is_none()) && diagnostics.is_empty();

    // ADR-0011 step (g): the confinement lint over the evaluated outputs
    // (Rust-side stage 2, never the Lua analyzer). WARNING severity — the
    // lint NEVER adds a failure mode: `ok` above is computed before it
    // runs, and its findings travel a separate channel (warn output /
    // `"lint"` JSON array), never the diagnostics list.
    let lint: Vec<crate::lint::LintWarning> = checked
        .as_ref()
        .filter(|c| c.error.is_none())
        .map(|c| crate::lint::confinement_lint(&c.outputs))
        .unwrap_or_default();
    for w in &lint {
        nau_infra::output::warn(&w.message);
    }

    let outputs: Vec<(String, String)> = checked
        .as_ref()
        .map(|c| {
            let mut pairs: Vec<(String, String)> = c
                .outputs
                .iter()
                // adopt-info outputs have no version until build time — the
                // placeholder must never read as a declared version.
                .map(|(name, meta)| (name.clone(), meta.display_version().to_string()))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs
        })
        .unwrap_or_default();

    if json {
        let names: Vec<String> = outputs.iter().map(|(n, _)| n.clone()).collect();
        report_check_json(file, &names, &diagnostics, &lint);
    } else if ok {
        report_check_ok(&outputs);
    } else {
        for d in &diagnostics {
            report_check_diagnostic(d);
        }
    }

    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// `--json` report: every diagnostic is self-contained — one optional nested
/// `"span"` object (per-diagnostic span fields, not a top-level `"spans"`
/// array). `"lint"` carries the confinement lint warnings (step (g)) —
/// warnings, never failures; they never appear in `"diagnostics"`.
fn report_check_json(
    file: &str,
    outputs: &[String],
    diagnostics: &[crate::lua::CheckDiagnostic],
    lint: &[crate::lint::LintWarning],
) {
    let diags: Vec<serde_json::Value> = diagnostics
        .iter()
        .map(|d| {
            serde_json::json!({
                "label": d.label,
                "key": d.key,
                "expected": d.expected,
                "actual": d.actual,
                "message": d.message,
                "span": d.span.as_ref().map(|s| serde_json::json!({
                    "begin_line": s.begin_line,
                    "begin_col": s.begin_col,
                    "end_line": s.end_line,
                    "end_col": s.end_col,
                })),
            })
        })
        .collect();
    let lint_json: Vec<serde_json::Value> = lint
        .iter()
        .map(|w| {
            serde_json::json!({
                "key": w.key,
                "message": w.message,
            })
        })
        .collect();
    let report = serde_json::json!({
        "file": file,
        "ok": diagnostics.is_empty(),
        "outputs": outputs,
        "diagnostics": diags,
        "lint": lint_json,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Success message for `nau check` — each output shown with its
/// version so the declared identity is visible, not just the name.
pub fn check_ok_message(outputs: &[(String, String)]) -> String {
    let list = if outputs.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = outputs
            .iter()
            .map(|(name, version)| format!("{name} {version}"))
            .collect();
        format!(": {}", items.join(", "))
    };
    format!("ok: {} output(s){list}", outputs.len())
}

fn report_check_ok(outputs: &[(String, String)]) {
    nau_infra::output::ok(check_ok_message(outputs));
}

fn report_check_diagnostic(d: &crate::lua::CheckDiagnostic) {
    match (&d.key, &d.span) {
        // Keyed diagnostics with a located declaration site show both: the
        // file:line:col prefix (grep-friendly, matches the analyzer arm)
        // plus the output key in brackets.
        (Some(key), Some(s)) => nau_infra::output::err(format!(
            "{}:{}:{}: [{key}] {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (Some(key), None) => nau_infra::output::err(format!("{}[{key}]: {}", d.label, d.message)),
        // Analyzer diagnostics print with their 1-based begin span.
        (None, Some(s)) => nau_infra::output::err(format!(
            "{}:{}:{}: {}",
            d.label, s.begin_line, s.begin_col, d.message
        )),
        (None, None) => nau_infra::output::err(&d.message),
    }
}

// ── Lint command (issue #53) ──

/// Load the package index the same way the eval worker does
/// (`NAU_INDEX_PATH`, else `package-index.json` in the CWD).
pub fn lint_index() -> miette::Result<crate::index::PackageIndex> {
    let path = std::env::var("NAU_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::index::DEFAULT_INDEX));
    crate::index::PackageIndex::load_or_default(&path)
}

/// The declared stage directory of a definition file, when it exists:
/// `<definition dir>/stage` — the same default the build uses.
pub fn lint_stage_dir(file: &str) -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new(file)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let stage = dir.join("stage");
    stage.is_dir().then_some(stage)
}

/// One pod package's lint entry: resolved meta when the package resolves
/// from local inputs, `None` (warned later) when it does not.
fn lint_finding_lines(f: &crate::checks::Finding, label: &str) -> String {
    format!(
        "[{}] {label}: {} {}: {}\n           fix: {}",
        f.severity.as_str(),
        f.check,
        f.package,
        f.message,
        f.hint
    )
}

/// Human report: every finding on its channel, then a one-line summary.
pub fn report_lint_human(findings: &[crate::checks::Finding], label: &str) {
    for f in findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            crate::checks::Severity::Error => nau_infra::output::err(lines),
            crate::checks::Severity::Warn => nau_infra::output::warn(lines),
        }
    }
    if findings.is_empty() {
        nau_infra::output::ok("lint clean: 0 findings");
    } else {
        let errors = findings
            .iter()
            .filter(|f| f.severity == crate::checks::Severity::Error)
            .count();
        nau_infra::output::status(format!(
            "lint: {errors} error(s), {} warning(s)",
            findings.len() - errors
        ));
    }
}

/// JSON report shape for `nau lint --json`.
pub fn report_lint_json(findings: &[crate::checks::Finding], label: &str) {
    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "check": f.check,
                "package": f.package,
                "severity": f.severity.as_str(),
                "message": f.message,
                "hint": f.hint,
            })
        })
        .collect();
    let errors = findings
        .iter()
        .filter(|f| f.severity == crate::checks::Severity::Error)
        .count();
    let report = serde_json::json!({
        "file": label,
        "ok": errors == 0,
        "errors": errors,
        "warnings": findings.len() - errors,
        "findings": findings_json,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}

/// `nau lint`: run the check battery over a definition file (or a
/// pod's packages) and report findings. Exit code 1 only on error findings.
fn report_audit_human(report: &crate::audit::AuditReport, label: &str, cache_dir: &Path) {
    for f in &report.findings {
        let lines = lint_finding_lines(f, label);
        match f.severity {
            crate::checks::Severity::Error => nau_infra::output::err(lines),
            crate::checks::Severity::Warn => nau_infra::output::warn(lines),
        }
    }
    if report.findings.is_empty() {
        nau_infra::output::ok("audit clean: 0 findings");
    } else {
        let errors = report
            .findings
            .iter()
            .filter(|f| f.severity == crate::checks::Severity::Error)
            .count();
        nau_infra::output::status(format!(
            "audit: {} lockfile pin(s), {errors} error(s), {} warning(s)",
            report.targets,
            report.findings.len() - errors
        ));
    }
    if report.degraded {
        nau_infra::output::warn(format!(
            "OSV database unreachable (offline?) — {} pin(s) left unaudited; run \
             `nau audit --update` when online (cache: {})",
            report.unaudited,
            cache_dir.display()
        ));
    }
}

/// JSON report: the `nau lint --json` shape (file/ok/errors/warnings/
/// findings) plus an additive `database` object for the audit counters.
fn report_audit_json(report: &crate::audit::AuditReport, label: &str) {
    let findings_json: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "check": f.check,
                "package": f.package,
                "severity": f.severity.as_str(),
                "message": f.message,
                "hint": f.hint,
            })
        })
        .collect();
    let errors = report
        .findings
        .iter()
        .filter(|f| f.severity == crate::checks::Severity::Error)
        .count();
    let out = serde_json::json!({
        "file": label,
        "ok": errors == 0,
        "errors": errors,
        "warnings": report.findings.len() - errors,
        "findings": findings_json,
        "database": {
            "degraded": report.degraded,
            "unaudited": report.unaudited,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    );
}

/// `nau audit`: check lockfile pins against the OSV vulnerability
/// database (issue #52). Exit code 1 only on confirmed (version-matched)
/// findings; offline/stale databases warn, never fail.
pub fn cmd_audit(
    file: Option<String>,
    lockfile: String,
    update: bool,
    json: bool,
) -> miette::Result<()> {
    nau_infra::output::set_mode(json);
    let lock_path = Path::new(&lockfile);
    let Some(lock) = LockFile::load(lock_path)? else {
        miette::bail!(
            "no lockfile at '{lockfile}' — nothing to audit (build once to create it, \
             or pass --lockfile)"
        );
    };
    // An explicitly-given definition enriches the audit (declared
    // versions, output-key labels); a failing eval is a hard error.
    let raw = match &file {
        Some(f) => Some(crate::lua::lint_eval_file(f)?.raw),
        None => None,
    };

    let cfg = crate::audit::AuditConfig::from_env(update);
    let report = crate::audit::run_audit(&lock, raw.as_ref(), &cfg)?;

    if json {
        report_audit_json(&report, &lockfile);
    } else {
        report_audit_human(&report, &lockfile, &cfg.cache_dir);
    }

    if crate::checks::has_errors(&report.findings) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Lock command ──

/// `nau lock`: resolve/refresh all input pins without building.
pub fn cmd_lock(file: String, lockfile_path: String) -> miette::Result<()> {
    let inputs = resolve_lock_inputs(&file)?;

    let lock_path = Path::new(&lockfile_path);
    let mut lockfile = LockFile::load(lock_path)?.unwrap_or_else(|| LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    });

    // Empty names = refresh every declared input. All pins are resolved
    // before any is applied: a failed refresh never half-updates the lock.
    let updates = crate::pkg_source::update_input_pins(&inputs, &[], &mut lockfile)?;

    report_lock_status(&updates, &lockfile);

    lockfile.save(lock_path)?;

    report_lock_output(&lockfile, &lockfile_path, updates.len())?;
    Ok(())
}

/// The inputs a `nau lock` run refreshes: the definition's global
/// inputs when the config exists and declares any, the default input
/// otherwise.
fn resolve_lock_inputs(file: &str) -> miette::Result<HashMap<String, PackageInput>> {
    let inputs = if Path::new(file).exists() {
        match crate::lua::evaluate_file_with_inputs(file) {
            Ok(eval) if !eval.global_inputs.is_empty() => eval.global_inputs,
            Ok(_) => {
                nau_infra::output::info(format!("no inputs declared in '{file}', using default"));
                default_input_map()
            }
            Err(e) => {
                return Err(miette::miette!("failed to read inputs from '{file}': {e}"));
            }
        }
    } else {
        nau_infra::output::info(format!("no config at '{file}', using default input"));
        default_input_map()
    };
    Ok(inputs)
}

/// Status lines for a lock run: each refreshed pin (old→new), then every
/// pin currently recorded in the lockfile.
fn report_lock_status(updates: &[crate::pkg_source::InputPinUpdate], lockfile: &LockFile) {
    for u in updates {
        nau_infra::output::status(pin_update_line(u));
    }
    for (name, entry) in &lockfile.inputs {
        if entry.local {
            nau_infra::output::status(format!("{name}: local (unlocked)"));
        } else if let Some(rev) = &entry.revision {
            nau_infra::output::status(format!("{name}: pinned to {}", rev.get(..7).unwrap_or(rev)));
        }
    }
}

/// JSON/human output tail for `nau lock` (the lockfile is already
/// saved by the time this runs).
fn report_lock_output(
    lockfile: &LockFile,
    lockfile_path: &str,
    updated: usize,
) -> miette::Result<()> {
    if nau_infra::output::is_json() {
        let mut pins: Vec<nau_infra::output::LockPinJson> = lockfile
            .inputs
            .iter()
            .map(|(name, e)| nau_infra::output::LockPinJson {
                name: name.clone(),
                local: e.local,
                revision: e.revision.clone(),
                sha256: e.sha256.clone(),
            })
            .collect();
        pins.sort_by(|a, b| a.name.cmp(&b.name));
        let out = nau_infra::output::LockOutputJson {
            command: "lock".to_string(),
            lockfile: lockfile_path.to_string(),
            updated,
            pins,
        };
        let json = serde_json::to_string_pretty(&out)
            .map_err(|e| miette::miette!("failed to serialize lock output: {e}"))?;
        println!("{json}");
    } else {
        nau_infra::output::ok(format!("{} input(s) locked -> {lockfile_path}", updated));
    }
    Ok(())
}

// ── Eval command ──

/// `nau eval`: evaluate a definition and emit the image manifest IR
/// (Phase 23, cross-distro-synthesis §5). No build, no store writes.
///
/// Resolution is data-only — definition pins, the Phase 16 lockfile, and
/// pre-resolved package-index pins — so a fully pinned project evals
/// offline and the result is a deterministic function of the definition +
/// lockfile. `--offline` additionally forbids fetching uncached package
/// inputs (named fail-closed error, same as build). Unresolvable pins and
/// missing lock entries fail closed: no partial manifest is ever written.
#[allow(clippy::too_many_arguments)]
fn fuzzy_score(query: &str, target: &str) -> u32 {
    let q = query.to_lowercase();
    let t = target.to_lowercase();

    if q.is_empty() || t.is_empty() {
        return 0;
    }

    if t == q {
        return 100;
    }
    if t.starts_with(&q) {
        return 90;
    }
    if t.contains(&q) {
        return 80;
    }

    // Subsequence matching: characters of query appear in order in target
    let q_chars: Vec<char> = q.chars().collect();
    let t_chars: Vec<char> = t.chars().collect();
    let mut qi = 0;
    let mut prev_match: Option<usize> = None;
    let mut consecutive = 0u32;
    let mut max_consecutive = 0u32;
    let mut gaps = 0u32;

    for (ti, tc) in t_chars.iter().enumerate() {
        if qi < q_chars.len() && *tc == q_chars[qi] {
            if let Some(prev) = prev_match {
                if ti == prev + 1 {
                    consecutive += 1;
                } else {
                    gaps += (ti - prev - 1) as u32;
                    consecutive = 0;
                }
            } else {
                consecutive = 1;
            }
            max_consecutive = max_consecutive.max(consecutive);
            prev_match = Some(ti);
            qi += 1;
        }
    }

    if qi < q_chars.len() {
        return 0; // not all query chars matched
    }

    let base = 60u32;
    let consec_bonus = (max_consecutive.saturating_sub(1)) * 5;
    let gap_penalty = gaps.min(20);
    base + consec_bonus - gap_penalty
}

pub fn cmd_search(query: &str, json: bool) {
    // Ensure global inputs are initialized for iter_packages
    let _ = crate::pkg_source::init_global_inputs(&HashMap::new());

    let candidates = crate::pkg_source::iter_packages();
    let mut scored: Vec<(u32, String)> = Vec::new();

    // Score all candidates
    for name in &candidates {
        let score = fuzzy_score(query, name);
        if score > 0 {
            scored.push((score, name.clone()));
        }
    }

    // Sort: highest score first, then alphabetically
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    if json {
        let results: Vec<&str> = scored.iter().map(|(_, n)| n.as_str()).collect();
        println!(
            "{}",
            serde_json::json!({
                "command": "search",
                "query": query,
                "results": results
            })
        );
    } else {
        eprintln!("Packages matching '{}':", query);
        if scored.is_empty() {
            eprintln!("  (no matches)");
        } else {
            for (_, name) in &scored {
                eprintln!("  {}", name);
            }
            eprintln!("  {} package(s) found", scored.len());
        }
    }
}

// ── Completion command ──
