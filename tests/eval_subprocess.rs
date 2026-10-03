//! Subprocess eval bounding (ADR-0010 Decisions 4+5).
//!
//! Integration tests over the real `nau __eval-worker` subprocess + IPC
//! path: happy-path eval, require-over-IPC with parent-side root
//! allowlisting, and the adversarial suite ported from
//! `spike/src/gates.rs` to Luau (containment: <5s wall, under rlimits,
//! parent unaffected, clean diagnostics).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nau::isolate::{self, EvalRequest, WorkerOutcome};
use nau::lua::{evaluate_file, evaluate_file_with_constraint, evaluate_string};

fn request(entry_label: &str, source: &str) -> EvalRequest {
    EvalRequest {
        prelude: nau::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: BTreeMap::new(),
        entry: source.to_string(),
        entry_label: entry_label.to_string(),
        allow_fetch: false,
        constraint: None,
        versions_mode: false,
    }
}

fn eval_err(label: &str, source: &str) -> String {
    match evaluate_string(label, source) {
        Ok(_) => panic!("expected eval of {label} to fail"),
        Err(e) => format!("{e:#}"),
    }
}

// ── Happy paths ──

#[test]
fn happy_path_eval_through_subprocess() {
    let src = r#"
    return {
        default = snap {
            name = "sub-test",
            version = "1.2.3",
            summary = "evaluated in the worker",
            architectures = { "amd64", "arm64" },
        },
    }"#;
    let outputs = evaluate_string("inline-test", src)
        .expect("happy-path eval through the subprocess must succeed");
    assert_eq!(outputs.len(), 1);
    let meta = &outputs["default"];
    assert_eq!(meta.name, "sub-test");
    assert_eq!(meta.version, "1.2.3");
    assert_eq!(
        meta.architectures.as_deref(),
        Some(&["amd64".to_string(), "arm64".to_string()][..])
    );
}

#[test]
fn require_goes_over_ipc_and_resolves_from_entry_dir() {
    // Full path: parent reads the file, ships it to the worker; the
    // definition's require() crosses back over IPC and the parent resolves
    // it from the entry file's directory (allowlisted root).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("nau.lua"),
        r#"
local base = require("base")
return { default = snap(merge(base, { name = "composed", version = "9.9.9" })) }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("base.lua"),
        r#"return { version = "0.1.0", summary = "from base" }"#,
    )
    .unwrap();

    let entry = dir.path().join("nau.lua");
    let outputs = evaluate_file(entry.to_str().unwrap())
        .expect("require over IPC must resolve the sibling module");
    assert_eq!(outputs["default"].name, "composed");
    // merge(): the entry overrides the module's version…
    assert_eq!(outputs["default"].version, "9.9.9");
    // …and the module-only field proves the require crossed the IPC boundary.
    assert_eq!(outputs["default"].summary.as_deref(), Some("from base"));
}

#[test]
fn preseeded_sources_load_without_filesystem() {
    let mut req = request("preseed-test", r#"return { v = require("libmod").v }"#);
    req.sources
        .insert("libmod".to_string(), "return { v = 7 }".to_string());
    let ok = isolate::run_eval(&req).expect("preseeded module must load");
    assert_eq!(ok.outputs["v"], 7);
}

#[test]
fn global_inputs_cross_back_as_data() {
    let src = r#"
inputs = { core = { url = "github:core/core22/main" } }
return { default = snap { name = "with-inputs", version = "1.0" } }
"#;
    let out = nau::lua::evaluate_string_with_inputs("inputs-test", src)
        .expect("inputs must be extracted through the subprocess");
    assert_eq!(out.outputs["default"].name, "with-inputs");
    assert_eq!(out.global_inputs["core"].url, "github:core/core22/main");
}

// ── Definition-relative resolution plumbing ──

#[test]
fn file_label_threads_definition_dir_into_outputs() {
    // A file-path label must land in every output's definition_dir so
    // hook/icon paths resolve relative to the definition first.
    let dir = tempfile::tempdir().unwrap();
    let def = dir.path().join("nau.lua");
    std::fs::write(
        &def,
        r#"return { default = snap { name = "wired", version = "1.0" } }"#,
    )
    .unwrap();
    let checked = nau::lua::check_file_with_inputs(def.to_str().unwrap());
    assert!(checked.error.is_none(), "{:?}", checked.error);
    let meta = &checked.outputs["default"];
    assert_eq!(meta.definition_dir.as_deref(), Some(dir.path()));
}

#[test]
fn embedded_label_has_no_definition_dir() {
    let checked = nau::lua::check_string_with_inputs(
        "embedded:test",
        r#"return { default = snap { name = "embedded-snap", version = "1.0" } }"#,
    );
    assert!(checked.error.is_none(), "{:?}", checked.error);
    let meta = &checked.outputs["default"];
    assert!(meta.definition_dir.is_none());
}

// ── Resolver policy (parent side) ──

#[test]
fn resolver_rejects_parent_traversal() {
    let src = r#"return { v = require("../secret").v }"#;
    let err = eval_err("resolver-traversal", src);
    assert!(
        err.contains("rejected"),
        "traversal must be rejected on the parent side, got: {err}"
    );
}

#[test]
fn resolver_rejects_absolute_path() {
    let src = r#"return { v = require("/etc/passwd") }"#;
    let err = eval_err("resolver-absolute", src);
    assert!(
        err.contains("rejected"),
        "absolute paths must be rejected on the parent side, got: {err}"
    );
}

#[test]
fn resolver_rejects_missing_module_outside_roots() {
    let src = r#"return { v = require("no-such-module-anywhere") }"#;
    let err = eval_err("resolver-missing", src);
    assert!(err.contains("not found in allowlisted roots"), "got: {err}");
}

// ── Adversarial suite (ported from spike/src/gates.rs) ──

/// Assert an adversarial run was contained: bounded wall time, no Ok
/// outcome, and (when the worker answered) a clean error diagnostic.
fn assert_contained(run: &isolate::EvalRun) {
    assert!(
        run.wall_ms < 5500.0,
        "case escaped the 5s wall-clock budget: {}ms, status {}",
        run.wall_ms,
        run.status.describe()
    );
    match &run.outcome {
        Some(WorkerOutcome::Ok(_)) => panic!("adversarial case must not succeed"),
        Some(WorkerOutcome::Err(err)) => {
            assert!(!err.diagnostics.is_empty(), "worker must send diagnostics");
        }
        None => {
            // Worker died before answering (rlimit kill): still contained,
            // the parent reports it as a clean failure.
        }
    }
}

#[test]
fn fuzz_deep_recursion_is_contained() {
    // Luau `let`/`local` is non-recursive: the self-application idiom
    // creates genuine unbounded recursion (`f f 100000000`).
    let src = r#"
local f = function(self, n)
    if n == 0 then return 0 else return 1 + self(self, n - 1) end
end
return { value = f(f, 100000000), name = "x", version = "1" }
"#;
    let run = isolate::run_eval_raw(&request("fuzz-deep-recursion", src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
    assert!(
        run.max_rss_kb < 512 * 1024,
        "worker stayed under the 512MB rlimit, peak was {}kB",
        run.max_rss_kb
    );
}

#[test]
fn fuzz_huge_string_growth_is_contained() {
    // Tiny source, exponential string doubling → allocation blowup.
    let mut src = String::from("local s0 = \"0123456789012345678901234567890123456789\"\n");
    for i in 1..=32 {
        let prev = i - 1;
        src.push_str(&format!("  local s{i} = s{prev} .. s{prev}\n"));
    }
    src.push_str("return { value = s32, name = \"x\", version = \"1\" }");

    let run = isolate::run_eval_raw(&request("fuzz-huge-literal", &src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
    assert!(
        run.max_rss_kb < 512 * 1024,
        "worker stayed under the 512MB rlimit, peak was {}kB",
        run.max_rss_kb
    );
}

#[test]
fn fuzz_deep_table_growth_is_contained() {
    let src = "local t = {}\nfor i = 1, 100000000 do t = { t } end\nreturn { value = t, name = \"x\", version = \"1\" }";
    let run = isolate::run_eval_raw(&request("fuzz-deep-table", src))
        .expect("parent must survive the adversarial case");
    assert_contained(&run);
}

#[test]
fn fuzz_contract_violation_is_a_clean_fast_diagnostic() {
    // Contract-style type error: snap() validates eagerly and raises, so the
    // eval fails fast with a clean diagnostic (never a crash or a hang).
    let src = r#"return { default = snap { name = 42, version = "1.0" } }"#;
    let start = Instant::now();
    let err = eval_err("fuzz-contract", src);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "contained in {elapsed:?}");
    assert!(err.contains("field 'name' must be a string"), "got: {err}");
}

#[test]
fn fuzz_busy_loop_hits_wall_clock_deadline() {
    let src = "while true do end";
    let start = Instant::now();
    let err = eval_err("fuzz-busy-loop", src);
    let elapsed = start.elapsed();
    // The parent killed the worker at the deadline and reports a clean error.
    assert!(
        elapsed >= Duration::from_millis(4500),
        "deadline fired too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "parent took too long to regain control: {elapsed:?}"
    );
    assert!(
        err.contains("deadline") || err.contains("signalled") || err.contains("signal"),
        "timeout must be reported as a clean diagnostic, got: {err}"
    );
}

// ── StdLib narrowing (ADR-0010 Decision 4) ──

#[test]
fn worker_has_no_os_library_determinism() {
    let src = r#"return { t = os.time(), name = "x", version = "1" }"#;
    let err = eval_err("stdlib-os", src);
    assert!(
        err.to_lowercase().contains("nil"),
        "`os` must be absent in the worker VM, got: {err}"
    );
}

#[test]
fn worker_has_no_debug_library() {
    let src = r#"return { t = debug.traceback(), name = "x", version = "1" }"#;
    let err = eval_err("stdlib-debug", src);
    assert!(
        err.to_lowercase().contains("nil"),
        "`debug` must be absent in the worker VM, got: {err}"
    );
}

// ── Fatal-eval semantics preserved across the boundary ──

#[test]
fn non_table_result_fails_with_original_message() {
    let err = eval_err("non-table", "return 42");
    assert!(
        err.contains("must return a table of outputs, got integer"),
        "got: {err}"
    );
}

#[test]
fn broken_output_is_skipped_with_warning_not_silently_dropped() {
    let src = r#"
    return {
        good = snap { name = "good-snap", version = "1.0" },
        bad = "not-a-snap-table",
    }
    "#;
    let outputs = evaluate_string("test-broken", src)
        .expect("broken output should warn and be skipped, not fail the eval");
    assert_eq!(outputs.len(), 1, "only the valid output should be kept");
    assert!(outputs.contains_key("good"));
}

#[test]
fn composed_config_via_evaluate_file() {
    let result = evaluate_file("test-fixtures/composed.lua");
    assert!(
        result.is_ok(),
        "composed config should evaluate: {:?}",
        result.err()
    );

    let outputs = result.unwrap();
    assert!(outputs.contains_key("default"));

    let meta = &outputs["default"];
    assert_eq!(meta.name, "my-composed-app");
    assert_eq!(meta.version, "1.0.0");
    // From the base template via merge
    assert_eq!(meta.summary.as_deref(), Some("A snap built with nau"));
    assert_eq!(meta.grade, "stable");
    assert_eq!(meta.confinement, "strict");
}

// ── Phase 15: complete snap.yaml coverage round-trip ──

#[test]
fn phase15_fields_survive_subprocess_round_trip() {
    // The full Phase 15 surface must survive the real worker subprocess:
    // Lua eval → lua_to_json → json_to_lua → SnapMeta.
    use nau::snap::{LayoutEntry, SnapPlug, TmpfsSpec};

    let outputs = evaluate_string(
        "phase15-round-trip",
        r#"
        return {
            default = snap {
                name = "round-trip",
                version = "3.1",
                type = "gadget",
                compression = "xz",
                icon = "icon.svg",
                environment = { VAR_A = "a", VAR_B = "b" },
                layout = {
                    ["/etc/app.conf"] = { bind_file = "$SNAP_DATA/etc/app.conf" },
                    ["/run/app"] = { tmpfs = true },
                    ["/var/app"] = { tmpfs = { size = "10M" } },
                },
                hooks = { configure = "scripts/configure.sh" },
                plugs = {
                    network = "network",
                    ["shared-data"] = {
                        interface = "content",
                        content = "c1",
                        target = "$SNAP/data",
                    },
                },
                slots = {
                    ["content-slot"] = { interface = "content", content = "c1" },
                },
            },
        }
        "#,
    )
    .expect("round-trip eval must succeed");

    let meta = &outputs["default"];
    assert_eq!(meta.name, "round-trip");
    assert_eq!(meta.type_.as_deref(), Some("gadget"));
    assert_eq!(meta.compression.as_deref(), Some("xz"));
    assert_eq!(meta.icon.as_deref(), Some("meta/gui/icon.svg"));
    assert_eq!(
        meta.environment
            .as_ref()
            .unwrap()
            .get("VAR_A")
            .map(String::as_str),
        Some("a")
    );
    let layout = meta.layout.as_ref().unwrap();
    assert_eq!(
        layout["/etc/app.conf"],
        LayoutEntry::BindFile("$SNAP_DATA/etc/app.conf".into())
    );
    assert_eq!(
        layout["/run/app"],
        LayoutEntry::Tmpfs(TmpfsSpec::Bare(true))
    );
    assert_eq!(
        layout["/var/app"],
        LayoutEntry::Tmpfs(TmpfsSpec::Sized { size: "10M".into() })
    );
    let hooks = meta.hooks.as_ref().unwrap();
    assert_eq!(hooks["configure"].command, "meta/hooks/configure");
    assert_eq!(hooks["configure"].source, "scripts/configure.sh");
    assert_eq!(
        meta.plugs.as_ref().unwrap()["network"],
        SnapPlug::Name("network".into())
    );
    match &meta.plugs.as_ref().unwrap()["shared-data"] {
        SnapPlug::Typed(p) => {
            assert_eq!(p.interface, "content");
            assert_eq!(
                p.attributes.get("target").map(String::as_str),
                Some("$SNAP/data")
            );
        }
        other => panic!("expected Typed plug, got {other:?}"),
    }
    match &meta.slots.as_ref().unwrap()["content-slot"] {
        SnapPlug::Typed(p) => assert_eq!(p.interface, "content"),
        other => panic!("expected Typed slot, got {other:?}"),
    }
}

// ── The eval-context constraint (ADR-0047 Decision 4) ──
//
// The request carries the pod spec's `@constraint`; the worker exposes it
// as the `constraint` global (nil when absent). These tests drive the real
// subprocess: the parent builds the request, the child's recipe reads the
// global — the exact boundary `load_meta_for` rides at pod resolution.

/// The lined recipe shape of pkgs/n/node.lua: select by constraint,
/// default to the current line, refuse an undeclared line.
const LINED: &str = r#"
local lines = {
    ["26"] = { version = "26.7.0" },
    ["22"] = { version = "22.23.3" },
}
local line = constraint or "26"
local picked = lines[line]
if picked == nil then
    error("lined: constraint '@" .. tostring(line) .. "' selects no declared line")
end
return { default = snap { name = "lined", version = picked.version } }
"#;

#[test]
fn constraint_global_absent_means_nil_in_the_recipe() {
    let req = request("constraint-nil", r#"return { v = type(constraint) }"#);
    let ok = isolate::run_eval(&req).expect("eval must succeed");
    assert_eq!(ok.outputs["v"], "nil");
}

#[test]
fn constraint_global_rides_the_request_into_the_recipe() {
    let mut req = request("constraint-22", r#"return { v = constraint }"#);
    req.constraint = Some("22".to_string());
    let ok = isolate::run_eval(&req).expect("eval must succeed");
    assert_eq!(ok.outputs["v"], "22");
}

#[test]
fn constraint_selects_the_line_through_the_subprocess() {
    let mut req = request("line-22", LINED);
    req.constraint = Some("22".to_string());
    let ok = isolate::run_eval(&req).expect("line selection must succeed");
    assert_eq!(ok.outputs["default"]["version"], "22.23.3");
}

#[test]
fn unconstrained_eval_selects_the_default_line() {
    let req = request("line-default", LINED);
    let ok = isolate::run_eval(&req).expect("default line must select");
    assert_eq!(ok.outputs["default"]["version"], "26.7.0");
}

#[test]
fn undeclared_line_refuses_through_the_subprocess() {
    let mut req = request("line-missing", LINED);
    req.constraint = Some("20".to_string());
    match isolate::run_eval(&req) {
        Err(e) => {
            let msg = format!("{e:#}");
            assert!(
                msg.contains("selects no declared line"),
                "refusal must name the missing line: {msg}"
            );
        }
        Ok(_) => panic!("an undeclared line must refuse, not fall back"),
    }
}

// ── The REAL pkgs/n/node.lua (ticket #278) ──
//
// The shipped recipe must select both lines at the eval boundary: the
// current 26 line when unconstrained, the LTS 22 line under `node@22`,
// and refuse a constraint naming no declared line. This is the
// selection half of ADR-0047's "line selection must be reproducible
// from the lockfile pin" — no build, no network, just the recipe.

fn repo_recipe(rel: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn real_node_recipe_defaults_to_the_26_line() {
    let outputs = evaluate_file(&repo_recipe("pkgs/n/node.lua"))
        .expect("the real node recipe must eval unconstrained");
    let meta = &outputs["default"];
    assert_eq!(meta.name, "node");
    assert_eq!(meta.version, "26.7.0");
    // The ADR-0047 wrapper invariant landed: npm/npx are declared apps
    // wrapping the bare interpreter name.
    assert!(meta.apps.contains_key("node"));
    let npm = &meta.apps["npm"];
    assert_eq!(npm.interpreter.as_deref(), Some("node"));
    assert_eq!(npm.command, "usr/bin/npm");
    assert_eq!(meta.apps["npx"].interpreter.as_deref(), Some("node"));
}

#[test]
fn real_node_recipe_selects_the_22_line_under_the_constraint() {
    let outputs = evaluate_file_with_constraint(&repo_recipe("pkgs/n/node.lua"), Some("22"))
        .expect("the real node recipe must eval at @22");
    let meta = &outputs["default"];
    assert_eq!(meta.name, "node", "one package, two lines — no rename");
    assert_eq!(meta.version, "22.23.3");
    match &meta.source {
        Some(nau::snap::SourceSpec::Pinned { url, sha256 }) => {
            assert_eq!(
                url,
                "https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz"
            );
            assert_eq!(
                sha256,
                "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de"
            );
        }
        other => panic!("expected pinned 22-line source, got {other:?}"),
    }
    // The build carries the bootstrap fix verbatim (rm precedes the
    // bootstraps): the staged entries require npm's own entry files in
    // place, so the #9 wrapper's tree exec keeps npm's require anchor.
    let build = meta.build.as_deref().expect("node build declared");
    assert!(
        build.contains("rm $STAGE/usr/bin/npm $STAGE/usr/bin/npx")
            && build.contains("require('../lib/node_modules/npm/bin/npm-cli.js')")
            && build.contains("require('../lib/node_modules/npm/bin/npx-cli.js')"),
        "the stashed bootstrap fix must be in the build: {build}"
    );
    // The apps bind unsuffixed to the pod's selected line.
    assert_eq!(meta.apps["npm"].interpreter.as_deref(), Some("node"));
    assert_eq!(meta.apps["npx"].command, "usr/bin/npx");
}

#[test]
fn real_node_recipe_refuses_a_dropped_line() {
    let err = evaluate_file_with_constraint(&repo_recipe("pkgs/n/node.lua"), Some("20"))
        .expect_err("a constraint naming no declared line must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("selects no declared line") && msg.contains("@20"),
        "refusal must name the constraint: {msg}"
    );
}
