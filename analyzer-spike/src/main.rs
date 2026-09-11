//! Spike harness: runs the four check cases and measures latency.
//!
//! Run: `cargo run --release` (subcommands not needed — one pass prints all).

use analyzer_spike::{check_once, Checker, Diagnostic};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

// --- sources ---------------------------------------------------------------

const PRELUDE_DECL: &str = r#"
--!strict
-- Stand-in for shuttle's typed prelude (what loadDefinitionFile or a seeded
-- module would provide). Typed snap/merge/app signatures, no implementation.
export type SnapMeta = {
    name: string,
    version: string,
    summary: string?,
    description: string?,
    license: string?,
    grade: string?,
    confinement: string?,
    source: string?,
    stage: string?,
    architectures: { string }?,
    type: string?,
    requires: { string }?,
    apps: { [string]: { command: string, plugs: { string }? } }?,
}

export type Snap = { name: string, version: string, summary: string?, apps: { [string]: any }? }

local function snap(meta: SnapMeta): Snap
    return { name = meta.name, version = meta.version, summary = meta.summary, apps = meta.apps }
end

local function merge(base: SnapMeta, overrides: SnapMeta): SnapMeta
    return base
end

local function app(opts: { command: string, plugs: { string }? }): { command: string, plugs: { string }? }
    return opts
end

return { snap = snap, merge = merge, app = app }
"#;

const CLEAN_CASE: &str = r#"
--!strict
local function snap(meta: { name: string, version: string }): { name: string, version: string }
    return { name = meta.name, version = meta.version }
end

snap { name = "hello", version = "2.10" }
"#;

const TYPE_ERROR_CASE: &str = r#"
--!strict
local function snap(meta: { name: string, version: string }): { name: string, version: string }
    return { name = meta.name, version = meta.version }
end

snap { name = 42, version = "2.10" }
"#;

const SYNTAX_ERROR_CASE: &str = r#"
--!strict
local x = { name = "unbalanced"
"#;

const PRELUDE_WIRED_CASE: &str = r#"
--!strict
local shuttle = require("shuttle-prelude")

return {
    default = shuttle.snap {
        name = "hello",
        version = "2.10",
        summary = "typed via seeded prelude module",
        architectures = { "amd64", "arm64" },
    },
}
"#;

const PRELUDE_WIRED_BAD_CASE: &str = r#"
--!strict
local shuttle = require("shuttle-prelude")

return {
    default = shuttle.snap {
        name = 42,
        version = "2.10",
    },
}
"#;

// --- harness ---------------------------------------------------------------

fn repo_pkgs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../pkgs")
}

fn read_repo_source(rel: &str) -> String {
    let path = repo_pkgs().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn print_case(title: &str, diags: &[Diagnostic]) {
    println!("== {title}");
    if diags.is_empty() {
        println!("   OK (0 diagnostics)");
        return;
    }
    for d in diags {
        println!(
            "   {}:{}-{}:{}  {}",
            d.begin_line, d.begin_col, d.end_line, d.end_col, d.message
        );
    }
}

fn json_of(diags: &[Diagnostic]) -> String {
    // Hand-rolled to keep the spike dependency-free; shape matches
    // ADR-0009 Decision 8 (span + message; expected/actual ride in message).
    let mut out = String::from("[");
    for (i, d) in diags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write!(
            out,
            r#"{{"span":{{"begin":{{"line":{},"col":{}}},"end":{{"line":{},"col":{}}}}},"message":{:?}}}"#,
            d.begin_line, d.begin_col, d.end_line, d.end_col, d.message
        )
        .unwrap();
    }
    out.push(']');
    out
}

fn median(v: &mut [u128]) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn bench_cold(source: &str, iterations: usize) -> (u128, u128, u128) {
    let mut samples = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let t = Instant::now();
        let diags = check_once("bench-cold", source, true);
        samples.push(t.elapsed().as_micros());
        let _ = (diags, i);
    }
    let (min, max) = (
        samples.iter().min().copied().unwrap(),
        samples.iter().max().copied().unwrap(),
    );
    (min, median(&mut samples), max)
}

fn bench_warm(
    checker: &mut Checker,
    base_name: &str,
    source: &str,
    iterations: usize,
) -> (u128, u128, u128) {
    let mut samples = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let name = format!("{base_name}-{i}"); // unique names dodge the module cache
        let t = Instant::now();
        let _ = checker.check(&name, source);
        samples.push(t.elapsed().as_micros());
    }
    let (min, max) = (
        samples.iter().min().copied().unwrap(),
        samples.iter().max().copied().unwrap(),
    );
    (min, median(&mut samples), max)
}

fn fmt_us(triple: (u128, u128, u128)) -> String {
    format!(
        "min {} µs / median {} µs / max {} µs",
        triple.0, triple.1, triple.2
    )
}

fn main() {
    println!("Luau analyzer spike (Luau 0.663, --!strict via ConfigResolver)\n");

    // Case (a): clean definition.
    let clean = check_once("clean", CLEAN_CASE, true);
    print_case("(a) clean typed definition", &clean);

    // Case (b): deliberate field type error -> structured diagnostics.
    let bad = check_once("type-error", TYPE_ERROR_CASE, true);
    print_case("(b) `snap { name = 42 }` field mismatch", &bad);
    println!("   JSON: {}", json_of(&bad));

    // Case (b2): same source, non-strict — shows the gate is strict-only.
    let bad_nonstrict = check_once("type-error-nonstrict", TYPE_ERROR_CASE, false);
    print_case("(b2) same source, non-strict mode", &bad_nonstrict);

    // Parse errors surface as structured diagnostics too.
    let syntax = check_once("syntax-error", SYNTAX_ERROR_CASE, true);
    print_case("(d) syntax error", &syntax);

    // Case (e): require wired to a seeded typed prelude — clean + failing variant.
    let mut wired = Checker::new(true);
    wired.seed_module("shuttle-prelude", PRELUDE_DECL);
    print_case(
        "(e1) require(\"shuttle-prelude\") + valid definition",
        &wired.check("wired-ok", PRELUDE_WIRED_CASE),
    );
    print_case(
        "(e2) require(\"shuttle-prelude\") + `name = 42` (type flows across the module boundary)",
        &wired.check("wired-bad", PRELUDE_WIRED_BAD_CASE),
    );

    // Case (c): the real corpus sources, raw (globals unbound, jq requires "lib").
    let hello_src = read_repo_source("h/hello.lua");
    let jq_src = read_repo_source("j/jq/init.lua");
    print_case(
        "(c1) pkgs/h/hello.lua, raw (snap/merge/app are unbound globals)",
        &check_once("hello", &hello_src, true),
    );
    print_case(
        "(c2) pkgs/j/jq/init.lua, raw (also requires \"lib\")",
        &check_once("jq", &jq_src, true),
    );

    // Latency.
    println!("\n== latency");
    let (n_cold, n_warm) = (20, 50);
    println!(
        "   cold  (fresh Frontend per check, subprocess model, n={n_cold}): {}",
        fmt_us(bench_cold(CLEAN_CASE, n_cold))
    );

    let mut bench = Checker::new(true);
    bench.seed_module("shuttle-prelude", PRELUDE_DECL);
    println!(
        "   warm  (reused Frontend, worker model, clean case, n={n_warm}):  {}",
        fmt_us(bench_warm(&mut bench, "warm-clean", CLEAN_CASE, n_warm))
    );
    println!(
        "   warm  real hello.lua (globals unbound):                        {}",
        fmt_us(bench_warm(&mut bench, "warm-hello", &hello_src, n_warm))
    );
    println!(
        "   warm  real jq/init.lua (require lib, unseeded):                {}",
        fmt_us(bench_warm(&mut bench, "warm-jq", &jq_src, n_warm))
    );
    println!(
        "   warm  prelude-wired definition (typed, cross-module):          {}",
        fmt_us(bench_warm(
            &mut bench,
            "warm-wired",
            PRELUDE_WIRED_CASE,
            n_warm
        ))
    );
}
