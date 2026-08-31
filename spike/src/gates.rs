//! Gate runners (ADR-0009 Decision 8) + crate bake-off (Decision 1).

pub use crate::isolate::{ChildHeader, IsolatedRun};
use crate::nickel::{
    index_entries_for_arch, prelude_with_index, referenced_store_names, rewrite_imports,
    NickelInputs,
};
use crate::schema::{diff_values, Diagnostic, DiagnosticSet};
use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;

pub fn store_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("store")
}

pub fn read_store(name: &str) -> Result<String> {
    Ok(std::fs::read_to_string(store_dir().join(name))?)
}

pub struct Report {
    pub lines: Vec<String>,
}

impl Report {
    pub fn new() -> Self {
        Report { lines: Vec::new() }
    }
    pub fn say(&mut self, s: impl AsRef<str>) {
        self.lines.push(s.as_ref().into());
    }
    pub fn gate(&mut self, pass: bool, name: &str, evidence: &str) {
        self.say(format!(
            "[{}] {name}\n       evidence: {evidence}",
            if pass { "PASS" } else { "FAIL" }
        ));
    }
    pub fn flush(&self) {
        for l in &self.lines {
            println!("{l}");
        }
    }
}

pub fn child_exe() -> PathBuf {
    std::env::current_exe().expect("current_exe")
}

pub fn store() -> crate::isolate::Store {
    crate::isolate::Store { dir: store_dir() }
}

pub fn index_entries() -> Result<Value> {
    let raw = read_store("package-index.json")?;
    Ok(serde_json::from_str(&raw)?)
}

/// Assemble inputs the way production would: prelude wrap (with host index
/// spliced in) around the import-rewritten definition, plus every transitive
/// store source the definition imports (seeded in-memory, never file-read by eval).
pub fn inputs_for_pkg(pkg: &str) -> Result<NickelInputs> {
    let prelude = prelude_with_index(
        &read_store("prelude.ncl")?,
        &index_entries_for_arch(&index_entries()?, "amd64"),
    );
    let pkg_name = format!("{pkg}.ncl");
    let pkg_src = rewrite_imports(&read_store(&pkg_name)?);

    let mut extra_seeds = Vec::new();
    for name in referenced_store_names(&pkg_src) {
        if name == "prelude.ncl" {
            continue;
        }
        let src = rewrite_imports(&read_store(&name)?);
        extra_seeds.push((name, src));
    }

    Ok(NickelInputs { prelude, pkg_name, pkg_src, extra_seeds })
}

pub fn inputs_for_inline(src: &str, name: &str) -> Result<NickelInputs> {
    Ok(NickelInputs {
        prelude: prelude_with_index(
            &read_store("prelude.ncl")?,
            &index_entries_for_arch(&index_entries()?, "amd64"),
        ),
        pkg_name: name.into(),
        pkg_src: rewrite_imports(src),
        extra_seeds: Vec::new(),
    })
}

/// Map Nickel's codespan JSON diagnostics to the shoot-check schema (Decision 4/8).
/// Extracts expected/actual heuristically from contract-blame messages; null when absent.
pub fn to_diagnostics(nickel_json: &str, files: &nickel_lang_core::files::Files) -> Result<DiagnosticSet> {
    let wrapper: serde_json::Value = serde_json::from_str(nickel_json)?;
    let mut out = Vec::new();
    if let Some(diags) = wrapper.get("diagnostics").and_then(|d| d.as_array()) {
        for d in diags {
            let message = d.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
            let severity = match d.get("severity").and_then(|s| s.as_str()) {
                Some("error") | None => "error".into(),
                Some(s) => s.into(),
            };
            // First label with a span becomes the primary span. codespan's
            // serialization shape is `range: {start, end}` (byte offsets).
            let mut span = None;
            if let Some(labels) = d.get("labels").and_then(|l| l.as_array()) {
                for l in labels {
                    let (Some(start), Some(end)) = (
                        l.get("range")
                            .and_then(|r| r.get("start"))
                            .and_then(|v| v.as_u64()),
                        l.get("range")
                            .and_then(|r| r.get("end"))
                            .and_then(|v| v.as_u64()),
                    ) else {
                        continue;
                    };
                    let file_id = l.get("file_id").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    let (ls, cs) = file_line_col(files, file_id, start as u32);
                    let (le, ce) = file_line_col(files, file_id, end as u32);
                    span = Some(crate::schema::Span {
                        byte_start: start as usize,
                        byte_end: end as usize,
                        line_start: ls,
                        col_start: cs,
                        line_end: le,
                        col_end: ce,
                        file: nickel_file_name(files, file_id),
                    });
                    break;
                }
            }
            let Some(span) = span else { continue };
            // expected = the contract expression the blame points at (secondary
            // label); actual = the offending value verbatim (primary label).
            let actual = label_snippet(files, d, "Primary").or(Some(String::new()));
            let expected = label_snippet(files, d, "Secondary");
            out.push(Diagnostic {
                severity,
                message: message.clone(),
                span,
                expected,
                actual,
                suggestion: suggestion_for(&message),
            });
        }
    }
    Ok(DiagnosticSet { diagnostics: out })
}

fn nickel_file_id(id: usize) -> nickel_lang_core::files::FileId {
    // FileId's constructor is private; round-trip through its serde impl.
    serde_json::from_value::<nickel_lang_core::files::FileId>(Value::from(id as u64))
        .expect("file id round-trip")
}

fn nickel_file_name(files: &nickel_lang_core::files::Files, id: usize) -> String {
    files
        .name(nickel_file_id(id))
        .to_string_lossy()
        .into_owned()
}

fn file_line_col(files: &nickel_lang_core::files::Files, id: usize, byte_idx: u32) -> (usize, usize) {
    let Ok(loc) = files.location(nickel_file_id(id), byte_idx) else {
        return (0, 0);
    };
    (loc.line.0 as usize + 1, loc.column.0 as usize + 1)
}

fn label_snippet(
    files: &nickel_lang_core::files::Files,
    diag: &Value,
    style: &str,
) -> Option<String> {
    let labels = diag.get("labels")?.as_array()?;
    for l in labels {
        if l.get("style")?.as_str()? != style {
            continue;
        }
        let start = l.pointer("/range/start")?.as_u64()? as usize;
        let end = l.pointer("/range/end")?.as_u64()? as usize;
        let id = l.get("file_id")?.as_u64()? as usize;
        let src = files.source(nickel_file_id(id));
        return src.get(start..end).map(|s| s.trim().to_string());
    }
    None
}

fn suggestion_for(message: &str) -> Option<String> {
    if message.contains("not found in package index") {
        Some("add the snap to the package index or use pin()".into())
    } else if message.contains("missing field") || message.contains("not defined") {
        Some("provide the required field in the definition".into())
    } else {
        None
    }
}

// ---------------- Gate: adversarial suite ----------------

pub struct AdversarialCase {
    pub name: &'static str,
    pub source: String,
}

pub fn adversarial_cases() -> Vec<AdversarialCase> {
    // 1. Infinite thunk (syntactic let-cycle + record self-reference).
    let infinite_thunk = r#"{ a = b, b = a, name = "x", version = "1" }"#.to_string();
    // 2. Generated recursion (not covered by blackholing). Nickel's `let` is
    // non-recursive, so the self-application idiom creates genuine unbounded
    // recursion — `f f 100000000` never terminates on its own.
    let deep_recursion = r#"
      let f = fun self n => if n == 0 then 0 else 1 + self self (n - 1) in
      { value = f f 100000000, name = "x", version = "1" }
    "#
    .to_string();
    // 3. Memory blowup from a tiny source: exponential string doubling.
    let mut huge = String::from("let s0 = \"0123456789012345678901234567890123456789\" in\n");
    for i in 0..32 {
        huge.push_str(&format!("  let s{} = s{} ++ s{} in\n", i + 1, i, i));
    }
    huge.push_str("{ value = s32, name = \"x\", version = \"1\" }");
    // 4. Contract violation with span.
    let contract_violation = r#"{ default = snap { name = 42, version = "1.0" } }"#.to_string();

    vec![
        AdversarialCase { name: "infinite-thunk", source: infinite_thunk },
        AdversarialCase { name: "deep-recursion", source: deep_recursion },
        AdversarialCase { name: "huge-literal-doubling", source: huge },
        AdversarialCase { name: "contract-violation", source: contract_violation },
    ]
}

pub fn run_isolated_source(src: &str, name: &str) -> Result<IsolatedRun> {
    crate::isolate::run_isolated(
        &child_exe(),
        &ChildHeader {
            pkg: None,
            inline_source: Some(src.to_string()),
            display_name: Some(name.into()),
        },
        &store(),
    )
}

pub fn run_isolated_pkg(pkg: &str) -> Result<IsolatedRun> {
    crate::isolate::run_isolated(
        &child_exe(),
        &ChildHeader { pkg: Some(pkg.into()), inline_source: None, display_name: None },
        &store(),
    )
}

// ---------------- Gate: golden parity ----------------

pub struct ParityResult {
    pub lua_json: Value,
    pub nickel_json: Value,
    pub diffs: Vec<String>,
}

pub fn parity_for(pkg: &str, lua_rel: &str) -> Result<ParityResult> {
    let lua_json = crate::golden::eval_lua_pkg(&store_dir().join("package-index.json"), lua_rel)?;

    // Nickel path through the subprocess (production shape).
    let run = run_isolated_pkg(pkg)?;
    let nickel_json = match run.outcome {
        Some(crate::isolate::ChildOutcomeLine::Ok(ok)) => ok.value,
        Some(crate::isolate::ChildOutcomeLine::Err(e)) => {
            anyhow::bail!("nickel eval failed for {pkg}: {}", e.diagnostics_json)
        }
        None => anyhow::bail!("nickel child produced no outcome: {}", run.status.describe()),
    };

    let mut diffs = Vec::new();
    diff_values("$", &lua_json, &nickel_json, &mut diffs);
    Ok(ParityResult { lua_json, nickel_json, diffs })
}
