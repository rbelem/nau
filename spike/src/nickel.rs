//! Nickel embed path — the chosen crate's real working API surface (ADR-0009 Decision 1/3).
//!
//! Empirical bake-off result (see REPORT.md): `nickel-lang-core` 0.18.0 wins.
//! The stable `nickel-lang` 2.2.0 `Context` offers `eval_deep` + `Expr::to_serde`
//! + `Error::format(ErrorFormat::Json)`, but has NO public way to:
//!   - seed in-memory import sources (`%inmem_src%:` channel),
//!   - inject host data into the evaluation environment,
//!   - access the parsed AST for import rewriting,
//! all of which the import-interception and index() gates need. `nickel-lang-core`
//! exposes all three via `ProgramBuilder`.

use anyhow::Result;
use nickel_lang_core::error::report::DiagnosticsWrapper;
use nickel_lang_core::error::IntoDiagnostics;
use nickel_lang_core::eval::cache::CacheImpl;
use nickel_lang_core::files::Files;
use nickel_lang_core::program::ProgramBuilder;
use serde::Deserialize as _;
use serde_json::Value;

/// Host-visible alias so store sources can `import "shoot-prelude"`; rewritten
/// to the in-memory prelude seed. ponytail: string-level rewrite via regex —
/// Nickel imports are always literal strings, but production should do this at
/// the AST level (parse -> traverse -> rewrite) to survive imports inside
/// comments/strings.
pub const PRELUDE_ALIAS: &str = "shoot-prelude";
pub const PRELUDE_NAME: &str = "prelude.ncl";

/// Rewrite every `import "<path>"` in a definition source to the `%inmem_src%:`
/// channel, so eval can never touch the filesystem for imports. This IS the
/// filesystem firewall: an unseeded inmem name can only fail with an import
/// error; the raw author path is never passed to the resolver.
pub fn rewrite_imports(src: &str) -> String {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"(import\s+)"((?:[^"\\]|\\.)*)""#).unwrap());
    re.replace_all(src, |caps: &regex::Captures| {
        let path = &caps[2];
        let mapped = if path == PRELUDE_ALIAS { PRELUDE_NAME } else { path };
        format!(
            "{}\"{}{}\"",
            &caps[1],
            nickel_lang_core::cache::IN_MEMORY_SOURCE_PATH_PREFIX,
            mapped
        )
    })
    .into_owned()
}

/// Sources seeded into the interpreter before eval. None of these are read
/// from the filesystem by the eval process itself.
///
/// Empirical finding (0.18.0): the synthesized multi-input `merge` evaluates
/// each input independently, so fields of one input are UNBOUND inside another
/// (verified: `{ x = index_data }` after merging a record defining it fails).
/// The wrap therefore binds the prelude lexically in a generated `let`:
///   let { snap, merge, pin, index, app, image } = import "%inmem_src%:prelude.ncl" in
///   <definition>
#[derive(Debug, Clone)]
pub struct NickelInputs {
    pub prelude: String,
    pub pkg_name: String,
    pub pkg_src: String,
    /// Additional in-memory store sources the definition imports (e.g. lib.ncl).
    /// Each is seeded under its store name; not_exported keeps them out of the export.
    pub extra_seeds: Vec<(String, String)>,
}

/// The prelude fields the host wrap puts in the definition's scope.
pub const PRELUDE_BINDINGS: &str = "snap, merge, pin, index, app, image";

const INDEX_MARKER: &str = "index_data | not_exported = null,";

/// Host composition: splice the populated index record into the prelude source.
pub fn prelude_with_index(prelude_src: &str, entries: &Value) -> String {
    let populated = format!("index_data | not_exported = {},", json_to_ncl(entries));
    prelude_src
        .replacen(INDEX_MARKER, &populated, 1)
        .replacen("  # @host-replace: the host swaps this line for the populated index record", "", 1)
}

/// The host wrap: bind prelude functions, then inline the definition.
/// (`..` keeps the record pattern open — `index_data` stays private.)
pub fn wrap_definition(pkg_src: &str) -> String {
    format!(
        "let {{ {}, .. }} = import \"{}{}\" in\n{}",
        PRELUDE_BINDINGS,
        nickel_lang_core::cache::IN_MEMORY_SOURCE_PATH_PREFIX,
        PRELUDE_NAME,
        pkg_src
    )
}

pub struct EvalOk {
    pub value: Value,
}

/// Evaluate fully (eval_full_for_export: drops `not_exported` fields) and
/// extract to serde_json via NickelValue's serde::Deserializer impl.
/// On eval failure, returns the JSON diagnostics + the file db for span lookup.
pub fn eval_inprocess(inputs: &NickelInputs) -> Result<EvalOk, (String, Files)> {
    let mut builder = ProgramBuilder::new()
        .add_source_string(inputs.prelude.clone(), PRELUDE_NAME);
    for (name, src) in &inputs.extra_seeds {
        builder = builder.add_source_string(src.clone(), name.clone());
    }
    let mut program = builder
        .add_source_string(wrap_definition(&inputs.pkg_src), inputs.pkg_name.clone())
        .build::<CacheImpl>()
        .map_err(|e| (format!("build: {e}"), Files::empty()))?;

    match program.eval_full_for_export() {
        Ok(nv) => {
            let value = serde_json::Value::deserialize(nv)
                .map_err(|e| (format!("serde extraction failed: {e}"), program.files()))?;
            Ok(EvalOk { value })
        }
        Err(err) => {
            let mut files = program.files();
            // NOTE: report_with(.., ErrorFormat::Json) ignores its writer and
            // dumps to stderr (verified in 0.18.0), so we serialize the
            // diagnostics wrapper ourselves.
            let diagnostics = err.into_diagnostics(&mut files);
            let json = serde_json::to_string(&DiagnosticsWrapper::from(diagnostics))
                .unwrap_or_else(|e| format!("{{\"diagnostics\":[],\"serialize_error\":\"{e}\"}}"));
            Err((json, files))
        }
    }
}

/// Store sources referenced by a rewritten source (the `%inmem_src%:<name>` names).
pub fn referenced_store_names(src: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(&format!(
            "{}([^\"]+)",
            regex::escape(nickel_lang_core::cache::IN_MEMORY_SOURCE_PATH_PREFIX)
        ))
        .unwrap()
    });
    re.captures_iter(src).map(|c| c[1].to_string()).collect()
}

/// Render serde_json as a Nickel source fragment (strings escaped, records/arrays).
pub fn json_to_ncl(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", s.escape_default()),
        Value::Array(a) => {
            let items: Vec<String> = a.iter().map(json_to_ncl).collect();
            format!("[{}]", items.join(", "))
        }
        Value::Object(o) => {
            let items: Vec<String> = o
                .iter()
                .map(|(k, v)| {
                    format!(
                        "\"{}\" = {}",
                        k.replace('\\', "\\\\").replace('"', "\\\""),
                        json_to_ncl(v)
                    )
                })
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

// --- stable-crate probe (bake-off): compile + run the documented high-level API ---

pub mod stable_probe {
    use nickel_lang::ErrorFormat as StableErrorFormat;

    #[derive(serde::Deserialize, Debug, PartialEq)]
    pub struct Point {
        pub x: f64,
        pub name: String,
    }

    /// Returns (serde extraction result, JSON diagnostics reachable?).
    pub fn probe() -> Result<(Point, bool), String> {
        let mut ctx = nickel_lang::Context::new();
        let expr = ctx
            .eval_deep("{ x = 1.5, name = \"probe\" }")
            .map_err(|e| format!("stable eval_deep failed: {e:?}"))?;
        let p: Point = expr.to_serde().map_err(|e| format!("stable to_serde failed: {e}"))?;

        let err = ctx
            .eval_deep("{ a = 1, } nonsense !!")
            .err()
            .ok_or("expected stable eval error for diagnostics probe")?;
        let mut buf = Vec::new();
        err.format(&mut buf, StableErrorFormat::Json)
            .map_err(|e| format!("stable Error::format(Json) failed: {e}"))?;
        let json_ok = serde_json::from_slice::<serde_json::Value>(&buf).is_ok();
        Ok((p, json_ok))
    }
}

/// Flatten shoot's package index (entries with per-arch pins) to the record the
/// prelude's `index()` consults: name -> { revision, sha3_384 } for the target arch.
pub fn index_entries_for_arch(index_json: &Value, arch: &str) -> Value {
    let mut out = serde_json::Map::new();
    let Some(entries) = index_json.get("entries").and_then(|e| e.as_object()) else {
        return Value::Object(out);
    };
    for entry in entries.values() {
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else { continue };
        let Some(pins) = entry.get("pins").and_then(|p| p.as_object()) else { continue };
        let Some(pin) = pins.get(arch) else { continue };
        out.insert(
            name.to_string(),
            serde_json::json!({
                "revision": pin.get("revision").cloned().unwrap_or(Value::Null),
                "sha3_384": pin.get("sha3_384").cloned().unwrap_or(Value::Null),
            }),
        );
    }
    Value::Object(out)
}
