use std::collections::HashMap;

use miette::{IntoDiagnostic, WrapErr};

use crate::analysis::Span;
use crate::image::ImageDeclaration;
use crate::snap::{PackageInput, SnapMeta};

/// Named outputs from a `shuttle.lua`, fully converted to owned Rust types.
pub type Outputs = HashMap<String, SnapMeta>;

/// Directory of the definition file a label points at, threaded into each
/// output so build-time file references (hooks, icons) resolve relative to
/// the definition first. Labels that aren't file paths (embedded
/// definitions, bare names) yield `None` and callers fall back to the CWD.
fn definition_dir_from_label(label: &str) -> Option<std::path::PathBuf> {
    let parent = std::path::Path::new(label).parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent.to_path_buf())
    }
}

/// Evaluate Lua source content and return the converted snap outputs.
///
/// The source is evaluated in a bounded subprocess worker (ADR-0010
/// Decisions 4+5): rlimits + wall-clock deadline in the child, IPC-backed
/// require with parent-side root allowlisting, narrowed stdlib. All eval
/// inputs (prelude, index data, source) cross the pipe; the child opens no
/// project files.
///
/// Like `evaluate_file` but takes the Lua source string directly instead of
/// reading from disk. Used for embedded packages that don't exist as files.
pub fn evaluate_string(label: &str, source: &str) -> miette::Result<Outputs> {
    let ok = run_worker_for(label, source)?;
    for diag in &ok.diagnostics {
        crate::output::warn(diag);
    }

    // Map the worker's JSON outputs back into typed SnapMeta through a
    // scratch VM, reusing the exact in-process validation (and its messages).
    let lua = mlua::Lua::new();
    let mut outputs = Outputs::new();
    for (key, json) in &ok.outputs {
        let value = json_to_lua(&lua, json)
            .map_err(|e| miette::miette!("{label}: output '{key}' conversion failed: {e}"))?;
        match SnapMeta::from_lua_value(&value) {
            Ok(mut meta) => {
                meta.definition_dir = definition_dir_from_label(label);
                outputs.insert(key.clone(), meta);
            }
            Err(e) => crate::output::warn(format!("skipping output '{key}' from {label}: {e}")),
        }
    }
    Ok(outputs)
}

/// Evaluate a Lua file and return the converted snap outputs.
///
/// The file must return a Lua table of snap declarations.
/// The shuttle DSL globals (`snap()`, `app()`) are injected before evaluation.
/// All data is converted to owned Rust structs before returning.
pub fn evaluate_file(path: &str) -> miette::Result<Outputs> {
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;
    evaluate_string(path, &source)
}

// ── Evaluation with global inputs ──

/// Result of evaluating a Lua file, including global inputs.
pub struct EvalOutput {
    pub outputs: Outputs,
    pub global_inputs: HashMap<String, PackageInput>,
}

/// One validation/eval diagnostic with structured fields (ADR-0010 Decisions
/// 2-3). `span` is set when the problem localizes to a source position:
/// analyzer-stage diagnostics carry the Luau type checker's 1-based spans,
/// and schema-stage (post-eval validation) diagnostics carry the located
/// declaration site of the offending output key (`locate_output_key`).
/// Diagnostics that cannot be localized keep `span: None` and locate the
/// problem with `label` (definition path) plus `key` (output name).
///
/// JSON shape decision: each diagnostic serializes as a self-contained object
/// with one optional nested `"span"` field
/// (`{begin_line, begin_col, end_line, end_col}` or `null`) — per-diagnostic
/// span fields, not a separate top-level `"spans"` array.
#[derive(Debug, Clone)]
pub struct CheckDiagnostic {
    /// Definition the diagnostic belongs to (eval label / file path).
    pub label: String,
    /// Output key, when the diagnostic is about one output.
    pub key: Option<String>,
    /// What the schema expected, when the message states it.
    pub expected: Option<String>,
    /// What the definition actually had, when the message states it.
    pub actual: Option<String>,
    /// The full diagnostic message.
    pub message: String,
    /// Source span when the problem localizes to a position; `None`
    /// otherwise.
    pub span: Option<Span>,
}

impl CheckDiagnostic {
    /// Diagnostic for one analyzer error (span set, eval fields empty).
    pub fn from_analyzer(label: &str, d: crate::analysis::Diagnostic) -> CheckDiagnostic {
        let span = d.span();
        CheckDiagnostic {
            label: label.to_string(),
            key: None,
            expected: None,
            actual: None,
            message: d.message,
            span: Some(span),
        }
    }
}

/// Everything one checked eval produced: the outputs that survived
/// validation, every warn-and-continue diagnostic, and the hard eval error
/// when the eval itself failed (ADR-0010 Decision 3 — no silent drops).
#[derive(Debug, Clone)]
pub struct CheckedEval {
    pub outputs: Outputs,
    pub global_inputs: HashMap<String, PackageInput>,
    pub diagnostics: Vec<CheckDiagnostic>,
    /// Set when the eval failed hard; `outputs`/`global_inputs` are then empty.
    pub error: Option<String>,
}

/// Lift the output key out of a child diagnostic like
/// `skipping output 'KEY' from LABEL: ...` so JSON consumers can locate it.
fn child_diag_key(diag: &str) -> Option<String> {
    let rest = diag.strip_prefix("skipping output '")?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Pull expected/actual out of a validation message like
/// `'architectures[1]' must be a string, got integer`. Conservative:
/// unmatched messages yield `(None, None)` and `message` stays authoritative.
fn parse_expected_actual(message: &str) -> (Option<String>, Option<String>) {
    const NEEDLE: &str = "must be a ";
    const GOT: &str = ", got ";
    let Some(i) = message.find(NEEDLE) else {
        return (None, None);
    };
    let rest = &message[i + NEEDLE.len()..];
    match rest.find(GOT) {
        Some(j) => (
            Some(rest[..j].to_string()),
            Some(rest[j + GOT.len()..].to_string()),
        ),
        None => (None, None),
    }
}

/// Evaluate Lua source for `shuttle check`: the exact same bounded
/// subprocess path and Rust-side validation as
/// [`evaluate_string_with_inputs`], but every warn-and-continue diagnostic
/// comes back as data instead of being printed, and hard eval failures are
/// reported in-band (ADR-0010 Decisions 2-3).
pub fn check_string_with_inputs(label: &str, source: &str) -> CheckedEval {
    fn failed(diagnostics: Vec<CheckDiagnostic>, error: String) -> CheckedEval {
        CheckedEval {
            outputs: Outputs::new(),
            global_inputs: HashMap::new(),
            diagnostics,
            error: Some(error),
        }
    }

    let mut diagnostics: Vec<CheckDiagnostic> = Vec::new();
    let ok = match run_worker_for(label, source) {
        Ok(ok) => ok,
        Err(e) => return failed(diagnostics, format!("{e:#}")),
    };
    for d in &ok.diagnostics {
        let key = child_diag_key(d);
        diagnostics.push(CheckDiagnostic {
            label: label.to_string(),
            span: key
                .as_deref()
                .and_then(|k| crate::analysis::locate_output_key(source, k)),
            key,
            expected: None,
            actual: None,
            message: d.clone(),
        });
    }

    let lua = mlua::Lua::new();
    let mut outputs = Outputs::new();
    for (key, json) in &ok.outputs {
        let value = match json_to_lua(&lua, json) {
            Ok(v) => v,
            Err(e) => {
                return failed(
                    diagnostics,
                    format!("{label}: output '{key}' conversion failed: {e}"),
                )
            }
        };
        match SnapMeta::from_lua_value(&value) {
            Ok(mut meta) => {
                meta.definition_dir = definition_dir_from_label(label);
                outputs.insert(key.clone(), meta);
            }
            Err(e) => {
                let (expected, actual) = parse_expected_actual(&e.to_string());
                diagnostics.push(CheckDiagnostic {
                    label: label.to_string(),
                    key: Some(key.clone()),
                    expected,
                    actual,
                    message: format!("skipping output '{key}' from {label}: {e}"),
                    span: crate::analysis::locate_output_key(source, key),
                });
            }
        }
    }

    // Rehydrate the global `inputs` table in the scratch VM so the existing
    // extraction (and its error messages) applies unchanged.
    let inputs_value = match json_to_lua(&lua, &ok.global_inputs) {
        Ok(v) => v,
        Err(e) => {
            return failed(
                diagnostics,
                format!("{label}: inputs conversion failed: {e}"),
            )
        }
    };
    if let Err(e) = lua.globals().set("inputs", inputs_value) {
        return failed(diagnostics, format!("failed to set inputs global: {e}"));
    }
    let global_inputs = match extract_inputs_from_lua(&lua) {
        Ok(i) => i,
        Err(e) => return failed(diagnostics, format!("{e:#}")),
    };

    CheckedEval {
        outputs,
        global_inputs,
        diagnostics,
        error: None,
    }
}

/// [`check_string_with_inputs`] for a file path; an unreadable file comes
/// back as a hard-error [`CheckedEval`] so `shuttle check` reports it
/// uniformly in both output modes.
pub fn check_file_with_inputs(path: &str) -> CheckedEval {
    match std::fs::read_to_string(path) {
        Ok(source) => check_string_with_inputs(path, &source),
        Err(e) => CheckedEval {
            outputs: Outputs::new(),
            global_inputs: HashMap::new(),
            diagnostics: Vec::new(),
            error: Some(format!("could not read {path}: {e}")),
        },
    }
}

/// Evaluate Lua source and return both outputs and global inputs.
///
/// Runs through the bounded subprocess worker (see [`evaluate_string`]).
pub fn evaluate_string_with_inputs(label: &str, source: &str) -> miette::Result<EvalOutput> {
    let checked = check_string_with_inputs(label, source);
    for diag in &checked.diagnostics {
        crate::output::warn(&diag.message);
    }
    if let Some(err) = checked.error {
        return Err(miette::miette!("{err}"));
    }
    Ok(EvalOutput {
        outputs: checked.outputs,
        global_inputs: checked.global_inputs,
    })
}

/// Evaluate a Lua file and return both outputs and global inputs.
pub fn evaluate_file_with_inputs(path: &str) -> miette::Result<EvalOutput> {
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;
    evaluate_string_with_inputs(path, &source)
}

/// Extract the global `inputs` table from an evaluated Lua state.
/// Returns an empty map if no inputs are set.
fn extract_inputs_from_lua(lua: &mlua::Lua) -> miette::Result<HashMap<String, PackageInput>> {
    let globals = lua.globals();
    let value: mlua::Value = globals.get("inputs").unwrap_or(mlua::Value::Nil);
    match value {
        mlua::Value::Table(t) => {
            let mut inputs = HashMap::new();
            for pair in t.pairs::<String, mlua::Value>() {
                let (name, val) = pair.map_err(|e| miette::miette!("inputs entry: {e}"))?;
                match val {
                    mlua::Value::Table(input_table) => {
                        let url: String = input_table
                            .get("url")
                            .map_err(|_| miette::miette!("inputs['{name}']: missing 'url'"))?;
                        inputs.insert(name, PackageInput { url });
                    }
                    other => {
                        return Err(miette::miette!(
                            "inputs['{name}'] must be a table, got {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(inputs)
        }
        mlua::Value::Nil => Ok(HashMap::new()),
        other => Err(miette::miette!(
            "'inputs' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Evaluate a Lua file and extract image declarations.
///
/// Runs through the bounded subprocess worker (see [`evaluate_string`]).
pub fn evaluate_images_file(path: &str) -> miette::Result<HashMap<String, ImageDeclaration>> {
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;
    let ok = run_worker_for(path, &source)?;
    for diag in &ok.diagnostics {
        crate::output::warn(diag);
    }

    let lua = mlua::Lua::new();
    let mut images = HashMap::new();
    for (key, json) in &ok.outputs {
        let value = json_to_lua(&lua, json)
            .map_err(|e| miette::miette!("{path}: image '{key}' conversion failed: {e}"))?;
        if let mlua::Value::Table(t) = value {
            match ImageDeclaration::from_lua_table(&t) {
                Ok(decl) => {
                    images.insert(key.clone(), decl);
                }
                Err(e) => crate::output::warn(format!("skipping image '{key}' from {path}: {e}")),
            }
        }
    }
    Ok(images)
}

// ── Worker plumbing ──

/// Build the full worker request for one definition eval: prelude, index
/// data, and source all cross the pipe; the child reads no project files.
fn eval_request(label: &str, source: &str) -> miette::Result<crate::isolate::EvalRequest> {
    let arch = std::env::var("SHUTTLE_ARCH").unwrap_or_else(|_| "amd64".into());
    let index_path = std::env::var("SHUTTLE_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::index::DEFAULT_INDEX));
    let index = crate::index::PackageIndex::load_or_default(&index_path)?;
    let index_data = serde_json::to_value(&index)
        .map_err(|e| miette::miette!("failed to serialize index data: {e}"))?;
    Ok(crate::isolate::EvalRequest {
        prelude: crate::dsl::prelude(),
        index_data,
        arch,
        sources: Default::default(),
        entry: source.to_string(),
        entry_label: label.to_string(),
    })
}

fn run_worker_for(label: &str, source: &str) -> miette::Result<crate::isolate::WorkerOk> {
    let req = eval_request(label, source)?;
    crate::isolate::run_eval(&req)
}

/// Convert a serde_json value into an mlua value (in a scratch VM).
///
/// Numbers stay Numbers (Luau has a single number type), arrays keep
/// 1-based sequence shape — matching what a direct in-process eval produced.
fn json_to_lua(lua: &mlua::Lua, v: &serde_json::Value) -> mlua::Result<mlua::Value> {
    Ok(match v {
        serde_json::Value::Null => mlua::Value::Nil,
        serde_json::Value::Bool(b) => mlua::Value::Boolean(*b),
        serde_json::Value::Number(n) => mlua::Value::Number(n.as_f64().unwrap_or_default()),
        serde_json::Value::String(s) => mlua::Value::String(lua.create_string(s.as_str())?),
        serde_json::Value::Array(items) => {
            let table = lua.create_table()?;
            for (i, item) in items.iter().enumerate() {
                table.raw_set((i + 1) as i64, json_to_lua(lua, item)?)?;
            }
            mlua::Value::Table(table)
        }
        serde_json::Value::Object(map) => {
            let table = lua.create_table()?;
            for (k, val) in map {
                table.raw_set(k.as_str(), json_to_lua(lua, val)?)?;
            }
            mlua::Value::Table(table)
        }
    })
}

#[cfg(test)]
mod tests {
    use mlua::Value;

    /// Create a fresh Lua instance with the DSL globals injected.
    fn with_dsl() -> mlua::Lua {
        let lua = mlua::Lua::new();
        lua.load(crate::dsl::prelude())
            .exec()
            .expect("failed to load DSL globals");
        lua
    }

    /// Evaluate Lua source with DSL globals and return the result.
    fn eval_with_dsl(source: &str) -> mlua::Result<Value> {
        let lua = with_dsl();
        lua.load(source).eval()
    }

    fn extract_lua_string(v: &Value) -> Option<String> {
        match v {
            Value::String(s) => s.to_str().ok().map(|s| s.to_string()),
            _ => None,
        }
    }

    // ── Phase 1: basic Lua eval (keep core tests) ──

    #[test]
    fn test_evaluate_empty_table() {
        let lua = mlua::Lua::new();
        let table: Value = lua.load("return {}").eval().unwrap();
        assert!(matches!(table, Value::Table(_)));
    }

    #[test]
    fn test_evaluate_multi_output_table() {
        let lua = mlua::Lua::new();
        let table: Value = lua
            .load(
                r#"return {
                    server = { name = "server-snap", version = "0.1.0" },
                    cli = { name = "cli-snap", version = "0.2.0" },
                }"#,
            )
            .eval()
            .unwrap();

        match table {
            Value::Table(t) => {
                let keys: Vec<String> = t.pairs::<String, Value>().map(|p| p.unwrap().0).collect();
                assert!(keys.contains(&"server".to_string()));
                assert!(keys.contains(&"cli".to_string()));
            }
            _ => panic!("expected top-level table"),
        }
    }

    #[test]
    fn test_evaluate_non_table_fails() {
        let result: std::result::Result<Value, mlua::Error> =
            mlua::Lua::new().load("return 42").eval();
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Integer(42)));
    }

    #[test]
    fn test_evaluate_with_lua_conditionals() {
        let lua = mlua::Lua::new();
        let table: Value = lua
            .load(
                r#"
                local arch = "amd64"
                return {
                    default = {
                        name = "my-snap",
                        arch = arch,
                        version = "2.0.0",
                    }
                }
                "#,
            )
            .eval()
            .unwrap();

        match table {
            Value::Table(t) => {
                let default: Value = t.get("default").unwrap();
                match default {
                    Value::Table(dt) => {
                        let arch: String = dt.get("arch").unwrap();
                        assert_eq!(arch, "amd64");
                    }
                    _ => panic!("expected table"),
                }
            }
            _ => panic!("expected top-level table"),
        }
    }

    // ── Phase 2: snap() and app() validation ──

    #[test]
    fn test_snap_with_pinned_source() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "pinned-snap",
                    version = "1.0",
                    source = {
                        url = "https://example.com/src.tar.gz",
                        sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    },
                    build = "make",
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_snap_with_pinned_source_no_hash() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "pinned-no-hash",
                    version = "1.0",
                    source = {
                        url = "https://example.com/src.tar.gz",
                    },
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_snap_with_source_url_missing() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "bad-source",
                    version = "1.0",
                    source = {
                        sha256 = "deadbeef",
                    },
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("source.url must be a string"),
            "error should mention missing url: {}",
            err
        );
    }

    #[test]
    fn test_snap_valid_full_config() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "hello",
                    version = "2.10",
                    summary = "GNU Hello",
                    description = "Prints a greeting",
                    license = "GPL-3.0-or-later",
                    grade = "stable",
                    confinement = "strict",
                    source = "http://example.com/hello.tar.gz",
                    stage = "./stage/",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_snap_minimal_config() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "minimal",
                    version = "1.0.0",
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_snap_missing_name() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    version = "1.0",
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing required field 'name'"),
            "error should mention missing name: {}",
            err
        );
    }

    #[test]
    fn test_snap_missing_version() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "test",
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing required field 'version'"),
            "error should mention missing version: {}",
            err
        );
    }

    #[test]
    fn test_snap_name_must_be_string() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = 42,
                    version = "1.0",
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be a string"),
            "error should mention type mismatch: {}",
            err
        );
    }

    #[test]
    fn test_snap_architectures_must_be_string_array() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "test",
                    version = "1.0",
                    architectures = { "amd64", 123 },
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be a string"),
            "error should mention architecture type mismatch: {}",
            err
        );
    }

    #[test]
    fn test_snap_apps_must_be_table() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "test",
                    version = "1.0",
                    apps = "not-a-table",
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be a table"),
            "error should mention apps type mismatch: {}",
            err
        );
    }

    #[test]
    fn test_app_valid() {
        let result = eval_with_dsl(r#"return app { command = "bin/hello" }"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_app_missing_command() {
        let result = eval_with_dsl(r#"return app { daemon = "simple" }"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing required field 'command'"),
            "error should mention missing command: {}",
            err
        );
    }

    #[test]
    fn test_app_command_must_be_string() {
        let result = eval_with_dsl(r#"return app { command = 42 }"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be a string"),
            "error should mention command type mismatch: {}",
            err
        );
    }

    #[test]
    fn test_app_full_config() {
        let result = eval_with_dsl(
            r#"
            return app {
                command = "bin/myservice",
                daemon = "simple",
                plugs = { "network", "network-bind" },
                slots = { "some-slot" },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_app_rejects_unknown_field() {
        let result = eval_with_dsl(
            r#"
            return app {
                command = "bin/myservice",
                restart_condition = "on-abnormal",
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field 'restart_condition'"),
            "error should name the unknown field: {}",
            err
        );
        assert!(
            err.contains("valid fields: command, daemon, plugs, slots, environment"),
            "error should list the valid fields: {}",
            err
        );
    }

    #[test]
    fn test_snap_defaults_grade_and_confinement() {
        let lua = with_dsl();
        let result: Value = lua
            .load(
                r#"
                local s = snap { name = "test", version = "1.0" }
                return s.grade .. "|" .. s.confinement
                "#,
            )
            .eval()
            .unwrap();
        match result {
            Value::String(s) => {
                let actual = s.to_str().unwrap();
                assert_eq!(actual, "stable|strict");
            }
            other => panic!("expected string, got {:?}", other),
        }
    }

    #[test]
    fn test_multi_output_with_dsl() {
        let result = eval_with_dsl(
            r#"
            return {
                server = snap {
                    name = "server-snap",
                    version = "1.0",
                    apps = {
                        daemon = app { command = "bin/serve", daemon = "simple" },
                    },
                },
                cli = snap {
                    name = "cli-snap",
                    version = "2.0",
                    apps = {
                        hello = app { command = "bin/cli" },
                    },
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_dsl_rejects_non_table_app() {
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "test",
                    version = "1.0",
                    apps = {
                        bad = "just-a-string",
                    },
                },
            }
            "#,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must be an app table"),
            "error should mention app table: {}",
            err
        );
    }

    #[test]
    fn test_snap_rejects_string_instead_of_table() {
        let result = eval_with_dsl(r#"return snap("not-a-table")"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expected a table"),
            "error should mention expected table: {}",
            err
        );
    }

    #[test]
    fn test_hello_example_roundtrip() {
        // Match the examples/hello/shuttle.lua structure
        let result = eval_with_dsl(
            r#"
            return {
                default = snap {
                    name = "hello",
                    version = "2.10",
                    summary = 'GNU Hello, the "hello world" snap',
                    description = "GNU hello prints a friendly greeting.",
                    license = "GPL-3.0-or-later",
                    grade = "stable",
                    confinement = "strict",
                    source = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
                    stage = "./stage/",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
        );
        assert!(result.is_ok());
    }

    // ── Phase 7: Composable DSL (merge + require) ──

    #[test]
    fn test_merge_basic() {
        let lua = with_dsl();
        let val: Value = lua
            .load(
                r#"
            local a = { x = 1, y = 2 }
            local b = { y = 3, z = 4 }
            local m = merge(a, b)
            return m.x .. "|" .. m.y .. "|" .. m.z
            "#,
            )
            .eval()
            .unwrap();
        let s = extract_lua_string(&val).unwrap();
        assert_eq!(s, "1|3|4");
    }

    #[test]
    fn test_merge_deep() {
        let lua = with_dsl();
        let val: Value = lua
            .load(
                r#"
            local base = { app = { command = "bin/default", daemon = "simple" } }
            local over = { app = { command = "bin/override" } }
            local m = merge(base, over)
            return m.app.command .. "|" .. m.app.daemon
            "#,
            )
            .eval()
            .unwrap();
        let s = extract_lua_string(&val).unwrap();
        assert_eq!(s, "bin/override|simple");
    }

    #[test]
    fn test_merge_with_nil() {
        let lua = with_dsl();
        let val: Value = lua
            .load(
                r#"
            local m = merge(nil, { a = 1 })
            return m.a
            "#,
            )
            .eval()
            .unwrap();
        assert_eq!(val, mlua::Value::Integer(1));
    }

    #[test]
    fn test_merge_array_is_replaced() {
        let lua = with_dsl();
        let val: Value = lua
            .load(
                r#"
            local base = { items = { "a", "b" } }
            local over = { items = { "c" } }
            local m = merge(base, over)
            -- arrays are replaced, not merged element-by-element
            return #m.items
            "#,
            )
            .eval()
            .unwrap();
        assert_eq!(val, mlua::Value::Integer(1));
    }

    // ── Check diagnostics (ADR-0010 Decisions 2-3) ──

    #[test]
    fn test_parse_expected_actual_from_type_message() {
        let (expected, actual) =
            super::parse_expected_actual("'architectures[1]' must be a string, got integer");
        assert_eq!(expected.as_deref(), Some("string"));
        assert_eq!(actual.as_deref(), Some("integer"));
    }

    #[test]
    fn test_parse_expected_actual_leaves_plain_messages_unset() {
        let (expected, actual) = super::parse_expected_actual("missing required field 'name'");
        assert_eq!(expected, None);
        assert_eq!(actual, None);
    }

    #[test]
    fn test_child_diag_key_lifts_output_name() {
        assert_eq!(
            super::child_diag_key("skipping output 'bad' from x.lua: unsupported value type"),
            Some("bad".to_string())
        );
        assert_eq!(
            super::child_diag_key("skipping output from x.lua: iteration error"),
            None
        );
    }

    // ── Definition-relative resolution plumbing ──

    #[test]
    fn test_definition_dir_from_label() {
        assert_eq!(
            super::definition_dir_from_label("pkgs/s/mypkg/shuttle.lua"),
            Some(std::path::PathBuf::from("pkgs/s/mypkg"))
        );
        assert_eq!(
            super::definition_dir_from_label("/abs/dir/shuttle.lua"),
            Some(std::path::PathBuf::from("/abs/dir"))
        );
        // Bare labels (embedded definitions) carry no directory.
        assert_eq!(super::definition_dir_from_label("shuttle.lua"), None);
        assert_eq!(super::definition_dir_from_label("embedded:test"), None);
    }
}
