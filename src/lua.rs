use std::collections::HashMap;

use miette::{IntoDiagnostic, WrapErr};
use mlua::Value;

use crate::image::ImageDeclaration;
use crate::snap::{PackageInput, SnapMeta};

/// Named outputs from a `shuttle.lua`, fully converted to owned Rust types.
pub type Outputs = HashMap<String, SnapMeta>;

/// Create a Lua instance with DSL globals injected and package.path configured.
pub fn new_lua(path: &str) -> miette::Result<mlua::Lua> {
    let lua = mlua::Lua::new();

    // Inject DSL globals before evaluating the user's config
    lua.load(crate::dsl::INIT_LUA)
        .exec()
        .map_err(|e| miette::miette!("failed to initialize shuttle DSL: {}", e))?;

    // Configure package.path so require() can find sibling .lua files
    if let Some(parent) = std::path::Path::new(path).parent() {
        let parent_str = parent.to_string_lossy().replace('\\', "/");
        let pkg_path = format!("{parent_str}/?.lua;{parent_str}/?/init.lua;");
        lua.globals()
            .get::<mlua::Table>("package")
            .ok()
            .and_then(|pkg| {
                let current: String = pkg.get("path").ok()?;
                pkg.set("path", pkg_path.clone() + &current).ok()
            });
    }

    // Register the index() function from Rust (handles file I/O)
    let arch = std::env::var("SHOOT_ARCH").unwrap_or_else(|_| "amd64".into());
    let index_path_env = std::env::var("SHOOT_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::index::DEFAULT_INDEX));

    let index_fn = lua
        .create_function(move |lua_ctx, name: String| {
            crate::index::lua_index_entry(lua_ctx, name, arch.clone(), index_path_env.clone())
        })
        .map_err(|e| miette::miette!("failed to register index(): {e}"))?;

    lua.globals()
        .set("index", index_fn)
        .map_err(|e| miette::miette!("failed to set index global: {e}"))?;

    Ok(lua)
}

/// Evaluate Lua source content and return the converted snap outputs.
///
/// Like `evaluate_file` but takes the Lua source string directly instead of
/// reading from disk. Used for embedded packages that don't exist as files.
pub fn evaluate_string(label: &str, source: &str) -> miette::Result<Outputs> {
    let lua = new_lua(label)?;

    let result: Value = lua
        .load(source)
        .eval()
        .map_err(|e| miette::miette!("{}: {}", label, e))?;

    match result {
        Value::Table(table) => {
            let mut outputs = Outputs::new();
            for pair in table.pairs::<String, Value>() {
                let (key, value) = pair.map_err(|e| miette::miette!("{}: {}", label, e))?;
                match SnapMeta::from_lua_value(&value) {
                    Ok(meta) => {
                        outputs.insert(key, meta);
                    }
                    Err(e) => {
                        crate::output::warn(format!("skipping output '{key}' from {label}: {e}"))
                    }
                }
            }
            Ok(outputs)
        }
        other => Err(miette::miette!(
            "{} must return a table of outputs, got {}",
            label,
            other.type_name()
        )),
    }
}

/// Evaluate a Lua file and return the converted snap outputs.
///
/// The file must return a Lua table of snap declarations.
/// The shuttle DSL globals (`snap()`, `app()`) are injected before evaluation.
/// All Lua data is converted to owned `SnapMeta` structs before returning
/// (the mlua state is dropped within this function).
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

/// Evaluate Lua source and return both outputs and global inputs.
pub fn evaluate_string_with_inputs(label: &str, source: &str) -> miette::Result<EvalOutput> {
    let lua = new_lua(label)?;

    let result: Value = lua
        .load(source)
        .eval()
        .map_err(|e| miette::miette!("{}: {}", label, e))?;

    let global_inputs = extract_inputs_from_lua(&lua)?;

    match result {
        Value::Table(table) => {
            let mut outputs = Outputs::new();
            for pair in table.pairs::<String, Value>() {
                let (key, value) = pair.map_err(|e| miette::miette!("{}: {}", label, e))?;
                match SnapMeta::from_lua_value(&value) {
                    Ok(meta) => {
                        outputs.insert(key, meta);
                    }
                    Err(e) => {
                        crate::output::warn(format!("skipping output '{key}' from {label}: {e}"))
                    }
                }
            }
            Ok(EvalOutput {
                outputs,
                global_inputs,
            })
        }
        other => Err(miette::miette!(
            "{} must return a table of outputs, got {}",
            label,
            other.type_name()
        )),
    }
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
        Value::Table(t) => {
            let mut inputs = HashMap::new();
            for pair in t.pairs::<String, Value>() {
                let (name, val) = pair.map_err(|e| miette::miette!("inputs entry: {e}"))?;
                match val {
                    Value::Table(input_table) => {
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
        Value::Nil => Ok(HashMap::new()),
        other => Err(miette::miette!(
            "'inputs' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Evaluate a Lua file and extract image declarations.
pub fn evaluate_images(
    lua: &mlua::Lua,
    path: &str,
) -> miette::Result<HashMap<String, ImageDeclaration>> {
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;

    let result: Value = lua
        .load(&source)
        .eval()
        .map_err(|e| miette::miette!("{}", e))?;

    match result {
        Value::Table(table) => {
            let mut images = HashMap::new();
            for pair in table.pairs::<String, Value>() {
                let (key, value) = pair.map_err(|e| miette::miette!("{}", e))?;
                if let Value::Table(t) = value {
                    match ImageDeclaration::from_lua_table(&t) {
                        Ok(decl) => {
                            images.insert(key, decl);
                        }
                        Err(e) => {
                            crate::output::warn(format!("skipping image '{key}' from {path}: {e}"))
                        }
                    }
                }
            }
            Ok(images)
        }
        other => Err(miette::miette!(
            "{} must return a table, got {}",
            path,
            other.type_name()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a fresh Lua instance with the DSL globals injected.
    fn with_dsl() -> mlua::Lua {
        let lua = mlua::Lua::new();
        lua.load(crate::dsl::INIT_LUA)
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
    fn test_evaluate_file_requires_table() {
        let path = "/tmp/test_shuttle_non_table.lua";
        std::fs::write(path, "return 42").unwrap();
        let result = evaluate_file(path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_broken_output_is_skipped_with_warning_not_silently_dropped() {
        let source = r#"
        return {
            good = snap { name = "good-snap", version = "1.0" },
            bad = "not-a-snap-table",
        }
        "#;
        let outputs = evaluate_string("test-broken", source)
            .expect("broken output should warn and be skipped, not fail the eval");
        assert_eq!(outputs.len(), 1, "only the valid output should be kept");
        assert!(outputs.contains_key("good"));
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

    #[test]
    fn test_composed_config_via_evaluate_file() {
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
        assert_eq!(meta.summary.as_deref(), Some("A snap built with shuttle"));
        assert_eq!(meta.grade, "stable");
        assert_eq!(meta.confinement, "strict");
    }
}
