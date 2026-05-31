use std::collections::HashMap;

use miette::{IntoDiagnostic, WrapErr};
use mlua::Value;

/// A named output configuration, keyed by output name (e.g. "default", "server", "cli").
pub type Outputs = HashMap<String, Value>;

/// Evaluate a Lua file and return the table of named outputs.
///
/// The file must return a Lua table (`{ default = { ... }, ... }`).
/// The shoot DSL globals (`snap()`, `app()`) are injected before evaluation.
/// Returns `Err` if the file cannot be read, is invalid Lua, or does not return a table.
pub fn evaluate_file(path: &str) -> miette::Result<Outputs> {
    let lua = mlua::Lua::new();
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;

    // Inject DSL globals before evaluating the user's config
    lua.load(crate::dsl::INIT_LUA)
        .exec()
        .map_err(|e| miette::miette!("failed to initialize shoot DSL: {}", e))?;

    let chunk = lua.load(&source);
    let result: Value = chunk.eval().map_err(|e| miette::miette!("{}", e))?;

    match result {
        Value::Table(table) => {
            let mut outputs = Outputs::new();
            for pair in table.pairs::<String, Value>() {
                let (key, value) = pair.map_err(|e| miette::miette!("{}", e))?;
                outputs.insert(key, value);
            }
            Ok(outputs)
        }
        other => Err(miette::miette!(
            "{} must return a table of outputs, got {}",
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
        let path = "/tmp/test_shoot_non_table.lua";
        std::fs::write(path, "return 42").unwrap();
        let result = evaluate_file(path);
        assert!(result.is_err());
        let _ = std::fs::remove_file(path);
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
        // Match the examples/hello/shoot.lua structure
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
}
