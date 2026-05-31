use std::collections::HashMap;

use miette::{IntoDiagnostic, WrapErr};
use mlua::Value;

/// A named output configuration, keyed by output name (e.g. "default", "server", "cli").
pub type Outputs = HashMap<String, Value>;

/// Evaluate a Lua file and return the table of named outputs.
///
/// The file must return a Lua table (`{ default = { ... }, ... }`).
/// Returns `Err` if the file cannot be read, is invalid Lua, or does not return a table.
pub fn evaluate_file(path: &str) -> miette::Result<Outputs> {
    let lua = mlua::Lua::new();
    let source = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read {}", path))?;

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

    #[test]
    fn test_evaluate_empty_table() {
        let lua = mlua::Lua::new();
        let table: Value = lua.load("return {}").eval().unwrap();
        assert!(matches!(table, Value::Table(_)));
    }

    #[test]
    fn test_evaluate_single_output_table() {
        let lua = mlua::Lua::new();
        let table: Value = lua
            .load(
                r#"return {
                    default = {
                        name = "my-snap",
                        version = "1.0.0",
                    }
                }"#,
            )
            .eval()
            .unwrap();

        match table {
            Value::Table(t) => {
                let default: Value = t.get("default").unwrap();
                match default {
                    Value::Table(dt) => {
                        let name: String = dt.get("name").unwrap();
                        assert_eq!(name, "my-snap");
                    }
                    _ => panic!("expected table for default"),
                }
            }
            _ => panic!("expected top-level table"),
        }
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
        let lua = mlua::Lua::new();
        let result: std::result::Result<Value, mlua::Error> = lua.load("return 42").eval();
        // This should succeed at the Lua level — it's valid Lua returning a number.
        // The table-or-error check happens in our evaluate_file wrapper.
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), Value::Integer(42)));
    }

    #[test]
    fn test_evaluate_file_requires_table() {
        // Write a temp file that returns a non-table, then check that evaluate_file rejects it.
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
}
