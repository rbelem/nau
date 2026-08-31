//! Golden-parity Lua path: run the ORIGINAL pkgs/*.lua through mlua with the
//! REAL production prelude (../src/dsl/init.lua) and a Rust-host index(),
//! extract to JSON. This is the incumbent side of the parity diff.

use anyhow::{Context as _, Result};
use mlua::{Lua, LuaSerdeExt, Value as LuaValue};
use serde_json::Value;

fn luaerr(e: mlua::Error) -> anyhow::Error {
    anyhow::anyhow!(e.to_string())
}

fn repo_root() -> std::path::PathBuf {
    // spike/ is one level below the repo root; CARGO_MANIFEST_DIR is spike/.
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub fn dsl_prelude_src() -> Result<String> {
    std::fs::read_to_string(repo_root().join("src/dsl/init.lua"))
        .context("reading the production Lua DSL prelude src/dsl/init.lua")
}

pub fn pkg_src(rel: &str) -> Result<String> {
    std::fs::read_to_string(repo_root().join(rel))
        .with_context(|| format!("reading golden package {rel}"))
}

/// Rust-host index() mirroring shoot's src/index.rs::lua_index_entry +
/// entry_to_lua_table (reads the same package-index.json the Nickel path gets).
fn register_index(lua: &Lua, index_path: &std::path::Path, arch: &'static str) -> Result<()> {
    let raw = std::fs::read_to_string(index_path)
        .with_context(|| format!("reading {}", index_path.display()))?;
    let index: Value = serde_json::from_str(&raw)?;

    let find = move |lua: &Lua, name: String| -> mlua::Result<LuaValue> {
        let entries = index
            .get("entries")
            .and_then(|e| e.as_object())
            .ok_or_else(|| mlua::Error::external("package index has no entries"))?;

        // find_by_name_or_alias
        let entry = entries
            .values()
            .find(|e| {
                e.get("name").and_then(|n| n.as_str()) == Some(name.as_str())
                    || e.get("aliases")
                        .and_then(|a| a.as_array())
                        .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(name.as_str())))
            })
            .ok_or_else(|| {
                mlua::Error::external(format!("snap '{name}' not found in package index"))
            })?;

        // entry_to_lua_table: { name, revision?, sha3_384? }
        let table = lua.create_table()?;
        table.set("name", entry.get("name").and_then(|n| n.as_str()).unwrap_or(&name))?;
        if let Some(pin) = entry.get("pins").and_then(|p| p.get(arch)) {
            if let Some(rev) = pin.get("revision").and_then(|v| v.as_i64()) {
                table.set("revision", rev)?;
            }
            if let Some(sha) = pin.get("sha3_384").and_then(|v| v.as_str()) {
                table.set("sha3_384", sha)?;
            }
        }
        Ok(LuaValue::Table(table))
    };

    let f = lua.create_function(find).map_err(luaerr)?;
    lua.globals().set("index", f).map_err(luaerr)?;
    Ok(())
}

/// Evaluate one package file through the Lua path and extract to JSON.
pub fn eval_lua_pkg(index_path: &std::path::Path, pkg_rel_path: &str) -> Result<Value> {
    let lua = Lua::new();

    let prelude = dsl_prelude_src()?;
    lua.load(&prelude).set_name("=src/dsl/init.lua").exec().map_err(luaerr)?;
    // Production order (src/lua.rs): the Rust host index REPLACES the prelude's
    // Lua fallback global after the DSL prelude is loaded.
    register_index(&lua, index_path, "amd64")?;

    let src = pkg_src(pkg_rel_path)?;
    // Mirror shoot's require() setup: the package's own directory is on the
    // module path (pkgs/j/jq/lib.lua is required as "lib").
    let pkg_dir = repo_root().join(pkg_rel_path).parent().unwrap().to_string_lossy().into_owned();
    lua.load(format!("package.path = {pkg_dir:?} .. '/?.lua;' .. package.path"))
        .exec()
        .map_err(luaerr)?;
    let value: LuaValue = lua
        .load(&src)
        .set_name(format!("={pkg_rel_path}"))
        .eval()
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .with_context(|| format!("evaluating {pkg_rel_path}"))?;

    lua.from_value(value).map_err(|e| anyhow::anyhow!(e.to_string()))
}
