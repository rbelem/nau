//! The Lua-side constructors for the shared vocabulary (issue #326).
//!
//! The value types live in `nau-core` (`nau_core::snap_types`,
//! `nau_core::manifest_ir`), and Rust only permits inherent impls in the
//! defining crate — but `nau-core` stays mlua-free, so their Lua-parsing
//! constructors live HERE as extension traits (the orphan rule then pins
//! the trait definitions beside their impls). The root crate's `snap`
//! and `image` modules re-export the traits so every pre-existing
//! `crate::snap_lua::FromLuaTable`-style path keeps resolving.
//!
//! Moved verbatim from root `snap.rs` and `image/mod.rs` (#326).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use mlua::Value;
use nau_core::channels::BOOTLOADER_PIBOOT;
// The mksquashfs compression contract + the source dir name down-moved to
// the core vocabulary (ADR-0053 pre-PR-2); re-exported so every
// `nau_chart::snap_lua::*` path — and this module's own callers — keep
// resolving unchanged.
use nau_core::manifest_ir::{
    BootloaderConfig, DiskLayout, ImageDeclaration, KernelEntry, Partition, StagedFile, SwapConfig,
};
pub use nau_core::snap::{
    effective_compression, validate_compression_choice, validate_compression_level, SOURCE_DIR_NAME,
};
use nau_core::snap_types::PackageInput;
use nau_core::snap_types::{
    default_confinement, default_grade, BackendKind, Confinement, DepsLockSpec, LayoutEntry,
    PackageDeps, PlugSlot, ServiceDaemon, ServiceDecl, SnapApp, SnapHook, SnapMeta, SnapPart,
    SnapPlug, SnapRef, SourceSpec, SubmoduleSpec, TmpfsSpec,
};

// ── Lua-side constructors for the shared vocabulary (ADR-0051) ──
//
// The value types now live in the `nau-core` crate (`crate::snap_types`
// re-exports them), and Rust only permits inherent impls in the defining
// crate. Their Lua-parsing constructors are eval/build-side machinery —
// `nau-core` stays mlua-free — so they remain here as extension traits.
// Import the trait wherever these constructors are called.

/// Construct from a Lua pin table (`pin = pin { … }`), validated by the DSL.
pub trait FromPinTable: Sized {
    fn from_pin_table(table: &mlua::Table) -> miette::Result<Self>;
}

/// Construct from an `mlua::Value` (must be a table).
pub trait FromLuaValue: Sized {
    fn from_lua_value(value: &mlua::Value) -> miette::Result<Self>;
}

/// Construct from a validated Lua table.
pub trait FromLuaTable: Sized {
    fn from_lua_table(table: &mlua::Table) -> miette::Result<Self>;
}

/// Construct from a validated Lua table plus the map key naming it
/// (`app = { … }`, `service = { … }` — the key names the errors).
pub trait FromLuaTableNamed: Sized {
    fn from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<Self>;
}

/// Module-private: layout entry parsing (via `SnapMeta::from_lua_table`).
trait LayoutEntryLua: Sized {
    fn from_lua_table(target: &str, t: &mlua::Table) -> miette::Result<Self>;
}

/// Module-private: typed plug/slot parsing (via `SnapMeta::from_lua_table`).
trait PlugSlotLua: Sized {
    fn from_lua_table(label: &str, t: &mlua::Table) -> miette::Result<Self>;
}

impl FromPinTable for SnapRef {
    /// Create from a Lua pin table (validated by the DSL).
    fn from_pin_table(table: &mlua::Table) -> miette::Result<Self> {
        let name: String = table
            .get("name")
            .map_err(|_| miette::miette!("pin(): missing required field 'name'"))?;
        let revision: Option<u32> = table.get("revision").ok();
        let sha3_384: Option<String> = table.get("sha3_384").ok();

        Ok(SnapRef {
            name,
            revision,
            sha3_384,
        })
    }
}

/// Parse a `submodules` declaration from an input table value.
/// `true` → all entries; a non-empty table of strings → named entries;
/// `false`/absent → `None`. Anything else fails, naming `ctx`.
pub fn parse_submodule_spec(v: mlua::Value, ctx: &str) -> miette::Result<Option<SubmoduleSpec>> {
    match v {
        mlua::Value::Nil | mlua::Value::Boolean(false) => Ok(None),
        mlua::Value::Boolean(true) => Ok(Some(SubmoduleSpec::All(true))),
        mlua::Value::Table(t) => {
            let mut names = Vec::new();
            for item in t.sequence_values::<String>() {
                let name = item.map_err(|e| miette::miette!("{ctx}: {e}"))?;
                if name.is_empty() {
                    return Err(miette::miette!("{ctx}: submodule names must not be empty"));
                }
                names.push(name);
            }
            if names.is_empty() {
                return Err(miette::miette!(
                    "{ctx}: 'submodules' list must not be empty — omit the field to fetch none"
                ));
            }
            Ok(Some(SubmoduleSpec::Named(names)))
        }
        other => Err(miette::miette!(
            "{ctx}: 'submodules' must be true or a list of submodule names, got {}",
            other.type_name()
        )),
    }
}

/// Environment VALUES keep their literal quoting contract: quotes and
/// backslashes are render-escaped, but a control character (a raw
/// newline) would still break the `Environment="…"` line, so it is
/// rejected here (issue #109 S5).
fn validate_env_value_text(service: &str, key: &str, value: &str) -> miette::Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        miette::bail!(
            "service '{service}': field 'environment.{key}': control characters are not \
             allowed in environment values — found {c:?} (quotes are escaped at render; \
             a control character would break the Environment line)"
        );
    }
    Ok(())
}

impl FromLuaTableNamed for ServiceDecl {
    /// Convert a Lua service table (from `service()` or a plain table)
    /// into a [`ServiceDecl`]. `name` is the service's key in `services`,
    /// used to name errors.
    ///
    /// Unknown fields are rejected here FIRST (not silently dropped):
    /// anything the schema doesn't know would otherwise vanish between
    /// the DSL and the emitted backend artifact — the same rule as
    /// [`SnapApp::from_lua_table`].
    fn from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<Self> {
        const VALID_FIELDS: &str =
            "command, daemon, args, options, after, environment, backend_options";
        let mut unknown: Vec<String> = Vec::new();
        for pair in table.pairs::<String, Value>() {
            let (k, _) = pair.map_err(|e| miette::miette!("service '{name}': {e}"))?;
            if !matches!(
                k.as_str(),
                "command"
                    | "daemon"
                    | "args"
                    | "options"
                    | "after"
                    | "environment"
                    | "backend_options"
            ) {
                unknown.push(k);
            }
        }
        if !unknown.is_empty() {
            unknown.sort();
            let list = unknown
                .iter()
                .map(|k| format!("'{k}'"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(miette::miette!(
                "service '{name}': unknown field(s) {list} (valid fields: {VALID_FIELDS})",
            ));
        }

        let command = match table.get::<Value>("command").unwrap_or(Value::Nil) {
            Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("service '{name}': field 'command': {e}"))?
                .to_string(),
            Value::Nil => {
                miette::bail!("service '{name}': field 'command' is required");
            }
            other => {
                return Err(miette::miette!(
                    "service '{name}': field 'command' must be a string, got {}",
                    other.type_name()
                ));
            }
        };
        let daemon = match table.get::<Value>("daemon").unwrap_or(Value::Nil) {
            Value::Nil => ServiceDaemon::Simple,
            Value::String(s) => {
                let kind: String = s
                    .to_str()
                    .map_err(|e| miette::miette!("service '{name}': field 'daemon': {e}"))?
                    .to_string();
                match kind.as_str() {
                    "simple" => ServiceDaemon::Simple,
                    "notify" => ServiceDaemon::Notify,
                    "forking" => ServiceDaemon::Forking,
                    "oneshot" => {
                        miette::bail!(
                            "service '{name}': field 'daemon' kind 'oneshot' is out of scope \
                             for v1 (ADR-0032 Decision 2)"
                        );
                    }
                    other => {
                        miette::bail!(
                            "service '{name}': field 'daemon' must be one of simple, notify, \
                             forking, got '{other}'"
                        );
                    }
                }
            }
            other => {
                return Err(miette::miette!(
                    "service '{name}': field 'daemon' must be a string, got {}",
                    other.type_name()
                ));
            }
        };
        let args = get_service_string_array(name, table, "args")?;
        let options = get_service_options(name, table)?;
        let after = get_service_string_array(name, table, "after")?;
        let environment = get_service_environment(name, table)?;
        let backend_options = get_service_backend_options(name, table)?;

        // Interpolation is validated fail-closed at parse: the option
        // set is fully known only after the fields above are read. The
        // exec-surface boundary rides the same loops (issue #109 S5):
        // command / args / option values reach the ExecStart line, so
        // control characters are rejected here — quotes stay legal
        // (the emitter single-quotes every arg).
        let option_keys: std::collections::BTreeSet<String> = options.keys().cloned().collect();
        validate_service_interpolation(name, "command", &command, &option_keys)?;
        validate_exec_text(name, "command", &command)?;
        for (i, arg) in args.iter().enumerate() {
            validate_service_interpolation(name, &format!("args[{}]", i + 1), arg, &option_keys)?;
            validate_exec_text(name, &format!("args[{}]", i + 1), arg)?;
        }
        for (key, value) in &options {
            if let Some(s) = value.as_str() {
                validate_service_interpolation(name, &format!("options.{key}"), s, &option_keys)?;
                validate_exec_text(name, &format!("options.{key}"), s)?;
            }
        }
        for (key, value) in &environment {
            validate_unit_text(name, &format!("environment.{key} (key)"), key)?;
            validate_service_env_literal(name, key, value)?;
            validate_env_value_text(name, key, value)?;
        }
        for (i, target) in after.iter().enumerate() {
            // An `after` target renders raw into an After= line: the
            // unit-text boundary applies (issue #109 S5).
            validate_unit_text(name, &format!("after[{}]", i + 1), target)?;
        }

        Ok(ServiceDecl {
            command,
            daemon,
            args,
            options,
            after,
            environment,
            backend_options,
        })
    }
}

/// Read a required-array-of-strings service field; every non-string entry
/// is an error naming the position (unlike [`get_opt_string_array`], which
/// silently skips — service parsing must fail closed).
fn get_service_string_array(
    service: &str,
    table: &mlua::Table,
    key: &str,
) -> miette::Result<Vec<String>> {
    let mut out = Vec::new();
    match table.get::<Value>(key).unwrap_or(Value::Nil) {
        Value::Nil => Ok(out),
        Value::Table(t) => {
            for pair in t.pairs::<usize, Value>() {
                let (idx, value) =
                    pair.map_err(|e| miette::miette!("service '{service}': field '{key}': {e}"))?;
                match value {
                    Value::String(s) => out.push(
                        s.to_str()
                            .map_err(|e| {
                                miette::miette!("service '{service}': field '{key}': {e}")
                            })?
                            .to_string(),
                    ),
                    other => {
                        return Err(miette::miette!(
                            "service '{service}': field '{key}' must be an array of \
                             strings — entry {idx} is {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(out)
        }
        other => Err(miette::miette!(
            "service '{service}': field '{key}' must be an array of strings, got {}",
            other.type_name()
        )),
    }
}

/// Read the `options` map: NixOS-style options with defaults. Keys are
/// strings, values must be scalars (string | number | boolean) — tables
/// and functions have no meaning in an option value. `enabled` is a named
/// option with boolean semantics (ADR-0032 Decisions 2 and 7), so a
/// non-boolean value fails here rather than materializing a lie.
fn get_service_options(
    service: &str,
    table: &mlua::Table,
) -> miette::Result<BTreeMap<String, serde_json::Value>> {
    let mut out = BTreeMap::new();
    let Some(t) = get_service_table(service, table, "options")? else {
        return Ok(out);
    };
    for pair in t.pairs::<String, Value>() {
        let (key, value) =
            pair.map_err(|e| miette::miette!("service '{service}': field 'options': {e}"))?;
        let json = match value {
            Value::String(s) => serde_json::Value::String(
                s.to_str()
                    .map_err(|e| miette::miette!("service '{service}': field 'options': {e}"))?
                    .to_string(),
            ),
            Value::Integer(i) => serde_json::Value::from(i),
            Value::Number(n) => serde_json::Number::from_f64(n)
                .map(serde_json::Value::Number)
                .ok_or_else(|| {
                    miette::miette!("service '{service}': field 'options.{key}': non-finite number")
                })?,
            Value::Boolean(b) => serde_json::Value::Bool(b),
            other => {
                return Err(miette::miette!(
                    "service '{service}': field 'options.{key}' must be a scalar \
                     (string, number, or boolean), got {}",
                    other.type_name()
                ));
            }
        };
        if key == "enabled" && !json.is_boolean() {
            miette::bail!(
                "service '{service}': field 'options.enabled' must be a boolean, got {json}"
            );
        }
        out.insert(key, json);
    }
    Ok(out)
}

/// Read the `environment` map: literal string → string (the strict
/// get_opt_string_map shape, failing closed per entry).
fn get_service_environment(
    service: &str,
    table: &mlua::Table,
) -> miette::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(t) = get_service_table(service, table, "environment")? else {
        return Ok(out);
    };
    for pair in t.pairs::<String, Value>() {
        let (key, value) =
            pair.map_err(|e| miette::miette!("service '{service}': field 'environment': {e}"))?;
        match value {
            Value::String(s) => out.insert(
                key,
                s.to_str()
                    .map_err(|e| miette::miette!("service '{service}': field 'environment': {e}"))?
                    .to_string(),
            ),
            other => {
                return Err(miette::miette!(
                    "service '{service}': field 'environment.{key}' must be a string, got {}",
                    other.type_name()
                ));
            }
        };
    }
    Ok(out)
}

/// Read the `backend_options` passthrough (ADR-0032 Decision 5, the
/// ADR-0016 grants pattern): keys must be exactly the known backends,
/// values are tables carried verbatim as JSON.
fn get_service_backend_options(
    service: &str,
    table: &mlua::Table,
) -> miette::Result<BTreeMap<String, serde_json::Value>> {
    const BACKENDS: &[&str] = &["systemd", "launchd", "portable"];
    let mut out = BTreeMap::new();
    let Some(t) = get_service_table(service, table, "backend_options")? else {
        return Ok(out);
    };
    for pair in t.pairs::<String, Value>() {
        let (key, value) =
            pair.map_err(|e| miette::miette!("service '{service}': field 'backend_options': {e}"))?;
        if !BACKENDS.contains(&key.as_str()) {
            miette::bail!(
                "service '{service}': field 'backend_options.{key}' names an unknown \
                 backend (allowed: {})",
                BACKENDS.join(", ")
            );
        }
        match value {
            Value::Table(_) => {
                let json = crate::isolate::lua_to_json(&value).map_err(|e| {
                    miette::miette!(
                        "service '{service}': field 'backend_options.{key}' must be a \
                         plain data table: {e}"
                    )
                })?;
                validate_backend_passthrough(service, &key, &json)?;
                out.insert(key, json);
            }
            other => {
                return Err(miette::miette!(
                    "service '{service}': field 'backend_options.{key}' must be a table, \
                     got {}",
                    other.type_name()
                ));
            }
        }
    }
    Ok(out)
}

/// The passthrough's inner keys and string values render verbatim into
/// the backend artifact (`Key=value` lines on systemd) — the unit-text
/// boundary applies to them too (issue #109 S5). Only the render surface
/// is checked: the passthrough's top-level scalar entries.
fn validate_backend_passthrough(
    service: &str,
    backend: &str,
    json: &serde_json::Value,
) -> miette::Result<()> {
    let Some(map) = json.as_object() else {
        return Ok(());
    };
    for (key, value) in map {
        validate_unit_text(
            service,
            &format!("backend_options.{backend}.{key} (key)"),
            key,
        )?;
        if let Some(text) = value.as_str() {
            validate_unit_text(service, &format!("backend_options.{backend}.{key}"), text)?;
        }
    }
    Ok(())
}

/// Fetch an optional service sub-table, failing closed on wrong types
/// (unlike [`get_opt_table`], which silently maps them to `None`).
fn get_service_table(
    service: &str,
    table: &mlua::Table,
    key: &str,
) -> miette::Result<Option<mlua::Table>> {
    match table.get::<Value>(key).unwrap_or(Value::Nil) {
        Value::Table(t) => Ok(Some(t)),
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "service '{service}': field '{key}' must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Parse a `confined` value from a Lua table (the DSL validates the shape;
/// this is the passive Rust conversion boundary).
pub fn confinement_from_lua(table: &mlua::Table) -> miette::Result<Confinement> {
    let backend = match table.get::<Value>("backend").unwrap_or(Value::Nil) {
        Value::Nil => BackendKind::default(),
        Value::String(s) => BackendKind::from_str(
            s.to_str()
                .map_err(|e| miette::miette!("confined.backend: {e}"))?
                .as_ref(),
        )
        .ok_or_else(|| miette::miette!("confined.backend must be 'bwrap' or 'apparmor'"))?,
        other => {
            return Err(miette::miette!(
                "confined.backend must be a string, got {}",
                other.type_name()
            ))
        }
    };
    let filesystem = get_opt_string_array(table, "filesystem")?.unwrap_or_default();
    let network = match table.get::<Value>("network").unwrap_or(Value::Nil) {
        Value::Nil => false,
        Value::Boolean(b) => b,
        other => {
            return Err(miette::miette!(
                "confined.network must be a boolean, got {}",
                other.type_name()
            ))
        }
    };
    let sockets = get_opt_string_array(table, "sockets")?.unwrap_or_default();
    let devices = get_opt_string_array(table, "devices")?.unwrap_or_default();
    let backend_options = get_opt_backend_options(table)?;

    Ok(Confinement {
        backend,
        filesystem,
        network,
        sockets,
        devices,
        backend_options,
    })
}

// ── §4 free functions (ADR-0053 council amendment): the passive Rust
// conversion boundary as plain functions, so the root build machinery
// consumes the vocabulary without naming the traits. The trait impls
// above stay the definitions; these are thin forwarders in the same
// style as [`confinement_from_lua`].

/// The `snap { … }` identity block (`name`, `version`, optional
/// `summary`) as a [`SnapRef`].
pub fn snap_ref_from_pin(table: &mlua::Table) -> miette::Result<SnapRef> {
    <SnapRef as FromPinTable>::from_pin_table(table)
}

/// A full `image { … }` declaration table as an [`ImageDeclaration`].
pub fn image_declaration_from_lua(table: &mlua::Table) -> miette::Result<ImageDeclaration> {
    <ImageDeclaration as FromLuaTable>::from_lua_table(table)
}

/// A parsed `snap { … }` table as a [`SnapMeta`].
pub fn snap_meta_from_lua_table(table: &mlua::Table) -> miette::Result<SnapMeta> {
    <SnapMeta as FromLuaTable>::from_lua_table(table)
}

/// One `app "name" { … }` table as a [`SnapApp`].
pub fn snap_app_from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<SnapApp> {
    <SnapApp as FromLuaTableNamed>::from_lua_table(name, table)
}

/// One `service "name" { … }` table as a [`ServiceDecl`].
pub fn service_decl_from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<ServiceDecl> {
    <ServiceDecl as FromLuaTableNamed>::from_lua_table(name, table)
}

/// Extract `backend_options`: a per-backend map of raw string values.
fn get_opt_backend_options(
    table: &mlua::Table,
) -> miette::Result<BTreeMap<String, serde_json::Value>> {
    let Some(t) = get_opt_table(table, "backend_options")? else {
        return Ok(BTreeMap::new());
    };
    let mut out = BTreeMap::new();
    for pair in t.pairs::<String, Value>() {
        let (key, value) = pair.map_err(|e| miette::miette!("confined.backend_options: {e}"))?;
        let json = crate::isolate::lua_to_json(&value)
            .map_err(|e| miette::miette!("confined.backend_options['{key}']: {e}"))?;
        out.insert(key, json);
    }
    Ok(out)
}

// ── Conversion from Lua (Phase 3) ──
//
// Per ADR-0002: Lua validates at eval time so Rust is a passive consumer.
// These conversions extract pre-validated fields — errors here indicate
// internal bugs or version mismatches, not user config errors.

impl FromLuaValue for SnapMeta {
    /// Convert from an `mlua::Value` (must be a table).
    fn from_lua_value(value: &mlua::Value) -> miette::Result<Self> {
        match value {
            Value::Table(table) => Self::from_lua_table(table),
            other => Err(miette::miette!(
                "expected a table from snap(), got {}",
                other.type_name()
            )),
        }
    }
}

impl FromLuaTable for SnapMeta {
    /// Convert a validated Lua table (from `snap()`) into a `SnapMeta`.
    fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
        let name = get_required_string(table, "name")?;
        let adopt_info = get_opt_string(table, "adopt_info")?;
        // With adopt-info, version (and summary/description) are adopted
        // from the named part at build time (see `extract_adopted_meta`).
        // Until then a "0" placeholder stands in for the schema; it is
        // marked with `version_adopted` so no identity output ever
        // presents it as a declared version, and a build without
        // extractable metadata fails hard instead of shipping it.
        let (version, version_adopted) = match get_opt_string(table, "version")? {
            Some(v) => (v, false),
            None if adopt_info.is_some() => ("0".to_string(), true),
            None => {
                return Err(miette::miette!(
                    "snap meta: field 'version' is required but invalid: missing, and no adopt_info set"
                ))
            }
        };
        let summary = get_opt_string(table, "summary")?;
        let description = get_opt_string(table, "description")?;
        let license = get_opt_string(table, "license")?;
        let source = get_source_spec(table)?;
        let sources = get_sources_spec(table)?;
        // One build tree shape at a time: a single tree at the build root
        // (`source`) or named trees under `$SRC` (`sources`) — never both.
        if source.is_some() && sources.is_some() {
            return Err(miette::miette!(
                "snap meta: 'source' and 'sources' are mutually exclusive — use one tree or named trees, not both"
            ));
        }
        let grade = get_opt_string(table, "grade")?.unwrap_or_else(default_grade);
        let confinement = get_opt_string(table, "confinement")?.unwrap_or_else(default_confinement);
        let architectures = get_opt_string_array(table, "architectures")?;
        let build = get_opt_string(table, "build")?;
        let parts = get_opt_parts(table)?;
        let type_: Option<String> = table.get("type").ok();
        let icon_source = get_opt_string(table, "icon")?;
        let icon = icon_target_from_source(icon_source.as_deref())?;
        let compression = get_opt_string(table, "compression")?;
        validate_compression_choice(compression.as_deref())?;
        let compression_level = get_opt_compression_level(table)?;
        validate_compression_level(compression.as_deref(), compression_level)?;
        let environment = get_opt_string_map(table, "environment")?;
        let layout = get_opt_layout(table)?;
        let hooks = get_opt_hooks(table)?;
        let plugs = get_opt_plug_map(table, "plugs")?;
        let slots = get_opt_plug_map(table, "slots")?;
        let aliases: Vec<String> = table.get("aliases").unwrap_or_default();
        let mut requires: Vec<String> = table.get("requires").unwrap_or_default();
        // Build-time-only dependencies (ADR-0018): same shape and validation
        // treatment as `requires` (the Lua DSL checks the array; unknown
        // names are rejected at resolution, exactly like `requires` names).
        let mut build_deps: Vec<String> = table.get("build_deps").unwrap_or_default();
        // Post-build leak-scan exceptions (ADR-0018 Decision 3): exact-match
        // strings that silence a named build-only reference. Same array
        // validation as the other name lists.
        let leaks_ok: Vec<String> = table.get("leaks_ok").unwrap_or_default();
        // Plugin parts contribute extra requires and extra build_deps —
        // expanded and deep-validated here so the Rust boundary is the
        // single choke point (ADR-0014 Decisions 3-4). Runtime toolchains
        // are gone: plugin toolchains land in `build_deps`, so they reach
        // the build sandbox but never the runtime closure (ADR-0018
        // Decision 5, issue #26). Dependency resolution reads these fields.
        if let Some(parts) = &parts {
            append_plugin_requires(parts, &mut requires)?;
            append_plugin_build_deps(parts, &mut build_deps)?;
        }
        let target: Option<String> = get_opt_string(table, "target")?;
        let toolchain: Option<String> = get_opt_string(table, "toolchain")?;
        let inputs: Option<HashMap<String, PackageInput>> = get_package_inputs(table)?;
        let confined = get_opt_table(table, "confined")?
            .map(|t| confinement_from_lua(&t))
            .transpose()?;
        let deps = get_opt_table(table, "deps")?
            .map(|t| package_deps_from_lua(&t))
            .transpose()?;
        // A dependency closure resolves from ONE of two roots: the
        // source tree (the lockfile ships in the source tarball) or the
        // recipe directory (the ADR-0017-addendum `recipe/` prefix — the
        // lockfile ships beside the recipe). `deps` therefore fails the
        // parse boundary only when it can resolve from NEITHER: a
        // source-relative lockfile without `source`. Recipe-local locks
        // need no source at all — which is what lets a multi-source
        // build (issue #41 `sources`) carry an ecosystem closure.
        if deps.is_some() && source.is_none() {
            let all_recipe_local = deps.as_ref().is_some_and(|d| d.all_locks_recipe_local());
            if !all_recipe_local {
                return Err(miette::miette!(
                    "snap meta: 'deps' requires 'source' — the lockfile resolves from the package source tree"
                ));
            }
        }
        // The adopt-info ladder reads ONE pinned source tree (its
        // extractors resolve relative to `$SRC`). With named sources there
        // is no single tree to read — reject instead of guessing.
        if adopt_info.is_some() && sources.is_some() {
            return Err(miette::miette!(
                "snap meta: 'adopt_info' is not supported with 'sources' — the adoption ladder reads a single source tree"
            ));
        }
        let floating = match table.get::<mlua::Value>("floating") {
            Ok(mlua::Value::Boolean(b)) => b,
            Ok(mlua::Value::Nil) => false,
            Ok(other) => {
                return Err(miette::miette!(
                    "snap meta: field 'floating' must be a boolean, got {}",
                    other.type_name()
                ))
            }
            Err(_) => false,
        };

        let apps = get_opt_table(table, "apps")?
            .map(|apps_table| {
                let mut apps = HashMap::new();
                for pair in apps_table.pairs::<String, Value>() {
                    let (name, value) = pair.map_err(|e| miette::miette!("apps entry: {}", e))?;
                    match value {
                        Value::Table(t) => {
                            apps.insert(name.clone(), SnapApp::from_lua_table(&name, &t)?);
                        }
                        other => {
                            return Err(miette::miette!(
                                "apps['{}'] must be a table, got {}",
                                name,
                                other.type_name()
                            ));
                        }
                    }
                }
                Ok(apps)
            })
            .transpose()?
            .unwrap_or_default();

        // Services (ADR-0032, issue #105): the name is the map key here
        // because it becomes every backend identifier component, so the
        // plain-name constraint checks where the name is first known.
        let services = get_opt_table(table, "services")?
            .map(|services_table| {
                let mut services = BTreeMap::new();
                for pair in services_table.pairs::<String, Value>() {
                    let (name, value) =
                        pair.map_err(|e| miette::miette!("services entry: {}", e))?;
                    validate_service_name(&name)?;
                    match value {
                        Value::Table(t) => {
                            services.insert(name.clone(), ServiceDecl::from_lua_table(&name, &t)?);
                        }
                        other => {
                            return Err(miette::miette!(
                                "services['{}'] must be a table, got {}",
                                name,
                                other.type_name()
                            ));
                        }
                    }
                }
                Ok(services)
            })
            .transpose()?
            .unwrap_or_default();

        Ok(SnapMeta {
            name,
            version,
            version_adopted,
            summary,
            description,
            license,
            source,
            sources,
            build,
            parts,
            architectures,
            grade,
            confinement,
            type_,
            adopt_info,
            icon_source,
            icon,
            compression,
            compression_level,
            environment,
            layout,
            hooks,
            plugs,
            slots,
            aliases,
            requires,
            build_deps,
            leaks_ok,
            target,
            toolchain,
            inputs,
            confined,
            apps,
            services,
            deps,
            floating,
            definition_dir: None,
        })
    }
}

/// Parse the `deps` table (ADR-0017): `{ npm = { lock = ... }, pip = { lock
/// = ..., index = ... }, cargo = { lock = ... }, go = { mods = ... } }` —
/// at least one resolver, known keys only, every resolver carrying a
/// non-empty string `lock` (or `mods` for go).
fn package_deps_from_lua(t: &mlua::Table) -> miette::Result<PackageDeps> {
    let mut npm = None;
    let mut pip = None;
    let mut cargo = None;
    let mut go = None;
    for pair in t.pairs::<String, mlua::Value>() {
        let (key, value) = pair.map_err(|e| miette::miette!("deps entry: {e}"))?;
        let value = match value {
            mlua::Value::Table(t) => t,
            other => {
                return Err(miette::miette!(
                    "deps['{key}'] must be a table, got {}",
                    other.type_name()
                ))
            }
        };
        match key.as_str() {
            "npm" | "pip" | "cargo" | "go" => {
                let spec = deps_lock_spec_from_lua(&key, &value)?;
                match key.as_str() {
                    "npm" => npm = Some(spec),
                    "pip" => pip = Some(spec),
                    "cargo" => cargo = Some(spec),
                    _ => go = Some(spec),
                }
            }
            other => {
                return Err(miette::miette!(
                    "deps: unknown resolver '{other}' (supported: npm, pip, cargo, go)"
                ))
            }
        }
    }
    if npm.is_none() && pip.is_none() && cargo.is_none() && go.is_none() {
        return Err(miette::miette!(
            "deps must name at least one resolver: npm, pip, cargo, or go"
        ));
    }
    Ok(PackageDeps {
        npm,
        pip,
        cargo,
        go,
    })
}

/// Parse one resolver's spec table: `lock` (required, relative to the
/// source root), `index` (optional registry override — pip's PEP 503
/// index, cargo's crates.io API base, go's GOPROXY), and — npm only —
/// `exclude` globs over lock keys (issue #14). pip, cargo, and go reject
/// `exclude`: pip has no lock keys to glob, and a lockfile is the complete
/// closure — partial vendoring would break the offline build it exists to
/// serve.
///
/// go (issue #40) accepts `mods` as an alias for `lock` (the ticket's
/// `deps = { go = { mods = "go.mod" } }`), plus an optional `sum` — the
/// go.sum path; when omitted it defaults to the sibling of `mods` with the
/// `.mod` extension replaced by `.sum` (go.mod → go.sum is the Go
/// toolchain's own invariant, preserving any `recipe/` prefix). Both
/// files resolve from the source tree, or from the package recipe
/// directory when `recipe/`-prefixed (see [`DepsLockSpec::lock`]).
pub fn deps_lock_spec_from_lua(key: &str, t: &mlua::Table) -> miette::Result<DepsLockSpec> {
    // go uses `mods` (the go.mod path); every other resolver uses `lock`.
    let lock = go_mods_alias(key, t)?
        .or(get_opt_string(t, "lock")?)
        .ok_or_else(|| {
            miette::miette!(
                "deps.{key}: field 'lock'{} is required (lockfile path relative to the source root)",
                if key == "go" { " (or 'mods')" } else { "" }
            )
        })?;
    if lock.is_empty() {
        return Err(miette::miette!("deps.{key}: 'lock' must not be empty"));
    }
    if lock.starts_with('/') {
        return Err(miette::miette!(
            "deps.{key}: 'lock' is relative to the source root — got absolute path '{lock}'"
        ));
    }
    let index = get_opt_string(t, "index")?;
    // go.sum: optional, defaults to the sibling of go.mod (go.mod → go.sum).
    let sum = match key {
        "go" => Some(go_sum_path(t, &lock)?),
        _ => None,
    };
    let exclude = match key {
        "npm" => npm_exclude_from_lua(t)?,
        "pip" => pip_exclude_from_lua(t)?,
        _ => {
            if pip_exclude_present(t) {
                return Err(miette::miette!(
                    "deps.{key}: 'exclude' is not supported (npm, pip only)"
                ));
            }
            Vec::new()
        }
    };
    let python = match key {
        "pip" => get_opt_string(t, "python")?,
        _ => {
            if get_opt_string(t, "python")?.is_some() {
                return Err(miette::miette!(
                    "deps.{key}: 'python' is not supported (pip only)"
                ));
            }
            None
        }
    };
    Ok(DepsLockSpec {
        lock,
        sum,
        index,
        exclude,
        python,
    })
}

/// go's `mods` alias for the lockfile path (only accepted for the go
/// resolver; other resolvers reject the key as unknown).
fn go_mods_alias(key: &str, t: &mlua::Table) -> miette::Result<Option<String>> {
    if key != "go" {
        if get_opt_string(t, "mods")?.is_some() {
            return Err(miette::miette!(
                "deps.{key}: 'mods' is a go-only field (use 'lock')"
            ));
        }
        return Ok(None);
    }
    get_opt_string(t, "mods")
}

/// The go.sum path: the explicit `sum` field, or the go.mod path with its
/// `.mod` extension replaced by `.sum` (Go's own convention). If go.mod
/// has no `.mod` extension (unusual), `go.sum` is the literal sibling.
fn go_sum_path(t: &mlua::Table, go_mod: &str) -> miette::Result<String> {
    if let Some(sum) = get_opt_string(t, "sum")? {
        if sum.starts_with('/') {
            return Err(miette::miette!(
                "deps.go: 'sum' is relative to the source root — got absolute path '{sum}'"
            ));
        }
        return Ok(sum);
    }
    let sum = if let Some(stem) = go_mod.strip_suffix(".mod") {
        format!("{stem}.sum")
    } else {
        format!("{go_mod}.sum")
    };
    Ok(sum)
}

/// The npm `exclude` globs: an optional string array; empty patterns are
/// rejected (an empty glob is always a typo, never a filter).
fn npm_exclude_from_lua(t: &mlua::Table) -> miette::Result<Vec<String>> {
    let Some(exclude) = get_opt_string_array(t, "exclude")? else {
        return Ok(Vec::new());
    };
    if exclude.iter().any(String::is_empty) {
        return Err(miette::miette!(
            "deps.npm: 'exclude' entries must not be empty"
        ));
    }
    Ok(exclude)
}

/// True when a pip spec table carries an `exclude` key (any value).
fn pip_exclude_present(t: &mlua::Table) -> bool {
    !matches!(t.get::<Value>("exclude").unwrap_or(Value::Nil), Value::Nil)
}

/// pip `exclude`: a plain array of exact package names (not globs) that
/// the closure fetch must skip — the declarative form of a documented
/// runtime degradation (e.g. a wheel that cannot serve the pod's
/// interpreter and whose absence the app itself tolerates).
fn pip_exclude_from_lua(t: &mlua::Table) -> miette::Result<Vec<String>> {
    let value = t.get::<Value>("exclude").unwrap_or(Value::Nil);
    let Value::Table(arr) = value else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for pair in arr.sequence_values::<Value>() {
        let Value::String(s) = pair.map_err(|e| miette::miette!("deps.pip: 'exclude': {e}"))?
        else {
            return Err(miette::miette!(
                "deps.pip: 'exclude' entries must be strings"
            ));
        };
        let name = s
            .to_str()
            .map_err(|e| miette::miette!("deps.pip: 'exclude': {e}"))?
            .to_string();
        if name.contains('*') || name.contains('?') {
            return Err(miette::miette!(
                "deps.pip: 'exclude' entries are exact package names — \
                 globs are an npm-only shape, got '{name}'"
            ));
        }
        out.push(name);
    }
    Ok(out)
}

/// Map an icon source path to its in-snap target (`meta/gui/icon.<ext>`),
/// preserving the extension as snapd expects.
fn icon_target_from_source(source: Option<&str>) -> miette::Result<Option<String>> {
    let Some(src) = source else {
        return Ok(None);
    };
    let ext = Path::new(src)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| !e.is_empty())
        .ok_or_else(|| {
            miette::miette!(
                "snap meta: 'icon' must have a file extension (e.g. icon.png), got '{src}'"
            )
        })?;
    Ok(Some(format!("meta/gui/icon.{ext}")))
}

impl LayoutEntryLua for LayoutEntry {
    /// Convert a validated Lua layout entry (exactly one of
    /// bind/bind_file/symlink/tmpfs) into a `LayoutEntry`.
    fn from_lua_table(target: &str, t: &mlua::Table) -> miette::Result<Self> {
        let bind = get_opt_entry_string(t, target, "bind")?;
        let bind_file = get_opt_entry_string(t, target, "bind_file")?;
        let symlink = get_opt_entry_string(t, target, "symlink")?;
        let tmpfs = get_opt_tmpfs(t, target)?;

        let count = bind.is_some() as u8
            + bind_file.is_some() as u8
            + symlink.is_some() as u8
            + tmpfs.is_some() as u8;
        if count == 0 {
            return Err(miette::miette!(
                "layout['{target}'] must have exactly one of bind, bind_file, symlink, tmpfs"
            ));
        }
        if count > 1 {
            return Err(miette::miette!(
                "layout['{target}'] must have exactly one of bind, bind_file, symlink, tmpfs (got {count})"
            ));
        }

        Ok(match (bind, bind_file, symlink, tmpfs) {
            (Some(v), None, None, None) => LayoutEntry::Bind(v),
            (None, Some(v), None, None) => LayoutEntry::BindFile(v),
            (None, None, Some(v), None) => LayoutEntry::Symlink(v),
            (None, None, None, Some(v)) => LayoutEntry::Tmpfs(v),
            _ => unreachable!("exactly-one constraint checked above"),
        })
    }
}

/// Read an optional string value from a layout entry table.
fn get_opt_entry_string(
    t: &mlua::Table,
    target: &str,
    key: &str,
) -> miette::Result<Option<String>> {
    match t.get::<Value>(key).unwrap_or(Value::Nil) {
        Value::String(s) => Ok(Some(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        )),
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "layout['{target}'].{key} must be a string, got {}",
            other.type_name()
        )),
    }
}

/// Read the optional tmpfs spec: bare `true` or a table with optional
/// string `size` (an empty table counts as bare).
fn get_opt_tmpfs(t: &mlua::Table, target: &str) -> miette::Result<Option<TmpfsSpec>> {
    match t.get::<Value>("tmpfs").unwrap_or(Value::Nil) {
        Value::Boolean(true) => Ok(Some(TmpfsSpec::Bare(true))),
        Value::Boolean(false) => Err(miette::miette!(
            "layout['{target}'].tmpfs must be true or a table with optional string 'size'"
        )),
        Value::Table(tt) => Ok(Some(match tt.get::<Value>("size").unwrap_or(Value::Nil) {
            Value::String(s) => TmpfsSpec::Sized {
                size: s
                    .to_str()
                    .map_err(|e| miette::miette!("{}", e))?
                    .to_string(),
            },
            Value::Nil => TmpfsSpec::Bare(true),
            other => {
                return Err(miette::miette!(
                    "layout['{target}'].tmpfs.size must be a string, got {}",
                    other.type_name()
                ));
            }
        })),
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "layout['{target}'].tmpfs must be true or a table, got {}",
            other.type_name()
        )),
    }
}

impl PlugSlotLua for PlugSlot {
    /// Convert a validated Lua plug/slot attribute table (required string
    /// `interface` plus string-valued attributes) into a `PlugSlot`.
    fn from_lua_table(label: &str, t: &mlua::Table) -> miette::Result<Self> {
        let interface = match t.get::<Value>("interface").unwrap_or(Value::Nil) {
            Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
            other => {
                return Err(miette::miette!(
                    "{label}.interface must be a string, got {}",
                    other.type_name()
                ));
            }
        };

        let mut attributes = BTreeMap::new();
        for pair in t.pairs::<String, Value>() {
            let (k, v) = pair.map_err(|e| miette::miette!("{label}: {e}"))?;
            if k == "interface" {
                continue;
            }
            match v {
                Value::String(s) => {
                    attributes.insert(
                        k,
                        s.to_str()
                            .map_err(|e| miette::miette!("{}", e))?
                            .to_string(),
                    );
                }
                other => {
                    return Err(miette::miette!(
                        "{label}.{k} must be a string, got {}",
                        other.type_name()
                    ));
                }
            }
        }

        Ok(PlugSlot {
            interface,
            attributes,
        })
    }
}

impl FromLuaTableNamed for SnapApp {
    /// Convert a validated Lua table (from `app()`) into a `SnapApp`.
    /// `name` is the app's key in `apps`, used to name errors.
    ///
    /// Unknown fields are rejected here (not silently dropped): anything
    /// the schema doesn't know would otherwise vanish between the DSL and
    /// the emitted snap.yaml — the same silent-drop bug class as outputs
    /// (e.g. a template emitting `restart_condition`, which the schema
    /// never supported).
    fn from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<Self> {
        let mut unknown: Vec<String> = Vec::new();
        for pair in table.pairs::<String, Value>() {
            let (k, _) = pair.map_err(|e| miette::miette!("app '{name}': {e}"))?;
            if !matches!(
                k.as_str(),
                "command"
                    | "daemon"
                    | "plugs"
                    | "slots"
                    | "environment"
                    | "desktop"
                    | "interpreter"
                    | "confined"
            ) {
                unknown.push(k);
            }
        }
        if !unknown.is_empty() {
            unknown.sort();
            let list = unknown
                .iter()
                .map(|k| format!("'{k}'"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(miette::miette!(
                "app '{name}': unknown field{} {list} (valid fields: command, daemon, plugs, slots, environment, desktop, interpreter, confined)",
                if unknown.len() == 1 { "" } else { "s" },
            ));
        }

        let command = get_required_string(table, "command")?;
        let daemon = get_opt_string(table, "daemon")?;
        let plugs = get_opt_string_array(table, "plugs")?;
        let slots = get_opt_string_array(table, "slots")?;
        let environment = get_opt_string_map(table, "environment")?;
        let desktop = get_opt_string(table, "desktop")?;
        if let Some(d) = &desktop {
            validate_desktop_path(name, d)?;
        }
        let interpreter = get_opt_string(table, "interpreter")?;
        let confined = get_opt_table(table, "confined")?
            .map(|t| confinement_from_lua(&t))
            .transpose()?;

        Ok(SnapApp {
            command,
            daemon,
            plugs,
            slots,
            environment,
            desktop,
            interpreter,
            confined,
        })
    }
}

/// Validate a `desktop` app field: a package-relative payload path to the
/// app's `.desktop` file. Must be relative (the payload root is implicit),
/// must not escape the payload with `..`, and must name a `.desktop` file
/// (snapd's own constraint on the app key).
fn validate_desktop_path(app: &str, path: &str) -> miette::Result<()> {
    if path.is_empty() {
        miette::bail!("app '{app}': 'desktop' must not be empty");
    }
    if path.starts_with('/') {
        miette::bail!(
            "app '{app}': 'desktop' must be a path inside the snap (relative), got {path:?}"
        );
    }
    if Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        miette::bail!("app '{app}': 'desktop' must not contain '..' (got {path:?})");
    }
    if !path.ends_with(".desktop") {
        miette::bail!("app '{app}': 'desktop' must name a .desktop file, got {path:?}");
    }
    Ok(())
}

// ── Lua table extraction helpers ──

fn get_required_string(table: &mlua::Table, key: &str) -> miette::Result<String> {
    table
        .get::<String>(key)
        .map_err(|e| miette::miette!("snap meta: field '{}' is required but invalid: {}", key, e))
}

fn get_opt_string(table: &mlua::Table, key: &str) -> miette::Result<Option<String>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::String(s) => Ok(Some(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        )),
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

fn get_opt_string_array(table: &mlua::Table, key: &str) -> miette::Result<Option<Vec<String>>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => {
            let mut items = Vec::new();
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("{}[{}]: {}", key, 0, e))?;
                if let Value::String(s) = value {
                    items.push(
                        s.to_str()
                            .map_err(|e| miette::miette!("{}", e))?
                            .to_string(),
                    );
                }
            }
            Ok(Some(items))
        }
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

fn get_opt_table(table: &mlua::Table, key: &str) -> miette::Result<Option<mlua::Table>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => Ok(Some(t)),
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

/// Extract an optional integer `compression_level`, rejecting fractional
/// values with a named error (mlua would accept `6.0` but the DSL contract
/// says integer — 6.5 fails here, not at mksquashfs).
fn get_opt_compression_level(table: &mlua::Table) -> miette::Result<Option<u32>> {
    match table
        .get::<Value>("compression_level")
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Integer(i) => u32::try_from(i).map(Some).map_err(|_| {
            miette::miette!(
                "snap meta: field 'compression_level' must be a positive integer, got {i}"
            )
        }),
        Value::Number(f) => {
            if f.fract() != 0.0 {
                return Err(miette::miette!(
                    "snap meta: field 'compression_level' must be an integer, got {f}"
                ));
            }
            u32::try_from(f as i64).map(Some).map_err(|_| {
                miette::miette!(
                    "snap meta: field 'compression_level' must be a positive integer, got {f}"
                )
            })
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "snap meta: field 'compression_level' must be an integer, got {}",
            other.type_name()
        )),
    }
}

/// Extract `source` which can be a string (legacy) or table `{ url, sha256? }`.
fn get_source_spec(table: &mlua::Table) -> miette::Result<Option<SourceSpec>> {
    let value: Value = table.get("source").unwrap_or(Value::Nil);
    match value {
        Value::String(s) => Ok(Some(SourceSpec::Unverified(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        ))),
        Value::Table(t) => {
            let url: String = t
                .get("url")
                .map_err(|_| miette::miette!("source table: missing required 'url' field"))?;
            let sha256: Option<String> = t.get("sha256").ok();
            Ok(match sha256 {
                Some(h) => Some(SourceSpec::Pinned { url, sha256: h }),
                None => Some(SourceSpec::Unverified(url)),
            })
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "snap meta: 'source' must be a string or table, got {}",
            other.type_name()
        )),
    }
}

/// Extract `sources` — the multi-source build-input map (issue #41):
/// `{ <name> = { url, sha256 }, ... }`. Unlike `source`, `sha256` is
/// REQUIRED per entry: a multi-source build declares its inputs
/// explicitly, so TOFU (trust-on-first-use) has no story for a hash
/// nobody pinned. Names become directory names under the build tree, so
/// they must be plain (no `/`, `.`, `..`) and never `source` — that name
/// is reserved for the shared single-source tree of parts builds.
/// Non-DSL constructors get the same validation the Lua DSL applies
/// (ADR-0002: Lua is the schema source of truth; Rust re-checks because
/// it is a passive consumer of pre-validated tables only in the DSL path).
fn get_sources_spec(table: &mlua::Table) -> miette::Result<Option<BTreeMap<String, SourceSpec>>> {
    let value: Value = table.get("sources").unwrap_or(Value::Nil);
    match value {
        Value::Nil => Ok(None),
        Value::Table(t) => {
            let mut map = BTreeMap::new();
            for pair in t.pairs::<String, Value>() {
                let (name, value) = pair.map_err(|e| miette::miette!("sources entry: {e}"))?;
                validate_source_name(&name)?;
                let Value::Table(spec) = value else {
                    return Err(miette::miette!(
                        "sources['{name}'] must be a table {{ url, sha256 }}, got {}",
                        value.type_name()
                    ));
                };
                let url: String = spec.get("url").map_err(|_| {
                    miette::miette!("sources['{name}']: missing required 'url' field")
                })?;
                let sha256: String = spec.get("sha256").map_err(|_| {
                    miette::miette!(
                        "sources['{name}'].sha256 is required (multi-source builds are always hash-pinned)"
                    )
                })?;
                map.insert(name, SourceSpec::Pinned { url, sha256 });
            }
            if map.is_empty() {
                return Err(miette::miette!(
                    "'sources' must not be empty — declare a 'source' instead"
                ));
            }
            Ok(Some(map))
        }
        other => Err(miette::miette!(
            "'sources' must be a table of name → {{ url, sha256 }}, got {}",
            other.type_name()
        )),
    }
}

/// Source (and part) names become directory names under the build tree;
/// keep them plain, and reserve the shared source dir name.
fn validate_source_name(name: &str) -> miette::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(miette::miette!(
            "invalid source name '{name}': must be a plain directory name (no '/', '.', '..')"
        ));
    }
    if name == SOURCE_DIR_NAME {
        return Err(miette::miette!(
            "invalid source name '{name}': reserved for the shared build source directory"
        ));
    }
    Ok(())
}

fn get_opt_string_map(
    table: &mlua::Table,
    key: &str,
) -> miette::Result<Option<BTreeMap<String, String>>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{}", e))?
    {
        Value::Table(t) => {
            let mut map = BTreeMap::new();
            for pair in t.pairs::<String, Value>() {
                let (k, v) = pair.map_err(|e| miette::miette!("{}: {}", key, e))?;
                if let Value::String(s) = v {
                    map.insert(
                        k,
                        s.to_str()
                            .map_err(|e| miette::miette!("{}", e))?
                            .to_string(),
                    );
                }
            }
            Ok(Some(map))
        }
        Value::Nil => Ok(None),
        _ => Ok(None),
    }
}

/// Extract `layout`: target path → exactly one of bind/bind_file/symlink/tmpfs.
fn get_opt_layout(table: &mlua::Table) -> miette::Result<Option<BTreeMap<String, LayoutEntry>>> {
    let Some(t) = get_opt_table(table, "layout")? else {
        return Ok(None);
    };
    let mut layout = BTreeMap::new();
    for pair in t.pairs::<String, Value>() {
        let (target, value) = pair.map_err(|e| miette::miette!("layout entry: {e}"))?;
        match value {
            Value::Table(entry_table) => {
                let entry = LayoutEntry::from_lua_table(&target, &entry_table)?;
                layout.insert(target, entry);
            }
            other => {
                return Err(miette::miette!(
                    "layout['{target}'] must be a table, got {}",
                    other.type_name()
                ));
            }
        }
    }
    Ok(Some(layout))
}

/// Extract `hooks`: hook name → script path. `command` follows snapd
/// convention: scripts live at `meta/hooks/<name>` (build_snap copies them
/// there from the DSL's source path).
fn get_opt_hooks(table: &mlua::Table) -> miette::Result<Option<BTreeMap<String, SnapHook>>> {
    let Some(t) = get_opt_table(table, "hooks")? else {
        return Ok(None);
    };
    let mut hooks = BTreeMap::new();
    for pair in t.pairs::<String, Value>() {
        let (name, value) = pair.map_err(|e| miette::miette!("hooks entry: {e}"))?;
        let script = match value {
            Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
            other => {
                return Err(miette::miette!(
                    "hooks['{name}'] must be a string script path, got {}",
                    other.type_name()
                ));
            }
        };
        hooks.insert(
            name.clone(),
            SnapHook {
                command: format!("meta/hooks/{name}"),
                source: script,
            },
        );
    }
    Ok(Some(hooks))
}

/// Extract `parts`: part name → { build | plugin, after?, options? }. The
/// Lua layer validates the schema (non-empty string command or known plugin
/// name, known/acyclic `after`, table options); this is the passive
/// conversion boundary. Plugin options are only shape-typed here — deep
/// validation happens at the plugin boundary ([`nau_core::plugins::expand`]).
fn get_opt_parts(table: &mlua::Table) -> miette::Result<Option<BTreeMap<String, SnapPart>>> {
    let Some(t) = get_opt_table(table, "parts")? else {
        return Ok(None);
    };
    let mut parts = BTreeMap::new();
    for pair in t.pairs::<String, Value>() {
        let (name, value) = pair.map_err(|e| miette::miette!("parts entry: {e}"))?;
        match value {
            Value::Table(pt) => {
                let plugin = get_part_plugin(&name, &pt)?;
                let build = if plugin.is_some() {
                    // Plugin parts carry an empty marker: the plugin IS the
                    // build (ADR-0014 Decision 2).
                    String::new()
                } else {
                    pt.get::<String>("build").map_err(|_| {
                        miette::miette!("parts['{name}']: 'build' must be a string command")
                    })?
                };
                let mut after = Vec::new();
                if let Value::Table(at) = pt.get::<Value>("after").unwrap_or(Value::Nil) {
                    for dep in at.pairs::<usize, Value>() {
                        let (_, v) =
                            dep.map_err(|e| miette::miette!("parts['{name}'].after: {e}"))?;
                        if let Value::String(s) = v {
                            after.push(
                                s.to_str()
                                    .map_err(|e| miette::miette!("{}", e))?
                                    .to_string(),
                            );
                        }
                    }
                }
                let plugin_options = get_part_options(&name, &pt)?;
                parts.insert(
                    name,
                    SnapPart {
                        build,
                        after,
                        plugin,
                        plugin_options,
                    },
                );
            }
            other => {
                return Err(miette::miette!(
                    "parts['{name}'] must be a table, got {}",
                    other.type_name()
                ));
            }
        }
    }
    Ok(Some(parts))
}

/// Extract one part's `plugin` name, if any.
fn get_part_plugin(name: &str, pt: &mlua::Table) -> miette::Result<Option<String>> {
    match pt.get::<Value>("plugin").unwrap_or(Value::Nil) {
        Value::Nil => Ok(None),
        Value::String(s) => Ok(Some(
            s.to_str()
                .map_err(|e| miette::miette!("{}", e))?
                .to_string(),
        )),
        other => Err(miette::miette!(
            "parts['{name}'].plugin must be a string, got {}",
            other.type_name()
        )),
    }
}

/// Extract one part's `options` table into raw [`PluginValue`]s. Table
/// values become arrays (integer keys, order-preserving) or string maps
/// (string keys); mixing the two shapes is an error.
fn get_part_options(
    name: &str,
    pt: &mlua::Table,
) -> miette::Result<Option<BTreeMap<String, nau_core::plugins::PluginValue>>> {
    match pt.get::<Value>("options").unwrap_or(Value::Nil) {
        Value::Nil => Ok(None),
        Value::Table(t) => {
            let mut options = BTreeMap::new();
            for pair in t.pairs::<Value, Value>() {
                let (key, value) =
                    pair.map_err(|e| miette::miette!("parts['{name}'].options: {e}"))?;
                let key = match key {
                    Value::String(s) => s
                        .to_str()
                        .map_err(|e| miette::miette!("{}", e))?
                        .to_string(),
                    other => {
                        return Err(miette::miette!(
                            "parts['{name}'].options: unsupported key type {}",
                            other.type_name()
                        ));
                    }
                };
                let label = format!("parts['{name}'].options['{key}']");
                options.insert(key, plugin_value_from_lua(&label, &value)?);
            }
            Ok(Some(options))
        }
        other => Err(miette::miette!(
            "parts['{name}'].options must be a table, got {}",
            other.type_name()
        )),
    }
}

/// Convert one plugin option value into a [`nau_core::plugins::PluginValue`].
fn plugin_value_from_lua(
    label: &str,
    value: &Value,
) -> miette::Result<nau_core::plugins::PluginValue> {
    match value {
        Value::String(s) => Ok(nau_core::plugins::PluginValue::Str(lua_str(s)?)),
        Value::Boolean(b) => Ok(nau_core::plugins::PluginValue::Bool(*b)),
        Value::Table(t) => plugin_table_value(label, t),
        other => Err(miette::miette!(
            "{label} must be a string, boolean, array of strings, or table of strings, got {}",
            other.type_name()
        )),
    }
}

/// Classify an option table: all-integer keys → ordered array of strings,
/// all-string keys → string map, empty → empty map, mixed → error.
fn plugin_table_value(
    label: &str,
    t: &mlua::Table,
) -> miette::Result<nau_core::plugins::PluginValue> {
    let mut items: Vec<(usize, String)> = Vec::new();
    let mut map = BTreeMap::new();
    for pair in t.pairs::<Value, Value>() {
        let (key, value) = pair.map_err(|e| miette::miette!("{label}: {e}"))?;
        match (key, value) {
            (Value::Integer(i), Value::String(s)) => items.push((i.max(0) as usize, lua_str(&s)?)),
            (Value::String(k), Value::String(s)) => {
                map.insert(lua_str(&k)?, lua_str(&s)?);
            }
            (key, Value::String(_)) => {
                return Err(miette::miette!(
                    "{label}: unsupported key type {}",
                    key.type_name()
                ));
            }
            (_, value) => {
                return Err(miette::miette!(
                    "{label}: option values must be strings, got {}",
                    value.type_name()
                ));
            }
        }
    }
    if !items.is_empty() && !map.is_empty() {
        return Err(miette::miette!(
            "{label}: cannot mix array and string-key entries"
        ));
    }
    if items.is_empty() && map.is_empty() {
        return Ok(nau_core::plugins::PluginValue::Map(map));
    }
    if !map.is_empty() {
        return Ok(nau_core::plugins::PluginValue::Map(map));
    }
    items.sort_by_key(|(index, _)| *index);
    Ok(nau_core::plugins::PluginValue::Arr(
        items.into_iter().map(|(_, s)| s).collect(),
    ))
}

/// Copy an mlua string into an owned Rust String.
fn lua_str(s: &mlua::LuaString) -> miette::Result<String> {
    s.to_str()
        .map_err(|e| miette::miette!("{}", e))
        .map(|s| s.to_string())
}

/// Append every plugin part's `extra_requires` to the snap's effective
/// requires (deduplicated, declaration order preserved). Also surfaces the
/// plugin boundary's named validation errors, prefixed with the part name.
fn append_plugin_requires(
    parts: &BTreeMap<String, SnapPart>,
    requires: &mut Vec<String>,
) -> miette::Result<()> {
    append_plugin_field(parts, |plan| &plan.extra_requires, requires)
}

/// Append every plugin part's `extra_build_deps` to the snap's effective
/// `build_deps` (deduplicated, declaration order preserved) — the path
/// plugin toolchains take into the build sandbox without entering the
/// runtime closure (ADR-0018 Decision 5, issue #26).
fn append_plugin_build_deps(
    parts: &BTreeMap<String, SnapPart>,
    build_deps: &mut Vec<String>,
) -> miette::Result<()> {
    append_plugin_field(parts, |plan| &plan.extra_build_deps, build_deps)
}

/// Shared append helper: expand each plugin part once and push its
/// contributed names (deduplicated, declaration order preserved) into
/// `target`, prefixed with the part name on a named validation error.
fn append_plugin_field(
    parts: &BTreeMap<String, SnapPart>,
    pick: impl Fn(&nau_core::plugins::BuildPlan) -> &Vec<String>,
    target: &mut Vec<String>,
) -> miette::Result<()> {
    for (name, part) in parts {
        let Some(plugin) = &part.plugin else {
            continue;
        };
        let plan = nau_core::plugins::expand(plugin, part.plugin_options.as_ref())
            .map_err(|e| miette::miette!("parts['{name}']: {e}"))?;
        for dep in pick(&plan) {
            if !target.contains(dep) {
                target.push(dep.clone());
            }
        }
    }
    Ok(())
}

/// Extract a snap-level `plugs`/`slots` map: name → bare interface string
/// (back-compat) or attribute table. Two string-array back-compat forms are
/// accepted: map form (`plugs = { network = "network" }`) and array form
/// (`plugs = { "network" }`, where the interface name doubles as the key).
fn get_opt_plug_map(
    table: &mlua::Table,
    key: &str,
) -> miette::Result<Option<BTreeMap<String, SnapPlug>>> {
    let Some(t) = get_opt_table(table, key)? else {
        return Ok(None);
    };
    let mut map = BTreeMap::new();
    for pair in t.pairs::<Value, Value>() {
        let (k, v) = pair.map_err(|e| miette::miette!("{key} entry: {e}"))?;
        let entry = match (&k, &v) {
            // Map form: `plugs = { network = "network" }`
            (Value::String(name), Value::String(iface)) => {
                let iface = iface
                    .to_str()
                    .map_err(|e| miette::miette!("{}", e))?
                    .to_string();
                let name = name
                    .to_str()
                    .map_err(|e| miette::miette!("{}", e))?
                    .to_string();
                (name, SnapPlug::Name(iface))
            }
            // Map form with attributes: `plugs = { shared = { interface = … } }`
            (Value::String(name), Value::Table(tt)) => {
                let name = name
                    .to_str()
                    .map_err(|e| miette::miette!("{}", e))?
                    .to_string();
                let plug = PlugSlot::from_lua_table(&format!("{key}['{name}']"), tt)?;
                (name, SnapPlug::Typed(plug))
            }
            // Array back-compat: `plugs = { "network" }`
            (Value::Integer(_), Value::String(iface)) => {
                let iface = iface
                    .to_str()
                    .map_err(|e| miette::miette!("{}", e))?
                    .to_string();
                (iface.clone(), SnapPlug::Name(iface))
            }
            (Value::Integer(i), other) => {
                return Err(miette::miette!(
                    "{key}[{i}] must be a string interface name, got {}",
                    other.type_name()
                ));
            }
            (other, _) => {
                return Err(miette::miette!(
                    "{key}: unsupported key type {}",
                    other.type_name()
                ));
            }
        };
        map.insert(entry.0, entry.1);
    }
    Ok(Some(map))
}

/// Extract `inputs` table: maps name → PackageInput { url, submodules? }.
fn get_package_inputs(
    table: &mlua::Table,
) -> miette::Result<Option<HashMap<String, PackageInput>>> {
    let value: Value = table.get("inputs").unwrap_or(Value::Nil);
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
                        let submodules = parse_submodule_spec(
                            input_table.get::<Value>("submodules").unwrap_or(Value::Nil),
                            &format!("inputs['{name}']"),
                        )?;
                        inputs.insert(name, PackageInput { url, submodules });
                    }
                    other => {
                        return Err(miette::miette!(
                            "inputs['{name}'] must be a table, got {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(Some(inputs))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "'inputs' must be a table, got {}",
            other.type_name()
        )),
    }
}

// ── Conversion from Lua: image declarations (moved from image/mod.rs, #326) ──

// ── Conversion from Lua ──

impl FromLuaTable for ImageDeclaration {
    /// Create from a validated Lua table (from `image()`).
    fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
        let name: String =
            get_required(table, "name").map_err(|e| miette::miette!("image(): {e}"))?;
        let version: String =
            get_required(table, "version").map_err(|e| miette::miette!("image(): {e}"))?;

        let base = get_required_snap_ref(table, "base")?;
        let kernel = get_opt_kernel_entry(table)?;
        let gadget = get_opt_snap_ref(table, "gadget")?;
        let gadget_channel = get_opt_pin_channel(table, "gadget")?;
        let extra_snaps = get_snap_ref_array(table, "snaps")?;

        // NEW: bootloader
        let bootloader = get_opt_bootloader(table)?;
        // NEW: disk layout
        let disk = get_opt_disk_layout(table)?;
        // NEW: sysctl
        let sysctl: Vec<String> = table.get("sysctl").unwrap_or_default();
        // #80: optional extra files staged into the rootfs. Fail closed on
        // a relative `dest`, a `..` component (staging would escape the
        // staged root), or a non-table entry — an image that silently
        // dropped a declared file would boot without the tooling it
        // declared.
        let files: Vec<StagedFile> = match table.get::<Vec<mlua::Table>>("files") {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| -> miette::Result<StagedFile> {
                    let source: String = entry.get("source").map_err(|_| {
                        miette::miette!("image(): files[] entry needs a 'source' string")
                    })?;
                    let dest: String = entry.get("dest").map_err(|_| {
                        miette::miette!("image(): files[] entry needs a 'dest' string")
                    })?;
                    if !dest.starts_with('/') {
                        return Err(miette::miette!(
                            "image(): files[].dest must be an absolute guest path, got {dest:?}"
                        ));
                    }
                    if Path::new(&dest)
                        .components()
                        .any(|c| c == std::path::Component::ParentDir)
                    {
                        return Err(miette::miette!(
                            "image(): files[].dest must not contain '..' (staging would \
                             escape the staged root): {dest:?}"
                        ));
                    }
                    if source.is_empty() {
                        return Err(miette::miette!("image(): files[].source must not be empty"));
                    }
                    Ok(StagedFile {
                        source: PathBuf::from(source),
                        dest,
                    })
                })
                .collect::<miette::Result<Vec<_>>>()?,
            Err(_) => Vec::new(),
        };
        // ADR-0011 step (d): optional sysupdate payload source URL
        let update_source = match table
            .get::<Value>("update_source")
            .map_err(|e| miette::miette!("image(): update_source: {e}"))?
        {
            Value::String(s) => Some(
                s.to_str()
                    .map_err(|e| miette::miette!("image(): update_source: {e}"))?
                    .to_string(),
            ),
            Value::Nil => None,
            other => Err(miette::miette!(
                "image(): 'update_source' must be a string URL, got {}",
                other.type_name()
            ))?,
        };
        // Issue #78: optional health-check command override.
        let boot_health_exec = match table
            .get::<Value>("boot_health_exec")
            .map_err(|e| miette::miette!("image(): boot_health_exec: {e}"))?
        {
            Value::String(s) => Some(
                s.to_str()
                    .map_err(|e| miette::miette!("image(): boot_health_exec: {e}"))?
                    .to_string(),
            ),
            Value::Nil => None,
            other => Err(miette::miette!(
                "image(): 'boot_health_exec' must be a string command, got {}",
                other.type_name()
            ))?,
        };

        Ok(ImageDeclaration {
            name,
            version,
            base,
            kernel,
            gadget,
            gadget_channel,
            extra_snaps,
            bootloader,
            disk,
            sysctl,
            files,
            update_source,
            boot_health_exec,
        })
    }
}

// ── Lua extraction helpers (for image tables) ──

fn get_required<T: mlua::FromLua>(table: &mlua::Table, key: &str) -> miette::Result<T> {
    table
        .get::<T>(key)
        .map_err(|e| miette::miette!("missing or invalid required field '{key}': {e}"))
}

fn get_opt_snap_ref(table: &mlua::Table, key: &str) -> miette::Result<Option<SnapRef>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => Ok(Some(SnapRef::from_pin_table(&t)?)),
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): '{key}' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

fn get_required_snap_ref(table: &mlua::Table, key: &str) -> miette::Result<SnapRef> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => Ok(SnapRef::from_pin_table(&t)?),
        other => Err(miette::miette!(
            "image(): required field '{key}' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

fn get_snap_ref_array(table: &mlua::Table, key: &str) -> miette::Result<Vec<SnapRef>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => {
            let mut snaps = Vec::new();
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("{key}[n]: {e}"))?;
                match value {
                    Value::Table(tbl) => snaps.push(SnapRef::from_pin_table(&tbl)?),
                    other => {
                        return Err(miette::miette!(
                            "image(): each entry in '{key}' must be a pin, got {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(snaps)
        }
        Value::Nil => Ok(Vec::new()),
        other => Err(miette::miette!(
            "image(): '{key}' must be an array of pins, got {}",
            other.type_name()
        )),
    }
}

fn get_opt_kernel_entry(table: &mlua::Table) -> miette::Result<Option<KernelEntry>> {
    match table
        .get::<Value>("kernel")
        .map_err(|e| miette::miette!("kernel: {e}"))?
    {
        Value::Table(t) => {
            let snap = SnapRef::from_pin_table(&t)?;
            let params: Vec<String> = t.get("params").unwrap_or_default();
            let modules: Vec<String> = t.get("modules").unwrap_or_default();
            let modprobe_config: Option<String> = t.get("modprobe_config").ok();
            let channel = get_opt_pin_channel(table, "kernel")?;
            Ok(Some(KernelEntry {
                snap,
                params,
                modules,
                modprobe_config,
                channel,
            }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'kernel' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

/// Read the ADR-0019 explicit `channel` opt off a kernel/gadget pin table
/// (`pin("pc-kernel", { channel = "22/stable" })`). The DSL passes unknown
/// pin fields through, so the opt reaches this boundary without being part
/// of [`SnapRef`]; an author-pinned channel escapes track derivation and
/// the declared-base check.
fn get_opt_pin_channel(table: &mlua::Table, key: &str) -> miette::Result<Option<String>> {
    match table.get::<Value>(key).unwrap_or(Value::Nil) {
        Value::Table(t) => match t.get::<Value>("channel").unwrap_or(Value::Nil) {
            Value::Nil => Ok(None),
            Value::String(s) => Ok(Some(
                s.to_str()
                    .map_err(|e| miette::miette!("{key}.channel: {e}"))?
                    .to_string(),
            )),
            other => Err(miette::miette!(
                "image(): '{key}.channel' must be a string, got {}",
                other.type_name()
            )),
        },
        _ => Ok(None),
    }
}

fn get_opt_bootloader(table: &mlua::Table) -> miette::Result<Option<BootloaderConfig>> {
    match table
        .get::<Value>("bootloader")
        .map_err(|e| miette::miette!("bootloader: {e}"))?
    {
        Value::Table(t) => {
            let type_: String = t.get("type").unwrap_or_else(|_| "systemd-boot".into());
            // Issues #71/#87: `populate_esp`/`install_uki` install
            // systemd-boot, and the piboot backend stages the Pi firmware
            // chain — two implemented backends total. Accepting any other
            // value here would silently lie. Fail closed at declaration
            // validation until a real GRUB backend exists (ADR-0011 §2's
            // deferred uc-seed profile).
            if type_ != "systemd-boot" && type_ != BOOTLOADER_PIBOOT {
                return Err(miette::miette!(
                    "image(): bootloader.type = \"{type_}\" is not implemented — only \
                     \"systemd-boot\" and \"piboot\" (Raspberry Pi firmware chain, \
                     issue #87) are supported (issue #71: the GRUB backend does not \
                     exist yet, so the declaration would silently install systemd-boot)"
                ));
            }
            let timeout: u32 = t.get("timeout").unwrap_or(3);
            Ok(Some(BootloaderConfig { type_, timeout }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'bootloader' must be a table, got {}",
            other.type_name()
        )),
    }
}

fn get_opt_disk_layout(table: &mlua::Table) -> miette::Result<Option<DiskLayout>> {
    match table
        .get::<Value>("disk")
        .map_err(|e| miette::miette!("disk: {e}"))?
    {
        Value::Table(t) => {
            let label: String = t.get("label").unwrap_or_else(|_| "gpt".into());
            let partitions = get_partitions(&t)?;
            let swap = get_opt_swap(&t)?;
            // ADR-0011 step (d): opt-in A/B slots — default off so existing
            // (kernel-free, single-slot) definitions behave identically.
            let ab: bool = t.get("ab").unwrap_or(false);
            Ok(Some(DiskLayout {
                label,
                partitions,
                swap,
                ab,
            }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'disk' must be a table, got {}",
            other.type_name()
        )),
    }
}

fn get_partitions(table: &mlua::Table) -> miette::Result<Vec<Partition>> {
    let mut partitions = Vec::new();
    let parts: Value = table.get("partitions").unwrap_or(Value::Nil);
    match parts {
        Value::Table(t) => {
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("partitions[n]: {e}"))?;
                match value {
                    Value::Table(pt) => {
                        let name: String = pt
                            .get("name")
                            .map_err(|_| miette::miette!("partition: missing 'name'"))?;
                        let size: String = pt
                            .get("size")
                            .map_err(|_| miette::miette!("partition '{}': missing 'size'", name))?;
                        let fs: String = pt
                            .get("fs")
                            .map_err(|_| miette::miette!("partition '{}': missing 'fs'", name))?;
                        // The mount is optional for UC gap partitions: a
                        // role-marked partition (system-seed/boot/data/save)
                        // is placed by the UC role model, not mounted from
                        // the painted rootfs — the gadget defines what the
                        // seed/boot partitions carry (#32).
                        let role_opt: Option<String> = pt.get("role").ok();
                        let mount: String = match pt.get("mount") {
                            Ok(m) => m,
                            Err(_) if role_opt.is_some() => String::new(),
                            Err(_) => {
                                return Err(miette::miette!(
                                    "partition '{}': missing 'mount'",
                                    name
                                ))
                            }
                        };
                        let options: Vec<String> = pt.get("options").unwrap_or_default();
                        // UC gadget role (issue #32) — optional; only honored
                        // under a UC base.
                        let role: String = role_opt.unwrap_or_default();
                        partitions.push(Partition {
                            name,
                            size,
                            fs,
                            mount,
                            options,
                            role,
                        });
                    }
                    other => {
                        return Err(miette::miette!(
                            "each partition must be a table, got {}",
                            other.type_name()
                        ))
                    }
                }
            }
        }
        Value::Nil => {}
        other => {
            return Err(miette::miette!(
                "'partitions' must be a table, got {}",
                other.type_name()
            ))
        }
    }
    Ok(partitions)
}

fn get_opt_swap(table: &mlua::Table) -> miette::Result<Option<SwapConfig>> {
    match table
        .get::<Value>("swap")
        .map_err(|e| miette::miette!("swap: {e}"))?
    {
        Value::Table(t) => {
            let size: String = t.get("size").unwrap_or_else(|_| "0".into());
            Ok(Some(SwapConfig { size }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'disk.swap' must be a table, got {}",
            other.type_name()
        )),
    }
}

// ── Moved with the service machinery (issue #326): root build path re-exports these ──

/// Fail-closed interpolation scan (ADR-0032 Decision 2) for `command`,
/// `args` entries, and `options` string values: every `${ref}` must name a
/// declared option of THIS service or exactly the `extensions` built-in;
/// `%` may introduce only `%h`, `%p`, or the `%%` escape — no `%`-token
/// ever reaches a backend artifact unexpanded. `%` followed by a non-letter
/// (e.g. `50%`) is a literal.
pub fn validate_service_interpolation(
    service: &str,
    field: &str,
    value: &str,
    option_keys: &std::collections::BTreeSet<String>,
) -> miette::Result<()> {
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '$' if i + 1 < chars.len() && chars[i + 1] == '{' => {
                let start = i + 2;
                let end = chars[start..]
                    .iter()
                    .position(|&c| c == '}')
                    .map(|p| start + p);
                let Some(end) = end else {
                    miette::bail!(
                        "service '{service}': field '{field}': unterminated '${{' in {value:?}"
                    );
                };
                let reference: String = chars[start..end].iter().collect();
                if reference.is_empty() {
                    miette::bail!(
                        "service '{service}': field '{field}': empty '${{}}' reference — \
                         name a declared option or '{SERVICE_BUILTIN_REF}'"
                    );
                }
                if reference != SERVICE_BUILTIN_REF && !option_keys.contains(&reference) {
                    miette::bail!(
                        "service '{service}': field '{field}': unknown '${{{reference}}}' \
                         reference — must be a declared option of this service or \
                         '{SERVICE_BUILTIN_REF}' (ADR-0032 Decision 2)"
                    );
                }
                i = end + 1;
            }
            '%' => match chars.get(i + 1) {
                Some('h') | Some('p') | Some('%') => i += 2,
                Some(c) if c.is_ascii_alphabetic() => {
                    miette::bail!(
                        "service '{service}': field '{field}': '%{c}' is not a nau \
                         specifier (only %h, %p, and the escape %%) (ADR-0032 Decision 2)"
                    );
                }
                _ => i += 1,
            },
            _ => i += 1,
        }
    }
    Ok(())
}

/// Exec-surface text (issue #109 S5): `command`, `args` entries, and
/// option string values are baked into the `ExecStart=` line — quotes
/// are safe there (the emitter single-quotes every arg), but a control
/// character is not: a raw newline terminates the directive and every
/// following line parses as a fresh unit directive. Rejected at the
/// parse boundary, fail-closed, naming the character. Also applied to
/// pod-side override strings at the merge boundary (`pod.rs`), which
/// reach the same render path.
pub fn validate_exec_text(service: &str, field: &str, value: &str) -> miette::Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        miette::bail!(
            "service '{service}': field '{field}': control characters are not allowed — \
             found {c:?}; the value reaches the ExecStart line, where a newline would \
             terminate the directive and the remainder would parse as unit directives"
        );
    }
    Ok(())
}

// ── Service validation vocabulary (moved with the service Lua-parse, #326) ──

/// The one built-in interpolation reference (ADR-0032 Decision 2): the
/// active generation's extensions dir resolved through `current`.
pub const SERVICE_BUILTIN_REF: &str = "extensions";

/// `environment` values are literals (the ADR-0030 spirit, extended by
/// ADR-0032 Decision 2): no `${` interpolation and no `%<letter>` specifier
/// is ever expanded there, so both fail at parse instead of leaking raw.
fn validate_service_env_literal(service: &str, key: &str, value: &str) -> miette::Result<()> {
    if value.contains("${") {
        miette::bail!(
            "service '{service}': field 'environment.{key}': environment values are \
             literals — '${{' interpolation is not allowed (ADR-0032 Decision 2)"
        );
    }
    let chars: Vec<char> = value.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '%' && chars.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic()) {
            miette::bail!(
                "service '{service}': field 'environment.{key}': environment values are \
                 literals — '%{}' specifiers are not allowed (ADR-0032 Decision 2)",
                chars[i + 1]
            );
        }
    }
    Ok(())
}

/// Unit-text safety (issue #109 S5): these strings land verbatim in a
/// file the service manager parses — a control character (a newline!)
/// injects arbitrary directives, and a quote escapes the emitter's
/// quoting. Rejected at the parse boundary, fail-closed, naming the
/// character.
pub fn validate_unit_text(service: &str, field: &str, value: &str) -> miette::Result<()> {
    if let Some(c) = value
        .chars()
        .find(|c| c.is_control() || matches!(c, '\'' | '"'))
    {
        miette::bail!(
            "service '{service}': field '{field}': control characters and quotes are not \
             allowed — found {c:?}; the value reaches a manager-parsed unit file verbatim"
        );
    }
    Ok(())
}

/// Service names become backend identifier components (unit names, labels,
/// supervisor process names — ADR-0032 Decisions 3 and 9); keep them plain
/// so every per-backend mapping stays total. Shared with the pod-level
/// `services` override keys (pod.rs).
pub fn validate_service_name(name: &str) -> miette::Result<()> {
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !plain {
        miette::bail!(
            "invalid service name '{name}': must be non-empty and match ^[a-z0-9-]+$ \
             (ADR-0032 Decision 3)"
        );
    }
    Ok(())
}
