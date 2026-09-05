//! Pod declarations and per-pod state (CONTEXT.md: Pod, Pod generation,
//! Overlay).
//!
//! Ticket scaffold (issue #2): parse, validate, and render the `pod()`
//! declaration in a pod's `pod.lua`; resolve package versions from the
//! shared package collection (`pkgs/` + inputs); pin the resolved versions
//! in the pod's lockfile. `shuttle pod add/remove/list` round-trip through
//! the declaration file. No builds, generations, farm, or activation —
//! those arrive in later tickets.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::lock::{LockFile, PodPackageLockEntry};

/// The implicit pod when no `--name` is given (`shuttle pod <verb>`).
pub const DEFAULT_POD: &str = "default";

/// The pod declaration file, inside the pod's state directory.
pub const POD_FILE: &str = "pod.lua";

// ── State layout ──

/// Root of all pod state. Resolution order: explicit `--root` flag, then
/// the `SHUTTLE_POD_ROOT` env var, then the user's local share state
/// (`$XDG_DATA_HOME/shuttle/pods`, defaulting to `~/.local/share`). Tests
/// MUST redirect via the flag or the env var — never the real home.
pub fn pod_root(explicit: Option<&str>) -> PathBuf {
    if let Some(root) = explicit.filter(|r| !r.is_empty()) {
        return PathBuf::from(root);
    }
    if let Ok(root) = std::env::var("SHUTTLE_POD_ROOT") {
        if !root.is_empty() {
            return PathBuf::from(root);
        }
    }
    let data_home = match std::env::var("XDG_DATA_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/share")
        }
    };
    data_home.join("shuttle").join("pods")
}

/// One pod's state directory: `<root>/<name>` (holding `pod.lua`, the
/// lockfile, and — in later tickets — generation links).
pub fn pod_dir(root: &Path, pod_name: &str) -> PathBuf {
    root.join(pod_name)
}

/// Validate a pod name: the name becomes a directory under the pod root,
/// so it must be a single path-safe component (no empty names, no path
/// separators, not `.` or `..`).
pub fn validate_pod_name(name: &str) -> miette::Result<()> {
    if name.is_empty() {
        miette::bail!("pod name must not be empty");
    }
    if name == "." || name == ".." {
        miette::bail!("pod name '{name}' is not allowed");
    }
    if name.chars().any(|c| c == '/' || c == '\\') {
        miette::bail!("pod name '{name}' must not contain path separators");
    }
    Ok(())
}

/// Path to a pod's `pod.lua`.
pub fn pod_lua_path(root: &Path, pod_name: &str) -> PathBuf {
    pod_dir(root, pod_name).join(POD_FILE)
}

/// Path to a pod's lockfile.
pub fn pod_lock_path(root: &Path, pod_name: &str) -> PathBuf {
    pod_dir(root, pod_name).join(LockFile::FILENAME)
}

// ── Package specs ──

/// One declared package: a name plus an optional `@constraint`
/// (e.g. `ripgrep@14`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodPackageSpec {
    pub name: String,
    pub constraint: Option<String>,
}

/// Parse a package spec string: `name` or `name@constraint`.
pub fn parse_pod_package(spec: &str) -> miette::Result<PodPackageSpec> {
    let (name, constraint) = match spec.split_once('@') {
        Some((n, c)) => (n, Some(c)),
        None => (spec, None),
    };
    if name.is_empty() {
        miette::bail!("invalid package spec '{spec}': package name must not be empty");
    }
    if name.chars().any(char::is_whitespace) {
        miette::bail!("invalid package spec '{spec}': package name must not contain whitespace");
    }
    if let Some(c) = constraint {
        if c.is_empty() {
            miette::bail!("invalid package spec '{spec}': version constraint must not be empty");
        }
        if c.chars().any(char::is_whitespace) {
            miette::bail!(
                "invalid package spec '{spec}': version constraint must not contain whitespace"
            );
        }
    }
    Ok(PodPackageSpec {
        name: name.to_string(),
        constraint: constraint.map(str::to_string),
    })
}

// ── Declaration ──

/// The validated `pod()` declaration. Only fields present in the file are
/// populated; rendering emits exactly what was declared.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PodDeclaration {
    /// Pods loaded under this one (`loads = { "base" }`).
    pub loads: Vec<String>,
    /// Package spec strings in declared order (`"jq"`, `"ripgrep@14"`).
    pub packages: Vec<String>,
    /// Inline overlays keyed by package name (CONTEXT.md: Overlay).
    pub overlay: BTreeMap<String, serde_json::Value>,
}

/// Evaluate and validate a pod declaration file.
pub fn evaluate_pod_file(path: &Path) -> miette::Result<PodDeclaration> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("could not read {}: {}", path.display(), e))?;
    evaluate_pod_source(&path.display().to_string(), &source)
}

/// The capture prelude: a `pod` global that records the declaration table
/// and how many times it was called. Data-only handshake — no Rust
/// closures cross into Lua.
const POD_CAPTURE_PRELUDE: &str = r#"
__pod_calls = 0
__pod_table = nil
function pod(tbl)
    if type(tbl) ~= "table" then
        error("pod() expects a table, got " .. type(tbl), 2)
    end
    __pod_calls = __pod_calls + 1
    __pod_table = tbl
end
"#;

/// Evaluate pod declaration source and convert it to a validated
/// [`PodDeclaration`].
///
/// Validation mirrors the `snap()` global's rigor: every field is
/// type-checked with an error naming the offending field. pod.lua is the
/// user's own trusted file, so (unlike untrusted definitions, ADR-0010)
/// evaluation runs in-process.
pub fn evaluate_pod_source(label: &str, source: &str) -> miette::Result<PodDeclaration> {
    let lua = mlua::Lua::new();
    lua.load(POD_CAPTURE_PRELUDE)
        .exec()
        .map_err(|e| miette::miette!("{label}: pod prelude failed: {e}"))?;
    lua.load(source)
        .exec()
        .map_err(|e| miette::miette!("{label}: {e}"))?;

    let calls: i64 = lua
        .globals()
        .get("__pod_calls")
        .map_err(|e| miette::miette!("{label}: {e}"))?;
    match calls {
        0 => miette::bail!("{label}: pod.lua must call pod {{ ... }} exactly once; found none"),
        1 => {}
        n => {
            miette::bail!("{label}: pod.lua must call pod {{ ... }} exactly once; found {n} calls")
        }
    }
    let table: mlua::Table = lua
        .globals()
        .get("__pod_table")
        .map_err(|e| miette::miette!("{label}: {e}"))?;
    validate_pod_table(&table)
}

/// Type-check the captured `pod()` table into a [`PodDeclaration`]. Every
/// failure names the offending field.
fn validate_pod_table(table: &mlua::Table) -> miette::Result<PodDeclaration> {
    let mut decl = PodDeclaration::default();
    let mut saw_loads = false;
    let mut saw_packages = false;
    let mut saw_overlay = false;

    for pair in table.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, value) = pair.map_err(|e| miette::miette!("pod(): {e}"))?;
        let key = match &key {
            mlua::Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("pod(): non-utf8 key: {e}"))?
                .to_string(),
            other => miette::bail!("pod(): keys must be strings, got {}", lua_type_name(other)),
        };
        match key.as_str() {
            "loads" => {
                if saw_loads {
                    miette::bail!("duplicate field 'loads' in pod() declaration");
                }
                saw_loads = true;
                decl.loads = expect_string_list(&value, "loads")?;
            }
            "packages" => {
                if saw_packages {
                    miette::bail!("duplicate field 'packages' in pod() declaration");
                }
                saw_packages = true;
                decl.packages = expect_package_list(&value)?;
            }
            "overlay" => {
                if saw_overlay {
                    miette::bail!("duplicate field 'overlay' in pod() declaration");
                }
                saw_overlay = true;
                decl.overlay = expect_overlay(&value)?;
            }
            other => miette::bail!(
                "unknown field '{other}' in pod() declaration (allowed: loads, packages, overlay)"
            ),
        }
    }
    Ok(decl)
}

/// Validate a `table of strings` field, erroring with the field name.
fn expect_string_list(value: &mlua::Value, field: &str) -> miette::Result<Vec<String>> {
    let table = match value {
        mlua::Value::Table(t) => t,
        other => miette::bail!(
            "'{field}' must be a table of strings, got {}",
            lua_type_name(other)
        ),
    };
    let mut out = Vec::new();
    for (idx, pair) in table
        .clone()
        .pairs::<mlua::Value, mlua::Value>()
        .enumerate()
    {
        let (key, item) = pair.map_err(|e| miette::miette!("'{field}': {e}"))?;
        let position = idx + 1;
        match key {
            mlua::Value::Integer(n) if n == position as mlua::Integer => {}
            _ => miette::bail!("'{field}' must be a sequential array (expected index {position})"),
        }
        match &item {
            mlua::Value::String(s) => out.push(
                s.to_str()
                    .map_err(|e| miette::miette!("'{field}': non-utf8 string: {e}"))?
                    .to_string(),
            ),
            other => miette::bail!(
                "'{field}[{position}]' must be a string, got {}",
                lua_type_name(other)
            ),
        }
    }
    Ok(out)
}

/// Validate the `packages` field: a table of spec strings, each parseable
/// as `name[@constraint]`, with no duplicate package names.
fn expect_package_list(value: &mlua::Value) -> miette::Result<Vec<String>> {
    let specs = expect_string_list(value, "packages")?;
    let mut seen: HashSet<String> = HashSet::new();
    for spec in &specs {
        let parsed = parse_pod_package(spec)?;
        if !seen.insert(parsed.name.clone()) {
            miette::bail!("duplicate package '{}' in 'packages'", parsed.name);
        }
    }
    Ok(specs)
}

/// Validate the `overlay` field: a table of package name → plain-data
/// table (functions and cycles are rejected, naming the entry).
fn expect_overlay(value: &mlua::Value) -> miette::Result<BTreeMap<String, serde_json::Value>> {
    let table = match value {
        mlua::Value::Table(t) => t,
        other => miette::bail!(
            "'overlay' must be a table of tables, got {}",
            lua_type_name(other)
        ),
    };
    let mut out = BTreeMap::new();
    for pair in table.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, item) = pair.map_err(|e| miette::miette!("'overlay': {e}"))?;
        let key = match &key {
            mlua::Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("'overlay': non-utf8 key: {e}"))?
                .to_string(),
            other => miette::bail!(
                "'overlay' keys must be strings, got {}",
                lua_type_name(other)
            ),
        };
        match &item {
            mlua::Value::Nil => {}
            mlua::Value::Table(_) => {
                let json = crate::isolate::lua_to_json(&item).map_err(|e| {
                    miette::miette!("'overlay.{key}' must be a plain data table: {e}")
                })?;
                out.insert(key, json);
            }
            other => miette::bail!(
                "'overlay.{key}' must be a table, got {}",
                lua_type_name(other)
            ),
        }
    }
    Ok(out)
}

fn lua_type_name(value: &mlua::Value) -> &'static str {
    match value {
        mlua::Value::Nil => "nil",
        mlua::Value::Boolean(_) => "boolean",
        mlua::Value::Integer(_) => "integer",
        mlua::Value::Number(_) => "number",
        mlua::Value::String(_) => "string",
        mlua::Value::Table(_) => "table",
        mlua::Value::Function(_) => "function",
        _ => "value",
    }
}

// ── Rendering ──

/// Render a declaration back to `pod.lua` source. Only populated sections
/// are emitted; overlay tables re-render as plain data (they were
/// validated data-only at parse time).
pub fn render_pod_source(decl: &PodDeclaration) -> String {
    let mut out = String::new();
    out.push_str("-- Pod declaration, maintained by `shuttle pod add/remove`.\n");
    out.push_str("-- Hand edits are allowed; malformed declarations fail validation.\n");
    out.push_str("pod {\n");
    if !decl.loads.is_empty() {
        out.push_str(&format!(
            "    loads = {},\n",
            render_string_array(&decl.loads)
        ));
    }
    if !decl.packages.is_empty() {
        out.push_str(&format!(
            "    packages = {},\n",
            render_string_array(&decl.packages)
        ));
    }
    if !decl.overlay.is_empty() {
        out.push_str("    overlay = {\n");
        for (key, value) in &decl.overlay {
            out.push_str(&format!(
                "        {} = {},\n",
                render_lua_key(key),
                render_json_lua(value, 2)
            ));
        }
        out.push_str("    },\n");
    }
    out.push_str("}\n");
    out
}

fn render_string_array(items: &[String]) -> String {
    let rendered: Vec<String> = items.iter().map(|s| render_lua_string(s)).collect();
    format!("{{ {} }}", rendered.join(", "))
}

fn render_lua_key(key: &str) -> String {
    let ident_ok = !key.is_empty()
        && key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ident_ok {
        key.to_string()
    } else {
        format!("[{}]", render_lua_string(key))
    }
}

fn render_lua_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Render a JSON value as Lua table syntax at the given indent level
/// (arrays inline, objects as indented nested tables).
fn render_json_lua(value: &serde_json::Value, depth: usize) -> String {
    match value {
        serde_json::Value::Null => "nil".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => render_lua_string(s),
        serde_json::Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(|v| render_json_lua(v, depth)).collect();
            format!("{{ {} }}", rendered.join(", "))
        }
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                return "{ }".to_string();
            }
            let pad = "    ".repeat(depth);
            let inner_pad = "    ".repeat(depth + 1);
            let mut out = String::from("{\n");
            for (key, item) in map {
                out.push_str(&format!(
                    "{}{} = {},\n",
                    inner_pad,
                    render_lua_key(key),
                    render_json_lua(item, depth + 1)
                ));
            }
            out.push_str(&format!("{}}}", pad));
            out
        }
    }
}

// ── Operations ──

/// Report for a successful `pod add`.
#[derive(Debug, Serialize)]
pub struct PodAddReport {
    pub pod: String,
    pub name: String,
    pub constraint: Option<String>,
    pub version: String,
    #[serde(skip)]
    pub pod_dir: PathBuf,
}

/// Report for a successful `pod remove`.
#[derive(Debug, Serialize)]
pub struct PodRemoveReport {
    pub pod: String,
    pub name: String,
}

/// One entry for `pod list`.
#[derive(Debug, Serialize)]
pub struct PodListEntry {
    /// Declared spec (`name` or `name@constraint`).
    pub spec: String,
    pub name: String,
    pub constraint: Option<String>,
    /// Resolved version: the lockfile pin when present, else a live
    /// resolution, else `None` (shown as unresolved).
    pub version: Option<String>,
    /// True when the version came from the lockfile pin.
    pub pinned: bool,
}

/// Load a pod declaration; a missing `pod.lua` yields the empty default
/// declaration (the `add` bootstrap case).
pub fn load_declaration_or_default(root: &Path, pod_name: &str) -> miette::Result<PodDeclaration> {
    let path = pod_lua_path(root, pod_name);
    if !path.exists() {
        return Ok(PodDeclaration::default());
    }
    evaluate_pod_file(&path)
}

/// Load a pod declaration; a missing `pod.lua` is an error.
pub fn load_declaration(root: &Path, pod_name: &str) -> miette::Result<PodDeclaration> {
    let path = pod_lua_path(root, pod_name);
    if !path.exists() {
        miette::bail!("pod '{pod_name}' has no declaration at {}", path.display());
    }
    evaluate_pod_file(&path)
}

/// Add a package to a pod: resolve it from the package collection FIRST
/// (an unknown package must not modify any state), then record it in
/// `pod.lua` and pin the resolved version in the lockfile.
pub fn add_package(root: &Path, pod_name: &str, spec_str: &str) -> miette::Result<PodAddReport> {
    validate_pod_name(pod_name)?;
    let spec = parse_pod_package(spec_str)?;

    // Resolve before touching any state.
    let meta = crate::deps::load_meta(&spec.name)
        .map_err(|e| miette::miette!("cannot add '{}': {e}", spec.name))?;

    let mut decl = load_declaration_or_default(root, pod_name)?;
    for existing in &decl.packages {
        let parsed = parse_pod_package(existing)?;
        if parsed.name == spec.name {
            miette::bail!(
                "package '{}' is already in pod '{}' (remove it first to change its pin)",
                spec.name,
                pod_name
            );
        }
    }
    decl.packages.push(spec_str.to_string());

    let dir = pod_dir(root, pod_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let decl_path = pod_lua_path(root, pod_name);
    std::fs::write(&decl_path, render_pod_source(&decl))
        .map_err(|e| miette::miette!("failed to write {}: {e}", decl_path.display()))?;

    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);
    lock.packages.insert(
        spec.name.clone(),
        PodPackageLockEntry {
            version: meta.version.clone(),
            constraint: spec.constraint.clone(),
        },
    );
    lock.save(&lock_path)?;

    Ok(PodAddReport {
        pod: pod_name.to_string(),
        name: spec.name,
        constraint: spec.constraint,
        version: meta.version,
        pod_dir: dir,
    })
}

/// Remove a package from a pod: drop it from the declaration and delete
/// its lockfile pin.
pub fn remove_package(
    root: &Path,
    pod_name: &str,
    spec_str: &str,
) -> miette::Result<PodRemoveReport> {
    validate_pod_name(pod_name)?;
    let spec = parse_pod_package(spec_str)?;
    let mut decl = load_declaration(root, pod_name)?;
    let before = decl.packages.len();
    decl.packages.retain(|existing| {
        match parse_pod_package(existing) {
            Ok(parsed) => parsed.name != spec.name,
            Err(_) => true, // unreachable: the declaration was validated
        }
    });
    if decl.packages.len() == before {
        miette::bail!("package '{}' is not in pod '{}'", spec.name, pod_name);
    }

    let decl_path = pod_lua_path(root, pod_name);
    std::fs::write(&decl_path, render_pod_source(&decl))
        .map_err(|e| miette::miette!("failed to write {}: {e}", decl_path.display()))?;

    let lock_path = pod_lock_path(root, pod_name);
    if let Some(mut lock) = LockFile::load(&lock_path)? {
        lock.packages.remove(&spec.name);
        lock.save(&lock_path)?;
    }

    Ok(PodRemoveReport {
        pod: pod_name.to_string(),
        name: spec.name,
    })
}

/// List a pod's packages with resolved versions. Read verbs do not
/// initialize pods: an unknown pod (no `pod.lua`) is a clear error —
/// `shuttle pod add` is what initializes a pod.
pub fn list_packages(root: &Path, pod_name: &str) -> miette::Result<Vec<PodListEntry>> {
    validate_pod_name(pod_name)?;
    let decl_path = pod_lua_path(root, pod_name);
    if !decl_path.exists() {
        miette::bail!(
            "pod '{pod_name}' has no declaration at {} (read verbs do not \
             initialize pods; `shuttle pod --name {pod_name} add <package>` does)",
            decl_path.display()
        );
    }
    let decl = evaluate_pod_file(&decl_path)?;
    let lock = LockFile::load(&pod_lock_path(root, pod_name))?;

    let mut entries = Vec::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        let pin = lock
            .as_ref()
            .and_then(|l| l.packages.get(&spec.name))
            .map(|e| e.version.clone());
        let (version, pinned) = match pin {
            Some(v) => (Some(v), true),
            None => match crate::deps::load_meta(&spec.name) {
                Ok(meta) => (Some(meta.version), false),
                Err(_) => (None, false),
            },
        };
        entries.push(PodListEntry {
            spec: spec_str.clone(),
            name: spec.name,
            constraint: spec.constraint,
            version,
            pinned,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pod_package() {
        let plain = parse_pod_package("jq").unwrap();
        assert_eq!(plain.name, "jq");
        assert_eq!(plain.constraint, None);

        let constrained = parse_pod_package("ripgrep@14").unwrap();
        assert_eq!(constrained.name, "ripgrep");
        assert_eq!(constrained.constraint.as_deref(), Some("14"));

        assert!(parse_pod_package("@14").is_err());
        assert!(parse_pod_package("jq@").is_err());
        assert!(parse_pod_package("").is_err());
        assert!(parse_pod_package("two words").is_err());
    }

    #[test]
    fn test_render_roundtrip() {
        let source = r#"
pod {
    loads = { "base" },
    packages = { "jq", "ripgrep@14" },
    overlay = {
        jq = { version = "1.8", flags = { "--static" } },
    },
}
"#;
        let decl = evaluate_pod_source("test", source).unwrap();
        assert_eq!(decl.loads, vec!["base"]);
        assert_eq!(decl.packages, vec!["jq", "ripgrep@14"]);
        assert_eq!(decl.overlay["jq"]["version"], serde_json::json!("1.8"));

        let redecl = evaluate_pod_source("test", &render_pod_source(&decl)).unwrap();
        assert_eq!(redecl, decl, "render → evaluate must round-trip");
    }

    #[test]
    fn test_validation_names_offending_field() {
        let cases: &[(&str, &str)] = &[
            ("pod { pkgs = {} }", "pkgs"),
            ("pod { loads = 3 }", "'loads'"),
            ("pod { packages = { true } }", "'packages[1]'"),
            ("pod { overlay = 7 }", "'overlay'"),
            ("pod { overlay = { jq = 3 } }", "'overlay.jq'"),
            ("return 42", "exactly once"),
        ];
        for (source, needle) in cases {
            let err = evaluate_pod_source("test", source).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "source {source:?} must name {needle:?}, got: {err}"
            );
        }
    }

    #[test]
    fn test_pod_root_explicit_flag_wins_over_env() {
        // The explicit flag must win over whatever the ambient
        // environment carries.
        let resolved = pod_root(Some("/tmp/explicit-root"));
        assert_eq!(resolved, PathBuf::from("/tmp/explicit-root"));
    }

    #[test]
    fn test_pod_dir_layout() {
        let root = Path::new("/state-root");
        assert_eq!(
            pod_lua_path(root, DEFAULT_POD),
            PathBuf::from("/state-root/default/pod.lua")
        );
        assert_eq!(
            pod_lock_path(root, DEFAULT_POD),
            PathBuf::from("/state-root/default/shuttle.lock")
        );
    }

    #[test]
    fn test_validate_pod_name() {
        assert!(validate_pod_name("work").is_ok());
        assert!(validate_pod_name("work.dev").is_ok());
        assert!(validate_pod_name(DEFAULT_POD).is_ok());
        assert!(validate_pod_name("").is_err());
        assert!(validate_pod_name(".").is_err());
        assert!(validate_pod_name("..").is_err());
        assert!(validate_pod_name("../escape").is_err());
        assert!(validate_pod_name("a/b").is_err());
    }
}
