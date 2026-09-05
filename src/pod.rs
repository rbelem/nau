//! Pod declarations and per-pod state (CONTEXT.md: Pod, Pod generation,
//! Overlay).
//!
//! Ticket scaffold (issue #2): parse, validate, and render the `pod()`
//! declaration in a pod's `pod.lua`; resolve package versions from the
//! shared package collection (`pkgs/` + inputs); pin the resolved versions
//! in the pod's lockfile. `shuttle pod add/remove/list` round-trip through
//! the declaration file.
//!
//! Issue #3: `add`/`remove` reconcile the declaration into the pod's
//! generation chain through the shared runtime store (`crate::runtime`,
//! pointed at the pod's state directory — no forked store), building each
//! declared package with the normal snap build path. The bin farm
//! (`crate::farm`) is re-emitted for the active generation and the pod's
//! `current` link flipped after every mutation; `shuttle pod sync`
//! re-runs the whole reconcile (hand-edited `pod.lua` included) and is a
//! no-op — no new generation — when nothing changed.
//!
//! Issue #5: pods move forward deliberately and backward safely.
//! `shuttle pod update` re-resolves every declared package to the newest
//! version matching its constraint, repins the lockfile, and reconciles
//! (only what changed is rebuilt — content identity is the no-op
//! detector). `shuttle pod rollback` flips ONLY that pod's `current`
//! link to a previous generation through the store's rollback machinery
//! (system generations are never touched); the farm follows, so binaries
//! the newer generation added disappear. `shuttle pod gc [--prune]`
//! reuses the store's mark-sweep: unreferenced pod generations are
//! pruned and their exclusive blobs freed, live generations keep theirs.
//!
//! Issue #6: inline code-only overlays. An `overlay = { pkg = { ... } }`
//! entry in a pod's own `pod.lua` patches that package's resolved
//! declaration for THIS pod only — the shared collection and every other
//! pod resolve the unmodified package. Layering (CONTEXT.md: Overlay):
//! shared collection → own packages (the pod's declaration + lockfile
//! pins hold the build against collection drift) → overlay, later wins.
//! Overlay fields are a validated whitelist (`version`, `build`); an
//! overlay version pin flows into the lockfile pin, the built payload,
//! the generation manifest, and the farm binary. Overlay validation
//! (key names a declared package, fields in the whitelist) runs before
//! any mutation.
//!
//! Issue #8: pod composition. A pod declares `loads = { "base" }` and
//! resolves as: shared collection < loaded pods (in listed order) < its
//! own packages < its inline overlay. Semantics, chosen here and
//! binding for later tickets:
//!
//! - **Read-only consumption**: a pod never mutates a pod it loads. The
//!   loading pod reads the loaded pod's active generation (its package
//!   versions + its overlay map) and nothing else; the loaded pod's
//!   lockfile is not consulted because the generation already records
//!   the versions that hold there. A loaded pod with no active
//!   generation yet contributes its declaration resolved the way its
//!   own first sync would resolve (overlay applied, live version) —
//!   the composition is live-following, never pinned across pods.
//! - **The version that executes**: a loaded package is rebuilt into
//!   the loading pod's store with the version its loaded generation
//!   records (same overlay build inputs), so the loading pod executes
//!   what the loaded pod executes. Rebuilt content is deterministic
//!   (fixed build epoch), so a no-change sync installs nothing new.
//! - **Rollback/update interplay**: rolling back (or updating) a loaded
//!   pod rewrites only THAT pod; the loading pod's generation stays put
//!   and picks the change up on its next reconcile (`sync`, `add`,
//!   `remove`, `update` all reconcile).
//! - **Precedence**: the loading pod's own declaration wins a name
//!   clash with a loaded pod outright (same package name = same
//!   identity: the loaded copy never enters the composition). Shared
//!   BINARY names across DIFFERENT packages go through the shared
//!   collision classifier (`crate::farm::classify_collision`,
//!   generalized to `Loaded` < `Own` < `Overlay` layers): a higher
//!   layer overrides with a warning naming winner and loser; two
//!   packages at the same precedence shipping the same binary are a
//!   hard error. Conflicts evaluate at mutation time (before any store
//!   write) and again at activation time (the farm/launcher emitters
//!   warn on every collision they resolve — no silent shadowing path).
//! - **Failure before mutation**: loading a nonexistent pod, or any
//!   load cycle (self-load included), fails validation before a single
//!   write, with the offending pod / the full cycle named.

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

// ── Overlays (issue #6) ──

/// The fields an overlay entry may patch on a resolved package
/// declaration (issue #6: version pins, build tweaks). Anything else is
/// rejected with the allowed set named.
const OVERLAY_FIELDS: &[&str] = &["version", "build"];

/// Apply one overlay entry (a plain-data patch table) onto a resolved
/// [`SnapMeta`]. This is the top layer of the pod resolution chain
/// (CONTEXT.md: Overlay): later layers win, upstream declarations are
/// never modified.
///
/// Only string-valued whitelisted fields (`version`, `build`) are
/// patched; unknown fields and non-string values fail naming
/// `overlay.<pkg>.<field>`.
fn apply_overlay(
    meta: &mut crate::snap::SnapMeta,
    patch: &serde_json::Value,
) -> miette::Result<()> {
    let Some(obj) = patch.as_object() else {
        miette::bail!("overlay entry must be a table of fields, got {}", patch);
    };
    for (key, value) in obj {
        let Some(s) = value.as_str() else {
            miette::bail!("overlay field '{key}' must be a string, got {value}");
        };
        match key.as_str() {
            "version" => meta.version = s.to_string(),
            "build" => meta.build = Some(s.to_string()),
            other => miette::bail!(
                "unsupported overlay field '{other}' (allowed: {})",
                OVERLAY_FIELDS.join(", ")
            ),
        }
    }
    Ok(())
}

/// Validate a declaration's overlay entries BEFORE any mutation: every
/// overlay key must name a package the pod builds — its declared
/// `packages` or one provided by a pod it loads (issue #8; an overlay
/// targeting a loaded package is this pod's top-layer decision) — and
/// every entry must be a patch of whitelisted string fields. Run at the
/// top of every mutating verb so a bad overlay fails with a clear error
/// and zero writes.
fn validate_overlays(root: &Path, decl: &PodDeclaration, pod_name: &str) -> miette::Result<()> {
    let mut declared: HashSet<String> = decl
        .packages
        .iter()
        .filter_map(|spec| parse_pod_package(spec).ok().map(|p| p.name))
        .collect();
    // Loaded pods join the targetable set (issue #8), sub-loads
    // included. A `loads` entry naming a nonexistent pod already failed
    // `validate_loads`; here a missing declaration simply contributes
    // no names.
    declared.extend(loaded_package_names(root, decl)?);
    for (pkg, patch) in &decl.overlay {
        if !declared.contains(pkg) {
            miette::bail!(
                "overlay targets package '{pkg}', which pod '{pod_name}' does not build \
                 — overlays apply to packages the pod declares in 'packages' or loads \
                 (issue #8); overlaying a nonexistent package is an error",
            );
        }
        let Some(obj) = patch.as_object() else {
            miette::bail!("overlay.{pkg} must be a table of fields");
        };
        for (key, value) in obj {
            if !OVERLAY_FIELDS.contains(&key.as_str()) {
                miette::bail!(
                    "overlay.{pkg}.{key}: unsupported overlay field '{key}' (allowed: {})",
                    OVERLAY_FIELDS.join(", ")
                );
            }
            if value.as_str().is_none() {
                miette::bail!("'overlay.{pkg}.{key}' must be a string, got {value}");
            }
        }
    }
    Ok(())
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
    /// The generation the package was installed into, when the store
    /// and farm were reconciled (None under the degraded no-squashfs
    /// mode or when install was a no-op).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(skip)]
    pub pod_dir: PathBuf,
}

/// Report for a successful `pod remove`.
#[derive(Debug, Serialize)]
pub struct PodRemoveReport {
    pub pod: String,
    pub name: String,
    /// The generation the removal produced (see [`PodAddReport`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
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

// ── Loads (issue #8) ──

/// Validate a pod's `loads` BEFORE any mutation: every loaded pod name
/// is valid and its declaration exists, and the load graph reachable
/// from `pod_name` contains no cycle (a self-load is a cycle of length
/// one). Pure reads — safe to run at the top of every mutating verb.
pub fn validate_loads(root: &Path, pod_name: &str, decl: &PodDeclaration) -> miette::Result<()> {
    for loaded in &decl.loads {
        validate_pod_name(loaded)
            .map_err(|e| miette::miette!("pod '{pod_name}' loads '{loaded}': {e}"))?;
        let path = pod_lua_path(root, loaded);
        if !path.exists() {
            miette::bail!(
                "pod '{pod_name}' loads '{loaded}', but pod '{loaded}' has no declaration \
                 at {} — create the loaded pod first \
                 (`shuttle pod --name {loaded} add <package>` initializes it)",
                path.display()
            );
        }
    }
    detect_load_cycle(root, pod_name, decl)
}

/// DFS over the load graph reachable from `start`: a pod revisited on
/// the current path is a cycle, named in full (`work -> base -> work`).
/// Fully-explored pods are memoized — a DAG branch is walked once.
fn detect_load_cycle(root: &Path, start: &str, start_decl: &PodDeclaration) -> miette::Result<()> {
    fn visit(
        root: &Path,
        pod: &str,
        decl: &PodDeclaration,
        stack: &mut Vec<String>,
        done: &mut HashSet<String>,
    ) -> miette::Result<()> {
        stack.push(pod.to_string());
        let result = (|| {
            for loaded in &decl.loads {
                if let Some(pos) = stack.iter().position(|p| p == loaded) {
                    let mut cycle: Vec<String> = stack[pos..].to_vec();
                    cycle.push(loaded.clone());
                    miette::bail!("pod load cycle detected: {}", cycle.join(" -> "));
                }
                if done.contains(loaded) {
                    continue;
                }
                let loaded_decl = load_declaration(root, loaded)?;
                visit(root, loaded, &loaded_decl, stack, done)?;
            }
            Ok(())
        })();
        stack.pop();
        done.insert(pod.to_string());
        result
    }
    let mut stack = Vec::new();
    let mut done = HashSet::new();
    visit(root, start, start_decl, &mut stack, &mut done)
}

/// What one loaded pod contributes to the loading pod's composition:
/// the package versions it currently executes (its active generation —
/// read-only) or, when it has no generation yet, the versions its own
/// first sync would build (declaration + its overlays, live). Sub-loads
/// are folded in beneath its own packages (same precedence rules one
/// level down), so a chain resolves through this one call.
struct LoadedContribution {
    /// The loaded pod's own overlay entries — applied when re-resolving
    /// its packages so the rebuilt payload carries the same build
    /// inputs the loaded pod itself used.
    overlay: BTreeMap<String, serde_json::Value>,
    /// Package name → executing version (None: resolve live).
    packages: BTreeMap<String, Option<String>>,
}

fn loaded_contribution(root: &Path, pod_name: &str) -> miette::Result<LoadedContribution> {
    let decl = load_declaration(root, pod_name)?;
    let store = pod_store(&pod_dir(root, pod_name));
    if let Some(active) = store.active_generation()? {
        return Ok(LoadedContribution {
            overlay: decl.overlay,
            packages: active
                .packages
                .iter()
                .map(|(name, pkg)| (name.clone(), Some(pkg.version.clone())))
                .collect(),
        });
    }
    // No generation yet: mirror the loaded pod's own first sync — its
    // declared packages resolve fresh (overlay applied), its sub-loads
    // fold in beneath (own packages win the name clash, issue #8).
    // Acyclicity is guaranteed: `validate_loads` ran before this read.
    let mut packages = BTreeMap::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
            miette::miette!("cannot resolve loaded pod's package '{}': {e}", spec.name)
        })?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch).map_err(|e| {
                miette::miette!(
                    "pod '{pod_name}' overlay of '{}' is invalid: {e}",
                    spec.name
                )
            })?;
        }
        packages.insert(spec.name, Some(meta.version));
    }
    for loaded in &decl.loads {
        let sub = loaded_contribution(root, loaded)?;
        for (name, version) in sub.packages {
            packages.entry(name).or_insert(version);
        }
    }
    Ok(LoadedContribution {
        overlay: decl.overlay,
        packages,
    })
}

/// The union of package names the pod's `loads` provide (own names
/// shadow sub-load names, but the union is what the overlay-target
/// check needs). Declaration-only, no resolution — read-only and cheap.
fn loaded_package_names(root: &Path, decl: &PodDeclaration) -> miette::Result<HashSet<String>> {
    fn collect(
        root: &Path,
        decl: &PodDeclaration,
        visited: &mut HashSet<String>,
        out: &mut HashSet<String>,
    ) -> miette::Result<()> {
        for spec in &decl.packages {
            if let Ok(parsed) = parse_pod_package(spec) {
                out.insert(parsed.name);
            }
        }
        for loaded in &decl.loads {
            if visited.insert(loaded.clone()) {
                let loaded_decl = load_declaration(root, loaded)?;
                collect(root, &loaded_decl, visited, out)?;
            }
        }
        Ok(())
    }
    let mut visited = HashSet::new();
    let mut out = HashSet::new();
    collect(root, decl, &mut visited, &mut out)?;
    Ok(out)
}
/// Add a package to a pod: resolve it from the package collection FIRST
/// (an unknown package must not modify any state), then record it in
/// `pod.lua` and pin the resolved version in the lockfile, then
/// reconcile the declaration into the pod's store, generation chain,
/// and bin farm (issue #3). Loads are validated (existence + cycles)
/// before any write (issue #8).
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
    // Loads must resolve and be acyclic before ANY write (issue #8);
    // overlays validated against own + loaded packages.
    validate_loads(root, pod_name, &decl)?;
    // The spec joins the declaration before overlay validation: an
    // overlay for the package being added is written ahead of the add.
    decl.packages.push(spec_str.to_string());
    validate_overlays(root, &decl, pod_name)?;
    // The overlay entry for this package is the top layer: pin the
    // EFFECTIVE version, not the collection's (issue #6).
    let mut meta = meta;
    if let Some(patch) = decl.overlay.get(&spec.name) {
        apply_overlay(&mut meta, patch)
            .map_err(|e| miette::miette!("cannot add '{}' with its overlay: {e}", spec.name))?;
    }
    // Binary-collision precheck (issue #8): a same-precedence clash with
    // the pod's post-state package set must fail BEFORE any write.
    let new_layer = if decl.overlay.contains_key(&spec.name) {
        crate::farm::ClaimLayer::Overlay
    } else {
        crate::farm::ClaimLayer::Own
    };
    precheck_binary_collision(root, &decl, &spec.name, &meta, new_layer)?;

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

    // The declaration is the source of truth; the store reconcile
    // follows it. A failed reconcile (unbuildable package) leaves the
    // declaration + pin in place — fix the package and re-run
    // `shuttle pod sync`.
    let sync = sync_pod(root, pod_name)?;
    if let Some(n) = sync.generation {
        crate::output::ok(format!(
            "installed '{}' into pod '{pod_name}' (generation {n})",
            spec.name
        ));
    }

    Ok(PodAddReport {
        pod: pod_name.to_string(),
        name: spec.name,
        constraint: spec.constraint,
        version: meta.version,
        generation: sync.generation,
        pod_dir: dir,
    })
}

/// Remove a package from a pod: drop it from the declaration and delete
/// its lockfile pin, then reconcile — the store generation without it
/// and a farm that no longer exposes its binaries (issue #3). Loads are
/// validated before any write (issue #8).
pub fn remove_package(
    root: &Path,
    pod_name: &str,
    spec_str: &str,
) -> miette::Result<PodRemoveReport> {
    validate_pod_name(pod_name)?;
    let spec = parse_pod_package(spec_str)?;
    let mut decl = load_declaration(root, pod_name)?;
    validate_loads(root, pod_name, &decl)?;
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

    let sync = sync_pod(root, pod_name)?;
    if let Some(n) = sync.generation {
        crate::output::ok(format!(
            "removed '{}' from pod '{pod_name}' (generation {n})",
            spec.name
        ));
    }

    Ok(PodRemoveReport {
        pod: pod_name.to_string(),
        name: spec.name,
        generation: sync.generation,
    })
}

// ── Update (issue #5) ──

/// One package moved by `pod update`.
#[derive(Debug, Serialize)]
pub struct PodUpdateEntry {
    pub name: String,
    /// The version the package was pinned at before the update (None
    /// when it had no pin yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The version the package is now pinned at.
    pub to: String,
}

/// One package `pod update` held back: its constraint no longer matches
/// the newest available version, so the pin stays put.
#[derive(Debug, Serialize)]
pub struct PodUpdateHeld {
    pub name: String,
    /// The version the package stays pinned at (None when unpinned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned: Option<String>,
    /// The candidate version that was rejected by the constraint.
    pub candidate: String,
    /// The constraint that rejected it.
    pub constraint: String,
}

/// Report for `shuttle pod update`.
#[derive(Debug, Serialize)]
pub struct PodUpdateReport {
    pub pod: String,
    /// Packages re-pinned at a newer matching version.
    pub updated: Vec<PodUpdateEntry>,
    /// Packages held back: newest candidate fails their constraint.
    pub held: Vec<PodUpdateHeld>,
    /// Packages already at their newest matching version.
    pub unchanged: Vec<String>,
    /// The generation now current (absent under the degraded
    /// no-squashfs mode or when nothing moved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
}

/// True when `version` satisfies a dotted-numeric `constraint`: every
/// constraint component must equal the version's corresponding
/// component (`14` matches `14` and `14.x.y`; `1.2` matches `1.2.9`;
/// `15` does not match `14.x`). Non-numeric components compare as
/// exact strings.
pub fn version_matches_constraint(version: &str, constraint: &str) -> bool {
    let vc: Vec<&str> = version.split('.').collect();
    let cc: Vec<&str> = constraint.split('.').collect();
    if cc.len() > vc.len() {
        return false;
    }
    for (c, v) in cc.iter().zip(vc.iter()) {
        let matched = match (c.parse::<u64>(), v.parse::<u64>()) {
            (Ok(cn), Ok(vn)) => cn == vn,
            _ => *c == *v,
        };
        if !matched {
            return false;
        }
    }
    true
}

/// Update a pod's packages to the newest versions matching their
/// constraints: re-resolve each declared package (all of them, or only
/// the named ones), repin the lockfile for every version that moved,
/// then reconcile — the store, farm, and generation follow the pins.
/// Constraint-honoring: `pkg@14` adopts the candidate only while it is
/// a 14.x; otherwise the package is held at its pin. Loads are
/// validated (existence + cycles) before any write (issue #8).
pub fn update_pod(
    root: &Path,
    pod_name: &str,
    targets: &[String],
) -> miette::Result<PodUpdateReport> {
    validate_pod_name(pod_name)?;
    let decl = load_declaration(root, pod_name)?;
    // Fail fast on a malformed overlay, before any resolution or repin.
    validate_loads(root, pod_name, &decl)?;
    validate_overlays(root, &decl, pod_name)?;

    // An explicit target set must name declared packages (a trailing
    // `@constraint` on the CLI argument is ignored, like `remove`).
    let wanted: Option<std::collections::BTreeSet<String>> = if targets.is_empty() {
        None
    } else {
        let mut set = std::collections::BTreeSet::new();
        for target in targets {
            let name = parse_pod_package(target)?.name;
            let declared = decl
                .packages
                .iter()
                .any(|spec| parse_pod_package(spec).is_ok_and(|s| s.name == name));
            if !declared {
                miette::bail!("package '{name}' is not in pod '{pod_name}'");
            }
            set.insert(name);
        }
        Some(set)
    };

    // Resolution outcome for one package, decided BEFORE any state is
    // touched (an unresolvable declared package fails the whole update
    // with nothing repinned).
    enum Move {
        Updated {
            name: String,
            from: Option<String>,
            to: String,
            constraint: Option<String>,
        },
        Held {
            name: String,
            pinned: Option<String>,
            candidate: String,
            constraint: String,
        },
        Unchanged(String),
    }

    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);
    let mut moves = Vec::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        if let Some(wanted) = &wanted {
            if !wanted.contains(&spec.name) {
                continue;
            }
        }
        // The candidate resolves through the pod's overlay layer (issue
        // #6): an overlay version pin IS the candidate — the overlay
        // beats both the collection and the package's constraint, so the
        // update lands the pod on the pinned version (or reports it
        // already current) instead of fighting the overlay.
        let mut candidate_meta = crate::deps::load_meta(&spec.name)
            .map_err(|e| miette::miette!("cannot update '{}': {e}", spec.name))?;
        let overlay = decl.overlay.get(&spec.name);
        if let Some(patch) = overlay {
            apply_overlay(&mut candidate_meta, patch)
                .map_err(|e| miette::miette!("cannot update '{}': {e}", spec.name))?;
        }
        let candidate = candidate_meta.version;
        let pin = lock.packages.get(&spec.name).map(|e| e.version.clone());
        let mv = if overlay.is_some() {
            if pin.as_deref() == Some(candidate.as_str()) {
                Move::Unchanged(spec.name.clone())
            } else {
                Move::Updated {
                    name: spec.name.clone(),
                    from: pin.clone(),
                    to: candidate.clone(),
                    constraint: spec.constraint.clone(),
                }
            }
        } else {
            match (&spec.constraint, pin.as_deref()) {
                (Some(constraint), _) if !version_matches_constraint(&candidate, constraint) => {
                    Move::Held {
                        name: spec.name,
                        pinned: pin,
                        candidate,
                        constraint: constraint.clone(),
                    }
                }
                (_, Some(pinned)) if pinned == candidate => Move::Unchanged(spec.name),
                (constraint, _) => Move::Updated {
                    name: spec.name,
                    from: pin,
                    to: candidate,
                    constraint: constraint.clone(),
                },
            }
        };
        moves.push(mv);
    }

    // Repin what moved, then reconcile (the shared path — the store,
    // farm, and generation follow the pins).
    let mut updated = Vec::new();
    let mut held = Vec::new();
    let mut unchanged = Vec::new();
    let mut dirty = false;
    for mv in moves {
        match mv {
            Move::Unchanged(name) => unchanged.push(name),
            Move::Held {
                name,
                pinned,
                candidate,
                constraint,
            } => held.push(PodUpdateHeld {
                name,
                pinned,
                candidate,
                constraint,
            }),
            Move::Updated {
                name,
                from,
                to,
                constraint,
            } => {
                lock.packages.insert(
                    name.clone(),
                    PodPackageLockEntry {
                        version: to.clone(),
                        constraint,
                    },
                );
                dirty = true;
                updated.push(PodUpdateEntry { name, from, to });
            }
        }
    }
    if dirty {
        lock.save(&lock_path)?;
    }

    let sync = sync_pod(root, pod_name)?;
    Ok(PodUpdateReport {
        pod: pod_name.to_string(),
        updated,
        held,
        unchanged,
        generation: sync.generation,
    })
}

// ── Rollback (issue #5) ──

/// Report for `shuttle pod rollback`.
#[derive(Debug, Serialize)]
pub struct PodRollbackReport {
    pub pod: String,
    /// The generation the pod was on before the rollback.
    pub from: u64,
    /// The generation the pod's `current` link now points at.
    pub to: u64,
    /// The farm directory now behind `current`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub farm: Option<PathBuf>,
}

/// Roll a pod back to a previous generation (default: the one before
/// the current): the store's rollback machinery flips that pod's
/// `active` link and relinks its sysext trees, then the bin farm is
/// re-emitted for the target generation and `current` follows — so
/// binaries the newer generation added disappear from the farm.
///
/// Pod-scoped by construction: the per-pod [`RuntimeStore`] lives
/// entirely inside the pod's state directory, so no system generation,
/// boot entry, or other pod is touched. No reboot is performed.
pub fn rollback_pod(
    root: &Path,
    pod_name: &str,
    target: Option<u64>,
) -> miette::Result<PodRollbackReport> {
    validate_pod_name(pod_name)?;
    let dir = pod_dir(root, pod_name);
    let store = pod_store(&dir);
    let tools = crate::runtime::RuntimeTools::from_host();
    let report = store.rollback(target, &tools)?;

    // The farm + `current` follow the flipped generation. Re-emitting
    // is idempotent and heals a farm that predates a lost emit.
    let gen = store.active_generation()?.ok_or_else(|| {
        miette::miette!("rollback left pod '{pod_name}' with no active generation")
    })?;
    let farm = crate::farm::emit(&store, &gen)?;
    crate::farm::flip_current(&dir, gen.n)?;

    Ok(PodRollbackReport {
        pod: pod_name.to_string(),
        from: report.from,
        to: report.to,
        farm: Some(farm),
    })
}

// ── GC (issue #5) ──

/// Garbage-collect a pod's content store: the shared mark-sweep over
/// every pod generation manifest (issue #3's per-pod store, no parallel
/// implementation). With `--prune`, all but the pod's current +
/// previous generations are dropped first — their exclusive blobs then
/// sweep free, while blobs shared with (or referenced by) live
/// generations survive. System generations are never eligible: the
/// store root is the pod's own state directory.
pub fn gc_pod(
    root: &Path,
    pod_name: &str,
    prune: bool,
) -> miette::Result<crate::runtime::GcReport> {
    validate_pod_name(pod_name)?;
    let dir = pod_dir(root, pod_name);
    let store = pod_store(&dir);
    store.gc(prune)
}

/// Report for the pod reconcile (`shuttle pod sync`, and the tail of
/// every add/remove).
#[derive(Debug, Serialize)]
pub struct PodSyncReport {
    pub pod: String,
    /// True when the reconcile changed nothing: every declared package
    /// already installed at the same content and nothing installed that
    /// isn't declared. No new generation, no farm churn.
    pub noop: bool,
    /// Names installed by this reconcile.
    pub installed: Vec<String>,
    /// Names removed from the store by this reconcile.
    pub removed: Vec<String>,
    /// Names HELD at their lockfile pins this reconcile: the package
    /// collection resolves a newer version but the pin (and the active
    /// generation's content) say otherwise — `shuttle pod update` moves
    /// them deliberately (issue #5).
    pub held: Vec<String>,
    /// The generation now current (absent when the pod has nothing
    /// installed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// The farm directory now behind the pod's `current` link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub farm: Option<PathBuf>,
}

/// The runtime store of one pod: the shared runtime store module
/// pointed at the pod's state directory (issue #3 seam — no forked
/// store). The sysext presentation links are kept INSIDE the pod dir so
/// a per-user pod never writes to the system extensions directory.
pub fn pod_store(pod_dir: &Path) -> crate::runtime::RuntimeStore {
    crate::runtime::RuntimeStore::new(pod_dir.to_path_buf())
        .with_extensions_link_dir(pod_dir.join("extensions"))
}

/// Reconcile a pod's declaration into its store: build every declared
/// package through the normal snap build path, install the changed set
/// as a new generation, remove store packages the declaration dropped,
/// then re-emit the active generation's bin farm and flip `current`.
///
/// Idempotent: run with no changes, install finds everything already
/// installed at the same content, removes nothing — no new generation.
///
/// The reconcile is pin-aware (issue #5): the lockfile pin is the source
/// of truth for what stays installed. When a declared package's pin
/// differs from the freshly resolved candidate AND the active generation
/// already carries the pinned version, the package is HELD at its store
/// content — not rebuilt at the candidate (that is what `shuttle pod
/// update` is for). Otherwise it builds normally.
///
/// Composition (issue #8): the pod's `loads` resolve FIRST — each loaded
/// pod contributes its ACTIVE generation's package versions (read-only;
/// a loading pod never mutates a pod it loads) or, when it has none yet,
/// its declaration as its own first sync would build it — folded in
/// beneath the loading pod's own packages, which win a same-name clash
/// outright. Loaded and own packages carrying the same BINARY name (across
/// DIFFERENT package names) run through the shared collision classifier
/// before any write: a higher layer overrides (warn), a same-precedence
/// duplicate errors. Loaded packages land at `ClaimLayer::Loaded`, own at
/// `Own`, overlay-patched at `Overlay`, recorded in the generation
/// manifest so the farm resamples the same order at activation.
pub fn sync_pod(root: &Path, pod_name: &str) -> miette::Result<PodSyncReport> {
    reconcile_pod(root, pod_name)
}

/// The reconcile proper (see [`sync_pod`]).
fn reconcile_pod(root: &Path, pod_name: &str) -> miette::Result<PodSyncReport> {
    validate_pod_name(pod_name)?;
    let decl = load_declaration(root, pod_name)?;
    // Loads (existence + cycles) and overlay validation happen FIRST,
    // before any mutation (issue #8/#6): a bad declaration fails here
    // with zero writes.
    validate_loads(root, pod_name, &decl)?;
    validate_overlays(root, &decl, pod_name)?;
    let dir = pod_dir(root, pod_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let store = pod_store(&dir);
    let tools = crate::runtime::RuntimeTools::from_host();
    let active = store.active_generation()?;

    // Resolve + build every declared package through the normal build
    // path. Resolution happens before any store state moves: a
    // declaration naming an unknown package fails the whole reconcile.
    // Degraded mode: without the squashfs pair nothing can be built or
    // unpacked, so the reconcile installs nothing — warn loudly and
    // keep the declaration half authoritative (removals below still
    // proceed; they never unpack).
    //
    // Layering (issue #6/#8, CONTEXT.md: Overlay): each package resolves
    // from the shared collection, then through the pod's own pin (the
    // hold below keeps collection drift from moving the pod silently),
    // then through the pod's overlay entry — later wins. Loaded pods'
    // packages resolve beneath the pod's own: the version a loaded pod
    // currently executes (its active generation — live-following, never
    // pinned across pods) or, when it has no generation, its declaration
    // as its own first sync would build it. A loading pod never mutates a
    // pod it loads: only the loaded pod's generation + declaration are
    // read.
    let can_install = tools.unsquashfs.is_some() && crate::runtime::tool_on_path("mksquashfs");
    let mut pending = Vec::new();
    let mut held = Vec::new();
    let mut declared_names = std::collections::BTreeSet::new();
    // Desktop application-ID claims of the post-state package set
    // (issue #7): collected in declaration order, resolved for
    // collisions BEFORE any store write.
    let mut desktop_claims = Vec::new();
    // Binary-name claims of the post-state package set (issue #8): the
    // shared collision classifier over loaded/own/overlay layers, run
    // BEFORE any store write so a same-precedence clash is a hard error
    // with zero writes.
    let mut binary_claims: Vec<BinaryClaim> = Vec::new();
    // Version pins the reconcile moved (overlay wins over the pin):
    // recorded only after the build succeeded, applied only after the
    // install succeeded — a failed reconcile leaves the pin in place.
    let mut repins: Vec<(String, PodPackageLockEntry)> = Vec::new();
    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);

    // Loaded pods, in listed order (issue #8): each contributes its
    // package versions. The own package set is the name-clash winner, so
    // a loaded package whose name the pod itself declares never enters
    // the composition. The loading pod does NOT write the loaded pod.
    let mut loaded_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut loaded_overlays: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    {
        for loaded in &decl.loads {
            let contribution = loaded_contribution(root, loaded)?;
            for (name, version) in contribution.packages {
                loaded_versions
                    .entry(name)
                    .or_insert(version.unwrap_or_default());
            }
            for (name, patch) in contribution.overlay {
                loaded_overlays.entry(name).or_insert(patch);
            }
        }
    }

    if can_install {
        // Own packages (in declared order) sit at `Own` (or `Overlay`
        // when patched) — above anything loaded.
        for spec_str in &decl.packages {
            let spec = parse_pod_package(spec_str)?;
            let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
                miette::miette!(
                    "cannot build declared package '{}': {e} (declaration at {})",
                    spec.name,
                    pod_lua_path(root, pod_name).display()
                )
            })?;
            let overlay = decl.overlay.get(&spec.name);
            if let Some(patch) = overlay {
                apply_overlay(&mut meta, patch).map_err(|e| {
                    miette::miette!(
                        "cannot build declared package '{}' with its overlay: {e}",
                        spec.name
                    )
                })?;
            }
            declared_names.insert(meta.name.clone());
            let layer = if overlay.is_some() {
                crate::farm::ClaimLayer::Overlay
            } else {
                crate::farm::ClaimLayer::Own
            };
            if overlay.is_none() {
                if let Some(pin) = lock.packages.get(&spec.name) {
                    if pin.version != meta.version
                        && active.as_ref().is_some_and(|g| {
                            g.packages
                                .get(&spec.name)
                                .is_some_and(|p| p.version == pin.version)
                        })
                    {
                        held.push(meta.name.clone());
                        if let Some(installed_pkg) =
                            active.as_ref().and_then(|g| g.packages.get(&spec.name))
                        {
                            push_desktop_claims(
                                &mut desktop_claims,
                                installed_pkg,
                                crate::farm::ClaimLayer::Own,
                            );
                            push_installed_binary_claims(
                                &mut binary_claims,
                                installed_pkg,
                                crate::farm::ClaimLayer::Own,
                            );
                        }
                        continue;
                    }
                }
            }
            push_meta_desktop_claims(&mut desktop_claims, &meta, layer);
            push_meta_binary_claims(&mut binary_claims, &meta, layer);
            if lock.packages.get(&spec.name).map(|e| e.version.as_str())
                != Some(meta.version.as_str())
            {
                repins.push((
                    spec.name.clone(),
                    PodPackageLockEntry {
                        version: meta.version.clone(),
                        constraint: spec.constraint.clone(),
                    },
                ));
            }
            pending.push(build_pending_snap(&store, &meta, layer)?);
        }

        // Loaded packages (issue #8): a loaded pod's package is rebuilt
        // at the version it currently executes — same overlay build
        // inputs, so the loading pod executes exactly what the loaded pod
        // executes. Deterministic build output keeps a no-change reconcile
        // a no-op. Own packages with the same NAME shadow them outright
        // (the loaded copy never enters); the name is skipped below.
        for (name, version) in &loaded_versions {
            if declared_names.contains(name) {
                continue;
            }
            let mut meta = crate::deps::load_meta(name).map_err(|e| {
                miette::miette!(
                    "loaded package '{}' from pod '{}' cannot be resolved: {e}",
                    name,
                    pod_name
                )
            })?;
            // Apply the loaded pod's overlay for this package so the
            // rebuilt payload carries the same build inputs it would get
            // in the loaded pod itself. The loading pod's own overlay for
            // this loaded package is the TOP layer: it wins.
            if let Some(patch) = loaded_overlays.get(name) {
                apply_overlay(&mut meta, patch).map_err(|e| {
                    miette::miette!("loaded package '{name}' overlay is invalid: {e}")
                })?;
            }
            if let Some(patch) = decl.overlay.get(name) {
                apply_overlay(&mut meta, patch).map_err(|e| {
                    miette::miette!(
                        "cannot build loaded package '{name}' with this pod's overlay: {e}"
                    )
                })?;
            }
            // Pin the loaded package at the executing version (a loaded
            // pod's active generation version wins over collection drift).
            if !version.is_empty() {
                meta.version = version.clone();
            }
            declared_names.insert(meta.name.clone());
            push_meta_desktop_claims(&mut desktop_claims, &meta, crate::farm::ClaimLayer::Loaded);
            push_meta_binary_claims(&mut binary_claims, &meta, crate::farm::ClaimLayer::Loaded);
            pending.push(build_pending_snap(
                &store,
                &meta,
                crate::farm::ClaimLayer::Loaded,
            )?);
        }
    } else if !decl.packages.is_empty() || !loaded_versions.is_empty() {
        warn_degraded_install();
    }

    // Desktop app-ID collision check (issue #7) and binary-name
    // collision check (issue #8) — BEFORE any store write, so a
    // same-precedence collision fails with zero writes.
    resolve_desktop_claims(&desktop_claims)?;
    resolve_binary_claims(&binary_claims)?;

    // Install the changed set (a no-op batch creates no generation).
    let mut installed = Vec::new();
    if !pending.is_empty() {
        let report = store.install_batch(&pending, &Default::default(), &tools)?;
        if !report.noop {
            installed = report.installed.iter().map(|s| s.name.clone()).collect();
        }
    }

    // Overlay-driven repins (issue #6): applied only after the installs
    // succeeded, so a failed reconcile leaves the pin untouched. Loaded
    // packages are NOT repinned in this pod's lockfile: a loaded pod's
    // versions live in the loaded pod, and this pod follows them live
    // (issue #8 — read-only consumption, no cross-pod pins).
    if !repins.is_empty() {
        for (name, entry) in repins {
            lock.packages.insert(name, entry);
        }
        lock.save(&lock_path)?;
    }

    // Remove store packages the declaration dropped. Removal never
    // unpacks, so it proceeds even in degraded mode. A package the
    // degraded mode never installed is simply absent — skip it.
    let mut removed = Vec::new();
    if let Some(active) = store.active_generation()? {
        for name in active.packages.keys() {
            if declared_names.contains(name) {
                continue;
            }
            store.remove(name, &tools)?;
            removed.push(name.clone());
        }
    }

    // Present whatever is now active. Nothing active → nothing exposed.
    let active = store.active_generation()?;
    let (generation, farm) = match &active {
        Some(gen) => {
            let farm = crate::farm::emit(&store, gen)?;
            crate::farm::flip_current(&dir, gen.n)?;
            (Some(gen.n), Some(farm))
        }
        None => {
            crate::farm::clear_current(&dir)?;
            // Nothing active exposes nothing: the user-level launcher
            // surface is withdrawn along with the farm (issue #7).
            crate::desktop::clear(&store)?;
            (None, None)
        }
    };

    Ok(PodSyncReport {
        pod: pod_name.to_string(),
        noop: installed.is_empty() && removed.is_empty(),
        installed,
        removed,
        held,
        generation,
        farm,
    })
}

/// One claim on a desktop application ID (issue #7): which package
/// claims the id, at which precedence layer.
#[derive(Debug, Clone)]
struct DesktopClaim {
    app_id: String,
    pkg: String,
    layer: crate::farm::ClaimLayer,
}

/// Collect the desktop application-ID claims of a freshly resolved meta
/// (a package about to be built): every app carrying a `desktop` field.
fn push_meta_desktop_claims(
    claims: &mut Vec<DesktopClaim>,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
) {
    for (app_id, app) in &meta.apps {
        if app.desktop.is_some() {
            claims.push(DesktopClaim {
                app_id: app_id.clone(),
                pkg: meta.name.clone(),
                layer,
            });
        }
    }
}

/// Collect the desktop application-ID claims of an already-installed
/// package (a held pin): the ids recorded in its manifest entry.
fn push_desktop_claims(
    claims: &mut Vec<DesktopClaim>,
    pkg: &crate::runtime::InstalledPackage,
    layer: crate::farm::ClaimLayer,
) {
    for app_id in pkg.desktops.keys() {
        claims.push(DesktopClaim {
            app_id: app_id.clone(),
            pkg: pkg.name.clone(),
            layer,
        });
    }
}

/// Resolve desktop application-ID collisions across the post-state
/// package set (issue #7). Same-precedence duplicates are a hard error
/// (zero writes — this runs before the install); a higher layer
/// overriding a lower one, or a lower one being shadowed, warns and the
/// higher layer wins. Declaration order breaks ties: the later package
/// is the incoming claim.
fn resolve_desktop_claims(claims: &[DesktopClaim]) -> miette::Result<()> {
    let mut incumbent: BTreeMap<String, DesktopClaim> = BTreeMap::new();
    for claim in claims {
        let Some(existing) = incumbent.get(&claim.app_id) else {
            incumbent.insert(claim.app_id.clone(), claim.clone());
            continue;
        };
        match crate::farm::classify_collision(existing.layer, claim.layer) {
            crate::farm::CollisionVerdict::Error => {
                miette::bail!(
                    "application id '{}' is declared by both '{}' and '{}' at the same \
                     precedence — same-precedence desktop app-ID collision; rename one of \
                     the apps or drop one of the packages",
                    claim.app_id,
                    existing.pkg,
                    claim.pkg
                );
            }
            crate::farm::CollisionVerdict::Override => {
                crate::output::warn(format!(
                    "application id '{}' from '{}' overrides '{}' (higher layer wins)",
                    claim.app_id, claim.pkg, existing.pkg
                ));
                incumbent.insert(claim.app_id.clone(), claim.clone());
            }
            crate::farm::CollisionVerdict::Shadowed => {
                crate::output::warn(format!(
                    "application id '{}' from '{}' is shadowed by '{}' (lower layer loses)",
                    claim.app_id, claim.pkg, existing.pkg
                ));
            }
        }
    }
    Ok(())
}

// ── Binary-name claims (issue #8) ──

/// Pre-write binary-collision check for `add_package` (issue #8): the
/// same-precedence clash must fail BEFORE the declaration or lockfile is
/// written. Collects the binary claims of the post-state package set —
/// the package being added (already overlaid) plus every existing
/// declared package — and resolves them. A same-precedence collision
/// bails (caller writes nothing); a cross-layer override is allowed here
/// (reconcile warns at activation). Loaded-pod contributions are folded
/// in at `Loaded` so an add never silently shadows a loaded binary either.
fn precheck_binary_collision(
    root: &Path,
    decl: &PodDeclaration,
    new_name: &str,
    new_meta: &crate::snap::SnapMeta,
    new_layer: crate::farm::ClaimLayer,
) -> miette::Result<()> {
    let mut claims: Vec<BinaryClaim> = Vec::new();
    push_meta_binary_claims(&mut claims, new_meta, new_layer);
    push_declared_binary_claims(&mut claims, decl, new_name)?;
    push_loaded_binary_claims(&mut claims, root, decl, new_name)?;
    resolve_binary_claims(&claims)
}

/// Collect the binary claims of every declared package except the one
/// being added, at its layer (own, or overlay when the pod patches it).
fn push_declared_binary_claims(
    claims: &mut Vec<BinaryClaim>,
    decl: &PodDeclaration,
    new_name: &str,
) -> miette::Result<()> {
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        if spec.name == new_name {
            continue; // the incoming package's claims are already added
        }
        let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
            miette::miette!("cannot check '{}' for a binary collision: {e}", spec.name)
        })?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch)
                .map_err(|e| miette::miette!("overlay of '{}' is invalid: {e}", spec.name))?;
        }
        let layer = if decl.overlay.contains_key(&spec.name) {
            crate::farm::ClaimLayer::Overlay
        } else {
            crate::farm::ClaimLayer::Own
        };
        push_meta_binary_claims(claims, &meta, layer);
    }
    Ok(())
}

/// Collect the binary claims of loaded-pod-provided packages, folded in
/// at `Loaded` (the composition floor). A name the pod itself declares is
/// already claimed at a higher layer, so it is skipped here.
fn push_loaded_binary_claims(
    claims: &mut Vec<BinaryClaim>,
    root: &Path,
    decl: &PodDeclaration,
    new_name: &str,
) -> miette::Result<()> {
    for name in loaded_package_names(root, decl)? {
        let declared = decl.packages.iter().any(|s| {
            parse_pod_package(s)
                .map(|p| p.name == name)
                .unwrap_or(false)
        });
        if declared || name == new_name {
            continue;
        }
        let meta = crate::deps::load_meta(&name).map_err(|e| {
            miette::miette!("cannot check loaded '{}' for a binary collision: {e}", name)
        })?;
        push_meta_binary_claims(claims, &meta, crate::farm::ClaimLayer::Loaded);
    }
    Ok(())
}

/// One claim on a shared binary name (issue #8): which package exports
/// the binary, at which composition precedence layer. Generalized from
/// the desktop-ID claim so the shared classifier runs unchanged.
#[derive(Debug, Clone)]
struct BinaryClaim {
    binary: String,
    pkg: String,
    layer: crate::farm::ClaimLayer,
}

/// Collect the binary-name claims of a freshly resolved meta (a package
/// about to be built): the name of every app the package exports.
fn push_meta_binary_claims(
    claims: &mut Vec<BinaryClaim>,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
) {
    for app in meta.apps.keys() {
        claims.push(BinaryClaim {
            binary: app.clone(),
            pkg: meta.name.clone(),
            layer,
        });
    }
}

/// Collect the binary-name claims of an already-installed package (a
/// held pin): the apps recorded in its manifest entry.
fn push_installed_binary_claims(
    claims: &mut Vec<BinaryClaim>,
    pkg: &crate::runtime::InstalledPackage,
    layer: crate::farm::ClaimLayer,
) {
    for app in pkg.apps.keys() {
        claims.push(BinaryClaim {
            binary: app.clone(),
            pkg: pkg.name.clone(),
            layer,
        });
    }
}

/// Resolve binary-name collisions across the post-state package set
/// (issue #8). Same-precedence duplicates are a hard error (zero writes
/// — this runs before the install); a higher layer overriding a lower
/// one warns naming winner and loser; a lower layer being shadowed
/// warns, the higher layer stays. Declaration order breaks ties: the
/// later claim is the incoming one.
fn resolve_binary_claims(claims: &[BinaryClaim]) -> miette::Result<()> {
    let mut incumbent: BTreeMap<String, BinaryClaim> = BTreeMap::new();
    for claim in claims {
        let Some(existing) = incumbent.get(&claim.binary) else {
            incumbent.insert(claim.binary.clone(), claim.clone());
            continue;
        };
        match crate::farm::classify_collision(existing.layer, claim.layer) {
            crate::farm::CollisionVerdict::Error => {
                miette::bail!(
                    "'{}' is shipped by both '{}' and '{}' at the same-precedence \
                     layer (loaded/own/overlay layering) — rename one of the packages or \
                     drop one of them",
                    claim.binary,
                    existing.pkg,
                    claim.pkg
                );
            }
            crate::farm::CollisionVerdict::Override => {
                crate::output::warn(format!(
                    "binary '{}' from '{}' overrides '{}' (higher layer wins)",
                    claim.binary, claim.pkg, existing.pkg
                ));
                incumbent.insert(claim.binary.clone(), claim.clone());
            }
            crate::farm::CollisionVerdict::Shadowed => {
                crate::output::warn(format!(
                    "binary '{}' from '{}' is shadowed by '{}' (lower layer loses)",
                    claim.binary, claim.pkg, existing.pkg
                ));
            }
        }
    }
    Ok(())
}

/// Degraded-mode banner for `pod add` when the squashfs pair is absent:
/// the declaration is written, the install is deferred to
/// `shuttle pod sync` once the tools exist.
pub(crate) fn warn_degraded_install() {
    crate::output::warn(
        "unsquashfs/mksquashfs not found — packages declared but not \
         installed; install squashfs-tools and run `shuttle pod sync`",
    );
}

/// Epoch stamped into pod-built payloads so the same content builds to
/// the same bytes on every sync (mksquashfs embeds build time otherwise
/// — verified: two builds of an identical tree differ without this, and
/// match with it). The no-op detection compares payload sha3-384s, so
/// reproducibility IS the idempotency guarantee.
const POD_BUILD_EPOCH: &str = "946684800";

/// Build one declared package into a `.snap` payload with the normal
/// snap build path (`shuttle::snap::build_snap` — the same pipeline
/// `shuttle build` uses, sandbox included) and shape it as a pending
/// store install at the given composition layer. Local builds carry
/// revision 0; content identity is the payload's sha3-384, which is
/// what the no-op detection compares.
fn build_pending_snap(
    store: &crate::runtime::RuntimeStore,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
) -> miette::Result<crate::runtime::PendingSnap> {
    // mksquashfs 4.4+ reads this natively; only set it when the user
    // hasn't chosen an epoch of their own.
    if std::env::var_os("SOURCE_DATE_EPOCH").is_none() {
        std::env::set_var("SOURCE_DATE_EPOCH", POD_BUILD_EPOCH);
    }
    let stage = tempfile::tempdir().map_err(|e| miette::miette!("temp stage dir: {e}"))?;
    let downloads = store.downloads_dir();
    std::fs::create_dir_all(&downloads)
        .map_err(|e| miette::miette!("creating {}: {e}", downloads.display()))?;
    let result = crate::snap::build_snap(
        meta,
        stage.path(),
        &downloads,
        crate::snap::host_arch(),
        crate::snap::StagePolicy::Default,
    )?;
    let payload = downloads.join(&result.snap_filename);
    let sha3_384 = crate::store::sha3_384_file(&payload)?;
    Ok(build_pending_snap_at(meta, &payload, sha3_384, layer))
}

/// Shape a built, content-hashed payload as a [`PendingSnap`] at the
/// package's composition layer (issue #8). Store/pull installs use the
/// `Own` default.
fn build_pending_snap_at(
    meta: &crate::snap::SnapMeta,
    payload_path: &Path,
    sha3_384: String,
    layer: crate::farm::ClaimLayer,
) -> crate::runtime::PendingSnap {
    crate::runtime::PendingSnap {
        name: meta.name.clone(),
        revision: 0,
        sha3_384,
        payload_path: payload_path.to_path_buf(),
        layer,
    }
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

    /// Bare SnapMeta with every optional field empty (mirrors the test
    /// helper in manifest.rs).
    fn bare_meta(name: &str, version: &str) -> crate::snap::SnapMeta {
        use std::collections::HashMap;
        crate::snap::SnapMeta {
            name: name.into(),
            version: version.into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            build: None,
            parts: None,
            architectures: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            version_adopted: false,
            icon_source: None,
            icon: None,
            compression: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            apps: HashMap::new(),
            definition_dir: None,
        }
    }

    #[test]
    fn test_apply_overlay_patches_whitelisted_fields() {
        let mut meta = bare_meta("tool", "14.4");
        apply_overlay(
            &mut meta,
            &serde_json::json!({"version": "9.9", "build": "echo hi"}),
        )
        .unwrap();
        assert_eq!(meta.version, "9.9");
        assert_eq!(meta.build.as_deref(), Some("echo hi"));
    }

    #[test]
    fn test_apply_overlay_rejects_unknown_and_non_string_fields() {
        let mut meta = bare_meta("tool", "1");
        let err = apply_overlay(&mut meta, &serde_json::json!({"grade": "devel"}))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("grade") && err.contains("version") && err.contains("build"),
            "error must name the field and the allowed set: {err}"
        );
        let err = apply_overlay(&mut meta, &serde_json::json!({"version": 9}))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'version'") && err.contains("string"),
            "non-string values must be rejected: {err}"
        );
        // A rejected patch must leave the meta untouched.
        assert_eq!(meta.version, "1");
    }

    #[test]
    fn test_validate_overlays_rejects_undeclared_key_before_mutation() {
        let decl = evaluate_pod_source(
            "test",
            r#"pod {
    packages = { "jq" },
    overlay = { ghost = { version = "1.0" } },
}"#,
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let err = validate_overlays(tmp.path(), &decl, "work")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ghost") && err.contains("does not build"),
            "error must name the undeclared overlay target: {err}"
        );
    }

    #[test]
    fn test_validate_overlays_accepts_declared_keys() {
        let decl = evaluate_pod_source(
            "test",
            r#"pod {
    packages = { "jq", "ripgrep@14" },
    overlay = {
        jq = { version = "1.8" },
        ripgrep = { build = "echo hi" },
    },
}"#,
        )
        .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        validate_overlays(tmp.path(), &decl, "work").unwrap();
    }

    #[test]
    fn test_version_matches_constraint() {
        // `pkg@14` means newest 14.x.
        assert!(version_matches_constraint("14", "14"));
        assert!(version_matches_constraint("14.1", "14"));
        assert!(version_matches_constraint("14.4.9", "14"));
        assert!(version_matches_constraint("1.2.9", "1.2"));
        // A newer major must NOT match an older constraint.
        assert!(!version_matches_constraint("15.0", "14"));
        assert!(!version_matches_constraint("2.0", "1.2"));
        // Constraint longer than version: not satisfiable.
        assert!(!version_matches_constraint("14", "14.1"));
        // Numeric compare, not string prefix ("10" is not "1").
        assert!(!version_matches_constraint("10.5", "1"));
        assert!(version_matches_constraint("10.5", "10"));
        // Non-numeric components compare as exact strings.
        assert!(version_matches_constraint("14a", "14a"));
        assert!(!version_matches_constraint("14b", "14a"));
    }
}
