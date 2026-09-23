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

use miette::{IntoDiagnostic, WrapErr};
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

/// Validate a pod name: the name becomes a directory under the pod root
/// AND reaches generated unit file names and `Description=` lines
/// (ADR-0032 Decision 4), so besides being a single path-safe component
/// it must not carry control characters or quotes (a newline would
/// inject into the unit text; a quote breaks its quoting — issue #109
/// S5).
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
    if name
        .chars()
        .any(|c| c.is_control() || c == '\'' || c == '"')
    {
        miette::bail!(
            "pod name '{name}' must not contain control characters or quotes — the \
             name reaches unit file names and unit descriptions verbatim"
        );
    }
    Ok(())
}

/// Resolve a `--pod` param to `(name, pod dir)` under an explicit pod
/// root — `default` when None, name validated per [`validate_pod_name`].
/// Split from [`resolve_pod_dir`] so tests can point the root at a
/// tempdir.
pub fn resolve_pod_dir_under(root: &Path, pod: Option<&str>) -> miette::Result<(String, PathBuf)> {
    let name = pod.unwrap_or(DEFAULT_POD);
    validate_pod_name(name)?;
    Ok((name.to_string(), pod_dir(root, name)))
}

/// [`resolve_pod_dir_under`] against the resolved [`pod_root`]: the one
/// pod-scope rule of the sharing verbs (ADR-0033 Decision 5) — peer and
/// static pulls stage into the named pod's store, `serve --pod` serves
/// it.
pub fn resolve_pod_dir(pod: Option<&str>) -> miette::Result<(String, PathBuf)> {
    resolve_pod_dir_under(&pod_root(None), pod)
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
    /// Declared environment (`env = { KEY = "value" }`), stored sorted —
    /// the resolved map is written to the generation and exported in
    /// this deterministic order (ADR-0016 §7 env hooks).
    pub env: BTreeMap<String, String>,
    /// Per-service option overrides (ADR-0032 Decision 3): service name →
    /// option overrides merged over each package-declared service's
    /// options (package defaults < loaded pods < this declaration).
    pub services: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
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
    let mut seen: HashSet<String> = HashSet::new();

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
            "loads" | "packages" | "overlay" | "env" | "services" => {
                if !seen.insert(key.clone()) {
                    miette::bail!("duplicate field '{key}' in pod() declaration");
                }
                assign_pod_field(&mut decl, &key, &value)?;
            }
            other => miette::bail!(
                "unknown field '{other}' in pod() declaration \
                 (allowed: loads, packages, overlay, env, services)"
            ),
        }
    }
    Ok(decl)
}

/// Parse one known `pod()` field into the declaration. Only called with
/// keys the match in [`validate_pod_table`] already accepted.
fn assign_pod_field(
    decl: &mut PodDeclaration,
    key: &str,
    value: &mlua::Value,
) -> miette::Result<()> {
    match key {
        "loads" => decl.loads = expect_string_list(value, "loads")?,
        "packages" => decl.packages = expect_package_list(value)?,
        "overlay" => decl.overlay = expect_overlay(value)?,
        "env" => decl.env = expect_env(value)?,
        "services" => decl.services = expect_service_overrides(value)?,
        _ => unreachable!("validate_pod_table filtered unknown keys"),
    }
    Ok(())
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

/// Validate the `env` field: a table of name → string value. Keys must
/// be valid environment names (see [`validate_env_key`]); values must be
/// UTF-8 strings without newlines (the shellenv export is line-based
/// POSIX shell — a newline would smuggle in a second command). An empty
/// value is allowed (exporting `KEY=''` is meaningful: it SHADOWS an
/// inherited value with empty).
fn expect_env(value: &mlua::Value) -> miette::Result<BTreeMap<String, String>> {
    let table = match value {
        mlua::Value::Table(t) => t,
        other => miette::bail!(
            "'env' must be a table of strings, got {}",
            lua_type_name(other)
        ),
    };
    let mut out = BTreeMap::new();
    for pair in table.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, item) = pair.map_err(|e| miette::miette!("'env': {e}"))?;
        let key = match &key {
            mlua::Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("'env': non-utf8 key: {e}"))?
                .to_string(),
            other => miette::bail!("'env' keys must be strings, got {}", lua_type_name(other)),
        };
        validate_env_key(&key)?;
        let value = match &item {
            mlua::Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("'env.{key}': non-utf8 value: {e}"))?
                .to_string(),
            other => miette::bail!("'env.{key}' must be a string, got {}", lua_type_name(other)),
        };
        if value.contains('\n') || value.contains('\r') {
            miette::bail!("'env.{key}' must not contain newlines");
        }
        out.insert(key, value);
    }
    Ok(out)
}

/// Validate the `services` field (ADR-0032 Decision 3): service name →
/// option-override table (string keys, scalar values). Names obey the
/// shared plain-name constraint (`^[a-z0-9-]+$`, shared with the package
/// declarations in snap.rs) so every backend identifier mapping stays
/// total; the overrides configure an existing service — referencing one
/// is validated at reconcile time, where the package set is known.
fn expect_service_overrides(
    value: &mlua::Value,
) -> miette::Result<BTreeMap<String, BTreeMap<String, serde_json::Value>>> {
    let table = match value {
        mlua::Value::Table(t) => t,
        other => miette::bail!(
            "'services' must be a table of tables, got {}",
            lua_type_name(other)
        ),
    };
    let mut out = BTreeMap::new();
    for pair in table.clone().pairs::<mlua::Value, mlua::Value>() {
        let (key, item) = pair.map_err(|e| miette::miette!("'services': {e}"))?;
        let name = match &key {
            mlua::Value::String(s) => s
                .to_str()
                .map_err(|e| miette::miette!("'services': non-utf8 key: {e}"))?
                .to_string(),
            other => miette::bail!(
                "'services' keys must be strings, got {}",
                lua_type_name(other)
            ),
        };
        crate::snap::validate_service_name(&name)
            .map_err(|e| miette::miette!("'services': {e}"))?;
        let options = match &item {
            mlua::Value::Table(_) => crate::isolate::lua_to_json(&item).map_err(|e| {
                miette::miette!("'services.{name}' must be a plain data table: {e}")
            })?,
            other => miette::bail!(
                "'services.{name}' must be a table of option overrides, got {}",
                lua_type_name(other)
            ),
        };
        let Some(obj) = options.as_object() else {
            miette::bail!("'services.{name}' must be a table of option overrides");
        };
        let mut overrides = BTreeMap::new();
        for (key, value) in obj {
            if !matches!(
                value,
                serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::String(_)
            ) {
                miette::bail!(
                    "'services.{name}.{key}' must be a scalar option override \
                     (string, number, or boolean)"
                );
            }
            overrides.insert(key.clone(), value.clone());
        }
        out.insert(name, overrides);
    }
    Ok(out)
}

/// An env name must be non-empty `[A-Za-z_][A-Za-z0-9_]*`. `PATH` and
/// `LD_LIBRARY_PATH` are RESERVED: PATH is the pod-computed activation
/// seam (farm-first prepend per ADR-0028), and `LD_LIBRARY_PATH` stays
/// pod-managed even though the shell export is gone (ADR-0034) — the
/// emit-time LD wrappers own it inside pod processes, and a declared
/// value would be silently overwritten or, worse, re-open the #110
/// leak. Declare payloads' dirs instead.
fn validate_env_key(key: &str) -> miette::Result<()> {
    let mut chars = key.chars();
    let well_formed = match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    };
    if !well_formed {
        miette::bail!("invalid env key '{key}': must match [A-Za-z_][A-Za-z0-9_]*");
    }
    if key == "PATH" || key == "LD_LIBRARY_PATH" {
        miette::bail!(
            "env key '{key}' is reserved: PATH and LD_LIBRARY_PATH are pod-managed \
             seams (farm-first PATH per ADR-0028; loader libs per ADR-0034's \
             emit-time wrappers) — a declared value would never survive"
        );
    }
    Ok(())
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
/// declaration (issue #6: version pins, build tweaks; ticket #11:
/// confinement override; ticket #13: float mode). Anything else is
/// rejected with the allowed set named.
const OVERLAY_FIELDS: &[&str] = &["version", "build", "confinement", "floating"];

/// Apply one overlay entry (a plain-data patch table) onto a resolved
/// [`SnapMeta`]. This is the top layer of the pod resolution chain
/// (CONTEXT.md: Overlay): later layers win, upstream declarations are
/// never modified.
///
/// String-valued whitelisted fields (`version`, `build`) are patched;
/// `confinement` is special: the string `"unconfined"` clears the
/// package's grants (the ADR-0016 explicit escape hatch), any other
/// value must be a plain-data grants table replacing them. Unknown fields
/// and non-string values fail naming `overlay.<pkg>.<field>`.
fn apply_overlay(
    meta: &mut crate::snap::SnapMeta,
    patch: &serde_json::Value,
) -> miette::Result<()> {
    let Some(obj) = patch.as_object() else {
        miette::bail!("overlay entry must be a table of fields, got {}", patch);
    };
    for (key, value) in obj {
        match key.as_str() {
            "version" => {
                let Some(s) = value.as_str() else {
                    miette::bail!("overlay field '{key}' must be a string, got {value}");
                };
                meta.version = s.to_string();
            }
            "build" => {
                let Some(s) = value.as_str() else {
                    miette::bail!("overlay field '{key}' must be a string, got {value}");
                };
                meta.build = Some(s.to_string());
            }
            "confinement" => apply_confinement_overlay(meta, value)?,
            "floating" => {
                let Some(b) = value.as_bool() else {
                    miette::bail!("overlay field '{key}' must be a boolean, got {value}");
                };
                meta.floating = b;
            }
            other => miette::bail!(
                "unsupported overlay field '{other}' (allowed: {})",
                OVERLAY_FIELDS.join(", ")
            ),
        }
    }
    Ok(())
}

/// Apply one overlay `confinement` value: the escape-hatch string
/// "unconfined" lifts confinement for this pod, a grants table replaces it.
fn apply_confinement_overlay(
    meta: &mut crate::snap::SnapMeta,
    value: &serde_json::Value,
) -> miette::Result<()> {
    if value.as_str() == Some("unconfined") {
        meta.confined = None;
        return Ok(());
    }
    let json = value.clone();
    meta.confined = Some(
        confinement_from_overlay(&json)
            .map_err(|e| miette::miette!("overlay confinement is invalid: {e}"))?,
    );
    Ok(())
}

/// Convert a plain-data overlay `confinement` value (already JSON) into a
/// [`crate::snap::Confinement`]. The overlay path is JSON data (the pod
/// table was serialized at parse time), so we round-trip through the
/// grant field parsers by rebuilding a Lua table — that reuses the single
/// Rust conversion boundary.
fn confinement_from_overlay(value: &serde_json::Value) -> miette::Result<crate::snap::Confinement> {
    if value.as_str() == Some("unconfined") {
        miette::bail!("expected a confinement grants table, got the string \"unconfined\"");
    }
    let obj = value.as_object().ok_or_else(|| {
        miette::miette!("confinement must be a table of grants or the string \"unconfined\"")
    })?;
    let lua = mlua::Lua::new();
    let table = lua.create_table().map_err(|e| miette::miette!("{e}"))?;
    for (k, v) in obj {
        let value = json_to_lua(&lua, v)?;
        table
            .set(k.as_str(), value)
            .map_err(|e| miette::miette!("{e}"))?;
    }
    crate::snap::confinement_from_lua(&table)
}

/// Convert a JSON value into a Lua value (for re-parsing overlay data).
fn json_to_lua(lua: &mlua::Lua, value: &serde_json::Value) -> miette::Result<mlua::Value> {
    Ok(match value {
        serde_json::Value::Null => mlua::Value::Nil,
        serde_json::Value::Bool(b) => mlua::Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                mlua::Value::Integer(i as mlua::Integer)
            } else if let Some(f) = n.as_f64() {
                mlua::Value::Number(f)
            } else {
                mlua::Value::Nil
            }
        }
        serde_json::Value::String(s) => {
            mlua::Value::String(lua.create_string(s).map_err(|e| miette::miette!("{e}"))?)
        }
        serde_json::Value::Array(items) => {
            let t = lua.create_table().map_err(|e| miette::miette!("{e}"))?;
            for (i, item) in items.iter().enumerate() {
                let v = json_to_lua(lua, item)?;
                t.set(i + 1, v).map_err(|e| miette::miette!("{e}"))?;
            }
            mlua::Value::Table(t)
        }
        serde_json::Value::Object(map) => {
            let t = lua.create_table().map_err(|e| miette::miette!("{e}"))?;
            for (k, item) in map {
                let v = json_to_lua(lua, item)?;
                t.set(k.as_str(), v).map_err(|e| miette::miette!("{e}"))?;
            }
            mlua::Value::Table(t)
        }
    })
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
        validate_overlay_entry(pkg, patch)?;
    }
    Ok(())
}

/// Validate one overlay entry's fields against the whitelist.
fn validate_overlay_entry(pkg: &str, patch: &serde_json::Value) -> miette::Result<()> {
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
        validate_overlay_value(pkg, key, value)?;
    }
    Ok(())
}

/// Type-check one overlay field value: `confinement` is either the
/// escape-hatch string "unconfined" or a grants table; `floating` is a
/// boolean (ADR-0017); the other fields are strings.
fn validate_overlay_value(pkg: &str, key: &str, value: &serde_json::Value) -> miette::Result<()> {
    if key == "confinement" {
        if value.as_str() == Some("unconfined") {
            return Ok(());
        }
        if value.as_object().is_none() {
            miette::bail!(
                "'overlay.{pkg}.confinement' must be a grants table or the string \"unconfined\", got {value}"
            );
        }
        return Ok(());
    }
    if key == "floating" {
        if value.as_bool().is_none() {
            miette::bail!("'overlay.{pkg}.floating' must be a boolean, got {value}");
        }
        return Ok(());
    }
    if value.as_str().is_none() {
        miette::bail!("'overlay.{pkg}.{key}' must be a string, got {value}");
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
    if !decl.services.is_empty() {
        out.push_str("    services = {\n");
        for (name, overrides) in &decl.services {
            out.push_str(&format!("        {} = {{\n", render_lua_key(name)));
            for (key, value) in overrides {
                out.push_str(&format!(
                    "            {} = {},\n",
                    render_lua_key(key),
                    render_json_lua(value, 3)
                ));
            }
            out.push_str("        },\n");
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

/// Report for a successful `pod rebuild` (issue #15).
#[derive(Debug, Serialize)]
pub struct PodRebuildReport {
    pub pod: String,
    pub name: String,
    pub version: String,
    /// True when the target was HELD, not rebuilt: a blob-pinned
    /// (sideloaded) package keeps its installed store content on every
    /// reconcile — the payload, not a recipe, is its content (issue
    /// #116).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// True when the rebuild deliberately moved the dependency-closure
    /// pin (`--latest`): the fresh closure hash differed from the
    /// previous pin's, or the package had no deps pin yet (ADR-0017
    /// Decision 5).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub deps_pin_moved: bool,
    /// The generation the rebuild produced (see [`PodAddReport`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
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
    /// Float mode (ADR-0017, issue #13): the package opts in via its
    /// declaration or a pod overlay; sync re-resolves its closure.
    pub floating: bool,
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
    detect_load_cycle(root, pod_name, decl)?;
    refuse_loaded_blob_pins(root, pod_name, decl)
}

/// Refuse a load graph that carries sideloaded packages (issue #116,
/// Decision 5): a loaded pod's packages are REBUILT into the loading
/// pod's store from collection source, and a blob-pinned package has no
/// collection entry — composition would die in `load_meta` halfway
/// through, or worse after writes. The refusal runs in
/// [`validate_loads`], so every mutating verb (add/sync/update/rebuild/
/// remove) fails BEFORE any write, naming the loaded pod, the pinned
/// packages, and this issue. Blob-copy across pods is deferred.
fn refuse_loaded_blob_pins(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<()> {
    fn visit(
        root: &Path,
        pod_name: &str,
        decl: &PodDeclaration,
        visited: &mut HashSet<String>,
    ) -> miette::Result<()> {
        for loaded in &decl.loads {
            if !visited.insert(loaded.clone()) {
                continue;
            }
            let loaded_decl = load_declaration(root, loaded)?;
            if let Some(lock) = LockFile::load(&pod_lock_path(root, loaded))? {
                let mut pins: Vec<String> = lock.snaps.keys().cloned().collect();
                pins.sort();
                if !pins.is_empty() {
                    miette::bail!(
                        "pod '{pod_name}' cannot load '{loaded}': it carries sideloaded \
                         package(s) ({}) — loading pods that carry blob-pinned packages \
                         is not supported yet (blob-copy across pods is deferred, \
                         issue #116)",
                        pins.join(", ")
                    );
                }
            }
            visit(root, pod_name, &loaded_decl, visited)?;
        }
        Ok(())
    }
    let mut visited = HashSet::new();
    visit(root, pod_name, decl, &mut visited)
}

/// Sibling pods whose load graph (transitively) reaches `pod_name`
/// (issue #135 loader-side brick): once this pod carries a blob pin,
/// [`refuse_loaded_blob_pins`] refuses every mutating verb of each of
/// them. Best-effort read-only scan — a pod without a declaration or
/// with an unreadable one is skipped; the warning must never fail the
/// add.
fn pods_loading(root: &Path, pod_name: &str) -> Vec<String> {
    fn reaches(root: &Path, from: &str, target: &str, seen: &mut HashSet<String>) -> bool {
        let Ok(decl) = load_declaration(root, from) else {
            return false;
        };
        for loaded in &decl.loads {
            if loaded == target
                || (seen.insert(loaded.clone()) && reaches(root, loaded, target, seen))
            {
                return true;
            }
        }
        false
    }
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == pod_name || !pod_lua_path(root, &name).is_file() {
            continue;
        }
        let mut seen = HashSet::new();
        if reaches(root, &name, pod_name, &mut seen) {
            out.push(name);
        }
    }
    out.sort();
    out
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

/// Resolve the pod's declared env (ADR-0030): own keys win per key over
/// loaded pods (silent — the issue #8 own-over-loaded rule); loaded
/// pods fold transitively, and a same-key collision between two loaded
/// pods resolves to the FIRST-DECLARED load with a warning (determinism
/// over surprise: adding a later load never silently steals an
/// existing key). Pure reads — safe before any mutation.
pub(crate) fn resolve_pod_env(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<BTreeMap<String, String>> {
    let folded = fold_pod_env(root, pod_name, decl, &mut Vec::new(), &mut HashSet::new())?;
    Ok(folded.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

/// The fold proper: key → (value, declaring pod). The provenance rides
/// along so a cross-load collision can name both pods in its warning;
/// `resolve_pod_env` strips it. Memoized + cycle-checked so it is safe
/// standalone, not only behind [`validate_loads`].
fn fold_pod_env(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
    stack: &mut Vec<String>,
    done: &mut HashSet<String>,
) -> miette::Result<BTreeMap<String, (String, String)>> {
    if let Some(pos) = stack.iter().position(|p| p == pod_name) {
        let mut cycle: Vec<String> = stack[pos..].to_vec();
        cycle.push(pod_name.to_string());
        miette::bail!("pod load cycle detected: {}", cycle.join(" -> "));
    }
    if !done.insert(pod_name.to_string()) {
        return Ok(BTreeMap::new());
    }
    stack.push(pod_name.to_string());
    let folded = (|| {
        let mut env: BTreeMap<String, (String, String)> = BTreeMap::new();
        for loaded in &decl.loads {
            let loaded_decl = load_declaration(root, loaded)?;
            for (key, contributed) in fold_pod_env(root, loaded, &loaded_decl, stack, done)? {
                match env.entry(key.clone()) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(contributed);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        crate::output::warn(format!(
                            "env '{key}' is declared by more than one loaded pod under \
                             '{pod_name}' — keeping the first-declared load's value"
                        ));
                    }
                }
            }
        }
        for (key, value) in &decl.env {
            env.insert(key.clone(), (value.clone(), pod_name.to_string()));
        }
        Ok(env)
    })();
    stack.pop();
    folded
}

/// What one loaded pod contributes to the loading pod's composition:
/// the package versions it currently executes (its active generation —
/// read-only) UNIONed with its declaration (issue #103), so a name the
/// pod declares that its generation does not carry (failed/partial
/// sync, degraded removal, a generation predating the declaration)
/// still reaches the loading pod. Generation content wins a name
/// clash with the declaration. Sub-loads fold in beneath (same
/// precedence rules one level down), so a chain resolves through this
/// one call.
struct LoadedContribution {
    /// The loaded pod's own overlay entries — applied when re-resolving
    /// its packages so the rebuilt payload carries the same build
    /// inputs the loaded pod itself used.
    overlay: BTreeMap<String, serde_json::Value>,
    /// Package name → executing version (None: resolve live).
    packages: BTreeMap<String, Option<String>>,
}

/// Fold a pod's DECLARATION alone: its own packages resolved live (the
/// pod's own overlay applied — the same inputs its first sync would
/// use) plus its sub-loads folded recursively beneath (own packages
/// win the name clash, issue #8). Acyclicity is guaranteed:
/// `validate_loads` ran before this read.
fn declared_contribution(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<BTreeMap<String, Option<String>>> {
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
    Ok(packages)
}

fn loaded_contribution(root: &Path, pod_name: &str) -> miette::Result<LoadedContribution> {
    let decl = load_declaration(root, pod_name)?;
    let store = pod_store(&pod_dir(root, pod_name));
    // Union (issue #103): what the pod EXECUTES (its active generation)
    // is the base and wins every name clash; its declaration folds in
    // beneath with `or_insert` so declaration-only names — resolved
    // live with the pod's own overlay, sub-loads recursive — are added
    // without ever displacing an executing version. Without the
    // generation the declaration alone is the whole story (it mirrors
    // the pod's own first sync).
    let packages = match store.active_generation()? {
        Some(active) => {
            let mut packages: BTreeMap<String, Option<String>> = active
                .packages
                .iter()
                .map(|(name, pkg)| (name.clone(), Some(pkg.version.clone())))
                .collect();
            for (name, version) in declared_contribution(root, pod_name, &decl)? {
                packages.entry(name).or_insert(version);
            }
            packages
        }
        None => declared_contribution(root, pod_name, &decl)?,
    };
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
    let lock = LockFile::load(&pod_lock_path(root, pod_name))?;
    for existing in &decl.packages {
        let parsed = parse_pod_package(existing)?;
        if parsed.name == spec.name {
            if lock
                .as_ref()
                .is_some_and(|l| l.snaps.contains_key(&spec.name))
            {
                // Blob pin (issue #135): the generic escape below is
                // false here — sync HOLDS a blob pin (no collection
                // recipe to rebuild); name the real escapes.
                miette::bail!(
                    "package '{}' is already in pod '{}' as a sideloaded blob \
                     pin — `shuttle pod sync` holds it at its pin (no collection \
                     recipe to rebuild); re-run `shuttle pod add --snap` to move \
                     the pin, or `shuttle pod remove '{}'` first",
                    spec.name,
                    pod_name,
                    spec.name
                );
            }
            miette::bail!(
                "package '{}' is already in pod '{}' (remove it first to change its \
                 constraint; `shuttle pod sync` rebuilds it at its pins)",
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
    // Service-name precheck (ADR-0032 Decision 3): same rules, same
    // zero-writes guarantee.
    precheck_service_collision(root, &decl, &spec.name, &meta, new_layer)?;

    let dir = pod_dir(root, pod_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let decl_path = pod_lua_path(root, pod_name);
    std::fs::write(&decl_path, render_pod_source(&decl))
        .map_err(|e| miette::miette!("failed to write {}: {e}", decl_path.display()))?;

    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);
    // Re-adding keeps an existing deps pin (ADR-0017): the closure content
    // did not change — the next sync re-verifies it as usual.
    let existing_deps = lock.packages.get(&spec.name).and_then(|e| e.deps.clone());
    lock.packages.insert(
        spec.name.clone(),
        PodPackageLockEntry {
            version: meta.version.clone(),
            constraint: spec.constraint.clone(),
            deps: existing_deps,
            recipe_sha256: None,
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

/// Report for `shuttle pod add --snap` (issue #116).
#[derive(Debug, Serialize)]
pub struct PodSnapAddReport {
    pub pod: String,
    /// Package name, taken from the payload's `meta/snap.yaml` — the
    /// sideloaded content is its own identity.
    pub name: String,
    /// Version from the payload's `meta/snap.yaml`.
    pub version: String,
    /// sha3-384 of the payload — the blob pin recorded in the pod
    /// lockfile's `snaps` section (revision 0 = sideload sentinel).
    pub sha3_384: String,
    /// True when the identical payload was already sideloaded and
    /// installed — nothing was written.
    pub noop: bool,
    /// The generation now current (absent for a no-op).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
}

/// The `meta/snap.yaml` version field of an unpacked payload (the
/// runtime's `MetaVersion` twin, kept local so the runtime's private
/// parse stays private).
#[derive(serde::Deserialize)]
struct PayloadIdentity {
    #[serde(default)]
    version: Option<String>,
}

/// Sideload a built `.snap` payload into a pod (issue #116): the
/// payload's `meta/snap.yaml` is its identity (name + version), its
/// sha3-384 is its pin. Records BOTH lockfile entries — `packages`
/// (version pin, existing tooling keeps working) and `snaps` (revision
/// 0, sha3-384) — then installs the payload through the store's normal
/// batch path (`install_batch`: sha3-384 re-verified fail-closed,
/// infrastructure types refused, `type: store` recorded inert) and
/// reconciles the rest of the pod around it.
///
/// Fail-closed gates, all BEFORE any write: `--ack-unsigned` (v1
/// sideloads carry no signature — snapd's `--dangerous` precedent),
/// filename↔meta identity, the trust gate, collision prechecks. A
/// re-add of the identical payload is a no-op (the blob hash is the
/// identity); divergent bytes — same version re-built or a new version
/// — move the pins and replace the member as a new generation (issue
/// #164 follow-up: recipe revisions no longer force `pod remove` →
/// re-add generation churn), all through the same gates; a payload
/// that also fails to unpack still refuses fail-closed naming the pin
/// mismatch.
pub fn add_snap_pod(
    root: &Path,
    pod_name: &str,
    payload: &Path,
    ack_unsigned: bool,
) -> miette::Result<PodSnapAddReport> {
    validate_pod_name(pod_name)?;
    // Trust gate first (zero writes): v1 sideloads are unsigned by
    // construction, so the acknowledgment is the only proof of intent.
    if !ack_unsigned {
        miette::bail!(
            "refusing to sideload '{}': the payload carries no shuttle \
             signature — pass --ack-unsigned to accept an unsigned payload",
            payload.display()
        );
    }
    if !payload.is_file() {
        miette::bail!("no such payload: {}", payload.display());
    }
    let sha3_384 = crate::store::sha3_384_file(payload)?;

    // Identity prechecks on the declared names avoid unpacking a
    // payload just to learn it is a re-add.
    let dir = pod_dir(root, pod_name);
    let decl = load_declaration_or_default(root, pod_name)?;
    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);
    // (filename, pinned sha3-384) when the filename names a package the
    // pod already blob-pins — the cheap re-add/divergence probe.
    let pinned_name = crate::oci::parse_artifact_filename(payload)
        .ok()
        .map(|(name, _, _)| name)
        .filter(|n| parse_pod_package_spec_names(&decl, n))
        .and_then(|n| lock.snaps.get(&n).map(|pin| (n, pin.sha3_384.clone())));
    if let Some((fname, pin_sha3_384)) = &pinned_name {
        if *pin_sha3_384 == sha3_384 {
            // The fast path honors the arch gate too (issue #150): a
            // re-add is still an add, and the filename's arch claim is
            // knowable before the report — refuse foreign-arch content
            // zero-write exactly like the post-unpack gate below.
            if let Ok((_, _, arch)) = crate::oci::parse_artifact_filename(payload) {
                refuse_foreign_arch(payload, arch.as_deref())?;
            }
            if let Some(mut report) = sideload_readd_report(root, pod_name, fname, &sha3_384)? {
                // Even a no-op re-add re-presents the pod: a previous
                // install whose follow-up sync FAILED (e.g. the
                // requires closure unresolved on a collection-less
                // machine) leaves farm/current/services stale while the
                // generation already carries the sha. sync is
                // idempotent here (present_active re-emits the farm and
                // services), so running it repairs the presentation and
                // keeps the "nothing to do" report true.
                let sync = match sync_pod(root, pod_name) {
                    Ok(sync) => sync,
                    Err(cause) => {
                        let generation = report
                            .generation
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "unknown".into());
                        return Err(sync_failure_wrap(
                            &report.name,
                            &report.version,
                            &generation,
                            cause,
                        ));
                    }
                };
                report.generation = sync.generation.or(report.generation);
                return Ok(report);
            }
            // Content missing from the generation: fall through to a
            // repair-install.
        }
        // Divergent bytes under a pinned name: fall through to the
        // full gated install — a replacement, same version or not. A
        // payload that ALSO fails to unpack refuses fail-closed below.
    }

    // Unpack once for identity + the trust gate (install re-unpacks and
    // re-verifies sha3-384 fail-closed on its own).
    let tools = pod_runtime_tools();
    let unsquashfs = tools.unsquashfs.as_ref().ok_or_else(|| {
        miette::miette!(
            "unsquashfs not found on PATH — sideloading cannot unpack \
             payloads; install squashfs-tools"
        )
    })?;
    let (meta, version) = match unpack_payload_identity(payload, unsquashfs) {
        Ok(found) => found,
        Err(e) => {
            if let Some((fname, pin_sha3_384)) = &pinned_name {
                if *pin_sha3_384 != sha3_384 {
                    miette::bail!(
                        "'{fname}': sideloaded payload sha3-384 {sha3_384} does not \
                         match the pod's blob pin ({pin_sha3_384}) — refusing \
                         (fail-closed); the payload also failed to unpack: {e}"
                    );
                }
            }
            return Err(e);
        }
    };
    let name = meta.name.clone().ok_or_else(|| {
        miette::miette!(
            "{}: meta/snap.yaml carries no name — refusing to sideload an \
             unidentified payload",
            payload.display()
        )
    })?;
    let version = version.unwrap_or_else(|| "0".into());

    // Filename↔meta identity (the `pending_from_blob` rule, copied):
    // the artifact filename is a claim about the payload; a mismatch
    // refuses fail-closed.
    if let Ok((fname, fversion, arch)) = crate::oci::parse_artifact_filename(payload) {
        if fname != name {
            miette::bail!(
                "{}: filename says '{fname}' but meta/snap.yaml says '{name}' — \
                 refusing to sideload (fail-closed)",
                payload.display()
            );
        }
        if fversion != version {
            miette::bail!(
                "{}: filename says version {fversion} but meta/snap.yaml says \
                 {version} — refusing to sideload (fail-closed)",
                payload.display()
            );
        }
        // Architecture gate (issue #133): the filename arch is a claim
        // about the payload; a mismatch with the host refuses before any
        // write — a foreign blob would install clean and fail only at
        // exec. `all` is the build default (resolve_archs) and makes no
        // host claim, like a filename without an arch component.
        refuse_foreign_arch(payload, arch.as_deref())?;
    }

    // Trust gate (the `prepare_snap` classification, evaluated before
    // any write so a refusal leaves zero state). The store-type notice
    // is deferred below the pre-flights (issue #150 — same ordering
    // rule as the conversion warning: a refusal emits no reassurance).
    let mut store_records_only = false;
    match crate::units::classify(meta.snap_type.as_deref()) {
        crate::units::RuntimeClass::Infrastructure => miette::bail!(
            "snap '{name}' is snapd infrastructure (type={:?}) — refusing to \
             sideload via the package axis",
            meta.snap_type
        ),
        crate::units::RuntimeClass::Store => store_records_only = true,
        crate::units::RuntimeClass::ShootBuilt => {}
    }

    // Re-add bookkeeping: identical content is a no-op (checked above
    // when the filename allowed the cheap path); divergent bytes — the
    // same version re-built or a version move — move the pins below,
    // and install_batch replaces the member as a new generation
    // (content-hash identity, issue #164 follow-up). Every gate above
    // and inside the install re-ran first (--ack-unsigned, trust
    // classification, identity, collisions, requires closure).
    let declared = parse_pod_package_spec_names(&decl, &name);
    if declared {
        // Constraint consistency (issue #135): a declared spec with an
        // `@constraint` must not gain a pin whose version violates it —
        // the lockfile would contradict itself (the blob branch never
        // evaluates constraints downstream). Refuse before any write.
        if let Some(constraint) = decl
            .packages
            .iter()
            .find_map(|s| parse_pod_package(s).ok().filter(|p| p.name == name))
            .and_then(|p| p.constraint)
        {
            if !version_matches_constraint(&version, &constraint) {
                miette::bail!(
                    "'{name}': sideloaded version {version} violates the declared \
                     constraint '@{constraint}' — refusing to record a pin that \
                     contradicts its own constraint; widen the constraint in the \
                     pod declaration, or `shuttle pod remove {name}` first"
                );
            }
        }
    }
    // The same zero-writes validation chain as `add_package` (issue
    // #8), with claims read from the payload — on EVERY identity path:
    // a payload naming a declared COLLECTION package converts it to a
    // blob pin (trust-model flip collection → unsigned content), so
    // its composition prechecks must refuse before any write too, not
    // just a new package's.
    validate_loads(root, pod_name, &decl)?;
    validate_overlays(root, &decl, pod_name)?;
    let layer = payload_layer(&decl, &name);
    // Sibling resolution sees the pod's OWN pins/blobs first (issue
    // #147): a collection-less pod accumulates sideloaded payloads, so
    // a declared sibling that is pinned and carried here must resolve
    // from its installed record, not through the collection.
    let store = pod_store(&dir);
    let active = store.active_generation()?;
    let pins = PodPins {
        lock: &lock,
        active: active.as_ref(),
    };
    precheck_payload_collisions(root, &decl, &name, &meta, layer, &pins)?;
    // Zero-write requires pre-flight (issue #132): a payload whose
    // meta/snap.yaml carries `requires` would go ACTIVE first and only
    // fail the follow-up sync's closure resolution on this machine —
    // a partial generation with no rollback. Refuse before any write —
    // and before the conversion warning below, so a refusal emits no
    // "converted" claim.
    preflight_requires_closure(&meta, &name, &version)?;
    if store_records_only {
        crate::output::warn(format!(
            "{name}: type=store — records only, nothing executable (store snaps \
             keep their own runtime)"
        ));
    }
    if declared && !lock.snaps.contains_key(&name) {
        // The conversion is allowed but loud: the collection recipe
        // stops governing this package's content — the payload (an
        // acknowledged-unsigned blob) does.
        crate::output::warn(format!(
            "{name}: declared collection package converted to a sideloaded blob \
             pin — its content is now the payload (unsigned, --ack-unsigned), \
             no longer the collection recipe"
        ));
    }

    // Loader-side brick warning (issue #135): a sideload into a pod
    // that OTHER pods load bricks those pods' mutating verbs —
    // `refuse_loaded_blob_pins` walks only the loading pod's own graph
    // and refuses once the loaded pod carries a pin. The sideload
    // itself is legitimate, so this warns (naming the loaders and the
    // escape) instead of refusing.
    for loader in pods_loading(root, pod_name) {
        crate::output::warn(format!(
            "pod '{pod_name}' is loaded by pod '{loader}' — this sideload makes \
             '{loader}' refuse its mutating verbs (loading pods that carry blob \
             pins is unsupported, issue #116); `shuttle pod remove` the pin from \
             '{pod_name}' to restore it"
        ));
    }

    // Writes: declaration (new packages only) + both lockfile pins.
    let mut decl = decl;
    if !declared {
        decl.packages.push(name.clone());
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let decl_path = pod_lua_path(root, pod_name);
    std::fs::write(&decl_path, render_pod_source(&decl))
        .map_err(|e| miette::miette!("failed to write {}: {e}", decl_path.display()))?;

    let constraint = decl
        .packages
        .iter()
        .find_map(|spec| {
            parse_pod_package(spec)
                .ok()
                .filter(|p| p.name == name)
                .map(|p| p.constraint)
        })
        .unwrap_or(None);
    lock.packages.insert(
        name.clone(),
        PodPackageLockEntry {
            version: version.clone(),
            constraint,
            deps: lock.packages.get(&name).and_then(|e| e.deps.clone()),
            // A sideload is a blob pin (issue #116): no collection
            // recipe closure to hash — the payload is the identity.
            recipe_sha256: None,
        },
    );
    lock.snaps.insert(
        name.clone(),
        crate::lock::SnapLockEntry {
            revision: 0,
            sha3_384: sha3_384.clone(),
        },
    );
    lock.save(&lock_path)?;

    // Install the payload through the store's normal batch path: it
    // re-verifies sha3-384 fail-closed, refuses infrastructure types,
    // records `type: store` inert, and emits the loud unsigned note.
    let pending = crate::runtime::PendingSnap {
        name: name.clone(),
        revision: 0,
        sha3_384: sha3_384.clone(),
        payload_path: payload.to_path_buf(),
        layer: payload_layer(&decl, &name),
        meta_digest: None,
    };
    let install = store.install_batch(&[pending], &Default::default(), &tools)?;
    for note in &install.notes {
        crate::output::info(note.clone());
    }

    // Reconcile the rest of the pod around the installed content: the
    // blob pin holds it in place (no rebuild), the farm, services, and
    // the requires closure follow. A sync failure cannot roll back —
    // `sync_failure_wrap` names the residual and the recovery verbs.
    let generation = install
        .generation
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unknown".into());
    let sync = match sync_pod(root, pod_name) {
        Ok(sync) => sync,
        Err(cause) => return Err(sync_failure_wrap(&name, &version, &generation, cause)),
    };

    Ok(PodSnapAddReport {
        pod: pod_name.to_string(),
        name,
        version,
        sha3_384,
        noop: false,
        generation: sync.generation.or(install.generation),
    })
}

/// Zero-write requires pre-flight for a sideload (issue #132): resolve
/// the payload's `requires` closure BEFORE any declaration, pin, or
/// generation write. The seeds mirror the follow-up sync exactly: sync
/// resolves the FULL requires list ([`install_requires_closure`])
/// before its per-member skips, so a member carried by the active
/// generation still fails sync when it has no resolvable recipe — the
/// pre-flight resolves the same full list through the same call. An
/// unresolvable member bails naming the fix; a refusal here leaves
/// zero state to roll back.
fn preflight_requires_closure(
    meta: &crate::units::PayloadSnap,
    name: &str,
    version: &str,
) -> miette::Result<()> {
    let seeds: Vec<String> = meta
        .requires
        .iter()
        .filter(|r| !r.is_empty())
        .cloned()
        .collect();
    if let Err(e) = crate::deps::resolve_dep_names(&seeds, true) {
        miette::bail!(
            "refusing to sideload '{name}' ({version}): its `requires` closure \
             does not resolve here ({e}) — provide the collection, or sideload \
             from a collection-bearing machine; nothing was written"
        );
    }
    Ok(())
}

/// The shared sync-failure wrap (issue #132, ADR-0037): the payload is
/// already ACTIVE on the generation the install flipped to, so a failed
/// reconcile cannot roll back. The accepted residual is a declared
/// partial generation — no restore is attempted; the error names the
/// cause and both recovery verbs.
fn sync_failure_wrap(
    name: &str,
    version: &str,
    generation: &str,
    cause: miette::Report,
) -> miette::Error {
    miette::miette!(
        "sideloaded '{name}' ('{version}') is ACTIVE on generation \
         {generation} with its `requires` closure incomplete ({cause}): \
         libraries missing, farm/services not re-presented — provide the \
         collection and run `shuttle pod sync` to complete, or `shuttle \
         pod remove {name}` to abandon"
    )
}

/// The identical-readd check that needs no unpack: `Some(report)` when
/// the active generation carries the pinned content (nothing to do),
/// `None` when the pin's content is missing from the generation — the
/// caller falls through to a repair-install.
fn sideload_readd_report(
    root: &Path,
    pod_name: &str,
    name: &str,
    sha3_384: &str,
) -> miette::Result<Option<PodSnapAddReport>> {
    let dir = pod_dir(root, pod_name);
    let store = pod_store(&dir);
    let active = store.active_generation()?;
    let installed = active.as_ref().and_then(|g| g.packages.get(name));
    if installed.is_some_and(|p| p.sha3_384 == sha3_384) {
        return Ok(Some(PodSnapAddReport {
            pod: pod_name.to_string(),
            name: name.to_string(),
            version: installed.map(|p| p.version.clone()).unwrap_or_default(),
            sha3_384: sha3_384.to_string(),
            noop: true,
            generation: active.map(|g| g.n),
        }));
    }
    Ok(None)
}

/// True when any declared package spec names `name` (no constraint
/// comparison — a sideload's identity is the payload, not a spec).
fn parse_pod_package_spec_names(decl: &PodDeclaration, name: &str) -> bool {
    decl.packages
        .iter()
        .any(|spec| parse_pod_package(spec).is_ok_and(|p| p.name == name))
}

/// The composition layer a sideloaded payload records at: `Overlay`
/// when the pod already patches the package, `Own` otherwise (issue #8
/// layering, same rule as `add_package`).
fn payload_layer(decl: &PodDeclaration, name: &str) -> crate::farm::ClaimLayer {
    if decl.overlay.contains_key(name) {
        crate::farm::ClaimLayer::Overlay
    } else {
        crate::farm::ClaimLayer::Own
    }
}

/// Unpack a payload with unsquashfs and read its `meta/snap.yaml`
/// identity: the runtime-planner shape plus the version field. The
/// [`crate::runtime::RuntimeStore`] twin (`unpack_payload`) stays
/// private to the install path; the sideload gate needs the same read
/// BEFORE any write.
fn unpack_payload_identity(
    payload: &Path,
    unsquashfs: &Path,
) -> miette::Result<(crate::units::PayloadSnap, Option<String>)> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let extract = work.path().join("extract");
    let status = std::process::Command::new(unsquashfs)
        .args([
            "-d",
            &extract.to_string_lossy(),
            "-no-xattrs",
            &payload.to_string_lossy(),
        ])
        .status()
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if !status.success() {
        miette::bail!(
            "unsquashfs failed to extract payload {} — not a readable \
             squashfs payload",
            payload.display()
        );
    }
    let yaml_path = extract.join("meta").join("snap.yaml");
    let yaml_text = std::fs::read_to_string(&yaml_path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "reading {} (no meta/snap.yaml — not a shuttle-built payload)",
                yaml_path.display()
            )
        })?;
    let meta: crate::units::PayloadSnap = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml parse for '{}': {e}", payload.display()))?;
    let identity: PayloadIdentity = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml version parse: {e}"))?;
    Ok((meta, identity.version))
}

/// The pod's own pins for sideload sibling resolution (issue #147):
/// the lockfile `snaps` blob pins plus the active generation's
/// installed records. A declared sibling both pinned and carried here
/// resolves from its installed record — the pod store's carried
/// payloads — BEFORE the collection is consulted, so a collection-less
/// pod can accumulate sideloaded payloads.
struct PodPins<'a> {
    lock: &'a LockFile,
    active: Option<&'a crate::runtime::Generation>,
}

impl PodPins<'_> {
    /// The installed record of a declared sibling the pod pins AND
    /// carries — the #135/#151 blob-pin lookup shape (`hold_blob_pinned`):
    /// the lockfile pin's sha3-384 must match the generation's content.
    /// `None` leaves the sibling to the collection fallback.
    fn carried(&self, name: &str) -> Option<&crate::runtime::InstalledPackage> {
        let pin = self.lock.snaps.get(name)?;
        let pkg = self.active?.packages.get(name)?;
        (pkg.sha3_384 == pin.sha3_384).then_some(pkg)
    }
}

/// Architecture gate (issue #133): the filename arch is a claim about
/// the payload; a mismatch with the host refuses before any write — a
/// foreign blob would install clean and fail only at exec. `all` is the
/// build default (resolve_archs) and makes no host claim, like a
/// filename without an arch component. Shared by every identity path
/// that carries a filename arch claim (issue #150), including the
/// identical-content re-add fast path.
fn refuse_foreign_arch(payload: &Path, arch: Option<&str>) -> miette::Result<()> {
    if let Some(arch) = arch {
        let host = crate::snap::host_arch();
        if arch != host && arch != "all" {
            miette::bail!(
                "{}: filename says arch {arch} but this host is {host} — \
                 refusing to sideload a foreign-architecture payload (it \
                 would install and fail only at exec); sideload a {host} \
                 payload",
                payload.display()
            );
        }
    }
    Ok(())
}

/// Pre-write collision checks for a sideloaded payload (issue #8 +
/// ADR-0032 Decision 3): binary and service claims read from the
/// payload's `meta/snap.yaml` against the pod's post-state package set,
/// resolved by the shared classifiers. Same guarantees as
/// `add_package`'s prechecks — a same-precedence clash fails with zero
/// writes. Declared siblings resolve through `pins` (the pod's own
/// pins/blobs, issue #147) first, falling back to the collection.
fn precheck_payload_collisions(
    root: &Path,
    decl: &PodDeclaration,
    name: &str,
    payload: &crate::units::PayloadSnap,
    layer: crate::farm::ClaimLayer,
    pins: &PodPins<'_>,
) -> miette::Result<()> {
    // Farm-link bare names (issue #150): the payload's app and service
    // names are `join`ed under the farm dir at emit — validate them with
    // the farm's own seam check so a `..` component or absolute path
    // refuses zero-write here, like every other precheck, instead of
    // surfacing at farm emit (post-install).
    for app in payload.apps.keys() {
        crate::farm::check_farm_link_name("app", app, name)?;
    }
    for service in payload.services.keys() {
        crate::farm::check_farm_link_name("service binary", service, name)?;
    }
    let mut binary_claims: Vec<BinaryClaim> = payload
        .apps
        .keys()
        .map(|app| BinaryClaim {
            binary: app.clone(),
            pkg: name.to_string(),
            layer,
        })
        .collect();
    push_declared_binary_claims(&mut binary_claims, decl, name, Some(pins))?;
    push_loaded_binary_claims(&mut binary_claims, root, decl, name)?;
    resolve_binary_claims(&binary_claims)?;

    let mut service_claims: Vec<ServiceClaim> = payload
        .services
        .keys()
        .map(|service| ServiceClaim {
            service: service.clone(),
            pkg: name.to_string(),
            layer,
        })
        .collect();
    push_declared_service_claims(&mut service_claims, decl, name, Some(pins))?;
    push_loaded_service_claims(&mut service_claims, root, decl, name)?;
    resolve_service_claims(&service_claims)
}

/// Remove a package from a pod: drop it from the declaration and delete
/// its lockfile pin, then reconcile — the store generation without it
/// and a farm that no longer exposes its binaries (issue #3). Loads are
/// validated before any write (issue #8). Works without the squashfs
/// pair (issue #16): the degraded reconcile records the remaining
/// declared set without building, so only the dropped package (plus
/// genuinely undeclared strays) leaves the store.
/// Drop `pod {}` service overrides no remaining declared package
/// provides: a dangling override hard-errors the next reconcile
/// ("no package declares service") with the removal already half-done —
/// the declaration must stay self-consistent. A package that fails to
/// load skips the whole prune (never destroy user config on a transient
/// read error); validation still runs at reconcile.
fn prune_dangling_service_overrides(decl: &mut PodDeclaration) {
    if decl.services.is_empty() {
        return;
    }
    let mut remaining: std::collections::BTreeSet<String> = Default::default();
    for spec_str in &decl.packages {
        let Ok(spec) = parse_pod_package(spec_str) else {
            continue;
        };
        match crate::deps::load_meta(&spec.name) {
            Ok(meta) => remaining.extend(meta.services.into_keys()),
            Err(_) => {
                crate::output::warn(
                    "could not verify remaining packages; service overrides left untouched",
                );
                return;
            }
        }
    }
    let dangling: Vec<String> = decl
        .services
        .keys()
        .filter(|k| !remaining.contains(*k))
        .cloned()
        .collect();
    for key in &dangling {
        decl.services.remove(key);
        crate::output::warn(format!(
            "service override '{key}' dropped — no remaining declared package provides it"
        ));
    }
}

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
    prune_dangling_service_overrides(&mut decl);

    let decl_path = pod_lua_path(root, pod_name);
    std::fs::write(&decl_path, render_pod_source(&decl))
        .map_err(|e| miette::miette!("failed to write {}: {e}", decl_path.display()))?;

    let lock_path = pod_lock_path(root, pod_name);
    if let Some(mut lock) = LockFile::load(&lock_path)? {
        lock.packages.remove(&spec.name);
        // A sideloaded package's blob pin goes with it (issue #116): a
        // stale `snaps` entry would hold a future re-add of the same
        // name from the collection at phantom content.
        lock.snaps.remove(&spec.name);
        lock.save(&lock_path)?;
    }

    // Degraded-safe (issue #16): removals never unpack, so the
    // reconcile proceeds without the squashfs pair — and its declared
    // set is recorded WITHOUT building, so only the dropped package
    // (plus genuinely undeclared strays) is removed.
    let (sync, _) = reconcile_pod_scoped(root, pod_name, None, false, true, &pod_runtime_tools())?;
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

/// Rebuild ONE declared package at its pins (issue #15): the version
/// pin and the dependency-closure pin stay put — the cached closure is
/// reused with zero fetches (unlike the remove+add workaround, which
/// drops the deps pin and re-fetches the whole closure) — and the sync
/// hold check is bypassed for this one package, so a package HELD at
/// its pin is rebuilt at ITS version, not the collection candidate.
/// `--latest` re-resolves the dependency closure instead (`deps fetch
/// --latest` semantics), deliberately moving the pin (ADR-0017
/// Decision 5).
///
/// Zero writes when the package is not declared in the pod.
pub fn rebuild_package(
    root: &Path,
    pod_name: &str,
    spec_str: &str,
    latest: bool,
) -> miette::Result<PodRebuildReport> {
    validate_pod_name(pod_name)?;
    let spec = parse_pod_package(spec_str)?;
    let decl = load_declaration(root, pod_name)?;
    let declared = decl
        .packages
        .iter()
        .any(|existing| parse_pod_package(existing).is_ok_and(|p| p.name == spec.name));
    if !declared {
        miette::bail!("package '{}' is not in pod '{}'", spec.name, pod_name);
    }

    let (sync, deps_pin_moved) = reconcile_pod_scoped(
        root,
        pod_name,
        Some(&spec.name),
        latest,
        false,
        &pod_runtime_tools(),
    )?;

    // The version the package now executes: its (kept or freshly
    // repinned) lockfile pin, else a live resolution. The deps pin
    // beside it names the moved closure (ADR-0017 Decision 5: the
    // lockfile IS the pin record).
    let lock = LockFile::load(&pod_lock_path(root, pod_name))?.unwrap_or_else(LockFile::empty);
    let entry = lock.packages.get(&spec.name);
    let version = entry
        .map(|e| e.version.as_str())
        .filter(|v| !v.is_empty())
        .map_or_else(
            || {
                crate::deps::load_meta(&spec.name)
                    .map(|m| m.version)
                    .unwrap_or_default()
            },
            str::to_string,
        );
    if deps_pin_moved {
        if let Some(deps) = entry.and_then(|e| e.deps.as_ref()) {
            crate::output::ok(format!(
                "moved dependency closure for '{}': {:.12}… (recorded in shuttle.lock)",
                spec.name, deps.deps_hash
            ));
        }
    }
    // A blob-pinned package cannot rebuild (the payload is its
    // content): the reconcile HELD it — surface that instead of letting
    // the "rebuilt" line claim a build happened (council round 2).
    let held = sync.held.contains(&spec.name);

    Ok(PodRebuildReport {
        pod: pod_name.to_string(),
        name: spec.name,
        version,
        held,
        deps_pin_moved,
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
    /// Sideloaded (blob-pinned) packages: never float and never
    /// re-resolve from the collection (issue #116) — a version move is
    /// a re-add with a new `--snap`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
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
    let mut skipped = Vec::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        if let Some(wanted) = &wanted {
            if !wanted.contains(&spec.name) {
                continue;
            }
        }
        // Blob pins never float and never re-resolve from the
        // collection (issue #116, Decision 6): the payload IS the
        // version — `update` reports the skip; a move is a re-add.
        if lock.snaps.contains_key(&spec.name) {
            skipped.push(spec.name);
            continue;
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
                // A version move never invalidates the deps pin
                // (ADR-0017): the closure is pinned by its own content
                // hash; sync re-verifies it against the new source.
                let deps = lock.packages.get(&name).and_then(|e| e.deps.clone());
                lock.packages.insert(
                    name.clone(),
                    PodPackageLockEntry {
                        version: to.clone(),
                        constraint,
                        deps,
                        recipe_sha256: None,
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
        skipped,
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
    /// The service reconcile tail (ADR-0032 Decision 8): the flip
    /// itself restarted changed services — no follow-up sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<crate::services::ServiceReconcileReport>,
    /// Blob pins the generation rolled back TO does not carry (issue
    /// #135): every mutating verb fails named (hold_blob_pinned) until
    /// each is re-added — the report names them so the recovery path
    /// is known at rollback time, not discovered at the next verb.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blob_pins_without_content: Vec<String>,
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
    rollback_pod_with(root, pod_name, target, &pod_runtime_tools())
}

/// [`rollback_pod`] with injected runtime tools — the seam the pod tests
/// use to prove activation runs without touching the host system bus.
pub fn rollback_pod_with(
    root: &Path,
    pod_name: &str,
    target: Option<u64>,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<PodRollbackReport> {
    validate_pod_name(pod_name)?;
    let dir = pod_dir(root, pod_name);
    let store = pod_store(&dir);
    let report = store.rollback(target, tools)?;

    // The farm + `current` follow the flipped generation. Re-emitting
    // is idempotent and heals a farm that predates a lost emit.
    let gen = store.active_generation()?.ok_or_else(|| {
        miette::miette!("rollback left pod '{pod_name}' with no active generation")
    })?;
    let farm = crate::farm::emit(&store, &gen)?;
    crate::farm::flip_current(&dir, gen.n)?;
    // The reconcile tail rides the flip itself (ADR-0032 Decision 8,
    // ticket #107): the hash covers the owning package's digest, so a
    // binary-only upgrade across the flip restarts the service HERE —
    // no follow-up sync (§5.4's restart caveat, resolved).
    let services = crate::services::reconcile(&store, &dir, pod_name, tools)?;

    // The rollback trap (issue #135): the target generation may predate
    // a blob pin — the pin's content is gone from the active generation,
    // so every mutating verb now fails named. Name the stranded pins in
    // the report instead of letting the next verb surprise.
    let mut blob_pins_without_content = Vec::new();
    if let Some(lock) = LockFile::load(&pod_lock_path(root, pod_name))? {
        for (name, pin) in &lock.snaps {
            let carried = gen
                .packages
                .get(name)
                .is_some_and(|p| p.sha3_384 == pin.sha3_384);
            if !carried {
                blob_pins_without_content.push(name.clone());
            }
        }
    }
    blob_pins_without_content.sort();

    Ok(PodRollbackReport {
        pod: pod_name.to_string(),
        from: report.from,
        to: report.to,
        farm: Some(farm),
        services: Some(services),
        blob_pins_without_content,
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
    /// The service reconcile tail (ADR-0032 Decision 8): what the
    /// systemd user registrations switched to on this reconcile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<crate::services::ServiceReconcileReport>,
}

/// The runtime store of one pod: the shared runtime store module
/// pointed at the pod's state directory (issue #3 seam — no forked
/// store). The sysext presentation links are kept INSIDE the pod dir so
/// a per-user pod never writes to the system extensions directory.
pub fn pod_store(pod_dir: &Path) -> crate::runtime::RuntimeStore {
    crate::runtime::RuntimeStore::new(pod_dir.to_path_buf())
        .with_extensions_link_dir(pod_dir.join("extensions"))
}

/// The runtime store of the pod a `--pod` param selects against the
/// resolved [`pod_root`] (the peer/static pull's staging target,
/// ADR-0033 Decision 5; shared with `serve --pod` via
/// [`resolve_pod_dir`]).
pub fn resolve_pod_store(pod: Option<&str>) -> miette::Result<crate::runtime::RuntimeStore> {
    let (_, dir) = resolve_pod_dir(pod)?;
    Ok(pod_store(&dir))
}

/// Runtime tools for the pod paths. Default: the host binaries with the
/// system-bus set suppressed when the host has no systemd or
/// `SHUTTLE_SYSTEMD` opts out (see [`RuntimeTools::for_pod_runtime`]).
///
/// `SHUTTLE_POD_TOOLS=absent` is a test-only seam (issue #66): it
/// resolves every tool to `None`, so `pod sync`/`pod rollback` reach
/// activation with no external tool at all and cannot touch the host
/// system bus. Production never sets it.
fn pod_runtime_tools() -> crate::runtime::RuntimeTools {
    match std::env::var("SHUTTLE_POD_TOOLS").as_deref() {
        Ok("absent") => crate::runtime::RuntimeTools::default(),
        _ => crate::runtime::RuntimeTools::for_pod_runtime(),
    }
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
    reconcile_pod_scoped(root, pod_name, None, false, false, &pod_runtime_tools())
        .map(|(report, _)| report)
}

/// What the scoped reconcile does with one own package before the
/// build (issue #15).
#[derive(Debug)]
enum OwnScope {
    /// Plain-sync hold: recorded + claims contributed, stores nothing.
    Held,
    /// Off-scope rebuild skip: claims contributed, stores nothing.
    SkipInstalled,
    /// Build, with the meta possibly pinned back to the version pin.
    Build,
}

/// Claims for a package that keeps its installed store content (the
/// hold path, and the scoped rebuild's off-scope skip, issue #15): the
/// generation must still present the package's desktop IDs and
/// binaries, so they are claimed from the INSTALLED package record
/// rather than from a freshly resolved meta.
fn hold_style_skip_claims(
    desktop_claims: &mut Vec<DesktopClaim>,
    binary_claims: &mut Vec<BinaryClaim>,
    service_claims: &mut Vec<ServiceClaim>,
    installed_pkg: &crate::runtime::InstalledPackage,
    meta: &crate::snap::SnapMeta,
) {
    push_desktop_claims(desktop_claims, installed_pkg, crate::farm::ClaimLayer::Own);
    push_installed_binary_claims(binary_claims, installed_pkg, crate::farm::ClaimLayer::Own);
    // Services have no installed-record entry yet (the manifest record is
    // ticket #106), so a held pin claims them from the freshly resolved
    // meta — the pin's content only differs when the pin MOVES, and a
    // move rebuilds.
    push_meta_service_claims(service_claims, meta, crate::farm::ClaimLayer::Own);
}

/// True when a freshly resolved own package would be HELD at its
/// lockfile pin (issue #5): the pin disagrees with the collection
/// candidate AND the active generation already carries the pinned
/// version — the pin plus the installed content win over collection
/// drift.
fn held_at_pin(
    lock: &LockFile,
    name: &str,
    meta_version: &str,
    active: Option<&crate::runtime::Generation>,
) -> bool {
    let Some(pin) = lock.packages.get(name) else {
        return false;
    };
    pin.version != meta_version
        && active.is_some_and(|g| {
            g.packages
                .get(name)
                .is_some_and(|p| p.version == pin.version)
        })
}

/// True when a freshly resolved own package's recipe digests identically
/// to the installed record's build inputs (issue #113): the installed
/// store content was built from THIS recipe, so a plain sync can hold.
/// `None` on the installed side never matches — pre-#113 manifests
/// rebuild once, record their digest, and hold from then on. Floating
/// packages never hold: float mode follows upstream content drift at a
/// constant recipe (ADR-0017) — its sync re-resolves the closure and
/// repins, which a hold would silently skip.
fn held_at_content(
    active: Option<&crate::runtime::Generation>,
    meta: &crate::snap::SnapMeta,
) -> bool {
    if meta.floating {
        return false;
    }
    let digest = meta.build_input_digest();
    active
        .and_then(|g| g.packages.get(&meta.name))
        .and_then(|p| p.meta_digest.as_deref())
        .is_some_and(|d| d == digest)
}

/// The plain-sync hold body: record the hold (issue #5, issue #113) and
/// contribute the installed record's claims so the generation still
/// presents the package's desktop IDs and binaries.
fn hold_plain_sync(
    ctx: &ReconcileCtx<'_>,
    meta: &crate::snap::SnapMeta,
    build: &mut ReconcileBuild,
) -> OwnScope {
    build.held.push(meta.name.clone());
    if let Some(installed_pkg) = ctx.active.and_then(|g| g.packages.get(&meta.name)) {
        hold_style_skip_claims(
            &mut build.desktop_claims,
            &mut build.binary_claims,
            &mut build.service_claims,
            installed_pkg,
            meta,
        );
    }
    OwnScope::Held
}

/// Verify the recorded deps-closure blob of a content-held package
/// (issue #125): the hold skips the build that would otherwise hash the
/// blob (issue #113), so a corrupted or missing store entry would ride
/// along silently — the held sync instead fails loud, fail-closed like
/// [`crate::dep_fetch::materialize_deps_entry`]. One stat + one
/// streaming hash of the already-local blob; no fetch, no unpack, no
/// auto-heal. Packages without a recorded deps pin (no `deps`
/// declaration, store/pull installs) skip cleanly: nothing to verify.
fn verify_held_deps_blob(ctx: &ReconcileCtx<'_>, name: &str) -> miette::Result<()> {
    let Some(hash) = ctx
        .lock
        .packages
        .get(name)
        .and_then(|e| e.deps.as_ref())
        .map(|d| d.deps_hash.as_str())
    else {
        return Ok(());
    };
    let blob = ctx.store.blob_path(hash);
    if !blob.exists() {
        miette::bail!(
            "held package '{name}': dependency closure {hash:.12}… is missing from the pod \
             store — the held sync refuses to proceed; run `shuttle deps fetch` to fetch it"
        );
    }
    let actual = crate::dep_fetch::sha256_file(&blob)?;
    if actual != hash {
        miette::bail!(
            "held package '{name}': dependency closure hash mismatch: expected {hash}, \
             found {actual} — the store entry is corrupted or tampered with; the held \
             sync refuses to proceed"
        );
    }
    Ok(())
}

/// The blob-pin hold body (issue #116): a sideloaded package keeps its
/// installed store content on every reconcile — there is no collection
/// recipe to rebuild from, the sha3-384 pin is the content. Claims come
/// from the installed record so the generation still presents the
/// package's desktop IDs, binaries, and services; its runtime `requires`
/// seeds the closure so the libraries it needs stay carried. A pin whose
/// content the active generation does NOT carry fails named (the
/// repair path is a re-add: `shuttle pod add --snap`).
fn hold_blob_pinned(
    ctx: &ReconcileCtx<'_>,
    name: &str,
    pin_sha3_384: &str,
    layer: crate::farm::ClaimLayer,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    let Some(installed_pkg) = ctx.active.and_then(|g| g.packages.get(name)) else {
        miette::bail!(
            "package '{name}' is blob-pinned (sideloaded) but the pod's active \
             generation does not carry its pinned content — re-run \
             `shuttle pod --name {} add --snap` to reinstall it",
            ctx.pod_name
        );
    };
    if installed_pkg.sha3_384 != pin_sha3_384 {
        miette::bail!(
            "package '{name}' is blob-pinned (sha3-384 {pin_sha3_384}) but the \
             active generation carries different content ({}) — re-run \
             `shuttle pod --name {} add --snap` to realign it",
            installed_pkg.sha3_384,
            ctx.pod_name
        );
    }
    build.declared_names.insert(name.to_string());
    build.held.push(name.to_string());
    build
        .requires_seeds
        .extend(installed_pkg.requires.iter().cloned());
    push_desktop_claims(&mut build.desktop_claims, installed_pkg, layer);
    push_installed_binary_claims(&mut build.binary_claims, installed_pkg, layer);
    push_installed_service_claims(&mut build.service_claims, installed_pkg, layer);
    Ok(())
}

/// Detect recipe-closure drift for one declared package (issue #142):
/// hash the canonical list of `(member_name, recipe_file_bytes)` over
/// the package's recipe-resolved `requires` closure and compare it with
/// the lockfile pin.
///
/// - Entry with an equal hash → today's behavior.
/// - Entry without a hash (pre-#142 lockfile) → the digest is stamped
///   silently, NO rebuild — existing pods must not mass-rebuild.
/// - No entry (new pin) → today's behavior; the pin is stamped when
///   written.
/// - Entry with a differing hash → drift: the package joins the
///   rebuilt set EVEN at an unchanged version, its recipe-resolved
///   (non-blob-pinned) closure members join the member-rebuild set, and
///   the drift is named on the output.
///
/// Members holding a blob pin (issue #116 sideloads) are excluded from
/// the digest: their recipes live in the collection but the pod holds
/// the blob — their drift must not force a rebuild.
fn detect_recipe_drift(
    ctx: &ReconcileCtx<'_>,
    spec: &PodPackageSpec,
    meta: &crate::snap::SnapMeta,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    let members = crate::deps::resolve_dep_names(&meta.requires, true)?;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for name in members {
        // Blob-pinned member (sideloaded): the pod holds the blob, the
        // collection recipe is not what executes — excluded.
        if ctx.lock.snaps.contains_key(&name) {
            continue;
        }
        let bytes = match crate::pkg_source::resolve_pkg(&name) {
            crate::pkg_source::PkgResult::File(path) => std::fs::read(&path)
                .map_err(|e| miette::miette!("failed to read recipe of '{name}': {e}"))?,
            crate::pkg_source::PkgResult::Found { content, .. } => content.into_bytes(),
            crate::pkg_source::PkgResult::NotFound => continue,
        };
        entries.push((name, bytes));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let digest = recipe_closure_hash(&entries);
    build
        .recipe_digests
        .push((spec.name.clone(), digest.clone()));
    let Some(entry) = ctx.lock.packages.get(&spec.name) else {
        // New pin: stamped when the entry is written.
        return Ok(());
    };
    match &entry.recipe_sha256 {
        None => {
            // Migration (issue #142): stamp silently, no rebuild.
            build.recipe_stamps.push((spec.name.clone(), digest));
        }
        Some(recorded) if *recorded == digest => {}
        Some(_) => {
            build.recipe_drift.insert(spec.name.clone());
            build
                .recipe_drift_members
                .extend(entries.iter().map(|(name, _)| name.clone()));
            build.recipe_stamps.push((spec.name.clone(), digest));
            crate::output::status(format!(
                "recipe drift: {} (closure recipe changed)",
                spec.name
            ));
        }
    }
    Ok(())
}

/// SHA-256 over the canonical closure listing (issue #142): entries
/// sorted by member name (sorted by the caller), each fed into one
/// running hash as `name \0 <length> \0 bytes` — the NAR-style
/// convention of [`crate::pkg_source::content_hash`] (sorted paths +
/// contents), lifted one level: the members are the paths, the recipe
/// bytes the contents. The length prefix keeps adjacent entries
/// unambiguous.
fn recipe_closure_hash(entries: &[(String, Vec<u8>)]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for (name, bytes) in entries {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Decide what one own package does in a scoped reconcile BEFORE any
/// build (issue #15): an off-scope package keeps its installed store
/// content (claims from the installed record, no build — or a normal
/// build when the generation lacks it, so a generation always contains
/// everything declared); the SELECTED package of a scoped rebuild
/// bypasses the hold but keeps its pin, while a plain sync holds.
/// `scoped` is true when the reconcile targets one package
/// (`only.is_some()`); `overlay` is true when the package has an
/// overlay (overlay packages never hold).
///
/// Two holds, two drift senses (both plain-sync only): the pin hold
/// (issue #5) keeps the installed content when the lockfile pin and the
/// collection candidate disagree on VERSION; the content hold (issue
/// #113) keeps it when the freshly resolved recipe digests identically
/// to the installed record — same version, no rebuild. Recipe-closure
/// drift (issue #142) bypasses both: the closure's recipes changed, so
/// the package rebuilds at its pin even at an unchanged version.
fn scope_own_package(
    ctx: &ReconcileCtx<'_>,
    selected: bool,
    scoped: bool,
    overlay: bool,
    meta: &mut crate::snap::SnapMeta,
    build: &mut ReconcileBuild,
) -> miette::Result<OwnScope> {
    if !selected {
        if let Some(installed_pkg) = ctx.active.and_then(|g| g.packages.get(&meta.name)) {
            hold_style_skip_claims(
                &mut build.desktop_claims,
                &mut build.binary_claims,
                &mut build.service_claims,
                installed_pkg,
                meta,
            );
            return Ok(OwnScope::SkipInstalled);
        }
        return Ok(OwnScope::Build);
    }
    // Recipe drift (issue #142) bypasses both holds: the package
    // rebuilds at its pin EVEN at an unchanged version — drift moves
    // content, not the version (`pod update` is the version verb).
    let drifted = build.recipe_drift.contains(&meta.name);
    if !drifted && !scoped && !overlay && held_at_content(ctx.active, meta) {
        // Content hold (issue #113): the installed record was built
        // from this exact recipe — plain sync keeps its store content.
        // The hold never reads the deps blob, so re-verify the recorded
        // closure pin first (issue #125): corrupted or missing store
        // content fails the sync loud instead of riding along.
        verify_held_deps_blob(ctx, &meta.name)?;
        return Ok(hold_plain_sync(ctx, meta, build));
    }
    if overlay || !held_at_pin(ctx.lock, &meta.name, &meta.version, ctx.active) || drifted {
        if drifted {
            if let Some(entry) = ctx.lock.packages.get(&meta.name) {
                meta.version = entry.version.clone();
            }
        }
        return Ok(OwnScope::Build);
    }
    if !scoped {
        // Plain sync holds (issue #5): the pin plus the active
        // generation's content win over collection drift.
        return Ok(hold_plain_sync(ctx, meta, build));
    }
    // Rebuild bypasses the hold (issue #15) but KEEPS THE PIN: build
    // at the pinned version, not the collection candidate — never
    // recorded as held (the deliberate version move is `pod update`'s
    // job). Pinning the meta to the executing version mirrors the
    // loaded-packages path.
    meta.version = ctx.lock.packages[&meta.name].version.clone();
    Ok(OwnScope::Build)
}

/// True when a scoped reconcile deliberately moved a package's
/// dependency-closure pin (issue #15 `--latest`): only a forced-float
/// ensure counts, and the pin moved when the fresh closure hash differs
/// from the pre-existing pin's — or when there was no pin yet.
fn deps_pin_moved(
    force_float: bool,
    prev_entry: Option<&PodPackageLockEntry>,
    fresh: Option<&crate::lock::PackageDepsLock>,
) -> bool {
    force_float
        && fresh.is_some_and(|new| {
            prev_entry.is_none_or(|e| {
                e.deps
                    .as_ref()
                    .is_none_or(|old| old.deps_hash != new.deps_hash)
            })
        })
}

/// Record one own package's pin movement after its build succeeded: a
/// version change repins (carrying the deps pin forward, ADR-0017); a
/// version kept with a fresh closure pin records the deps pin
/// separately (float). Every written entry carries the package's
/// recipe-closure digest (issue #142) — a repin must not wipe it.
fn record_pin_movement(
    repins: &mut Vec<(String, PodPackageLockEntry)>,
    deps_pins: &mut Vec<(String, crate::lock::PackageDepsLock)>,
    lock: &LockFile,
    spec: &PodPackageSpec,
    meta: &crate::snap::SnapMeta,
    deps_pin: Option<&crate::lock::PackageDepsLock>,
    recipe_sha256: Option<&str>,
) {
    let version_changed =
        lock.packages.get(&spec.name).map(|e| e.version.as_str()) != Some(meta.version.as_str());
    if version_changed {
        // A repin carries the existing deps pin forward (ADR-0017):
        // content-addressed, re-verified by sync. Same for the recipe
        // closure hash (issue #142): the fresh digest when this
        // reconcile computed one, else the recorded hash carried
        // forward — a repin never wipes the pin.
        let deps = deps_pin
            .cloned()
            .or_else(|| lock.packages.get(&spec.name).and_then(|e| e.deps.clone()));
        let recipe_sha256 = recipe_sha256.map(str::to_string).or_else(|| {
            lock.packages
                .get(&spec.name)
                .and_then(|e| e.recipe_sha256.clone())
        });
        repins.push((
            spec.name.clone(),
            PodPackageLockEntry {
                version: meta.version.clone(),
                constraint: spec.constraint.clone(),
                deps,
                recipe_sha256,
            },
        ));
    } else if let Some(pin) = deps_pin {
        // Same version, moved closure (float): the repin path above
        // doesn't fire — record the pin separately.
        deps_pins.push((spec.name.clone(), pin.clone()));
    }
}

/// The pure pre-build resolutions of one reconcile: the declared env
/// (ADR-0030) and the folded pod-level service overrides (ADR-0032
/// Decision 3), validated against the declaration BEFORE any build
/// phase — a bad declaration must fail with zero writes. The overrides
/// are resolved ONCE here and threaded through validation into the
/// staging tail's service record.
fn resolve_pure_inputs(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<(BTreeMap<String, String>, PodServiceOverrides)> {
    let env_vars = resolve_pod_env(root, pod_name, decl)?;
    let svc_overrides = resolve_pod_service_overrides(root, pod_name, decl)?;
    validate_service_overrides(root, pod_name, &svc_overrides, decl)?;
    Ok((env_vars, svc_overrides))
}

/// The reconcile proper (see [`sync_pod`]). `only` scopes it to ONE
/// declared package — the `pod rebuild` core (issue #15): the selected
/// package rebuilds at its pins, every other installed package keeps
/// its store content. `float_deps` makes the selected package's
/// dependency ensure float regardless of its own float mode
/// (`rebuild --latest`): the closure is re-resolved and its pin moved
/// deliberately (ADR-0017 Decision 5). Returns the report plus whether
/// the selected package's deps pin moved.
///
/// `allow_degraded` (issue #16): when the squashfs pair is absent,
/// build-capable verbs (`sync`, `rebuild`) fail closed BEFORE any
/// store/lock/farm mutation, while the removal flow (`allow_degraded`)
/// proceeds — nothing builds, but the declared set is still recorded
/// so the removal phase drops only genuinely undeclared packages.
fn reconcile_pod_scoped(
    root: &Path,
    pod_name: &str,
    only: Option<&str>,
    float_deps: bool,
    allow_degraded: bool,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<(PodSyncReport, bool)> {
    let mut state = prepare_reconcile(root, pod_name, allow_degraded, tools)?;
    let (env_vars, svc_overrides) = resolve_pure_inputs(&state.root, &state.pod_name, &state.decl)?;
    let mut build = ReconcileBuild::default();
    collect_pending(&mut state, only, float_deps, &mut build)?;
    let installed = install_pending(&mut state, &mut build)?;

    // Overlay-driven repins (issue #6) and moved dependency-closure pins
    // (ADR-0017): applied only after the installs succeeded, so a failed
    // reconcile leaves the pin untouched.
    apply_pin_updates(
        &mut state.lock,
        &build.repins,
        &build.deps_pins,
        &build.recipe_stamps,
        &state.lock_path,
    )?;
    // Remove store packages the declaration dropped.
    let removed = remove_undeclared(&state.store, &state.tools, &build.declared_names)?;
    present_and_reconcile(&state, pod_name, &env_vars, &svc_overrides, tools).map(
        |(generation, farm, services)| {
            (
                PodSyncReport {
                    pod: pod_name.to_string(),
                    noop: installed.is_empty() && removed.is_empty(),
                    installed,
                    removed,
                    held: build.held,
                    generation,
                    farm,
                    services: Some(services),
                },
                build.deps_moved,
            )
        },
    )
}

/// Present whatever is now active and run the service reconcile tail
/// (ADR-0032 Decision 8, ticket #107): diff + switch the systemd user
/// registrations to the generation just presented, AFTER the flip on
/// every path. A cold pod (nothing active) withdraws whatever its
/// applied state remembers, with the same stop-then-withdraw rule.
fn present_and_reconcile(
    state: &ReconcileState,
    pod_name: &str,
    env_vars: &BTreeMap<String, String>,
    svc_overrides: &PodServiceOverrides,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<(
    Option<u64>,
    Option<PathBuf>,
    crate::services::ServiceReconcileReport,
)> {
    let (generation, farm) = present_active(&state.store, &state.dir, env_vars, svc_overrides)?;
    let services = match generation {
        Some(_) => crate::services::reconcile(&state.store, &state.dir, pod_name, tools)?,
        None => crate::services::reconcile_empty(&state.dir, pod_name, tools)?,
    };
    Ok((generation, farm, services))
}

/// Validated inputs + pod state for one scoped reconcile: everything
/// the build phases need, opened before any store write.
struct ReconcileState {
    root: PathBuf,
    pod_name: String,
    decl: PodDeclaration,
    dir: PathBuf,
    store: crate::runtime::RuntimeStore,
    tools: crate::runtime::RuntimeTools,
    active: Option<crate::runtime::Generation>,
    lock: LockFile,
    lock_path: PathBuf,
    loaded_versions: BTreeMap<String, String>,
    loaded_overlays: BTreeMap<String, serde_json::Value>,
}

/// Validate a pod declaration for a reconcile BEFORE any mutation
/// (issue #8/#6): name, loads (existence + cycles), overlays — a bad
/// declaration fails here with zero writes.
fn validate_reconcile_inputs(root: &Path, pod_name: &str) -> miette::Result<PodDeclaration> {
    validate_pod_name(pod_name)?;
    let decl = load_declaration(root, pod_name)?;
    validate_loads(root, pod_name, &decl)?;
    validate_overlays(root, &decl, pod_name)?;
    Ok(decl)
}

/// True when the host can build and unpack payloads: the squashfs pair
/// is on PATH. The single install-capability gate — the degraded
/// guard and the build phase must agree.
fn install_capable(tools: &crate::runtime::RuntimeTools) -> bool {
    tools.unsquashfs.is_some() && crate::runtime::tool_on_path("mksquashfs")
}

/// Prepare one scoped reconcile: validate the declaration, open the
/// pod's store + lockfile, read the active generation, and fold the
/// `loads` graph (issue #8). The create_dir_all is the pod state-dir
/// bootstrap (issue #3). Degraded guard (issue #16): a build-capable
/// verb fails closed BEFORE the create_dir_all — the first mutation —
/// while the removal flow (`allow_degraded`) proceeds.
fn prepare_reconcile(
    root: &Path,
    pod_name: &str,
    allow_degraded: bool,
    tools: &crate::runtime::RuntimeTools,
) -> miette::Result<ReconcileState> {
    let decl = validate_reconcile_inputs(root, pod_name)?;
    if !allow_degraded && !install_capable(tools) {
        miette::bail!(
            "cannot reconcile pod '{pod_name}': mksquashfs/unsquashfs not found on PATH \
             — install squashfs-tools and re-run"
        );
    }
    let dir = pod_dir(root, pod_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let store = pod_store(&dir);
    let active = store.active_generation()?;
    // Loaded pods, in listed order (issue #8): each contributes its
    // package versions. The own package set is the name-clash winner,
    // so a loaded package whose name the pod itself declares never
    // enters the composition. The loading pod does NOT write the
    // loaded pod.
    let (loaded_versions, loaded_overlays) = loaded_contributions(root, &decl)?;
    let lock_path = pod_lock_path(root, pod_name);
    let lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);
    Ok(ReconcileState {
        root: root.to_path_buf(),
        pod_name: pod_name.to_string(),
        decl,
        dir,
        store,
        tools: tools.clone(),
        active,
        lock,
        lock_path,
        loaded_versions,
        loaded_overlays,
    })
}

/// Build every package the scope demands (own packages first — the
/// scoped decisions of issue #15 — then loaded packages, issue #8).
/// Degraded mode (removal flow only, issue #16): without the squashfs
/// pair nothing can be built or unpacked, so the reconcile installs
/// nothing — the declared set is still recorded WITHOUT building (so
/// the removal phase never wipes declared packages) and the degraded
/// warning is loud when declared packages remain uninstalled.
fn collect_pending(
    state: &mut ReconcileState,
    only: Option<&str>,
    float_deps: bool,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    if install_capable(&state.tools) {
        let ctx = ReconcileCtx {
            store: &state.store,
            lock: &state.lock,
            active: state.active.as_ref(),
            root: &state.root,
            pod_name: &state.pod_name,
        };
        collect_own_packages(&ctx, &state.decl, only, float_deps, build)?;
        collect_loaded_packages(
            &ctx,
            &state.decl,
            &state.loaded_versions,
            &state.loaded_overlays,
            build,
        )?;
        // Runtime requires closure (issue #35): after the full post-state
        // package set is known, every requires member the declared
        // packages don't already provide is built and installed into the
        // pod so the farm links it.
        install_requires_closure(&ctx, build)?;
        return Ok(());
    }
    collect_degraded_names(&state.decl, &state.loaded_versions, build);
    warn_degraded_missing(state, build);
    Ok(())
}

/// Warn when the degraded reconcile leaves declared packages
/// uninstalled (issue #16): only names in the post-state declared set
/// that the active generation does not carry — a degraded removal whose
/// remaining packages are all installed stays silent.
fn warn_degraded_missing(state: &ReconcileState, build: &ReconcileBuild) {
    let installed: std::collections::BTreeSet<String> = state
        .active
        .as_ref()
        .map(|g| g.packages.keys().cloned().collect())
        .unwrap_or_default();
    let missing: Vec<String> = build
        .declared_names
        .difference(&installed)
        .cloned()
        .collect();
    if !missing.is_empty() {
        crate::output::warn(format!(
            "unsquashfs/mksquashfs not found — declared but not installed: {}; \
             install squashfs-tools and run `shuttle pod sync`",
            missing.join(", ")
        ));
    }
}

/// Record the post-state package names WITHOUT building (degraded
/// removal, issue #16): own names from the declaration, loaded names
/// from the folded contributions — the same sets the build path
/// records via `declared_names`, so `remove_undeclared` drops only
/// genuinely undeclared packages and never wipes declared ones.
fn collect_degraded_names(
    decl: &PodDeclaration,
    loaded_versions: &BTreeMap<String, String>,
    build: &mut ReconcileBuild,
) {
    for spec_str in &decl.packages {
        if let Ok(spec) = parse_pod_package(spec_str) {
            build.declared_names.insert(spec.name);
        }
    }
    build.declared_names.extend(loaded_versions.keys().cloned());
}

/// Resolve the claim collisions (issues #7/#8 — BEFORE any store write,
/// so a same-precedence collision fails with zero writes) and install
/// the changed set (a no-op batch creates no generation). Returns the
/// names the install moved.
fn install_pending(
    state: &mut ReconcileState,
    build: &mut ReconcileBuild,
) -> miette::Result<Vec<String>> {
    resolve_desktop_claims(&build.desktop_claims)?;
    resolve_binary_claims(&build.binary_claims)?;
    resolve_service_claims(&build.service_claims)?;
    let mut installed = Vec::new();
    if !build.pending.is_empty() {
        let report =
            state
                .store
                .install_batch(&build.pending, &Default::default(), &state.tools)?;
        if !report.noop {
            installed = report.installed.iter().map(|s| s.name.clone()).collect();
        }
    }
    Ok(installed)
}

/// Shared inputs for the build phases of one scoped reconcile: the pod
/// store, the pre-reconcile lockfile, and the active generation when
/// one exists.
struct ReconcileCtx<'a> {
    store: &'a crate::runtime::RuntimeStore,
    lock: &'a LockFile,
    active: Option<&'a crate::runtime::Generation>,
    root: &'a Path,
    pod_name: &'a str,
}

/// Everything the build phases of one scoped reconcile accumulate:
/// packages awaiting install, claims, pin movements, and whether the
/// selected package's deps pin moved (issue #15).
#[derive(Default)]
struct ReconcileBuild {
    /// Packages resolved + built, awaiting install.
    pending: Vec<crate::runtime::PendingSnap>,
    /// Names held at their pins this reconcile (plain sync, issue #5).
    held: Vec<String>,
    /// Package names of the post-state (own + loaded).
    declared_names: std::collections::BTreeSet<String>,
    /// Desktop application-ID claims of the post-state package set
    /// (issue #7): collected in declaration order, resolved for
    /// collisions BEFORE any store write.
    desktop_claims: Vec<DesktopClaim>,
    /// Binary-name claims of the post-state package set (issue #8): the
    /// shared collision classifier over loaded/own/overlay layers, run
    /// BEFORE any store write so a same-precedence clash is a hard error
    /// with zero writes.
    binary_claims: Vec<BinaryClaim>,
    /// Service-name claims of the post-state package set (ADR-0032,
    /// issue #105): same classifier, same pre-write gate.
    service_claims: Vec<ServiceClaim>,
    /// Version pins the reconcile moved (overlay wins over the pin):
    /// recorded only after the build succeeded, applied only after the
    /// install succeeded — a failed reconcile leaves the pin in place.
    repins: Vec<(String, PodPackageLockEntry)>,
    /// Dependency-closure pins moved by this reconcile (ADR-0017): a
    /// float whose closure changed at constant version. Version repins
    /// above carry their deps pin inside the entry; this catches the
    /// version-stayed case.
    deps_pins: Vec<(String, crate::lock::PackageDepsLock)>,
    /// Whether the selected package's deps pin moved (issue #15).
    deps_moved: bool,
    /// The `requires` seeds of every post-state package (own + loaded,
    /// resolved metas): the runtime-closure union the pod must carry
    /// (issue #35). Seeds, not members — the pass resolves them
    /// transitively once the full declared set is known.
    requires_seeds: Vec<String>,
    /// Recipe-closure digests computed this reconcile (issue #142), per
    /// declared package: recorded onto every pin the reconcile writes.
    recipe_digests: Vec<(String, String)>,
    /// Silent migration stamps (issue #142): lock entries that predate
    /// the closure hash get theirs recorded WITHOUT a rebuild — existing
    /// pods must not mass-rebuild on the first post-#142 sync.
    recipe_stamps: Vec<(String, String)>,
    /// Declared packages whose recipe closure drifted (issue #142):
    /// rebuilt at their pins EVEN at an unchanged version.
    recipe_drift: std::collections::BTreeSet<String>,
    /// Requires members whose collection recipes drifted (issue #142):
    /// rebuilt from their recipes even though the active generation
    /// carries content for them.
    recipe_drift_members: std::collections::BTreeSet<String>,
}

/// Fold the `loads` graph one level deep (issue #8): each loaded pod
/// contributes its active generation's package versions UNIONed with
/// its declaration (generation wins the clash, issue #103; with no
/// generation the declaration alone mirrors its own first sync) and
/// its overlay map.
fn loaded_contributions(
    root: &Path,
    decl: &PodDeclaration,
) -> miette::Result<(
    BTreeMap<String, String>,
    BTreeMap<String, serde_json::Value>,
)> {
    let mut loaded_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut loaded_overlays: BTreeMap<String, serde_json::Value> = BTreeMap::new();
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
    Ok((loaded_versions, loaded_overlays))
}

/// Resolve one declared own package through the collection + the pod's
/// overlay layer (issue #6: the overlay wins over the collection).
fn resolve_own_meta(
    root: &Path,
    pod_name: &str,
    spec: &PodPackageSpec,
    overlay: &BTreeMap<String, serde_json::Value>,
) -> miette::Result<crate::snap::SnapMeta> {
    let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
        miette::miette!(
            "cannot build declared package '{}': {e} (declaration at {})",
            spec.name,
            pod_lua_path(root, pod_name).display()
        )
    })?;
    if let Some(patch) = overlay.get(&spec.name) {
        apply_overlay(&mut meta, patch).map_err(|e| {
            miette::miette!(
                "cannot build declared package '{}' with its overlay: {e}",
                spec.name
            )
        })?;
    }
    Ok(meta)
}

/// Resolve + build the pod's OWN packages (in declared order, issue
/// #3): each resolves collection → pin (hold) → overlay, later wins,
/// then builds after its dependency closure is ensured (ADR-0017
/// Decision 7). The scoped-reconcile decisions (issue #15) come from
/// [`scope_own_package`].
fn collect_own_packages(
    ctx: &ReconcileCtx<'_>,
    decl: &PodDeclaration,
    only: Option<&str>,
    float_deps: bool,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        // Blob pins (issue #116) have no collection entry to resolve:
        // the installed content IS the pin. When the generation carries
        // it, the package holds (claims from the installed record, no
        // build — the sideloaded payload is not rebuildable from source);
        // when it does not, the reconcile fails named instead of dying
        // in `load_meta` with a confusing collection error.
        if let Some(pin) = ctx.lock.snaps.get(&spec.name) {
            let layer = if decl.overlay.contains_key(&spec.name) {
                crate::farm::ClaimLayer::Overlay
            } else {
                crate::farm::ClaimLayer::Own
            };
            hold_blob_pinned(ctx, &spec.name, &pin.sha3_384, layer, build)?;
            continue;
        }
        let mut meta = resolve_own_meta(ctx.root, ctx.pod_name, &spec, &decl.overlay)?;
        build.declared_names.insert(meta.name.clone());
        // Runtime-closure seeds (issue #35): the declared package's own
        // requires — the overlay-won meta is what the pod executes.
        build.requires_seeds.extend(meta.requires.iter().cloned());
        let overlay = decl.overlay.contains_key(&spec.name);
        let layer = if overlay {
            crate::farm::ClaimLayer::Overlay
        } else {
            crate::farm::ClaimLayer::Own
        };
        let selected = only.is_none_or(|n| n == spec.name.as_str());
        // Recipe-closure drift (issue #142): decided BEFORE scoping, so
        // a drifted package can bypass the sync holds. Off-scope
        // packages (a scoped rebuild of a sibling) are not probed —
        // their drift stays for a plain sync to sweep.
        if selected {
            detect_recipe_drift(ctx, &spec, &meta, build)?;
        }
        if let OwnScope::Build =
            scope_own_package(ctx, selected, only.is_some(), overlay, &mut meta, build)?
        {
            build_own_package(ctx, &spec, &meta, layer, float_deps && selected, build)?;
        }
    }
    Ok(())
}

/// Build one own package that survived scoping: contribute its claims,
/// ensure its dependency closure, record pin movements, and queue the
/// pending build (issue #3/#15).
fn build_own_package(
    ctx: &ReconcileCtx<'_>,
    spec: &PodPackageSpec,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
    force_float: bool,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    push_meta_desktop_claims(&mut build.desktop_claims, meta, layer);
    push_meta_binary_claims(&mut build.binary_claims, meta, layer);
    push_meta_service_claims(&mut build.service_claims, meta, layer);
    // Dependency closure first (ADR-0017 Decision 7): fetch or verify
    // BEFORE the sandboxed offline build consumes it. `force_float`
    // floats the closure regardless of the meta's own float mode
    // (issue #15 --latest).
    let deps_pin = ensure_own_deps(ctx.store, ctx.lock, meta, &spec.name, force_float)
        .map_err(|e| miette::miette!("cannot fetch dependency closure for '{}': {e}", spec.name))?;
    let prev_entry = ctx.lock.packages.get(&spec.name);
    if deps_pin_moved(force_float, prev_entry, deps_pin.as_ref()) {
        build.deps_moved = true;
    }
    record_pin_movement(
        &mut build.repins,
        &mut build.deps_pins,
        ctx.lock,
        spec,
        meta,
        deps_pin.as_ref(),
        build
            .recipe_digests
            .iter()
            .find(|(name, _)| *name == spec.name)
            .map(|(_, digest)| digest.as_str()),
    );
    build.pending.push(build_pending_snap(
        ctx.store,
        meta,
        layer,
        deps_pin.as_ref(),
    )?);
    Ok(())
}

/// Resolve a loaded pod's package through BOTH overlay layers (issue
/// #8): the loaded pod's own overlay (so the rebuilt payload carries
/// the same build inputs it would get in the loaded pod itself)
/// beneath the loading pod's overlay — the top layer wins.
fn resolve_loaded_meta(
    name: &str,
    pod_name: &str,
    loaded_patch: Option<&serde_json::Value>,
    own_patch: Option<&serde_json::Value>,
) -> miette::Result<crate::snap::SnapMeta> {
    let mut meta = crate::deps::load_meta(name).map_err(|e| {
        miette::miette!("loaded package '{name}' from pod '{pod_name}' cannot be resolved: {e}")
    })?;
    if let Some(patch) = loaded_patch {
        apply_overlay(&mut meta, patch)
            .map_err(|e| miette::miette!("loaded package '{name}' overlay is invalid: {e}"))?;
    }
    if let Some(patch) = own_patch {
        apply_overlay(&mut meta, patch).map_err(|e| {
            miette::miette!("cannot build loaded package '{name}' with this pod's overlay: {e}")
        })?;
    }
    Ok(meta)
}

/// Rebuild the LOADED packages (issue #8): each at the version its pod
/// currently executes — same overlay build inputs, so the loading pod
/// executes exactly what the loaded pod executes. Deterministic build
/// output keeps a no-change reconcile a no-op. Own packages with the
/// same NAME shadow them outright (the loaded copy never enters).
fn collect_loaded_packages(
    ctx: &ReconcileCtx<'_>,
    decl: &PodDeclaration,
    loaded_versions: &BTreeMap<String, String>,
    loaded_overlays: &BTreeMap<String, serde_json::Value>,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    for (name, version) in loaded_versions {
        if build.declared_names.contains(name) {
            continue;
        }
        let mut meta = resolve_loaded_meta(
            name,
            ctx.pod_name,
            loaded_overlays.get(name),
            decl.overlay.get(name),
        )?;
        // Pin the loaded package at the executing version (a loaded
        // pod's active generation version wins over collection drift).
        if !version.is_empty() {
            meta.version = version.clone();
        }
        build.declared_names.insert(meta.name.clone());
        // Runtime-closure seeds (issue #35): loaded packages need their
        // requires members in THIS pod's store too.
        build.requires_seeds.extend(meta.requires.iter().cloned());
        push_meta_desktop_claims(
            &mut build.desktop_claims,
            &meta,
            crate::farm::ClaimLayer::Loaded,
        );
        push_meta_binary_claims(
            &mut build.binary_claims,
            &meta,
            crate::farm::ClaimLayer::Loaded,
        );
        push_meta_service_claims(
            &mut build.service_claims,
            &meta,
            crate::farm::ClaimLayer::Loaded,
        );
        build.pending.push(build_pending_snap(
            ctx.store,
            &meta,
            crate::farm::ClaimLayer::Loaded,
            None,
        )?);
    }
    Ok(())
}

/// Install the runtime requires closure into the pod (issue #35): every
/// transitive `requires` member of the post-state packages that the
/// declared set doesn't already provide is resolved, built
/// ([`ensure_pod_dep_payload`]) and queued for installation, so the
/// generation carries the libraries/tools its packages require and the
/// farm links them.
///
/// Members provided by the declaration (own/overlay/loaded) are skipped —
/// the declared copy wins. Members already in the active generation keep
/// their store content (a no-op sync stays a no-op) but are recorded into
/// the post-state set so [`remove_undeclared`] never wipes a live closure
/// member — and a requires edge that disappears drops the orphaned member
/// on the next sync.
///
/// Members install at the `Loaded` layer (the composition floor): a
/// declared package's binaries/desktop entries always outrank dependency
/// contributions. No desktop/binary claims are collected for them — a
/// collision resolves at farm emission by layer precedence instead of
/// failing the reconcile.
fn install_requires_closure(
    ctx: &ReconcileCtx<'_>,
    build: &mut ReconcileBuild,
) -> miette::Result<()> {
    if build.requires_seeds.is_empty() {
        return Ok(());
    }
    let members = crate::deps::resolve_dep_names(&build.requires_seeds, true)?;
    let active_names: std::collections::BTreeSet<String> = ctx
        .active
        .map(|g| g.packages.keys().cloned().collect())
        .unwrap_or_default();
    let mut building: Vec<String> = Vec::new();
    for name in members {
        if build.declared_names.contains(&name) {
            continue;
        }
        // Recipe drift (issue #142): a member whose collection recipe
        // drifted rebuilds from its recipe even though the active
        // generation carries content — that carried content is what
        // recipe-only fixes never used to reach.
        let drifted = build.recipe_drift_members.contains(&name);
        if active_names.contains(&name) && !drifted {
            build.declared_names.insert(name);
            continue;
        }
        let dep_meta = crate::deps::load_meta(&name)?;
        let payload = ensure_pod_dep_payload(ctx.store, &name, &dep_meta, &mut building, drifted)?;
        let sha3_384 = crate::store::sha3_384_file(&payload)?;
        if drifted {
            // Churn guard: an UNDRIFTED member of a drifted closure
            // rebuilds to identical bytes and keeps its store content —
            // only a genuinely changed payload earns an install.
            if let Some(installed) = ctx.active.as_ref().and_then(|g| g.packages.get(&name)) {
                if installed.sha3_384 == sha3_384 {
                    build.declared_names.insert(name);
                    continue;
                }
            }
        }
        build.pending.push(build_pending_snap_at(
            &dep_meta,
            &payload,
            sha3_384,
            crate::farm::ClaimLayer::Loaded,
        ));
        build.declared_names.insert(name);
    }
    Ok(())
}

/// Apply overlay-driven repins (issue #6), moved dependency-closure
/// pins (ADR-0017), and recipe-closure stamps (issue #142) to the
/// lockfile — called only after the installs succeeded, so a failed
/// reconcile leaves the pins untouched. Loaded packages are NOT
/// repinned in this pod's lockfile: a loaded pod's versions live in the
/// loaded pod, and this pod follows them live (issue #8 — read-only
/// consumption, no cross-pod pins).
fn apply_pin_updates(
    lock: &mut LockFile,
    repins: &[(String, PodPackageLockEntry)],
    deps_pins: &[(String, crate::lock::PackageDepsLock)],
    recipe_stamps: &[(String, String)],
    lock_path: &Path,
) -> miette::Result<()> {
    if repins.is_empty() && deps_pins.is_empty() && recipe_stamps.is_empty() {
        return Ok(());
    }
    for (name, entry) in repins {
        lock.packages.insert(name.clone(), entry.clone());
    }
    for (name, deps) in deps_pins {
        if let Some(entry) = lock.packages.get_mut(name) {
            entry.deps = Some(deps.clone());
        } else {
            lock.packages.insert(
                name.clone(),
                PodPackageLockEntry {
                    version: String::new(),
                    constraint: None,
                    deps: Some(deps.clone()),
                    recipe_sha256: None,
                },
            );
        }
    }
    // Recipe-closure stamps (issue #142): only entries that exist — a
    // stamp never creates a pin, it records onto one.
    for (name, digest) in recipe_stamps {
        if let Some(entry) = lock.packages.get_mut(name) {
            entry.recipe_sha256 = Some(digest.clone());
        }
    }
    lock.save(lock_path)
}

/// Remove store packages the declaration dropped. Removal never
/// unpacks, so it proceeds even in degraded mode. A package the
/// degraded mode never installed is simply absent — skip it.
fn remove_undeclared(
    store: &crate::runtime::RuntimeStore,
    tools: &crate::runtime::RuntimeTools,
    declared_names: &std::collections::BTreeSet<String>,
) -> miette::Result<Vec<String>> {
    let mut removed = Vec::new();
    if let Some(active) = store.active_generation()? {
        for name in active.packages.keys() {
            if declared_names.contains(name) {
                continue;
            }
            store.remove(name, tools)?;
            removed.push(name.clone());
        }
    }
    Ok(removed)
}

/// Present whatever is now active: record the staging-tail artifacts and
/// re-emit the bin farm for the active generation, then flip the pod's
/// `current` link. Nothing active → nothing exposed: the farm and the
/// user-level launcher and service surfaces are withdrawn along with it
/// (issue #7, ADR-0032).
///
/// The staging order matters: the declared env (ADR-0030) is recorded
/// FIRST, then the service record — it composes the recorded env into
/// the rendered units — and only then the emit, which renders services
/// from the just-recorded `units.json`, and the flip. All of this is the
/// staging tail where a generation is PRESENTED, never inside
/// `farm::emit`: a rollback re-emits through its own path and must serve
/// the target generation's RECORDED env + units, not a re-resolution
/// against the current declaration.
fn present_active(
    store: &crate::runtime::RuntimeStore,
    dir: &Path,
    env_vars: &BTreeMap<String, String>,
    svc_overrides: &PodServiceOverrides,
) -> miette::Result<(Option<u64>, Option<PathBuf>)> {
    let active = store.active_generation()?;
    Ok(match &active {
        Some(gen) => {
            crate::farm::write_generation_env(store, gen.n, env_vars)?;
            crate::services::record(store, gen, svc_overrides)?;
            let farm = crate::farm::emit(store, gen)?;
            crate::farm::flip_current(dir, gen.n)?;
            (Some(gen.n), Some(farm))
        }
        None => {
            crate::farm::clear_current(dir)?;
            crate::desktop::clear(store)?;
            crate::services::clear(store)?;
            (None, None)
        }
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
    // No `pins`: `add_package` resolves the incoming package from the
    // collection, so its declared siblings stay collection-resolved
    // (the sideload path passes the pod's own pins first, issue #147).
    push_declared_binary_claims(&mut claims, decl, new_name, None)?;
    push_loaded_binary_claims(&mut claims, root, decl, new_name)?;
    resolve_binary_claims(&claims)
}

/// Collect the binary claims of every declared package except the one
/// being added, at its layer (own, or overlay when the pod patches it).
/// With `pins` (the sideload path, issue #147) a sibling the pod pins
/// and carries resolves from its installed record first — the pod's
/// own pins/blobs — and only falls back to the collection otherwise.
fn push_declared_binary_claims(
    claims: &mut Vec<BinaryClaim>,
    decl: &PodDeclaration,
    new_name: &str,
    pins: Option<&PodPins<'_>>,
) -> miette::Result<()> {
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        if spec.name == new_name {
            continue; // the incoming package's claims are already added
        }
        let layer = if decl.overlay.contains_key(&spec.name) {
            crate::farm::ClaimLayer::Overlay
        } else {
            crate::farm::ClaimLayer::Own
        };
        if let Some(pkg) = pins.and_then(|p| p.carried(&spec.name)) {
            push_installed_binary_claims(claims, pkg, layer);
            continue;
        }
        let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
            miette::miette!("cannot check '{}' for a binary collision: {e}", spec.name)
        })?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch)
                .map_err(|e| miette::miette!("overlay of '{}' is invalid: {e}", spec.name))?;
        }
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

/// Collect the service-name claims of an already-installed package: the
/// service declarations recorded in its manifest entry at install time
/// (issue #106) — the blob-pin hold (issue #116) has no freshly resolved
/// meta to read them from.
fn push_installed_service_claims(
    claims: &mut Vec<ServiceClaim>,
    pkg: &crate::runtime::InstalledPackage,
    layer: crate::farm::ClaimLayer,
) {
    for service in pkg.services.keys() {
        claims.push(ServiceClaim {
            service: service.clone(),
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

// ── Service-name claims (ADR-0032 Decision 3, issue #105) ──

/// One claim on a service name (ADR-0032): which package declares the
/// service, at which composition precedence layer. Mirrors the binary
/// claim so the shared classifier runs unchanged. Package-level pod{}
/// `services` entries are NOT claims — they configure an existing
/// service; only a package's declared `services` claims the name.
#[derive(Debug, Clone)]
struct ServiceClaim {
    service: String,
    pkg: String,
    layer: crate::farm::ClaimLayer,
}

/// Pre-write service-collision check for `add_package` (ADR-0032
/// Decision 3): a same-precedence service-name clash with the pod's
/// post-state package set must fail BEFORE any write. Mirrors
/// [`precheck_binary_collision`].
fn precheck_service_collision(
    root: &Path,
    decl: &PodDeclaration,
    new_name: &str,
    new_meta: &crate::snap::SnapMeta,
    new_layer: crate::farm::ClaimLayer,
) -> miette::Result<()> {
    let mut claims: Vec<ServiceClaim> = Vec::new();
    push_meta_service_claims(&mut claims, new_meta, new_layer);
    push_declared_service_claims(&mut claims, decl, new_name, None)?;
    push_loaded_service_claims(&mut claims, root, decl, new_name)?;
    resolve_service_claims(&claims)
}

/// Collect the service claims of every declared package except the one
/// being added, at its layer (own, or overlay when the pod patches it).
/// With `pins` (the sideload path, issue #147) a sibling the pod pins
/// and carries resolves from its installed record first — the pod's
/// own pins/blobs — and only falls back to the collection otherwise.
fn push_declared_service_claims(
    claims: &mut Vec<ServiceClaim>,
    decl: &PodDeclaration,
    new_name: &str,
    pins: Option<&PodPins<'_>>,
) -> miette::Result<()> {
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        if spec.name == new_name {
            continue; // the incoming package's claims are already added
        }
        let layer = if decl.overlay.contains_key(&spec.name) {
            crate::farm::ClaimLayer::Overlay
        } else {
            crate::farm::ClaimLayer::Own
        };
        if let Some(pkg) = pins.and_then(|p| p.carried(&spec.name)) {
            push_installed_service_claims(claims, pkg, layer);
            continue;
        }
        let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
            miette::miette!("cannot check '{}' for a service collision: {e}", spec.name)
        })?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch)
                .map_err(|e| miette::miette!("overlay of '{}' is invalid: {e}", spec.name))?;
        }
        push_meta_service_claims(claims, &meta, layer);
    }
    Ok(())
}

/// Collect the service claims of loaded-pod-provided packages, folded in
/// at `Loaded` (the composition floor). A package the pod itself declares
/// is already claimed at a higher layer, so it is skipped here.
fn push_loaded_service_claims(
    claims: &mut Vec<ServiceClaim>,
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
            miette::miette!(
                "cannot check loaded '{}' for a service collision: {e}",
                name
            )
        })?;
        push_meta_service_claims(claims, &meta, crate::farm::ClaimLayer::Loaded);
    }
    Ok(())
}

/// Collect the service claims of a freshly resolved meta: the name of
/// every service the package declares.
fn push_meta_service_claims(
    claims: &mut Vec<ServiceClaim>,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
) {
    for service in meta.services.keys() {
        claims.push(ServiceClaim {
            service: service.clone(),
            pkg: meta.name.clone(),
            layer,
        });
    }
}

/// Resolve service-name collisions across the post-state package set
/// (ADR-0032 Decision 3): same-precedence duplicate service names are a
/// hard error (zero writes); a higher layer overrides with a warning
/// naming winner and loser; a lower layer is shadowed with a warning.
/// Declaration order breaks ties: the later claim is the incoming one.
fn resolve_service_claims(claims: &[ServiceClaim]) -> miette::Result<()> {
    let mut incumbent: BTreeMap<String, ServiceClaim> = BTreeMap::new();
    for claim in claims {
        let Some(existing) = incumbent.get(&claim.service) else {
            incumbent.insert(claim.service.clone(), claim.clone());
            continue;
        };
        match crate::farm::classify_collision(existing.layer, claim.layer) {
            crate::farm::CollisionVerdict::Error => {
                miette::bail!(
                    "service '{}' is declared by both '{}' and '{}' at the same \
                     precedence — same-precedence service-name collision; rename one of \
                     the services or drop one of the packages (ADR-0032 Decision 3)",
                    claim.service,
                    existing.pkg,
                    claim.pkg
                );
            }
            crate::farm::CollisionVerdict::Override => {
                crate::output::warn(format!(
                    "service '{}' from '{}' overrides '{}' (higher layer wins)",
                    claim.service, claim.pkg, existing.pkg
                ));
                incumbent.insert(claim.service.clone(), claim.clone());
            }
            crate::farm::CollisionVerdict::Shadowed => {
                crate::output::warn(format!(
                    "service '{}' from '{}' is shadowed by '{}' (lower layer loses)",
                    claim.service, claim.pkg, existing.pkg
                ));
            }
        }
    }
    Ok(())
}

// ── Pod-level service overrides (ADR-0032 Decision 3) ──

/// One resolved service option set: the merged pass-through options plus
/// `enabled` materialized as a bool (ADR-0032 Decision 7 — default
/// `false`, declaring never starts anything). The service emitter
/// consumes this; the resolution helpers here only validate.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedServiceOptions {
    pub enabled: bool,
    pub options: BTreeMap<String, serde_json::Value>,
}

/// Resolve one service's options (ADR-0032 Decision 3): the package's
/// defaults merged per-key with the pod-level overrides, override wins.
/// Every overridden key warns naming winner and loser — a cross-layer
/// override is never silent. `enabled` is materialized separately:
/// the pod override wins, else the package default, else `false`.
pub(crate) fn resolve_service_options(
    service: &str,
    defaults: &BTreeMap<String, serde_json::Value>,
    overrides: &BTreeMap<String, serde_json::Value>,
    winner_label: &str,
    loser_label: &str,
) -> miette::Result<ResolvedServiceOptions> {
    let mut options = defaults.clone();
    for (key, value) in overrides {
        if defaults.get(key) != Some(value) {
            crate::output::warn(format!(
                "service '{service}': option '{key}' from {winner_label} overrides \
                 {loser_label} (override wins)"
            ));
        }
        options.insert(key.clone(), value.clone());
    }
    // Pod-side override strings reach the same render path as declared
    // values (ExecStart args, interpolation), so the parse-side exec
    // boundary applies at the merge too (issue #109 S5): a control
    // character (a raw newline) in a string value is rejected here,
    // naming the key.
    for (key, value) in &options {
        if let Some(s) = value.as_str() {
            crate::snap::validate_exec_text(service, &format!("options.{key}"), s)?;
        }
    }
    // `enabled` drives activation (ADR-0032 Decision 7) — a quoted
    // "true" is a string, not an enable, and silently disabling a
    // service the user asked to enable is the worst failure mode.
    if let Some(v) = options.get("enabled") {
        if !v.is_boolean() {
            miette::bail!("service '{service}': option 'enabled' must be a boolean, got {v}");
        }
    }
    let enabled = options
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(ResolvedServiceOptions { enabled, options })
}

/// The folded pod-level service overrides: service name → option key →
/// (value, declaring pod). Provenance rides along so a collision can
/// name both pods, like [`fold_pod_env`].
type FoldedServiceOverrides = BTreeMap<String, BTreeMap<String, (serde_json::Value, String)>>;

/// The resolved pod-level service overrides, provenance stripped:
/// service name → option key → value (ADR-0032 Decision 3). The form
/// threaded through validation into the staging tail's service record.
pub(crate) type PodServiceOverrides = BTreeMap<String, BTreeMap<String, serde_json::Value>>;

/// The fold proper for pod{} service overrides (ADR-0032 Decision 3),
/// mirroring [`fold_pod_env`]: loaded pods fold transitively, a
/// same-key override between two loaded pods keeps the FIRST-declared
/// load's value with a warning, and the pod's own declaration wins a
/// cross-layer clash with a warning naming winner and loser. Memoized +
/// cycle-checked; pure reads.
fn fold_pod_services(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
    stack: &mut Vec<String>,
    done: &mut HashSet<String>,
) -> miette::Result<FoldedServiceOverrides> {
    if let Some(pos) = stack.iter().position(|p| p == pod_name) {
        let mut cycle: Vec<String> = stack[pos..].to_vec();
        cycle.push(pod_name.to_string());
        miette::bail!("pod load cycle detected: {}", cycle.join(" -> "));
    }
    if !done.insert(pod_name.to_string()) {
        return Ok(BTreeMap::new());
    }
    stack.push(pod_name.to_string());
    let folded = (|| {
        let mut folded: FoldedServiceOverrides = BTreeMap::new();
        for loaded in &decl.loads {
            let loaded_decl = load_declaration(root, loaded)?;
            for (service, options) in fold_pod_services(root, loaded, &loaded_decl, stack, done)? {
                let entry = folded.entry(service.clone()).or_default();
                for (key, contributed) in options {
                    match entry.get(&key) {
                        None => {
                            entry.insert(key, contributed);
                        }
                        Some(_) => {
                            crate::output::warn(format!(
                                "service override for '{service}' option '{key}' comes from \
                                 more than one loaded pod under '{pod_name}' — keeping the \
                                 first-declared load's value"
                            ));
                        }
                    }
                }
            }
        }
        for (service, options) in &decl.services {
            let entry = folded.entry(service.clone()).or_default();
            for (key, value) in options {
                if let Some((_, loser)) =
                    entry.insert(key.clone(), (value.clone(), pod_name.to_string()))
                {
                    crate::output::warn(format!(
                        "service '{service}': option '{key}' from pod '{pod_name}' \
                         overrides pod '{loser}' (higher layer wins)"
                    ));
                }
            }
        }
        Ok(folded)
    })();
    stack.pop();
    folded
}

/// Fold the loaded + own service overrides into one map (provenance
/// stripped), like [`resolve_pod_env`] strips [`fold_pod_env`]'s.
fn resolve_pod_service_overrides(
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<PodServiceOverrides> {
    let folded = fold_pod_services(root, pod_name, decl, &mut Vec::new(), &mut HashSet::new())?;
    Ok(folded
        .into_iter()
        .map(|(svc, options)| (svc, options.into_iter().map(|(k, (v, _))| (k, v)).collect()))
        .collect())
}

/// Validate the pod-level `services` overrides (ADR-0032 Decision 3)
/// BEFORE any write, on every reconcile: every override must reference a
/// service the post-state package set actually declares (a typo is a hard
/// error, not a silent no-op). The layering itself resolved when the
/// overrides were folded ([`resolve_pod_service_overrides`], warning per
/// overridden key); this pass only proves them well-formed against the
/// declared services.
fn validate_service_overrides(
    root: &Path,
    pod_name: &str,
    overrides: &PodServiceOverrides,
    decl: &PodDeclaration,
) -> miette::Result<()> {
    if overrides.is_empty() {
        return Ok(()); // nothing to reference-check
    }
    let declared = walk_post_state_services(root, decl, overrides, pod_name)?;
    for service in overrides.keys() {
        if !declared.contains_key(service) {
            miette::bail!(
                "pod '{pod_name}' services: no package declares service '{service}' — \
                 the override must name a service declared by one of the pod's packages \
                 (ADR-0032 Decision 3)"
            );
        }
    }
    Ok(())
}

/// Walk the post-state package set — own declared packages (overlay
/// applied, the payload this pod would execute) plus loaded-pod packages
/// at their claim layers, like the collision prechecks — resolving each
/// package's services against the folded overrides. Returns the service
/// name → declaring-packages map the reference check needs.
fn walk_post_state_services(
    root: &Path,
    decl: &PodDeclaration,
    overrides: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    pod_name: &str,
) -> miette::Result<BTreeMap<String, Vec<String>>> {
    let mut declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        let mut meta = crate::deps::load_meta(&spec.name).map_err(|e| {
            miette::miette!(
                "cannot validate service overrides against '{}': {e}",
                spec.name
            )
        })?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch)
                .map_err(|e| miette::miette!("overlay of '{}' is invalid: {e}", spec.name))?;
        }
        resolve_service_overrides_against_meta(overrides, &meta, pod_name)?;
        record_declared_services(&mut declared, &meta);
    }
    for name in loaded_package_names(root, decl)? {
        let own = decl
            .packages
            .iter()
            .filter_map(|s| parse_pod_package(s).ok())
            .any(|p| p.name == name);
        if own {
            continue;
        }
        let meta = crate::deps::load_meta(&name).map_err(|e| {
            miette::miette!("cannot validate service overrides against loaded '{name}': {e}")
        })?;
        resolve_service_overrides_against_meta(overrides, &meta, pod_name)?;
        record_declared_services(&mut declared, &meta);
    }
    Ok(declared)
}

/// Record one package's service claims in the declared-service map.
fn record_declared_services(
    declared: &mut BTreeMap<String, Vec<String>>,
    meta: &crate::snap::SnapMeta,
) {
    for service in meta.services.keys() {
        declared
            .entry(service.clone())
            .or_default()
            .push(meta.name.clone());
    }
}

/// Resolve one package's declared services against the folded pod-level
/// overrides (warnings fire here, `enabled` materializes) — the
/// validation-path consumption of [`resolve_service_options`]. Results
/// are dropped until the emitter lands (ticket #106).
fn resolve_service_overrides_against_meta(
    overrides: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    meta: &crate::snap::SnapMeta,
    pod_name: &str,
) -> miette::Result<()> {
    for (service, decl) in &meta.services {
        let pod_overrides = overrides.get(service).cloned().unwrap_or_default();
        let _resolved = resolve_service_options(
            service,
            &decl.options,
            &pod_overrides,
            &format!("pod '{pod_name}'"),
            "the package default",
        )?;
    }
    Ok(())
}

/// Degraded-mode banner for `pod add` when the squashfs pair is absent:
/// the declaration is written, the install is deferred to
/// `shuttle pod sync` once the tools exist.
/// Epoch stamped into pod-built payloads so the same content builds to
/// the same bytes on every sync (mksquashfs embeds build time otherwise
/// — verified: two builds of an identical tree differ without this, and
/// match with it). The no-op detection compares payload sha3-384s, so
/// reproducibility IS the idempotency guarantee.
const POD_BUILD_EPOCH: &str = "946684800";

/// Stamp the pod build epoch unless the user chose one. Called by every
/// pod-side build entry point (own/loaded packages and closure-member
/// payloads) so nested builds inherit a deterministic timestamp even when
/// the outer build skipped it.
fn set_pod_build_epoch() {
    if std::env::var_os("SOURCE_DATE_EPOCH").is_none() {
        std::env::set_var("SOURCE_DATE_EPOCH", POD_BUILD_EPOCH);
    }
}

/// Build one declared package into a `.snap` payload with the normal
/// snap build path (`shuttle::snap::build_snap` — the same pipeline
/// `shuttle build` uses, sandbox included) and shape it as a pending
/// store install at the given composition layer. Local builds carry
/// revision 0; content identity is the payload's sha3-384, which is
/// what the no-op detection compares.
///
/// A package with a `deps` declaration builds against its verified,
/// store-mounted dependency closure (ADR-0017): the pin must exist —
/// own packages fetch it in [`ensure_own_deps`] right before this call;
/// a loaded package has no pin here and fails with a clear error (deps
/// resolve in the pod that declares the package).
///
/// A package with `requires`/`build_deps` builds against the merged
/// build prefix (ADR-0018, issue #35 — the same machinery the pool
/// `shuttle build` path uses): every closure member's payload is
/// ensured in the pod's downloads dir ([`ensure_pod_dep_payload`]) and
/// materialized into one `/usr`-like tree bound read-only into the
/// sandbox. The leak scan runs on the same data — pod-built payloads
/// carry no build-only references.
fn build_pending_snap(
    store: &crate::runtime::RuntimeStore,
    meta: &crate::snap::SnapMeta,
    layer: crate::farm::ClaimLayer,
    deps_pin: Option<&crate::lock::PackageDepsLock>,
) -> miette::Result<crate::runtime::PendingSnap> {
    set_pod_build_epoch();
    let deps_dir = match (meta.deps.as_ref(), deps_pin) {
        (Some(_), Some(pin)) => Some(crate::dep_fetch::materialize_deps_entry(
            store,
            &pin.deps_hash,
        )?),
        (Some(_), None) => miette::bail!(
            "package '{}' declares deps but no closure pin exists for it here — \
             dependency closures resolve in the pod that declares the package \
             (`shuttle deps fetch`)",
            meta.name
        ),
        (None, _) => None,
    };
    // Merged build prefix (ADR-0018, issue #35): `requires` ∪ `build_deps`
    // payloads ensured + merged, exactly like the pool path. None when the
    // package runs no build or declares neither list.
    let mut building: Vec<String> = vec![meta.name.clone()];
    let build_prefix = pod_build_prefix(store, meta, &mut building)?;
    let scan_listings = match &build_prefix {
        Some(p) => Some(crate::leak_scan::listings_for_build(meta, p)?),
        None => Some(crate::leak_scan::PayloadListings::default()),
    };
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
        // Issue #9: a pod build supplies its store so build-time interpreter
        // wrappers can bake the script's content-addressed store path.
        Some(store),
        deps_dir.as_ref().map(|d| d.path()),
        build_prefix.as_ref().map(|p| p.path()),
        scan_listings.as_ref(),
    )?;
    let payload = downloads.join(&result.snap_filename);
    let sha3_384 = crate::store::sha3_384_file(&payload)?;
    Ok(build_pending_snap_at(meta, &payload, sha3_384, layer))
}

/// Resolve `meta`'s build-time dependency closure (`requires` ∪
/// `build_deps`, transitively), ensure every member's payload is
/// available in the pod ([`ensure_pod_dep_payload`]), and materialize the
/// merged `/usr`-like build prefix (ADR-0018 Decision 2). The pod-side
/// twin of the pool path's `ensure_build_prefix`: `None` when the package
/// runs no build or declares neither list — nothing to bind.
///
/// The returned [`MergedPrefix`] owns its tempdir — the caller must keep
/// it alive for as long as the build runs.
fn pod_build_prefix(
    store: &crate::runtime::RuntimeStore,
    meta: &crate::snap::SnapMeta,
    building: &mut Vec<String>,
) -> miette::Result<Option<crate::build_prefix::MergedPrefix>> {
    // Only source builds consume a build prefix — meta/store snaps and
    // fetch-only declarations never run a build command.
    if meta.build.is_none() && meta.parts.is_none() {
        return Ok(None);
    }
    let seeds = crate::deps::build_dep_seeds(meta);
    if seeds.is_empty() {
        return Ok(None);
    }
    let closure_names = crate::deps::resolve_dep_names(&seeds, true)?;
    let mut payloads = Vec::new();
    for name in closure_names {
        let dep_meta = crate::deps::load_meta(&name)?;
        let snap = ensure_pod_dep_payload(store, &name, &dep_meta, building, false)?;
        payloads.push(crate::build_prefix::Payload { pkg: name, snap });
    }
    let merged = crate::build_prefix::materialize_merged_prefix(&payloads)?;
    if !payloads.is_empty() {
        let names: Vec<&str> = payloads.iter().map(|p| p.pkg.as_str()).collect();
        crate::output::status(format!(
            "build prefix: merged {} payload(s) — {}",
            payloads.len(),
            names.join(", ")
        ));
    }
    Ok(Some(merged))
}

/// Ensure one requires/build_deps member's built payload is available for
/// the merged build prefix: the pod's downloads dir first (a previous sync
/// or an earlier build this reconcile produced it), else build it there
/// now — giving the dependency its own merged prefix first, because its
/// build may need its own build-time deps (ADR-0018 applies to every
/// source build, pod builds included).
///
/// `building` is the in-progress stack for cycle detection: a circular
/// requires/build_deps chain fails with a clear chain instead of
/// recursing forever. `force_build` (issue #142) skips the cached
/// downloads hit: a recipe-drifted member must rebuild from its recipe,
/// and the fresh payload overwrites the stale cache entry.
fn ensure_pod_dep_payload(
    store: &crate::runtime::RuntimeStore,
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    building: &mut Vec<String>,
    force_build: bool,
) -> miette::Result<std::path::PathBuf> {
    set_pod_build_epoch();
    let downloads = store.downloads_dir();
    std::fs::create_dir_all(&downloads)
        .map_err(|e| miette::miette!("creating {}: {e}", downloads.display()))?;
    let existing = downloads.join(format!(
        "{}_{}_{}.snap",
        name,
        dep_meta.version,
        crate::snap::host_arch()
    ));
    if existing.exists() && !force_build {
        return Ok(existing);
    }

    if building.iter().any(|n| n == name) {
        miette::bail!(
            "circular dependency while building '{name}': {} → {name}",
            building.join(" → ")
        );
    }
    building.push(name.to_string());

    // The dependency's own build prefix (its requires ∪ build_deps,
    // transitively — a dep build is a build like any other, ADR-0018).
    let dep_prefix = pod_build_prefix(store, dep_meta, building)?;
    let scan_listings = match &dep_prefix {
        Some(p) => Some(crate::leak_scan::listings_for_build(dep_meta, p)?),
        None => Some(crate::leak_scan::PayloadListings::default()),
    };

    let stage =
        tempfile::tempdir().map_err(|e| miette::miette!("temp stage dir for {name}: {e}"))?;
    let result = crate::snap::build_snap(
        dep_meta,
        stage.path(),
        &downloads,
        crate::snap::host_arch(),
        crate::snap::StagePolicy::Default,
        // Same pod-store treatment as any pod build (issue #9 wrappers,
        // #12 ELF repair): the payload may expose host-run binaries.
        Some(store),
        None,
        dep_prefix.as_ref().map(|p| p.path()),
        scan_listings.as_ref(),
    )?;
    building.pop();
    Ok(downloads.join(&result.snap_filename))
}

/// Fetch (or verify the cached) dependency closure for an own pod package
/// BEFORE the sandboxed build consumes it (ADR-0017 Decision 7: add/sync
/// auto-fetch). `force_float` floats the closure regardless of the
/// meta's own float mode — the `pod rebuild --latest` seam (issue #15,
/// ADR-0017 Decision 5). Returns the pin to merge into the lockfile;
/// `None` when the package declares no deps.
fn ensure_own_deps(
    store: &crate::runtime::RuntimeStore,
    lock: &LockFile,
    meta: &crate::snap::SnapMeta,
    pkg_name: &str,
    force_float: bool,
) -> miette::Result<Option<crate::lock::PackageDepsLock>> {
    if meta.deps.is_none() {
        return Ok(None);
    }
    let prev = lock.packages.get(pkg_name).and_then(|e| e.deps.clone());
    let floating = force_float || meta.floating;
    let recipe_dir = crate::deps::recipe_dir(pkg_name);
    crate::dep_fetch::ensure_pod_deps(store, meta, prev.as_ref(), floating, recipe_dir.as_deref())
        .map(Some)
        .map_err(|e| miette::miette!("package '{pkg_name}': {e}"))
}

/// Shape a built, content-hashed payload as a [`PendingSnap`] at the
/// package's composition layer (issue #8). Store/pull installs use the
/// `Own` default. The resolved recipe's build-input digest rides along
/// (issue #113) — the install records it so a plain sync can hold
/// recipe-identical packages instead of rebuilding them.
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
        meta_digest: Some(meta.build_input_digest()),
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
        // Float marking (ADR-0017): the overlay wins, else the
        // declaration itself. Resolution failure is not a float.
        let floating = match decl
            .overlay
            .get(&spec.name)
            .and_then(|p| p.get("floating"))
            .and_then(|v| v.as_bool())
        {
            Some(b) => b,
            None => crate::deps::load_meta(&spec.name)
                .map(|m| m.floating)
                .unwrap_or(false),
        };
        entries.push(PodListEntry {
            spec: spec_str.clone(),
            name: spec.name,
            constraint: spec.constraint,
            version,
            pinned,
            floating,
        });
    }
    Ok(entries)
}

// ── Interactive shellenv (issue #47) ──

/// The environment a pod exposes to an interactive shell (issue #47):
/// the pod's bin farm behind its `current` link. `shuttle pod shellenv`
/// renders it as POSIX shell statements the user `eval`s — the
/// interactive half of farm activation (ADR-0015 §7: "a single PATH
/// prepend"), never an RC-file write, daemon, or watcher.
///
/// The loader half moved OUT of the shell env (issue #110, ADR-0034,
/// amending ADR-0028): exporting `LD_LIBRARY_PATH` here injected the
/// pod's extension libraries into every child of the hosting shell
/// (host curl lost TLS, nix git-remote-https failed cert checks, node
/// hit sqlite symbol mismatches). The emit now wraps each
/// libs-carrying app in a generation-scoped LD wrapper
/// (`farm::ld_wrappers`), so the pod's libraries ride only the
/// processes the pod launches and this export exports nothing but PATH
/// plus the declared env (ADR-0030).
#[derive(Debug, PartialEq, Serialize)]
pub struct PodShellenv {
    /// The pod this environment belongs to.
    pub pod: String,
    /// Absolute farm path for the PATH prepend:
    /// `<root>/<pod>/current`. Kept as the `current` LINK itself —
    /// never canonicalized through to the generation — so an already
    /// eval'd shell picks up rollback/update flips transparently (the
    /// activation seam, CONTEXT.md: Pod generation).
    pub farm: String,
    /// The generation the farm currently serves, when the `current`
    /// link's target parses.
    pub generation: Option<u64>,
    /// The generation's recorded declared env (ADR-0030): sorted key →
    /// literal value, read from `generations/<n>/env.json`. Empty for
    /// env-less generations; the renderer exports nothing and `shuttle
    /// run` overlays nothing in that case.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
}

/// Resolve the environment the selected pod exposes to an interactive
/// shell (issue #47). Read verb: fails on an unknown pod or one with no
/// active generation — pointing a shell's PATH at a missing farm would
/// fail silently at every command lookup, so there is no degraded mode.
/// The returned farm path is absolute (the root is canonicalized first;
/// the `current` segment stays a symlink), so the export is eval-safe
/// from any cwd.
pub fn shellenv(root: &Path, pod_name: &str) -> miette::Result<PodShellenv> {
    validate_pod_name(pod_name)?;
    let pod = pod_dir(root, pod_name);
    if !pod.is_dir() {
        miette::bail!(
            "pod '{pod_name}' has no state at {} (read verbs do not \
             initialize pods; `shuttle pod --name {pod_name} add <package>` does)",
            pod.display()
        );
    }
    let farm = pod.join(crate::farm::CURRENT_LINK);
    // Follows the link: a missing OR dangling `current` fails here, and
    // the error is the user-facing "sync first" one either way.
    std::fs::metadata(&farm).map_err(|_| {
        miette::miette!(
            "pod '{pod_name}' has no active generation at {} — sync the \
             pod first (`shuttle pod --name {pod_name} sync`)",
            farm.display()
        )
    })?;
    let root_abs = std::fs::canonicalize(root)
        .map_err(|e| miette::miette!("pod root {}: {e}", root.display()))?;
    let farm = root_abs.join(pod_name).join(crate::farm::CURRENT_LINK);
    let generation = crate::farm::current_generation(&pod)?;
    // The loader-lib list (issue #89) is no longer part of the shell
    // surface: issue #110 (ADR-0034) moved the seam into per-app LD
    // wrappers written by the farm emit, so no `LD_LIBRARY_PATH` is
    // exported here. The recorded list still feeds the wrappers and
    // `shuttle run`'s pod-scoped overlay.
    // ADR-0030: the generation's recorded declared env. A missing file
    // is a pre-env surface generation (or an env-less one) — an empty
    // map is the correct answer, exactly like the loader-lib list
    // handling in the farm emit above.
    let vars = match generation {
        Some(n) => read_generation_env(
            &pod.join("generations")
                .join(n.to_string())
                .join(crate::farm::ENV_FILE),
        )?,
        None => BTreeMap::new(),
    };
    Ok(PodShellenv {
        pod: pod_name.to_string(),
        farm: farm.display().to_string(),
        generation,
        vars,
    })
}

/// Parse a generation's recorded env object (ADR-0030): a JSON map of
/// sorted key → literal value. A missing file is a generation emitted
/// before the surface existed — an empty map is the correct answer. A
/// corrupt object fails the read verb loudly (the loader-lib reader's
/// rule for trusted data) — never a silently wrong export set.
fn read_generation_env(path: &Path) -> miette::Result<BTreeMap<String, String>> {
    let body = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => {
            return Err(miette::miette!("reading {}: {e}", path.display()));
        }
    };
    serde_json::from_str(&body)
        .map_err(|e| miette::miette!("corrupt generation env {}: {e}", path.display()))
}

/// POSIX single-quote a declared env value: every `'` becomes `'\''`
/// (close the quoting, an escaped quote, reopen), so the wrapped
/// literal survives any bytes the parser lets through (UTF-8, no
/// newlines).
fn sh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Render a shellenv as eval-safe POSIX shell statements (issue #47):
/// the PATH prepend plus the declared env exports (ADR-0030). Pure —
/// the JSON branch prints the struct instead.
///
/// The loader-lib `LD_LIBRARY_PATH` export lived here until issue #110
/// (ADR-0034) moved the seam into the emit-time LD wrappers: an env
/// export reached every child of the hosting shell and broke host curl,
/// nix git, and node. Nothing in the rendered script touches the
/// loader path anymore.
pub fn render_shellenv(env: &PodShellenv) -> String {
    let mut script = format!("export PATH=\"{}:$PATH\"\n", env.farm);
    // ADR-0030: one export per declared var, BTreeMap order (sorted —
    // byte-deterministic across syncs and rebuilds).
    for (key, value) in &env.vars {
        script.push_str(&format!("export {key}={}\n", sh_single_quote(value)));
    }
    script
}

// ── Dependency fetch (ADR-0017, issue #13) ──

/// One fetched (or verified) dependency closure in a
/// [`DepsFetchReport`].
#[derive(Debug, Serialize)]
pub struct DepsFetchedEntry {
    pub name: String,
    pub deps_hash: String,
    /// True when this fetch moved the closure content (float mode or a
    /// first fetch).
    pub changed: bool,
}

/// Report for `shuttle deps fetch`.
#[derive(Debug, Serialize)]
pub struct DepsFetchReport {
    pub pod: String,
    /// Packages whose closure was (re-)fetched and re-pinned.
    pub fetched: Vec<DepsFetchedEntry>,
    /// Locked packages whose pin is cached — untouched (no re-fetch).
    pub skipped: Vec<String>,
    /// Sideloaded (blob-pinned) packages: never re-resolve from the
    /// collection (issue #116) — the payload is their content, there
    /// is no collection meta to load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sideloaded: Vec<String>,
}

/// Explicit dependency-closure fetch for every declared package with a
/// `deps` section (ADR-0017 Decision 7): the float path and the "always
/// latest" knob. `latest` re-resolves even locked packages. Writes the
/// moved pins to the pod lockfile; no build, no install.
pub fn fetch_pod_deps(
    root: &Path,
    pod_name: &str,
    latest: bool,
) -> miette::Result<DepsFetchReport> {
    validate_pod_name(pod_name)?;
    let decl = load_declaration(root, pod_name)?;
    // Same validation-first discipline as sync: a bad declaration fails
    // with zero writes.
    validate_loads(root, pod_name, &decl)?;
    validate_overlays(root, &decl, pod_name)?;
    let dir = pod_dir(root, pod_name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("failed to create {}: {e}", dir.display()))?;
    let store = pod_store(&dir);
    let lock_path = pod_lock_path(root, pod_name);
    let mut lock = LockFile::load(&lock_path)?.unwrap_or_else(LockFile::empty);

    let mut report = DepsFetchReport {
        pod: pod_name.to_string(),
        fetched: Vec::new(),
        skipped: Vec::new(),
        sideloaded: Vec::new(),
    };
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        // Blob pins never re-resolve from the collection (issue #116,
        // the same skip `update` applies): the payload IS their
        // content, and `load_meta` here would die in collection
        // resolution — fatally on a collection-less machine — for a
        // package that was never a collection package at all.
        if lock.snaps.contains_key(&spec.name) {
            report.sideloaded.push(spec.name.clone());
            continue;
        }
        let mut meta = crate::deps::load_meta(&spec.name)?;
        if let Some(patch) = decl.overlay.get(&spec.name) {
            apply_overlay(&mut meta, patch)?;
        }
        let Some(_) = meta.deps.as_ref() else {
            continue;
        };
        let floating = meta.floating || latest;
        let prev = lock.packages.get(&spec.name).and_then(|e| e.deps.clone());
        // Locked + cached = the no-refetch guarantee; say so and move on.
        if !floating {
            if let Some(p) = &prev {
                if store.blob_path(&p.deps_hash).exists() {
                    report.skipped.push(spec.name.clone());
                    continue;
                }
            }
        }
        let old_hash = prev.as_ref().map(|p| p.deps_hash.clone());
        let recipe_dir = crate::deps::recipe_dir(&spec.name);
        let pin = crate::dep_fetch::ensure_pod_deps(
            &store,
            &meta,
            prev.as_ref(),
            floating,
            recipe_dir.as_deref(),
        )
        .map_err(|e| miette::miette!("package '{}': {e}", spec.name))?;
        let changed = old_hash.as_deref() != Some(pin.deps_hash.as_str());
        lock.packages
            .entry(spec.name.clone())
            .or_insert_with(|| PodPackageLockEntry {
                version: meta.version.clone(),
                constraint: spec.constraint.clone(),
                deps: None,
                recipe_sha256: None,
            })
            .deps = Some(pin.clone());
        report.fetched.push(DepsFetchedEntry {
            name: spec.name.clone(),
            deps_hash: pin.deps_hash,
            changed,
        });
    }
    lock.save(&lock_path)?;
    Ok(report)
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
        // Issue #109 S5: the name reaches unit file names and
        // Description= lines — control characters and quotes are
        // rejected; spaces stay legal (no injection vector).
        assert!(validate_pod_name("pod\n.service]").is_err());
        assert!(validate_pod_name("po\"d").is_err());
        assert!(validate_pod_name("po'd").is_err());
        assert!(validate_pod_name("my pod").is_ok());
    }

    // ── Pod-level service overrides (ADR-0032, issue #105) ──

    #[test]
    fn services_field_parses() {
        let decl = evaluate_pod_source(
            "test",
            r#"
            pod {
                packages = { "valkey" },
                services = {
                    valkey = { port = 6380, enabled = true },
                    wigolo = {},
                },
            }
        "#,
        )
        .unwrap();
        assert_eq!(decl.services["valkey"]["port"], serde_json::json!(6380));
        assert_eq!(decl.services["valkey"]["enabled"], serde_json::json!(true));
        assert!(decl.services["wigolo"].is_empty());
    }

    #[test]
    fn unknown_field_message_lists_services_as_allowed() {
        let err = evaluate_pod_source("test", r#"pod { pkgs = { "jq" } }"#)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("allowed: loads, packages, overlay, env, services"),
            "got: {err}"
        );
    }

    #[test]
    fn services_override_names_obey_the_name_constraint() {
        for bad in ["Valkey", "valkey_2", ""] {
            let entry = if bad.is_empty() {
                r#"[""] = {}"#.to_string()
            } else {
                format!("{bad} = {{}}")
            };
            let err = evaluate_pod_source("test", &format!("pod {{ services = {{ {entry} }} }}"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("invalid service name"),
                "override name {bad:?} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn services_override_values_are_scalars_only() {
        let err = evaluate_pod_source(
            "test",
            r#"pod { services = { valkey = { nested = { deep = 1 } } } }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("services.valkey.nested") && err.contains("scalar"),
            "got: {err}"
        );
    }

    #[test]
    fn service_declaration_renders_and_round_trips() {
        let decl = evaluate_pod_source(
            "test",
            r#"
            pod {
                services = { valkey = { port = 6380, enabled = true } },
            }
        "#,
        )
        .unwrap();
        let redecl = evaluate_pod_source("test", &render_pod_source(&decl)).unwrap();
        assert_eq!(redecl, decl, "render → evaluate must round-trip services");
    }

    #[test]
    fn resolve_service_options_merges_and_materializes_enabled() {
        let defaults = [
            ("port".to_string(), serde_json::json!(6379)),
            ("enabled".to_string(), serde_json::json!(false)),
        ]
        .into_iter()
        .collect();
        let overrides = [
            ("port".to_string(), serde_json::json!(6380)),
            ("enabled".to_string(), serde_json::json!(true)),
        ]
        .into_iter()
        .collect();
        let resolved = resolve_service_options(
            "valkey",
            &defaults,
            &overrides,
            "pod 'work'",
            "the package default",
        )
        .unwrap();
        assert_eq!(resolved.options["port"], serde_json::json!(6380));
        assert!(resolved.enabled, "pod override must win enablement");

        // Neither layer declares `enabled` → false (Decision 7).
        let resolved = resolve_service_options(
            "valkey",
            &BTreeMap::new(),
            &BTreeMap::new(),
            "pod 'work'",
            "the package default",
        )
        .unwrap();
        assert!(!resolved.enabled);
    }

    #[test]
    fn resolve_service_options_rejects_non_boolean_enabled() {
        let overrides = [("enabled".to_string(), serde_json::json!("true"))]
            .into_iter()
            .collect();
        let err = resolve_service_options(
            "valkey",
            &BTreeMap::new(),
            &overrides,
            "pod 'work'",
            "the package default",
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("must be a boolean"),
            "a quoted \"true\" must fail loudly, never silently disable: {err}"
        );
    }

    #[test]
    fn resolve_service_options_rejects_control_chars_in_override_strings() {
        // Issue #109 S5: pod-side override strings reach the same
        // render path as declared values (ExecStart args, interpola-
        // tion) — a control character is rejected at the merge
        // boundary, naming the key.
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "data_dir".to_string(),
            serde_json::json!("x\nKillMode=never"),
        );
        let err = resolve_service_options(
            "valkey",
            &BTreeMap::new(),
            &overrides,
            "pod 'work'",
            "the package default",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("options.data_dir") && err.contains("control characters"),
            "got: {err}"
        );
        // A quoted override stays legal — the emitter quotes/escapes
        // at render; only control characters are the boundary.
        let mut quoted = BTreeMap::new();
        quoted.insert(
            "msg".to_string(),
            serde_json::json!("it's a \"quoted\" value"),
        );
        resolve_service_options(
            "valkey",
            &BTreeMap::new(),
            &quoted,
            "pod 'work'",
            "the package default",
        )
        .expect("quoted override values must stay legal");
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
            sources: None,
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
            build_deps: vec![],
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: HashMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    // ── Content hold (issue #113) ──

    /// An installed record for `tool` with an optional build-input
    /// digest (the field a pre-#113 manifest carries `None` of).
    fn installed_tool(meta_digest: Option<String>) -> crate::runtime::InstalledPackage {
        crate::runtime::InstalledPackage {
            name: "tool".into(),
            version: "1.0".into(),
            revision: 1,
            sha3_384: "abc".into(),
            files: vec![],
            units: vec![],
            layer: crate::farm::ClaimLayer::Own,
            apps: BTreeMap::new(),
            requires: Vec::new(),
            launchers: BTreeMap::new(),
            assembly: BTreeMap::new(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
            fonts: BTreeMap::new(),
            services: BTreeMap::new(),
            service_bins: BTreeMap::new(),
            meta_digest,
        }
    }

    /// A generation carrying exactly one installed record.
    fn gen_with_record(record: crate::runtime::InstalledPackage) -> crate::runtime::Generation {
        let mut packages = BTreeMap::new();
        packages.insert(record.name.clone(), record);
        crate::runtime::Generation {
            n: 1,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    /// A reconcile context over a tempdir whose lock pins `tool` at
    /// 1.0 and whose active generation carries `record`.
    struct HoldFixture {
        _dir: tempfile::TempDir,
        store: crate::runtime::RuntimeStore,
        lock: LockFile,
        gen: crate::runtime::Generation,
    }

    fn hold_fixture(record: crate::runtime::InstalledPackage) -> HoldFixture {
        use std::collections::HashMap;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::runtime::RuntimeStore::new(dir.path().join("store"));
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };
        lock.packages.insert(
            "tool".to_string(),
            PodPackageLockEntry {
                version: "1.0".into(),
                constraint: None,
                deps: None,
                recipe_sha256: None,
            },
        );
        let gen = gen_with_record(record);
        HoldFixture {
            _dir: dir,
            store,
            lock,
            gen,
        }
    }

    impl HoldFixture {
        fn ctx(&self) -> ReconcileCtx<'_> {
            ReconcileCtx {
                store: &self.store,
                lock: &self.lock,
                active: Some(&self.gen),
                root: self._dir.path(),
                pod_name: "default",
            }
        }
    }

    /// Plain sync + digest match + the generation carries the package
    /// → HELD at the installed store content, no build queued.
    #[test]
    fn test_plain_sync_holds_when_the_recipe_matches_the_installed_record() {
        let mut meta = bare_meta("tool", "1.0");
        let fixture = hold_fixture(installed_tool(Some(meta.build_input_digest())));
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, false, false, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Held));
        assert_eq!(build.held, vec!["tool".to_string()]);
        assert!(
            build.pending.is_empty(),
            "a held package must not queue a build: {:?}",
            build.pending
        );
    }

    /// The recipe's build command changed → digest mismatch → the
    /// plain sync rebuilds (the whole point of the hold's sense: it
    /// skips only when the build inputs are identical).
    #[test]
    fn test_plain_sync_rebuilds_when_the_build_command_changed() {
        let mut installed_meta = bare_meta("tool", "1.0");
        installed_meta.build = Some("echo old".into());
        let fixture = hold_fixture(installed_tool(Some(installed_meta.build_input_digest())));

        let mut meta = bare_meta("tool", "1.0");
        meta.build = Some("echo new".into());
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, false, false, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Build));
        assert!(build.held.is_empty(), "a changed recipe must not hold");
    }

    /// `pod rebuild <pkg>` (scoped) bypasses the content hold even
    /// when the digest matches — a scoped rebuild is deliberate.
    #[test]
    fn test_scoped_rebuild_bypasses_the_content_hold() {
        let mut meta = bare_meta("tool", "1.0");
        let fixture = hold_fixture(installed_tool(Some(meta.build_input_digest())));
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, true, false, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Build));
        assert!(build.held.is_empty(), "scoped rebuild is never held");
    }

    /// Overlay packages never hold — the overlay may have changed the
    /// recipe in ways the installed record predates.
    #[test]
    fn test_overlay_package_never_content_holds() {
        let mut meta = bare_meta("tool", "1.0");
        let fixture = hold_fixture(installed_tool(Some(meta.build_input_digest())));
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, false, true, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Build));
        assert!(build.held.is_empty(), "overlay packages never hold");
    }

    /// A pre-#113 manifest carries no digest: it never holds — the
    /// first sync rebuilds once and records the digest, and the NEXT
    /// plain sync holds on the identical recipe.
    #[test]
    fn test_manifest_without_a_digest_rebuilds_once_then_holds() {
        let mut meta = bare_meta("tool", "1.0");
        let fixture = hold_fixture(installed_tool(None));
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, false, false, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Build));

        // The rebuild records its digest on the installed record —
        // simulated here by reinstalling the fixture with the digest.
        let fixture = hold_fixture(installed_tool(Some(meta.build_input_digest())));
        let mut build = ReconcileBuild::default();
        let scope =
            scope_own_package(&fixture.ctx(), true, false, false, &mut meta, &mut build).unwrap();
        assert!(matches!(scope, OwnScope::Held));
        assert_eq!(build.held, vec!["tool".to_string()]);
    }

    // ── Held-sync deps verification (issue #125) ──

    /// Record a deps pin for `tool` in the fixture's lockfile.
    fn pin_tool_deps(fixture: &mut HoldFixture, hash: &str) {
        fixture.lock.packages.get_mut("tool").unwrap().deps = Some(crate::lock::PackageDepsLock {
            deps_hash: hash.to_string(),
            fetched_at: None,
            lock_sha256: None,
        });
    }

    /// A content-held package with NO recorded deps pin skips
    /// verification: the loud failure must only fire on recorded pins
    /// (store/pull installs, deps-less declarations).
    #[test]
    fn test_held_sync_skips_verification_without_a_recorded_deps_pin() {
        let fixture = hold_fixture(installed_tool(Some(
            bare_meta("tool", "1.0").build_input_digest(),
        )));
        verify_held_deps_blob(&fixture.ctx(), "tool").unwrap();
    }

    /// An intact deps blob verifies cleanly on the held sync — the
    /// happy path keeps the #113 no-fetch hold (issue #125).
    #[test]
    fn test_held_sync_verifies_an_intact_deps_blob() {
        use sha2::{Digest, Sha256};
        let mut fixture = hold_fixture(installed_tool(Some(
            bare_meta("tool", "1.0").build_input_digest(),
        )));
        let content = b"closure bytes";
        let hash: String = Sha256::digest(content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let blob = fixture.store.blob_path(&hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, content).unwrap();
        pin_tool_deps(&mut fixture, &hash);
        verify_held_deps_blob(&fixture.ctx(), "tool").unwrap();
    }

    /// A MISSING deps blob fails the held sync loud: the hold never
    /// reads the blob, so the sync itself must (issue #125).
    #[test]
    fn test_held_sync_fails_loud_when_the_recorded_deps_blob_is_missing() {
        let mut fixture = hold_fixture(installed_tool(Some(
            bare_meta("tool", "1.0").build_input_digest(),
        )));
        let hash = "a1".repeat(32);
        pin_tool_deps(&mut fixture, &hash);
        let err = verify_held_deps_blob(&fixture.ctx(), "tool").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing from the pod store"),
            "must name the missing blob: {msg}"
        );
        assert!(
            msg.contains("held package 'tool'"),
            "must name the package: {msg}"
        );
    }

    /// A TAMPERED deps blob fails the held sync loud, fail-closed like
    /// materialize_deps_entry, naming recorded vs actual (issue #125).
    #[test]
    fn test_held_sync_fails_loud_when_the_recorded_deps_blob_is_tampered() {
        let mut fixture = hold_fixture(installed_tool(Some(
            bare_meta("tool", "1.0").build_input_digest(),
        )));
        let hash = "a1".repeat(32);
        let blob = fixture.store.blob_path(&hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"not the closure").unwrap();
        pin_tool_deps(&mut fixture, &hash);
        let err = verify_held_deps_blob(&fixture.ctx(), "tool").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("hash mismatch"),
            "must name the mismatch: {msg}"
        );
        assert!(msg.contains(&hash), "must name the recorded hash: {msg}");
        assert!(
            msg.contains("held package 'tool'"),
            "must name the package: {msg}"
        );
    }

    /// The wiring: a plain sync whose content hold hits a tampered deps
    /// blob fails the SCOPING loud — the hold is never recorded
    /// (issue #125).
    #[test]
    fn test_content_hold_fails_loud_when_the_deps_blob_is_tampered() {
        let mut meta = bare_meta("tool", "1.0");
        let mut fixture = hold_fixture(installed_tool(Some(
            bare_meta("tool", "1.0").build_input_digest(),
        )));
        let hash = "a1".repeat(32);
        let blob = fixture.store.blob_path(&hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"not the closure").unwrap();
        pin_tool_deps(&mut fixture, &hash);
        let mut build = ReconcileBuild::default();
        let err = scope_own_package(&fixture.ctx(), true, false, false, &mut meta, &mut build)
            .unwrap_err();
        assert!(
            format!("{err}").contains("hash mismatch"),
            "the content hold must refuse loud: {err}"
        );
        assert!(
            build.held.is_empty(),
            "a refused hold must not be recorded: {:?}",
            build.held
        );
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

    // ── shellenv (issue #47) ──

    /// Seed one pod with an active generation farm: the `current` link
    /// is created by the production flip mechanism (`crate::farm`), not
    /// by hand.
    fn seed_active_pod(root: &Path, pod: &str, generation: u64) {
        let dir = pod_dir(root, pod);
        let farm = dir
            .join("generations")
            .join(generation.to_string())
            .join("farm");
        std::fs::create_dir_all(&farm).unwrap();
        std::fs::write(farm.join("tool"), "#!/bin/sh\n").unwrap();
        crate::farm::flip_current(&dir, generation).unwrap();
    }

    #[test]
    fn test_shellenv_farm_path_is_the_current_link() {
        let tmp = tempfile::tempdir().unwrap();
        seed_active_pod(tmp.path(), "default", 3);

        let env = shellenv(tmp.path(), "default").unwrap();
        assert_eq!(env.pod, "default");
        assert_eq!(env.generation, Some(3));
        // Absolute (eval-safe from any cwd) and pointing at the
        // `current` LINK — never canonicalized through to the
        // generation, so rollback flips stay visible to the shell.
        let farm = PathBuf::from(&env.farm);
        assert!(farm.is_absolute(), "farm must be absolute: {env:?}");
        assert_eq!(
            farm,
            tmp.path().canonicalize().unwrap().join("default/current")
        );
    }

    #[test]
    fn test_shellenv_works_for_named_pods() {
        let tmp = tempfile::tempdir().unwrap();
        seed_active_pod(tmp.path(), "work", 1);

        let env = shellenv(tmp.path(), "work").unwrap();
        assert!(
            env.farm.ends_with("work/current"),
            "farm must be the work pod's: {env:?}"
        );
        assert_eq!(env.generation, Some(1));
    }

    #[test]
    fn test_shellenv_fails_on_unknown_pod() {
        let tmp = tempfile::tempdir().unwrap();
        let err = shellenv(tmp.path(), "ghost").unwrap_err().to_string();
        assert!(
            err.contains("ghost") && err.contains("add"),
            "error must name the pod and the initializing verb: {err}"
        );
    }

    #[test]
    fn test_shellenv_fails_without_active_generation() {
        let tmp = tempfile::tempdir().unwrap();
        // A declared but never-synced pod: state exists, no `current`.
        std::fs::create_dir_all(pod_dir(tmp.path(), "default")).unwrap();
        std::fs::write(pod_lua_path(tmp.path(), "default"), "pod { packages = {} }").unwrap();

        let err = shellenv(tmp.path(), "default").unwrap_err().to_string();
        assert!(
            err.contains("no active generation") && err.contains("sync"),
            "error must point at syncing: {err}"
        );
    }

    #[test]
    fn test_shellenv_fails_on_dangling_current() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = pod_dir(tmp.path(), "default");
        std::fs::create_dir_all(&dir).unwrap();
        // current → a generation that does not exist (torn state).
        std::os::unix::fs::symlink("generations/9/farm", dir.join("current")).unwrap();
        assert!(shellenv(tmp.path(), "default").is_err());
    }

    // ── shellenv loader-lib seam (issue #89) ──

    /// A minimal public-fields generation with one package, so the
    /// pod-level tests can drive `farm::emit` directly.
    fn gen_with_one_pkg(n: u64, pkg: &str) -> crate::runtime::Generation {
        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            crate::runtime::InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![],
                units: vec![],
                layer: crate::farm::ClaimLayer::Own,
                apps: BTreeMap::new(),
                requires: Vec::new(),
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
                fonts: BTreeMap::new(),
                services: BTreeMap::new(),
                service_bins: BTreeMap::new(),
                meta_digest: None,
            },
        );
        crate::runtime::Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    #[test]
    fn test_shellenv_exports_no_loader_libs_even_for_lib_payloads() {
        let tmp = tempfile::tempdir().unwrap();
        // The documented layout `<data-home>/shuttle/pods/<pod>`: the
        // emit's desktop/font surfaces derive their user-level dirs
        // from this shape, so every write stays inside the tempdir.
        let root = tmp.path().join("data/shuttle/pods");
        let dir = pod_dir(&root, "default");
        let store = pod_store(&dir);
        // Generation 1 carries a lib payload (the emit records its lib
        // dirs and writes the per-app LD wrappers); generation 2 does
        // not (the rollback target).
        let ext1 = store
            .generation_dir(1)
            .join("extensions/tmux-deps/usr/usr/lib");
        std::fs::create_dir_all(&ext1).unwrap();
        crate::farm::emit(&store, &gen_with_one_pkg(1, "tmux-deps")).unwrap();
        crate::farm::emit(&store, &gen_with_one_pkg(2, "tmux")).unwrap();
        crate::farm::flip_current(&dir, 1).unwrap();

        // Issue #110 (ADR-0034): the shell export carries NO loader
        // libs — the seam moved into the emit's per-app LD wrappers.
        // The wrappers themselves are the farm emit's contract (tested
        // there); here the absence from the shell surface is the point.
        let env = shellenv(&root, "default").unwrap();
        let script = render_shellenv(&env);
        assert!(
            !script.contains("LD_LIBRARY_PATH"),
            "shellenv must not export loader libs: {script}"
        );

        // Rollback semantics: the flipped-to generation re-emits and
        // the shell surface stays clean either way.
        crate::farm::flip_current(&dir, 2).unwrap();
        let env2 = shellenv(&root, "default").unwrap();
        assert!(
            !render_shellenv(&env2).contains("LD_LIBRARY_PATH"),
            "rollback target: {env2:?}"
        );
    }

    #[test]
    fn test_shellenv_without_a_loader_lib_list_exports_none() {
        let tmp = tempfile::tempdir().unwrap();
        // A generation emitted before the seam existed: no loader-libs
        // file. The shellenv must degrade to the #47 PATH-only export.
        seed_active_pod(tmp.path(), "default", 4);
        let env = shellenv(tmp.path(), "default").unwrap();
        assert_eq!(
            render_shellenv(&env),
            format!("export PATH=\"{}:$PATH\"\n", env.farm)
        );
    }

    #[test]
    fn test_render_shellenv_is_eval_safe_under_nounset() {
        let env = PodShellenv {
            pod: "default".into(),
            farm: "/root/default/current".into(),
            generation: Some(1),
            vars: BTreeMap::new(),
        };
        let script = render_shellenv(&env);
        assert_eq!(script, "export PATH=\"/root/default/current:$PATH\"\n");

        // The real proof: eval the script under `set -u` with
        // LD_LIBRARY_PATH unset, set, and empty. The rendered script
        // never mentions the variable (issue #110: the loader seam
        // moved into the emit's per-app wrappers), so the caller's
        // value passes through untouched in every case.
        let eval = |pre: Option<&str>| {
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(format!(
                "set -u\n{script}\nprintf '%s' \"${{LD_LIBRARY_PATH-__UNSET__}}\""
            ));
            match pre {
                Some(v) => cmd.env("LD_LIBRARY_PATH", v),
                None => cmd.env_remove("LD_LIBRARY_PATH"),
            };
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "stderr: {:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(eval(None), "__UNSET__");
        assert_eq!(eval(Some("keep")), "keep");
        assert_eq!(eval(Some("")), "");
    }

    // ── declared pod env (ADR-0030) ──

    /// Drop a `pod.lua` for `pod` under `root` (the fold tests drive
    /// real declarations on disk, exactly like production reads).
    fn seed_pod_lua(root: &Path, pod: &str, body: &str) {
        let dir = pod_dir(root, pod);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(pod_lua_path(root, pod), body).unwrap();
    }

    #[test]
    fn env_declaration_parses_and_reserved_seams_are_rejected() {
        let ok = evaluate_pod_source(
            "t",
            r#"pod { packages = { "jq" }, env = { EDITOR = "vi", EMPTY = "" } }"#,
        )
        .unwrap();
        assert_eq!(ok.env.get("EDITOR").map(String::as_str), Some("vi"));
        assert_eq!(ok.env.get("EMPTY").map(String::as_str), Some(""));

        for (src, needle) in [
            (r#"pod { env = { EDITOR = 5 } }"#, "'env.EDITOR'"),
            (r#"pod { env = { ["BAD-KEY"] = "v" } }"#, "invalid env key"),
            (r#"pod { env = { PATH = "/usr/bin" } }"#, "reserved"),
            (r#"pod { env = { LD_LIBRARY_PATH = "/x" } }"#, "reserved"),
            (r#"pod { env = { K = "a\nb" } }"#, "newlines"),
        ] {
            let err = format!("{}", evaluate_pod_source("t", src).unwrap_err());
            assert!(err.contains(needle), "{src}: {err}");
        }

        // The unknown-field message keeps naming the allowed set.
        let err = format!(
            "{}",
            evaluate_pod_source("t", "pod { nope = 1 }").unwrap_err()
        );
        assert!(err.contains("env"), "{err}");
    }

    #[test]
    fn resolve_pod_env_own_beats_loaded_and_loads_fold_transitively() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_pod_lua(root, "base", r#"pod { env = { A = "base", B = "base" } }"#);
        seed_pod_lua(
            root,
            "mid",
            r#"pod { loads = { "base" }, env = { B = "mid", C = "mid" } }"#,
        );
        seed_pod_lua(
            root,
            "work",
            r#"pod { loads = { "mid" }, env = { C = "work" } }"#,
        );
        let decl = load_declaration(root, "work").unwrap();
        let env = resolve_pod_env(root, "work", &decl).unwrap();
        assert_eq!(env.get("A").map(String::as_str), Some("base"));
        assert_eq!(env.get("B").map(String::as_str), Some("mid"));
        assert_eq!(env.get("C").map(String::as_str), Some("work"));
    }

    #[test]
    fn resolve_pod_env_first_declared_load_wins_cross_load_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_pod_lua(root, "one", r#"pod { env = { K = "one" } }"#);
        seed_pod_lua(root, "two", r#"pod { env = { K = "two" } }"#);
        seed_pod_lua(root, "work", r#"pod { loads = { "one", "two" } }"#);
        let decl = load_declaration(root, "work").unwrap();
        let env = resolve_pod_env(root, "work", &decl).unwrap();
        assert_eq!(
            env.get("K").map(String::as_str),
            Some("one"),
            "adding a later load must not silently steal an existing key"
        );
    }

    #[test]
    fn resolve_pod_env_detects_cycles_standalone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_pod_lua(root, "a", r#"pod { loads = { "b" } }"#);
        seed_pod_lua(root, "b", r#"pod { loads = { "a" } }"#);
        let decl = load_declaration(root, "a").unwrap();
        let err = format!("{}", resolve_pod_env(root, "a", &decl).unwrap_err());
        assert!(err.contains("cycle"), "{err}");
    }

    #[test]
    fn test_shellenv_serves_the_generation_env_and_the_flip_restores_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data/shuttle/pods");
        let dir = pod_dir(&root, "default");
        let store = pod_store(&dir);
        crate::farm::emit(&store, &gen_with_one_pkg(1, "jq")).unwrap();
        crate::farm::emit(&store, &gen_with_one_pkg(2, "fzf")).unwrap();
        let gen1_vars: BTreeMap<String, String> = [("EDITOR".to_string(), "vi".to_string())]
            .into_iter()
            .collect();
        let gen2_vars: BTreeMap<String, String> = [("MODE".to_string(), "pod".to_string())]
            .into_iter()
            .collect();
        crate::farm::write_generation_env(&store, 1, &gen1_vars).unwrap();
        crate::farm::write_generation_env(&store, 2, &gen2_vars).unwrap();

        crate::farm::flip_current(&dir, 1).unwrap();
        let env = shellenv(&root, "default").unwrap();
        assert_eq!(env.vars.get("EDITOR").map(String::as_str), Some("vi"));

        // Rollback semantics: the flip alone re-scopes the vars to the
        // target generation's RECORDED env — no rewrite, no
        // re-resolution against the current declaration.
        crate::farm::flip_current(&dir, 2).unwrap();
        let env2 = shellenv(&root, "default").unwrap();
        assert_eq!(env2.vars.get("MODE").map(String::as_str), Some("pod"));
        assert!(!env2.vars.contains_key("EDITOR"));
        crate::farm::flip_current(&dir, 1).unwrap();
        let env3 = shellenv(&root, "default").unwrap();
        assert_eq!(env3.vars.get("EDITOR").map(String::as_str), Some("vi"));
    }

    #[test]
    fn test_shellenv_without_an_env_object_exports_no_vars() {
        let tmp = tempfile::tempdir().unwrap();
        seed_active_pod(tmp.path(), "default", 4);
        let env = shellenv(tmp.path(), "default").unwrap();
        assert!(env.vars.is_empty());
        assert!(
            !serde_json::to_value(&env)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("vars"),
            "empty vars are omitted from the JSON output"
        );
        assert_eq!(
            render_shellenv(&env),
            format!("export PATH=\"{}:$PATH\"\n", env.farm)
        );
    }

    #[test]
    fn test_shellenv_fails_loudly_on_a_corrupt_generation_env() {
        let tmp = tempfile::tempdir().unwrap();
        seed_active_pod(tmp.path(), "default", 4);
        let env_file = pod_dir(tmp.path(), "default")
            .join("generations")
            .join("4")
            .join(crate::farm::ENV_FILE);
        std::fs::write(&env_file, "{not json").unwrap();
        let err = format!("{}", shellenv(tmp.path(), "default").unwrap_err());
        assert!(err.contains("corrupt generation env"), "{err}");
    }

    #[test]
    fn test_render_shellenv_exports_declared_vars_eval_safe() {
        let mut vars = BTreeMap::new();
        vars.insert("EDITOR".to_string(), "vi".to_string());
        vars.insert(
            "GREETING".to_string(),
            "it's $fine, 'quoted' with spaces".to_string(),
        );
        vars.insert("EMPTY".to_string(), String::new());
        vars.insert("A_FIRST".to_string(), "sorted".to_string());
        let env = PodShellenv {
            pod: "default".into(),
            farm: "/root/default/current".into(),
            generation: Some(1),
            vars,
        };
        let script = render_shellenv(&env);
        // Sorted keys, POSIX single-quote escaping (`'` → `'\''`).
        assert_eq!(
            script,
            "export PATH=\"/root/default/current:$PATH\"\n\
             export A_FIRST='sorted'\n\
             export EDITOR='vi'\n\
             export EMPTY=''\n\
             export GREETING='it'\\''s $fine, '\\''quoted'\\'' with spaces'\n"
        );

        // The real proof: eval under `set -u` and read the values back —
        // including the empty one, which must still count as SET.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "set -u\n{script}\nprintf '%s|%s|%s|%s' \
                 \"$A_FIRST\" \"$EDITOR\" \"$EMPTY\" \"$GREETING\""
            ))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "stderr: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "sorted|vi||it's $fine, 'quoted' with spaces"
        );

        // JSON carries the map when present, omits it when empty.
        let with = serde_json::to_value(&env).unwrap();
        assert_eq!(with["vars"]["EDITOR"], "vi");
        let bare = PodShellenv {
            vars: BTreeMap::new(),
            ..env
        };
        assert!(!serde_json::to_value(&bare)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("vars"));
    }

    #[test]
    fn present_active_records_the_declared_env_on_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data/shuttle/pods");
        let dir = pod_dir(&root, "default");
        let store = pod_store(&dir);
        crate::farm::emit(&store, &gen_with_one_pkg(1, "jq")).unwrap();
        // The store's active pointer, the way the production mechanisms
        // leave it: a manifest-bearing generation dir plus the `active`
        // link (as confine.rs's seed_command_pod does).
        let gen_dir = store.generation_dir(1);
        std::fs::write(
            gen_dir.join("manifest.json"),
            serde_json::to_vec(&gen_with_one_pkg(1, "jq")).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink("generations/1", dir.join("active")).unwrap();

        let vars: BTreeMap<String, String> = [("EDITOR".to_string(), "vi".to_string())]
            .into_iter()
            .collect();
        let (generation, _) = present_active(&store, &dir, &vars, &BTreeMap::new()).unwrap();
        assert_eq!(generation, Some(1));
        let recorded: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(crate::farm::env_path(&store, 1)).unwrap())
                .unwrap();
        assert_eq!(recorded, vars, "the staging tail records the resolved env");

        // Re-presenting with no declared env writes the empty object —
        // stale vars are withdrawn, the loader-libs re-emit rule.
        present_active(&store, &dir, &BTreeMap::new(), &BTreeMap::new()).unwrap();
        let recorded: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(crate::farm::env_path(&store, 1)).unwrap())
                .unwrap();
        assert!(recorded.is_empty());
    }
}
