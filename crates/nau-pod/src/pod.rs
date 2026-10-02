//! The pod grammar's PURE halves (issue #326 PR 6 crate extraction):
//! declaration/lockfile paths, package specs, the [`PodDeclaration`]
//! shape, `pod.lua` rendering, the load-graph walks (validate/fold),
//! the env/secrets folds, and the interactive shellenv.
//!
//! The load-graph walks take the declaration loader as a parameter
//! ([`PodDeclLoader`]): production passes the eval-coupled loader (the
//! root `load_declaration` — pod.lua EVAL stays root, mlua-direct);
//! this keeps the walks pure and testable over literals without
//! dragging an eval engine into the spine's dependent crates. The root
//! `pod` module keeps original-signature wrappers so every call site
//! (and the integration suite) is unchanged.
//!
//! The shellenv reads the pod's generation records through
//! [`nau_core::generation_view::StoreView`] (amendment 8) — never the
//! root `RuntimeStore`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use nau_core::generation_view::StoreView;
use nau_core::lock::LockFile;
use serde::Serialize;

// The secret-reference grammar lives beside its resolver
// ([`crate::secrets`]); the declaration carries references only.
pub use crate::secrets::SecretSource;

/// The declaration loader the load-graph walks use: resolves a loaded
/// pod's name to its validated declaration. Production passes the
/// eval-coupled loader (the root `load_declaration`); tests pass
/// declaration literals.
pub type PodDeclLoader<'a> = &'a dyn Fn(&str) -> miette::Result<PodDeclaration>;

/// The pod declaration file, inside the pod's state directory.
pub const POD_FILE: &str = "pod.lua";

// ── State layout ──

/// Path to a pod's `pod.lua`.
pub fn pod_lua_path(root: &Path, pod_name: &str) -> PathBuf {
    nau_core::paths::pod_dir(root, pod_name).join(POD_FILE)
}

/// Path to a pod's lockfile.
pub fn pod_lock_path(root: &Path, pod_name: &str) -> PathBuf {
    nau_core::paths::pod_dir(root, pod_name).join(LockFile::FILENAME)
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
    /// Declared secret references (`secrets = { KEY = { source =
    /// "bitwarden", id = "…" } }`, ADR-0042 D1) — references only, never
    /// values; values resolve at serve time (D3). Stored sorted like
    /// `env`, so the generation record is byte-canonical.
    pub secrets: BTreeMap<String, SecretSource>,
    /// Per-service option overrides (ADR-0032 Decision 3): service name →
    /// option overrides merged over each package-declared service's
    /// options (package defaults < loaded pods < this declaration).
    pub services: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// Server-front override (ADR-0052 Decision 6): this pod's ordered
    /// `servers` list, replacing the system config's list wholesale when
    /// non-empty (pod override → system list in order → named error).
    /// URLs, validated at parse time against
    /// `nau_core::servers::validate_server_url`; stored in declaration
    /// order — the order IS the try order.
    pub servers: Vec<String>,
}

// ── Rendering ──

/// Render a declaration back to `pod.lua` source. Only populated sections
/// are emitted; overlay tables re-render as plain data (they were
/// validated data-only at parse time).
pub fn render_pod_source(decl: &PodDeclaration) -> String {
    let mut out = String::new();
    out.push_str("-- Pod declaration, maintained by `nau pod add/remove`.\n");
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
    if !decl.servers.is_empty() {
        // ADR-0052 Decision 6: the pod-level servers override must
        // round-trip through `nau pod add/remove`/`declare` re-renders
        // like every other declared field.
        out.push_str(&format!(
            "    servers = {},\n",
            render_string_array(&decl.servers)
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
    if !decl.env.is_empty() {
        out.push_str("    env = {\n");
        for (key, value) in &decl.env {
            out.push_str(&format!(
                "        {} = {},\n",
                render_lua_key(key),
                render_lua_string(value)
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
    if !decl.secrets.is_empty() {
        out.push_str("    secrets = {\n");
        for (key, source) in &decl.secrets {
            out.push_str(&format!(
                "        {} = {},\n",
                render_lua_key(key),
                render_secret_source(source)
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

/// Render one secret reference as inline Lua (`{ source = "bitwarden",
/// id = "..." }`), strings escaped per [`render_lua_string`], so
/// `pod add`/`declare` round-trips through [`evaluate_pod_source`].
fn render_secret_source(source: &SecretSource) -> String {
    match source {
        SecretSource::Bitwarden { id } => {
            format!(
                "{{ source = \"bitwarden\", id = {} }}",
                render_lua_string(id)
            )
        }
        SecretSource::Vault { mount, path, field } => format!(
            "{{ source = \"vault\", mount = {}, path = {}, field = {} }}",
            render_lua_string(mount),
            render_lua_string(path),
            render_lua_string(field)
        ),
        SecretSource::Libsecret { attributes } => {
            let pairs: Vec<String> = attributes
                .iter()
                .map(|(k, v)| format!("{} = {}", render_lua_key(k), render_lua_string(v)))
                .collect();
            format!(
                "{{ source = \"libsecret\", attributes = {{ {} }} }}",
                pairs.join(", ")
            )
        }
        SecretSource::Exec { command } => format!(
            "{{ source = \"exec\", command = {} }}",
            render_string_array(command)
        ),
        SecretSource::Env { var } => {
            format!("{{ source = \"env\", var = {} }}", render_lua_string(var))
        }
    }
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

// ── Loads (issue #8) ──

/// Validate a pod's `loads` BEFORE any mutation: every loaded pod name
/// is valid and its declaration exists, and the load graph reachable
/// from `pod_name` contains no cycle (a self-load is a cycle of length
/// one). Pure reads — safe to run at the top of every mutating verb.
pub fn validate_loads(
    load: PodDeclLoader<'_>,
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<()> {
    for loaded in &decl.loads {
        nau_core::paths::validate_pod_name(loaded)
            .map_err(|e| miette::miette!("pod '{pod_name}' loads '{loaded}': {e}"))?;
        let path = pod_lua_path(root, loaded);
        if !path.exists() {
            miette::bail!(
                "pod '{pod_name}' loads '{loaded}', but pod '{loaded}' has no declaration \
                 at {} — create the loaded pod first \
                 (`nau pod --name {loaded} add <package>` initializes it)",
                path.display()
            );
        }
    }
    detect_load_cycle(load, pod_name, decl)?;
    refuse_loaded_blob_pins(load, root, pod_name, decl)
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
    load: PodDeclLoader<'_>,
    root: &Path,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<()> {
    fn visit(
        load: PodDeclLoader<'_>,
        root: &Path,
        pod_name: &str,
        decl: &PodDeclaration,
        visited: &mut HashSet<String>,
    ) -> miette::Result<()> {
        for loaded in &decl.loads {
            if !visited.insert(loaded.clone()) {
                continue;
            }
            let loaded_decl = load(loaded)?;
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
            visit(load, root, pod_name, &loaded_decl, visited)?;
        }
        Ok(())
    }
    let mut visited = HashSet::new();
    visit(load, root, pod_name, decl, &mut visited)
}

/// Sibling pods whose load graph (transitively) reaches `pod_name`
/// (issue #135 loader-side brick): once this pod carries a blob pin,
/// [`refuse_loaded_blob_pins`] refuses every mutating verb of each of
/// them. Best-effort read-only scan — a pod without a declaration or
/// with an unreadable one is skipped; the warning must never fail the
/// add.
pub fn pods_loading(load: PodDeclLoader<'_>, root: &Path, pod_name: &str) -> Vec<String> {
    fn reaches(
        load: PodDeclLoader<'_>,
        from: &str,
        target: &str,
        seen: &mut HashSet<String>,
    ) -> bool {
        let Ok(decl) = load(from) else {
            return false;
        };
        for loaded in &decl.loads {
            if loaded == target
                || (seen.insert(loaded.clone()) && reaches(load, loaded, target, seen))
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
        if reaches(load, &name, pod_name, &mut seen) {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// DFS over the load graph reachable from `start`: a pod revisited on
/// the current path is a cycle, named in full (`work -> base -> work`).
/// Fully-explored pods are memoized — a DAG branch is walked once.
fn detect_load_cycle(
    load: PodDeclLoader<'_>,
    start: &str,
    start_decl: &PodDeclaration,
) -> miette::Result<()> {
    fn visit(
        load: PodDeclLoader<'_>,
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
                let loaded_decl = load(loaded)?;
                visit(load, loaded, &loaded_decl, stack, done)?;
            }
            Ok(())
        })();
        stack.pop();
        done.insert(pod.to_string());
        result
    }
    let mut stack = Vec::new();
    let mut done = HashSet::new();
    visit(load, start, start_decl, &mut stack, &mut done)
}

/// Resolve the pod's declared env (ADR-0030): own keys win per key over
/// loaded pods (silent — the issue #8 own-over-loaded rule); loaded
/// pods fold transitively, and a same-key collision between two loaded
/// pods resolves to the FIRST-DECLARED load with a warning (determinism
/// over surprise: adding a later load never silently steals an
/// existing key). Pure reads — safe before any mutation.
pub fn resolve_pod_env(
    load: PodDeclLoader<'_>,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<BTreeMap<String, String>> {
    let folded = fold_pod_env(load, pod_name, decl, &mut Vec::new(), &mut HashSet::new())?;
    Ok(folded.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

/// Resolve the pod's declared secret references (ADR-0042 D2): own keys
/// win per key over loaded pods (silent — the same own-over-loaded rule
/// as [`resolve_pod_env`]); loaded pods fold transitively. The one
/// deliberate tightening vs env: a same-key collision between two
/// loaded pods is a HARD ERROR naming the key and both pods, not a
/// warning — env literals are inert, but a losing credential reference
/// silently changes live credentials under masking. Pure reads — safe
/// before any mutation.
/// `pod secrets` reference resolution (ADR-0042, issue #183): the pod's
/// own folded secret references and its active generation.
pub fn resolve_pod_secrets(
    load: PodDeclLoader<'_>,
    pod_name: &str,
    decl: &PodDeclaration,
) -> miette::Result<BTreeMap<String, SecretSource>> {
    let folded = fold_pod_secrets(load, pod_name, decl, &mut Vec::new(), &mut HashSet::new())?;
    Ok(folded.into_iter().map(|(k, (v, _))| (k, v)).collect())
}

/// The secrets fold proper: key → (reference, declaring pod). The
/// provenance rides along so a cross-load collision can name both pods
/// in its hard error; [`resolve_pod_secrets`] strips it. Memoized +
/// cycle-checked so it is safe standalone, not only behind
/// [`validate_loads`].
fn fold_pod_secrets(
    load: PodDeclLoader<'_>,
    pod_name: &str,
    decl: &PodDeclaration,
    stack: &mut Vec<String>,
    done: &mut HashSet<String>,
) -> miette::Result<BTreeMap<String, (SecretSource, String)>> {
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
        let mut secrets: BTreeMap<String, (SecretSource, String)> = BTreeMap::new();
        for loaded in &decl.loads {
            let loaded_decl = load(loaded)?;
            for (key, contributed) in fold_pod_secrets(load, loaded, &loaded_decl, stack, done)? {
                match secrets.entry(key.clone()) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(contributed);
                    }
                    std::collections::btree_map::Entry::Occupied(e) => {
                        let (_, holder) = e.get();
                        let (_, claimant) = &contributed;
                        miette::bail!(
                            "secret '{key}' is declared by more than one loaded pod under \
                             '{pod_name}' (pod '{holder}' and pod '{claimant}') — \
                             secret-key collisions across loads are a hard error, not a \
                             warning (ADR-0042 D2: a losing credential reference silently \
                             changes live credentials under masking)"
                        );
                    }
                }
            }
        }
        for (key, source) in &decl.secrets {
            secrets.insert(key.clone(), (source.clone(), pod_name.to_string()));
        }
        Ok(secrets)
    })();
    stack.pop();
    folded
}

/// The fold proper: key → (value, declaring pod). The provenance rides
/// along so a cross-load collision can name both pods in its warning;
/// `resolve_pod_env` strips it. Memoized + cycle-checked so it is safe
/// standalone, not only behind [`validate_loads`].
fn fold_pod_env(
    load: PodDeclLoader<'_>,
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
            let loaded_decl = load(loaded)?;
            for (key, contributed) in fold_pod_env(load, loaded, &loaded_decl, stack, done)? {
                match env.entry(key.clone()) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(contributed);
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        nau_infra::output::warn(format!(
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

// ── Interactive shellenv (issue #47) ──

/// The environment a pod exposes to an interactive shell (issue #47):
/// the pod's bin farm behind its `current` link. `nau pod shellenv`
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
/// plus the declared env (ADR-0030) — and *clears* any ambient
/// loader-lib value the hosting shell inherited (issue #311: a stale
/// pre-#110 ancestor would otherwise keep poisoning host flatpak/curl
/// /node until it dies).
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
    /// env-less generations; the renderer exports nothing and `nau
    /// run` overlays nothing in that case.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, String>,
    /// Resolved secret values (ADR-0042 D3, issue #184): the recorded
    /// references resolved at serve time, all-or-nothing (D7). The
    /// renderer exports these AFTER the env lines; `nau run`
    /// overlays them onto the exec'd process with the same
    /// declared-replaces-inherited rule. NEVER serialized (D8): the
    /// JSON branch of `pod shellenv` must not become a value
    /// exfiltration path — [`Self::secrets`] is the only `--json` face.
    #[serde(skip)]
    pub secret_vars: BTreeMap<String, String>,
    /// Per-secret serve metadata for `--json` (D8): the source kind and
    /// session-cache state only, never a value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, crate::secrets::SecretMeta>,
}

/// Resolve the environment the selected pod exposes to an interactive
/// shell (issue #47). Read verb: fails on an unknown pod or one with no
/// active generation — pointing a shell's PATH at a missing farm would
/// fail silently at every command lookup, so there is no degraded mode.
/// The returned farm path is absolute (the root is canonicalized first;
/// the `current` segment stays a symlink), so the export is eval-safe
/// from any cwd.
pub fn shellenv(root: &Path, pod_name: &str) -> miette::Result<PodShellenv> {
    shellenv_with(root, pod_name, None)
}

/// [`shellenv`] with an explicit secrets session-cache base (tests —
/// the production path derives `$XDG_RUNTIME_DIR` inside the resolve).
/// `None` keeps the default derivation, tmpfs gate included.
pub fn shellenv_with(
    root: &Path,
    pod_name: &str,
    secrets_cache_base: Option<&Path>,
) -> miette::Result<PodShellenv> {
    nau_core::paths::validate_pod_name(pod_name)?;
    let pod = nau_core::paths::pod_dir(root, pod_name);
    if !pod.is_dir() {
        miette::bail!(
            "pod '{pod_name}' has no state at {} (read verbs do not \
             initialize pods; `nau pod --name {pod_name} add <package>` does)",
            pod.display()
        );
    }
    let farm = pod.join(crate::farm::CURRENT_LINK);
    // Follows the link: a missing OR dangling `current` fails here, and
    // the error is the user-facing "sync first" one either way.
    std::fs::metadata(&farm).map_err(|_| {
        miette::miette!(
            "pod '{pod_name}' has no active generation at {} — sync the \
             pod first (`nau pod --name {pod_name} sync`)",
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
    // `nau run`'s pod-scoped overlay.
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
    // ADR-0042 D3 (issue #184): resolve the generation's RECORDED
    // secret references — never the declaration, the same read rule as
    // `env.json` (a rollback must serve the target generation's pinned
    // refs, not a re-resolution against a moved declaration). The
    // resolve is all-or-nothing (D7): an unreachable provider fails the
    // verb named, never a partial export set — and it also materializes
    // the 0600 runtime envfile the service units reference.
    let (secret_vars, secrets) = shellenv_secrets(&pod, pod_name, generation, secrets_cache_base)?;
    Ok(PodShellenv {
        pod: pod_name.to_string(),
        farm: farm.display().to_string(),
        generation,
        vars,
        secret_vars,
        secrets,
    })
}

/// The shellenv's secrets half (split out to keep [`shellenv_with`]
/// small): the active generation's recorded `secrets.json` through the
/// ONE serve step. Empty refs (a secret-less generation) never touch
/// `$XDG_RUNTIME_DIR` — the D3 empty rule.
fn shellenv_secrets(
    pod: &Path,
    pod_name: &str,
    generation: Option<u64>,
    secrets_cache_base: Option<&Path>,
) -> miette::Result<(
    BTreeMap<String, String>,
    BTreeMap<String, crate::secrets::SecretMeta>,
)> {
    let Some(n) = generation else {
        return Ok((BTreeMap::new(), BTreeMap::new()));
    };
    // The pod state root's paired `<state-root>/store` blob store —
    // the same construction the root glue's `pod_store(..).store_view()`
    // performs (amendment 8's pairing invariant).
    let view = {
        let blobs = nau_core::blob_store::BlobStore::new(pod.join("store"));
        StoreView::new(pod.to_path_buf(), blobs)
    };
    let refs = crate::farm::read_generation_secrets(&view, n)?;
    if refs.is_empty() {
        return Ok((BTreeMap::new(), BTreeMap::new()));
    }
    let served = crate::secrets::serve_pod(pod, pod_name, n, &refs, secrets_cache_base)?;
    Ok((served.values, served.meta))
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
/// the PATH prepend, the loader-lib strip, and the declared env exports
/// (ADR-0030). Pure — the JSON branch prints the struct instead.
///
/// The loader-lib `LD_LIBRARY_PATH` export lived here until issue #110
/// (ADR-0034) moved the seam into the emit-time LD wrappers: an env
/// export reached every child of the hosting shell and broke host curl,
/// nix git, and node. Issue #311 completed the seam: shells launched
/// from pre-#110 ancestors (a stale eval, or a long-lived daemon
/// started under one) still carry the poisoned ambient value for as
/// long as that ancestor lives, so the render now *clears* all four
/// loader-lib vars instead of merely not exporting them. Pod payloads
/// get loader env only from their wrappers, per process.
pub fn render_shellenv(env: &PodShellenv) -> String {
    let mut script = format!("export PATH=\"{}:$PATH\"\n", env.farm);
    // The wrappers (farm::ld_wrappers, issue #164) set LD_LIBRARY_PATH
    // and LIBRARY_PATH and clear CPATH/COMPILER_PATH per pod process,
    // so an ambient value here can only be stale inheritance — poison
    // to every host binary the shell launches (flatpak/curl TLS deaths,
    // node symbol mismatches, gcc startfile loss).
    script.push_str("unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n");
    // ADR-0030: one export per declared var, BTreeMap order (sorted —
    // byte-deterministic across syncs and rebuilds).
    for (key, value) in &env.vars {
        script.push_str(&format!("export {key}={}\n", sh_single_quote(value)));
    }
    // ADR-0042 D3 (issue #184): secret exports come AFTER the env
    // exports — one POSIX single-quoted export per resolved secret,
    // sorted keys. Single quotes survive any bytes the providers yield,
    // newline-bearing PEM values included; the same
    // declared-replaces-inherited rule `nau run` overlays with.
    for (key, value) in &env.secret_vars {
        script.push_str(&format!("export {key}={}\n", sh_single_quote(value)));
    }
    script
}

// ── Tests (the literal-pure population; eval/fixture tests stay root) ──

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
    fn render_round_trips_the_servers_override() {
        // ADR-0052 Decision 6: the pod-level servers override must
        // survive `nau pod add/remove`/`declare` re-renders like every
        // other declared field.
        let decl = PodDeclaration {
            packages: vec!["jq".into()],
            servers: vec![
                "https://primary.example/nau".into(),
                "http://backup.example:7780".into(),
            ],
            ..Default::default()
        };
        let source = render_pod_source(&decl);
        assert!(
            source.contains(
                "servers = { \"https://primary.example/nau\", \
                             \"http://backup.example:7780\" }"
            ),
            "the override renders in declaration order: {source}"
        );
        // Absent servers render nothing (zero behavior change).
        let bare = render_pod_source(&PodDeclaration::default());
        assert!(!bare.contains("servers"), "{bare}");
    }

    #[test]
    fn test_render_shellenv_is_eval_safe_under_nounset() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let env = PodShellenv {
            pod: "default".into(),
            farm: "/root/default/current".into(),
            generation: Some(1),
            vars: BTreeMap::new(),
            secret_vars: BTreeMap::new(),
            secrets: BTreeMap::new(),
        };
        let script = render_shellenv(&env);
        assert_eq!(
            script,
            "export PATH=\"/root/default/current:$PATH\"\n\
             unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n"
        );

        // The real proof: eval the script under `set -u` with each
        // loader var unset, set, and empty. Issue #110 moved the seam
        // into the emit's per-app wrappers; issue #311 makes the eval
        // actively clear what it inherited, so a stale pre-#110
        // ancestor's poisoned value cannot reach this shell's children
        // in any case.
        let eval = |pre: Option<&str>| {
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(format!(
                "set -u\n{script}\nprintf '%s' \"${{LD_LIBRARY_PATH-__UNSET__}},\
                 ${{LIBRARY_PATH-__UNSET__}},${{CPATH-__UNSET__}},${{COMPILER_PATH-__UNSET__}}\""
            ));
            match pre {
                Some(v) => {
                    for k in ["LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "COMPILER_PATH"] {
                        cmd.env(k, v);
                    }
                }
                None => {
                    for k in ["LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "COMPILER_PATH"] {
                        cmd.env_remove(k);
                    }
                }
            };
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "stderr: {:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(eval(None), "__UNSET__,__UNSET__,__UNSET__,__UNSET__");
        assert_eq!(
            eval(Some("keep")),
            "__UNSET__,__UNSET__,__UNSET__,__UNSET__"
        );
        assert_eq!(eval(Some("")), "__UNSET__,__UNSET__,__UNSET__,__UNSET__");
    }

    #[test]
    fn test_render_shellenv_exports_declared_vars_eval_safe() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
            secret_vars: BTreeMap::new(),
            secrets: BTreeMap::new(),
        };
        let script = render_shellenv(&env);
        // Sorted keys, POSIX single-quote escaping (`'` → `'\''`),
        // and the #311 loader strip right after the PATH prepend.
        assert_eq!(
            script,
            "export PATH=\"/root/default/current:$PATH\"\n\
             unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n\
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
}
