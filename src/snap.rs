use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};

use mlua::Value;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;
use sha2::Digest;

use crate::output;

// ── Snap pinning (references to external snaps) ──

/// A reference to a snap from the Snap Store, optionally pinned by revision
/// and content hash for reproducibility.
///
/// Created by the `pin()` DSL function:
/// ```lua
/// pin("core22")                                    -- name only
/// pin("core22", { revision = 1847 })               -- + revision
/// pin("core22", { revision = 1847, sha3_384 = "…" }) -- fully pinned
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SnapRef {
    pub name: String,
    pub revision: Option<u32>,
    /// sha3-384 hex digest (lowercase, without prefix).
    pub sha3_384: Option<String>,
}

impl SnapRef {
    /// Create from a Lua pin table (validated by the DSL).
    pub fn from_pin_table(table: &mlua::Table) -> miette::Result<Self> {
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

// ── Reproducible builds: source pinning ──

/// How a source was specified: bare URL, or URL + pinning hash.
#[derive(Debug, Clone)]
pub enum SourceSpec {
    /// Just a URL — no hash verification (legacy).
    Unverified(String),
    /// URL + expected SHA-256 hash for pinning.
    Pinned { url: String, sha256: String },
}

impl SourceSpec {
    pub fn url(&self) -> &str {
        match self {
            SourceSpec::Unverified(url) => url,
            SourceSpec::Pinned { url, .. } => url,
        }
    }

    /// The SHA-256 hash the source is expected to have, if pinned.
    pub fn expected_sha256(&self) -> Option<&str> {
        match self {
            SourceSpec::Unverified(_) => None,
            SourceSpec::Pinned { sha256, .. } => Some(sha256),
        }
    }
}

/// Serialize as a plain URL string (for `meta/snap.yaml` backward compat).
impl Serialize for SourceSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.url().serialize(serializer)
    }
}

// ── Build result ──

/// Info about a downloaded source, for lockfile recording.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub url: String,
    pub sha256: String,
}

/// Result of building one snap, including lockfile-relevant metadata.
#[derive(Debug)]
pub struct BuildResult {
    /// The output `.snap` filename (e.g. `hello_2.10_amd64.snap`).
    pub snap_filename: String,
    /// The snap version actually built: the declared version, or the
    /// version extracted at build time for adopt-info snaps (the declared
    /// placeholder never reaches the filename).
    pub version: String,
    /// Source info if a source was downloaded and processed.
    pub source_info: Option<SourceInfo>,
}

// ── Package inputs (inspired by Nix flake inputs) ──

/// A package input source — declares where to fetch package definitions from.
///
/// URL schemes:
///   `github:user/repo[/branch]` — GitHub repository (cloned shallow)
///   `path:/local/dir`            — Local filesystem path
#[derive(Debug, Clone, Serialize)]
pub struct PackageInput {
    /// URL in Nix-inspired format (e.g. "github:rbelem/shuttle/main",
    /// "path:/home/user/pkgs").
    pub url: String,
}

/// Dependency-closure declaration (ADR-0017, issue #13): which ecosystem
/// resolvers a package needs and where their lockfiles live. Coexists with
/// `source` (hybrid), stands alone, or is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageDeps {
    /// npm resolver: `deps = { npm = { lock = "package-lock.json" } }`.
    pub npm: Option<DepsLockSpec>,
    /// pip resolver: `deps = { pip = { lock = "requirements.lock" } }`.
    pub pip: Option<DepsLockSpec>,
}

/// One ecosystem resolver's spec: its lockfile (relative to the source
/// root) and, for index-driven ecosystems, the index to resolve against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepsLockSpec {
    /// Lockfile path relative to the source root (e.g.
    /// "package-lock.json", "requirements.lock").
    pub lock: String,
    /// Package index URL (pip only; default: the official PyPI simple
    /// index). npm resolves from the lockfile's own `resolved` URLs.
    pub index: Option<String>,
}

// ── Phase 3: Snap metadata structs ──

/// Top-level metadata for one snap output.
///
/// Maps directly to the `meta/snap.yaml` schema that snapd expects.
#[derive(Debug, Clone, Serialize)]
pub struct SnapMeta {
    pub name: String,
    pub version: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    /// Source identity (URL + optional pinned hash). Build-time only —
    /// snapd's snap.yaml schema has no top-level `source:` key, so emitting
    /// it risks rejecting the snap. Identity lives in the lockfile
    /// (`sources:`) and the binary-cache closure instead.
    #[serde(skip)]
    pub source: Option<SourceSpec>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,

    /// Build command (shell). If set, tool fetches source and runs build
    /// before snap assembly. Skipped in YAML — build-time only.
    #[serde(skip)]
    pub build: Option<String>,

    /// Multi-part build: part name → build spec. Parts run sequentially in
    /// `after`-dependency order into a shared `$STAGE`. Mutually exclusive
    /// with `build` (enforced in the DSL, re-checked at build time).
    /// Skipped in YAML — build-time only.
    #[serde(default, skip)]
    pub parts: Option<BTreeMap<String, SnapPart>>,

    #[serde(default = "default_grade")]
    pub grade: String,

    #[serde(default = "default_confinement")]
    pub confinement: String,

    /// Snap type. Doubles as a shuttle build classification
    /// ("source"/"meta"/"store" — build-time only, skipped in YAML) and the
    /// snapd `type` field ("app"/"base"/"gadget"/"kernel"/"snapd").
    /// snapd defaults to "app", so `type:` is only emitted for the non-app
    /// snapd types.
    #[serde(
        default,
        rename = "type",
        skip_serializing_if = "skip_internal_or_default_type"
    )]
    pub type_: Option<String>,

    /// Name of the part whose metadata (version/summary/description) this
    /// snap adopts. Build-time only — snapd's snap.yaml schema has no
    /// `adopt-info` key (it is a snapcraft build-time key), so it is never
    /// emitted: the concrete values are extracted from the built part at
    /// build time (see [`extract_adopted_meta`]) and written into snap.yaml.
    #[serde(skip)]
    pub adopt_info: Option<String>,

    /// True when `version` is the adopt-info placeholder ("0") — no
    /// explicit version was declared and the real one arrives at build
    /// time. Marks the placeholder so no identity output ever presents it
    /// as declared. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub version_adopted: bool,

    /// Source path of the icon file from the DSL (e.g. "icon.png").
    /// Build-time only — the file is copied to `meta/gui/icon.<ext>` and
    /// the `icon` field below points there, as snapd expects.
    #[serde(skip)]
    pub icon_source: Option<String>,

    /// Path of the icon inside the snap (e.g. "meta/gui/icon.png").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// SquashFS compression for mksquashfs ("xz" or "lzo"). Build-time only
    /// — snap.yaml has no compression field; it's a property of the image.
    #[serde(default, skip)]
    pub compression: Option<String>,

    /// Global environment variables applied to every app in the snap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,

    /// Filesystem layout overrides: target path → one of bind/bind-file/
    /// symlink/tmpfs, matching snapd's `layout:` schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<BTreeMap<String, LayoutEntry>>,

    /// Hook scripts: hook name → command. The source script is copied to
    /// `meta/hooks/<name>` during build; `command` points there per snapd
    /// convention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<BTreeMap<String, SnapHook>>,

    /// Typed snap-level plugs: name → interface name or attribute table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugs: Option<BTreeMap<String, SnapPlug>>,

    /// Typed snap-level slots: name → interface name or attribute table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<BTreeMap<String, SnapPlug>>,

    /// Alternative names this package is known by. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub aliases: Vec<String>,

    /// Build/runtime dependencies. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub requires: Vec<String>,

    /// Runtime confinement grants (ADR-0016, ticket #11). Present
    /// (`Some`) declares the package `confined`; absent is `unconfined`
    /// (the default for simple CLIs). Emitted into snap.yaml so it
    /// survives the pod build → install pipeline (the runtime emitter
    /// records it in the generation manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,

    /// Package input references. Maps input name to a URL.
    /// Example: `{ packages = { url = "github:rbelem/shuttle/main" } }`
    /// Skipped in YAML — build metadata only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<HashMap<String, PackageInput>>,

    /// Cross-compilation target triplet (e.g. "x86_64-linux-gnu", "aarch64-linux-gnu").
    /// When set, the build sandbox sets CC/CXX/LD/etc to the cross-compiler and
    /// exports CONFIGURE_TARGET for autotools-based packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Name of the toolchain meta-package to use for builds (e.g. "toolchain-gcc-gnu-x86_64").
    /// Controls which compiler/linker are mounted into the build sandbox.
    /// Default: host system toolchain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<String>,

    #[serde(default)]
    pub apps: HashMap<String, SnapApp>,

    /// Dependency-closure declaration (ADR-0017, issue #13): ecosystem
    /// resolvers with their lockfiles, e.g.
    /// `deps = { npm = { lock = "package-lock.json" } }`. Build-time only —
    /// never emitted into snap.yaml (the closure ships as ordinary payload
    /// files; the resolver spec has no runtime meaning).
    #[serde(skip)]
    pub deps: Option<PackageDeps>,

    /// Float mode (ADR-0017, issue #13): opt-in per package via the
    /// declaration (`floating = true`) or a pod overlay. Locked (default,
    /// false): sync never re-fetches a cached closure. Floating: sync
    /// re-resolves and records the new hash — still hash-verified.
    #[serde(skip)]
    pub floating: bool,

    /// Directory of the definition file this output came from, threaded
    /// from the eval label in `lua.rs`. Used to resolve build-time file
    /// references (hook scripts, icon) relative to the definition first;
    /// `None` for non-file labels (embedded definitions) and non-DSL
    /// constructors, which fall back to the process CWD. Build-time only.
    #[serde(skip)]
    pub definition_dir: Option<std::path::PathBuf>,
}

/// Skip `type:` in snap.yaml for shuttle build classifications
/// ("source"/"meta"/"store") and snapd's default ("app").
fn skip_internal_or_default_type(t: &Option<String>) -> bool {
    !matches!(t.as_deref(), Some("base" | "gadget" | "kernel" | "snapd"))
}

fn default_grade() -> String {
    "stable".to_string()
}

fn default_confinement() -> String {
    "strict".to_string()
}

/// An app declared inside a snap.
#[derive(Debug, Clone, Serialize)]
pub struct SnapApp {
    pub command: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugs: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,

    /// Path to the app's `.desktop` file inside the snap (like snapd's
    /// `desktop:` app key; issue #7). The pod launcher emitter parses it
    /// at install time and generates the user-level entry from it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,

    /// For an interpreter-based app (issue #9): the interpreter the app's
    /// command script runs under (e.g. `node`). When a pod build emits a
    /// command binary that is a script (not a native ELF), a launcher
    /// wrapper is authored into the store payload at build time so the
    /// farm's direct symlink points at a working wrapper. Native-ELF
    /// commands get no wrapper.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,

    /// Per-app runtime confinement override (ticket #11): wins over the
    /// snap-level `confined` for this app. Present (`Some`) declares the
    /// app confined; `None` inherits the snap's value. Emitted into
    /// snap.yaml so it survives the pod build → install pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,
}

// ── Runtime confinement (ADR-0016, ticket #11) ──

/// The two runtime confinement levels (ADR-0016 Decision 1): a package
/// either runs unconfined on the host (the pod farm's direct-symlink
/// model, the default for simple CLIs) or confined inside a backend
/// sandbox with declared grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfinementLevel {
    Unconfined,
    Confined,
}

/// The backend keyword selecting the enforcement mechanism (ADR-0016
/// Decision 3). Both backends honor the SAME shared grants vocabulary, so
/// they are interchangeable for anything expressible in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    /// bubblewrap (unprivileged user namespaces)
    #[default]
    Bwrap,
    /// AppArmor profile + seccomp filter
    Apparmor,
}

impl BackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendKind::Bwrap => "bwrap",
            BackendKind::Apparmor => "apparmor",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "bwrap" => Some(BackendKind::Bwrap),
            "apparmor" => Some(BackendKind::Apparmor),
            _ => None,
        }
    }
}

/// The shared confinement grants vocabulary (ADR-0016 Decision 5) — the
/// portable contract both backends honor.
///
/// Defaults deny: no filesystem mounts, no network, no sockets, no
/// devices. A package author declares precisely what a confined app may
/// reach; `backend_options` is the non-portable finetune escape hatch
/// (warned as lost when switching backends).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Confinement {
    #[serde(default)]
    pub backend: BackendKind,
    /// Filesystem grants: a list of path/host mounts. The portable
    /// keywords `read` and `write` grant read-only / read-write access to
    /// the standard host roots; any other entry is a path bound at its
    /// own location (an optional `ro:`/`rw:` prefix selects the access
    /// mode, default read-write).
    #[serde(default)]
    pub filesystem: Vec<String>,
    /// Network access: false (default) denies the net namespace.
    #[serde(default)]
    pub network: bool,
    /// Named socket grants (e.g. `wayland`, `x11`, `ssh-auth`, `pulseaudio`,
    /// `session-bus`).
    #[serde(default)]
    pub sockets: Vec<String>,
    /// Device grants (e.g. `/dev/dri`, `/dev/input`).
    #[serde(default)]
    pub devices: Vec<String>,
    /// Non-portable, backend-specific raw flags (ADR-0016 Decision 4).
    /// Lost when switching backends — the shared grants remain the
    /// portability contract.
    #[serde(default)]
    pub backend_options: BTreeMap<String, serde_json::Value>,
}

impl Confinement {
    /// The per-app effective confinement: an app-level override wins,
    /// else the package-level one.
    pub fn for_app<'a>(
        app_confined: Option<&'a Confinement>,
        snap_confined: Option<&'a Confinement>,
    ) -> Option<&'a Confinement> {
        app_confined.or(snap_confined)
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

// ── Phase 15: snap.yaml coverage structs ──

/// tmpfs layout spec: bare `true` or `{ size = "…" }`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TmpfsSpec {
    Bare(bool),
    Sized { size: String },
}

/// One `layout:` entry — exactly one of bind / bind-file / symlink / tmpfs.
/// Serializes as a single-key plain map, matching snapd's schema:
/// `bind: $SNAP/...`, `bind-file: $SNAP_DATA/...`, `symlink: ...`,
/// `tmpfs: true|{ size: ... }`.
///
/// Hand-written (not `#[derive(Serialize)]`) because serde_yaml renders
/// derived enum variants with `!Tag` annotations, which snapd rejects.
#[derive(Debug, Clone, PartialEq)]
pub enum LayoutEntry {
    Bind(String),
    BindFile(String),
    Symlink(String),
    Tmpfs(TmpfsSpec),
}

impl serde::Serialize for LayoutEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            LayoutEntry::Bind(v) => map.serialize_entry("bind", v)?,
            LayoutEntry::BindFile(v) => map.serialize_entry("bind-file", v)?,
            LayoutEntry::Symlink(v) => map.serialize_entry("symlink", v)?,
            LayoutEntry::Tmpfs(spec) => map.serialize_entry("tmpfs", spec)?,
        }
        map.end()
    }
}

/// A typed plug or slot: `interface` plus string-valued attributes
/// flattened beside it in snap.yaml:
///
/// ```yaml
/// plugs:
///   shared-data:
///     interface: content
///     content: my-content
///     target: $SNAP/data
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlugSlot {
    pub interface: String,

    /// Interface-specific attributes (content, target, default_provider, …).
    #[serde(flatten)]
    pub attributes: BTreeMap<String, String>,
}

/// A snap-level plug or slot value: a bare interface name (back-compat,
/// `plugs = { "network" }`) or a typed attribute table.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SnapPlug {
    Name(String),
    Typed(PlugSlot),
}

/// A hook: `command` is the in-snap path snapd executes (always
/// `meta/hooks/<name>`, per snapcraft convention); `source` is the script
/// path from the DSL, copied to that location at build time.
#[derive(Debug, Clone, Serialize)]
pub struct SnapHook {
    pub command: String,

    /// Source script path from the DSL (build-time only, skipped in YAML).
    #[serde(skip)]
    pub source: String,
}

/// One part of a multi-part build: a shell command plus optional `after`
/// dependencies (names of parts that must complete first).
///
/// Per-part sources/inputs are future work — today every part shares the
/// snap's single source and identical sandbox env/inputs; only the command
/// and the ordering edges are per-part.
///
/// A part may instead select a built-in builder plugin (ADR-0014): `plugin`
/// names the plugin and `plugin_options` carries its raw options table.
/// `build` and `plugin` are mutually exclusive (a plugin IS the build);
/// plugin parts carry an empty `build` marker string.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapPart {
    pub build: String,
    pub after: Vec<String>,
    /// Built-in builder plugin name (ADR-0014). Build-time only.
    pub plugin: Option<String>,
    /// Raw plugin options (deep-validated by the plugin at the Rust
    /// boundary). Build-time only — never emitted to snap.yaml.
    pub plugin_options: Option<BTreeMap<String, crate::plugins::PluginValue>>,
}

// ── Conversion from Lua (Phase 3) ──
//
// Per ADR-0002: Lua validates at eval time so Rust is a passive consumer.
// These conversions extract pre-validated fields — errors here indicate
// internal bugs or version mismatches, not user config errors.

impl SnapMeta {
    /// Convert from an `mlua::Value` (must be a table).
    pub fn from_lua_value(value: &mlua::Value) -> miette::Result<Self> {
        match value {
            Value::Table(table) => Self::from_lua_table(table),
            other => Err(miette::miette!(
                "expected a table from snap(), got {}",
                other.type_name()
            )),
        }
    }

    /// Convert a validated Lua table (from `snap()`) into a `SnapMeta`.
    pub fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
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
        let grade = get_opt_string(table, "grade")?.unwrap_or_else(default_grade);
        let confinement = get_opt_string(table, "confinement")?.unwrap_or_else(default_confinement);
        let architectures = get_opt_string_array(table, "architectures")?;
        let build = get_opt_string(table, "build")?;
        let parts = get_opt_parts(table)?;
        let type_: Option<String> = table.get("type").ok();
        let icon_source = get_opt_string(table, "icon")?;
        let icon = icon_target_from_source(icon_source.as_deref())?;
        let compression = get_opt_string(table, "compression")?;
        let environment = get_opt_string_map(table, "environment")?;
        let layout = get_opt_layout(table)?;
        let hooks = get_opt_hooks(table)?;
        let plugs = get_opt_plug_map(table, "plugs")?;
        let slots = get_opt_plug_map(table, "slots")?;
        let aliases: Vec<String> = table.get("aliases").unwrap_or_default();
        let mut requires: Vec<String> = table.get("requires").unwrap_or_default();
        // Plugin parts contribute extra requires (e.g. `cargo` pulls the
        // rust toolchain package) — expanded and deep-validated here so the
        // Rust boundary is the single choke point (ADR-0014 Decisions 3-4).
        // Dependency resolution reads this same field.
        if let Some(parts) = &parts {
            append_plugin_requires(parts, &mut requires)?;
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
        // A dependency closure resolves from the source tree (the lockfile
        // ships in the source tarball), so `deps` without `source` can
        // never fetch. Fail at the parse boundary, not mid-fetch.
        if deps.is_some() && source.is_none() {
            return Err(miette::miette!(
                "snap meta: 'deps' requires 'source' — the lockfile resolves from the package source tree"
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

        Ok(SnapMeta {
            name,
            version,
            version_adopted,
            summary,
            description,
            license,
            source,
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
            environment,
            layout,
            hooks,
            plugs,
            slots,
            aliases,
            requires,
            target,
            toolchain,
            inputs,
            confined,
            apps,
            deps,
            floating,
            definition_dir: None,
        })
    }
}

/// Parse the `deps` table (ADR-0017): `{ npm = { lock = ... }, pip = { lock
/// = ..., index = ... } }` — at least one resolver, known keys only, every
/// resolver carrying a non-empty string `lock`.
fn package_deps_from_lua(t: &mlua::Table) -> miette::Result<PackageDeps> {
    let mut npm = None;
    let mut pip = None;
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
            "npm" | "pip" => {
                let lock = get_opt_string(&value, "lock")?.ok_or_else(|| {
                    miette::miette!("deps.{key}: field 'lock' is required (lockfile path relative to the source root)")
                })?;
                if lock.is_empty() {
                    return Err(miette::miette!("deps.{key}: 'lock' must not be empty"));
                }
                if lock.starts_with('/') {
                    return Err(miette::miette!(
                        "deps.{key}: 'lock' is relative to the source root — got absolute path '{lock}'"
                    ));
                }
                let index = get_opt_string(&value, "index")?;
                let spec = DepsLockSpec { lock, index };
                if key == "npm" {
                    npm = Some(spec);
                } else {
                    pip = Some(spec);
                }
            }
            other => {
                return Err(miette::miette!(
                    "deps: unknown resolver '{other}' (supported: npm, pip)"
                ))
            }
        }
    }
    if npm.is_none() && pip.is_none() {
        return Err(miette::miette!(
            "deps must name at least one resolver: npm or pip"
        ));
    }
    Ok(PackageDeps { npm, pip })
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

impl LayoutEntry {
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

impl PlugSlot {
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

impl SnapApp {
    /// Convert a validated Lua table (from `app()`) into a `SnapApp`.
    /// `name` is the app's key in `apps`, used to name errors.
    ///
    /// Unknown fields are rejected here (not silently dropped): anything
    /// the schema doesn't know would otherwise vanish between the DSL and
    /// the emitted snap.yaml — the same silent-drop bug class as outputs
    /// (e.g. a template emitting `restart_condition`, which the schema
    /// never supported).
    pub fn from_lua_table(name: &str, table: &mlua::Table) -> miette::Result<Self> {
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
/// validation happens at the plugin boundary ([`crate::plugins::expand`]).
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
) -> miette::Result<Option<BTreeMap<String, crate::plugins::PluginValue>>> {
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

/// Convert one plugin option value into a [`crate::plugins::PluginValue`].
fn plugin_value_from_lua(
    label: &str,
    value: &Value,
) -> miette::Result<crate::plugins::PluginValue> {
    match value {
        Value::String(s) => Ok(crate::plugins::PluginValue::Str(lua_str(s)?)),
        Value::Boolean(b) => Ok(crate::plugins::PluginValue::Bool(*b)),
        Value::Table(t) => plugin_table_value(label, t),
        other => Err(miette::miette!(
            "{label} must be a string, boolean, array of strings, or table of strings, got {}",
            other.type_name()
        )),
    }
}

/// Classify an option table: all-integer keys → ordered array of strings,
/// all-string keys → string map, empty → empty map, mixed → error.
fn plugin_table_value(label: &str, t: &mlua::Table) -> miette::Result<crate::plugins::PluginValue> {
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
        return Ok(crate::plugins::PluginValue::Map(map));
    }
    if !map.is_empty() {
        return Ok(crate::plugins::PluginValue::Map(map));
    }
    items.sort_by_key(|(index, _)| *index);
    Ok(crate::plugins::PluginValue::Arr(
        items.into_iter().map(|(_, s)| s).collect(),
    ))
}

/// Copy an mlua string into an owned Rust String.
fn lua_str(s: &mlua::String) -> miette::Result<String> {
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
    for (name, part) in parts {
        let Some(plugin) = &part.plugin else {
            continue;
        };
        let plan = crate::plugins::expand(plugin, part.plugin_options.as_ref())
            .map_err(|e| miette::miette!("parts['{name}']: {e}"))?;
        for require in plan.extra_requires {
            if !requires.contains(&require) {
                requires.push(require);
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

/// Extract `inputs` table: maps name → PackageInput { url }.
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
            Ok(Some(inputs))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "'inputs' must be a table, got {}",
            other.type_name()
        )),
    }
}

// ── Phase 4: YAML serialization ──

impl SnapMeta {
    /// Serialize to YAML string (the `meta/snap.yaml` content).
    pub fn to_yaml(&self) -> miette::Result<String> {
        serde_yaml::to_string(self)
            .map_err(|e| miette::miette!("failed to serialize snap metadata to YAML: {}", e))
    }

    /// The version to show in identity output (`shuttle check`, build
    /// status): an adopt-info snap has no declared version until build
    /// time, and the "0" placeholder must never read as one.
    pub fn display_version(&self) -> &str {
        if self.adopt_info.is_some() && self.version_adopted {
            "(version adopted at build)"
        } else {
            &self.version
        }
    }
}

// ── Phase 5/6: Snap directory assembly + SquashFS packaging ──

/// Who owns the stage directory for a build.
///
/// Tracks whether `--stage` was passed explicitly (the CLI flag is
/// `Option<String>`; `None` means shuttle's default `./stage/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagePolicy {
    /// No `--stage` flag: the stage is shuttle-owned scratch space. Its
    /// contents are wiped whenever a build phase is about to populate it,
    /// so leftovers from previous builds can never leak into a new snap.
    /// (A build-less snap — pre-built binaries staged by hand — never
    /// reaches the wipe: its stage is the input, not an output.)
    Default,
    /// `--stage` passed explicitly: the directory belongs to the user and
    /// is never wiped. It must be empty (or new) to start; `shuttle build`
    /// refuses up front otherwise — see [`check_explicit_stage`].
    Explicit,
}

/// One-time guard at the start of `shuttle build`: an explicitly passed
/// `--stage` directory that already exists and is non-empty is refused.
/// shuttle never deletes a user-chosen directory.
pub fn check_explicit_stage(stage_dir: &Path) -> miette::Result<()> {
    let nonempty = stage_dir.exists()
        && std::fs::read_dir(stage_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
    if nonempty {
        return Err(miette::miette!(
            "stage directory '{}' exists and is not empty — refusing to build. \
             shuttle never deletes a directory passed via --stage; pass a fresh \
             (empty or new) directory, or omit --stage to let shuttle wipe and \
             manage its default './stage/' automatically.",
            stage_dir.display()
        ));
    }
    Ok(())
}

/// Wipe and recreate the shuttle-owned default stage. Only called right
/// before a build phase populates it.
fn clear_stage_dir(stage_dir: &Path) -> miette::Result<()> {
    if stage_dir.exists() {
        std::fs::remove_dir_all(stage_dir).map_err(|e| {
            miette::miette!("failed to clear stage dir {}: {}", stage_dir.display(), e)
        })?;
    }
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| miette::miette!("failed to create stage dir {}: {}", stage_dir.display(), e))
}

/// Host architecture in snapd naming ("amd64", "arm64", …). Rust's
/// `consts::ARCH` passes through unchanged for other targets.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Leading-component architecture of a GNU target triplet.
/// "aarch64-linux-gnu" → Some("arm64"), "x86_64-linux-gnu" → Some("amd64"),
/// "arm-linux-gnueabihf" → Some("armhf"). Unknown vendor/OS suffixes are not
/// interpreted: the first component maps by the rules above, else identity.
fn triplet_arch(triplet: &str) -> Option<&str> {
    let first = triplet.split('-').next()?;
    match first {
        "x86_64" | "amd64" => Some("amd64"),
        "aarch64" | "arm64" => Some("arm64"),
        "arm" => Some("armhf"),
        other => Some(other),
    }
}

/// Refuse builds whose requested architecture cannot be produced honestly.
///
/// Building for a foreign arch without a cross toolchain silently produces
/// `arm64`-named snaps full of host binaries. Allowed when:
/// * the arch is `"all"` (arch-independent), or
/// * it matches the host arch, or
/// * a cross toolchain is configured for exactly that arch (a `--target`
///   triplet — or the snap's own `target` field — whose leading component
///   names the requested arch).
pub fn check_cross_build(arch: &str, target: Option<&str>) -> miette::Result<()> {
    if arch == "all" || arch == host_arch() {
        return Ok(());
    }
    if target.is_some_and(|t| triplet_arch(t) == Some(arch)) {
        return Ok(());
    }
    let hint = match arch {
        "arm64" => "aarch64-linux-gnu",
        "amd64" => "x86_64-linux-gnu",
        _ => "<triplet>",
    };
    Err(match target {
        Some(t) => miette::miette!(
            "refusing to build for '{arch}' on this {host} host: --target '{t}' does \
             not select an {arch} toolchain (expected a triplet like {hint}); the \
             build would silently pack {host} binaries into an {arch} snap",
            host = host_arch(),
        ),
        None => miette::miette!(
            "refusing to build for '{arch}' on this {host} host: no cross toolchain \
             is configured, so the snap would silently contain {host} binaries. \
             Pass --target <triplet> (e.g. --target {hint}) to select a cross \
             toolchain, or build for '{host}'",
            host = host_arch(),
        ),
    })
}

/// Author build-time launcher wrappers (issues #9 and #10).
///
/// Two cases, both authored into the store payload at build time — the nix
/// `makeWrapper`/`wrapProgram` analogy — so the pod farm's direct symlink
/// points at a working launcher and the farm never adds shims:
///
/// 1. **Interpreter script (issue #9).** An app declaring `interpreter`
///    (e.g. `interpreter = "node"`) whose command binary is a **script**
///    (no native ELF magic) gets a wrapper: the original script is preserved
///    at a sibling `<command>.real` path (still shipped in the payload) and
///    the command path is replaced by a wrapper that single-`exec`s the
///    interpreter with the script's content-addressed store path, e.g.
///    `exec "node" "$POD/store/aa/<sha256>" "$@"`.
///
/// 2. **Native-ELF with bundled runtime libs (issue #10 part B).** A native
///    ELF command binary that needs shared libraries the payload itself
///    ships (`libjq.so.1`, `libonig.so.5` for jq — separate content-
///    addressed store blobs, NOT on the binary's runpath) gets a wrapper:
///    the real ELF is preserved at `<command>.real` and the command path is
///    replaced by a wrapper that sets `LD_LIBRARY_PATH` to the active
///    generation's name-preserving lib dir (where those blobs are
///    hardlinked) and single-`exec`s the real binary's store blob.
///
/// Native-ELF packages whose libs are already resolvable (no bundled libs)
/// get NO wrapper; apps without an `interpreter` were never touched by #9
/// and only get wrapped by #10 when they bundle a runtime lib.
///
/// Runs only when a pod store is provided (the build is a pod build) —
/// `pod_store` is used to bake the command's future store blob path, which
/// is only defined for a pod content store.
fn emit_build_wrappers(
    meta: &SnapMeta,
    stage_dir: &Path,
    pod_store: &crate::runtime::RuntimeStore,
) -> miette::Result<()> {
    for (app_name, app) in &meta.apps {
        wrap_app(app_name, app, meta, stage_dir, pod_store)?;
    }
    Ok(())
}

/// Wrap one app's command, if it qualifies (see [`emit_build_wrappers`]).
fn wrap_app(
    app_name: &str,
    app: &SnapApp,
    meta: &SnapMeta,
    stage_dir: &Path,
    pod_store: &crate::runtime::RuntimeStore,
) -> miette::Result<()> {
    if app.interpreter.as_deref() == Some("") {
        return Err(miette::miette!(
            "app '{app_name}': 'interpreter' must not be empty"
        ));
    }
    let Some(cmd_path) = crate::units::resolve_command_path(&app.command) else {
        return Ok(());
    };
    let entry = stage_dir.join(&cmd_path);
    if !entry.is_file() {
        // A missing command binary is caught later by the install-time
        // planner's fail-closed lookup — nothing to wrap.
        return Ok(());
    }

    // Ticket #11: a confined app gets a separate launcher wrapper blob
    // (at `<command>.shuttle-launcher`) that invokes `shuttle run`. The
    // farm's direct symlink for a confined app points at this wrapper,
    // so `which`/PATH stay truthful while `shuttle run` sets up the
    // sandbox. The real command binary stays untouched — `apps[app]`
    // still records it and `shuttle run` execs it inside the sandbox.
    if Confinement::for_app(app.confined.as_ref(), meta.confined.as_ref()).is_some() {
        emit_confined_launcher(app_name, &entry, pod_store)?;
    }

    if is_elf(&entry) {
        // Issue #10 part B: native-ELF wrapper ONLY when the payload
        // bundles a runtime lib the binary needs (separate store blob
        // not on its runpath). Already-resolvable ELFs stay unwrapped.
        let lib_dirs = bundled_runtime_lib_dirs(&entry, stage_dir);
        if lib_dirs.is_empty() {
            return Ok(());
        }
        emit_elf_lib_wrapper(app_name, &entry, &lib_dirs, meta, pod_store)
    } else {
        // Issue #9: interpreter-script wrapper.
        let Some(interpreter) = &app.interpreter else {
            return Ok(());
        };
        if meta.deps.is_some() {
            // ADR-0017 (issue #13): with a dependency closure the app
            // must run from the generation's extension tree, where the
            // staged `node_modules`/site-packages sit next to the
            // script (require()/sys.path resolve relative to the
            // script). A file-blob store path (the #9 default) would
            // strand the interpreter with no modules beside it.
            emit_script_tree_wrapper(app_name, &entry, interpreter, &meta.name, &cmd_path)
        } else {
            emit_script_wrapper(app_name, &entry, interpreter, pod_store)
        }
    }
}

/// The preserved-script sibling name. Inserts `.real` before the final
/// extension when there is one (`index.js` → `index.real.js`), else
/// appends (`zdemo` → `zdemo.real`). The extension must survive: Node's
/// ESM loader dispatches on it and rejects `index.js.real` with
/// ERR_UNKNOWN_FILE_EXTENSION.
fn real_sibling_name(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}.real.{ext}"),
        _ => format!("{file_name}.real"),
    }
}

/// Author the interpreter-script wrapper (issue #9) for a command path
/// that is a shebang/script (not native ELF).
fn emit_script_wrapper(
    app_name: &str,
    entry: &Path,
    interpreter: &str,
    pod_store: &crate::runtime::RuntimeStore,
) -> miette::Result<()> {
    // Preserve the original script in the payload at a sibling path, then
    // replace the command path with the wrapper. The wrapper references
    // the script by its content-addressed store blob path (computed here
    // at build time from the script's sha256 — deterministic, so ingest
    // later stores it at the same path).
    let file_name = entry
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let script_path = entry.with_file_name(real_sibling_name(&file_name));
    std::fs::rename(entry, &script_path).map_err(|e| {
        miette::miette!(
            "app '{app_name}': preserving interpreter script {}: {e}",
            script_path.display()
        )
    })?;
    let script_sha256 = sha256_file(&script_path).map_err(|e| {
        miette::miette!(
            "app '{app_name}': hashing interpreter script {}: {e}",
            script_path.display()
        )
    })?;
    let script_store_path = pod_store.blob_path(&script_sha256);

    let wrapper = format!(
        "#!/bin/sh\nexec \"{}\" \"{}\" \"$@\"\n",
        interpreter,
        script_store_path.display()
    );
    write_wrapper(app_name, entry, &wrapper)
}

/// Author the interpreter-script wrapper for a package WITH a dependency
/// closure (ADR-0017, issue #13): same preserve-and-replace shape as
/// [`emit_script_wrapper`], but the wrapper execs the `.real` script from
/// the active generation's extension tree —
/// `$PODROOT/active/extensions/<pkg>/usr/<command>.real` — where modules
/// staged next to it (`node_modules`, site-packages) resolve. PODROOT is
/// derived from the wrapper's own store-blob path (`store/<aa>/<hash>`),
/// the same derivation the #10 ELF lib wrapper uses.
fn emit_script_tree_wrapper(
    app_name: &str,
    entry: &Path,
    interpreter: &str,
    pkg_name: &str,
    cmd_rel: &str,
) -> miette::Result<()> {
    let file_name = entry
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let script_path = entry.with_file_name(real_sibling_name(&file_name));
    std::fs::rename(entry, &script_path).map_err(|e| {
        miette::miette!(
            "app '{app_name}': preserving interpreter script {}: {e}",
            script_path.display()
        )
    })?;
    // The extension-preserving sibling in the extension tree (same rule
    // as the preserve-rename above, applied to the command's relative
    // path — the tree path must name the SAME file).
    let cmd_rel_real = match cmd_rel.rsplit_once('/') {
        Some((dir, file)) => format!("{dir}/{}", real_sibling_name(file)),
        None => real_sibling_name(cmd_rel),
    };
    let tree_script = format!("$PODROOT/active/extensions/{pkg_name}/usr/{cmd_rel_real}");
    // The farm symlink resolves to the wrapper blob at
    // `<podroot>/store/<aa>/<hash>` — three dirnames to the pod root
    // (same derivation as the #10 ELF lib wrapper).
    let wrapper = format!(
        "#!/bin/sh\n\
         SCRIPT=\"$(readlink -f \"$0\")\"\n\
         PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"\n\
         exec \"{interpreter}\" \"{tree_script}\"\n"
    );
    write_wrapper(app_name, entry, &wrapper)
}

/// Author the native-ELF runtime-lib wrapper (issue #10 part B): preserves
/// the real ELF at `<command>.real`, then replaces the command path with a
/// wrapper that sets `LD_LIBRARY_PATH` to the active generation's
/// name-preserving lib dirs (where the payload's bundled runtime blobs are
/// hardlinked) and single-`exec`s the real binary's store blob.
fn emit_elf_lib_wrapper(
    app_name: &str,
    entry: &Path,
    lib_dirs: &[std::path::PathBuf],
    meta: &SnapMeta,
    pod_store: &crate::runtime::RuntimeStore,
) -> miette::Result<()> {
    let file_name = entry
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let real_path = entry.with_file_name(real_sibling_name(&file_name));
    std::fs::rename(entry, &real_path).map_err(|e| {
        miette::miette!(
            "app '{app_name}': preserving native-ELF {}: {e}",
            real_path.display()
        )
    })?;
    let real_sha256 = sha256_file(&real_path).map_err(|e| {
        miette::miette!(
            "app '{app_name}': hashing native-ELF {}: {e}",
            real_path.display()
        )
    })?;
    let real_store_path = pod_store.blob_path(&real_sha256);

    // The payload's bundled libs are materialized (by name) under the
    // generation tree at `extensions/<pkg>/usr/<rel-dir>`; the pod's
    // `active` link points at the current generation. The wrapper resolves
    // its own store blob path to derive the pod root, then points
    // LD_LIBRARY_PATH at those name-preserving lib dirs.
    let ld_paths: Vec<String> = lib_dirs
        .iter()
        .map(|rel| {
            format!(
                "$PODROOT/active/extensions/{}/usr/{}",
                meta.name,
                rel.display()
            )
        })
        .collect();
    let wrapper = format!(
        "#!/bin/sh\n\
         SCRIPT=\"$(readlink -f \"$0\")\"\n\
         BLODIR=\"$(dirname \"$SCRIPT\")\"\n\
         PODROOT=\"$(dirname \"$(dirname \"$BLODIR\")\")\"\n\
         export LD_LIBRARY_PATH=\"{}\"\n\
         exec \"{}\" \"$@\"\n",
        ld_paths.join(":"),
        real_store_path.display()
    );
    write_wrapper(app_name, entry, &wrapper)
}

/// Author the confined app launcher (ADR-0016 ticket #11): a wrapper blob
/// at `<command>.shuttle-launcher` that single-`exec`s `shuttle run` for
/// the app. The wrapper derives its pod from its own store-blob path (the
/// #10 `readlink -f $0` pattern): `store/<aa>/<hash>` sits two levels
/// under the pod root, whose basename is the pod name.
///
/// The farm's direct symlink for a confined app points at this wrapper;
/// `shuttle run` resolves the app's grants from the pod's generation
/// manifest and execs the real command binary inside the sandbox.
fn emit_confined_launcher(
    app_name: &str,
    entry: &Path,
    _pod_store: &crate::runtime::RuntimeStore,
) -> miette::Result<()> {
    let launcher_path = launcher_sibling_path(entry);
    let wrapper = format!(
        "#!/bin/sh\nSELF=\"$(readlink -f \"$0\")\"\nPODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SELF\")\")\")\"\nPOD=\"$(basename \"$PODROOT\")\"\nexec shuttle run --pod \"$POD\" --root \"$(dirname \"$PODROOT\")\" {app_name} \"$@\"\n"
    );
    write_wrapper(app_name, &launcher_path, &wrapper)
}

/// The sibling path of a command entry that carries the confined launcher
/// wrapper (e.g. `usr/bin/app` → `usr/bin/app.shuttle-launcher`).
pub fn launcher_sibling_path(entry: &Path) -> PathBuf {
    let mut name = entry
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(".shuttle-launcher");
    entry.with_file_name(name)
}

/// The relative payload path of a command's confined launcher wrapper
/// (e.g. `usr/bin/app` → `usr/bin/app.shuttle-launcher`), for the
/// install-time planner to locate the wrapper blob in the payload tree.
pub fn launcher_sibling_rel_path(command_rel: &str) -> String {
    let path = Path::new(command_rel);
    launcher_sibling_path(path).to_string_lossy().into_owned()
}

/// Write a launcher wrapper at `entry` and mark it owner-executable.
fn write_wrapper(app_name: &str, entry: &Path, wrapper: &str) -> miette::Result<()> {
    std::fs::write(entry, wrapper).map_err(|e| {
        miette::miette!(
            "app '{app_name}': writing launcher wrapper {}: {e}",
            entry.display()
        )
    })?;
    make_owner_executable(entry).map_err(|e| {
        miette::miette!(
            "app '{app_name}': making wrapper executable {}: {e}",
            entry.display()
        )
    })
}

/// True when `path` is a native ELF binary (its first four bytes are the
/// ELF magic). Used by [`emit_build_wrappers`] to route a command path to
/// the native-ELF vs interpreter-script wrapper logic.
fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == b"\x7fELF"
}

/// Set the owner-execute bit plus read for group/other so a wrapper is
/// runnable from the farm the way a built binary is.
fn make_owner_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(path, perms)
}

/// Add the owner-write bit so a build-time tool (patchelf) can rewrite a
/// possibly read-only ELF in place. Returns the original mode to restore.
fn with_write_permission(path: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::metadata(path)?.permissions();
    let mode = perms.mode();
    let mut perms = perms;
    perms.set_mode(mode | 0o200);
    std::fs::set_permissions(path, perms)?;
    Ok(mode)
}

/// Restore the original mode captured by [`with_write_permission`].
fn restore_write_permission(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(perms) = std::fs::metadata(path) {
        let mut perms = perms.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// ELF class / byte-order of a file's ELF header, if it is an ELF.
fn elf_class_endian(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.len() < 16 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    Some((bytes[4], bytes[5])) // EI_CLASS, EI_DATA
}

/// Read one endian-aware unsigned integer from `bytes` at `off`.
fn read_uint(bytes: &[u8], off: usize, size: usize, big: bool) -> Option<u64> {
    if off.checked_add(size)? > bytes.len() {
        return None;
    }
    let slice = &bytes[off..off + size];
    Some(if big {
        slice.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    } else {
        slice
            .iter()
            .rev()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    })
}

/// Shared-library SONAMEs listed in an ELF's `DT_NEEDED` dynamic entries.
/// Minimal, dependency-free ELF parser (ELF32/ELF64, either byte order):
/// walks the program headers to `PT_DYNAMIC`, reads `DT_NEEDED` offsets
/// into the `DT_STRTAB` string table. A statically-linked binary returns
/// an empty list; an unparseable (non-ELF/truncated) binary returns
/// `None`.
fn elf_needed_libs(path: &Path) -> Option<Vec<String>> {
    const PT_DYNAMIC: u64 = 2;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    const DT_STRTAB: u64 = 5;
    let bytes = std::fs::read(path).ok()?;
    let (class, data) = elf_class_endian(&bytes)?;
    let big = data == 2; // ELFDATA2MSB
    let is64 = class == 2; // ELFCLASS64
    let (phoff, _phentsize, phnum) = if is64 {
        (
            read_uint(&bytes, 0x20, 8, big)?,
            read_uint(&bytes, 0x36, 2, big)?,
            read_uint(&bytes, 0x38, 2, big)?,
        )
    } else {
        (
            read_uint(&bytes, 0x1c, 4, big)?,
            read_uint(&bytes, 0x2a, 2, big)?,
            read_uint(&bytes, 0x2c, 2, big)?,
        )
    };
    let (entry_size, offset_off, filesz_off) = if is64 {
        (56usize, 8usize, 32usize)
    } else {
        (32usize, 4usize, 16usize)
    };
    // Locate PT_DYNAMIC's file range.
    let mut dyn_range = None;
    for i in 0..phnum {
        let off = phoff as usize + (i as usize) * entry_size;
        let p_type = read_uint(&bytes, off, 4, big)?;
        if p_type == PT_DYNAMIC {
            let p_offset = read_uint(&bytes, off + offset_off, if is64 { 8 } else { 4 }, big)?;
            let p_filesz = read_uint(&bytes, off + filesz_off, if is64 { 8 } else { 4 }, big)?;
            dyn_range = Some((p_offset as usize, p_filesz as usize));
            break;
        }
    }
    let (dyn_off, dyn_sz) = dyn_range?;
    let (tag_size, val_size) = if is64 {
        (8usize, 8usize)
    } else {
        (4usize, 4usize)
    };
    let mut strtab = None;
    let mut needed = Vec::new();
    let mut i = dyn_off;
    let end = dyn_off + dyn_sz;
    while i + tag_size + val_size <= end {
        let tag = read_uint(&bytes, i, tag_size, big)?;
        let val = read_uint(&bytes, i + tag_size, val_size, big)?;
        if tag == DT_NULL {
            break;
        }
        if tag == DT_NEEDED {
            needed.push(val as usize);
        } else if tag == DT_STRTAB {
            strtab = Some(val as usize);
        }
        i += tag_size + val_size;
    }
    let strtab = strtab?;
    Some(
        needed
            .into_iter()
            .filter_map(|n| {
                // Read a NUL-terminated C string at strtab + n.
                let j = strtab + n;
                let mut end0 = j;
                while end0 < bytes.len() && bytes[end0] != 0 {
                    end0 += 1;
                }
                if end0 >= bytes.len() {
                    return None;
                }
                Some(String::from_utf8_lossy(&bytes[j..end0]).into_owned())
            })
            .collect(),
    )
}

/// ELF machine type (`e_machine`) of a file, if it is an ELF.
fn elf_machine(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return None;
    }
    read_uint(bytes, 0x12, 2, bytes[5] == 2) // EI_DATA: MSB=2
}

/// The `PT_INTERP` interpreter string of an ELF (e.g.
/// `/nix/store/...-/lib/ld-linux-x86-64.so.2`), or `None` if the ELF has no
/// interpreter (a static binary) or is unparseable.
fn elf_interpreter(path: &Path) -> Option<String> {
    const PT_INTERP: u64 = 3;
    let bytes = std::fs::read(path).ok()?;
    let (class, data) = elf_class_endian(&bytes)?;
    let big = data == 2;
    let is64 = class == 2;
    let (phoff, phnum) = if is64 {
        (
            read_uint(&bytes, 0x20, 8, big)?,
            read_uint(&bytes, 0x38, 2, big)?,
        )
    } else {
        (
            read_uint(&bytes, 0x1c, 4, big)?,
            read_uint(&bytes, 0x2c, 2, big)?,
        )
    };
    let (entry_size, offset_off, filesz_off) = if is64 {
        (56usize, 8usize, 32usize)
    } else {
        (32usize, 4usize, 16usize)
    };
    for i in 0..phnum {
        let off = phoff as usize + (i as usize) * entry_size;
        let p_type = read_uint(&bytes, off, 4, big)?;
        if p_type != PT_INTERP {
            continue;
        }
        let p_offset = read_uint(&bytes, off + offset_off, if is64 { 8 } else { 4 }, big)?;
        let p_filesz = read_uint(&bytes, off + filesz_off, if is64 { 8 } else { 4 }, big)?;
        let start = p_offset as usize;
        let end = start + p_filesz as usize;
        if end > bytes.len() || end <= start {
            return None;
        }
        // The string is NUL-terminated within PT_INTERP's file range.
        let str_bytes = &bytes[start..end];
        let nul = str_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(str_bytes.len());
        return Some(String::from_utf8_lossy(&str_bytes[..nul]).into_owned());
    }
    None
}

/// The `DT_RUNPATH`/`DT_RPATH` string of an ELF, or `None` if the dynamic
/// section carries neither (or the ELF is unparseable).
fn elf_runpath(path: &Path) -> Option<String> {
    const DT_RUNPATH: u64 = 29;
    const DT_RPATH: u64 = 15;
    let bytes = std::fs::read(path).ok()?;
    let (class, data) = elf_class_endian(&bytes)?;
    let big = data == 2;
    let is64 = class == 2;
    let (phoff, _phentsize, phnum) = if is64 {
        (
            read_uint(&bytes, 0x20, 8, big)?,
            read_uint(&bytes, 0x36, 2, big)?,
            read_uint(&bytes, 0x38, 2, big)?,
        )
    } else {
        (
            read_uint(&bytes, 0x1c, 4, big)?,
            read_uint(&bytes, 0x2a, 2, big)?,
            read_uint(&bytes, 0x2c, 2, big)?,
        )
    };
    let (entry_size, offset_off, filesz_off) = if is64 {
        (56usize, 8usize, 32usize)
    } else {
        (32usize, 4usize, 16usize)
    };
    let mut dyn_range = None;
    for i in 0..phnum {
        let off = phoff as usize + (i as usize) * entry_size;
        let p_type = read_uint(&bytes, off, 4, big)?;
        if p_type == 2
        /* PT_DYNAMIC */
        {
            let p_offset = read_uint(&bytes, off + offset_off, if is64 { 8 } else { 4 }, big)?;
            let p_filesz = read_uint(&bytes, off + filesz_off, if is64 { 8 } else { 4 }, big)?;
            dyn_range = Some((p_offset as usize, p_filesz as usize));
            break;
        }
    }
    let (dyn_off, dyn_sz) = dyn_range?;
    let (tag_size, val_size) = if is64 {
        (8usize, 8usize)
    } else {
        (4usize, 4usize)
    };
    let mut strtab = None;
    let mut rpath_off = None;
    let mut i = dyn_off;
    let end = dyn_off + dyn_sz;
    while i + tag_size + val_size <= end {
        let tag = read_uint(&bytes, i, tag_size, big)?;
        let val = read_uint(&bytes, i + tag_size, val_size, big)?;
        if tag == 0
        /* DT_NULL */
        {
            break;
        }
        if tag == DT_RUNPATH || tag == DT_RPATH {
            // Either tag marks a runtime search path we must not leave
            // pointing into the build machine's nix store. (Detection only;
            // `patchelf` clears both when it rewrites.)
            rpath_off = Some(val as usize);
        } else if tag == 5
        /* DT_STRTAB */
        {
            strtab = Some(val as usize);
        }
        i += tag_size + val_size;
    }
    let (strtab, rpath_off) = (strtab?, rpath_off?);
    let j = strtab + rpath_off;
    if j >= bytes.len() {
        return None;
    }
    let mut end0 = j;
    while end0 < bytes.len() && bytes[end0] != 0 {
        end0 += 1;
    }
    Some(String::from_utf8_lossy(&bytes[j..end0]).into_owned())
}

/// The system ELF interpreter path a non-nix Linux host provides for the
/// given ELF machine type (e.g. x86-64 → `/lib64/ld-linux-x86-64.so.2`).
/// This is the interpreter a pod-built binary will use so it runs on a
/// host without the build machine's nix store.
fn system_elf_interpreter_for(machine: u64) -> String {
    match machine {
        62 => "/lib64/ld-linux-x86-64.so.2".to_string(), // EM_X86_64
        183 => "/lib/ld-linux-aarch64.so.1".to_string(), // EM_AARCH64
        // Unknown arch: keep the standard `lib/`-relative location for the
        // interpreter basename; correct for the common glibc loaders.
        _ => "/lib64/ld-linux.so.2".to_string(),
    }
}

/// Find the `patchelf` binary on PATH (used to repoint an ELF
/// interpreter/RUNPATH at build time). Returns `None` when unavailable.
fn find_patchelf() -> Option<String> {
    std::process::Command::new("which")
        .arg("patchelf")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            let s = s.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
}

/// Rewrite a native command binary's ELF interpreter and RUNPATH so it runs
/// on a non-nix host (ticket #12). A nix-toolchain build bakes the build
/// machine's `/nix/store/...-glibc.../ld-linux-x86-64.so.2` as the
/// interpreter and `/nix/store/.../lib` paths into RUNPATH; a plain host has
/// neither. At build time we repoint the interpreter at the system loader
/// (`/lib64/ld-linux-x86-64.so.2`) and clear RUNPATH so runtime libs resolve
/// from the host's default search path plus the #10 pod library wrapper's
/// `LD_LIBRARY_PATH` — never the build machine's nix store.
///
/// Returns the number of ELF binaries repointed. Binaries whose interpreter
/// and RUNPATH already carry no `/nix/store` reference are left untouched.
fn repair_elf_for_portability(meta: &SnapMeta, stage_dir: &Path) -> miette::Result<usize> {
    let patchelf = find_patchelf();
    let mut repaired = 0usize;
    for (app_name, app) in &meta.apps {
        let Some(cmd_path) = crate::units::resolve_command_path(&app.command) else {
            continue;
        };
        repaired += repair_command_elf(
            app_name,
            &cmd_path,
            &stage_dir.join(&cmd_path),
            patchelf.as_ref(),
        )?;
    }
    // ADR-0017 (issue #13): prebuilt native addons inside a fetched
    // dependency closure (`.node`/`.so`/bundled executables under
    // `node_modules`) get the same build-time ELF repair as commands, so
    // a nix-built prebuild's interpreter/RUNPATH resolves on any host.
    if meta.deps.is_some() {
        let mut elves = Vec::new();
        collect_stage_elves(stage_dir, &mut elves);
        for path in elves {
            repaired += repair_closure_elf(&path, patchelf.as_ref())?;
        }
    }
    Ok(repaired)
}

/// The command-binary repair (ticket #12): repoint a nix interpreter at
/// the system loader and clear the nix RUNPATH. Returns 1 when repaired.
fn repair_command_elf(
    app_name: &str,
    cmd_path: &str,
    entry: &Path,
    patchelf: Option<&String>,
) -> miette::Result<usize> {
    if !entry.is_file() || !is_elf(entry) {
        return Ok(0);
    }
    if !elf_has_nix_refs(entry) {
        return Ok(0);
    }
    repair_elf_on_host(app_name, cmd_path, entry, patchelf, "")
}

/// True when the ELF's interpreter OR RUNPATH references the build
/// machine's /nix/store (a nix-toolchain build baked in).
fn elf_has_nix_refs(entry: &Path) -> bool {
    let nix_interp = elf_interpreter(entry)
        .map(|i| i.contains("/nix/store/"))
        .unwrap_or(false);
    let nix_rpath = elf_runpath(entry)
        .map(|r| r.contains("/nix/store/"))
        .unwrap_or(false);
    nix_interp || nix_rpath
}

/// Shared patchelf invocation: set the system interpreter (when the ELF
/// has one) and set RUNPATH to `rpath`, returning 1 on success.
fn repair_elf_on_host(
    label: &str,
    display_path: &str,
    entry: &Path,
    patchelf: Option<&String>,
    rpath: &str,
) -> miette::Result<usize> {
    let Some(patchelf) = patchelf else {
        return Err(miette::miette!(
            "{label}: native-ELF {display_path} references the build machine's \
             /nix/store toolchain in its interpreter/RUNPATH (ticket #12), but 'patchelf' is \
             not on PATH — install it (e.g. add patchelf to devbox.json) so pod builds can \
             repoint the interpreter to a non-nix system loader",
        ));
    };
    // Derive the system interpreter from the ELF's machine type.
    let bytes = std::fs::read(entry)
        .map_err(|e| miette::miette!("{label}: reading {display_path}: {e}"))?;
    let machine = elf_machine(&bytes).unwrap_or(62); // default x86-64
    let interpreter = system_elf_interpreter_for(machine);
    // patchelf rewrites the file in place, so a copied read-only ELF
    // (e.g. `cp /bin/sh $STAGE/...`) needs a write bit during repair.
    let saved = with_write_permission(entry).map_err(|e| {
        miette::miette!("{label}: making {display_path} writable for patchelf: {e}")
    })?;
    let mut cmd = std::process::Command::new(patchelf);
    if elf_interpreter(entry).is_some() {
        cmd.arg("--set-interpreter").arg(&interpreter);
    }
    cmd.arg("--set-rpath").arg(rpath).arg(entry);
    let status = cmd
        .status()
        .map_err(|e| miette::miette!("{label}: running patchelf on {display_path}: {e}"))?;
    restore_write_permission(entry, saved);
    if !status.success() {
        return Err(miette::miette!(
            "{label}: patchelf failed on {display_path} (exit {:?})",
            status.code()
        ));
    }
    Ok(1)
}

/// Repair one ELF found in the staged dependency closure (ADR-0017):
/// bundled executables get the full command treatment (interpreter + clear
/// RUNPATH); shared objects (`.node`/`.so` — no PT_INTERP) keep sibling
/// resolution with RUNPATH `$ORIGIN` and simply drop the nix leak.
fn repair_closure_elf(entry: &Path, patchelf: Option<&String>) -> miette::Result<usize> {
    let rel = entry.to_string_lossy().to_string();
    if elf_interpreter(entry).is_some() {
        return repair_elf_on_host("deps closure", &rel, entry, patchelf, "");
    }
    if elf_runpath(entry)
        .map(|r| r.contains("/nix/store/"))
        .unwrap_or(false)
    {
        return repair_elf_on_host("deps closure", &rel, entry, patchelf, "$ORIGIN");
    }
    Ok(0)
}

/// Collect every ELF regular file under `dir` (depth-first, symlink-free).
fn collect_stage_elves(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => collect_stage_elves(&path, out),
            Ok(t) if t.is_file() && is_elf(&path) => out.push(path),
            _ => {}
        }
    }
}

/// Relative (to the stage root) parent directories of shared libraries the
/// payload itself ships that an ELF needs — i.e. runtime libs that will be
/// separate content-addressed store blobs and are NOT resolvable from the
/// binary's own runpath/system dirs. A package whose ELF needs no bundled
/// lib is self-resolvable and needs no wrapper (issue #10 part B).
fn bundled_runtime_lib_dirs(elf_path: &Path, stage_dir: &Path) -> Vec<std::path::PathBuf> {
    let Some(needed) = elf_needed_libs(elf_path) else {
        return Vec::new();
    };
    if needed.is_empty() {
        return Vec::new();
    }
    // Walk the stage once, mapping each shared-library basename to its
    // parent dir relative to the stage root.
    let mut by_name: std::collections::HashMap<String, std::path::PathBuf> =
        std::collections::HashMap::new();
    collect_shared_libs(stage_dir, stage_dir, &mut by_name);
    let mut dirs = Vec::new();
    for soname in &needed {
        let found = by_name.iter().find_map(|(name, rel_dir)| {
            if name == soname
                || name
                    .strip_prefix(soname.as_str())
                    .is_some_and(|s| s.starts_with('.'))
            {
                Some(rel_dir.clone())
            } else {
                None
            }
        });
        if let Some(dir) = found {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    dirs
}

/// Recursively record `(shared-lib basename → parent dir rel to root)`
/// for every regular `.so`/`.so.<n>` file under `dir`.
fn collect_shared_libs(
    root: &Path,
    dir: &Path,
    out: &mut std::collections::HashMap<String, std::path::PathBuf>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_shared_libs(root, &path, out);
        } else if path.is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_shared_lib_name(&name) {
                if let Ok(rel_dir) = path.parent().unwrap_or(root).strip_prefix(root) {
                    out.insert(name, rel_dir.to_path_buf());
                }
            }
        }
    }
}

/// True for a shared-library filename (`lib*.so[.<digits>]` or a bare
/// `*.so`).
fn is_shared_lib_name(name: &str) -> bool {
    let Some(dot) = name.rfind(".so") else {
        return false;
    };
    let (base, rest) = name.split_at(dot);
    let rest = &rest[3..]; // past ".so"
    !base.is_empty()
        && rest.chars().all(|c| c == '.' || c.is_ascii_digit())
        && (rest.is_empty() || rest.starts_with('.'))
}

/// Build a `.snap` package for a single architecture.
///
/// The `arch` parameter controls which architecture appears in the
/// `meta/snap.yaml` and the output filename `{name}_{version}_{arch}.snap`.
/// `stage_policy` selects stage hygiene: under [`StagePolicy::Default`] the
/// stage is wiped before a build phase populates it; under
/// [`StagePolicy::Explicit`] it is never wiped (an existing non-empty
/// explicit stage is rejected up front by [`check_explicit_stage`]).
///
/// `pod_store` is `Some` only when building into a pod's store (issue #9):
/// it is what a build-time interpreter wrapper bakes the script's
/// content-addressed store path from (see [`emit_build_wrappers`]). The
/// generic `shuttle build` path passes `None` — those builds have no store
/// to bake and produce no wrappers.
///
/// Returns the output filename (not the full path).
pub fn build_snap(
    meta: &SnapMeta,
    stage_dir: &Path,
    output_dir: &Path,
    arch: &str,
    stage_policy: StagePolicy,
    pod_store: Option<&crate::runtime::RuntimeStore>,
    deps_dir: Option<&Path>,
) -> miette::Result<BuildResult> {
    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {}", e))?;

    // 1. Run build phase (download source, run build command) if configured
    let outcome = run_build(meta, stage_dir, stage_policy, deps_dir)?;

    // 1a. Repair native-ELF command binaries for portability (ticket #12):
    // a nix-toolchain build bakes `/nix/store/...` interpreter + RUNPATH
    // into a built binary, which a non-nix host cannot execute. Repoint the
    // interpreter at the system loader and clear RUNPATH at build time
    // (never host-side). Only pod builds export binaries to a host, so this
    // runs when a pod store is provided. patchelf is a build tool the pod
    // build path provides.
    if pod_store.is_some() {
        repair_elf_for_portability(meta, stage_dir)?;
    }

    // 1b. Author build-time launcher wrappers into the stage for
    // interpreter-based apps (issue #9): an app declaring `interpreter`
    // whose command binary is a script (no native ELF) gets its command
    // path replaced by a single-`exec` wrapper referencing the script's
    // content-addressed store path. Only pod builds provide a store.
    if let Some(store) = pod_store {
        emit_build_wrappers(meta, stage_dir, store)?;
    }

    // Clone meta with architecture filtered to the target arch
    let mut arch_meta = meta.clone();
    arch_meta.architectures = Some(vec![arch.to_string()]);

    // 1c. Apply adopt-info metadata extracted at build time (post-build by
    // design: the adopted part's files and the pinned tree are what the
    // ladder reads). The extracted version feeds the snap.yaml AND the
    // output filename — version identity is only honest once extracted.
    if let Some(adopted) = &outcome.adopted {
        for warning in &adopted.warnings {
            output::warn(warning);
        }
        if let Some(v) = &adopted.version {
            arch_meta.version = v.value.clone();
        }
        if arch_meta.summary.is_none() {
            arch_meta.summary = adopted.summary.clone();
        }
        if arch_meta.description.is_none() {
            arch_meta.description = adopted.description.clone();
        }
    }

    // 2. Write meta/snap.yaml
    let meta_dir = build_dir.path().join("meta");
    std::fs::create_dir_all(&meta_dir)
        .map_err(|e| miette::miette!("failed to create meta/ directory: {}", e))?;

    let yaml = arch_meta.to_yaml()?;
    std::fs::write(meta_dir.join("snap.yaml"), &yaml)
        .map_err(|e| miette::miette!("failed to write meta/snap.yaml: {}", e))?;

    // 2b. Copy hook scripts to meta/hooks/<name> — the location the emitted
    // `hooks: <name>: command:` entries point at (snapd convention).
    copy_hook_scripts(&arch_meta, build_dir.path())?;

    // 2c. Copy the icon to meta/gui/icon.<ext> — the location the emitted
    // `icon:` field points at.
    copy_icon(&arch_meta, build_dir.path())?;

    // 3. Copy stage contents into build root
    if stage_dir.exists() {
        cp_r(stage_dir, build_dir.path())
            .map_err(|e| miette::miette!("failed to copy from {:?}: {}", stage_dir, e))?;
    }

    // 4. Output filename — built from the resolved arch_meta so an
    // adopt-info snap is named by its real extracted version.
    let output_filename = format!("{}_{}_{}.snap", arch_meta.name, arch_meta.version, arch);
    let output_path = output_dir.join(&output_filename);

    // 5. Run mksquashfs with optional SOURCE_DATE_EPOCH
    let pack_spinner = output::spinner(&format!("packaging {} as .snap...", meta.name));
    let compression = meta.compression.as_deref().unwrap_or("xz");
    let mut mksquashfs = std::process::Command::new("mksquashfs");
    mksquashfs
        .arg(build_dir.path())
        .arg(&output_path)
        .arg("-noappend")
        .arg("-comp")
        .arg(compression)
        .arg("-all-root");

    // Reproducible timestamps via SOURCE_DATE_EPOCH.
    // mksquashfs 4.4+ reads this env var natively — we just need to
    // ensure it's propagated into the child process.
    // (We set it in main.rs from the --source-date-epoch flag.)

    let status = mksquashfs
        .status()
        .map_err(|e| miette::miette!("failed to execute mksquashfs: {}", e))?;

    if !status.success() {
        output::finish_err(&pack_spinner, &format!("packaging {} failed", meta.name));
        return Err(miette::miette!("mksquashfs exited with error"));
    }
    output::finish_ok(
        &pack_spinner,
        &format!(
            "packaged {}.snap",
            &output_filename[..output_filename.len().min(60)]
        ),
    );

    Ok(BuildResult {
        snap_filename: output_filename,
        version: arch_meta.version.clone(),
        source_info: outcome.source,
    })
}

/// Subdirectory of the build tree holding the shared downloaded/extracted
/// source in multi-part builds. Part work dirs are siblings of it, so the
/// name is reserved as a part name.
const SOURCE_DIR_NAME: &str = "source";

/// What a build phase produced: lockfile-relevant source info plus the
/// adopt-info metadata extracted from the built part, if any.
#[derive(Debug, Default)]
struct BuildOutcome {
    source: Option<SourceInfo>,
    adopted: Option<AdoptedMeta>,
}

/// Run the build phase: download source, extract, and execute build command(s).
///
/// Single-part form (`build = "..."`): one command runs with `$STAGE`
/// pointing to the stage directory and `$SRC` to the downloaded/extracted
/// source — unchanged since before parts existed.
///
/// Multi-part form (`parts = { ... }`): the source is downloaded and
/// extracted once, then each part runs sequentially in `after`-dependency
/// order (see [`order_parts`]) in its own work dir under the build tree,
/// all installing into the shared stage.
///
/// When the snap declares `adopt-info`, the adopted part's metadata is
/// extracted after the parts have built (see [`extract_adopted_meta`]).
///
/// Returns the [`BuildOutcome`]: `SourceInfo` with the computed SHA-256 if
/// a source was downloaded, and the extracted adopt metadata if any.
fn run_build(
    meta: &SnapMeta,
    stage_dir: &Path,
    stage_policy: StagePolicy,
    deps_dir: Option<&Path>,
) -> miette::Result<BuildOutcome> {
    // Build plan: `parts` and `build` are mutually exclusive (the DSL
    // enforces this; re-checked here for non-DSL constructors).
    match (&meta.parts, &meta.build) {
        (Some(_), Some(_)) => {
            return Err(miette::miette!(
                "snap has both 'build' and 'parts' — use one or the other"
            ));
        }
        (Some(parts), None) if parts.is_empty() => {
            return Err(miette::miette!("'parts' must not be empty"));
        }
        (Some(_), None) => {} // multi-part mode
        (None, Some(_)) => {} // single-part mode
        (None, None) => {
            // adopt-info names a part to adopt from — a snap with nothing
            // built has nothing to adopt from.
            if let Some(part) = &meta.adopt_info {
                return Err(miette::miette!(
                    "adopt-info names part '{part}' but the snap has no source or parts to adopt from"
                ));
            }
            return Ok(BuildOutcome::default());
        }
    }
    let parts_mode = meta.parts.is_some();

    // adopt-info names a parts: entry to adopt from — a single-`build` snap
    // has no part, so the definition can never work. Fail before any
    // download work.
    if let Some(part) = &meta.adopt_info {
        if !parts_mode {
            return Err(miette::miette!(
                "adopt-info names part '{part}' but the snap has no parts (adopt-info refers to a parts: entry)"
            ));
        }
    }

    let source_spec = match &meta.source {
        Some(s) => s,
        None => {
            return Err(miette::miette!(
                "build is set but no source — add 'source = \"...\"' to snap()"
            ));
        }
    };

    let source_url = source_spec.url();

    if !source_url.starts_with("http://") && !source_url.starts_with("https://") {
        return Err(miette::miette!(
            "build requires a URL source, got: {}",
            source_url
        ));
    }

    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {}", e))?;
    let build_path = build_dir.path();

    let pkg_label = format!("{} {}", meta.name, meta.display_version());

    // 1. Download source tarball
    let filename = source_url.rsplit('/').next().unwrap_or("source.tar.gz");
    let tarball = build_path.join(filename);

    let dl_spinner = output::spinner(&format!("downloading {}...", pkg_label));
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o", &tarball.to_string_lossy(), source_url])
        .status()
        .map_err(|e| miette::miette!("curl not found: {}", e))?;

    if !status.success() {
        output::finish_err(&dl_spinner, &format!("download failed: {}", meta.name));
        return Err(miette::miette!("failed to download {}", source_url));
    }
    output::finish_ok(&dl_spinner, &format!("downloaded {}", meta.name));

    // 2. Compute SHA-256 of downloaded file
    let computed_sha256 = sha256_file(&tarball)?;

    // 3. Verify against pinned hash
    if let Some(expected) = source_spec.expected_sha256() {
        if computed_sha256 != expected {
            return Err(miette::miette!(
                "SHA-256 mismatch for {}:\n  expected: {}\n  got:      {}",
                source_url,
                expected,
                computed_sha256
            ));
        }
        output::ok(format!("SHA-256 verified: {:.16}...", computed_sha256));
    } else if !output::is_json() {
        output::info(format!(
            "source hash: {:.16}... (add to source.sha256 to pin)",
            computed_sha256
        ));
    }

    // 4. Extract the tarball into the shared source dir (parts mode keeps
    // part work dirs separate) or the build tree root (single-part mode,
    // unchanged layout).
    let extract_dir: std::path::PathBuf = if parts_mode {
        let dir = build_path.join(SOURCE_DIR_NAME);
        std::fs::create_dir_all(&dir)
            .map_err(|e| miette::miette!("failed to create source dir: {}", e))?;
        dir
    } else {
        build_path.to_path_buf()
    };
    let is_tarball = filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.xz")
        || filename.ends_with(".tgz");
    if is_tarball {
        let xtract_spinner = output::spinner(&format!("extracting {}...", meta.name));
        let tarball_str = tarball.to_string_lossy().to_string();
        let status = std::process::Command::new("tar")
            .arg("xaf")
            .arg(&tarball_str)
            .arg("-C")
            .arg(&extract_dir)
            .current_dir(build_path)
            .status()
            .map_err(|e| miette::miette!("tar not found: {}", e))?;
        if !status.success() {
            output::finish_err(
                &xtract_spinner,
                &format!("extraction failed: {}", meta.name),
            );
            return Err(miette::miette!("failed to extract {}", filename));
        }
        output::finish_ok(&xtract_spinner, &format!("extracted {}", meta.name));
    }

    // 5. `$SRC` points at the source root (the single top-level dir after
    // extraction, if there is exactly one) — shared and identical for every
    // part in multi-part mode.
    let src_root = find_source_root(&extract_dir).unwrap_or_else(|| extract_dir.clone());

    // 6. Create stage dir and run the build plan. Stage hygiene: the
    // default stage is shuttle-owned scratch — wipe it so leftovers from
    // previous builds can never leak into this snap (observed: pciutils
    // files inside a bzip2 snap). An explicit --stage belongs to the user:
    // it was verified empty before the build started and is never wiped.
    if stage_policy == StagePolicy::Default {
        clear_stage_dir(stage_dir)?;
    }
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| miette::miette!("failed to create stage dir: {}", e))?;

    // Convert stage_dir to absolute path (DESTDIR requires absolute)
    let abs_stage = std::fs::canonicalize(stage_dir).unwrap_or_else(|_| stage_dir.to_path_buf());

    if parts_mode {
        let parts = meta
            .parts
            .as_ref()
            .expect("parts_mode implies a parts spec");
        run_parts(
            parts,
            build_path,
            &src_root,
            &abs_stage,
            meta.target.as_deref(),
            deps_dir,
        )?;
    } else {
        // Single-part: cwd and $SRC both point at the source root, as before.
        let build_cmd = meta.build.as_deref().ok_or_else(|| {
            miette::miette!("internal: neither parts nor build plan for {}", meta.name)
        })?;
        let build_spinner = output::spinner(&format!("building {}...", meta.name));
        run_build_command(
            build_cmd,
            build_path,
            &src_root,
            &src_root,
            &abs_stage,
            meta.target.as_deref(),
            None,
            &[],
            deps_dir,
        )?;
        output::finish_ok(&build_spinner, &format!("built {}", meta.name));
    }

    // 7. adopt-info: extract the adopted part's metadata now that the
    //    named part has built — the pinned source tree is unpacked and the
    //    part's files are staged (the two read-only inputs of the ladder).
    //    Post-build by design: version feeds the snap filename and cache
    //    identity, so it must come from what was actually built, and a
    //    missing version hard-errors here instead of shipping "0".
    let adopted = extract_adopted_meta(meta, &src_root, &abs_stage)?;

    Ok(BuildOutcome {
        source: Some(SourceInfo {
            url: source_url.to_string(),
            sha256: computed_sha256,
        }),
        adopted,
    })
}

// ── adopt-info: build-time metadata extraction ──

/// Metadata extracted at build time for an adopt-info snap. Only the fields
/// the ladder actually found are present — explicit DSL fields never move.
#[derive(Debug, Clone, Default)]
pub struct AdoptedMeta {
    /// The extracted version, with where it came from. `None` when the
    /// snap declared an explicit version (which wins, with a warning).
    pub version: Option<ExtractedField>,
    pub summary: Option<String>,
    pub description: Option<String>,
    /// Human-readable warnings for the caller to print (explicit-field
    /// divergence etc.).
    pub warnings: Vec<String>,
}

/// A value extracted from the build tree, with where it came from.
#[derive(Debug, Clone)]
pub struct ExtractedField {
    pub value: String,
    pub from: String,
}

/// snapd's real per-field limits for the adoptable identity fields (snapd
/// `snap/validate.go`): version ≤ 32 *bytes* (with a constrained charset),
/// summary ≤ 128 Unicode codepoints, description ≤ 4096 codepoints —
/// version is the only byte-measured field (see [`check_adopt_cap`]).
const SNAPD_VERSION_MAX_BYTES: usize = 32;
const SNAPD_SUMMARY_MAX_CHARS: usize = 128;
const SNAPD_DESCRIPTION_MAX_CHARS: usize = 4096;

/// The adopt-info extraction ladder for one snap, run at build time after
/// the named part has built:
///
/// 1. An explicit `version` in the definition wins outright — with a
///    warning, because version feeds the cache identity and the snap
///    filename, so silently diverging from the adopted metadata would be a
///    reproducibility lie. Explicit summary/description win per-field,
///    silently (they feed no identity).
/// 2. `$STAGE/snap/metadata.json` — snapcraft's own convention file.
/// 3. The adopted part's plugin reads the pinned source tree post-unpack
///    (autotools `AC_INIT`, `Cargo.toml [package]`, CMake
///    `project(VERSION)`, meson `project(version:)`); two extracted
///    sources within the part disagreeing on version is a hard error —
///    never an arbitrary pick.
/// 4. An installed AppStream `metainfo.xml` under
///    `$STAGE/usr/share/metainfo` supplies summary/description (snapcraft
///    parse-info precedent).
///
/// The ladder is per-field: each field takes the first rung that provides
/// it. A version that no rung provides is a hard error — the "0"
/// placeholder never survives into snap.yaml.
fn extract_adopted_meta(
    meta: &SnapMeta,
    src_root: &Path,
    stage: &Path,
) -> miette::Result<Option<AdoptedMeta>> {
    let Some(adopt_name) = &meta.adopt_info else {
        return Ok(None);
    };

    let Some(parts) = &meta.parts else {
        return Err(miette::miette!(
            "adopt-info names part '{adopt_name}' but the snap has no parts (adopt-info refers to a parts: entry)"
        ));
    };
    let part = parts.get(adopt_name).ok_or_else(|| {
        miette::miette!(
            "adopt-info names part '{adopt_name}' but the snap has no such part (parts: {})",
            parts.keys().cloned().collect::<Vec<_>>().join(", ")
        )
    })?;

    let mut warnings = Vec::new();

    // ── version ──
    let version = if !meta.version_adopted {
        let explicit = &meta.version;
        match extract_version_from_rungs(adopt_name, part, src_root, stage)? {
            Some(found) => warnings.push(format!(
                "adopt-info: explicit version '{explicit}' wins over the extracted version '{}' (from {}) — \
                 version feeds the cache identity and the snap filename, so this divergence is deliberate only if kept",
                found.value, found.from
            )),
            None => warnings.push(format!(
                "adopt-info: explicit version '{explicit}' wins (no version metadata found to adopt from part '{adopt_name}')"
            )),
        }
        None
    } else {
        match extract_version_from_rungs(adopt_name, part, src_root, stage)? {
            Some(found) => {
                check_adopt_cap("version", &found.value, &found.from)?;
                Some(found)
            }
            None => {
                return Err(miette::miette!(
                    "adopt-info: no version metadata found for part '{adopt_name}' (plugin '{}'); \
                     snapd requires a real version — declare version = \"…\" explicitly, or ship \
                     snap/metadata.json or plugin metadata in the source",
                    part.plugin.as_deref().unwrap_or("(none)")
                ));
            }
        }
    };

    // ── summary/description ──
    let json_summary = metadata_json_field(stage, "summary")?;
    let json_description = metadata_json_field(stage, "description")?;
    let (metainfo_summary, metainfo_description, metainfo_from) =
        metainfo_summary_description(stage)?;

    let summary = if meta.summary.is_some() {
        None
    } else if let Some(s) = json_summary {
        check_adopt_cap("summary", &s, "snap/metadata.json")?;
        Some(s)
    } else if let Some(s) = metainfo_summary {
        check_adopt_cap("summary", &s, &metainfo_from)?;
        Some(s)
    } else {
        None
    };

    let description = if meta.description.is_some() {
        None
    } else if let Some(d) = json_description {
        check_adopt_cap("description", &d, "snap/metadata.json")?;
        Some(d)
    } else if let Some(d) = metainfo_description {
        check_adopt_cap("description", &d, &metainfo_from)?;
        Some(d)
    } else {
        None
    };

    Ok(Some(AdoptedMeta {
        version,
        summary,
        description,
        warnings,
    }))
}

/// Rungs 2-3 for the version field: `$STAGE/snap/metadata.json`, then the
/// part's plugin reading the pinned source tree. More than one distinct
/// extracted value within the part is a hard error (never an arbitrary
/// pick); agreeing sources collapse to one hit.
fn extract_version_from_rungs(
    part_name: &str,
    part: &SnapPart,
    src_root: &Path,
    stage: &Path,
) -> miette::Result<Option<ExtractedField>> {
    if let Some(v) = metadata_json_field(stage, "version")? {
        return Ok(Some(ExtractedField {
            value: v,
            from: "snap/metadata.json".to_string(),
        }));
    }

    let Some(plugin) = &part.plugin else {
        return Ok(None);
    };
    let hits = crate::plugins::extract_versions(plugin, src_root);
    let mut distinct: Vec<&crate::plugins::ExtractedVersion> = Vec::new();
    for hit in &hits {
        if distinct.iter().any(|d| d.value == hit.value) {
            continue;
        }
        distinct.push(hit);
    }
    match distinct.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(ExtractedField {
            value: one.value.clone(),
            from: one.from.clone(),
        })),
        many => {
            let listed = many
                .iter()
                .map(|h| format!("{} says '{}'", h.from, h.value))
                .collect::<Vec<_>>()
                .join(", ");
            Err(miette::miette!(
                "adopt-info: conflicting version metadata within part '{part_name}' ({plugin}): \
                 {listed} — fix the source metadata; shuttle never picks arbitrarily"
            ))
        }
    }
}

/// Read a string field from `$STAGE/snap/metadata.json` (snapcraft's
/// convention file). A present-but-unparsable file is a hard error —
/// silently ignoring it would bury a broken stage.
fn metadata_json_field(stage: &Path, field: &str) -> miette::Result<Option<String>> {
    let path = stage.join("snap").join("metadata.json");
    if !path.is_file() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| miette::miette!("adopt-info: failed to read {}: {}", path.display(), e))?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| miette::miette!("adopt-info: {} is not valid JSON: {e}", path.display()))?;
    Ok(value
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string))
}

/// Summary/description from an installed AppStream metainfo file (snapcraft
/// parse-info precedent): the first `*.metainfo.xml` / `*.appdata.xml` in
/// `$STAGE/usr/share/metainfo`, name-sorted for determinism. Minimal
/// deterministic scan — no XML crate.
fn metainfo_summary_description(
    stage: &Path,
) -> miette::Result<(Option<String>, Option<String>, String)> {
    let dir = stage.join("usr/share/metainfo");
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| miette::miette!("adopt-info: failed to read {}: {}", dir.display(), e))?
        {
            let entry = entry
                .map_err(|e| miette::miette!("adopt-info: failed to read metainfo entry: {e}"))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".metainfo.xml") || name.ends_with(".appdata.xml") {
                candidates.push(entry.path());
            }
        }
    }
    candidates.sort();
    let Some(path) = candidates.into_iter().next() else {
        return Ok((None, None, String::new()));
    };
    let from = format!(
        "usr/share/metainfo/{}",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    let content = std::fs::read_to_string(&path)
        .map_err(|e| miette::miette!("adopt-info: failed to read {}: {}", path.display(), e))?;
    let summary = xml_element_text(&content, "summary");
    let description = xml_element_text(&content, "description").map(|d| xml_paragraphs(&d));
    Ok((summary, description, from))
}

/// Inner text of the first `<tag>` element in an XML document, whitespace-
/// collapsed. Handles attribute soup on the open tag (`<summary
/// xml:lang="en">`); self-closing or unclosed elements yield nothing.
fn xml_element_text(content: &str, tag: &str) -> Option<String> {
    xml_element_span(content, tag)
        .map(|(inner, _)| inner.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// (inner text, remainder after the closing tag) of the first `<tag>`
/// element. Skips false positives like `<summaryfoo>`.
fn xml_element_span<'a>(content: &'a str, tag: &str) -> Option<(&'a str, &'a str)> {
    let open = format!("<{tag}");
    let mut search = content;
    loop {
        let idx = search.find(&open)?;
        let after = &search[idx + open.len()..];
        if !(after.starts_with('>')
            || after.starts_with(' ')
            || after.starts_with('\t')
            || after.starts_with('\n'))
        {
            search = after;
            continue;
        }
        let gt = after.find('>')?;
        let body = &after[gt + 1..];
        let close = format!("</{tag}>");
        let close_idx = body.find(&close)?;
        return Some((&body[..close_idx], &body[close_idx + close.len()..]));
    }
}

/// Description text: the `<p>` paragraphs inside an AppStream
/// `<description>`, joined by blank lines (markdown-ish, the convention
/// snapcraft parse-info follows). Falls back to the tag-stripped inner text
/// when the element holds no paragraphs.
fn xml_paragraphs(description_inner: &str) -> String {
    let mut paragraphs = Vec::new();
    let mut rest = description_inner;
    while let Some((inner, remainder)) = xml_element_span(rest, "p") {
        paragraphs.push(inner.split_whitespace().collect::<Vec<_>>().join(" "));
        rest = remainder;
    }
    if paragraphs.is_empty() {
        return strip_tags(description_inner);
    }
    paragraphs.join("\n\n")
}

/// Remove `<…>` markup from a string.
fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Enforce snapd's per-field limits on an extracted value — error, never
/// truncate (a truncated summary or version would be published as if it
/// were the source's own; snapd likewise `fmt.Errorf`s every over-limit
/// field rather than cutting it, `snap/validate.go`). Version counts bytes;
/// summary and description count Unicode codepoints.
fn check_adopt_cap(field: &str, value: &str, from: &str) -> miette::Result<()> {
    match field {
        "version" => {
            if value.len() > SNAPD_VERSION_MAX_BYTES {
                return Err(miette::miette!(
                    "adopt-info: extracted version \"{value}\" (from {from}) exceeds snapd's \
                     {SNAPD_VERSION_MAX_BYTES}-byte limit — shorten the source metadata or \
                     declare the field explicitly instead"
                ));
            }
            if !is_snapd_version_charset_ok(value) {
                return Err(miette::miette!(
                    "adopt-info: extracted version \"{value}\" (from {from}) does not match \
                     snapd's version charset (must start and end with a letter or digit; \
                     interior characters may also be one of : . + ~ -)"
                ));
            }
            Ok(())
        }
        "summary" => check_adopt_text_cap("summary", value, from, SNAPD_SUMMARY_MAX_CHARS),
        "description" => {
            check_adopt_text_cap("description", value, from, SNAPD_DESCRIPTION_MAX_CHARS)
        }
        other => unreachable!("unknown adopt-info field {other:?}"),
    }
}

/// snapd's version charset (`snap/validate.go`): one or more characters,
/// starting with a letter or digit, ending with a letter/digit/`+`/`~`, and
/// interior characters may additionally be one of `:`, `.`, `+`, `~`, `-`.
/// All classes are ASCII (so ≤ 32 bytes follows from the shape); non-ASCII
/// never matches. Hand-rolled to keep a regex dependency out of this path.
fn is_snapd_version_charset_ok(v: &str) -> bool {
    let alnum = |c: char| c.is_ascii_alphanumeric();
    let tail = |c: char| alnum(c) || matches!(c, '+' | '~');
    let interior = |c: char| tail(c) || matches!(c, ':' | '.' | '-');
    let mut chars = v.chars();
    match chars.next() {
        Some(first) => {
            alnum(first)
                && chars.all(interior)
                && v.chars().next_back().is_some_and(tail)
                && v.len() <= SNAPD_VERSION_MAX_BYTES
        }
        None => false,
    }
}

/// snapd counts summary/description in Unicode codepoints (not bytes).
fn check_adopt_text_cap(field: &str, value: &str, from: &str, max: usize) -> miette::Result<()> {
    if value.chars().count() > max {
        return Err(miette::miette!(
            "adopt-info: extracted {field} \"{value}\" (from {from}) exceeds snapd's \
             {max}-character limit — shorten the source metadata or declare \
             the field explicitly instead"
        ));
    }
    Ok(())
}

/// Deterministic execution order for parts: a part is runnable once every
/// `after` dependency has completed; parts with no `after` are runnable
/// immediately. Among ready parts the name-sorted one runs first — the
/// documented deterministic tie-break (Lua tables don't preserve order, so
/// any non-`after` ordering is intentionally unspecified beyond this
/// determinism).
pub fn order_parts(parts: &BTreeMap<String, SnapPart>) -> miette::Result<Vec<String>> {
    for name in parts.keys() {
        validate_part_name(name)?;
    }
    let mut order = Vec::with_capacity(parts.len());
    let mut done: std::collections::HashSet<String> = std::collections::HashSet::new();
    while order.len() < parts.len() {
        // Smallest ready part name.
        let next = parts
            .iter()
            .filter(|(name, part)| {
                !done.contains(name.as_str())
                    && part.after.iter().all(|dep| done.contains(dep.as_str()))
            })
            .map(|(name, _)| name)
            .min()
            .cloned();
        let Some(next) = next else {
            let stuck: Vec<String> = parts
                .keys()
                .filter(|name| !done.contains(name.as_str()))
                .cloned()
                .collect();
            return Err(miette::miette!(
                "circular or unsatisfiable dependency among parts: {}",
                stuck.join(", ")
            ));
        };
        done.insert(next.clone());
        order.push(next);
    }
    Ok(order)
}

/// Part names become directory names under the build tree; keep them plain,
/// and reserve the shared source dir name.
fn validate_part_name(name: &str) -> miette::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(miette::miette!(
            "invalid part name '{name}': must be a plain directory name (no '/', '.', '..')"
        ));
    }
    if name == SOURCE_DIR_NAME {
        return Err(miette::miette!(
            "invalid part name '{name}': reserved for the shared build source directory"
        ));
    }
    Ok(())
}

/// Run named parts sequentially in dependency order (v1 — no parallelism).
///
/// Each part runs in its own work dir under the build tree
/// (`<build-tree>/<part-name>/`) with `$STAGE` shared across parts — the
/// integration point: every part installs into the same stage. `$PART_NAME`
/// holds the running part's name. The whole build tree (shared source dir
/// included) is visible in every sandbox and sandbox env/inputs are
/// identical for every part; per-part sources/inputs are future work.
fn run_parts(
    parts: &BTreeMap<String, SnapPart>,
    build_tree: &Path,
    src_dir: &Path,
    stage_dir: &Path,
    target: Option<&str>,
    deps_dir: Option<&Path>,
) -> miette::Result<()> {
    for name in order_parts(parts)? {
        let part = parts.get(&name).expect("name comes from the same map");
        let plan = part_build_plan(&name, part)?;
        let part_dir = build_tree.join(&name);
        std::fs::create_dir_all(&part_dir)
            .map_err(|e| miette::miette!("failed to create work dir for part '{name}': {}", e))?;
        let spinner = output::spinner(&format!("[{name}] building..."));
        for cmd in &plan.commands {
            run_build_command(
                cmd,
                build_tree,
                &part_dir,
                src_dir,
                stage_dir,
                target,
                Some(&name),
                &plan.env,
                deps_dir,
            )?;
        }
        output::finish_ok(&spinner, &format!("[{name}] built"));
    }
    Ok(())
}

/// The command sequence a part runs. Plugin parts expand to their
/// declarative [`crate::plugins::BuildPlan`] (ADR-0014 Decision 4) — the
/// plugin cannot execute arbitrary logic beyond the commands it emits.
/// Command parts run their single `build` command unchanged.
fn part_build_plan(name: &str, part: &SnapPart) -> miette::Result<crate::plugins::BuildPlan> {
    match (&part.plugin, part.build.is_empty()) {
        (Some(plugin), true) => crate::plugins::expand(plugin, part.plugin_options.as_ref()),
        (Some(_), false) | (None, true) => Err(miette::miette!(
            "part '{name}' must have exactly one of 'build' or 'plugin'"
        )),
        (None, false) => Ok(crate::plugins::BuildPlan {
            commands: vec![part.build.clone()],
            env: Vec::new(),
            extra_requires: Vec::new(),
        }),
    }
}

/// Compute SHA-256 of a file (streaming, memory-efficient for large files).
fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {}", path.display(), e))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette::miette!("failed to read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Run a build command, optionally wrapped in a bubblewrap sandbox.
///
/// `build_path` is the root build directory (host-side).
/// `work_dir` is the command's working directory (inside `build_path`).
/// `src_dir` is the source root `$SRC` points at (inside `build_path`;
/// equals `work_dir` for single-part builds).
/// Inside the sandbox the build dir is mounted at `/build` and
/// `$SRC` points to the source subdirectory.
/// If `bwrap` is unavailable, falls back to direct execution.
///
/// `part_name` is set for multi-part builds and exported as `$PART_NAME`.
///
/// Cross-compilation support:
/// - If `target` is set, env vars CC, CXX, LD, AR, etc. are set to
///   `{target}-{tool}` (using the GNU cross-compiler naming convention).
/// - `CONFIGURE_TARGET` is exported for autotools-based packages.
/// - The cross-toolchain sysroot is expected at the standard host path
///   `/usr/{target}` or can be provided via `CROSS_SYSROOT`.
///
/// `extra_env` carries plugin BuildPlan env vars (ADR-0014 Decision 4),
/// exported to the command in both sandboxed and direct modes.
#[allow(clippy::too_many_arguments)]
fn run_build_command(
    cmd: &str,
    build_path: &Path,
    work_dir: &Path,
    src_dir: &Path,
    stage_dir: &Path,
    target: Option<&str>,
    part_name: Option<&str>,
    extra_env: &[(String, String)],
    deps_dir: Option<&Path>,
) -> miette::Result<()> {
    let bwrap_bin = detect_bwrap();
    let cross_env = cross_compile_env(target);

    if let Some(bwrap_bin) = bwrap_bin {
        run_bwrapped(
            &bwrap_bin, cmd, build_path, work_dir, src_dir, stage_dir, target, &cross_env,
            part_name, extra_env, deps_dir,
        )
    } else {
        output::warn("sandbox unavailable — building WITHOUT isolation");
        run_direct(
            cmd, work_dir, src_dir, stage_dir, &cross_env, part_name, extra_env, deps_dir,
        )
    }
}
/// Detect the bubblewrap binary, if available.
fn detect_bwrap() -> Option<String> {
    std::process::Command::new("which")
        .arg("bwrap")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            let s = s.trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
}

/// Build cross-compilation environment variables if target is set.
/// These follow the GNU cross-compiler naming convention:
///   CC = <target>-gcc, CXX = <target>-g++, etc.
fn cross_compile_env(target: Option<&str>) -> Vec<(&'static str, String)> {
    let Some(triplet) = target else {
        return Vec::new();
    };
    let mut env = Vec::new();
    env.push(("CONFIGURE_TARGET", triplet.to_string()));
    env.push(("CC", format!("{}-gcc", triplet)));
    env.push(("CXX", format!("{}-g++", triplet)));
    env.push(("LD", format!("{}-ld", triplet)));
    env.push(("AR", format!("{}-ar", triplet)));
    env.push(("AS", format!("{}-as", triplet)));
    env.push(("RANLIB", format!("{}-ranlib", triplet)));
    env.push(("STRIP", format!("{}-strip", triplet)));
    env.push(("OBJCOPY", format!("{}-objcopy", triplet)));
    env.push(("OBJDUMP", format!("{}-objdump", triplet)));
    env.push(("NM", format!("{}-nm", triplet)));
    env.push(("PKG_CONFIG", format!("{}-pkg-config", triplet)));
    // Standard autotools cross-compilation vars
    env.push(("BUILD", std::env::consts::ARCH.to_string()));
    env.push(("HOST", triplet.to_string()));
    env.push(("CROSS_COMPILE", format!("{}-", triplet)));
    env
}

/// Apply cross-compilation env vars to a command.
fn apply_cross_env(cmd: &mut std::process::Command, cross_env: &[(&'static str, String)]) {
    for (key, val) in cross_env {
        cmd.env(key, val);
    }
}

/// Read-only bind of `path` into the sandbox, if it exists on the host.
fn ro_bind_if_exists(cmd: &mut std::process::Command, path: &str) {
    if Path::new(path).exists() {
        cmd.arg("--ro-bind").arg(path).arg(path);
    }
}

/// Host path roots bound read-only into the build sandbox (see
/// [`bind_system_ro_paths`]). This is the sandbox's entire view of the host
/// filesystem: a build tool resolves inside the sandbox only if its PATH
/// entry lives under one of these roots. Entries elsewhere (e.g. a
/// project's `.devbox` profile dir) are invisible to sandboxed builds, and
/// a `nix store` garbage collection can delete `/nix/store` paths a stale
/// shell still exports — both turn a working host setup into an obscure
/// mid-build failure. Doctor and the sandboxed build runner resolve tools
/// against this same list so that failure mode becomes a named pre-flight
/// diagnostic instead.
pub const SANDBOX_RO_ROOTS: [&str; 6] = [
    "/usr",
    "/lib",
    "/lib64",
    "/nix",
    "/bin",
    "/run/current-system",
];

/// Where the fetched dependency closure (ADR-0017, issue #13) is mounted
/// inside the build sandbox (read-only), and what `$SHUTTLE_DEPS_DIR`
/// points the build command at.
pub const SANDBOX_DEPS_DIR: &str = "/shuttle-deps";

/// The process PATH split into absolute directory entries. Relative and
/// empty entries are dropped — the sandbox only ever mirrors absolute host
/// paths.
pub fn path_entries() -> Vec<PathBuf> {
    std::env::var("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|e| e.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// True if `path` lives under a sandbox bind root ([`SANDBOX_RO_ROOTS`])
/// — the sandbox binds those roots at the same host path, so anything
/// under them is visible to a sandboxed build. Component-wise, so a
/// sibling prefix (`/usrlocal`) does not match.
pub fn sandbox_visible(path: &Path) -> bool {
    SANDBOX_RO_ROOTS.iter().any(|root| path.starts_with(root))
}

/// PATH entries the sandbox can actually see: under a bind root AND still
/// present on the host. A garbage-collected `/nix/store/...` entry is
/// bound via `/nix` but its directory no longer exists — it resolves
/// nothing and is dropped, matching what the sandbox would see.
pub fn sandbox_visible_entries(entries: &[PathBuf]) -> Vec<PathBuf> {
    sandbox_visible_entries_with(entries, &[])
}

/// Like [`sandbox_visible_entries`], but `extra_roots` are host paths the
/// sandbox binds at their own location — the stage dir is rw-bound at its
/// host path, so tools under it resolve inside the sandbox.
///
/// Each entry is first resolved to its canonical path (symlinks followed):
/// a devbox/nix profile dir like `$PROJECT/.devbox/nix/profile/default/bin`
/// is a symlink into `/nix/store`, so canonicalizing maps it onto a bound
/// root and keeps the tools it exposes usable inside the sandbox (the
/// sandbox binds `/nix`, but binds the *profile* dir nowhere). Entries that
/// do not exist (a garbage-collected store path, a missing dir) resolve to
/// nothing and are dropped, matching what the sandbox would see.
pub fn sandbox_visible_entries_with(entries: &[PathBuf], extra_roots: &[PathBuf]) -> Vec<PathBuf> {
    entries
        .iter()
        .filter_map(|e| std::fs::canonicalize(e).ok())
        .filter(|e| {
            (sandbox_visible(e) || extra_roots.iter().any(|r| e.starts_with(r))) && e.is_dir()
        })
        .collect()
}

/// The `PATH` the sandbox can actually see for the given `extra_roots`
/// (a colon-joined [`sandbox_visible_entries_with`]) — used as the
/// hermetic sandbox `PATH` so inherited host env (devbox/nix-shell paths
/// that are NOT bound) never leaks into the build.
pub fn sandbox_path(extra_roots: &[PathBuf]) -> std::ffi::OsString {
    let entries = sandbox_visible_entries_with(&path_entries(), extra_roots);
    std::env::join_paths(entries).unwrap_or_default()
}

/// First existing, executable match for `name` in `entries` (PATH order —
/// the same resolution `sh` performs).
pub fn resolve_in_path(name: &str, entries: &[PathBuf]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    entries
        .iter()
        .map(|entry| entry.join(name))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

/// Shell keywords and POSIX sh builtins — never resolved through PATH.
const SHELL_WORDS: [&str; 59] = [
    "if", "then", "else", "elif", "fi", "do", "done", "case", "esac", "while", "until", "for",
    "in", "function", "select", "time", "{", "}", "!", "[[", "]]", ":", ".", "alias", "bg",
    "break", "cd", "command", "continue", "echo", "eval", "exec", "exit", "export", "false", "fg",
    "getopts", "hash", "jobs", "kill", "local", "printf", "pwd", "read", "readonly", "return",
    "set", "shift", "test", "times", "trap", "true", "type", "ulimit", "umask", "unalias", "unset",
    "wait", "[",
];

/// Command words in `cmd` that `sh` would resolve through PATH: the first
/// word of each `&&`/`||`/`;`/`|`/newline-separated segment, after
/// skipping leading variable assignments (`DESTDIR=$STAGE cmake ...`).
/// Only `&&` separates commands — a lone `&` is a background mark or part
/// of a redirection (`2>&1`) and must not split the segment. Words naming
/// a direct path, a variable, a glob, or a shell builtin resolve outside
/// PATH and are not probed.
fn path_resolved_words(cmd: &str) -> Vec<String> {
    let mut words = Vec::new();
    for chunk in cmd.split("&&") {
        for segment in chunk.split(['|', ';', '\n']) {
            for word in segment.split_whitespace() {
                if is_variable_assignment(word) {
                    continue;
                }
                let word = unquote(word);
                if is_path_resolved_word(word) {
                    words.push(word.to_string());
                }
                break;
            }
        }
    }
    words
}

/// True if `word` (unquoted) is a bare command name the shell resolves
/// through PATH — no path separators, variables, globs, redirections,
/// quotes, or shell keywords/builtins.
fn is_path_resolved_word(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && !word.contains(['/', '$', '`', '<', '>', '*', '?', '[', '"', '\''])
        && !SHELL_WORDS.contains(&word)
}

/// Strip one layer of matching surrounding quotes.
fn unquote(word: &str) -> &str {
    let quoted = word.len() >= 2
        && (word.starts_with('"') && word.ends_with('"')
            || word.starts_with('\'') && word.ends_with('\''));
    if quoted {
        &word[1..word.len() - 1]
    } else {
        word
    }
}

/// True for `NAME=value` words — environment assignments prefixing a
/// command, not the command itself.
fn is_variable_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            let mut chars = name.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
                _ => return false,
            }
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Fail a sandboxed build BEFORE running it when its command needs a tool
/// the sandbox cannot see. Each PATH-resolved command word is resolved
/// against the sandbox-visible PATH ([`sandbox_visible_entries`]); an
/// invisible tool becomes a named error instead of an obscure mid-build
/// failure (e.g. autotools `config.status` breaking because `make` sat
/// only on an unbound PATH entry or was garbage-collected out of
/// /nix/store). Tools shadowed by an unbound entry but also present under
/// a bind root resolve fine and pass.
pub fn preflight_sandbox_tools(cmd: &str, entries: &[PathBuf]) -> miette::Result<()> {
    preflight_sandbox_tools_with(cmd, entries, &[])
}

/// Like [`preflight_sandbox_tools`], with `extra_roots`: host paths the
/// sandbox binds at their own location (the stage dir), so PATH entries
/// under them count as sandbox-visible.
pub fn preflight_sandbox_tools_with(
    cmd: &str,
    entries: &[PathBuf],
    extra_roots: &[PathBuf],
) -> miette::Result<()> {
    let visible = sandbox_visible_entries_with(entries, extra_roots);
    for word in path_resolved_words(cmd) {
        if resolve_in_path(&word, &visible).is_some() {
            continue;
        }
        return Err(sandbox_tool_error(&word, entries));
    }
    Ok(())
}

/// The named, actionable error for a build tool the sandbox cannot see.
fn sandbox_tool_error(tool: &str, entries: &[PathBuf]) -> miette::Error {
    let roots = SANDBOX_RO_ROOTS.join(", ");
    match resolve_in_path(tool, entries) {
        Some(host_path) => miette::miette!(
            "tool '{tool}' resolves on the host to '{host}' via PATH entry '{entry}', which is \
             outside the sandbox bind roots ({roots}) — sandboxed builds cannot see it. \
             Fix: install it system-wide or under another bound root (devbox profile dirs \
             like .devbox/nix/profile are not bound).",
            host = host_path.display(),
            entry = host_path
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ),
        None => miette::miette!(
            "tool '{tool}' was not found in any sandbox-visible PATH directory (bind roots: \
             {roots}). Fix: install it — e.g. add its package to devbox.json and re-run from \
             a fresh devbox shell (a 'nix store' GC can remove /nix/store paths a stale shell \
             still exports on PATH).",
        ),
    }
}

/// Best-effort markers that a failed build was trying to reach the network.
/// The sandbox unshares the net, so a build that downloads anything fails
/// confusingly — sources must come from the definition instead.
const NETWORK_FETCH_MARKERS: [&str; 5] = ["curl", "wget", "fetch", "clon", "download"];

/// True if captured build output looks like a failed download attempt
/// (best-effort substring match over the lowercased text).
fn stderr_suggests_network_fetch(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    NETWORK_FETCH_MARKERS.iter().any(|m| lower.contains(m))
}

/// One-line hint printed when a failed build looks like it tried to
/// download something. Best-effort: matched against the build's stderr
/// text, not a parser.
fn warn_no_network_hint(stderr: &str) {
    if stderr_suggests_network_fetch(stderr) {
        output::warn(
            "build failed and its output mentions a download (sandbox has no network — fetch sources via the definition's source/inputs)",
        );
    }
}

/// Spawn a build command, forwarding its stderr to our stderr line-by-line
/// (output still streams live) while also collecting it, so a failure can
/// be inspected. Reading to EOF before reaping avoids pipe deadlock.
fn run_build_child(
    mut cmd_proc: std::process::Command,
) -> std::io::Result<(std::process::ExitStatus, String)> {
    use std::io::BufRead;
    use std::process::Stdio;
    cmd_proc.stderr(Stdio::piped());
    let mut child = cmd_proc.spawn()?;
    let collected = match child.stderr.take() {
        Some(stderr) => std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stderr);
            let mut collected = String::new();
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("{line}");
                collected.push_str(&line);
                collected.push('\n');
            }
            collected
        })
        .join()
        .unwrap_or_default(),
        None => String::new(),
    };
    let status = child.wait()?;
    Ok((status, collected))
}

/// Read-only system paths for toolchain, shebangs, and Nix/devbox builds.
/// The bind set is [`SANDBOX_RO_ROOTS`] — doctor's sandbox-visibility
/// check and the build pre-flight resolve tools against the same list.
/// Each root is bound only when it exists (bwrap errors on missing bind
/// sources; the FHS roots exist on every host where sandboxed builds run).
fn bind_system_ro_paths(cmd: &mut std::process::Command) {
    for root in SANDBOX_RO_ROOTS {
        ro_bind_if_exists(cmd, root);
    }
}

/// Run the build command inside a bubblewrap sandbox.
#[allow(clippy::too_many_arguments)]
fn run_bwrapped(
    bwrap_bin: &str,
    cmd: &str,
    build_path: &Path,
    work_dir: &Path,
    src_dir: &Path,
    stage_dir: &Path,
    target: Option<&str>,
    cross_env: &[(&'static str, String)],
    part_name: Option<&str>,
    extra_env: &[(String, String)],
    deps_dir: Option<&Path>,
) -> miette::Result<()> {
    // Tool resolution must work the way the sandbox will see it — fail
    // here, naming the tool, instead of mid-build (see
    // `preflight_sandbox_tools_with`). The stage dir is bound at its own
    // host path, so PATH entries under it are visible.
    preflight_sandbox_tools_with(cmd, &path_entries(), &[stage_dir.to_path_buf()])?;
    // Map a host path under the build dir to its sandbox path under /build.
    let to_inner = |p: &Path| -> std::path::PathBuf {
        if p == build_path {
            Path::new("/build").to_path_buf()
        } else {
            let rel = p.strip_prefix(build_path).unwrap_or(Path::new(""));
            Path::new("/build").join(rel)
        }
    };
    let inner_src = to_inner(src_dir);
    let inner_cwd = to_inner(work_dir);

    let mut cmd_proc = std::process::Command::new(bwrap_bin);
    cmd_proc
        .arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-net")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        // Private /tmp for build temp files. Mounted BEFORE the binds below:
        // bwrap applies mounts in argument order, so a later stage bind must
        // win over the tmpfs for stage dirs that live under /tmp.
        .arg("--tmpfs")
        .arg("/tmp")
        // Mount build dir at /build inside sandbox
        .arg("--bind")
        .arg(build_path)
        .arg("/build")
        // Mount stage dir at its absolute host path
        .arg("--bind")
        .arg(stage_dir)
        .arg(stage_dir);
    // Dependency closure (ADR-0017, issue #13): the fetched tree is bound
    // READ-ONLY at a fixed sandbox path — the only view of the closure a
    // build gets. It is never writable and never the shared host cache.
    if let Some(deps) = deps_dir {
        cmd_proc.arg("--ro-bind").arg(deps).arg(SANDBOX_DEPS_DIR);
    }
    bind_system_ro_paths(&mut cmd_proc);
    // Cross-compilation sysroot mount
    if let Some(triplet) = target {
        let sysroot = Path::new("/usr").join(triplet);
        if sysroot.exists() {
            cmd_proc.arg("--ro-bind").arg(&sysroot).arg(&sysroot);
        }
    }
    cmd_proc.arg("--chdir").arg(&inner_cwd);
    // Hermetic sandbox (issue #10): drop the inherited host env so
    // `NIX_LD`/`NIX_CFLAGS_COMPILE`/devbox PATH cannot leak host-nix store
    // paths into built artifacts, then export a controlled PATH limited to
    // the sandbox-visible toolchain dirs (symlinks canonicalized onto the
    // bound roots — see `sandbox_visible_entries_with`) plus the build vars.
    cmd_proc.env_clear();
    cmd_proc
        .env("PATH", sandbox_path(&[stage_dir.to_path_buf()]))
        .env("STAGE", stage_dir)
        .env("SRC", &inner_src);
    if deps_dir.is_some() {
        cmd_proc.env("SHUTTLE_DEPS_DIR", SANDBOX_DEPS_DIR);
    }
    if let Some(name) = part_name {
        cmd_proc.env("PART_NAME", name);
    }
    apply_cross_env(&mut cmd_proc, cross_env);
    apply_extra_env(&mut cmd_proc, extra_env);
    cmd_proc.arg("sh").arg("-c").arg(cmd);

    let (status, stderr_text) =
        run_build_child(cmd_proc).map_err(|e| miette::miette!("bwrap execution failed: {}", e))?;

    if !status.success() {
        warn_no_network_hint(&stderr_text);
        return Err(miette::miette!(
            "build command exited with error (in sandbox)"
        ));
    }
    Ok(())
}

/// Fallback: run the build command directly on host (no sandbox).
#[allow(clippy::too_many_arguments)]
fn run_direct(
    cmd: &str,
    work_dir: &Path,
    src_dir: &Path,
    stage_dir: &Path,
    cross_env: &[(&'static str, String)],
    part_name: Option<&str>,
    extra_env: &[(String, String)],
    deps_dir: Option<&Path>,
) -> miette::Result<()> {
    let mut cmd_proc = std::process::Command::new("sh");
    cmd_proc
        .args(["-c", cmd])
        .env("STAGE", stage_dir)
        .env("SRC", src_dir);
    // No sandbox means no read-only bind — the closure tree is exposed at
    // its host path (degraded mode only; the bwrap path binds it RO).
    if let Some(deps) = deps_dir {
        cmd_proc.env("SHUTTLE_DEPS_DIR", deps);
    }
    if let Some(name) = part_name {
        cmd_proc.env("PART_NAME", name);
    }
    apply_cross_env(&mut cmd_proc, cross_env);
    apply_extra_env(&mut cmd_proc, extra_env);
    cmd_proc.current_dir(work_dir);

    let (status, stderr_text) =
        run_build_child(cmd_proc).map_err(|e| miette::miette!("failed to execute build: {}", e))?;

    if !status.success() {
        warn_no_network_hint(&stderr_text);
        return Err(miette::miette!("build command exited with error"));
    }
    Ok(())
}

/// Export plugin BuildPlan env vars to a command (ADR-0014 Decision 4).
fn apply_extra_env(cmd: &mut std::process::Command, extra_env: &[(String, String)]) {
    for (key, val) in extra_env {
        cmd.env(key, val);
    }
}

/// Find the single top-level directory in a path (the source root
/// after extracting a tarball). If there's more than one entry or
/// no entry, returns None.
fn find_source_root(dir: &Path) -> Option<std::path::PathBuf> {
    let mut entries: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && !entry.file_name().to_string_lossy().starts_with('.')
            {
                entries.push(entry.path());
            }
        }
    }
    if entries.len() == 1 {
        Some(entries.into_iter().next().unwrap())
    } else {
        None
    }
}

/// Resolve a build-time file reference (hook script, icon) from the DSL.
///
/// Absolute paths pass through unchanged. Relative paths resolve against
/// the definition file's directory first — so a definition in a subpackage
/// dir can reference sibling files regardless of where `shuttle build` runs
/// — falling back to the process CWD for definitions that predate
/// definition-relative resolution (and for `definition_dir: None`).
fn resolve_definition_relative(definition_dir: Option<&Path>, path: &str) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    if let Some(dir) = definition_dir {
        let candidate = dir.join(p);
        if candidate.is_file() {
            return candidate;
        }
    }
    p.to_path_buf()
}

/// True if `path` has the owner execute bit set.
fn is_owner_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o100 != 0)
        .unwrap_or(false)
}

/// Warning for a hook script whose mode lacks owner+x: snapd executes hooks
/// directly, so a non-executable copy would never run. `None` when the
/// script is executable.
fn hook_exec_warning(name: &str, src: &Path) -> Option<String> {
    if is_owner_executable(src) {
        return None;
    }
    Some(format!(
        "hook '{name}': '{}' is not executable (mode lacks owner x) — snapd runs hooks directly; chmod +x the source file",
        src.display()
    ))
}

/// Copy hook scripts from the DSL's source paths into `<build_root>/meta/hooks/<name>`.
///
/// Relative paths resolve against the definition file's directory first,
/// then the project directory `shuttle build` runs from. A script whose
/// mode lacks owner+x is copied but warned about — snapd would never run it.
fn copy_hook_scripts(meta: &SnapMeta, build_root: &Path) -> miette::Result<()> {
    let Some(hooks) = &meta.hooks else {
        return Ok(());
    };
    let hooks_dir = build_root.join("meta").join("hooks");
    for (name, hook) in hooks {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| miette::miette!("failed to create meta/hooks/: {}", e))?;
        let src = resolve_definition_relative(meta.definition_dir.as_deref(), &hook.source);
        if !src.is_file() {
            return Err(miette::miette!(
                "hook '{name}': script not found: {} (relative paths resolve from the definition's directory, then the project directory)",
                hook.source
            ));
        }
        if let Some(warning) = hook_exec_warning(name, &src) {
            output::warn(warning);
        }
        std::fs::copy(&src, hooks_dir.join(name))
            .map_err(|e| miette::miette!("failed to copy hook '{name}': {}", e))?;
    }
    Ok(())
}

/// Copy the icon source file to `<build_root>/<icon>` (meta/gui/icon.<ext>).
///
/// Relative paths resolve against the definition file's directory first,
/// then the project directory (see [`resolve_definition_relative`]).
fn copy_icon(meta: &SnapMeta, build_root: &Path) -> miette::Result<()> {
    let (Some(src), Some(target)) = (&meta.icon_source, &meta.icon) else {
        return Ok(());
    };
    let dst = build_root.join(target);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("failed to create {}: {}", parent.display(), e))?;
    }
    let src_path = resolve_definition_relative(meta.definition_dir.as_deref(), src);
    if !src_path.is_file() {
        return Err(miette::miette!(
            "icon: file not found: {src} (relative paths resolve from the definition's directory, then the project directory)"
        ));
    }
    std::fs::copy(&src_path, &dst)
        .map_err(|e| miette::miette!("failed to copy icon {src}: {e}"))?;
    Ok(())
}

/// Determine the set of architectures to build.
///
/// * If `cli_archs` is non-empty, use those (from `--arch` flags).
/// * Otherwise use the architectures declared in `meta`.
/// * If neither is set, default to `["all"]`.
pub fn resolve_archs(meta: &SnapMeta, cli_archs: &[String]) -> Vec<String> {
    if !cli_archs.is_empty() {
        cli_archs.to_vec()
    } else {
        meta.architectures
            .clone()
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| vec!["all".to_string()])
    }
}

/// Recursive copy of directory contents into destination.
fn cp_r(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut dirs = vec![src.to_path_buf()];
    while let Some(current) = dirs.pop() {
        let relative = current.strip_prefix(src).unwrap();
        let target = dst.join(relative);

        if current.is_dir() && current != src {
            std::fs::create_dir_all(&target)?;
        }

        if let Ok(read) = std::fs::read_dir(&current) {
            for entry in read {
                let entry = entry?;
                let path = entry.path();
                let rel = path.strip_prefix(src).unwrap();
                let dest = dst.join(rel);

                if path.is_dir() {
                    std::fs::create_dir_all(&dest)?;
                    dirs.push(path);
                } else {
                    std::fs::copy(&path, &dest)?;
                }
            }
        }
    }
    Ok(())
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluate with DSL and get top-level table (keeps Lua alive for the duration).
    struct LuaEnv {
        lua: mlua::Lua,
    }

    impl LuaEnv {
        fn new() -> Self {
            let lua = mlua::Lua::new();
            lua.load(crate::dsl::prelude())
                .exec()
                .expect("DSL init failed");
            LuaEnv { lua }
        }

        fn eval(&self, source: &str) -> miette::Result<mlua::Table> {
            let value: Value = self
                .lua
                .load(source)
                .eval()
                .map_err(|e| miette::miette!("{}", e))?;
            match value {
                Value::Table(t) => Ok(t),
                other => Err(miette::miette!("expected table, got {}", other.type_name())),
            }
        }
    }

    // ── SourceSpec tests ──

    #[test]
    fn test_source_spec_unverified() {
        let s = SourceSpec::Unverified("https://example.com/tarball.tar.gz".into());
        assert_eq!(s.url(), "https://example.com/tarball.tar.gz");
        assert!(s.expected_sha256().is_none());
    }

    #[test]
    fn test_source_spec_pinned() {
        let hash = "e9b1d4d5f3c0b2a1d9c8f7e6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b";
        let s = SourceSpec::Pinned {
            url: "https://example.com/tarball.tar.gz".into(),
            sha256: hash.into(),
        };
        assert_eq!(s.url(), "https://example.com/tarball.tar.gz");
        assert_eq!(s.expected_sha256(), Some(hash));
    }

    #[test]
    fn test_source_spec_serialize_as_url() {
        let s = SourceSpec::Pinned {
            url: "https://example.com/pkg.tar.gz".into(),
            sha256: "abc123".into(),
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert_eq!(yaml.trim(), "https://example.com/pkg.tar.gz");
    }

    #[test]
    fn test_source_spec_dsl_string() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "legacy",
                    version = "1.0",
                    source = "https://example.com/old.tar.gz",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Unverified(url)) => {
                assert_eq!(url, "https://example.com/old.tar.gz");
            }
            other => panic!("expected Unverified, got {:?}", other),
        }
    }

    #[test]
    fn test_source_spec_dsl_table_pinned() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "pinned",
                    version = "1.0",
                    source = {
                        url = "https://example.com/pkg.tar.gz",
                        sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Pinned { url, sha256 }) => {
                assert_eq!(url, "https://example.com/pkg.tar.gz");
                assert_eq!(
                    sha256,
                    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                );
            }
            other => panic!("expected Pinned, got {:?}", other),
        }
    }

    #[test]
    fn test_source_spec_dsl_table_no_hash() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "no-hash",
                    version = "1.0",
                    source = {
                        url = "https://example.com/pkg.tar.gz",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        match meta.source {
            Some(SourceSpec::Unverified(url)) => {
                assert_eq!(url, "https://example.com/pkg.tar.gz");
            }
            other => panic!("expected Unverified, got {:?}", other),
        }
    }

    #[test]
    fn test_source_none_when_unset() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "no-source",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert!(meta.source.is_none());
    }

    #[test]
    fn test_sha256_file_known_content() {
        // Create a temp file with known content and verify its hash
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"hello world\n").unwrap();
        let hash = super::sha256_file(&path).unwrap();
        // SHA-256 of "hello world\n"
        assert_eq!(
            hash,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
    }

    // ── Phase 3 tests: struct conversion ──

    #[test]
    fn test_snap_meta_from_lua_full() {
        let env = LuaEnv::new();
        let table = env
            .eval(
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
                    source = "http://example.com/tarball.tar.gz",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(meta.name, "hello");
        assert_eq!(meta.version, "2.10");
        assert_eq!(meta.summary.as_deref(), Some("GNU Hello"));
        assert_eq!(meta.grade, "stable");
        assert_eq!(meta.confinement, "strict");
        let archs = meta.architectures.as_ref().unwrap();
        assert_eq!(archs, &vec!["amd64".to_string(), "arm64".to_string()]);
        assert_eq!(meta.apps.len(), 1);
        assert_eq!(meta.apps["hello"].command, "bin/hello");
    }

    #[test]
    fn test_snap_meta_from_lua_minimal() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "minimal",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(meta.name, "minimal");
        assert_eq!(meta.version, "1.0");
        assert!(meta.summary.is_none());
        assert_eq!(meta.grade, "stable"); // default
        assert_eq!(meta.confinement, "strict"); // default
        assert!(meta.apps.is_empty());
    }

    #[test]
    fn test_snap_app_from_lua() {
        let env = LuaEnv::new();
        let value: Value = env
            .lua
            .load(r#"return app { command = "bin/serve", daemon = "simple" }"#)
            .eval()
            .unwrap();

        let _ = env; // keep alive for the value reference

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };
        let app = SnapApp::from_lua_table("serve", &table).unwrap();

        assert_eq!(app.command, "bin/serve");
        assert_eq!(app.daemon.as_deref(), Some("simple"));
        assert!(app.plugs.is_none());
    }

    #[test]
    fn test_app_unknown_field_rejected_with_named_error() {
        // Hand-built app table (bypasses the DSL's app()): the Rust-side
        // conversion must reject unknown fields naming the app, not drop
        // them silently.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return snap {
                name = "drifted",
                version = "1.0",
                apps = {
                    svc = {
                        command = "bin/svc",
                        restart_condition = "on-abnormal",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let err = SnapMeta::from_lua_table(&table).unwrap_err().to_string();
        assert!(
            err.contains("app 'svc': unknown field 'restart_condition'"),
            "got: {err}"
        );
    }

    #[test]
    fn test_app_unknown_field_lists_valid_fields() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return snap {
                name = "desktoped",
                version = "1.0",
                apps = { svc = { command = "bin/svc", desktop = "share/applications/svc.desktop" } },
            }
            "#,
            )
            .unwrap();
        let meta = SnapMeta::from_lua_table(&table).unwrap();
        assert_eq!(
            meta.apps["svc"].desktop.as_deref(),
            Some("share/applications/svc.desktop")
        );
        // The field flows into the emitted snap.yaml (the payload's
        // meta/snap.yaml is what the install-time launcher recorder
        // reads, issue #7).
        let yaml = meta.to_yaml().unwrap();
        assert!(
            yaml.contains("desktop: share/applications/svc.desktop"),
            "yaml: {yaml}"
        );
    }

    #[test]
    fn test_app_desktop_field_is_validated() {
        let env = LuaEnv::new();
        let cases: &[(&str, &str)] = &[
            ("absolute path", "/etc/x.desktop"),
            ("parent escape", "../x.desktop"),
            ("wrong extension", "share/applications/x.txt"),
            ("empty", ""),
        ];
        for (what, value) in cases {
            let table = env
                .eval(&format!(
                    r#"
                return snap {{
                    name = "bad",
                    version = "1.0",
                    apps = {{ svc = {{ command = "bin/svc", desktop = "{value}" }} }},
                }}
                "#
                ))
                .unwrap();
            let err = SnapMeta::from_lua_table(&table).unwrap_err().to_string();
            assert!(
                err.contains("'desktop'"),
                "{what}: error must name the field, got: {err}"
            );
        }
    }

    #[test]
    fn test_app_known_fields_still_accepted() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return snap {
                name = "ok",
                version = "1.0",
                apps = {
                    svc = {
                        command = "bin/svc",
                        daemon = "simple",
                        plugs = { "network" },
                        slots = { "s" },
                        environment = { MODE = "x" },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let meta = SnapMeta::from_lua_table(&table).unwrap();
        let app = &meta.apps["svc"];
        assert_eq!(app.daemon.as_deref(), Some("simple"));
        assert_eq!(app.environment.as_ref().unwrap()["MODE"], "x");
    }

    // ── pkgs/lib templates validate against the app schema (drift guard) ──

    /// Run one pkgs/lib template's `M.app` through the DSL's app() and the
    /// Rust conversion — the exact path a definition's apps table takes.
    fn template_app_validates(template: &str, template_name: &str) {
        let env = LuaEnv::new();
        let src = format!(
            "return (function()\nlocal M = (function()\n{}end)()\n\
             return snap {{\nname = \"tmpl\", version = \"1.0\",\n\
             apps = {{ svc = M.app {{ command = \"bin/svc\" }} }},\n}}\nend)()",
            template
        );
        let value: Value = env.lua.load(&src).eval().unwrap();
        let table = match value {
            Value::Table(t) => t,
            other => panic!("expected table, got {}", other.type_name()),
        };
        let meta = SnapMeta::from_lua_table(&table)
            .unwrap_or_else(|e| panic!("{template_name} template must validate: {e}"));
        assert_eq!(meta.apps["svc"].command, "bin/svc");
    }

    #[test]
    fn test_daemon_template_validates() {
        template_app_validates(include_str!("../pkgs/lib/daemon.lua"), "daemon");
    }

    #[test]
    fn test_cli_template_validates() {
        template_app_validates(include_str!("../pkgs/lib/cli.lua"), "cli");
    }

    #[test]
    fn test_desktop_template_validates() {
        template_app_validates(include_str!("../pkgs/lib/desktop.lua"), "desktop");
    }

    #[test]
    fn test_daemon_template_emits_no_schema_unknown_keys() {
        // The drift this guards against: daemon.lua used to emit
        // restart_condition, which the schema silently dropped.
        let env = LuaEnv::new();
        let src = format!(
            "M = (function()\n{}end)()\nreturn M.app {{ command = \"bin/x\" }}",
            include_str!("../pkgs/lib/daemon.lua")
        );
        let app_value: Value = env.lua.load(&src).set_name("daemon.lua").eval().unwrap();
        let app_table = match app_value {
            Value::Table(t) => t,
            other => panic!("expected app table, got {}", other.type_name()),
        };
        assert!(
            app_table
                .get::<Value>("restart_condition")
                .unwrap()
                .is_nil(),
            "daemon template must not emit keys outside the app schema"
        );
    }

    // ── Phase 4 tests: YAML output ──

    #[test]
    fn test_snap_yaml_full() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "hello",
                    version = "2.10",
                    summary = "GNU Hello",
                    description = "Prints a greeting",
                    grade = "stable",
                    confinement = "strict",
                    architectures = { "amd64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();

        assert!(yaml.contains("name: hello"));
        assert!(yaml.contains("version: '2.10'"));
        assert!(yaml.contains("bin/hello"));
        assert!(yaml.contains("amd64"));
        assert!(yaml.contains("summary:")); // present, not skipped
    }

    #[test]
    fn test_snap_yaml_minimal_omits_optionals() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "minimal",
                    version = "1.0",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();

        assert!(yaml.contains("name: minimal"));
        assert!(yaml.contains("grade: stable"));
        assert!(yaml.contains("confinement: strict"));
        assert!(!yaml.contains("summary:")); // skipped
        assert!(!yaml.contains("description:")); // skipped
    }

    // ── Phase 5/6 tests: build pipeline ──

    #[test]
    fn test_build_snap_creates_snap_file() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "test-snap",
                    version = "0.1.0",
                    architectures = { "amd64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let stage_dir = std::path::Path::new("test-fixtures");
        let output_dir = tempfile::tempdir().unwrap();

        let result = build_snap(
            &meta,
            stage_dir,
            output_dir.path(),
            "amd64",
            StagePolicy::Default,
            None,
            None,
        );
        assert!(result.is_ok());

        let build_result = result.unwrap();
        assert_eq!(build_result.snap_filename, "test-snap_0.1.0_amd64.snap");
        // No source pinned, so source_info is None
        assert!(build_result.source_info.is_none());

        let snap_path = output_dir.path().join(&build_result.snap_filename);
        assert!(
            snap_path.exists(),
            "snap file should exist at {:?}",
            snap_path
        );

        // Verify it's a valid SquashFS via unsquashfs
        let check = std::process::Command::new("unsquashfs")
            .args(["-l", &snap_path.to_string_lossy()])
            .output()
            .expect("unsquashfs should be available");

        let stdout = String::from_utf8_lossy(&check.stdout);
        assert!(
            stdout.contains("meta/snap.yaml"),
            "snap should contain meta/snap.yaml"
        );
    }

    #[test]
    fn test_build_multi_arch() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "multi-test",
                    version = "2.0",
                    architectures = { "amd64", "arm64" },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let output_dir = tempfile::tempdir().unwrap();
        let stage_dir = std::path::Path::new("test-fixtures");

        // Build amd64
        let snap_amd64 = build_snap(
            &meta,
            stage_dir,
            output_dir.path(),
            "amd64",
            StagePolicy::Default,
            None,
            None,
        )
        .unwrap();
        assert_eq!(snap_amd64.snap_filename, "multi-test_2.0_amd64.snap");
        assert!(output_dir.path().join(&snap_amd64.snap_filename).exists());

        // Build arm64
        let snap_arm64 = build_snap(
            &meta,
            stage_dir,
            output_dir.path(),
            "arm64",
            StagePolicy::Default,
            None,
            None,
        )
        .unwrap();
        assert_eq!(snap_arm64.snap_filename, "multi-test_2.0_arm64.snap");
        assert!(output_dir.path().join(&snap_arm64.snap_filename).exists());

        // Verify both have correct arch in YAML
        for snap_result in [&snap_amd64, &snap_arm64] {
            let check = std::process::Command::new("unsquashfs")
                .args([
                    "-l",
                    &output_dir
                        .path()
                        .join(&snap_result.snap_filename)
                        .to_string_lossy(),
                ])
                .output()
                .expect("unsquashfs should be available");
            let stdout = String::from_utf8_lossy(&check.stdout);
            assert!(stdout.contains("meta/snap.yaml"), "missing snap.yaml");
        }
    }

    #[test]
    fn test_resolve_archs_defaults_to_meta() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                    architectures = { "amd64", "arm64" },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &[]);
        assert_eq!(archs, vec!["amd64", "arm64"]);
    }

    #[test]
    fn test_resolve_archs_cli_overrides_meta() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                    architectures = { "amd64", "arm64" },
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &["arm64".to_string()]);
        assert_eq!(archs, vec!["arm64"]);
    }

    #[test]
    fn test_resolve_archs_defaults_to_all() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "t",
                    version = "1",
                },
            }
            "#,
            )
            .unwrap();

        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let archs = resolve_archs(&meta, &[]);
        assert_eq!(archs, vec!["all"]);
    }

    // ── Phase 15 tests: complete snap.yaml coverage ──

    #[test]
    fn test_layout_dsl_and_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "laid-out",
                    version = "1.0",
                    layout = {
                        ["/etc/myapp.conf"] = { bind_file = "$SNAP_DATA/etc/myapp.conf" },
                        ["/var/run/myapp"] = { symlink = "$SNAP_COMMON/run" },
                        ["/usr/share/fonts"] = { bind = "$SNAP/fonts" },
                        ["/tmp/cache"] = { tmpfs = { size = "100M" } },
                        ["/run/lock"] = { tmpfs = true },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let layout = meta.layout.as_ref().unwrap();
        assert_eq!(layout.len(), 5);
        assert_eq!(
            layout["/etc/myapp.conf"],
            LayoutEntry::BindFile("$SNAP_DATA/etc/myapp.conf".into())
        );
        assert_eq!(
            layout["/var/run/myapp"],
            LayoutEntry::Symlink("$SNAP_COMMON/run".into())
        );
        assert_eq!(
            layout["/usr/share/fonts"],
            LayoutEntry::Bind("$SNAP/fonts".into())
        );
        assert_eq!(
            layout["/tmp/cache"],
            LayoutEntry::Tmpfs(TmpfsSpec::Sized {
                size: "100M".into()
            })
        );
        assert_eq!(
            layout["/run/lock"],
            LayoutEntry::Tmpfs(TmpfsSpec::Bare(true))
        );

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("layout:"));
        assert!(yaml.contains("bind-file: $SNAP_DATA/etc/myapp.conf"));
        assert!(yaml.contains("symlink: $SNAP_COMMON/run"));
        assert!(yaml.contains("bind: $SNAP/fonts"));
        assert!(yaml.contains("size: 100M"));
    }

    #[test]
    fn test_layout_validation_errors() {
        let env = LuaEnv::new();
        // No type key
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = {} },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "layout['/etc/x'] must have exactly one of bind, bind_file, symlink, tmpfs"
            ),
            "got: {err}"
        );

        // Two type keys
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = { bind = "$SNAP/a", symlink = "$SNAP/b" } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "layout['/etc/x'] must have exactly one of bind, bind_file, symlink, tmpfs (got 2)"
            ),
            "got: {err}"
        );

        // Non-string bind value
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = { bind = 42 } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("layout['/etc/x'].bind must be a string, got number"),
            "got: {err}"
        );

        // Bad tmpfs value
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = { tmpfs = "yes" } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "layout['/etc/x'].tmpfs must be true or a table with optional string 'size'"
            ),
            "got: {err}"
        );

        // tmpfs table with non-string size
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = { tmpfs = { size = 100 } } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("layout['/etc/x'].tmpfs.size must be a string, got number"),
            "got: {err}"
        );

        // Entry not a table
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "l", version = "1",
                    layout = { ["/etc/x"] = "bind" },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("layout['/etc/x'] must be a table, got string"),
            "got: {err}"
        );
    }

    #[test]
    fn test_hooks_dsl_struct_and_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "hooked",
                    version = "1.0",
                    hooks = {
                        configure = "scripts/configure.sh",
                        install = "scripts/install.sh",
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let hooks = meta.hooks.as_ref().unwrap();
        assert_eq!(hooks["configure"].command, "meta/hooks/configure");
        assert_eq!(hooks["configure"].source, "scripts/configure.sh");
        assert_eq!(hooks["install"].command, "meta/hooks/install");

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("hooks:"));
        assert!(yaml.contains("command: meta/hooks/configure"));
        assert!(yaml.contains("command: meta/hooks/install"));
        // Source paths are build-time only — never in snap.yaml.
        assert!(!yaml.contains("scripts/configure.sh"));
    }

    #[test]
    fn test_hooks_validation_error() {
        let env = LuaEnv::new();
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "h", version = "1",
                    hooks = { configure = 42 },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("hooks['configure'] must be a string script path, got number"),
            "got: {err}"
        );
    }

    // ── Hook/icon source resolution (definition-relative) ──

    /// Set the owner execute bit on `path`.
    fn chmod_owner_x(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(perms.mode() | 0o100);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// Meta for one hook resolved against `definition_dir`.
    fn hook_meta(env: &LuaEnv, script_ref: &str) -> SnapMeta {
        let src = format!(
            r#"
            return snap {{
                name = "hooked", version = "1.0",
                hooks = {{ configure = "{}" }},
            }}
            "#,
            script_ref
        );
        SnapMeta::from_lua_table(&env.eval(&src).unwrap()).unwrap()
    }

    #[test]
    fn test_hook_resolves_relative_to_definition() {
        // A definition in a subdirectory referencing a sibling script must
        // build regardless of the process CWD.
        let project = tempfile::tempdir().unwrap();
        let def_dir = project.path().join("pkgs/s/mypkg");
        std::fs::create_dir_all(&def_dir).unwrap();
        let script = def_dir.join("configure.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        chmod_owner_x(&script);

        let env = LuaEnv::new();
        let mut meta = hook_meta(&env, "configure.sh");
        meta.definition_dir = Some(def_dir.clone());

        let build_root = tempfile::tempdir().unwrap();
        super::copy_hook_scripts(&meta, build_root.path()).unwrap();
        let copied = build_root.path().join("meta/hooks/configure");
        assert!(copied.is_file(), "hook must be copied into the snap");
        let content = std::fs::read_to_string(&copied).unwrap();
        assert!(content.contains("exit 0"), "copied content must match");
    }

    #[test]
    fn test_hook_missing_reports_both_resolution_roots() {
        let project = tempfile::tempdir().unwrap();
        let def_dir = project.path().join("def");
        std::fs::create_dir_all(&def_dir).unwrap();

        let env = LuaEnv::new();
        let mut meta = hook_meta(&env, "nowhere.sh");
        meta.definition_dir = Some(def_dir);

        let build_root = tempfile::tempdir().unwrap();
        let err = super::copy_hook_scripts(&meta, build_root.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("hook 'configure': script not found: nowhere.sh"),
            "got: {err}"
        );
        assert!(
            err.contains("definition's directory, then the project directory"),
            "error must name both resolution roots: {err}"
        );
    }

    #[test]
    fn test_hook_warns_when_not_executable() {
        // Default 0o644 — no execute bit. The hook is copied (the emitted
        // snap.yaml already points at meta/hooks/configure) but a warning
        // is raised instead of the copy passing silently.
        let project = tempfile::tempdir().unwrap();
        let def_dir = project.path().join("def");
        std::fs::create_dir_all(&def_dir).unwrap();
        let script = def_dir.join("configure.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(
            super::hook_exec_warning("configure", &script).is_some(),
            "non-executable script must produce a warning"
        );

        let env = LuaEnv::new();
        let mut meta = hook_meta(&env, "configure.sh");
        meta.definition_dir = Some(def_dir);

        let build_root = tempfile::tempdir().unwrap();
        super::copy_hook_scripts(&meta, build_root.path()).unwrap();
        assert!(build_root.path().join("meta/hooks/configure").is_file());
    }

    #[test]
    fn test_hook_exec_warning_none_when_executable() {
        let project = tempfile::tempdir().unwrap();
        let script = project.path().join("configure.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        chmod_owner_x(&script);
        assert!(super::hook_exec_warning("configure", &script).is_none());
    }

    #[test]
    fn test_icon_resolves_relative_to_definition() {
        let project = tempfile::tempdir().unwrap();
        let def_dir = project.path().join("assets-nested");
        std::fs::create_dir_all(&def_dir).unwrap();
        std::fs::write(def_dir.join("logo.png"), b"fake png").unwrap();

        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return snap {
                name = "iconic", version = "1.0",
                icon = "logo.png",
            }
            "#,
            )
            .unwrap();
        let mut meta = SnapMeta::from_lua_table(&table).unwrap();
        meta.definition_dir = Some(def_dir);

        let build_root = tempfile::tempdir().unwrap();
        super::copy_icon(&meta, build_root.path()).unwrap();
        let copied = build_root.path().join("meta/gui/icon.png");
        assert!(copied.is_file(), "icon must be copied into the snap");
    }

    // ── Build-failure network hint (sandbox unshares the net) ──

    #[test]
    fn test_stderr_suggests_network_fetch() {
        assert!(super::stderr_suggests_network_fetch(
            "curl: (6) Could not resolve host: example.com"
        ));
        assert!(super::stderr_suggests_network_fetch(
            "wget: unable to resolve host address 'example.com'"
        ));
        assert!(super::stderr_suggests_network_fetch(
            "Performing download step (download, verify, extract) for 'dep'"
        ));
        assert!(super::stderr_suggests_network_fetch(
            "Cloning into 'lib'..."
        ));
        assert!(!super::stderr_suggests_network_fetch(
            "make: *** [Makefile:42: all] Error 1"
        ));
        assert!(!super::stderr_suggests_network_fetch(""));
    }

    #[test]
    fn test_typed_plugs_and_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "plugged",
                    version = "1.0",
                    plugs = {
                        network = { interface = "network" },
                        ["shared-data"] = {
                            interface = "content",
                            content = "my-content",
                            target = "$SNAP/data",
                            default_provider = "producer",
                        },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let plugs = meta.plugs.as_ref().unwrap();
        match &plugs["network"] {
            SnapPlug::Typed(p) => {
                assert_eq!(p.interface, "network");
                assert!(p.attributes.is_empty());
            }
            other => panic!("expected Typed plug, got {other:?}"),
        }
        match &plugs["shared-data"] {
            SnapPlug::Typed(p) => {
                assert_eq!(p.interface, "content");
                assert_eq!(
                    p.attributes.get("content").map(String::as_str),
                    Some("my-content")
                );
                assert_eq!(
                    p.attributes.get("target").map(String::as_str),
                    Some("$SNAP/data")
                );
                assert_eq!(
                    p.attributes.get("default_provider").map(String::as_str),
                    Some("producer")
                );
            }
            other => panic!("expected Typed plug, got {other:?}"),
        }

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("plugs:"));
        assert!(yaml.contains("interface: content"));
        assert!(yaml.contains("content: my-content"));
        assert!(yaml.contains("target: $SNAP/data"));
        assert!(yaml.contains("default_provider: producer"));
    }

    #[test]
    fn test_string_plugs_back_compat() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "legacy-plugs",
                    version = "1.0",
                    plugs = { "network", "network-bind" },
                    slots = { "home" },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(
            meta.plugs.as_ref().unwrap()["network"],
            SnapPlug::Name("network".into())
        );
        assert_eq!(
            meta.plugs.as_ref().unwrap()["network-bind"],
            SnapPlug::Name("network-bind".into())
        );

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("network: network"));
        assert!(yaml.contains("network-bind: network-bind"));
        assert!(yaml.contains("home: home"));
    }

    #[test]
    fn test_typed_slots_and_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "slotted",
                    version = "1.0",
                    slots = {
                        ["shared-data"] = {
                            interface = "content",
                            content = "my-content",
                            read = "$SNAP/data",
                        },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let slots = meta.slots.as_ref().unwrap();
        match &slots["shared-data"] {
            SnapPlug::Typed(p) => {
                assert_eq!(p.interface, "content");
                assert_eq!(
                    p.attributes.get("content").map(String::as_str),
                    Some("my-content")
                );
            }
            other => panic!("expected Typed slot, got {other:?}"),
        }
        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("slots:"));
        assert!(yaml.contains("interface: content"));
    }

    #[test]
    fn test_plug_map_validation_errors() {
        let env = LuaEnv::new();

        // Non-string, non-table value
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "p", version = "1",
                    plugs = { network = 42 },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("plugs['network'] must be a string or table, got number"),
            "got: {err}"
        );

        // Typed entry without interface
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "p", version = "1",
                    plugs = { shared = { content = "x" } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("plugs['shared'].interface must be a string, got nil"),
            "got: {err}"
        );

        // Non-string attribute
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "p", version = "1",
                    slots = { shared = { interface = "content", content = 7 } },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("slots['shared'].content must be a string, got number"),
            "got: {err}"
        );
    }

    #[test]
    fn test_global_environment_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "envy",
                    version = "1.0",
                    environment = { MY_VAR = "hello", OTHER_VAR = "world" },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let env_map = meta.environment.as_ref().unwrap();
        assert_eq!(env_map.get("MY_VAR").map(String::as_str), Some("hello"));
        assert_eq!(env_map.get("OTHER_VAR").map(String::as_str), Some("world"));

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("environment:"));
        assert!(yaml.contains("MY_VAR: hello"));
        assert!(yaml.contains("OTHER_VAR: world"));
    }

    #[test]
    fn test_environment_validation_error() {
        let env = LuaEnv::new();
        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "e", version = "1",
                    environment = { VAR = 42 },
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("environment['VAR'] must be a string, got number"),
            "got: {err}"
        );
    }

    #[test]
    fn test_icon_target_and_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "iconic",
                    version = "1.0",
                    icon = "assets/logo.png",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        assert_eq!(meta.icon_source.as_deref(), Some("assets/logo.png"));
        assert_eq!(meta.icon.as_deref(), Some("meta/gui/icon.png"));

        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("icon: meta/gui/icon.png"));
        // Source path stays out of snap.yaml.
        assert!(!yaml.contains("assets/logo.png"));
    }

    #[test]
    fn test_icon_requires_extension() {
        let env = LuaEnv::new();
        let result = env.eval(
            r#"
            return {
                default = snap {
                    name = "i", version = "1",
                    icon = "assets/README",
                },
            }
            "#,
        );
        // DSL accepts the string; Rust derivation rejects the missing extension.
        let table = result.unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let err = SnapMeta::from_lua_table(&default_table)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'icon' must have a file extension"),
            "got: {err}"
        );
    }

    #[test]
    fn test_compression_validation() {
        let env = LuaEnv::new();
        for comp in ["xz", "lzo"] {
            let table = env
                .eval(&format!(
                    r#"
                    return {{
                        default = snap {{
                            name = "c", version = "1",
                            compression = "{comp}",
                        }},
                    }}
                    "#
                ))
                .unwrap();
            let default_table: mlua::Table = table.get("default").unwrap();
            let meta = SnapMeta::from_lua_table(&default_table).unwrap();
            assert_eq!(meta.compression.as_deref(), Some(comp));
        }

        let err = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "c", version = "1",
                    compression = "lzip",
                },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("'compression' must be one of: xz, lzo"),
            "got: {err}"
        );
    }

    #[test]
    fn test_type_snapd_types_emitted() {
        let env = LuaEnv::new();

        // base emits type: base
        let table = env
            .eval(
                r#"
            return {
                default = snap { name = "b", version = "1", type = "base" },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();
        assert!(yaml.contains("type: base"), "got: {yaml}");

        // app is snapd's default — omitted
        let table = env
            .eval(
                r#"
            return {
                default = snap { name = "a", version = "1", type = "app" },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();
        assert!(!yaml.contains("type:"), "got: {yaml}");

        // Internal build classifications stay out of snap.yaml
        let table = env
            .eval(
                r#"
            return {
                default = snap { name = "s", version = "1", type = "source" },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(meta.type_.as_deref(), Some("source")); // build metadata preserved
        let yaml = meta.to_yaml().unwrap();
        assert!(!yaml.contains("type:"), "got: {yaml}");
    }

    #[test]
    fn test_type_validation_error() {
        let env = LuaEnv::new();
        let err = env
            .eval(
                r#"
            return {
                default = snap { name = "t", version = "1", type = "os" },
            }
            "#,
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "'type' must be one of: source, meta, store, app, base, gadget, kernel, snapd"
            ),
            "got: {err}"
        );
    }

    #[test]
    fn test_adopt_info_relaxes_version() {
        let env = LuaEnv::new();

        // adopt-info without version: accepted, version placeholder —
        // marked as adopted so it never reads as a declared version.
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "adopted",
                    adopt_info = "my-part",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(meta.adopt_info.as_deref(), Some("my-part"));
        assert_eq!(meta.version, "0"); // placeholder — resolved at build time
        assert!(meta.version_adopted);
        assert_eq!(meta.display_version(), "(version adopted at build)");

        // adopt-info is a snapcraft build-time key, not snapd schema — it
        // must never be emitted into snap.yaml (same bug class as `source:`).
        let yaml = meta.to_yaml().unwrap();
        assert!(
            !yaml.contains("adopt-info"),
            "adopt-info must not be emitted to snap.yaml, got: {yaml}"
        );

        // adopt-info with explicit version: version preserved and marked
        // declared.
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "adopted",
                    version = "2.5",
                    adopt_info = "my-part",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(meta.version, "2.5");
        assert!(!meta.version_adopted);
        assert_eq!(meta.display_version(), "2.5");
    }

    // ── adopt-info: build-time extraction ladder ──

    /// Eval a definition with adopt-info into a SnapMeta.
    fn adopt_meta(lua_snap_body: &str) -> SnapMeta {
        let env = LuaEnv::new();
        let table = env
            .eval(&format!(
                "return {{ default = snap {{ {lua_snap_body} }} }}"
            ))
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        SnapMeta::from_lua_table(&default_table).unwrap()
    }

    /// A source tree + stage pair for extraction fixtures, with `files`
    /// written under `src_root` or `stage` respectively.
    fn adopt_fixtures(
        src_files: &[(&str, &str)],
        stage_files: &[(&str, &str)],
    ) -> (tempfile::TempDir, tempfile::TempDir) {
        let src = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        for (name, content) in src_files {
            std::fs::write(src.path().join(name), content).unwrap();
        }
        for (name, content) in stage_files {
            let path = stage.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        (src, stage)
    }

    #[test]
    fn test_adopt_info_metadata_json_supplies_fields() {
        let meta = adopt_meta(
            r#"name = "adopted", adopt_info = "core", parts = { core = { plugin = "make" } }"#,
        );
        let (src, stage) = adopt_fixtures(
            &[],
            &[(
                "snap/metadata.json",
                r#"{"version": "7.4", "summary": "Adopted summary", "description": "Adopted description"}"#,
            )],
        );
        let adopted = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap()
            .expect("adopt metadata extracted");
        let version = adopted.version.expect("version extracted");
        assert_eq!(version.value, "7.4");
        assert_eq!(version.from, "snap/metadata.json");
        assert_eq!(adopted.summary.as_deref(), Some("Adopted summary"));
        assert_eq!(adopted.description, Some("Adopted description".into()));
        assert!(adopted.warnings.is_empty());
    }

    #[test]
    fn test_adopt_info_metadata_json_unparsable_is_an_error() {
        let meta = adopt_meta(
            r#"name = "adopted", adopt_info = "core", parts = { core = { plugin = "make" } }"#,
        );
        let (src, stage) = adopt_fixtures(&[], &[("snap/metadata.json", "{not json")]);
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not valid JSON"), "got: {err}");
    }

    #[test]
    fn test_adopt_info_explicit_version_wins_with_warning() {
        let meta = adopt_meta(
            r#"
            name = "adopted", version = "2.5", adopt_info = "core",
            parts = { core = { plugin = "autotools" } }
            "#,
        );
        let (src, stage) = adopt_fixtures(
            &[("configure.ac", "AC_INIT([adopted], [7.4])\n")],
            &[("snap/metadata.json", r#"{"summary": "Stage summary"}"#)],
        );
        let adopted = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap()
            .unwrap();
        // Explicit version wins outright — it feeds cache identity and the
        // snap filename, so it never moves silently.
        assert!(adopted.version.is_none());
        assert_eq!(meta.version, "2.5");
        // The divergence is warned about, naming both sides.
        assert!(
            adopted
                .warnings
                .iter()
                .any(|w| w.contains("explicit version '2.5' wins")
                    && w.contains("7.4")
                    && w.contains("configure.ac")),
            "got: {:?}",
            adopted.warnings
        );
        // Explicit version wins per-field only: summary still adopted.
        assert_eq!(adopted.summary.as_deref(), Some("Stage summary"));
    }

    #[test]
    fn test_adopt_info_plugin_extractors_on_fixture_trees() {
        // The registry plugins with canonical version files (meson has an
        // extractor too, but no plugin — tested at the plugins.rs level).
        let cases: Vec<(&str, &str, &str, &str)> = vec![
            // (plugin, fixture file, fixture content, expected version)
            (
                "autotools",
                "configure.ac",
                "AC_INIT([pkg], [7.4])\n",
                "7.4",
            ),
            (
                "cargo",
                "Cargo.toml",
                "[package]\nname = \"pkg\"\nversion = \"0.8.2\"\n",
                "0.8.2",
            ),
            (
                "cmake",
                "CMakeLists.txt",
                "project(pkg VERSION 5.6.4 LANGUAGES C)\n",
                "5.6.4",
            ),
        ];
        for (plugin, file, content, expected) in cases {
            let meta = adopt_meta(&format!(
                r#"name = "adopted", adopt_info = "core", parts = {{ core = {{ plugin = "{plugin}" }} }}"#
            ));
            let (src, stage) = adopt_fixtures(&[(file, content)], &[]);
            let adopted = extract_adopted_meta(&meta, src.path(), stage.path())
                .unwrap_or_else(|e| panic!("{plugin}: {e}"))
                .unwrap();
            let version = adopted
                .version
                .unwrap_or_else(|| panic!("{plugin}: no version extracted"));
            assert_eq!(version.value, expected, "plugin {plugin}");
            assert!(!version.from.is_empty());
        }
    }

    #[test]
    fn test_adopt_info_version_disagreement_is_an_error() {
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "autotools" } }
            "#,
        );
        let (src, stage) = adopt_fixtures(
            &[
                ("configure.ac", "AC_INIT([pkg], [1.0])\n"),
                ("configure.in", "AC_INIT([pkg], [2.0])\n"),
            ],
            &[],
        );
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("conflicting version metadata within part 'core'")
                && err.contains("configure.ac says '1.0'")
                && err.contains("configure.in says '2.0'"),
            "got: {err}"
        );
    }

    #[test]
    fn test_adopt_info_absent_version_is_an_error_never_placeholder() {
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "autotools" } }
            "#,
        );
        // No metadata anywhere — extraction must fail, never fall back to "0".
        let (src, stage) = adopt_fixtures(&[], &[]);
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no version metadata found for part 'core'"),
            "got: {err}"
        );

        // A make part has no canonical version file either — same error,
        // naming the plugin.
        let meta = adopt_meta(
            r#"name = "adopted", adopt_info = "core", parts = { core = { plugin = "make" } }"#,
        );
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("plugin 'make'"), "got: {err}");
    }

    #[test]
    fn test_adopt_info_field_caps_error_never_truncate() {
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "make" } }
            "#,
        );
        // Over-limit version (33 bytes > snapd's 32-byte cap): snapd
        // measures version in bytes.
        let long_version = "a".repeat(33);
        let (src, stage) = adopt_fixtures(
            &[],
            &[(
                "snap/metadata.json",
                &format!(r#"{{"version": "{long_version}"}}"#),
            )],
        );
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds snapd's 32-byte limit"), "got: {err}");

        // Same for an over-long summary (129 codepoints > 128)...
        let long_summary = "s".repeat(129);
        let (src, stage) = adopt_fixtures(
            &[],
            &[(
                "snap/metadata.json",
                &format!(r#"{{"version": "1.0", "summary": "{long_summary}"}}"#),
            )],
        );
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("extracted summary") && err.contains("128-character limit"),
            "got: {err}"
        );

        // ...and an over-long description (4097 codepoints > 4096).
        let long_description = "d".repeat(4097);
        let (src, stage) = adopt_fixtures(
            &[],
            &[(
                "snap/metadata.json",
                &format!(r#"{{"version": "1.0", "description": "{long_description}"}}"#),
            )],
        );
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("extracted description") && err.contains("4096-character limit"),
            "got: {err}"
        );
    }

    #[test]
    fn test_adopt_info_field_caps_at_limit_pass() {
        // At-limit values pass: version counts BYTES, summary/description
        // count Unicode codepoints — 128 'é' are 256 bytes but exactly at
        // snapd's 128-codepoint summary cap.
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "make" } }
            "#,
        );
        let version = "a".repeat(32);
        let summary = "é".repeat(128);
        let description = "é".repeat(4096);
        let metadata = format!(
            r#"{{"version": "{version}", "summary": "{summary}", "description": "{description}"}}"#
        );
        let (src, stage) = adopt_fixtures(&[], &[("snap/metadata.json", &metadata)]);
        let adopted = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap()
            .expect("at-limit values must pass");
        assert_eq!(adopted.version.unwrap().value, version);
        assert_eq!(adopted.summary.as_deref(), Some(summary.as_str()));
        assert_eq!(adopted.description.as_deref(), Some(description.as_str()));
    }

    #[test]
    fn test_adopt_info_version_charset_is_enforced() {
        // snapd also constrains the version charset (snap/validate.go):
        // starts alphanumeric, ends alphanumeric or `+`/`~`, interior may
        // additionally be one of `: . + ~ -` — same hard-error stance.
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "make" } }
            "#,
        );
        let cases: &[(&str, bool)] = &[
            ("7.4", true),
            ("1.0-beta+build.2", true),
            ("2", true),
            ("-1.0", false),     // must start alphanumeric
            ("1.", false),       // must end alphanumeric or +/~
            ("1.0 beta", false), // space is not in the charset
            ("1.0λ", false),     // non-ASCII never matches
            ("", false),         // empty is not a version
        ];
        for (version, ok) in cases {
            let metadata = format!(r#"{{"version": "{version}"}}"#);
            let (src, stage) = adopt_fixtures(&[], &[("snap/metadata.json", &metadata)]);
            let result = extract_adopted_meta(&meta, src.path(), stage.path());
            assert_eq!(result.is_ok(), *ok, "version {version:?}: got {result:?}");
        }
        // The rejection names the charset, not the length.
        let (src, stage) =
            adopt_fixtures(&[], &[("snap/metadata.json", r#"{"version": "1.0 beta"}"#)]);
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("version charset"), "got: {err}");
    }

    #[test]
    fn test_adopt_info_metainfo_supplies_summary_description() {
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "core",
            parts = { core = { plugin = "make" } }
            "#,
        );
        let (src, stage) = adopt_fixtures(
            &[],
            &[(
                "snap/metadata.json",
                r#"{"version": "7.4"}"#,
            ),
            (
                "usr/share/metainfo/pkg.metainfo.xml",
                "<component>\n  <summary>  Short one-line summary </summary>\n  <description>\n\
                 <p>First.</p>\n<p xml:lang=\"en\">Second.</p>\n\
                 </description>\n</component>\n",
            )],
        );
        let adopted = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap()
            .unwrap();
        // Version comes from rung 2 (metadata.json); summary/description
        // per-field from the metainfo rung.
        assert_eq!(adopted.version.unwrap().value, "7.4");
        assert_eq!(adopted.summary.as_deref(), Some("Short one-line summary"));
        assert_eq!(adopted.description.as_deref(), Some("First.\n\nSecond."));
    }

    #[test]
    fn test_adopt_info_names_must_reference_a_real_part() {
        // Unknown part name.
        let meta = adopt_meta(
            r#"
            name = "adopted", adopt_info = "nope",
            parts = { core = { plugin = "make" } }
            "#,
        );
        let (src, stage) = adopt_fixtures(&[], &[]);
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("adopt-info names part 'nope'") && err.contains("no such part"),
            "got: {err}"
        );

        // No parts at all (single `build` snap).
        let meta = adopt_meta(r#"name = "adopted", adopt_info = "core", build = "true""#);
        let err = extract_adopted_meta(&meta, src.path(), stage.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("has no parts (adopt-info refers to a parts: entry)"),
            "got: {err}"
        );
    }

    #[test]
    fn test_version_still_required_without_adopt_info() {
        let env = LuaEnv::new();
        let result = env.eval(
            r#"
            return {
                default = snap { name = "strict" },
            }
            "#,
        );
        // Lua-side rejection
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing required field 'version'"),
            "got: {err}"
        );

        // Rust-side rejection (table smuggled past Lua validation)
        let table = env
            .eval(
                r#"
            return { default = { name = "strict" } }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let err = SnapMeta::from_lua_table(&default_table)
            .unwrap_err()
            .to_string();
        assert!(err.contains("field 'version' is required"), "got: {err}");
    }

    // ── Phase 15 integration: all new fields at once ──

    #[test]
    fn test_phase15_all_fields_snap_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "my-app",
                    version = "1.0",
                    summary = "Full-coverage app",
                    description = "Exercises every Phase 15 field",
                    type = "app",
                    compression = "lzo",
                    icon = "my-icon.svg",
                    adopt_info = nil, -- explicit version above
                    environment = { APP_MODE = "production" },
                    layout = {
                        ["/etc/myapp.conf"] = { bind_file = "$SNAP_DATA/etc/myapp.conf" },
                        ["/var/run/myapp"] = { symlink = "$SNAP_COMMON/run" },
                        ["/var/cache/myapp"] = { tmpfs = { size = "100M" } },
                    },
                    hooks = {
                        configure = "scripts/configure.sh",
                        install = "scripts/install.sh",
                    },
                    plugs = {
                        network = { interface = "network" },
                        ["shared-data"] = {
                            interface = "content",
                            content = "my-content",
                            target = "$SNAP/data",
                            default_provider = "producer",
                        },
                    },
                    slots = {
                        ["shared-data"] = { interface = "content", content = "my-content" },
                    },
                    apps = {
                        hello = app { command = "bin/hello" },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();

        // layout block
        assert!(yaml.contains("layout:"));
        assert!(yaml.contains("bind-file: $SNAP_DATA/etc/myapp.conf"));
        assert!(yaml.contains("symlink: $SNAP_COMMON/run"));
        assert!(yaml.contains("tmpfs:"));
        assert!(yaml.contains("size: 100M"));

        // hooks block
        assert!(yaml.contains("hooks:"));
        assert!(yaml.contains("configure:"));
        assert!(yaml.contains("command: meta/hooks/configure"));
        assert!(yaml.contains("install:"));
        assert!(yaml.contains("command: meta/hooks/install"));

        // plugs/slots blocks
        assert!(yaml.contains("plugs:"));
        assert!(yaml.contains("network:"));
        assert!(yaml.contains("shared-data:"));
        assert!(yaml.contains("interface: content"));
        assert!(yaml.contains("default_provider: producer"));
        assert!(yaml.contains("slots:"));

        // global environment, icon, compression (build-only), type (default omitted)
        assert!(yaml.contains("environment:"));
        assert!(yaml.contains("APP_MODE: production"));
        assert!(yaml.contains("icon: meta/gui/icon.svg"));
        assert!(!yaml.contains("compression")); // build-time only
        assert!(!yaml.contains("type:")); // app is snapd's default
    }

    #[test]
    fn test_phase15_build_copies_hooks_icon_and_compression() {
        // Real files for hook scripts and the icon (absolute paths).
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("scripts")).unwrap();
        std::fs::write(
            project.path().join("scripts/configure.sh"),
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();
        std::fs::write(project.path().join("my-icon.png"), b"fake png bytes").unwrap();

        let env = LuaEnv::new();
        let src = format!(
            r#"
            return {{
                default = snap {{
                    name = "phase15-build",
                    version = "1.0",
                    compression = "lzo",
                    icon = "{}",
                    hooks = {{
                        configure = "{}",
                    }},
                }},
            }}
            "#,
            project.path().join("my-icon.png").display(),
            project.path().join("scripts/configure.sh").display(),
        );
        let table = env.eval(&src).unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let stage_dir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let result = build_snap(
            &meta,
            stage_dir.path(),
            output_dir.path(),
            "amd64",
            StagePolicy::Default,
            None,
            None,
        )
        .unwrap();
        let snap_path = output_dir.path().join(&result.snap_filename);
        assert!(snap_path.exists());

        // Hook script and icon must be inside the snap.
        let listing = std::process::Command::new("unsquashfs")
            .args(["-l", &snap_path.to_string_lossy()])
            .output()
            .expect("unsquashfs should be available");
        let stdout = String::from_utf8_lossy(&listing.stdout);
        assert!(stdout.contains("meta/hooks/configure"), "got: {stdout}");
        assert!(stdout.contains("meta/gui/icon.png"), "got: {stdout}");

        // Extract snap.yaml and check the emitted hook command + icon path.
        let extract_dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("unsquashfs")
            .args([
                "-f",
                "-d",
                &extract_dir.path().to_string_lossy(),
                &snap_path.to_string_lossy(),
                "meta/snap.yaml",
            ])
            .status()
            .expect("unsquashfs should be available");
        assert!(status.success());
        let yaml = std::fs::read_to_string(extract_dir.path().join("meta/snap.yaml")).unwrap();
        assert!(
            yaml.contains("command: meta/hooks/configure"),
            "got: {yaml}"
        );
        assert!(yaml.contains("icon: meta/gui/icon.png"), "got: {yaml}");

        // compression = "lzo" was wired into mksquashfs — an invalid -comp
        // value would have failed the build above.
        assert_eq!(meta.compression.as_deref(), Some("lzo"));
    }

    // ── Phase 18 tests: multi-part builds ──

    #[test]
    fn test_parts_dsl_roundtrip() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "multi",
                    version = "1.0",
                    parts = {
                        ui = { build = "npm run build", after = { "core" } },
                        core = { build = "make" },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let parts = meta.parts.as_ref().expect("parts extracted");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts["core"].build, "make");
        assert!(parts["core"].after.is_empty());
        assert_eq!(parts["ui"].build, "npm run build");
        assert_eq!(parts["ui"].after, vec!["core".to_string()]);
        assert!(meta.build.is_none());
    }

    #[test]
    fn test_implicit_single_part_back_compat() {
        // `build = "..."` stays valid and never produces parts.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "legacy",
                    version = "1.0",
                    build = "make && make install DESTDIR=$STAGE",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(
            meta.build.as_deref(),
            Some("make && make install DESTDIR=$STAGE")
        );
        assert!(meta.parts.is_none());
    }

    #[test]
    fn test_parts_stay_out_of_snap_yaml() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "multi",
                    version = "1.0",
                    parts = { core = { build = "make" } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let yaml = meta.to_yaml().unwrap();
        assert!(!yaml.contains("parts:"));
        assert!(!yaml.contains("build:"));
    }

    fn eval_parts_source_error(lua_source: &str) -> String {
        let env = LuaEnv::new();
        let src = format!(
            r#"
            return {{
                default = snap {{
                    name = "bad-parts",
                    version = "1.0",
                    {lua_source}
                }},
            }}
            "#
        );
        env.eval(&src).unwrap_err().to_string()
    }

    #[test]
    fn test_parts_conflict_with_build_dsl() {
        let err =
            eval_parts_source_error(r#"build = "make", parts = { core = { build = "make" } }"#);
        assert!(
            err.contains("mutually exclusive"),
            "error should mention the build/parts conflict: {err}"
        );
    }

    #[test]
    fn test_parts_must_be_table_dsl() {
        let err = eval_parts_source_error(r#"parts = "core""#);
        assert!(
            err.contains("'parts' must be a table"),
            "error should mention parts type: {err}"
        );
    }

    #[test]
    fn test_parts_must_not_be_empty_dsl() {
        let err = eval_parts_source_error("parts = {}");
        assert!(
            err.contains("'parts' must not be empty"),
            "error should mention empty parts: {err}"
        );
    }

    #[test]
    fn test_parts_entry_must_be_table_dsl() {
        let err = eval_parts_source_error(r#"parts = { core = "make" }"#);
        assert!(
            err.contains("parts['core'] must be a table"),
            "error should mention part type: {err}"
        );
    }

    #[test]
    fn test_parts_build_must_be_non_empty_string_dsl() {
        let err = eval_parts_source_error("parts = { core = { after = {} } }");
        assert!(
            err.contains("parts['core'].build must be a non-empty string"),
            "error should mention missing build: {err}"
        );

        let err = eval_parts_source_error(r#"parts = { core = { build = "" } }"#);
        assert!(
            err.contains("parts['core'].build must be a non-empty string"),
            "error should mention empty build: {err}"
        );
    }

    #[test]
    fn test_parts_after_must_be_string_array_dsl() {
        let err =
            eval_parts_source_error(r#"parts = { core = { build = "make", after = "libs" } }"#);
        assert!(
            err.contains("parts['core'].after must be an array"),
            "error should mention after type: {err}"
        );

        let err =
            eval_parts_source_error(r#"parts = { core = { build = "make", after = { 42 } } }"#);
        assert!(
            err.contains("parts['core'].after[1] must be a string"),
            "error should mention after element type: {err}"
        );
    }

    #[test]
    fn test_parts_unknown_after_dsl() {
        let err =
            eval_parts_source_error(r#"parts = { core = { build = "make", after = { "libs" } } }"#);
        assert!(
            err.contains("parts['core'].after references unknown part 'libs'"),
            "error should mention the unknown part: {err}"
        );
    }

    #[test]
    fn test_parts_self_cycle_dsl() {
        let err = eval_parts_source_error(r#"parts = { a = { build = "make", after = { "a" } } }"#);
        assert!(
            err.contains("circular dependency in parts: a -> a"),
            "error should report the cycle path: {err}"
        );
    }

    #[test]
    fn test_parts_two_node_cycle_dsl() {
        let err = eval_parts_source_error(
            r#"
            parts = {
                a = { build = "make", after = { "b" } },
                b = { build = "make", after = { "a" } },
            }
            "#,
        );
        assert!(
            err.contains("circular dependency in parts") && err.contains("->"),
            "error should report the cycle path: {err}"
        );
    }

    #[test]
    fn test_order_parts_dependency_respecting_with_name_tiebreak() {
        // Diamond: libs has no after and is the only runnable part first;
        // among {app, cli, zzz} after libs completes, name order applies.
        let parts: BTreeMap<String, SnapPart> = [
            (
                "app",
                SnapPart {
                    build: "make app".into(),
                    after: vec!["libs".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "cli",
                SnapPart {
                    build: "make cli".into(),
                    after: vec!["libs".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "libs",
                SnapPart {
                    build: "make libs".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "zzz",
                SnapPart {
                    build: "make zzz".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        assert_eq!(
            order_parts(&parts).unwrap(),
            vec!["libs", "app", "cli", "zzz"]
        );
    }

    #[test]
    fn test_order_parts_chain() {
        let parts: BTreeMap<String, SnapPart> = [
            (
                "c",
                SnapPart {
                    build: "c".into(),
                    after: vec!["b".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "b",
                SnapPart {
                    build: "b".into(),
                    after: vec!["a".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "a",
                SnapPart {
                    build: "a".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        assert_eq!(order_parts(&parts).unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_order_parts_rejects_cycle_in_rust() {
        // Non-DSL constructors can bypass Lua validation; the scheduler
        // must not hang.
        let parts: BTreeMap<String, SnapPart> = [
            (
                "a",
                SnapPart {
                    build: "a".into(),
                    after: vec!["b".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "b",
                SnapPart {
                    build: "b".into(),
                    after: vec!["a".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        let err = order_parts(&parts).unwrap_err().to_string();
        assert!(
            err.contains("circular or unsatisfiable dependency among parts"),
            "got: {err}"
        );
    }

    #[test]
    fn test_order_parts_rejects_invalid_names() {
        let make = |name: &str| {
            BTreeMap::from([(
                name.to_string(),
                SnapPart {
                    build: "true".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            )])
        };
        assert!(order_parts(&make("source")).is_err()); // reserved
        assert!(order_parts(&make("a/b")).is_err());
        assert!(order_parts(&make("..")).is_err());
        assert!(order_parts(&make(".")).is_err());
    }

    #[test]
    fn test_run_parts_ordering_shared_stage_and_part_env() {
        let tree = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let abs_stage = std::fs::canonicalize(stage.path()).unwrap();
        std::fs::create_dir_all(tree.path().join(SOURCE_DIR_NAME)).unwrap();

        let parts: BTreeMap<String, SnapPart> = [
            (
                "b",
                SnapPart {
                    // Proves: $PART_NAME, `after` blocked until `a` was done
                    // (its marker exists), and cwd is b's own work dir.
                    build: r#"test "$PART_NAME" = "b" && test -f "$STAGE/a.done" && pwd > "$STAGE/b.pwd""#.into(),
                    after: vec!["a".into()],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "a",
                SnapPart {
                    build: r#"test "$PART_NAME" = "a" && touch "$STAGE/a.done""#.into(),
                    after: vec![], plugin: None,
 plugin_options: None,
                },
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        run_parts(
            &parts,
            tree.path(),
            &tree.path().join(SOURCE_DIR_NAME),
            &abs_stage,
            None,
            None,
        )
        .unwrap();

        // Shared stage: both parts installed into the same dir.
        assert!(abs_stage.join("a.done").exists(), "a must have run");
        let pwd = std::fs::read_to_string(abs_stage.join("b.pwd")).unwrap();
        let pwd = pwd.trim_end();
        assert!(
            pwd.ends_with("/b"),
            "b must run in its own work dir under the build tree, got: {pwd}"
        );
        assert!(tree.path().join("b").is_dir());
    }

    #[test]
    fn test_run_parts_fails_when_after_dependency_missing_marker() {
        // If ordering were violated, b's marker check would fail.
        let tree = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        let abs_stage = std::fs::canonicalize(stage.path()).unwrap();

        let parts: BTreeMap<String, SnapPart> = [(
            "b",
            SnapPart {
                build: r#"test -f "$STAGE/never-created""#.into(),
                after: vec![],
                plugin: None,
                plugin_options: None,
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        assert!(run_parts(&parts, tree.path(), tree.path(), &abs_stage, None, None).is_err());
    }

    #[test]
    fn test_run_build_rejects_build_and_parts_conflict() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap { name = "conflict", version = "1.0", build = "make" },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let mut meta = SnapMeta::from_lua_table(&default_table).unwrap();
        meta.parts = Some(BTreeMap::from([(
            "core".to_string(),
            SnapPart {
                build: "make".into(),
                after: vec![],
                plugin: None,
                plugin_options: None,
            },
        )]));

        let err = run_build(
            &meta,
            Path::new("/nonexistent-stage"),
            StagePolicy::Default,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("both 'build' and 'parts'"), "got: {err}");
    }

    #[test]
    fn test_run_build_rejects_empty_parts() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap { name = "empty-parts", version = "1.0" },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let mut meta = SnapMeta::from_lua_table(&default_table).unwrap();
        meta.build = None;
        meta.parts = Some(BTreeMap::new());

        let err = run_build(
            &meta,
            Path::new("/nonexistent-stage"),
            StagePolicy::Default,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("'parts' must not be empty"), "got: {err}");
    }

    // ── ADR-0014: built-in builder plugins ──

    #[test]
    fn test_plugin_part_dsl_roundtrip() {
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "plugins",
                    version = "1.0",
                    parts = {
                        core = {
                            plugin = "make",
                            options = { target = "all" },
                        },
                        docs = { build = "true", after = { "core" } },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let parts = meta.parts.as_ref().expect("parts extracted");
        let core = &parts["core"];
        assert_eq!(core.plugin.as_deref(), Some("make"));
        assert_eq!(core.build, "", "plugin parts carry an empty build marker");
        assert_eq!(
            core.plugin_options.as_ref().expect("options extracted")["target"],
            crate::plugins::PluginValue::Str("all".into())
        );
        assert!(parts["docs"].plugin.is_none());
        // Plugin must not leak into snap.yaml.
        let yaml = meta.to_yaml().unwrap();
        assert!(!yaml.contains("parts:"));
        assert!(!yaml.contains("options"));
    }

    #[test]
    fn test_plugin_conflicts_with_build_dsl() {
        let err =
            eval_parts_source_error(r#"parts = { core = { plugin = "make", build = "make" } }"#);
        assert!(
            err.contains("parts['core'] must have exactly one of 'build' or 'plugin'"),
            "error should mention the per-part conflict: {err}"
        );
    }

    #[test]
    fn test_plugin_unknown_name_dsl() {
        let err = eval_parts_source_error(r#"parts = { core = { plugin = "gmake" } }"#);
        assert!(
            err.contains("parts['core'].plugin must be one of:")
                && err.contains("autotools")
                && err.contains("cargo")
                && err.contains("cmake")
                && err.contains("make")
                && err.contains("gmake"),
            "error should list available plugins: {err}"
        );
    }

    #[test]
    fn test_plugin_must_be_string_dsl() {
        let err = eval_parts_source_error("parts = { core = { plugin = 42 } }");
        assert!(
            err.contains("parts['core'].plugin must be a non-empty string"),
            "got: {err}"
        );
        let err = eval_parts_source_error(r#"parts = { core = { plugin = "" } }"#);
        assert!(
            err.contains("parts['core'].plugin must be a non-empty string"),
            "got: {err}"
        );
    }

    #[test]
    fn test_plugin_options_must_be_table_dsl() {
        let err =
            eval_parts_source_error(r#"parts = { core = { plugin = "make", options = "x" } }"#);
        assert!(
            err.contains("parts['core'].options must be a table"),
            "got: {err}"
        );
    }

    #[test]
    fn test_plugin_options_deep_validated_at_rust_boundary() {
        // The Lua layer accepts any options table; the named error comes
        // from the plugin boundary (ADR-0014 Decision 3).
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "bad-options",
                    version = "1.0",
                    parts = { core = { plugin = "cargo", options = { channel = "fork" } } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let err = SnapMeta::from_lua_table(&default_table)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("parts['core']")
                && err.contains("cargo: option 'channel' must be one of: stable, beta, nightly"),
            "got: {err}"
        );

        // Wrong option type.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "bad-options",
                    version = "1.0",
                    parts = { core = { plugin = "cargo", options = { channel = { "stable" } } } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let err = SnapMeta::from_lua_table(&default_table)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cargo: option 'channel' must be a string"),
            "got: {err}"
        );

        // Unknown option.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "bad-options",
                    version = "1.0",
                    parts = { core = { plugin = "make", options = { jobs = "4" } } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let err = SnapMeta::from_lua_table(&default_table)
            .unwrap_err()
            .to_string();
        assert!(err.contains("make: unknown option 'jobs'"), "got: {err}");

        // Booleans and string maps pass the boundary (registry v2 growth:
        // make `install`, autotools `in_source`, make `variables`).
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "grown-options",
                    version = "1.0",
                    parts = {
                        core = {
                            plugin = "make",
                            options = {
                                install = false,
                                variables = { CFLAGS = "-O2" },
                            },
                        },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        let options = meta.parts.as_ref().expect("parts extracted")["core"]
            .plugin_options
            .as_ref()
            .expect("options extracted");
        assert_eq!(options["install"], crate::plugins::PluginValue::Bool(false));
        assert_eq!(
            options["variables"],
            crate::plugins::PluginValue::Map(
                [("CFLAGS".to_string(), "-O2".to_string())]
                    .into_iter()
                    .collect()
            )
        );
    }

    #[test]
    fn test_cargo_plugin_appends_toolchain_require() {
        // ADR-0014 Decision 4: extra_requires land in the snap's effective
        // requires (the same field dependency resolution reads).
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "rust-app",
                    version = "1.0",
                    requires = { "zlib" },
                    parts = { core = { plugin = "cargo", options = { channel = "beta" } } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(
            meta.requires,
            vec!["zlib".to_string(), "toolchain-gcc-gnu-x86_64".to_string()]
        );

        // Deduplicated on repeat plugin parts.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "rust-app",
                    version = "1.0",
                    parts = {
                        a = { plugin = "cargo" },
                        b = { plugin = "cargo", after = { "a" } },
                    },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert_eq!(meta.requires, vec!["toolchain-gcc-gnu-x86_64".to_string()]);
    }

    #[test]
    fn test_part_build_plan_rejects_corrupt_parts() {
        // Non-DSL constructors can bypass Lua validation.
        let both = SnapPart {
            build: "make".into(),
            after: vec![],
            plugin: Some("make".into()),
            plugin_options: None,
        };
        let err = part_build_plan("core", &both).unwrap_err().to_string();
        assert!(
            err.contains("part 'core' must have exactly one of 'build' or 'plugin'"),
            "got: {err}"
        );

        let neither = SnapPart {
            build: String::new(),
            after: vec![],
            plugin: None,
            plugin_options: None,
        };
        let err = part_build_plan("core", &neither).unwrap_err().to_string();
        assert!(
            err.contains("part 'core' must have exactly one of 'build' or 'plugin'"),
            "got: {err}"
        );
    }

    // ── ADR-0014 E2E: plugin parts through run_parts ──
    //
    // Every host tool is stubbed (a stage-local PATH prepend), so these run
    // identically with and without bwrap: the stub directory lives under the
    // stage, which the sandbox binds at its absolute host path. Stubbed:
    // `make`, `cmake`, `cargo`. `sh` and coreutils are real. The `configure`
    // fixture for autotools is a plain sh script written by the test — no
    // real autotools involved. No network access is needed or performed.

    /// Prepend `dir` to PATH for the duration of `f`, restoring afterwards
    /// (even if `f` panics). Serialized: PATH is process-global, so parallel
    /// E2E tests must not interleave set/restore.
    fn with_path_prepend<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var("PATH").unwrap_or_default();
        std::env::set_var("PATH", format!("{}:{old}", dir.display()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        std::env::set_var("PATH", old);
        drop(guard);
        result.unwrap()
    }

    /// The path `$SRC` expands to for commands: the build tree is mounted at
    /// `/build` inside the bwrap sandbox, so assertions on expanded `$SRC`
    /// must expect the sandbox path there (host path in direct mode).
    fn expected_src(src: &Path) -> std::path::PathBuf {
        if detect_bwrap().is_some() {
            Path::new("/build").join(SOURCE_DIR_NAME)
        } else {
            src.to_path_buf()
        }
    }

    /// Create an executable stub script at `dir/<name>`.
    fn write_stub(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Shared plugin-E2E scaffolding: build tree with a source dir, stage
    /// (canonicalized, like run_build does for DESTDIR), and the stub dir
    /// under the stage.
    struct PluginE2e {
        tree: tempfile::TempDir,
        src: std::path::PathBuf,
        stage: std::path::PathBuf,
        stubs: std::path::PathBuf,
        _stage_dir: tempfile::TempDir,
    }

    impl PluginE2e {
        fn new() -> Self {
            let tree = tempfile::tempdir().unwrap();
            let stage_dir = tempfile::tempdir().unwrap();
            let stage = std::fs::canonicalize(stage_dir.path()).unwrap();
            let src = tree.path().join(SOURCE_DIR_NAME);
            std::fs::create_dir_all(&src).unwrap();
            let stubs = stage.join(".stubs");
            std::fs::create_dir_all(&stubs).unwrap();
            PluginE2e {
                tree,
                src,
                stage,
                stubs,
                _stage_dir: stage_dir,
            }
        }

        fn invocations(&self) -> String {
            std::fs::read_to_string(self.stage.join("invocations.log")).unwrap_or_default()
        }
    }

    #[test]
    fn test_e2e_make_plugin_expands_and_installs_into_stage() {
        let e2e = PluginE2e::new();
        std::fs::write(
            e2e.src.join("Makefile"),
            "# real Makefile (unused by the stub; proves -C $SRC wiring)\n",
        )
        .unwrap();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
# DESTDIR arrives as a make command-line arg (make install DESTDIR=...), not env.
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
if [ -n "$DESTDIR" ]; then
  mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/hello"
fi
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [(
                        "target".to_string(),
                        crate::plugins::PluginValue::Str("all".into()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let inner_src = expected_src(&e2e.src);
        let log = e2e.invocations();
        assert!(
            log.contains(&format!("make -C {} all", inner_src.display())),
            "build command must run make against $SRC with the target: {log}"
        );
        assert!(
            log.contains(&format!(
                "make -C {} PREFIX=/usr install DESTDIR={}",
                inner_src.display(),
                e2e.stage.display()
            )),
            "install command must honor PREFIX=/usr + DESTDIR=$STAGE: {log}"
        );
        assert!(e2e.stage.join("usr/bin/hello").exists());
    }

    #[test]
    fn test_e2e_make_plugin_variables_reach_command_line() {
        let e2e = PluginE2e::new();
        std::fs::write(
            e2e.src.join("Makefile"),
            "# real Makefile (unused by the stub; proves -C $SRC wiring)\n",
        )
        .unwrap();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
# DESTDIR arrives as a make command-line arg (make install DESTDIR=...), not env.
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
if [ -n "$DESTDIR" ]; then
  mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/hello"
fi
"#,
        );

        // pciutils-shaped part: PREFIX supplied via variables (which replaces
        // the prefix-derived one), inserted out of order to prove sorting.
        let parts: BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [(
                        "variables".to_string(),
                        crate::plugins::PluginValue::Map(
                            [
                                ("ZFLAG".to_string(), "1".to_string()),
                                ("AFLAG".to_string(), "2".to_string()),
                                ("PREFIX".to_string(), "/usr".to_string()),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let inner_src = expected_src(&e2e.src);
        let log = e2e.invocations();
        let vars = "AFLAG=2 PREFIX=/usr ZFLAG=1";
        assert!(
            log.contains(&format!("make -C {} {vars}", inner_src.display())),
            "variables must reach the build command line, sorted: {log}"
        );
        assert!(
            log.contains(&format!(
                "make -C {} {vars} install DESTDIR={}",
                inner_src.display(),
                e2e.stage.display()
            )),
            "variables must reach the install command line: {log}"
        );
        assert!(e2e.stage.join("usr/bin/hello").exists());
    }

    #[test]
    fn test_e2e_make_plugin_install_false_skips_install_step() {
        let e2e = PluginE2e::new();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
if [ -n "$DESTDIR" ]; then
  mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/hello"
fi
"#,
        );

        // Lib-only part (bzip2 shared-lib pattern): staging is arranged by
        // an earlier part; install = false must emit no install step.
        let parts: BTreeMap<String, SnapPart> = [(
            "lib",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [(
                        "install".to_string(),
                        crate::plugins::PluginValue::Bool(false),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let inner_src = expected_src(&e2e.src);
        let log = e2e.invocations();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "install = false must emit exactly one command: {log}"
        );
        assert_eq!(
            lines[0],
            format!("make -C {}", inner_src.display()),
            "and it must be the build command only: {log}"
        );
        assert!(
            !e2e.stage.join("usr/bin/hello").exists(),
            "no install step means nothing was staged"
        );
    }

    #[test]
    fn test_e2e_autotools_in_source_configures_in_src() {
        let e2e = PluginE2e::new();
        // Non-autoconf configure (dhcpcd-style): writes its Makefile next to
        // itself, in $SRC — regardless of the caller's cwd. This is exactly
        // the layout the VPATH expansion breaks.
        std::fs::write(
            e2e.src.join("configure"),
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/configure.log\"\ncat > \"$(dirname \"$0\")/Makefile\" <<'EOF'\nall:\n\t: > \"$(dirname \"$0\")/built\"\ninstall:\n\tmkdir -p $(DESTDIR)/usr/sbin && : > $(DESTDIR)/usr/sbin/dhcpcd\nEOF\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            e2e.src.join("configure"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
case " $* " in
  *" install "*)
    mkdir -p "$DESTDIR/usr/sbin" && : > "$DESTDIR/usr/sbin/dhcpcd" ;;
  *) : > built ;;
esac
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [(
            "lib",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("autotools".into()),
                plugin_options: Some(
                    [
                        (
                            "in_source".to_string(),
                            crate::plugins::PluginValue::Bool(true),
                        ),
                        (
                            "args".to_string(),
                            crate::plugins::PluginValue::Arr(vec!["--sysconfdir=/etc".into()]),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        // configure ran inside $SRC with --prefix=/usr and the args, and its
        // Makefile landed there; make's `built` marker followed (cwd = $SRC).
        let configure_log = std::fs::read_to_string(e2e.src.join("configure.log")).unwrap();
        let lines: Vec<&str> = configure_log.lines().collect();
        assert_eq!(lines, vec!["--prefix=/usr", "--sysconfdir=/etc"]);
        assert!(
            e2e.src.join("Makefile").exists() && e2e.src.join("built").exists(),
            "in_source build must run entirely inside $SRC"
        );
        assert!(
            !e2e.tree.path().join("lib/built").exists(),
            "nothing may land in the VPATH work dir"
        );

        let log = e2e.invocations();
        assert!(
            log.contains("make \n"),
            "plain make must run before install: {log}"
        );
        assert!(
            log.contains(&format!("make install DESTDIR={}", e2e.stage.display())),
            "install must honor DESTDIR=$STAGE: {log}"
        );
        assert!(e2e.stage.join("usr/sbin/dhcpcd").exists());
    }

    #[test]
    fn test_e2e_autotools_plugin_configures_vpath_and_installs_into_stage() {
        let e2e = PluginE2e::new();
        // Fake configure: records its args and emits a Makefile in the cwd
        // (the part work dir — a VPATH build).
        std::fs::write(
            e2e.src.join("configure"),
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > configure.log\ncat > Makefile <<'EOF'\nall:\n\t: > built\ninstall:\n\tmkdir -p $(DESTDIR)/usr/bin && : > $(DESTDIR)/usr/bin/demo\nEOF\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            e2e.src.join("configure"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
# DESTDIR arrives as a make command-line arg, not env.
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
case " $* " in
  *" install "*)
    mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/demo" ;;
  *) : > built ;;
esac
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [(
            "lib",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("autotools".into()),
                plugin_options: Some(
                    [(
                        "args".to_string(),
                        crate::plugins::PluginValue::Arr(vec![
                            "--disable-nls".into(),
                            "--with-ssl".into(),
                        ]),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        // configure ran with --prefix=/usr and the args, in order, and its
        // output landed in the part work dir (not $SRC).
        let configure_log =
            std::fs::read_to_string(e2e.tree.path().join("lib/configure.log")).unwrap();
        let lines: Vec<&str> = configure_log.lines().collect();
        assert_eq!(lines, vec!["--prefix=/usr", "--disable-nls", "--with-ssl"]);
        assert!(
            !e2e.src.join("Makefile").exists(),
            "configure must not write into $SRC"
        );
        assert!(
            e2e.tree.path().join("lib/built").exists(),
            "make ran in the work dir"
        );

        let log = e2e.invocations();
        assert!(
            log.contains("make \n"),
            "plain make must run before install: {log}"
        );
        assert!(
            log.contains(&format!("make install DESTDIR={}", e2e.stage.display())),
            "install must honor DESTDIR=$STAGE: {log}"
        );
        assert!(e2e.stage.join("usr/bin/demo").exists());
    }

    #[test]
    fn test_e2e_cmake_plugin_configures_builds_and_installs_into_stage() {
        let e2e = PluginE2e::new();
        write_stub(
            &e2e.stubs,
            "cmake",
            r#"printf 'cmake %s\n' "$*" >> "$STAGE/invocations.log"
case "$1" in
  -S) mkdir -p build ;;
  --build) : ;;
  --install)
    printf 'DESTDIR=%s\n' "$DESTDIR" >> "$STAGE/invocations.log"
    mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/app" ;;
esac
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("cmake".into()),
                plugin_options: Some(
                    [
                        (
                            "generator".to_string(),
                            crate::plugins::PluginValue::Str("Ninja".into()),
                        ),
                        (
                            "defines".to_string(),
                            crate::plugins::PluginValue::Map(
                                [("USE_SSL".to_string(), "ON".to_string())]
                                    .into_iter()
                                    .collect(),
                            ),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let inner_src = expected_src(&e2e.src);
        let log = e2e.invocations();
        assert!(
            log.contains(&format!(
                "cmake -S {} -B build -G Ninja -DUSE_SSL=ON -DCMAKE_INSTALL_PREFIX=/usr",
                inner_src.display()
            )),
            "configure must point at $SRC with generator + defines: {log}"
        );
        assert!(log.contains("cmake --build build"), "must build: {log}");
        assert!(
            log.contains("cmake --install build")
                && log.contains(&format!("DESTDIR={}", e2e.stage.display())),
            "install must honor DESTDIR=$STAGE: {log}"
        );
        assert!(e2e.stage.join("usr/bin/app").exists());
    }

    #[test]
    fn test_e2e_cargo_plugin_runs_stubbed_toolchain_with_channel_env() {
        let e2e = PluginE2e::new();
        // Stub cargo: logs the invocation AND the channel env the plugin
        // exported, then "installs" a binary into $STAGE/bin.
        write_stub(
            &e2e.stubs,
            "cargo",
            r#"printf 'cargo %s\n' "$*" >> "$STAGE/invocations.log"
printf 'RUSTUP_TOOLCHAIN=%s\n' "$RUSTUP_TOOLCHAIN" >> "$STAGE/invocations.log"
mkdir -p "$STAGE/bin" && : > "$STAGE/bin/app"
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("cargo".into()),
                plugin_options: Some(
                    [(
                        "channel".to_string(),
                        crate::plugins::PluginValue::Str("nightly".into()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let inner_src = expected_src(&e2e.src);
        let log = e2e.invocations();
        assert!(
            log.contains(&format!(
                "cargo install --path {} --root {}",
                inner_src.display(),
                e2e.stage.display()
            )),
            "cargo must build from $SRC and install into $STAGE: {log}"
        );
        assert!(
            log.contains("RUSTUP_TOOLCHAIN=nightly"),
            "channel option must be exported as RUSTUP_TOOLCHAIN: {log}"
        );
        assert!(e2e.stage.join("bin/app").exists());
    }

    #[test]
    fn test_e2e_plugin_and_command_parts_share_stage_and_ordering() {
        // Mixed spec: a command part, then a plugin part after it — both
        // install into the same shared $STAGE in `after` order.
        let e2e = PluginE2e::new();
        write_stub(
            &e2e.stubs,
            "make",
            r#"printf 'make %s\n' "$*" >> "$STAGE/invocations.log"
# DESTDIR arrives as a make command-line arg, not env.
for a in "$@"; do
  case "$a" in DESTDIR=*) DESTDIR="${a#DESTDIR=}" ;; esac
done
if [ -n "$DESTDIR" ]; then
  printf 'saw=%s\n' "$(cat "$STAGE/a.done" 2>/dev/null)" >> "$STAGE/invocations.log"
  mkdir -p "$DESTDIR/usr/bin" && : > "$DESTDIR/usr/bin/hello"
fi
"#,
        );

        let parts: BTreeMap<String, SnapPart> = [
            (
                "a",
                SnapPart {
                    build: "printf 'first\\n' > \"$STAGE/a.done\"".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            ),
            (
                "b",
                SnapPart {
                    build: String::new(),
                    after: vec!["a".into()],
                    plugin: Some("make".into()),
                    plugin_options: None,
                },
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

        with_path_prepend(&e2e.stubs, || {
            run_parts(&parts, e2e.tree.path(), &e2e.src, &e2e.stage, None, None).unwrap();
        });

        let log = e2e.invocations();
        assert!(
            log.contains("saw=first"),
            "plugin part must run after the command part and see its stage output: {log}"
        );
        assert!(e2e.stage.join("usr/bin/hello").exists());
    }

    // ── Stage hygiene (stage-reuse correctness) ──

    #[test]
    fn test_clear_stage_dir_wipes_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(stage.join("usr/bin")).unwrap();
        std::fs::write(stage.join("usr/bin/pciutils"), b"stale").unwrap();

        clear_stage_dir(&stage).unwrap();

        assert!(stage.is_dir());
        assert_eq!(
            std::fs::read_dir(&stage).unwrap().count(),
            0,
            "default stage must be wiped before a build populates it"
        );
    }

    #[test]
    fn test_check_explicit_stage_refuses_nonempty() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("user-file"), b"precious").unwrap();

        let err = check_explicit_stage(&stage).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--stage"),
            "error should point at --stage handling: {msg}"
        );
        assert!(
            stage.join("user-file").exists(),
            "an explicit stage is never deleted"
        );
    }

    #[test]
    fn test_check_explicit_stage_allows_empty_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(check_explicit_stage(&empty).is_ok());

        let missing = dir.path().join("missing");
        assert!(check_explicit_stage(&missing).is_ok());
    }

    #[test]
    fn test_buildless_snap_keeps_default_stage_contents() {
        // A build-less snap's stage is the INPUT (pre-built binaries staged
        // by hand) — the Default-policy wipe only fires when a build phase
        // populates the stage, so the pre-built workflow still works.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "prebuilt",
                    version = "1",
                    apps = { hello = app { command = "bin/hello" } },
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();

        let stage_dir = tempfile::tempdir().unwrap();
        let bin = stage_dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("hello"), b"#!/bin/sh\necho hi\n").unwrap();

        let output_dir = tempfile::tempdir().unwrap();
        build_snap(
            &meta,
            stage_dir.path(),
            output_dir.path(),
            "amd64",
            StagePolicy::Default,
            None,
            None,
        )
        .unwrap();

        assert!(
            bin.join("hello").exists(),
            "build-less snap must consume, not wipe, the pre-populated stage"
        );
    }

    // ── Cross-build arch guard ──

    #[test]
    fn test_check_cross_build_allows_host_arch() {
        assert!(check_cross_build(host_arch(), None).is_ok());
    }

    #[test]
    fn test_check_cross_build_allows_all() {
        assert!(check_cross_build("all", None).is_ok());
    }

    #[test]
    fn test_check_cross_build_refuses_foreign_arch_without_target() {
        let other = if host_arch() == "amd64" {
            "arm64"
        } else {
            "amd64"
        };
        let err = check_cross_build(other, None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--target"),
            "error must explain the --target escape hatch: {msg}"
        );
        assert!(msg.contains(other));
    }

    #[test]
    fn test_check_cross_build_allows_matching_target() {
        assert!(check_cross_build("arm64", Some("aarch64-linux-gnu")).is_ok());
        assert!(check_cross_build("amd64", Some("x86_64-linux-gnu")).is_ok());
        // A target for a DIFFERENT arch does not unlock the build.
        assert!(check_cross_build("arm64", Some("x86_64-linux-gnu")).is_err());
    }

    #[test]
    fn test_triplet_arch_mapping() {
        assert_eq!(triplet_arch("aarch64-linux-gnu"), Some("arm64"));
        assert_eq!(triplet_arch("x86_64-linux-gnu"), Some("amd64"));
        assert_eq!(triplet_arch("arm-linux-gnueabihf"), Some("armhf"));
        assert_eq!(triplet_arch("riscv64-linux-gnu"), Some("riscv64"));
    }

    // ── snap.yaml schema honesty ──

    #[test]
    fn test_yaml_omits_top_level_source_key() {
        // snapd's schema has no top-level `source:` key; emitting it risks
        // rejection. Source identity lives in the lockfile/cache instead.
        let env = LuaEnv::new();
        let table = env
            .eval(
                r#"
            return {
                default = snap {
                    name = "s", version = "1",
                    source = "https://example.com/pkg.tar.gz",
                    build = "make",
                },
            }
            "#,
            )
            .unwrap();
        let default_table: mlua::Table = table.get("default").unwrap();
        let meta = SnapMeta::from_lua_table(&default_table).unwrap();
        assert!(
            meta.source.is_some(),
            "source identity still tracked in meta"
        );

        let yaml = meta.to_yaml().unwrap();
        assert!(
            !yaml.contains("source"),
            "snap.yaml must not carry a source key, got: {yaml}"
        );
    }

    // ── sandbox tool visibility (bind roots, build pre-flight) ──

    use std::path::PathBuf;

    fn write_exec(dir: &Path, name: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn sandbox_visible_matches_bind_roots_componentwise() {
        assert!(sandbox_visible(Path::new("/usr/bin/make")));
        assert!(sandbox_visible(Path::new(
            "/nix/store/abc-gnumake-4.4.1/bin/make"
        )));
        assert!(sandbox_visible(Path::new("/run/current-system/sw/bin/ls")));
        // Component-wise: a sibling prefix must not match.
        assert!(!sandbox_visible(Path::new("/usrlocal/bin/make")));
        assert!(!sandbox_visible(Path::new("/nixpkgs/bin/make")));
        // The failure fixtures: unbound profile dirs and relative paths.
        assert!(!sandbox_visible(Path::new(
            "/home/u/proj/.devbox/nix/profile/default/bin/bison"
        )));
        assert!(!sandbox_visible(Path::new("relative/bin/make")));
    }

    #[test]
    fn sandbox_visible_entries_keep_bound_existing_dirs_only() {
        let unbound = tempfile::tempdir().unwrap();
        // Whichever bind root exists on this host (FHS /usr, or /nix on a
        // NixOS/devbox box).
        let bound_root = SANDBOX_RO_ROOTS
            .iter()
            .find(|r| Path::new(r).is_dir())
            .map(PathBuf::from)
            .expect("test host must have at least one sandbox bind root");
        // A /nix path that does not exist is invisible exactly like a
        // garbage-collected store path — bound via /nix, resolves nothing.
        let entries = vec![
            bound_root.clone(),
            unbound.path().to_path_buf(),
            PathBuf::from("/nix/store/00000000000000000000000000000000-gnumake-4.4.1/bin"),
        ];
        assert_eq!(sandbox_visible_entries(&entries), vec![bound_root]);
    }

    #[test]
    fn resolve_in_path_follows_path_order_and_checks_exec() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_exec(first.path(), "tool-probe");
        let entries = vec![second.path().to_path_buf(), first.path().to_path_buf()];
        assert_eq!(
            resolve_in_path("tool-probe", &entries),
            Some(first.path().join("tool-probe"))
        );
        // A non-executable file is not resolved.
        std::fs::write(first.path().join("plain"), "").unwrap();
        assert_eq!(resolve_in_path("plain", &entries), None);
        assert_eq!(resolve_in_path("absent", &entries), None);
    }

    #[test]
    fn preflight_names_tool_visible_only_on_unbound_entry() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "make");
        let entries = vec![dir.path().to_path_buf()];
        let err = preflight_sandbox_tools("make -C $SRC", &entries)
            .expect_err("tool on an unbound PATH entry must fail preflight");
        let msg = format!("{err:#}");
        assert!(msg.contains("make"), "error must name the tool: {msg}");
        assert!(
            msg.contains(&dir.path().display().to_string()),
            "error must name the invisible PATH entry: {msg}"
        );
        assert!(msg.contains("not bound"), "error must carry the fix: {msg}");
    }

    #[test]
    fn preflight_names_tool_missing_after_store_gc() {
        // A garbage-collected /nix/store entry: under a bind root but the
        // dir no longer exists — invisible to the sandbox.
        let entries = vec![
            PathBuf::from("/nix/store/00000000000000000000000000000000-gnumake-4.4.1/bin"),
            PathBuf::from("/usr/bin"),
        ];
        let err = preflight_sandbox_tools("make-gc-victim", &entries)
            .expect_err("a GC'd store path must fail preflight");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("make-gc-victim"),
            "error must name the tool: {msg}"
        );
        assert!(
            msg.contains("GC"),
            "error must mention the GC failure mode: {msg}"
        );
    }

    #[test]
    fn preflight_probes_only_bare_path_words() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![dir.path().to_path_buf()];
        // Nothing here resolves through PATH: assignments, direct paths,
        // variables, builtins, redirections are all skipped.
        preflight_sandbox_tools(
            "DESTDIR=$STAGE ./configure --prefix=/usr && $SRC/configure --prefix=/usr \
             && cd $SRC && echo built > log 2>&1",
            &entries,
        )
        .expect("no bare PATH-resolved words to probe");
    }

    #[test]
    fn preflight_probes_each_segments_command() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "flex");
        let entries = vec![dir.path().to_path_buf()];
        // The second segment's command is probed even though the first
        // segment's word (./configure) is a direct path.
        let err = preflight_sandbox_tools("./configure --prefix=/usr && flex -o out", &entries)
            .expect_err("flex is only on an unbound entry");
        assert!(format!("{err:#}").contains("flex"));
    }

    #[test]
    fn preflight_probes_command_after_assignment_prefix() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "bison");
        let entries = vec![dir.path().to_path_buf()];
        let err = preflight_sandbox_tools("BISON_PKGDATADIR=$SRC bison -d grammar.y", &entries)
            .expect_err("assignment prefixes must not hide the command");
        assert!(format!("{err:#}").contains("bison"));
    }

    #[test]
    fn preflight_accepts_tools_under_the_stage_bind() {
        // The stage dir is rw-bound at its own host path, so stub tools
        // under it (the plugin-e2e harness pattern) are sandbox-visible.
        let stage = tempfile::tempdir().unwrap();
        let stubs = stage.path().join("stubs");
        std::fs::create_dir_all(&stubs).unwrap();
        write_exec(&stubs, "cmake");
        let entries = vec![stubs];
        let stage_root = stage.path().to_path_buf();
        preflight_sandbox_tools_with(
            "DESTDIR=$STAGE cmake -S $SRC -B build",
            &entries,
            std::slice::from_ref(&stage_root),
        )
        .expect("stage-bound tools are visible to the sandbox");
        // The same setup fails without the stage bind.
        assert!(preflight_sandbox_tools_with("cmake -S $SRC", &entries, &[]).is_err());
    }

    #[test]
    fn bind_system_ro_paths_binds_declared_roots_that_exist() {
        let mut cmd = std::process::Command::new("true");
        bind_system_ro_paths(&mut cmd);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for root in SANDBOX_RO_ROOTS {
            if !Path::new(root).exists() {
                continue;
            }
            assert!(
                args.windows(3).any(|w| w == ["--ro-bind", root, root]),
                "expected --ro-bind {root} {root}, got {args:?}"
            );
        }
    }
}

/// Issue #9: build-time interpreter wrappers (see [`emit_build_wrappers`]).
#[cfg(test)]
mod wrapper_tests {
    use super::*;

    fn stage_file(stage: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = stage.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// Minimal SnapMeta carrying a single declared app (all other fields
    /// default to their empty/None values — `emit_build_wrappers` only
    /// reads `name`, `apps[].command`, and `apps[].interpreter`).
    fn meta_with_app(app_name: &str, command: &str, interpreter: Option<&str>) -> SnapMeta {
        let app = SnapApp {
            command: command.to_string(),
            daemon: None,
            plugs: None,
            slots: None,
            environment: None,
            desktop: None,
            interpreter: interpreter.map(|s| s.to_string()),
            confined: None,
        };
        let mut apps = HashMap::new();
        apps.insert(app_name.to_string(), app);
        SnapMeta {
            name: "pkg".into(),
            version: "1.0".into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            architectures: None,
            build: None,
            parts: None,
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
            aliases: Vec::new(),
            requires: Vec::new(),
            inputs: None,
            target: None,
            toolchain: None,
            confined: None,
            apps,
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn store_fixture(dir: &Path) -> crate::runtime::RuntimeStore {
        crate::runtime::RuntimeStore::new(dir.to_path_buf())
    }

    #[test]
    fn is_elf_detects_magic() {
        let stage = tempfile::tempdir().unwrap();
        let elf = stage_file(stage.path(), "bin/t", b"\x7fELFrest");
        assert!(is_elf(&elf));
        let script = stage_file(stage.path(), "bin/s", b"#!/bin/sh\necho hi\n");
        assert!(!is_elf(&script));
        let empty = stage_file(stage.path(), "bin/e", b"");
        assert!(!is_elf(&empty));
        let missing = stage.path().join("bin/nope");
        assert!(!is_elf(&missing));
    }

    #[test]
    fn interpreter_app_wraps_a_script_at_build_time() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        let script = stage_file(
            stage.path(),
            "bin/zg",
            b"#!/usr/bin/env node\nconsole.log('zg')\n",
        );
        let meta = meta_with_app("zg", "bin/zg", Some("node"));

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        // The command path is now the wrapper: a single exec of the
        // interpreter with the script's content-addressed store path.
        let wrapper = std::fs::read_to_string(&script).unwrap();
        assert!(wrapper.starts_with("#!/bin/sh\n"));
        assert!(
            wrapper.contains("exec \"node\""),
            "wrapper must exec the interpreter: {wrapper}"
        );
        let store_blob = store.blob_path(&sha256_file(&stage.path().join("bin/zg.real")).unwrap());
        assert!(
            wrapper.contains(&store_blob.display().to_string()),
            "wrapper must bake the script's store path: {wrapper}"
        );

        // The original script is preserved at the sibling `.real` path.
        let real = stage.path().join("bin/zg.real");
        assert!(real.is_file());
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "#!/usr/bin/env node\nconsole.log('zg')\n"
        );
    }

    #[test]
    fn interpreter_wrapper_preserves_extension() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        let script = stage_file(
            stage.path(),
            "lib/cli/index.js",
            b"#!/usr/bin/env node\nconsole.log('zg')\n",
        );
        let meta = meta_with_app("zg", "lib/cli/index.js", Some("node"));

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        // The preserved sibling keeps the extension (node's ESM loader
        // dispatches on it) — `index.real.js`, not `index.js.real`.
        let real = stage.path().join("lib/cli/index.real.js");
        assert!(real.is_file(), "extension must survive the .real rename");
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "#!/usr/bin/env node\nconsole.log('zg')\n"
        );
    }

    #[test]
    fn real_sibling_name_inserts_before_extension() {
        assert_eq!(real_sibling_name("index.js"), "index.real.js");
        assert_eq!(real_sibling_name("cli.mjs"), "cli.real.mjs");
        assert_eq!(real_sibling_name("index.min.js"), "index.min.real.js");
        assert_eq!(real_sibling_name("zdemo"), "zdemo.real");
        // A dotfile has no extension — append.
        assert_eq!(real_sibling_name(".profile"), ".profile.real");
    }

    #[test]
    fn native_elf_command_gets_no_wrapper() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        // A minimal ELF magic-prefixed binary is enough — is_elf keys on
        // the magic; the build path never wraps a real ELF.
        let elf = stage_file(stage.path(), "bin/ztool", b"\x7fELF\x02\x01\x01rest");
        let meta = meta_with_app("ztool", "bin/ztool", Some("node"));

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        // The command binary is untouched (still the ELF magic), and no
        // sibling `.real` script was created.
        assert_eq!(std::fs::read(&elf).unwrap(), b"\x7fELF\x02\x01\x01rest");
        assert!(!stage.path().join("bin/ztool.real").exists());
    }

    #[test]
    fn no_interpreter_means_no_wrapper() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        let script = stage_file(stage.path(), "bin/plain", b"#!/bin/sh\necho hi\n");
        let meta = meta_with_app("plain", "bin/plain", None);

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        assert_eq!(
            std::fs::read_to_string(&script).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
        assert!(!stage.path().join("bin/plain.real").exists());
    }

    // ── Issue #10 part B: native-ELF runtime-lib wrappers ──

    /// True when a C compiler (`$CC` or `cc`) is available to build the
    /// native-ELF fixtures.
    fn cc_available() -> bool {
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        std::process::Command::new(&cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Compile a tiny shared library (SONAME `lib<n>.so.1`) and an
    /// executable linking it, into `stage/usr/lib` and `stage/usr/bin`.
    /// Returns the app path. Gated on `cc_available()`.
    fn build_c_fixture(stage: &Path, name: &str) -> Option<std::path::PathBuf> {
        if !cc_available() {
            return None;
        }
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        let libdir = stage.join("usr/lib");
        let bindir = stage.join("usr/bin");
        let srcdir = stage.join("src");
        std::fs::create_dir_all(&libdir).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        std::fs::create_dir_all(&srcdir).unwrap();
        let sym = format!("lib{name}");
        let hdr = srcdir.join(format!("{sym}.c"));
        std::fs::write(&hdr, format!("int {name}_value(void){{ return 42; }}\n")).unwrap();
        std::fs::write(
            srcdir.join(format!("{name}.c")),
            format!(
                "#include <stdio.h>\nint {name}_value(void);\nint main(){{ printf(\"{name}-ran %d\\n\", {name}_value()); return 0; }}\n"
            ),
        )
        .unwrap();
        let so1 = libdir.join(format!("{sym}.so.1"));
        let so = libdir.join(format!("{sym}.so"));
        let status = std::process::Command::new(&cc)
            .args([
                "-shared",
                "-fPIC",
                &format!("-Wl,-soname,{sym}.so.1"),
                "-o",
                so1.to_str().unwrap(),
                hdr.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "building shared lib failed");
        // A non-symlink `lib<name>.so` (same bytes) so `-l<name>` links
        // against it; the SONAME `lib<name>.so.1` is what the binary needs
        // at runtime and what the bundled-lib detector keys on.
        std::fs::copy(&so1, &so).unwrap();
        let app = bindir.join(name);
        let out = std::process::Command::new(&cc)
            .args([
                "-o",
                app.to_str().unwrap(),
                srcdir.join(format!("{name}.c")).to_str().unwrap(),
                &format!("-L{}", libdir.display()),
                &format!("-l{name}"),
            ])
            .output()
            .unwrap();
        if !out.status.success() {
            panic!(
                "linking app failed: {}\nlibdir={}\napp={}",
                String::from_utf8_lossy(&out.stderr),
                libdir.display(),
                app.display(),
            );
        }
        Some(app)
    }

    #[test]
    fn is_shared_lib_name_matches_so_and_soname_variants() {
        assert!(is_shared_lib_name("libjq.so"));
        assert!(is_shared_lib_name("libjq.so.1"));
        assert!(is_shared_lib_name("libonig.so.5.5.0"));
        assert!(!is_shared_lib_name("jq"));
        assert!(!is_shared_lib_name("libjq.a"));
        assert!(!is_shared_lib_name("libjq.so.1.extra"));
        assert!(!is_shared_lib_name(".so"));
    }

    #[test]
    fn elf_needed_libs_reads_the_test_binary_dynamic_deps() {
        // The test binary itself is a real native ELF with DT_NEEDED libs
        // (libc at minimum); the parser must return names, not fail.
        let exe = std::env::current_exe().unwrap();
        let needed = elf_needed_libs(&exe);
        assert!(needed.is_some(), "current exe must parse as ELF");
        let needed = needed.unwrap();
        assert!(!needed.is_empty(), "test binary must have DT_NEEDED libs");
        assert!(
            needed.iter().any(|n| n.contains("libc")),
            "test binary must need libc, got {needed:?}"
        );
    }

    #[test]
    fn native_elf_with_bundled_lib_gets_wrapper() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        let Some(app) = build_c_fixture(stage.path(), "jtool") else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let meta = meta_with_app("jtool", "usr/bin/jtool", None);

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        let wrapper = std::fs::read_to_string(&app).unwrap();
        assert!(
            wrapper.starts_with("#!/bin/sh"),
            "native-ELF with bundled lib must be wrapped: {wrapper}"
        );
        assert!(
            wrapper.contains("LD_LIBRARY_PATH"),
            "wrapper must set LD_LIBRARY_PATH: {wrapper}"
        );
        assert!(
            wrapper.contains("usr/lib"),
            "wrapper must point at the payload lib dir: {wrapper}"
        );
        // The real ELF is preserved at the sibling `.real` path.
        let real = app.with_file_name("jtool.real");
        assert!(real.is_file(), "real ELF must be preserved as jtool.real");
        let real_sha = sha256_file(&real).unwrap();
        assert!(
            wrapper.contains(&store.blob_path(&real_sha).display().to_string()),
            "wrapper must exec the real binary's store blob: {wrapper}"
        );
    }

    #[test]
    fn native_elf_without_bundled_lib_gets_no_wrapper() {
        let stage = tempfile::tempdir().unwrap();
        let store = store_fixture(&stage.path().join("store"));
        let Some(app) = build_c_fixture(stage.path(), "ktool") else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        // Remove the bundled lib: the app now needs only system libs.
        std::fs::remove_file(stage.path().join("usr/lib/libktool.so.1")).unwrap();
        std::fs::remove_file(stage.path().join("usr/lib/libktool.so")).unwrap();
        let meta = meta_with_app("ktool", "usr/bin/ktool", None);

        emit_build_wrappers(&meta, stage.path(), &store).unwrap();

        // Still the real ELF (magic), no `.real` sibling, no wrapper.
        assert!(is_elf(&app), "app must remain a native ELF");
        assert!(
            !app.with_file_name("ktool.real").exists(),
            "no .real sibling for a resolvable ELF"
        );
    }
}
