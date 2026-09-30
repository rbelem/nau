//! Snap value types — the pure, serializable vocabulary of a package
//! declaration (#316; the first wall of the future `nau-core` crate,
//! ADR-0051).
//!
//! This home is deliberately dependency-light: std, serde, and the
//! plugin option payload ([`crate::plugins::PluginValue`]) only — no mlua,
//! no full_moon, no build machinery. The code that parses Lua definitions
//! and drives builds stays on the heavy side ([`crate::snap`]); re-exports
//! there keep every pre-existing `crate::snap::` path compiling.

use std::collections::{BTreeMap, HashMap};

use serde::Serializer;
use serde::{Deserialize, Serialize};

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

// ── Package inputs (inspired by Nix flake inputs) ──

/// Submodule policy for a git input (issue #43): `submodules = true`
/// fetches every `.gitmodules` entry at the parent's pinned revision; a
/// list fetches only the named entries (matched against `.gitmodules`
/// section names or paths). Absent — the default — never touches
/// submodules: gitlinks stay unmaterialized, exactly like before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SubmoduleSpec {
    /// `submodules = { "libfoo", "libbar" }` — the named entries only.
    Named(Vec<String>),
    /// `submodules = true` (or an explicit `false`, which means none).
    All(bool),
}

impl SubmoduleSpec {
    /// False for a hand-built `All(false)`; the DSL parse normalizes
    /// `false` away, but non-DSL constructors can produce this value.
    pub fn active(&self) -> bool {
        !matches!(self, SubmoduleSpec::All(false))
    }
}

/// A package input source — declares where to fetch package definitions from.
///
/// URL schemes:
///   `github:user/repo[/branch]` — GitHub repository (cloned shallow)
///   `path:/local/dir`            — Local filesystem path
#[derive(Debug, Clone, Serialize)]
pub struct PackageInput {
    /// URL in Nix-inspired format (e.g. "github:rbelem/nau/main",
    /// "path:/home/user/pkgs").
    pub url: String,

    /// Submodule policy (issue #43). `None` = parent tree only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submodules: Option<SubmoduleSpec>,
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
    /// cargo resolver: `deps = { cargo = { lock = "Cargo.lock" } }`
    /// (issue #36). Fetches every registry crate the lockfile pins into a
    /// `cargo vendor`-equivalent tree.
    pub cargo: Option<DepsLockSpec>,
    /// go resolver: `deps = { go = { mods = "go.mod" } }` (issue #40).
    /// Resolves go.mod + go.sum from the source tree and fetches every
    /// module closure into the Go module cache layout.
    pub go: Option<DepsLockSpec>,
}

impl PackageDeps {
    /// True when every declared lockfile is recipe-local
    /// (`recipe/`-prefixed): those resolve against the recipe directory
    /// (the ADR-0017 addendum — the lockfile ships beside the recipe),
    /// not a source tree, so the closure can fetch without a `source`.
    /// The `deps`+`source` parse check relaxes on this predicate; the
    /// motivating shape is a multi-source build (issue #41 `sources`)
    /// that vendors an ecosystem closure from a recipe-local lock while
    /// `sources` delivers the artifacts the no-network sandbox cannot
    /// fetch (agentmemory: npm closure + pinned iii binary).
    pub fn all_locks_recipe_local(&self) -> bool {
        let specs = [&self.npm, &self.pip, &self.cargo, &self.go];
        specs.iter().all(|s| {
            s.as_ref()
                .is_none_or(|spec| spec.lock.starts_with("recipe/"))
        })
    }
}

/// One ecosystem resolver's spec: its lockfile (relative to the source
/// root, or `recipe/`-prefixed to resolve against the package recipe
/// directory — the lockfile ships beside the recipe; fail-closed, no
/// source-tree fallback), the index to resolve against (index-driven
/// ecosystems), and — npm only — fetch-side exclusion globs over lock
/// keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepsLockSpec {
    /// Lockfile path relative to the source root (e.g.
    /// "package-lock.json", "requirements.lock", "go.mod"), or
    /// `recipe/<path>` to resolve against the package recipe directory    /// (the dir holding the package's `init.lua` or single `<name>.lua`).
    /// Plain values fall back to the recipe dir when the source tree has
    /// no lockfile; `recipe/` values never fall back to the source tree.
    /// go's `sum` (go.sum) follows the same rules, its `recipe/` sibling
    /// defaulting beside a `recipe/` go.mod.
    pub lock: String,
    /// Hash/checksum source path relative to the source root (go only:
    /// the go.sum sibling, required). Cargo/npm/pip read their checksums
    /// from the lockfile itself, so those leave this `None`.
    pub sum: Option<String>,
    /// Package index / registry API URL (index-driven ecosystems;
    /// default: the official one — pip's PyPI simple index, cargo's
    /// crates.io API base, go's GOPROXY). npm resolves from the
    /// lockfile's own `resolved` URLs. Tests point the override at a
    /// loopback server.
    pub index: Option<String>,
    /// Glob patterns (`*` / `?`) matched against lock keys
    /// (`node_modules/...`, full-key match); any key matching one is
    /// never fetched (npm only, issue #14). pip reuses the field with
    /// exact-name semantics: a listed package is never fetched.
    pub exclude: Vec<String>,
    /// pip only: the CPython minor version the consuming pod interpreter
    /// runs (e.g. "3.14"). Declared, every fetched wheel's tags are
    /// validated against it and a mismatch fails the fetch closed —
    /// uv.lock entries carry the locking machine's wheel choice, which
    /// is silently wrong for a different interpreter (cp312 wheels on a
    /// 3.14 pod import nothing). Undeclared: no tag validation (legacy).
    pub python: Option<String>,
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

    /// Multi-source build inputs (issue #41): name → pinned source. Each
    /// entry downloads, verifies, and extracts into `$SRC/<name>/`.
    /// Mutually exclusive with `source` (enforced in the DSL, re-checked
    /// at the parse boundary). Build-time only — snap.yaml has no such
    /// key; identity lives in the lockfile and the cache closure.
    #[serde(default, skip)]
    pub sources: Option<BTreeMap<String, SourceSpec>>,

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

    /// Snap type. Doubles as a nau build classification
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

    /// SquashFS compression for mksquashfs ("zstd", "xz" or "lzo"; zstd when
    /// absent — ticket #154). Build-time only — snap.yaml has no compression
    /// field; it's a property of the image.
    #[serde(default, skip)]
    pub compression: Option<String>,

    /// Optional mksquashfs `-Xcompression-level` (ticket #154): zstd accepts
    /// 1-22 (the pack path pins 6 when absent), lzo 1-9; rejected for xz —
    /// mksquashfs' xz wrapper has no `-Xcompression-level`. Build-time only,
    /// like `compression`.
    #[serde(default, skip)]
    pub compression_level: Option<u32>,

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

    /// Build/runtime dependencies. Serialized into `meta/snap.yaml`
    /// (issue #110/ADR-0034): the runtime emitter records it on the
    /// installed package so the farm emit can tell libs-carrying
    /// packages (requires beyond the glibc family) from self-contained
    /// ones without re-reading the pool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,

    /// Build-time-only dependencies (ADR-0018, issue #17): payloads are
    /// mounted into the build sandbox for the duration of the build (merged
    /// prefix, [`SANDBOX_BUILD_PREFIX`]) and never enter the runtime
    /// closure. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub build_deps: Vec<String>,

    /// Named post-build leak-scan exceptions (ADR-0018 Decision 3, issue
    /// #22): exact-match entries that silence a detected build-only
    /// reference. Exceptions stay greppable in the definition; a hit is
    /// still visibly logged. Skipped in YAML — build metadata only.
    #[serde(skip)]
    pub leaks_ok: Vec<String>,

    /// Runtime confinement grants (ADR-0016, ticket #11). Present
    /// (`Some`) declares the package `confined`; absent is `unconfined`
    /// (the default for simple CLIs). Emitted into snap.yaml so it
    /// survives the pod build → install pipeline (the runtime emitter
    /// records it in the generation manifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,

    /// Package input references. Maps input name to a URL.
    /// Example: `{ packages = { url = "github:rbelem/nau/main" } }`
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

    /// Services declared by this package (ADR-0032, issue #105), keyed by
    /// service name. Emitted into snap.yaml so it survives the pod build →
    /// install pipeline exactly like `apps` (the service emitter later
    /// records it in the generation manifest).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, ServiceDecl>,

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

/// Skip `type:` in snap.yaml for nau build classifications
/// ("source"/"meta"/"store") and snapd's default ("app").
fn skip_internal_or_default_type(t: &Option<String>) -> bool {
    !matches!(t.as_deref(), Some("base" | "gadget" | "kernel" | "snapd"))
}

pub(crate) fn default_grade() -> String {
    "stable".to_string()
}

pub(crate) fn default_confinement() -> String {
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

// ── Service declarations (ADR-0032, Decisions 1–3) ──

/// How the service daemon signals readiness (ADR-0032 Decision 2). The
/// spelling deliberately matches the Snap app `daemon` key. `oneshot` is
/// out of scope for v1 (ADR-0032 revisit trigger keeps the door open).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceDaemon {
    Simple,
    Notify,
    Forking,
}

/// One service declared by a package (`services = { name = service { … } }`,
/// ADR-0032 Decision 2). The shared vocabulary every backend must accept;
/// `options` are NixOS-style declarations with defaults (`enabled` among
/// them, materialized to `false` at pod resolution), `backend_options` the
/// per-backend raw passthrough.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub command: String,
    pub daemon: ServiceDaemon,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub backend_options: BTreeMap<String, serde_json::Value>,
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

    pub(crate) fn from_str(s: &str) -> Option<Self> {
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
