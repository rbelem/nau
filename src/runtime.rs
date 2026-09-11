//! On-device runtime — generations + file-level content store
//! (ADR-0012 step 5, Phase 24b).
//!
//! `shuttle install/remove/upgrade/rollback/gc` operate on a *state root*
//! (default `/var/lib/shuttle`, overridable via `--state-dir`):
//!
//! ```text
//! <root>/
//!   generations/<N>/manifest.json          # Generation (see below)
//!   generations/<N>/extensions/<pkg>/...   # per-package sysext directory trees
//!   generations/.staging-<N>/              # staging dir; rename(2)'d into place
//!   store/<aa>/<sha256>                    # file-level content blobs
//!   active -> generations/<N>              # relative symlink; rename-flip = atomic
//!   journal.json                           # crash-recovery journal
//!   downloads/                             # fetched .snap payloads (pre-ingest)
//! ```
//!
//! # Content store
//!
//! Every regular file of an installed payload is content-addressed by its
//! sha256 under `store/`. Generation extension trees are materialized with
//! **hardlinks into the blob store** — never copies, never symlinks. The
//! hardlink is load-bearing: generations stay ~free (the ADR's retention
//! argument), and a generation file *is* the content-addressed blob, so
//! blob identity and installed identity can never diverge. Cross-device
//! hardlinks fail closed with a loud error — the state root is documented
//! to live on ONE filesystem. A symlink fallback is deliberately absent:
//! a symlinked generation tree would make blob deletion (gc) dangle every
//! installed file, and a copy fallback would silently double storage while
//! breaking the "generations are free" invariant.
//!
//! # Presentation
//!
//! Each package with runtime content is presented as a systemd-sysext
//! *directory* image at `generations/<N>/extensions/<pkg>/` carrying a
//! `usr/` tree plus `usr/lib/extension-release/extension-release.<pkg>`
//! (ID/VERSION_ID matching the base os-release read at runtime; the
//! documented fallback `ID=_any` / `VERSION_ID=_any` is used when the host
//! os-release is unreadable — `_any` is systemd-sysext's wildcard).
//! Activation links the tree into `<extensions-link-dir>/<pkg>` (default
//! `/var/lib/extensions/<pkg>`) and runs `systemd-sysext refresh`,
//! `systemctl daemon-reload`, and unit enable/start — all best-effort:
//! warn, never fail, when the binary is absent. Production resolves those
//! binaries with [`RuntimeTools::from_host`]; the test-aware
//! [`RuntimeTools::for_pod_runtime`] resolves them to `None` when
//! `SHUTTLE_SYSTEMD` is `off`/`0`/`no`, or when the host has no systemd
//! (`/run/systemd/system` absent) — so tests never reach the system bus.
//!
//! # Generations
//!
//! A generation pins base version + the full package set + per-package
//! content hashes in one `manifest.json`. Install/remove/upgrade stage a
//! new generation (max+1, first=1) at `generations/.staging-<N>`, commit
//! it with rename(2), then flip `active` atomically (temp symlink +
//! rename). A `journal.json` records started → staging → committed so a
//! crash at any point is recoverable at the next runtime command:
//!
//! - `started`  → remove the journal (nothing durable was written)
//! - `staging`  → remove the staging dir + the journal
//! - `committed`→ finish the `active` flip (idempotent) + remove the journal
//!
//! # GC
//!
//! Mark-sweep ONLY (no refcounts — a crash between two refcount writes
//! would corrupt the store; mark-sweep re-derives truth from the
//! manifests every run). Mark = union of per-file hashes across ALL
//! generation manifests; sweep = delete unreferenced blobs, reporting
//! bytes reclaimed. Generations are cheap (manifests + hardlinks), so
//! plain `gc` sweeps blobs only. `gc --prune` additionally drops all
//! generations except active + previous *before* the sweep so their
//! exclusive blobs free.
//!
//! # Trust
//!
//! Snap downloads go through [`crate::store`]'s resolve path — the
//! snap-revision assertion verification there is fail-closed and is
//! reused, never reimplemented. Manifest signatures (ADR-0011 step (d))
//! verify against the on-device trust set `/etc/shuttle/trusted-keys/`
//! (with `/etc/shuttle/update-key.pub` kept as a single-anchor fallback)
//! or the `~/.config/shuttle/keys/` keychain when present.
//!
//! ADR-0024 §4: the embedded revocation list `/etc/shuttle/revoked-keys`
//! (one key id per line) is consulted first — a signature under a revoked
//! id is refused with a precise message, even when another trusted key
//! also signed. That is what makes "revoked" distinguishable from "never
//! trusted". An unsigned manifest still proceeds with a note (signing is
//! opt-in); a signed manifest with no trusted, unrevoked anchor fails
//! closed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::store::StoreClient;
use crate::units::{
    classify, plan_app, spec_from_payload_app, DaemonUnit, PayloadSnap, RuntimeClass,
};

// ── Constants ──

/// Default state root for generations + the content store.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/shuttle";

/// Default systemd-sysext scan directory the activation links live in.
pub const DEFAULT_EXTENSIONS_LINK_DIR: &str = "/var/lib/extensions";

/// On-device trust anchor embedded at image build time (ADR-0011 step (d)).
pub const DEVICE_ANCHOR: &str = "/etc/shuttle/update-key.pub";

// ── Generation model ──

/// One installed package as pinned in a generation manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub revision: u32,
    /// sha3-384 of the payload — the snap-level content address, carried
    /// through from the store resolve.
    pub sha3_384: String,
    /// sha256 content hashes of every file the package contributes to
    /// the store — the GC mark set for this package.
    pub files: Vec<String>,
    /// Daemon unit names this package contributed (empty for plain
    /// apps) — the unit reconciliation set difference works over these.
    pub units: Vec<String>,
    /// The composition precedence layer this package was installed at
    /// (issue #8): what a loaded pod provided (`Loaded`), the pod's own
    /// declaration (`Own`), or the pod's overlay (`Overlay`). The farm
    /// and launcher emitters iterate in this order so the higher layer
    /// wins a shared binary or desktop-entry name. Manifests from
    /// before the field default to `Own`.
    #[serde(default)]
    pub layer: crate::farm::ClaimLayer,
    /// App name → sha256 of the app's command binary in the store.
    /// The farm emitter's source of truth (pod farm, `farm.rs`): each
    /// entry becomes a direct symlink from the farm into the content
    /// store. Empty for packages without apps and store-recorded snaps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<String, String>,
    /// App name → sha256 of the app's confined-launcher wrapper blob in
    /// the store (ticket #11). Only present for confined apps. The farm
    /// emitter prefers this over `apps` for a confined app so the farm's
    /// symlink points at a wrapper that invokes `shuttle run`, while
    /// `apps` still records the real command binary `shuttle run` execs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launchers: BTreeMap<String, String>,
    /// Multi-file app payloads (issue #37): app name → the app's
    /// in-payload binary path plus the sibling content recorded beside
    /// it at install time. The pod farm builds multi-file packages a
    /// per-package assembly subtree from this (`crate::farm`), so
    /// relative-to-executable sibling reads (`pi`'s package.json,
    /// git-credential-manager's libSkiaSharp.so) resolve beside the
    /// executed binary; single-binary packages record nothing here and
    /// keep the bare direct farm link.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assembly: BTreeMap<String, crate::farm::AppAssembly>,
    /// Runtime confinement grants (ADR-0016, ticket #11): the package-level
    /// `confined` declaration. `Some` = the package is confined (its
    /// apps default to confined), `None` = unconfined. Recorded from the
    /// payload's snap.yaml at install time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<crate::snap::Confinement>,
    /// Per-app confinement overrides (ticket #11): app name → grants, only
    /// for apps whose `confined` differs from the package default. The
    /// farm emitter and `shuttle run` resolve effective confinement as
    /// `app_confined.get(app).or(confined.as_ref())`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, crate::snap::Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from the
    /// package's `.desktop` file at install time and recorded in the
    /// manifest so the launcher emitter rebuilds entries from the
    /// manifest alone — rollback re-emits without re-unpacking. Empty
    /// for packages without GUI apps.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, DesktopLauncher>,
}

/// One GUI app's desktop-launcher metadata (issue #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopLauncher {
    /// `Name=` of the source `.desktop` file (falls back to the app id
    /// in the generated entry when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `GenericName=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_name: Option<String>,
    /// `Comment=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Menu categories, split from the source file's `Categories=`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// `Icon=` of the source file, passed through ONLY when the package
    /// ships no icon blob (a theme icon name); when the package ships
    /// one, the emitter substitutes the pod-namespaced link name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_ref: Option<String>,
    /// The package's shipped icon, ingested into the store at install
    /// time and linked by the launcher emitter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<DesktopIcon>,
}

/// An icon blob in the content store plus its file extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIcon {
    pub sha256: String,
    pub ext: String,
}

/// One bootable selection: base version + package set + content hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub n: u64,
    /// Base OS version this generation was created on (from the host
    /// os-release; the base axis itself updates via sysupdate, never
    /// through these commands).
    pub base_version: String,
    /// The full installed package set, keyed by snap name.
    pub packages: BTreeMap<String, InstalledPackage>,
    pub created_epoch: u64,
    /// The boot entry id this generation corresponds to, when known
    /// (sysupdate integration); None for package-axis-only generations.
    pub boot_entry: Option<String>,
}

// ── Journal ──

/// Journal states, in pipeline order (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalState {
    Started,
    Staging,
    Committed,
}

/// Crash-recovery journal persisted beside the state root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    /// Informational: which command wrote the journal.
    pub op: String,
    /// The generation the in-flight operation is producing.
    pub target_gen: u64,
    pub state: JournalState,
}

// ── Inputs ──

/// A resolved, downloaded, not-yet-installed snap. Resolution/download
/// happen ABOVE this type (the CLI uses [`crate::store`]; tests feed
/// pre-made payloads) — install re-verifies sha3-384 fail-closed.
#[derive(Debug, Clone, Default)]
pub struct PendingSnap {
    pub name: String,
    pub revision: u32,
    pub sha3_384: String,
    /// Path to the downloaded `.snap` payload.
    pub payload_path: PathBuf,
    /// The composition precedence layer to record the package at
    /// (issue #8). Store/pull installs land at `Own` (the default).
    pub layer: crate::farm::ClaimLayer,
}

/// A channel-side manifest signature envelope (ADR-0011 step (d)): the
/// canonical bytes the signatures cover plus the signatures map. Empty
/// = unsigned — install proceeds with a note.
#[derive(Debug, Clone, Default)]
pub struct SignatureEnvelope {
    pub canonical_bytes: Vec<u8>,
    pub signatures: BTreeMap<String, serde_json::Value>,
}

impl SignatureEnvelope {
    pub fn is_unsigned(&self) -> bool {
        self.signatures.is_empty()
    }
}

// ── Reports ──

/// One installed snap in an [`InstallReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledSummary {
    pub name: String,
    pub version: String,
    pub revision: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReport {
    /// True when every pending snap was already installed at the same
    /// revision — no generation was created.
    pub noop: bool,
    /// The generation activated (None for a no-op).
    pub generation: Option<u64>,
    pub installed: Vec<InstalledSummary>,
    /// Pending snaps skipped because the active generation already has
    /// the exact same name+revision+sha3.
    pub skipped: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveReport {
    pub generation: u64,
    pub removed: String,
    pub stopped: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    pub from: u64,
    pub to: u64,
    /// Units started by reconciliation (present in target, absent before).
    pub started: Vec<String>,
    /// Units stopped by reconciliation (present before, absent in target).
    pub stopped: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    pub blobs_removed: usize,
    pub bytes_reclaimed: u64,
    /// Generations dropped by --prune before the sweep.
    pub generations_removed: Vec<u64>,
}

// ── Shell-out seam ──

/// External tools the runtime shells out to, injectable for hermetic
/// tests (the [`build_uki_with`][crate::image] precedent). `None` means
/// the tool was not found / was not injected:
///
/// - `unsquashfs` absent → install FAILS closed (nothing can unpack).
/// - `systemd-sysext` / `systemctl` / `bootctl` absent → best-effort
///   steps warn and continue (a presentation hiccup must never corrupt
///   durable generation state).
#[derive(Debug, Clone, Default)]
pub struct RuntimeTools {
    pub unsquashfs: Option<PathBuf>,
    pub systemd_sysext: Option<PathBuf>,
    pub systemctl: Option<PathBuf>,
    pub bootctl: Option<PathBuf>,
}

impl RuntimeTools {
    /// Resolve every tool from the host PATH.
    pub fn from_host() -> RuntimeTools {
        RuntimeTools {
            unsquashfs: find_on_path("unsquashfs"),
            systemd_sysext: find_on_path("systemd-sysext"),
            systemctl: find_on_path("systemctl"),
            bootctl: find_on_path("bootctl"),
        }
    }

    /// Resolve the tools the way the POD paths want them: the host
    /// binaries, but with the system-bus set (`systemd-sysext`,
    /// `systemctl`, `bootctl`) resolved to `None` when the host has no
    /// systemd at all, or when [`systemd_disabled`] says so.
    ///
    /// Production on a systemd host is byte-identical to [`from_host`];
    /// the fallbacks only fire where running the real tools could never
    /// succeed (a container without `/run/systemd/system`) or where the
    /// caller explicitly opted out. `unsquashfs` is never suppressed: it
    /// unpacks payloads and has nothing to do with the system bus.
    ///
    /// [`from_host`]: RuntimeTools::from_host
    pub fn for_pod_runtime() -> RuntimeTools {
        let mut tools = RuntimeTools::from_host();
        if systemd_disabled() {
            tools.systemd_sysext = None;
            tools.systemctl = None;
            tools.bootctl = None;
        }
        tools
    }

    /// Suppress the system-bus tools (test seam / explicit opt-out):
    /// `systemd-sysext`, `systemctl` and `bootctl` become `None`, so
    /// `activate` and the unit helpers skip them without touching any
    /// bus. `unsquashfs` is kept.
    pub fn without_systemd(mut self) -> RuntimeTools {
        self.systemd_sysext = None;
        self.systemctl = None;
        self.bootctl = None;
        self
    }
}

/// `SHUTTLE_SYSTEMD` semantics for the system-bus tools:
///
/// - `off` / `0` / `no` → suppress them (tests pin this to keep the
///   suite off the real bus).
/// - `on` / `1` / `yes`  → always resolve them from the host PATH, even
///   on a host without `/run/systemd/system` (explicit override).
/// - unset / anything else → suppress them when the host has no
///   systemd ([`systemd_present`]); otherwise resolve from the host.
fn systemd_disabled() -> bool {
    match std::env::var("SHUTTLE_SYSTEMD")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "off" | "0" | "no" => true,
        "on" | "1" | "yes" => false,
        _ => !systemd_present(),
    }
}

/// Whether the host runs systemd: `/run/systemd/system` exists on every
/// booted systemd host (it is the `RuntimeDirectory` of systemd itself).
/// Pod deployments are not systemd-scoped, so their runtime paths do not
/// need the system bus.
fn systemd_present() -> bool {
    Path::new("/run/systemd/system").exists()
}

fn find_on_path(tool: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(tool);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

/// Whether an external tool is on the host PATH. Public seam for the pod
/// install path, which degrades (warn + skip, no store state touched)
/// when the squashfs pair is missing instead of failing an add whose
/// declaration half is already complete.
pub fn tool_on_path(tool: &str) -> bool {
    find_on_path(tool).is_some()
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

// ── Payload tree entries ──

/// One walked payload entry. Blobs are content-addressed; symlinks are
/// recreated verbatim (never followed — a link out of the payload must
/// not pull outside trees into the store).
#[derive(Debug, Clone)]
enum TreeEntry {
    Blob { rel: String, sha256: String },
    Symlink { rel: String, target: String },
}

/// Everything extracted from one pending payload, ready to stage.
#[derive(Debug)]
struct PreparedSnap {
    pkg: InstalledPackage,
    /// unit-planner warnings, surfaced as report notes.
    planner_notes: Vec<String>,
    entries: Vec<TreeEntry>,
    units: Vec<DaemonUnit>,
    /// (source content hash, destination rel path under the tree) for
    /// renamed app binaries — `usr/bin/<snap>-<app>`, documented naming
    /// shared with the image-build path.
    renames: Vec<(String, String)>,
}

// ── The store ──

/// State-root-rooted runtime store: generations + content store + the
/// `active` symlink + journal.
#[derive(Debug, Clone)]
pub struct RuntimeStore {
    root: PathBuf,
    extensions_link_dir: PathBuf,
}

impl RuntimeStore {
    /// Store at `root` (should be absolute — symlink targets recorded in
    /// the extensions link dir use the root as given).
    pub fn new(root: PathBuf) -> RuntimeStore {
        RuntimeStore {
            root,
            extensions_link_dir: PathBuf::from(DEFAULT_EXTENSIONS_LINK_DIR),
        }
    }

    /// Store at the CLI-provided state dir or the documented default.
    pub fn from_state_dir(state_dir: Option<&str>) -> RuntimeStore {
        match state_dir {
            Some(dir) => RuntimeStore::new(PathBuf::from(dir)),
            None => RuntimeStore::new(PathBuf::from(DEFAULT_STATE_DIR)),
        }
    }

    /// Override the sysext link directory (tests; the CLI uses the
    /// documented default).
    pub fn with_extensions_link_dir(mut self, dir: PathBuf) -> RuntimeStore {
        self.extensions_link_dir = dir;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory fetched .snap payloads download into before ingest.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }

    fn generations_dir(&self) -> PathBuf {
        self.root.join("generations")
    }

    /// Directory of generation `n` (manifest + per-package extension
    /// trees + the farm). Public for the pod farm emitter (`farm.rs`),
    /// which hangs per-generation artifacts off it.
    pub fn generation_dir(&self, n: u64) -> PathBuf {
        self.generations_dir().join(n.to_string())
    }

    fn staging_dir(&self, n: u64) -> PathBuf {
        self.generations_dir().join(format!(".staging-{n}"))
    }

    fn store_dir(&self) -> PathBuf {
        self.root.join("store")
    }

    /// Path of the content blob with hash `sha256` (`store/<aa>/<sha>`).
    /// Public for the pod farm emitter, whose farm entries are direct
    /// symlinks into the store.
    pub fn blob_path(&self, sha256: &str) -> PathBuf {
        let (aa, _) = sha256.split_at(2.min(sha256.len()));
        self.store_dir().join(aa).join(sha256)
    }

    fn active_link(&self) -> PathBuf {
        self.root.join("active")
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join("journal.json")
    }

    // ── Crash recovery ──

    /// Reconcile any leftover journal. Runs at the start of EVERY
    /// runtime command (see the module docs for the state table).
    pub fn recover(&self) -> miette::Result<()> {
        let path = self.journal_path();
        if !path.exists() {
            return Ok(());
        }
        let text = std::fs::read_to_string(&path)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading journal {}", path.display()))?;
        let journal: Journal = serde_json::from_str(&text)
            .map_err(|e| miette::miette!("corrupt journal {}: {e}", path.display()))?;
        match journal.state {
            JournalState::Started => self.recover_started(&path)?,
            JournalState::Staging => self.recover_staging(&journal, &path)?,
            JournalState::Committed => self.recover_committed(&journal, &path)?,
        }
        Ok(())
    }

    /// `started`: nothing durable was written yet — the journal itself
    /// is the only residue.
    fn recover_started(&self, journal: &Path) -> miette::Result<()> {
        std::fs::remove_file(journal)
            .into_diagnostic()
            .wrap_err("removing started journal")
    }

    /// `staging`: the staging dir is half-built — remove it and the
    /// journal; the previous generation is untouched.
    fn recover_staging(&self, journal: &Journal, journal_path: &Path) -> miette::Result<()> {
        let staging = self.staging_dir(journal.target_gen);
        if staging.exists() {
            std::fs::remove_dir_all(&staging)
                .into_diagnostic()
                .wrap_err_with(|| format!("removing staging {}", staging.display()))?;
        }
        std::fs::remove_file(journal_path)
            .into_diagnostic()
            .wrap_err("removing staging journal")
    }

    /// `committed`: the rename landed but activation didn't finish.
    /// The flip is idempotent — finish it, then drop the journal.
    fn recover_committed(&self, journal: &Journal, journal_path: &Path) -> miette::Result<()> {
        let manifest = self
            .generation_dir(journal.target_gen)
            .join("manifest.json");
        if !manifest.exists() {
            return Err(miette::miette!(
                "committed journal points at missing generation {} \
                 (no manifest at {}) — manual inspection required",
                journal.target_gen,
                manifest.display()
            ));
        }
        self.flip_active(journal.target_gen)?;
        std::fs::remove_file(journal_path)
            .into_diagnostic()
            .wrap_err("removing committed journal")
    }

    // ── Reading state ──

    /// Every complete generation, sorted by number. A present but
    /// unparseable manifest is a named error — GC must never sweep with
    /// a manifest it could not read.
    pub fn generations(&self) -> miette::Result<Vec<Generation>> {
        let dir = self.generations_dir();
        let mut gens = Vec::new();
        let Ok(read) = std::fs::read_dir(&dir) else {
            return Ok(gens);
        };
        for entry in read {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(n) = name.parse::<u64>() else {
                continue; // .staging-* and anything non-numeric
            };
            let manifest = entry.path().join("manifest.json");
            let text = std::fs::read_to_string(&manifest)
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", manifest.display()))?;
            let mut gen: Generation = serde_json::from_str(&text).map_err(|e| {
                miette::miette!("corrupt generation manifest {}: {e}", manifest.display())
            })?;
            // The directory name is authoritative for the generation
            // number — `active` flips and prunes address generations by
            // directory.
            gen.n = n;
            gens.push(gen);
        }
        gens.sort_by_key(|g| g.n);
        Ok(gens)
    }

    /// The generation `active` points at, or None when nothing is
    /// installed yet.
    pub fn active_generation(&self) -> miette::Result<Option<Generation>> {
        let link = self.active_link();
        let target = match std::fs::read_link(&link) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
            return Err(miette::miette!(
                "active symlink {} points at a non-generation target {:?}",
                link.display(),
                target
            ));
        };
        let n: u64 = name.parse().map_err(|_| {
            miette::miette!("active symlink points at non-numeric generation {name:?}")
        })?;
        let manifest = self.generation_dir(n).join("manifest.json");
        let text = std::fs::read_to_string(&manifest)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", manifest.display()))?;
        let gen = serde_json::from_str(&text).map_err(|e| {
            miette::miette!("corrupt generation manifest {}: {e}", manifest.display())
        })?;
        Ok(Some(gen))
    }

    /// Next generation number: max existing + 1; the first is 1.
    pub fn next_generation_number(&self) -> miette::Result<u64> {
        Ok(self.generations()?.iter().map(|g| g.n).max().unwrap_or(0) + 1)
    }

    // ── Install ──

    /// Install a batch of pending snaps as one new generation.
    ///
    /// Already-installed-exact snaps (same name+revision+sha3 in the
    /// active generation) are skipped; when that skips everything the
    /// call is a no-op note and NO generation is created.
    pub fn install_batch(
        &self,
        pending: &[PendingSnap],
        envelope: &SignatureEnvelope,
        tools: &RuntimeTools,
    ) -> miette::Result<InstallReport> {
        self.recover()?;

        let active = self.active_generation()?;
        let mut to_install = Vec::new();
        let mut skipped = Vec::new();
        for snap in pending {
            let done = active
                .as_ref()
                .and_then(|g| g.packages.get(&snap.name))
                .is_some_and(|ip| ip.revision == snap.revision && ip.sha3_384 == snap.sha3_384);
            if done {
                skipped.push(snap.name.clone());
            } else {
                to_install.push(snap.clone());
            }
        }
        if to_install.is_empty() {
            return Ok(InstallReport {
                noop: true,
                generation: None,
                installed: Vec::new(),
                skipped,
                notes: vec!["already installed at the same revision — no new generation".into()],
            });
        }

        let mut notes = Vec::new();
        match verify_signatures(&envelope.canonical_bytes, &envelope.signatures) {
            Ok(None) => notes.push(
                "manifest unsigned — proceeding (update signing ceremony \
                 pending, ADR-0011 step (e))"
                    .into(),
            ),
            Ok(Some(key_id)) => notes.push(format!("manifest signature verified (key {key_id})")),
            Err(e) => return Err(e),
        }

        let mut prepared = Vec::new();
        for snap in &to_install {
            prepared.push(self.prepare_snap(snap, tools)?);
        }
        for p in &prepared {
            notes.extend(p.planner_notes.iter().cloned());
        }

        let n = self.next_generation_number()?;
        let mut packages = active.map(|g| g.packages).unwrap_or_default();
        for p in &prepared {
            packages.insert(p.pkg.name.clone(), p.pkg.clone());
        }
        let staged: std::collections::BTreeSet<String> =
            prepared.iter().map(|p| p.pkg.name.clone()).collect();

        self.commit_generation("install", n, &packages, &prepared, &staged)?;

        let new_units: Vec<String> = prepared
            .iter()
            .flat_map(|p| p.units.iter().map(|u| u.unit_name.clone()))
            .collect();
        let activator = self.activate(n, tools)?;
        notes.extend(activator.notes);
        for unit in &new_units {
            run_best_effort(
                &tools.systemctl,
                &["enable", "--now", unit],
                &format!("enable {unit}"),
                &mut notes,
            );
        }

        self.clear_journal()?;

        Ok(InstallReport {
            noop: false,
            generation: Some(n),
            installed: prepared
                .iter()
                .map(|p| InstalledSummary {
                    name: p.pkg.name.clone(),
                    version: p.pkg.version.clone(),
                    revision: p.pkg.revision,
                })
                .collect(),
            skipped,
            notes,
        })
    }

    // ── Remove ──

    /// Remove one installed package as a new generation without it.
    /// The package's units are stopped/disabled and its sysext link
    /// dropped (best-effort); its blobs stay until gc — other
    /// generations may still reference them.
    pub fn remove(&self, name: &str, tools: &RuntimeTools) -> miette::Result<RemoveReport> {
        self.recover()?;
        let active = self
            .active_generation()?
            .ok_or_else(|| miette::miette!("nothing installed — no active generation"))?;
        let removed = active.packages.get(name).ok_or_else(|| {
            miette::miette!(
                "package '{name}' is not installed (generation {})",
                active.n
            )
        })?;

        let mut notes = Vec::new();
        let mut packages = active.packages.clone();
        let removed_units = removed.units.clone();
        packages.remove(name);

        let n = self.next_generation_number()?;
        let prepared: Vec<PreparedSnap> = Vec::new();
        self.commit_generation("remove", n, &packages, &prepared, &Default::default())?;

        for unit in &removed_units {
            run_best_effort(
                &tools.systemctl,
                &["disable", "--now", unit],
                &format!("disable {unit}"),
                &mut notes,
            );
        }
        let activator = self.activate(n, tools)?;
        notes.extend(activator.notes);

        self.clear_journal()?;

        Ok(RemoveReport {
            generation: n,
            removed: name.to_string(),
            stopped: removed_units,
            notes,
        })
    }

    // ── Rollback ──

    /// Roll back to a previous generation (default: the highest one
    /// below active). Flips `active`, relinks sysext trees, reconciles
    /// units by set difference, and sets the boot entry when the
    /// generation records one (best-effort). No reboot is performed.
    pub fn rollback(
        &self,
        target: Option<u64>,
        tools: &RuntimeTools,
    ) -> miette::Result<RollbackReport> {
        self.recover()?;
        let active = self.active_generation()?.ok_or_else(|| {
            miette::miette!("nothing installed — no active generation to roll back from")
        })?;

        let to = match target {
            Some(n) => n,
            None => self
                .generations()?
                .iter()
                .map(|g| g.n)
                .filter(|n| *n < active.n)
                .max()
                .ok_or_else(|| {
                    miette::miette!(
                        "no previous generation below {} — nothing to roll back to",
                        active.n
                    )
                })?,
        };
        if to == active.n {
            return Err(miette::miette!(
                "generation {to} is already active — nothing to roll back"
            ));
        }
        let target_gen = self
            .generations()?
            .into_iter()
            .find(|g| g.n == to)
            .ok_or_else(|| miette::miette!("generation {to} does not exist"))?;

        let mut notes = Vec::new();
        if target_gen.base_version != active.base_version {
            notes.push(format!(
                "generation {to} was created on base {} but active generation {} runs base {} \
                 — reboot to complete base rollback",
                target_gen.base_version, active.n, active.base_version
            ));
        }

        let (started, stopped) = reconcile_units(&active.packages, &target_gen.packages);

        self.begin_journal("rollback", to);
        let activator = self.activate(to, tools)?;
        notes.extend(activator.notes);
        for unit in &started {
            run_best_effort(
                &tools.systemctl,
                &["enable", "--now", unit],
                &format!("enable {unit}"),
                &mut notes,
            );
        }
        for unit in &stopped {
            run_best_effort(
                &tools.systemctl,
                &["disable", "--now", unit],
                &format!("disable {unit}"),
                &mut notes,
            );
        }
        match (&target_gen.boot_entry, &tools.bootctl) {
            (Some(entry), Some(bootctl)) => {
                run_best_effort(
                    &Some(bootctl.clone()),
                    &["set-default", entry],
                    &format!("bootctl set-default {entry}"),
                    &mut notes,
                );
            }
            (Some(_), None) => notes.push(
                "bootctl not found — boot entry not selected (rollback completes on reboot)".into(),
            ),
            (None, _) => notes.push(format!(
                "generation {to} records no boot entry — base rollback (if any) \
                 completes on reboot"
            )),
        }
        self.clear_journal()?;

        Ok(RollbackReport {
            from: active.n,
            to,
            started,
            stopped,
            notes,
        })
    }

    // ── GC ──

    /// Mark-sweep the content store. Mark = union of per-file hashes
    /// across ALL generation manifests; sweep = delete unreferenced
    /// blobs. `prune` first drops every generation except active +
    /// previous (manifests + trees) so their exclusive blobs free.
    pub fn gc(&self, prune: bool) -> miette::Result<GcReport> {
        self.recover()?;
        let mut generations_removed = Vec::new();

        if prune {
            let active = self.active_generation()?.ok_or_else(|| {
                miette::miette!(
                    "no active generation — nothing anchors retention; \
                     refusing to prune (install something first)"
                )
            })?;
            let previous = self
                .generations()?
                .iter()
                .map(|g| g.n)
                .filter(|n| *n < active.n)
                .max();
            let keep: BTreeSet<u64> = Some(active.n).into_iter().chain(previous).collect();
            for n in self.generations()?.iter().map(|g| g.n).collect::<Vec<_>>() {
                if keep.contains(&n) {
                    continue;
                }
                std::fs::remove_dir_all(self.generation_dir(n))
                    .into_diagnostic()
                    .wrap_err_with(|| format!("pruning generation {n}"))?;
                generations_removed.push(n);
            }
        }

        let mut mark: BTreeSet<String> = BTreeSet::new();
        for gen in self.generations()? {
            for pkg in gen.packages.values() {
                mark.extend(pkg.files.iter().cloned());
            }
        }

        let mut blobs_removed = 0usize;
        let mut bytes_reclaimed = 0u64;
        let store = self.store_dir();
        let Ok(shards) = std::fs::read_dir(&store) else {
            return Ok(GcReport {
                blobs_removed,
                bytes_reclaimed,
                generations_removed,
            });
        };
        for shard in shards {
            let shard = shard
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", store.display()))?;
            if !shard.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            for blob in std::fs::read_dir(shard.path())
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", shard.path().display()))?
            {
                let blob = blob.into_diagnostic().wrap_err("reading store blob")?;
                let path = blob.path();
                if blob.file_type().is_ok_and(|t| t.is_file())
                    && !mark.contains(&blob.file_name().to_string_lossy().to_string())
                {
                    bytes_reclaimed += blob.metadata().map(|m| m.len()).unwrap_or(0);
                    std::fs::remove_file(&path)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("sweeping {}", path.display()))?;
                    blobs_removed += 1;
                }
            }
        }

        Ok(GcReport {
            blobs_removed,
            bytes_reclaimed,
            generations_removed,
        })
    }

    // ── Pipeline internals ──

    /// Verify, unpack, classify, plan units, and ingest one payload
    /// into the content store. Nothing durable is touched outside the
    /// store (staging happens later).
    fn prepare_snap(
        &self,
        snap: &PendingSnap,
        tools: &RuntimeTools,
    ) -> miette::Result<PreparedSnap> {
        let unsquashfs = tools.unsquashfs.as_ref().ok_or_else(|| {
            miette::miette!(
                "unsquashfs not found on PATH — on-device install cannot unpack \
                 payloads; install squashfs-tools"
            )
        })?;

        // Fail-closed sha3-384 re-verification over the download (the
        // store resolve already checked the assertion chain; this pins
        // the bytes actually on disk).
        StoreClient::verify(&snap.payload_path, &snap.sha3_384)?;

        let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
        let extract = work.path().join("extract");
        let (meta, version) = self.unpack_payload(snap, unsquashfs, &extract)?;

        match classify(meta.snap_type.as_deref()) {
            RuntimeClass::Infrastructure => Err(miette::miette!(
                "snap '{}' is snapd infrastructure (type={:?}) — refusing to install \
                 via the package axis; the base OS updates through systemd-sysupdate",
                snap.name,
                meta.snap_type
            )),
            RuntimeClass::Store => {
                crate::output::info(format!(
                    "{}: type=store — recorded without a sysext tree (store snaps \
                     keep their own runtime)",
                    snap.name
                ));
                Ok(PreparedSnap {
                    pkg: self.recorded_package(
                        snap,
                        &version,
                        Vec::new(),
                        Vec::new(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        None,
                        BTreeMap::new(),
                        BTreeMap::new(),
                    ),
                    planner_notes: Vec::new(),
                    entries: Vec::new(),
                    units: Vec::new(),
                    renames: Vec::new(),
                })
            }
            RuntimeClass::ShootBuilt => {
                // Ingest every payload file (minus packaging metadata)
                // into the content store, then plan runtime units from
                // the payload metadata (Phase 24a planner).
                let entries = self.ingest_tree(&extract, "meta")?;
                let runtime = plan_payload_runtime(&meta, &entries, snap)?;
                let desktops = self.record_desktops(&meta, &extract)?;
                let pkg_units = runtime.units.iter().map(|u| u.unit_name.clone()).collect();
                Ok(PreparedSnap {
                    pkg: self.recorded_package(
                        snap,
                        &version,
                        entry_hashes(&entries),
                        pkg_units,
                        runtime.apps,
                        runtime.launchers,
                        runtime.assembly,
                        runtime.confined,
                        runtime.app_confined,
                        desktops,
                    ),
                    planner_notes: runtime.notes,
                    entries,
                    units: runtime.units,
                    renames: runtime.renames,
                })
            }
        }
    }

    /// Extract the payload with unsquashfs (same tool + flags as the
    /// base-rootfs flow) and read `meta/snap.yaml` twice: once into the
    /// planner's shape, once for the version field.
    fn unpack_payload(
        &self,
        snap: &PendingSnap,
        unsquashfs: &Path,
        extract: &Path,
    ) -> miette::Result<(PayloadSnap, MetaVersion)> {
        let status = std::process::Command::new(unsquashfs)
            .args([
                "-d",
                &extract.to_string_lossy(),
                "-no-xattrs",
                &snap.payload_path.to_string_lossy(),
            ])
            .status()
            .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
        if !status.success() {
            return Err(miette::miette!(
                "unsquashfs failed to extract payload for '{}'",
                snap.name
            ));
        }
        let yaml_path = extract.join("meta").join("snap.yaml");
        let yaml_text = std::fs::read_to_string(&yaml_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", yaml_path.display()))?;
        let meta: PayloadSnap = serde_yaml::from_str(&yaml_text)
            .map_err(|e| miette::miette!("meta/snap.yaml parse for '{}': {e}", snap.name))?;
        let version: MetaVersion = serde_yaml::from_str(&yaml_text)
            .map_err(|e| miette::miette!("meta/snap.yaml version parse: {e}"))?;
        Ok((meta, version))
    }

    #[allow(clippy::too_many_arguments)]
    fn recorded_package(
        &self,
        snap: &PendingSnap,
        version: &MetaVersion,
        files: Vec<String>,
        units: Vec<String>,
        apps: BTreeMap<String, String>,
        launchers: BTreeMap<String, String>,
        assembly: BTreeMap<String, crate::farm::AppAssembly>,
        confined: Option<crate::snap::Confinement>,
        app_confined: BTreeMap<String, crate::snap::Confinement>,
        desktops: BTreeMap<String, DesktopLauncher>,
    ) -> InstalledPackage {
        InstalledPackage {
            name: snap.name.clone(),
            version: version.version.clone().unwrap_or_else(|| "0".into()),
            revision: snap.revision,
            sha3_384: snap.sha3_384.clone(),
            files,
            units,
            layer: snap.layer,
            apps,
            launchers,
            assembly,
            confined,
            app_confined,
            desktops,
        }
    }

    /// Walk an extracted payload tree, content-addressing every regular
    /// file into the store and recording symlinks verbatim. `skip` names
    /// a top-level directory to exclude (payload packaging metadata).
    fn ingest_tree(&self, src: &Path, skip: &str) -> miette::Result<Vec<TreeEntry>> {
        let mut entries = Vec::new();
        self.ingest_dir(src, src, true, skip, &mut entries)?;
        Ok(entries)
    }

    /// Record the desktop-launcher metadata of one ShootBuilt payload
    /// (issue #7): for every app carrying a `desktop:` field, parse its
    /// `.desktop` file out of the extracted payload and, when the snap
    /// ships an icon (`meta/gui/icon.<ext>`), ingest that icon into the
    /// content store. The result is recorded in the package's manifest
    /// entry so the launcher emitter rebuilds entries from the manifest
    /// alone (rollback re-emits without re-unpacking).
    ///
    /// A declared `.desktop` file or a declared icon that is missing from
    /// the payload is a hard error — a GUI package that cannot produce a
    /// resolvable launcher must fail the install, not leak a broken menu
    /// entry.
    fn record_desktops(
        &self,
        meta: &PayloadSnap,
        extract: &Path,
    ) -> miette::Result<BTreeMap<String, DesktopLauncher>> {
        let mut out = BTreeMap::new();
        for (app_name, app) in &meta.apps {
            let Some(desktop_rel) = &app.desktop else {
                continue;
            };
            let desktop_path = payload_subpath(extract, desktop_rel)
                .map_err(|e| miette::miette!("app '{app_name}': {e}"))?;
            let text = std::fs::read_to_string(&desktop_path).map_err(|e| {
                miette::miette!(
                    "app '{app_name}': cannot read declared .desktop file {}: {e}",
                    desktop_path.display()
                )
            })?;
            let source = crate::desktop::parse_source(
                &text,
                &format!("{}:{app_name}", meta.name.as_deref().unwrap_or("snap")),
            )?;
            let icon = match &meta.icon {
                Some(icon_rel) => Some(self.ingest_icon(extract, icon_rel)?),
                None => None,
            };
            out.insert(
                app_name.clone(),
                DesktopLauncher {
                    name: source.name,
                    generic_name: source.generic_name,
                    comment: source.comment,
                    categories: source.categories,
                    icon_ref: source.icon_ref,
                    icon,
                },
            );
        }
        Ok(out)
    }

    /// Content-address one icon file into the store and return its
    /// DesktopIcon record (sha256 + extension).
    fn ingest_icon(&self, extract: &Path, icon_rel: &str) -> miette::Result<DesktopIcon> {
        let path = payload_subpath(extract, icon_rel)?;
        let sha256 = sha256_file(&path)?;
        self.blob_store(&path, &sha256)?;
        let ext = Path::new(icon_rel)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_string();
        if ext.is_empty() {
            miette::bail!("snap icon {icon_rel:?} has no file extension");
        }
        Ok(DesktopIcon { sha256, ext })
    }

    fn ingest_dir(
        &self,
        root: &Path,
        dir: &Path,
        is_top: bool,
        skip: &str,
        entries: &mut Vec<TreeEntry>,
    ) -> miette::Result<()> {
        for entry in std::fs::read_dir(dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?
        {
            let entry = entry.into_diagnostic().wrap_err("walking payload")?;
            self.ingest_entry(root, &entry.path(), is_top, skip, entries)?;
        }
        Ok(())
    }

    /// Classify and record one walked entry. Symlink metadata is taken
    /// FIRST — a symlinked directory must be recorded as a link, never
    /// descended into.
    fn ingest_entry(
        &self,
        root: &Path,
        path: &Path,
        is_top: bool,
        skip: &str,
        entries: &mut Vec<TreeEntry>,
    ) -> miette::Result<()> {
        let rel = path
            .strip_prefix(root)
            .expect("walk paths are under root")
            .to_string_lossy()
            .to_string();
        let meta = std::fs::symlink_metadata(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("statting {}", path.display()))?;
        if meta.file_type().is_symlink() {
            self.record_symlink(path, rel, entries)
        } else if meta.is_dir() {
            self.descend_or_skip(root, path, is_top, &rel, skip, entries)
        } else if meta.is_file() {
            self.record_file(path, rel, entries)
        } else {
            Err(miette::miette!(
                "unsupported file type at {} (fifos/sockets/devices are not \
                 installable payload content)",
                path.display()
            ))
        }
    }

    fn record_symlink(
        &self,
        path: &Path,
        rel: String,
        entries: &mut Vec<TreeEntry>,
    ) -> miette::Result<()> {
        let target = std::fs::read_link(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading link {}", path.display()))?;
        entries.push(TreeEntry::Symlink {
            rel,
            target: target.to_string_lossy().to_string(),
        });
        Ok(())
    }

    fn descend_or_skip(
        &self,
        root: &Path,
        path: &Path,
        is_top: bool,
        rel: &str,
        skip: &str,
        entries: &mut Vec<TreeEntry>,
    ) -> miette::Result<()> {
        if is_top && rel == skip {
            return Ok(());
        }
        self.ingest_dir(root, path, false, skip, entries)
    }

    fn record_file(
        &self,
        path: &Path,
        rel: String,
        entries: &mut Vec<TreeEntry>,
    ) -> miette::Result<()> {
        let sha256 = sha256_file(path)?;
        self.blob_store(path, &sha256)?;
        entries.push(TreeEntry::Blob { rel, sha256 });
        Ok(())
    }

    /// Content-address one file into the store: store/<aa>/<sha256>.
    /// Present blobs are kept (dedup across payloads and generations).
    fn blob_store(&self, src: &Path, sha256: &str) -> miette::Result<()> {
        let dest = self.blob_path(sha256);
        if dest.exists() {
            return Ok(());
        }
        let shard = dest
            .parent()
            .expect("blob path always has a shard parent")
            .to_path_buf();
        std::fs::create_dir_all(&shard)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", shard.display()))?;
        let tmp = shard.join(format!(".{}.tmp-{}", sha256, std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::fs::copy(src, &tmp)
            .into_diagnostic()
            .wrap_err_with(|| format!("storing blob {}", dest.display()))?;
        std::fs::rename(&tmp, &dest)
            .into_diagnostic()
            .wrap_err_with(|| format!("finalizing blob {}", dest.display()))?;
        Ok(())
    }

    /// Materialize one package's sysext tree in the staging dir via
    /// hardlinks into the blob store (see the module docs for why
    /// hardlinks are load-bearing and symlinks are forbidden).
    fn materialize_tree(&self, entries: &[TreeEntry], tree: &Path) -> miette::Result<()> {
        let usr = tree.join("usr");
        std::fs::create_dir_all(&usr)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", usr.display()))?;
        for entry in entries {
            self.materialize_entry(entry, &usr)?;
        }
        Ok(())
    }

    fn materialize_entry(&self, entry: &TreeEntry, usr: &Path) -> miette::Result<()> {
        let dest = match entry {
            TreeEntry::Blob { rel, .. } | TreeEntry::Symlink { rel, .. } => usr.join(rel),
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }
        match entry {
            TreeEntry::Blob { sha256, .. } => self.hardlink_blob(sha256, &dest),
            TreeEntry::Symlink { target, .. } => std::os::unix::fs::symlink(target, &dest)
                .into_diagnostic()
                .wrap_err_with(|| format!("linking {}", dest.display())),
        }
    }

    /// Hardlink a content blob into a generation tree. Cross-device
    /// (EXDEV) is a loud fail-closed error: the state root is documented
    /// to live on ONE filesystem.
    fn hardlink_blob(&self, sha256: &str, dest: &Path) -> miette::Result<()> {
        let blob = self.blob_path(sha256);
        std::fs::hard_link(&blob, dest).map_err(|e| {
            if e.raw_os_error() == Some(libc::EXDEV) {
                miette::miette!(
                    "cannot hardlink blob into the generation tree: {} and {} \
                     are on different filesystems (EXDEV). The state root must \
                     live on ONE filesystem — generations share the store's \
                     inodes, so a copy would double storage and a symlink would \
                     dangle under gc. Move --state-dir onto the store's \
                     filesystem.",
                    blob.display(),
                    dest.display()
                )
            } else {
                miette::miette!("hardlinking {} -> {}: {e}", blob.display(), dest.display())
            }
        })
    }

    /// Stage generation `n` at generations/.staging-<N>: per-package
    /// sysext trees + the manifest, then the caller rename(2)s it into
    /// place.
    fn stage_generation(
        &self,
        n: u64,
        packages: &BTreeMap<String, InstalledPackage>,
        prepared: &[PreparedSnap],
        staged: &std::collections::BTreeSet<String>,
    ) -> miette::Result<()> {
        let staging = self.staging_dir(n);
        std::fs::create_dir_all(&staging)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", staging.display()))?;
        for p in prepared {
            self.stage_package(&staging, p)?;
        }
        self.carry_forward_trees(packages, &staging, staged)?;
        let gen = Generation {
            n,
            base_version: read_base_os_release().1,
            packages: packages.clone(),
            created_epoch: now_epoch(),
            boot_entry: None,
        };
        write_json_atomic(&staging.join("manifest.json"), &gen)
    }

    /// Stage one package: sysext tree + units + renamed binaries +
    /// extension-release. Only packages that actually present content
    /// get a tree (an empty prepared contributes nothing).
    fn stage_package(&self, staging: &Path, p: &PreparedSnap) -> miette::Result<()> {
        let tree = staging.join("extensions").join(&p.pkg.name);
        self.materialize_tree(&p.entries, &tree)?;
        self.stage_units(&tree, &p.units)?;
        self.stage_renames(&tree, &p.renames)?;
        if !p.entries.is_empty() {
            self.stage_extension_release(&tree, &p.pkg.name)?;
        }
        Ok(())
    }

    fn stage_units(&self, tree: &Path, units: &[DaemonUnit]) -> miette::Result<()> {
        for unit in units {
            let unit_dir = tree.join("usr/lib/systemd/system");
            std::fs::create_dir_all(&unit_dir)
                .into_diagnostic()
                .wrap_err("creating unit dir")?;
            std::fs::write(unit_dir.join(&unit.unit_name), &unit.text)
                .into_diagnostic()
                .wrap_err_with(|| format!("writing {}", unit.unit_name))?;
        }
        Ok(())
    }

    fn stage_renames(&self, tree: &Path, renames: &[(String, String)]) -> miette::Result<()> {
        for (hash, dest_rel) in renames {
            let dest = tree.join(dest_rel);
            std::fs::create_dir_all(dest.parent().expect("rename dest has a parent"))
                .into_diagnostic()
                .wrap_err("creating bin dir")?;
            self.hardlink_blob(hash, &dest)?;
        }
        Ok(())
    }

    /// `usr/lib/extension-release/extension-release.<pkg>` with ID and
    /// VERSION_ID matching the base os-release (read at runtime; see
    /// the `_any` fallback on [`read_base_os_release`]).
    fn stage_extension_release(&self, tree: &Path, name: &str) -> miette::Result<()> {
        let release_dir = tree.join("usr/lib/extension-release");
        std::fs::create_dir_all(&release_dir)
            .into_diagnostic()
            .wrap_err("creating extension-release dir")?;
        let (base_id, base_version_id) = read_base_os_release();
        std::fs::write(
            release_dir.join(format!("extension-release.{name}")),
            extension_release_text(&base_id, &base_version_id),
        )
        .into_diagnostic()
        .wrap_err("writing extension-release")
    }

    /// Copy (hardlink-preserving rename is impossible across dirs, so
    /// this re-hardlinks) the extension trees of packages carried over
    /// from the active generation into the new generation, so every
    /// generation is self-contained and activation can relink purely
    /// from the target generation's disk state.
    fn carry_forward_trees(
        &self,
        packages: &BTreeMap<String, InstalledPackage>,
        staging: &Path,
        staged: &std::collections::BTreeSet<String>,
    ) -> miette::Result<()> {
        let Some(active) = self.active_generation()? else {
            return Ok(());
        };
        for name in packages.keys() {
            // Packages freshly staged above already have their NEW tree
            // in the staging dir — carrying their OLD tree over it would
            // collide (a changed revision must replace, not merge).
            if staged.contains(name) {
                continue;
            }
            let src = self.generation_dir(active.n).join("extensions").join(name);
            if !src.exists() {
                continue;
            }
            let dest = staging.join("extensions").join(name);
            copy_tree_hardlinks(&src, &dest)?;
        }
        Ok(())
    }

    /// Point `active` at generation `n` atomically: temp symlink +
    /// rename(2) — a reader either sees the old or the new target.
    fn flip_active(&self, n: u64) -> miette::Result<()> {
        let link = self.active_link();
        let tmp = self
            .root
            .join(format!(".active.tmp-{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(format!("generations/{n}"), &tmp)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging active -> {n}"))?;
        std::fs::rename(&tmp, &link)
            .into_diagnostic()
            .wrap_err_with(|| format!("activating generation {n}"))?;
        Ok(())
    }

    /// Activate generation `n`: flip `active`, relink every sysext tree
    /// the generation carries, refresh sysext + daemon-reload
    /// (best-effort). Idempotent — every runtime command can heal a
    /// partially-activated state by re-running activation.
    ///
    /// The refresh/reload steps warn when their tool is missing or
    /// failing. `skipped` counts the ones that were deliberately not run
    /// (tool absent, `/run/systemd/system` missing, or `SHUTTLE_SYSTEMD`
    /// opted out) — a silent no-op is reported distinctly from a tool
    /// that ran and failed, so "nothing was exercised" is never mistaken
    /// for a successful reload.
    ///
    /// Public since #60: the emitted boot oneshot (and its CLI client)
    /// calls the same seam the install/remove/rollback paths use, so a
    /// boot never re-derives a fourth activation variant.
    pub fn activate(&self, n: u64, tools: &RuntimeTools) -> miette::Result<ActivateReport> {
        let mut notes = Vec::new();
        self.flip_active(n)?;
        self.relink_extension_trees(n)?;
        let sysext = run_best_effort(
            &tools.systemd_sysext,
            &["refresh"],
            "systemd-sysext refresh",
            &mut notes,
        );
        let reload = run_best_effort(
            &tools.systemctl,
            &["daemon-reload"],
            "systemctl daemon-reload",
            &mut notes,
        );
        let skipped = [sysext, reload]
            .into_iter()
            .filter(|r| *r == ToolOutcome::Skipped)
            .count();
        if skipped > 0 {
            let note = format!(
                "activation: {skipped} systemd step(s) skipped — system bus not in use \
                 (no systemd tools resolved)"
            );
            crate::output::info(&note);
            notes.push(note);
        }
        Ok(ActivateReport { notes, skipped })
    }

    /// Boot-time entry point (ADR-0023 §4, #60): converge a half-written
    /// journal, then activate whatever `active` already points at.
    ///
    /// - **Cold store** (no `active` symlink / no generation): a clean
    ///   no-op with a note — a fresh device must not fail boot.
    /// - **Warm store**: `activate(n, tools)` on the current generation.
    ///
    /// # Convergence rule for a half-written journal
    ///
    /// [`Self::recover`] (used by every *mutating CLI* command) fails
    /// closed on an unparseable `journal.json` — that is correct for a
    /// command that is about to mutate durable state, but a boot must
    /// never wedge on it. `write_json_atomic` makes a *completed* write
    /// atomic (temp + rename), so a truncated journal can only come from
    /// an aborted external writer, never from this code's own writes. The
    /// `active` symlink is the durable source of truth and the flip is
    /// idempotent, so a boot converges by **discarding the unparseable
    /// journal and proceeding from disk truth** (the current `active`
    /// target). The journal is removed so the next mutating command sees
    /// a clean slate; the corruption is named loudly, never silently.
    ///
    /// `recover()`'s own semantics (and its journal-state-machine tests)
    /// are deliberately untouched: the lenient rule lives only on this
    /// boot path.
    pub fn activate_current(&self, tools: &RuntimeTools) -> miette::Result<ActivateCurrentReport> {
        let mut notes = Vec::new();
        if let Err(e) = self.recover() {
            let path = self.journal_path();
            let note = format!(
                "boot activation: journal {} unreadable ({e:#}) — discarding it and \
                 converging from the active symlink (the durable source of truth)",
                path.display()
            );
            crate::output::warn(&note);
            notes.push(note);
            // Discard the unparseable journal so the next mutating command
            // is not blocked by it. A failure to remove is fatal — the
            // boot path must not proceed while a corrupt journal could
            // still mislead the next command.
            std::fs::remove_file(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("discarding corrupt journal {}", path.display()))?;
        }

        let Some(active) = self.active_generation()? else {
            let note = "boot activation: no active generation (cold store) — nothing to activate"
                .to_string();
            crate::output::info(&note);
            notes.push(note);
            return Ok(ActivateCurrentReport {
                generation: None,
                noop: true,
                notes,
                skipped: 0,
            });
        };

        let activator = self.activate(active.n, tools)?;
        notes.extend(activator.notes);
        Ok(ActivateCurrentReport {
            generation: Some(active.n),
            noop: false,
            notes,
            skipped: activator.skipped,
        })
    }

    /// Rebuild the sysext links for generation `n`: every tree under
    /// generations/<n>/extensions gets a link in the extensions dir;
    /// links pointing into our state root for packages the generation
    /// does NOT carry are removed. Links pointing elsewhere (not ours)
    /// are left alone.
    fn relink_extension_trees(&self, n: u64) -> miette::Result<()> {
        std::fs::create_dir_all(&self.extensions_link_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", self.extensions_link_dir.display()))?;
        let gen_extensions = self.generation_dir(n).join("extensions");
        let mut carried: BTreeSet<String> = BTreeSet::new();
        if let Ok(read) = std::fs::read_dir(&gen_extensions) {
            for entry in read {
                let entry = entry
                    .into_diagnostic()
                    .wrap_err_with(|| format!("reading {}", gen_extensions.display()))?;
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    carried.insert(name.clone());
                    let tree = entry.path();
                    let link = self.extensions_link_dir.join(&name);
                    replace_symlink(&tree, &link)?;
                }
            }
        }
        // Drop our own stale links (presented packages the target
        // generation no longer carries).
        for entry in std::fs::read_dir(&self.extensions_link_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", self.extensions_link_dir.display()))?
        {
            let entry = entry
                .into_diagnostic()
                .wrap_err("scanning extension links")?;
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_symlink()) {
                let target = std::fs::read_link(&path).unwrap_or_default();
                let ours = self.generations_dir();
                let name = entry.file_name().to_string_lossy().to_string();
                if target.starts_with(&ours) && !carried.contains(&name) {
                    std::fs::remove_file(&path)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("removing stale link {}", path.display()))?;
                }
            }
        }
        Ok(())
    }

    fn begin_journal(&self, op: &str, n: u64) {
        self.write_journal(op, n, JournalState::Started);
    }

    /// Stage generation `n`, rename it into place, and drive the journal
    /// through `started → staging → committed` — the shared commit step
    /// every generation-producing operation runs (#60). Extracted from
    /// the install/remove sequences so there is ONE spelling of the
    /// staging→rename→journal state machine, byte-identical to the
    /// historical inline form.
    ///
    /// A caller that only reorganizes existing trees (rollback) does not
    /// stage and so does not call this; it shares [`Self::clear_journal`]
    /// and [`Self::activate`] instead.
    fn commit_generation(
        &self,
        op: &str,
        n: u64,
        packages: &BTreeMap<String, InstalledPackage>,
        prepared: &[PreparedSnap],
        staged: &BTreeSet<String>,
    ) -> miette::Result<()> {
        self.begin_journal(op, n);
        self.stage_generation(n, packages, prepared, staged)?;
        self.write_journal(op, n, JournalState::Staging);
        std::fs::rename(self.staging_dir(n), self.generation_dir(n))
            .into_diagnostic()
            .wrap_err_with(|| format!("committing generation {n}"))?;
        self.write_journal(op, n, JournalState::Committed);
        Ok(())
    }

    /// Drop the crash-recovery journal once an operation has fully
    /// finished (generation committed, activation done). The shared tail
    /// of install/remove/rollback.
    fn clear_journal(&self) -> miette::Result<()> {
        std::fs::remove_file(self.journal_path())
            .into_diagnostic()
            .wrap_err("clearing journal")
    }

    fn write_journal(&self, op: &str, n: u64, state: JournalState) {
        let journal = Journal {
            op: op.to_string(),
            target_gen: n,
            state,
        };
        if let Err(e) = write_json_atomic(&self.journal_path(), &journal) {
            crate::output::warn(format!("journal write failed: {e:#}"));
        }
    }
}

// ── Pure helpers (unit-tested directly) ──

impl TreeEntry {
    fn rel(&self) -> &str {
        match self {
            TreeEntry::Blob { rel, .. } | TreeEntry::Symlink { rel, .. } => rel,
        }
    }
}

/// sha256 hashes of every content entry (symlinks carry no content and
/// stay out of the GC mark set).
fn entry_hashes(entries: &[TreeEntry]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| match e {
            TreeEntry::Blob { sha256, .. } => Some(sha256.clone()),
            TreeEntry::Symlink { .. } => None,
        })
        .collect()
}

/// Resolve a payload-relative path (a declared `.desktop` file, the snap
/// icon) under an extracted payload root. The path must be relative and
/// must not escape the payload with `..` — the declared path is metadata
/// the payload author controls, so it is validated before use.
fn payload_subpath(root: &Path, rel: &str) -> miette::Result<PathBuf> {
    if rel.is_empty() {
        miette::bail!("payload path must not be empty");
    }
    if rel.starts_with('/') {
        miette::bail!("payload path must be relative to the payload root, got {rel:?}");
    }
    let path = root.join(rel);
    let canonical_root = root
        .canonicalize()
        .map_err(|e| miette::miette!("payload root {}: {e}", root.display()))?;
    let canonical = path
        .canonicalize()
        .map_err(|e| miette::miette!("payload path {rel:?}: {e}"))?;
    if !canonical.starts_with(&canonical_root) {
        miette::bail!("payload path {rel:?} escapes the payload root");
    }
    Ok(canonical)
}

/// Planned runtime for one ShootBuilt payload: daemon units, the
/// renamed-command-binary hardlink specs, confinement launchers, and
/// planner warnings.
struct PayloadRuntime {
    units: Vec<DaemonUnit>,
    renames: Vec<(String, String)>,
    /// app name → binary content hash (mirrors the renames; recorded in
    /// the package manifest for the pod farm).
    apps: BTreeMap<String, String>,
    /// app name → confined-launcher wrapper blob hash (ticket #11). Only
    /// populated for confined apps; the farm emitter prefers it over
    /// `apps` for those so the farm symlink invokes `shuttle run`.
    launchers: BTreeMap<String, String>,
    /// app name → sibling assembly (issue #37), only for apps whose
    /// payload directory carries content beside the binary; recorded in
    /// the package manifest for the farm's assembly subtree.
    assembly: BTreeMap<String, crate::farm::AppAssembly>,
    /// Package-level confinement grants (ticket #11).
    confined: Option<crate::snap::Confinement>,
    /// Per-app confinement overrides (ticket #11): only apps that differ
    /// from the package default.
    app_confined: BTreeMap<String, crate::snap::Confinement>,
    notes: Vec<String>,
}

/// Plan the runtime for a ShootBuilt payload with the Phase 24a
/// planner: daemon units, renamed command binaries (hardlinking the
/// same content blob as the in-payload path — content-addressed
/// identity preserved), and the planner's warnings.
fn plan_payload_runtime(
    meta: &PayloadSnap,
    entries: &[TreeEntry],
    snap: &PendingSnap,
) -> miette::Result<PayloadRuntime> {
    let snap_name = meta.name.as_deref().unwrap_or(&snap.name).to_string();
    let snap_plugs: Vec<_> = meta
        .plugs
        .iter()
        .map(|(plug_name, plug)| plug.to_plug_ref(plug_name))
        .collect();
    let mut out = PayloadRuntime {
        units: Vec::new(),
        renames: Vec::new(),
        apps: BTreeMap::new(),
        launchers: BTreeMap::new(),
        assembly: BTreeMap::new(),
        confined: meta.confined.clone(),
        app_confined: BTreeMap::new(),
        notes: Vec::new(),
    };
    for (app_name, app) in &meta.apps {
        let spec = spec_from_payload_app(&snap_name, app_name, app, snap_plugs.clone());
        let plan = plan_app(&spec);
        out.notes.extend(plan.warnings);
        if let Some(unit) = plan.daemon {
            out.units.push(unit);
        }
        let hash = blob_hash_for(entries, &plan.in_snap_binary, &snap.name)?;
        out.renames
            .push((hash.clone(), format!("usr/bin/{}-{}", plan.snap, plan.app)));
        out.apps.insert(plan.app.clone(), hash);
        // Issue #37: record the payload content beside the command
        // binary so the pod farm can assemble multi-file packages.
        let asm = sibling_assembly(entries, &plan.in_snap_binary);
        if !asm.is_empty() {
            out.assembly.insert(plan.app.clone(), asm);
        }
        // Ticket #11: a confined app records its launcher-wrapper blob
        // (the `<command>.shuttle-launcher` sibling authored at build
        // time) so the farm symlink points at a `shuttle run` wrapper,
        // and its per-app confinement override when it differs from the
        // package default.
        if let Some(_confined) =
            crate::snap::Confinement::for_app(app.confined.as_ref(), meta.confined.as_ref())
        {
            let launcher_rel = crate::snap::launcher_sibling_rel_path(&plan.in_snap_binary);
            let launcher_hash = blob_hash_for(entries, &launcher_rel, &snap.name)?;
            out.launchers.insert(plan.app.clone(), launcher_hash);
            if let Some(override_conf) = &app.confined {
                out.app_confined
                    .insert(plan.app.clone(), override_conf.clone());
            }
        }
    }
    Ok(out)
}

fn blob_hash_for(entries: &[TreeEntry], rel: &str, snap_name: &str) -> miette::Result<String> {
    match entries.iter().find(|e| e.rel() == rel) {
        Some(TreeEntry::Blob { sha256, .. }) => Ok(sha256.clone()),
        _ => Err(miette::miette!(
            "command binary '{rel}' not found in payload '{snap_name}'"
        )),
    }
}

/// Record one app's sibling assembly (issue #37): every payload entry
/// under the command binary's directory other than the binary itself,
/// with paths relative to that directory so the farm can reproduce the
/// layout beside the assembled binary. A payload that ships the binary
/// alone yields an empty assembly — the manifest stays unchanged and
/// the farm keeps the bare direct link.
///
/// A command carrying the build-time wrapper's `.real` sibling
/// (issues #9/#10/#13) is wrapper-managed: the wrapper resolves the
/// real entry and its own path derivations from the command's STORE
/// blob location, so it must keep the bare store link — no assembly is
/// recorded for it.
fn sibling_assembly(entries: &[TreeEntry], in_snap_binary: &str) -> crate::farm::AppAssembly {
    let mut asm = crate::farm::AppAssembly {
        binary: in_snap_binary.to_string(),
        files: BTreeMap::new(),
        links: BTreeMap::new(),
    };
    let Some(dir) = Path::new(in_snap_binary).parent() else {
        return asm;
    };
    if dir.as_os_str().is_empty() {
        return asm;
    }
    let file_name = in_snap_binary
        .rsplit_once('/')
        .map(|(_, f)| f)
        .unwrap_or(in_snap_binary);
    let wrapper_real_rel = dir.join(crate::snap::real_sibling_name(file_name));
    if entries
        .iter()
        .any(|e| e.rel() == wrapper_real_rel.to_string_lossy())
    {
        // Wrapper-managed command (issues #9/#10/#13) — no assembly.
        return crate::farm::AppAssembly::default();
    }
    for entry in entries {
        let rel = entry.rel();
        if rel == in_snap_binary {
            continue;
        }
        let Ok(rest) = Path::new(rel).strip_prefix(dir) else {
            continue;
        };
        let rel_to_binary = rest.to_string_lossy().into_owned();
        if rel_to_binary.is_empty() {
            continue;
        }
        match entry {
            TreeEntry::Blob { sha256, .. } => {
                asm.files.insert(rel_to_binary, sha256.clone());
            }
            TreeEntry::Symlink { target, .. } => {
                asm.links.insert(rel_to_binary, target.clone());
            }
        }
    }
    asm
}

/// Unit reconciliation set difference between two generations: units to
/// START (in `to`, absent in `from`) and units to STOP (in `from`,
/// absent in `to`).
pub fn reconcile_units(
    from: &BTreeMap<String, InstalledPackage>,
    to: &BTreeMap<String, InstalledPackage>,
) -> (Vec<String>, Vec<String>) {
    let from_units: BTreeSet<&String> = from.values().flat_map(|p| p.units.iter()).collect();
    let to_units: BTreeSet<&String> = to.values().flat_map(|p| p.units.iter()).collect();
    let started: Vec<String> = to_units.difference(&from_units).cloned().cloned().collect();
    let stopped: Vec<String> = from_units.difference(&to_units).cloned().cloned().collect();
    (started, stopped)
}

/// Which installed pins differ from a freshly resolved set of
/// (name, revision, sha3-384) triples: not installed, or revision/hash
/// changed. The upgrade no-op detector.
pub fn changed_pins(
    resolved: &[(String, u32, String)],
    installed: &BTreeMap<String, InstalledPackage>,
) -> Vec<String> {
    resolved
        .iter()
        .filter(|(name, revision, sha3)| {
            installed
                .get(name)
                .is_none_or(|ip| ip.revision != *revision || ip.sha3_384 != *sha3)
        })
        .map(|(name, _, _)| name.clone())
        .collect()
}

/// Verify a channel manifest's signatures (ADR-0011 step (d)) against
/// the on-device anchors. `Ok(None)` = unsigned (proceed with a note);
/// `Ok(Some(key_id))` = verified under that key; `Err` = signed but no
/// trusted signature verifies — fail closed.
pub fn verify_signatures(
    canonical: &[u8],
    signatures: &BTreeMap<String, serde_json::Value>,
) -> miette::Result<Option<String>> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let anchor = PathBuf::from(DEVICE_ANCHOR);
    let keys = crate::sign::keys_dir(&home);
    verify_signatures_at(canonical, signatures, &anchor, &keys)
}

pub fn verify_signatures_at(
    canonical: &[u8],
    signatures: &BTreeMap<String, serde_json::Value>,
    anchor: &Path,
    keys: &Path,
) -> miette::Result<Option<String>> {
    if signatures.is_empty() {
        return Ok(None);
    }
    // 0. ADR-0024 §4 revocation gate. The embedded revocation list lives
    // beside the device anchor (/etc/shuttle/revoked-keys); the operator
    // list lives under the keychain dir (~/.config/shuttle/keys/
    // revoked-keys). A signature under a revoked id is refused BEFORE any
    // anchor check, so "trusted once, revoked now" cannot be masked by a
    // dual-signed manifest that a still-trusted key also signed.
    let revoked = embedded_revoked_keys(anchor, keys)?;
    crate::sign::reject_revoked(signatures, &revoked)?;

    // 1. The embedded device trust set (/etc/shuttle/trusted-keys/*.pub),
    //    plus the single-anchor fallback (/etc/shuttle/update-key.pub) for
    //    images built before the set shape existed.
    let embedded_chain = crate::sign::Keychain::load_dir(&trusted_keys_dir(anchor))?;
    for (key_id, public) in embedded_chain.entries_for_verify() {
        if crate::sign::verify(canonical, signatures, &to_hex(&public)).is_ok() {
            return Ok(Some(key_id));
        }
    }
    if let Ok(text) = std::fs::read_to_string(anchor) {
        if let Some(public_hex) = key_line(&text) {
            if crate::sign::verify(canonical, signatures, public_hex).is_ok() {
                return Ok(Some(key_id_of(public_hex)));
            }
        }
    }

    // 2. The operator keychain (~/.config/shuttle/keys/*.pub). The
    //    revocation gate ran above, so the closed-set verify is enough.
    let chain = crate::sign::Keychain::load_dir(keys)?;
    match crate::sign::verify_keychain(canonical, signatures, &chain) {
        Ok(key_id) => Ok(Some(key_id)),
        Err(e) => Err(miette::miette!(
            "manifest carries signatures but no trusted anchor verifies them \
             (anchor: {}, keychain: {}): {e}",
            anchor.display(),
            keys.display()
        )),
    }
}

/// The embedded-key-set directory beside a device anchor: for
/// `/etc/shuttle/update-key.pub` that is `/etc/shuttle/trusted-keys/`.
fn trusted_keys_dir(anchor: &Path) -> PathBuf {
    anchor
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("trusted-keys")
}

/// Read the device revocation list beside the anchor, unioned with the
/// operator list under the keychain dir. A missing file is an empty list;
/// the operator side is the local `revoked-keys` the key ceremony writes.
fn embedded_revoked_keys(anchor: &Path, keys: &Path) -> miette::Result<Vec<String>> {
    let mut revoked = Vec::new();
    let device = anchor
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("revoked-keys");
    if let Ok(text) = std::fs::read_to_string(&device) {
        revoked.extend(parse_revoked_keys(&text, &device)?);
    }
    revoked.extend(crate::sign::read_revoked_keys(keys)?);
    revoked.sort();
    revoked.dedup();
    Ok(revoked)
}

/// Parse a revocation list body: one 16-hex key id per line, `#` comments
/// and blanks skipped. Malformed lines are named errors — a corrupt
/// revocation list is never treated as empty (that would silently bless
/// revoked keys).
fn parse_revoked_keys(text: &str, path: &Path) -> miette::Result<Vec<String>> {
    let mut ids = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 16 || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(miette::miette!(
                "revocation list {} line {} is not a 16-hex key id: {line:?}",
                path.display(),
                n + 1
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    Ok(ids)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// First non-comment, non-empty line of a two-line public key file.
fn key_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
}

fn key_id_of(public_hex: &str) -> String {
    public_hex.chars().take(16).collect()
}

/// (base ID, VERSION_ID) from the host os-release; the documented
/// fallback `("_any", "_any")` — systemd-sysext's wildcard — when the
/// host os-release is unreadable, so the tree still presents.
fn read_base_os_release() -> (String, String) {
    const ANY: &str = "_any";
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else {
        return (ANY.into(), ANY.into());
    };
    let mut id = None;
    let mut version_id = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key {
            "ID" => id = Some(value),
            "VERSION_ID" => version_id = Some(value),
            _ => {}
        }
    }
    (
        id.unwrap_or_else(|| ANY.into()),
        version_id.unwrap_or_else(|| ANY.into()),
    )
}

fn extension_release_text(id: &str, version_id: &str) -> String {
    format!("ID={id}\nVERSION_ID={version_id}\n")
}

/// Copy a tree, hardlinking regular files (never copying contents) —
/// the carried-over-tree path for packages untouched by an operation.
fn copy_tree_hardlinks(src: &Path, dest: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dest)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dest.display()))?;
    for entry in std::fs::read_dir(src)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", src.display()))?
    {
        let entry = entry.into_diagnostic().wrap_err("copying tree")?;
        copy_tree_entry(&entry.path(), &dest.join(entry.file_name()))?;
    }
    Ok(())
}

fn copy_tree_entry(from: &Path, to: &Path) -> miette::Result<()> {
    let meta = std::fs::symlink_metadata(from)
        .into_diagnostic()
        .wrap_err_with(|| format!("statting {}", from.display()))?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(from)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading link {}", from.display()))?;
        std::os::unix::fs::symlink(target, to)
            .into_diagnostic()
            .wrap_err_with(|| format!("linking {}", to.display()))
    } else if meta.is_dir() {
        copy_tree_hardlinks(from, to)
    } else {
        std::fs::hard_link(from, to)
            .into_diagnostic()
            .wrap_err_with(|| format!("hardlinking {}", to.display()))
    }
}

fn replace_symlink(target: &Path, link: &Path) -> miette::Result<()> {
    let tmp = link.with_file_name(format!(
        ".{}.tmp-{}",
        link.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "link".into()),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .into_diagnostic()
        .wrap_err_with(|| format!("staging link {}", link.display()))?;
    std::fs::rename(&tmp, link)
        .into_diagnostic()
        .wrap_err_with(|| format!("replacing link {}", link.display()))?;
    Ok(())
}

/// Serialize `value` as pretty JSON and rename it over `path` (the
/// manifest.rs write_atomic pattern — a crash mid-write leaves the
/// previous file intact). Tiny local duplicate: ImageManifest's
/// write_atomic is an inherent method, not a generic helper.
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> miette::Result<()> {
    let mut content = serde_json::to_string_pretty(value)
        .map_err(|e| miette::miette!("serialize {}: {e}", path.display()))?;
    content.push('\n');
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let cleanup = |tmp: &Path| {
        let _ = std::fs::remove_file(tmp);
    };
    if let Err(e) = std::fs::write(&tmp, &content) {
        cleanup(&tmp);
        return Err(miette::miette!("failed to write {}: {e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        cleanup(&tmp);
        return Err(miette::miette!(
            "failed to finalize {}: {e}",
            path.display()
        ));
    }
    Ok(())
}

/// Best-effort shell-out: a missing tool or a failing command warns and
/// continues — presentation hiccups must never corrupt durable state.
/// Returns whether the tool actually ran ([`ToolOutcome::Skipped`] when
/// it is absent, so callers can report "not exercised" distinctly from
/// "exited nonzero").
fn run_best_effort(
    tool: &Option<PathBuf>,
    args: &[&str],
    what: &str,
    notes: &mut Vec<String>,
) -> ToolOutcome {
    let Some(tool) = tool else {
        let note = format!("{what}: skipped (systemd not in use — {} not run)", args[0]);
        crate::output::warn(&note);
        notes.push(note);
        return ToolOutcome::Skipped;
    };
    match std::process::Command::new(tool).args(args).status() {
        Ok(status) if status.success() => {
            crate::output::ok(what);
            ToolOutcome::Ran
        }
        Ok(status) => {
            let note = format!("{what}: exited {:?} (continuing)", status.code());
            crate::output::warn(&note);
            notes.push(note);
            ToolOutcome::Ran
        }
        Err(e) => {
            let note = format!("{what}: {e} (continuing)");
            crate::output::warn(&note);
            notes.push(note);
            ToolOutcome::Ran
        }
    }
}

/// Whether a best-effort tool ran ([`Ran`]) or was deliberately not
/// invoked because it is absent ([`Skipped`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolOutcome {
    Ran,
    Skipped,
}

/// What one activation did: the notes to surface, and how many of the
/// system-bus steps were deliberately skipped rather than run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateReport {
    pub notes: Vec<String>,
    /// Count of system-bus steps skipped because their tool is absent.
    /// Kept on the report so callers (and tests) can assert the
    /// skipped-vs-failed distinction without parsing notes.
    pub skipped: usize,
}

/// What [`RuntimeStore::activate_current`] did — the boot-time entry
/// point. A cold store is a clean no-op (`generation: None`), never an
/// error: a fresh device must not fail boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateCurrentReport {
    /// The generation activated, or `None` when the store is cold (no
    /// `active` symlink yet) — a no-op, not a failure.
    pub generation: Option<u64>,
    /// True when there was nothing to activate (cold store / no active
    /// generation).
    pub noop: bool,
    pub notes: Vec<String>,
    /// System-bus steps deliberately skipped (tool absent / not in use).
    pub skipped: usize,
}

fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {e}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette::miette!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `version` from a payload's meta/snap.yaml (the units.rs planner's
/// PayloadSnap deliberately carries no version — it is build-side).
#[derive(Debug, Deserialize)]
struct MetaVersion {
    #[serde(default)]
    version: Option<String>,
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sha3_384_file;
    use std::os::unix::fs::MetadataExt;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const ORPHAN: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    // ── Fixtures ──

    /// A state root with a temp extensions-link dir (never /var/lib).
    struct Fixture {
        _dir: tempfile::TempDir,
        links: tempfile::TempDir,
        store: RuntimeStore,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let links = tempfile::tempdir().unwrap();
        let store = RuntimeStore::new(dir.path().to_path_buf())
            .with_extensions_link_dir(links.path().to_path_buf());
        Fixture {
            _dir: dir,
            links,
            store,
        }
    }

    fn pkg(name: &str, units: &[&str], files: Vec<String>) -> InstalledPackage {
        InstalledPackage {
            name: name.into(),
            version: "1.0".into(),
            revision: 1,
            sha3_384: "abc".into(),
            files,
            units: units.iter().map(|s| s.to_string()).collect(),
            layer: crate::farm::ClaimLayer::Own,
            apps: BTreeMap::new(),
            launchers: BTreeMap::new(),
            assembly: BTreeMap::new(),
            confined: None,
            app_confined: BTreeMap::new(),
            desktops: BTreeMap::new(),
        }
    }

    /// Seed a generation dir + manifest directly (hermetic — no
    /// payloads needed for rollback/gc tests).
    fn seed_generation(store: &RuntimeStore, n: u64, packages: BTreeMap<String, InstalledPackage>) {
        let dir = store.generation_dir(n);
        std::fs::create_dir_all(dir.join("extensions")).unwrap();
        let gen = Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        };
        write_json_atomic(&dir.join("manifest.json"), &gen).unwrap();
    }

    fn seed_tree(store: &RuntimeStore, n: u64, name: &str) {
        let tree = store.generation_dir(n).join("extensions").join(name);
        std::fs::create_dir_all(tree.join("usr/lib/extension-release")).unwrap();
        std::fs::write(
            tree.join("usr/lib/extension-release")
                .join(format!("extension-release.{name}")),
            "ID=any\n",
        )
        .unwrap();
        std::fs::write(tree.join("usr").join(name), "content").unwrap();
    }

    fn seed_blob(store: &RuntimeStore, hash: &str, len: usize) {
        let path = store.blob_path(hash);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![0u8; len]).unwrap();
    }

    fn one_pkg_map(p: InstalledPackage) -> BTreeMap<String, InstalledPackage> {
        let mut m = BTreeMap::new();
        m.insert(p.name.clone(), p);
        m
    }

    /// A fake tool: exits 0 and touches a marker — proves injection.
    fn fake_tool(dir: &Path, name: &str, marker: &Path) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn has_tool(tool: &str) -> bool {
        find_on_path(tool).is_some()
    }

    /// Pack a minimal shoot-built payload with mksquashfs (units.rs
    /// test pattern); None when the squashfs tools are unavailable.
    fn pack_payload(dir: &Path) -> Option<PathBuf> {
        pack_payload_with(dir, "exec true")
    }

    /// [`pack_payload`] with an injectable build-marker: two payloads
    /// built with different markers have different content hashes.
    fn pack_payload_with(dir: &Path, marker: &str) -> Option<PathBuf> {
        if !has_tool("unsquashfs") || !has_tool("mksquashfs") {
            eprintln!("skipping: unsquashfs/mksquashfs unavailable");
            return None;
        }
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("meta")).unwrap();
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::write(
            tree.join("meta/snap.yaml"),
            "\
name: my-snap
version: '1.0'
confinement: strict
apps:
  srv:
    command: bin/myservice --listen :80
    daemon: simple
    plugs: [network, bus]
plugs:
  network: network
  bus:
    interface: dbus
    name: com.example.Srv
",
        )
        .unwrap();
        std::fs::write(tree.join("bin/myservice"), format!("#!/bin/sh\n{marker}\n")).unwrap();
        // A payload-internal symlink: recreated, never followed.
        std::os::unix::fs::symlink("myservice", tree.join("bin/myservice-link")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            tree.join("bin/myservice"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let payload = dir.join("my-snap_1_abc.snap");
        let status = std::process::Command::new("mksquashfs")
            .arg(&tree)
            .arg(&payload)
            .arg("-noappend")
            .arg("-all-root")
            .output()
            .unwrap();
        assert!(status.status.success(), "mksquashfs failed");
        Some(payload)
    }

    fn gated_tools(work: &Path) -> Option<RuntimeTools> {
        let unsquashfs = find_on_path("unsquashfs")?;
        let sysext_marker = work.join("sysext.marker");
        let systemctl_marker = work.join("systemctl.marker");
        Some(RuntimeTools {
            unsquashfs: Some(unsquashfs),
            systemd_sysext: Some(fake_tool(work, "fake-sysext", &sysext_marker)),
            systemctl: Some(fake_tool(work, "fake-systemctl", &systemctl_marker)),
            bootctl: None,
        })
    }

    // ── Generation numbering + roundtrip ──

    #[test]
    fn generation_numbering_starts_at_1_and_increments() {
        let f = fixture();
        assert_eq!(f.store.next_generation_number().unwrap(), 1);
        seed_generation(&f.store, 1, BTreeMap::new());
        assert_eq!(f.store.next_generation_number().unwrap(), 2);
        seed_generation(&f.store, 7, BTreeMap::new());
        assert_eq!(f.store.next_generation_number().unwrap(), 8);
        assert_eq!(f.store.generations().unwrap().len(), 2);
    }

    #[test]
    fn generation_manifest_roundtrip() {
        let gen = Generation {
            n: 3,
            base_version: "24.04".into(),
            packages: one_pkg_map(pkg("a", &["a-srv.service"], vec![H1.into()])),
            created_epoch: 42,
            boot_entry: Some("shuttle-os-7.conf".into()),
        };
        let json = serde_json::to_string(&gen).unwrap();
        let back: Generation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, gen);
        assert!(json.contains("boot_entry"));
    }

    // ── Active symlink atomicity ──

    #[test]
    fn active_flip_readlink_target_is_relative_and_replaced() {
        let f = fixture();
        seed_generation(&f.store, 3, BTreeMap::new());
        seed_generation(&f.store, 4, BTreeMap::new());
        f.store.flip_active(3).unwrap();
        assert_eq!(
            std::fs::read_link(f.store.active_link()).unwrap(),
            Path::new("generations/3")
        );
        // Second flip REPLACES the link (never appends, never fails).
        f.store.flip_active(4).unwrap();
        assert_eq!(
            std::fs::read_link(f.store.active_link()).unwrap(),
            Path::new("generations/4")
        );
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 4);
    }

    // ── Journal recovery — all three states ──

    #[test]
    fn journal_recovery_started_removes_only_the_journal() {
        let f = fixture();
        f.store.begin_journal("install", 5);
        let staging = f.store.staging_dir(5);
        std::fs::create_dir_all(&staging).unwrap();
        f.store.recover().unwrap();
        assert!(!f.store.journal_path().exists(), "journal removed");
        assert!(staging.exists(), "started recovery touches nothing else");
    }

    #[test]
    fn journal_recovery_staging_removes_staging_dir_and_journal() {
        let f = fixture();
        f.store.write_journal("install", 5, JournalState::Staging);
        let staging = f.store.staging_dir(5);
        std::fs::create_dir_all(staging.join("extensions/x")).unwrap();
        f.store.recover().unwrap();
        assert!(!staging.exists(), "half-built staging removed");
        assert!(!f.store.journal_path().exists(), "journal removed");
    }

    #[test]
    fn journal_recovery_committed_finishes_the_flip() {
        let f = fixture();
        seed_generation(&f.store, 5, BTreeMap::new());
        f.store.flip_active(1).unwrap(); // stale pre-crash state
        f.store.write_journal("install", 5, JournalState::Committed);
        f.store.recover().unwrap();
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 5);
        assert!(!f.store.journal_path().exists(), "journal removed");
    }

    #[test]
    fn journal_recovery_committed_missing_generation_is_named_error() {
        let f = fixture();
        f.store.write_journal("install", 9, JournalState::Committed);
        let err = f.store.recover().unwrap_err();
        assert!(
            format!("{err:#}").contains("missing generation 9"),
            "named error required: {err:#}"
        );
    }

    // ── Boot-time activation (#60, ADR-0023 §4) ──

    /// `recover()` keeps failing closed on an unparseable journal — the
    /// boot path's lenient rule must NOT loosen the mutating-command
    /// state machine.
    #[test]
    fn recover_still_fails_closed_on_a_truncated_journal() {
        let f = fixture();
        std::fs::write(f.store.journal_path(), "{\"op\":\"insta").unwrap();
        let err = f.store.recover().unwrap_err();
        assert!(
            format!("{err:#}").contains("corrupt journal"),
            "mutating commands still fail closed: {err:#}"
        );
        assert!(
            f.store.journal_path().exists(),
            "recover() must not consume the journal it refused"
        );
    }

    /// A cold boot against a half-written journal: the boot path names
    /// the corruption, discards it, and converges on activating the
    /// current generation. A second run is the same state (idempotent).
    #[test]
    fn activate_current_converges_from_a_truncated_journal() {
        let f = fixture();
        seed_generation(&f.store, 1, BTreeMap::new());
        seed_generation(&f.store, 2, BTreeMap::new());
        f.store.flip_active(2).unwrap();
        seed_tree(&f.store, 2, "my-snap");

        // A partial write from an aborted external writer.
        std::fs::write(f.store.journal_path(), "{\"op\":\"install\",\"targe").unwrap();

        let report = f.store.activate_current(&RuntimeTools::default()).unwrap();
        assert!(
            !report.noop,
            "a warm store activates its current generation"
        );
        assert_eq!(report.generation, Some(2));
        assert!(
            report.notes.iter().any(|n| n.contains("unreadable")),
            "the corruption is named, never silent: {:?}",
            report.notes
        );
        assert!(
            !f.store.journal_path().exists(),
            "the corrupt journal is discarded"
        );
        // Converged: active still points at generation 2, tree relinked.
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 2);
        assert!(f
            .store
            .extensions_link_dir
            .join("my-snap")
            .symlink_metadata()
            .is_ok());

        // Idempotent: a second run reaches the same state, not a new one.
        let second = f.store.activate_current(&RuntimeTools::default()).unwrap();
        assert_eq!(second.generation, Some(2));
        assert_eq!(
            std::fs::read_link(f.store.active_link()).unwrap(),
            Path::new("generations/2")
        );
    }

    /// A cold store (no generations, no `active` link) is a clean no-op —
    /// a fresh device must not fail boot.
    #[test]
    fn activate_current_on_a_cold_store_is_a_clean_noop() {
        let f = fixture();
        assert!(!f.store.active_link().exists(), "cold store has no active");
        let report = f.store.activate_current(&RuntimeTools::default()).unwrap();
        assert!(report.noop);
        assert_eq!(report.generation, None);
        assert!(
            report.notes.iter().any(|n| n.contains("cold store")),
            "cold boot is noted: {:?}",
            report.notes
        );
    }

    /// A stale `committed` journal for a missing generation must not wedge
    /// boot: the boot path discards the journal and activates the current
    /// generation instead of failing on the dangling target.
    #[test]
    fn activate_current_discards_a_committed_journal_for_a_missing_generation() {
        let f = fixture();
        seed_generation(&f.store, 1, BTreeMap::new());
        f.store.flip_active(1).unwrap();
        f.store.write_journal("install", 9, JournalState::Committed);

        let report = f.store.activate_current(&RuntimeTools::default()).unwrap();
        assert_eq!(report.generation, Some(1));
        assert!(!f.store.journal_path().exists());
    }

    /// `commit_generation` drives the journal through the exact
    /// state-machine sequence the inline install/remove code did: it
    /// stages, renames, and leaves `committed` on disk (the caller clears
    /// it once activation finishes).
    #[test]
    fn commit_generation_stages_renames_and_journals_committed() {
        let f = fixture();
        // A `committed` journal makes recover() finish the flip; clear it
        // before exercising the helper directly.
        f.store
            .commit_generation("install", 3, &BTreeMap::new(), &[], &BTreeSet::new())
            .unwrap();
        assert!(
            f.store.generation_dir(3).join("manifest.json").is_file(),
            "staging was renamed into place"
        );
        assert!(!f.store.staging_dir(3).exists(), "staging dir consumed");
        let text = std::fs::read_to_string(f.store.journal_path()).unwrap();
        let journal: Journal = serde_json::from_str(&text).unwrap();
        assert_eq!(journal.state, JournalState::Committed);
        assert_eq!(journal.target_gen, 3);
        // The shared tail clears it.
        f.store.clear_journal().unwrap();
        assert!(!f.store.journal_path().exists());
    }

    // ── Install pipeline (gated on squashfs tools) ──

    #[test]
    fn install_creates_generation_blobs_and_extension_tree() {
        let work = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        let Some(payload) = pack_payload(work.path()) else {
            return; // gated
        };
        let Some(tools) = gated_tools(work.path()) else {
            return;
        };
        let f = fixture();
        let pending = PendingSnap {
            name: "my-snap".into(),
            revision: 7,
            sha3_384: sha3_384_file(&payload).unwrap(),
            payload_path: payload,
            ..Default::default()
        };

        let report = f
            .store
            .install_batch(
                std::slice::from_ref(&pending),
                &SignatureEnvelope::default(),
                &tools,
            )
            .unwrap();
        assert!(!report.noop);
        assert_eq!(report.generation, Some(1));
        assert_eq!(report.installed.len(), 1);
        assert_eq!(report.installed[0].version, "1.0");
        assert_eq!(report.installed[0].revision, 7);
        assert!(
            report.notes.iter().any(|n| n.contains("unsigned")),
            "unsigned-envelope note required: {:?}",
            report.notes
        );

        // Manifest: package recorded with version from meta/snap.yaml,
        // content hashes present, unit registered.
        let gen = f.store.active_generation().unwrap().unwrap();
        assert_eq!(gen.n, 1);
        let ip = gen.packages.get("my-snap").expect("package recorded");
        assert!(!ip.files.is_empty(), "content hashes recorded for GC mark");
        assert_eq!(ip.units, vec!["my-snap-srv.service".to_string()]);

        // Blob exists under the shard layout and the tree file is the
        // SAME INODE — hardlink, not copy.
        let hash = &ip.files[0];
        let blob = f.store.blob_path(hash);
        assert!(
            blob.exists(),
            "blob at store/<aa>/<hash>: {}",
            blob.display()
        );
        let tree_bin = f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/bin/myservice");
        let blob_meta = std::fs::metadata(&blob).unwrap();
        let tree_meta = std::fs::metadata(&tree_bin).unwrap();
        assert_eq!(blob_meta.dev(), tree_meta.dev(), "same device");
        assert_eq!(blob_meta.ino(), tree_meta.ino(), "hardlink: same inode");

        // Payload symlink recreated (as a symlink), meta/ excluded.
        let tree_link = f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/bin/myservice-link");
        assert!(std::fs::symlink_metadata(&tree_link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/meta")
            .exists());

        // Renamed app binary hardlinks the same blob.
        let renamed = f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/bin/my-snap-srv");
        assert!(renamed.exists());
        assert_eq!(
            std::fs::metadata(&renamed).unwrap().ino(),
            blob_meta.ino(),
            "rename shares the blob inode"
        );

        // Daemon unit + extension-release inside the tree.
        let unit = f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/lib/systemd/system/my-snap-srv.service");
        let unit_text = std::fs::read_to_string(&unit).unwrap();
        assert!(unit_text.contains("ExecStart=/usr/bin/my-snap-srv"));
        let release = f
            .store
            .generation_dir(1)
            .join("extensions/my-snap/usr/lib/extension-release/extension-release.my-snap");
        assert!(std::fs::read_to_string(&release)
            .unwrap()
            .starts_with("ID="));

        // Activation link points into the generation tree.
        let link = f.links.path().join("my-snap");
        let target = std::fs::read_link(&link).unwrap();
        assert!(
            target.ends_with("generations/1/extensions/my-snap"),
            "link target: {target:?}"
        );

        // Injected best-effort tools actually RAN (fakes touched markers).
        assert!(
            work.path().join("sysext.marker").exists(),
            "sysext refresh ran"
        );
        assert!(
            work.path().join("systemctl.marker").exists(),
            "systemctl ran"
        );

        // Journal cleared on success.
        assert!(!f.store.journal_path().exists());
    }

    #[test]
    fn install_same_revision_is_a_noop_without_new_generation() {
        let work = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        let Some(payload) = pack_payload(work.path()) else {
            return; // gated
        };
        let Some(tools) = gated_tools(work.path()) else {
            return;
        };
        let f = fixture();
        let pending = PendingSnap {
            name: "my-snap".into(),
            revision: 7,
            sha3_384: sha3_384_file(&payload).unwrap(),
            payload_path: payload,
            ..Default::default()
        };
        f.store
            .install_batch(
                std::slice::from_ref(&pending),
                &SignatureEnvelope::default(),
                &tools,
            )
            .unwrap();
        let report = f
            .store
            .install_batch(&[pending], &SignatureEnvelope::default(), &tools)
            .unwrap();
        assert!(report.noop, "same name+revision+sha3 → no-op");
        assert_eq!(report.generation, None);
        assert_eq!(f.store.generations().unwrap().len(), 1);
    }

    #[test]
    fn reinstall_changed_payload_replaces_tree_without_collision() {
        // A changed revision must REPLACE the carried tree, not
        // hardlink over it: carry-forward of the old tree onto the
        // freshly staged new one used to fail with "File exists"
        // (observed via the pod sync path, issue #3).
        let work = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        let Some(payload_a) = pack_payload_with(&work.path().join("a"), "exec true") else {
            return; // gated
        };
        let Some(payload_b) = pack_payload_with(&work.path().join("b"), "exec false") else {
            return;
        };
        let Some(tools) = gated_tools(work.path()) else {
            return;
        };
        let f = fixture();
        let make_pending = |p: &Path| PendingSnap {
            name: "my-snap".into(),
            revision: 7,
            sha3_384: sha3_384_file(p).unwrap(),
            payload_path: p.to_path_buf(),
            ..Default::default()
        };
        f.store
            .install_batch(
                &[make_pending(&payload_a)],
                &SignatureEnvelope::default(),
                &tools,
            )
            .unwrap();

        let report = f
            .store
            .install_batch(
                &[make_pending(&payload_b)],
                &SignatureEnvelope::default(),
                &tools,
            )
            .unwrap();
        assert!(!report.noop, "changed sha3 is a real install");
        assert_eq!(report.generation, Some(2));
        assert_eq!(f.store.generations().unwrap().len(), 2);

        // The new generation's tree carries the NEW content only.
        let renamed = f
            .store
            .generation_dir(2)
            .join("extensions/my-snap/usr/bin/my-snap-srv");
        let content = std::fs::read_to_string(&renamed).unwrap();
        assert!(
            content.contains("exec false"),
            "generation 2 tree must carry the changed content, got: {content}"
        );
        let gen = f.store.active_generation().unwrap().unwrap();
        assert_eq!(
            gen.packages["my-snap"].sha3_384,
            sha3_384_file(&payload_b).unwrap(),
            "manifest pins the new content address"
        );
    }

    #[test]
    fn install_infrastructure_payload_is_refused() {
        let work = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        if !has_tool("unsquashfs") || !has_tool("mksquashfs") {
            eprintln!("skipping: unsquashfs/mksquashfs unavailable");
            return;
        }
        let tree = work.path().join("tree");
        std::fs::create_dir_all(tree.join("meta")).unwrap();
        std::fs::write(
            tree.join("meta/snap.yaml"),
            "name: core22\ntype: base\nversion: '1.0'\n",
        )
        .unwrap();
        let payload = work.path().join("core22_1_abc.snap");
        let status = std::process::Command::new("mksquashfs")
            .arg(&tree)
            .arg(&payload)
            .arg("-noappend")
            .arg("-all-root")
            .output()
            .unwrap();
        assert!(status.status.success());
        let f = fixture();
        let tools = RuntimeTools {
            unsquashfs: find_on_path("unsquashfs"),
            ..RuntimeTools::default()
        };
        let pending = PendingSnap {
            name: "core22".into(),
            revision: 1,
            sha3_384: sha3_384_file(&payload).unwrap(),
            payload_path: payload,
            ..Default::default()
        };
        let err = f
            .store
            .install_batch(&[pending], &SignatureEnvelope::default(), &tools)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("systemd-sysupdate"),
            "base-axis refusal must be named: {err:#}"
        );
    }

    // ── Install → remove → rollback E2E (gated) ──

    #[test]
    fn install_remove_rollback_relinks_and_reconciles_units() {
        let work = match tempfile::tempdir() {
            Ok(d) => d,
            Err(_) => return,
        };
        let Some(payload) = pack_payload(work.path()) else {
            return; // gated
        };
        let Some(tools) = gated_tools(work.path()) else {
            return;
        };
        let f = fixture();
        let pending = PendingSnap {
            name: "my-snap".into(),
            revision: 7,
            sha3_384: sha3_384_file(&payload).unwrap(),
            payload_path: payload,
            ..Default::default()
        };
        f.store
            .install_batch(&[pending], &SignatureEnvelope::default(), &tools)
            .unwrap();

        // Remove: generation 2 without the package; link gone; blobs
        // and generation 1 kept (generations are cheap; blobs free on gc).
        let remove_report = f.store.remove("my-snap", &tools).unwrap();
        assert_eq!(remove_report.generation, 2);
        assert_eq!(
            remove_report.stopped,
            vec!["my-snap-srv.service".to_string()]
        );
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 2);
        assert!(!f.links.path().join("my-snap").exists(), "link deactivated");
        assert!(f.store.generation_dir(1).exists(), "old generation kept");
        let gen1_files = f
            .store
            .generations()
            .unwrap()
            .into_iter()
            .find(|g| g.n == 1)
            .unwrap()
            .packages
            .get("my-snap")
            .unwrap()
            .files
            .clone();
        for hash in &gen1_files {
            assert!(
                f.store.blob_path(hash).exists(),
                "remove never sweeps blobs"
            );
        }

        // Rollback (default: previous) → generation 1, link restored.
        let rb = f.store.rollback(None, &tools).unwrap();
        assert_eq!(rb.from, 2);
        assert_eq!(rb.to, 1);
        assert_eq!(rb.started, vec!["my-snap-srv.service".to_string()]);
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 1);
        assert!(f.links.path().join("my-snap").exists(), "link reactivated");

        // Removing a package that is not installed is a named error and
        // creates no generation.
        let err = f.store.remove("ghost", &tools).unwrap_err();
        assert!(
            format!("{err:#}").contains("'ghost' is not installed"),
            "named error: {err:#}"
        );
        assert_eq!(f.store.generations().unwrap().len(), 2);
    }

    // ── Rollback (hermetic, seeded generations) ──

    #[test]
    fn rollback_default_previous_and_base_version_warning() {
        let f = fixture();
        let mut gen2 = BTreeMap::new();
        gen2.insert("app".into(), pkg("app", &[], vec![]));
        gen2.insert("extra".into(), pkg("extra", &["extra-srv.service"], vec![]));
        seed_generation(&f.store, 1, one_pkg_map(pkg("app", &[], vec![])));
        seed_generation(&f.store, 2, gen2);
        seed_tree(&f.store, 1, "app");
        seed_tree(&f.store, 2, "app");
        seed_tree(&f.store, 2, "extra");
        f.store.flip_active(2).unwrap();
        // Simulate differing base: gen1 manifest carries another base.
        let manifest = f.store.generation_dir(1).join("manifest.json");
        let text = std::fs::read_to_string(&manifest)
            .unwrap()
            .replace("24.04", "22.04");
        std::fs::write(&manifest, text).unwrap();

        let tools = RuntimeTools::default(); // everything absent → warn path
        let rb = f.store.rollback(None, &tools).unwrap();
        assert_eq!(rb.from, 2);
        assert_eq!(rb.to, 1);
        assert_eq!(rb.stopped, vec!["extra-srv.service".to_string()]);
        assert!(rb.started.is_empty());
        assert_eq!(f.store.active_generation().unwrap().unwrap().n, 1);
        assert!(
            rb.notes
                .iter()
                .any(|n| n.contains("reboot to complete base rollback")),
            "base difference must warn: {:?}",
            rb.notes
        );
        // Link set follows the target generation.
        assert!(f.links.path().join("app").exists());
        assert!(!f.links.path().join("extra").exists(), "stale link removed");

        // Rolling back to a nonexistent generation is a named error.
        let err = f.store.rollback(Some(9), &tools).unwrap_err();
        assert!(
            format!("{err:#}").contains("generation 9 does not exist"),
            "named error: {err:#}"
        );
        // Rolling back with no previous below the active generation is
        // a named error (gen 2 is ABOVE active gen 1 — not a candidate).
        let err = f.store.rollback(None, &tools).unwrap_err();
        assert!(
            format!("{err:#}").contains("no previous generation below 1"),
            "named error: {err:#}"
        );
    }

    // ── Activation: skipped tools vs failed tools (issue #66) ──

    /// `activate` with every system-bus tool absent reports the skips
    /// distinctly from a tool that ran and failed: the notes say
    /// "skipped", and no fake tool is ever executed.
    #[test]
    fn activate_without_tools_reports_skips_not_failures() {
        let f = fixture();
        seed_generation(&f.store, 1, BTreeMap::new());
        let report = f.store.activate(1, &RuntimeTools::default()).unwrap();
        assert_eq!(report.skipped, 2, "sysext refresh + daemon-reload skipped");
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("systemd-sysext refresh: skipped")),
            "sysext skip must be named: {:?}",
            report.notes
        );
        assert!(
            report.notes.iter().all(|n| !n.contains("exited")),
            "absent tools must never look like failures: {:?}",
            report.notes
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("system bus not in use")),
            "the no-op must be visible as a skip: {:?}",
            report.notes
        );
    }

    /// A tool that runs and FAILS is reported as a failure, not a skip —
    /// the distinction the issue asks for. Exit 3 is not success.
    #[test]
    fn activate_with_failing_tool_reports_failure_not_skip() {
        let work = tempfile::tempdir().unwrap();
        let fail: PathBuf = work.path().join("fail-tool");
        std::fs::write(&fail, "#!/bin/sh\nexit 3\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fail, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tools = RuntimeTools {
            systemd_sysext: Some(fail.clone()),
            systemctl: Some(fail),
            ..RuntimeTools::default()
        };
        let f = fixture();
        seed_generation(&f.store, 1, BTreeMap::new());
        let report = f.store.activate(1, &tools).unwrap();
        assert_eq!(report.skipped, 0, "a failing tool RAN, it was not skipped");
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("systemd-sysext refresh: exited")),
            "failure must be named: {:?}",
            report.notes
        );
        assert!(
            report.notes.iter().all(|n| !n.contains("skipped")),
            "a run tool must never be reported as skipped: {:?}",
            report.notes
        );
    }

    /// The test-aware constructor suppresses every system-bus tool while
    /// keeping the unpacker, so tests can never reach the host bus.
    #[test]
    fn for_pod_runtime_suppresses_systemd_tools_only() {
        let tools = RuntimeTools {
            unsquashfs: Some(PathBuf::from("/fake/unsquashfs")),
            systemd_sysext: Some(PathBuf::from("/fake/systemd-sysext")),
            systemctl: Some(PathBuf::from("/fake/systemctl")),
            bootctl: Some(PathBuf::from("/fake/bootctl")),
        }
        .without_systemd();
        assert_eq!(tools.unsquashfs, Some(PathBuf::from("/fake/unsquashfs")));
        assert_eq!(tools.systemd_sysext, None);
        assert_eq!(tools.systemctl, None);
        assert_eq!(tools.bootctl, None);
    }

    // ── GC ──

    #[test]
    fn gc_sweeps_unreferenced_keeps_referenced() {
        let f = fixture();
        let mut g1 = BTreeMap::new();
        g1.insert("a".into(), pkg("a", &[], vec![H1.into()]));
        let mut g3 = BTreeMap::new();
        g3.insert("c".into(), pkg("c", &[], vec![H2.into(), H3.into()]));
        seed_generation(&f.store, 1, g1);
        seed_generation(&f.store, 3, g3);
        f.store.flip_active(3).unwrap();
        for h in [H1, H2, H3, ORPHAN] {
            seed_blob(&f.store, h, 10);
        }

        let report = f.store.gc(false).unwrap();
        assert_eq!(report.blobs_removed, 1, "only the orphan swept");
        assert_eq!(report.bytes_reclaimed, 10);
        assert!(report.generations_removed.is_empty());
        for h in [H1, H2, H3] {
            assert!(f.store.blob_path(h).exists(), "referenced blob kept");
        }
        assert!(!f.store.blob_path(ORPHAN).exists());
        assert_eq!(f.store.generations().unwrap().len(), 2, "generations kept");
    }

    #[test]
    fn gc_prune_drops_old_generations_then_sweeps() {
        let f = fixture();
        let mut g1 = BTreeMap::new();
        g1.insert("a".into(), pkg("a", &[], vec![H1.into()]));
        let mut g2 = BTreeMap::new();
        g2.insert("b".into(), pkg("b", &[], vec![H2.into()]));
        let mut g3 = BTreeMap::new();
        g3.insert("c".into(), pkg("c", &[], vec![H3.into()]));
        seed_generation(&f.store, 1, g1);
        seed_generation(&f.store, 2, g2);
        seed_generation(&f.store, 3, g3);
        f.store.flip_active(3).unwrap();
        for h in [H1, H2, H3] {
            seed_blob(&f.store, h, 10);
        }

        let report = f.store.gc(true).unwrap();
        // Keep = active (3) + previous (2); generation 1 dropped first so
        // its exclusive blob frees.
        assert_eq!(report.generations_removed, vec![1]);
        assert_eq!(report.blobs_removed, 1, "H1 swept, H2+H3 kept");
        assert_eq!(report.bytes_reclaimed, 10);
        assert!(!f.store.blob_path(H1).exists());
        assert!(f.store.blob_path(H2).exists());
        assert!(f.store.blob_path(H3).exists());
        assert!(!f.store.generation_dir(1).exists(), "generation 1 dropped");
    }

    #[test]
    fn gc_prune_without_active_generation_is_refused() {
        let f = fixture();
        let err = f.store.gc(true).unwrap_err();
        assert!(
            format!("{err:#}").contains("no active generation"),
            "refusal must be named: {err:#}"
        );
    }

    // ── Pure helpers ──

    #[test]
    fn reconcile_units_computes_the_set_difference() {
        let mut from = BTreeMap::new();
        from.insert(
            "a".into(),
            pkg("a", &["a-srv.service", "shared.service"], vec![]),
        );
        from.insert("b".into(), pkg("b", &["b-srv.service"], vec![]));
        let mut to = BTreeMap::new();
        to.insert("a".into(), pkg("a", &["shared.service"], vec![]));
        to.insert("c".into(), pkg("c", &["c-srv.service"], vec![]));
        let (started, stopped) = reconcile_units(&from, &to);
        assert_eq!(started, vec!["c-srv.service".to_string()]);
        assert_eq!(
            stopped,
            vec!["a-srv.service".to_string(), "b-srv.service".to_string()]
        );
    }

    #[test]
    fn changed_pins_detects_new_and_changed_snaps_only() {
        let mut installed = BTreeMap::new();
        installed.insert(
            "same".into(),
            InstalledPackage {
                name: "same".into(),
                version: "1".into(),
                revision: 5,
                sha3_384: "aaa".into(),
                files: vec![],
                units: vec![],
                layer: crate::farm::ClaimLayer::Own,
                apps: BTreeMap::new(),
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
            },
        );
        installed.insert(
            "changed".into(),
            InstalledPackage {
                name: "changed".into(),
                version: "1".into(),
                revision: 5,
                sha3_384: "bbb".into(),
                files: vec![],
                units: vec![],
                layer: crate::farm::ClaimLayer::Own,
                apps: BTreeMap::new(),
                launchers: BTreeMap::new(),
                assembly: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
            },
        );
        let resolved = vec![
            ("same".to_string(), 5, "aaa".to_string()),
            ("changed".to_string(), 6, "bbb".to_string()), // new revision
            ("hashchanged".to_string(), 5, "zzz".to_string()),
            ("brand-new".to_string(), 1, "ccc".to_string()),
        ];
        let changed = changed_pins(&resolved, &installed);
        assert_eq!(
            changed,
            vec![
                "changed".to_string(),
                "hashchanged".to_string(),
                "brand-new".to_string()
            ]
        );
    }

    // ── Sibling assembly recording (issue #37) ──

    #[test]
    fn sibling_assembly_captures_payload_content_beside_the_binary() {
        let entries = vec![
            TreeEntry::Blob {
                rel: "usr/bin/pi".into(),
                sha256: "h1".into(),
            },
            TreeEntry::Blob {
                rel: "usr/bin/package.json".into(),
                sha256: "h2".into(),
            },
            TreeEntry::Blob {
                rel: "usr/bin/theme/now.txt".into(),
                sha256: "h3".into(),
            },
            TreeEntry::Symlink {
                rel: "usr/bin/export-html".into(),
                target: "theme/export-html".into(),
            },
            // Not beside the binary: stays out of the assembly.
            TreeEntry::Blob {
                rel: "usr/share/doc/readme".into(),
                sha256: "h4".into(),
            },
            TreeEntry::Blob {
                rel: "bin/other".into(),
                sha256: "h5".into(),
            },
        ];
        let asm = sibling_assembly(&entries, "usr/bin/pi");
        assert_eq!(asm.binary, "usr/bin/pi");
        assert_eq!(
            asm.files,
            [
                ("package.json".to_string(), "h2".to_string()),
                ("theme/now.txt".to_string(), "h3".to_string()),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>()
        );
        assert_eq!(
            asm.links,
            [("export-html".to_string(), "theme/export-html".to_string())]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        );
        assert!(!asm.is_empty());
    }

    #[test]
    fn sibling_assembly_is_empty_for_a_lone_binary_payload() {
        let entries = vec![
            TreeEntry::Blob {
                rel: "usr/bin/rg".into(),
                sha256: "h1".into(),
            },
            TreeEntry::Blob {
                rel: "usr/share/man/rg.1".into(),
                sha256: "h2".into(),
            },
        ];
        let asm = sibling_assembly(&entries, "usr/bin/rg");
        assert!(asm.is_empty());
        assert_eq!(asm.binary, "usr/bin/rg");
    }

    #[test]
    fn sibling_assembly_skips_wrapper_managed_commands() {
        // Issues #9/#10/#13: the command path was replaced by a
        // build-time wrapper, the real entry preserved at the `.real`
        // sibling. The wrapper derives its own paths from the command's
        // STORE blob location, so the command must keep the bare store
        // link — no assembly.
        let entries = vec![
            TreeEntry::Blob {
                rel: "bin/pytool".into(),
                sha256: "wrapper".into(),
            },
            TreeEntry::Blob {
                rel: "bin/pytool.real".into(),
                sha256: "script".into(),
            },
        ];
        let asm = sibling_assembly(&entries, "bin/pytool");
        assert!(asm.is_empty());
        // The extension-inserting variant (`cli.js` → `cli.real.js`).
        let entries = vec![
            TreeEntry::Blob {
                rel: "bin/cli.js".into(),
                sha256: "wrapper".into(),
            },
            TreeEntry::Blob {
                rel: "bin/cli.real.js".into(),
                sha256: "script".into(),
            },
        ];
        let asm = sibling_assembly(&entries, "bin/cli.js");
        assert!(asm.is_empty());
    }

    // ── Signature verify hook ──

    #[test]
    fn unsigned_envelope_proceeds_with_none() {
        let sigs = BTreeMap::new();
        assert_eq!(
            verify_signatures_at(b"x", &sigs, Path::new("/nope"), Path::new("/nope")).unwrap(),
            None
        );
    }

    #[test]
    fn signed_without_anchors_fails_closed() {
        let mut sigs = BTreeMap::new();
        sigs.insert(
            "deadbeef00112233".to_string(),
            serde_json::Value::String("not-a-real-signature".into()),
        );
        let err =
            verify_signatures_at(b"x", &sigs, Path::new("/nope"), Path::new("/nope")).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted anchor verifies"),
            "fail-closed error must be named: {err:#}"
        );
    }

    #[test]
    fn signed_manifest_verifies_under_the_keychain() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        crate::sign::install_public_key(&kp, &keys).unwrap();
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &kp).unwrap();
        let canonical = crate::sign::canonical_bytes(&manifest).unwrap();
        let verified = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            Path::new("/definitely/not/here"),
            &keys,
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));
    }

    /// A minimal manifest signed by `kp`.
    fn manifest_signed_by(
        kp: &crate::sign::KeyPair,
    ) -> (Vec<u8>, BTreeMap<String, serde_json::Value>) {
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, kp).unwrap();
        let canonical = crate::sign::canonical_bytes(&manifest).unwrap();
        (canonical, manifest.signatures)
    }

    #[test]
    fn device_trust_set_accepts_an_embedded_anchor() {
        let home = tempfile::tempdir().unwrap();
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        // The image-embedded shape: anchor dir beside update-key.pub.
        let anchor_dir = home.path().join("etc/shuttle");
        crate::sign::install_public_key(&kp, &anchor_dir.join("trusted-keys")).unwrap();
        let (canonical, sigs) = manifest_signed_by(&kp);
        let verified = verify_signatures_at(
            &canonical,
            &sigs,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));
    }

    #[test]
    fn device_revocation_list_refuses_a_revoked_signer() {
        let home = tempfile::tempdir().unwrap();
        let revoked = crate::sign::create_secret_key(home.path()).unwrap();
        let anchor_dir = home.path().join("etc/shuttle");
        crate::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
        // The device carries the revocation list beside the anchor.
        std::fs::write(
            anchor_dir.join("revoked-keys"),
            format!("{}\n", revoked.key_id()),
        )
        .unwrap();

        let (canonical, sigs) = manifest_signed_by(&revoked);
        let err = verify_signatures_at(
            &canonical,
            &sigs,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&revoked.key_id()),
            "revoked signer refused by id: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("REVOKED"),
            "refusal is explicit: {err:#}"
        );
    }

    #[test]
    fn device_revocation_refuses_even_when_a_trusted_key_also_signed() {
        let home = tempfile::tempdir().unwrap();
        let revoked = crate::sign::create_secret_key(home.path()).unwrap();
        let trusted = crate::sign::create_secret_key(&home.path().join("other")).unwrap();
        let anchor_dir = home.path().join("etc/shuttle");
        crate::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
        crate::sign::install_public_key(&trusted, &anchor_dir.join("trusted-keys")).unwrap();
        std::fs::write(
            anchor_dir.join("revoked-keys"),
            format!("{}\n", revoked.key_id()),
        )
        .unwrap();

        // Dual-signed: revoked + trusted. The trusted signature alone
        // would verify — revocation must still refuse.
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &revoked).unwrap();
        crate::sign::cosign(&mut manifest, &trusted).unwrap();
        let canonical = crate::sign::canonical_bytes(&manifest).unwrap();
        let err = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&revoked.key_id()),
            "revoked signer wins over the trusted co-signer: {err:#}"
        );
    }
}
