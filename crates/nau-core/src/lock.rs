use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::snap_types::SnapRef;

/// A lockfile captures resolved hashes of all build inputs for reproducibility.
///
/// On first build: creates `nau.lock` with SHA-256 of every downloaded source
/// and sha3-384 of every pinned snap.
/// On subsequent builds: lockfile entries pin inputs even if the DSL only
/// specified names/channels.
///
/// Analogous to: Cargo.lock, yarn.lock, flake.lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    pub version: u32,

    /// Sources keyed by URL. Each entry records the SHA-256 that was
    /// observed when first downloaded.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub sources: HashMap<String, SourceLockEntry>,

    /// Snaps keyed by name. Each entry records the exact revision and
    /// sha3-384 that was observed when first resolved.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub snaps: HashMap<String, SnapLockEntry>,

    /// Package inputs keyed by input name. Each entry pins the input to the
    /// exact revision (git commit SHA) observed at lock time. `path:` inputs
    /// are recorded as local and never pinned.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub inputs: HashMap<String, InputLockEntry>,

    /// Pod package pins (pods, issue #2). Per-pod lockfiles live in the
    /// pod state directory and record the resolved version of every
    /// declared package, keyed by package name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub packages: HashMap<String, PodPackageLockEntry>,

    /// Build-dependency pins (ADR-0018 Decision 4, issue #22). Each entry
    /// pins a build-time-only dependency to the resolved version observed
    /// at lock time, so a changed build_dep is recorded and reproducible.
    /// The lockfile IS the pin record (ADR-0017 Decision 5).
    #[serde(default, skip_serializing_if = "is_empty_build_deps")]
    pub build_deps: HashMap<String, BuildDepsLockEntry>,
}

/// A single source entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLockEntry {
    pub sha256: String,

    /// The HTTP validator (ETag) the server returned for the response the
    /// `sha256` was observed in, verbatim as received (quoted form
    /// included, never normalized). Present only when a fetch captured it;
    /// drives the conditional drift probe of floating sources (the 304
    /// plan): a 304 under this etag certifies `sha256` unchanged. Co-write
    /// invariant: patched only by the same write that (re)sets `sha256` —
    /// never independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,

    /// Unix epoch seconds of the last FULL (status 200) fetch of the
    /// source — the freshness anchor of the conditional probe's TTL. A
    /// 304 never touches it. Co-write invariant: patched only by the same
    /// write that (re)sets `sha256`, or by a validation refresh that
    /// re-certifies the recorded `sha256` unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated_at: Option<u64>,
}

/// How long a recorded source validator ([`SourceLockEntry::etag`] plus
/// [`SourceLockEntry::validated_at`]) may drive conditional 304 probes
/// before a full GET must re-anchor it. Bounds etag rot (a CDN whose etag
/// outlives its content) and, with it, how long a 304 short-circuit can
/// stand in for a real re-resolve.
pub const VALIDATOR_TTL_SECS: u64 = 7 * 24 * 3600;

/// The conditional-GET validator pair a previous full fetch recorded for
/// a source: the etag verbatim, paired with the sha256 observed in the
/// SAME response — so a 304 under this etag certifies `recorded_sha256`
/// unchanged without downloading a byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceValidators {
    pub etag: String,
    pub recorded_sha256: String,
}

impl SourceLockEntry {
    /// The probe validators this entry can offer at `now`, or `None` when
    /// the entry carries no etag, only a weak one (`W/` prefix — never
    /// probed against), or its validation stamp is older than
    /// [`VALIDATOR_TTL_SECS`] (a full GET must re-anchor it).
    pub fn validators(&self, now: u64) -> Option<SourceValidators> {
        let etag = self.etag.as_deref()?;
        if etag.starts_with("W/") {
            return None;
        }
        let validated_at = self.validated_at?;
        if now.saturating_sub(validated_at) > VALIDATOR_TTL_SECS {
            return None;
        }
        Some(SourceValidators {
            etag: etag.to_string(),
            recorded_sha256: self.sha256.clone(),
        })
    }
}

/// Unix epoch seconds for the current instant (no chrono dependency —
/// the same source [`crate::lock`]'s `validated_at` stamps use).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A single package-input entry in the lockfile.
///
/// `github:` inputs carry `revision` (resolved branch-head commit SHA) and
/// `sha256` (content hash of the input tree). `path:` inputs only carry
/// `local = true` — they are resolved from the filesystem and unlocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputLockEntry {
    /// Resolved git commit SHA of the branch head at lock time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// SHA-256 over the input's content tree (excluding `.git`) at lock time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// True for `path:` inputs — always resolved from the local filesystem.
    #[serde(default, skip_serializing_if = "is_false")]
    pub local: bool,

    /// Submodule pins (issue #43): `.gitmodules` name → resolved commit,
    /// materialization path, and content hash, all observed at lock time
    /// under the parent's pinned revision. Present only for inputs
    /// declared with `submodules`; absent (default) for every other entry,
    /// so pre-#43 lockfiles load unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submodules: Option<HashMap<String, SubmoduleLockEntry>>,
}

/// One pinned submodule of a git input (issue #43): the commit the
/// parent's pinned revision records for it (its gitlink), where it
/// materializes inside the parent tree, and the content hash of its tree
/// at lock time — verified on every resolution, named on mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmoduleLockEntry {
    /// Path within the parent tree (from `.gitmodules`) where the
    /// submodule materializes (e.g. "vendor/mylib").
    pub path: String,

    /// Resolved git commit SHA of the submodule at the parent's pin.
    pub revision: String,

    /// SHA-256 over the submodule's content tree (excluding `.git`).
    pub sha256: String,
}

/// `skip_serializing_if` helper: omit `local = false` from the lockfile.
fn is_false(b: &bool) -> bool {
    !*b
}

/// `skip_serializing_if` helper: omit an empty `build_deps` map from older
/// lockfiles (backcompat with pre-ADR-0018 lockfiles).
fn is_empty_build_deps(m: &HashMap<String, BuildDepsLockEntry>) -> bool {
    m.is_empty()
}

/// Copy the entries `other` holds and `target` lacks. The target's own
/// entry wins where both have one.
fn fill_gaps<K, V>(target: &mut HashMap<K, V>, other: &HashMap<K, V>)
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    for (key, value) in other {
        target.entry(key.clone()).or_insert_with(|| value.clone());
    }
}

/// A single build-dependency pin (ADR-0018 Decision 4, issue #22): the
/// resolved version observed when the dependency first entered the build
/// closure, plus the optional content hash when the lockfile has it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDepsLockEntry {
    /// Resolved version (declared version or lockfile pin) of the
    /// build-time-only dependency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,

    /// Content hash (sha3-384) when recorded by a prior lock/snap pin;
    /// `None` for a pure declared-version pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// The resolved-pin shape [`LockFile::record_build_dep`] records — the
/// build_deps member of a `nau.lock` entry.
pub struct BuildDepPin {
    pub pin: Option<String>,
    pub hash: Option<String>,
}

/// A pod package pin (pods, issue #2): the resolved version observed when
/// the package was added to a pod, plus the declared constraint (if any).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodPackageLockEntry {
    /// Resolved package version (from the package declaration).
    pub version: String,

    /// Version constraint from the declaration (`name@constraint`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,

    /// Dependency-closure pin (ADR-0017, issue #13): the content hash of
    /// the fetched interpreted-package dependency closure (npm/pip) and
    /// the date it was last (re-)fetched. Absent for packages without a
    /// `deps` declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deps: Option<PackageDepsLock>,

    /// Recipe pin (issues #142 + #172): SHA-256 over the canonical,
    /// sorted list of `(member_name, recipe_file_bytes)` covering the
    /// package's OWN recipe plus its recipe-resolved `requires` closure
    /// (v2 scheme — see [`Self::recipe_digest_scheme`]) — the members
    /// reconcile builds from collection recipes (blob-pinned sideloads
    /// excluded). Sync compares it to detect recipe drift at an
    /// unchanged version pin and rebuilds the affected package.
    /// Absent from pre-#142 lockfiles, which load unchanged and are
    /// stamped on the next sync without a rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe_sha256: Option<String>,

    /// Digest-scheme marker for [`Self::recipe_sha256`] (issue #172):
    /// `2` once the digest covers the package's OWN recipe bytes plus
    /// its requires closure. Absent → the #142 v1 scheme (closure only)
    /// or a pre-#142 lockfile: the first sync under the v2 scheme
    /// re-stamps WITHOUT a rebuild (the migration clause) — own-recipe
    /// drift predating that stamp is unrecoverable; `pod refresh
    /// <member>` rebuilds a member from its current recipe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipe_digest_scheme: Option<u32>,
}

/// The dependency-closure pin for one pod package (ADR-0017, issue #13).
///
/// `deps_hash` is the SHA-256 of the canonical archive of the materialized
/// dependency tree (sorted paths + contents — the NAR-style digest). The
/// pod store holds the closure as one content-addressed blob named by this
/// hash; the sandbox build verifies the blob against it before mounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageDepsLock {
    /// SHA-256 (hex) of the canonical closure archive = the store blob name.
    pub deps_hash: String,

    /// Date of the last content-changing fetch (`YYYY-MM-DD`). Float-mode
    /// bookkeeping: kept stable across fetches that resolve to the same
    /// content, updated when a floating re-fetch moves the closure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,

    /// SHA-256 (hex) of the lockfile bytes when the closure's lock resolved
    /// from the package recipe directory (`recipe/` lock path): the audit
    /// trail binding the pin to the exact recipe-shipped lockfile. `None`
    /// when every lock resolved from the fetched source tree (the default
    /// contract), so existing pod lockfiles keep their shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_sha256: Option<String>,
}

/// A single snap entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapLockEntry {
    pub revision: u32,
    #[serde(rename = "sha3-384")]
    pub sha3_384: String,
}

impl LockFile {
    /// Default lockfile filename.
    pub const FILENAME: &'static str = "nau.lock";

    /// A fresh, empty lockfile at the current format version.
    pub fn empty() -> Self {
        LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        }
    }

    /// Fill this lockfile's gaps from `other`: every map keeps this
    /// file's entry when it has one and takes `other`'s entry when it
    /// does not. The caller decides which file is which.
    ///
    /// A pod can carry two lockfiles, the canonical name and the
    /// pre-rename one, and the canonical file is not necessarily the
    /// complete record: a writer that had already learned the new name
    /// but still read the old one started from an empty lock and saved
    /// only the packages it had touched. Taking either file whole drops
    /// the pins the other one holds (issue #20).
    ///
    /// Every map in [`LockFile`] is merged here. A map added to the
    /// struct later must be added here too, or its entries are dropped
    /// silently.
    pub fn merge_missing_from(&mut self, other: &LockFile) {
        fill_gaps(&mut self.sources, &other.sources);
        fill_gaps(&mut self.snaps, &other.snaps);
        fill_gaps(&mut self.inputs, &other.inputs);
        fill_gaps(&mut self.packages, &other.packages);
        fill_gaps(&mut self.build_deps, &other.build_deps);
    }

    /// Load lockfile from disk. Returns `None` if the file doesn't exist.
    pub fn load(path: &Path) -> miette::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| miette::miette!("failed to read {}: {}", path.display(), e))?;
        let lock: LockFile = serde_json::from_str(&content)
            .map_err(|e| miette::miette!("invalid lockfile at {}: {}", path.display(), e))?;
        Ok(Some(lock))
    }

    /// Save lockfile to disk atomically: serialize to a temp file in the
    /// target's directory, then rename over the target. A crash or failure
    /// mid-write leaves the previous lockfile intact — readers never see a
    /// half-written file.
    pub fn save(&self, path: &Path) -> miette::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("failed to serialize lockfile: {}", e))?;
        let content = content + "\n";
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("nau.lock"),
            std::process::id()
        ));
        let cleanup = |tmp: &Path| {
            let _ = std::fs::remove_file(tmp);
        };
        if let Err(e) = std::fs::write(&tmp, &content) {
            cleanup(&tmp);
            return Err(miette::miette!("failed to write {}: {}", tmp.display(), e));
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            cleanup(&tmp);
            return Err(miette::miette!(
                "failed to finalize {}: {}",
                path.display(),
                e
            ));
        }
        Ok(())
    }

    /// Look up a source URL in the lockfile and return its pinned SHA-256.
    pub fn lookup_source(&self, url: &str) -> Option<&str> {
        self.sources.get(url).map(|e| e.sha256.as_str())
    }

    /// Look up a snap name in the lockfile and return its pinned revision
    /// and sha3-384 as a `SnapRef`.
    pub fn lookup_snap(&self, name: &str) -> Option<SnapRef> {
        self.snaps.get(name).map(|e| SnapRef {
            name: name.to_string(),
            revision: Some(e.revision),
            sha3_384: Some(e.sha3_384.clone()),
        })
    }

    /// Record a resolved snap in the lockfile (if not already present).
    pub fn record_snap(&mut self, snap: &SnapRef) {
        if let (Some(rev), Some(hash)) = (snap.revision, &snap.sha3_384) {
            self.snaps
                .entry(snap.name.clone())
                .or_insert(SnapLockEntry {
                    revision: rev,
                    sha3_384: hash.clone(),
                });
        }
    }

    /// Look up a build-dep pin by name (ADR-0018 Decision 4, issue #22).
    pub fn lookup_build_dep(&self, name: &str) -> Option<&BuildDepsLockEntry> {
        self.build_deps.get(name)
    }

    /// Record a build-dep pin in the lockfile (ADR-0018 Decision 4). A
    /// first observation records whatever `pin`/`hash` are known; a pin
    /// already present is left untouched (record-once, like sources).
    pub fn record_build_dep(&mut self, name: &str, pin: &BuildDepPin) {
        self.build_deps
            .entry(name.to_string())
            .or_insert(BuildDepsLockEntry {
                pin: pin.pin.clone(),
                hash: pin.hash.clone(),
            });
    }
}

// ── Requires-member projection (issue #326) ──

/// Resolve a requires member from lockfile data only (no I/O, safe offline).
/// Returns `None` when the snap has no lock pin — the caller falls back to
/// declared-version pinning with `hash: None`.
///
/// Lives beside the lockfile vocabulary it reads (moved from the root
/// `cache.rs`, issue #326); the root `cache` module re-exports it so the
/// build path keeps resolving.
pub fn pinned_member(name: &str, lock: &LockFile) -> Option<crate::cache_key::RequiresMember> {
    lock.snaps
        .get(name)
        .map(|snap| crate::cache_key::RequiresMember {
            name: name.to_string(),
            pin: Some(snap.revision.to_string()),
            hash: Some(snap.sha3_384.clone()),
        })
}

#[cfg(test)]
mod tests;
