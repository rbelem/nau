//! Binary package cache — store and retrieve built `.snap` files by
//! build-input closure hash.
//!
//! The cache lives at `~/.cache/shuttle/pkgs/` (configurable via `--cache`).
//! Each cached snap is stored as:
//!
//! ```text
//! <cache_dir>/v2:<closure_sha256>/<name>_<version>_<arch>.snap
//! ```
//!
//! The directory key is `v2:` + SHA-256 over the canonical build-input
//! closure ([`BuildClosure`]): source identity, parts spec, cross-compilation
//! target, and the resolved `requires` closure. Any change to any of these
//! changes the key and forces a fresh build (gap-analysis §4.3: the cache is
//! keyed by the full input closure, not just the source tarball). The `v2:`
//! prefix version-bumps deliberately: keys from the old source-only format
//! simply miss once and rebuild — an accepted one-time cold-cache break.
//! Meta/store packages (closure source `none`) are never cached.
//!
//! Usage:
//! ```rust,ignore
//! let cache = PackageCache::new(Some("/path/to/cache"));
//! let closure = BuildClosure::for_meta(&meta, requires);
//! if let Some(path) = cache.lookup(&meta, "amd64", &closure) {
//!     // use cached build
//! } else {
//!     let result = build_snap(&meta, ...)?;
//!     cache.store(&meta, &result, &result_dir, &closure)?;
//! }
//! ```

use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::snap::{BuildResult, SnapMeta, SnapPart};

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheInfo {
    pub entries: usize,
    pub packages: usize,
    pub size_bytes: u64,
    pub root: std::path::PathBuf,
}

/// Default cache directory name under `~/.cache/shuttle/`.
const DEFAULT_CACHE_SUBDIR: &str = "pkgs";

/// Magic string for packages without source (meta/store types).
const NO_SOURCE_HASH: &str = "none";

/// Closure format version and cache-key prefix. These MUST move together:
/// bump both when the closure schema changes so old entries can never be
/// served for a new format (no silent key collisions across formats).
const CLOSURE_FORMAT_VERSION: u32 = 2;
const KEY_PREFIX: &str = "v2";

/// Target value for builds without an explicit cross-compilation triplet.
const NATIVE_TARGET: &str = "native";

/// SHA-256 hex digest of a string.
fn sha256_hex(input: &str) -> String {
    let hash = sha2::Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// One member of the resolved `requires` closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiresMember {
    pub name: String,
    /// Resolved revision (lockfile pin) or declared version, when known.
    pub pin: Option<String>,
    /// Content hash of the dependency, when available from lockfile data.
    ///
    /// `None` marks an unpinned store dependency: its reproducibility is
    /// version-pinned at best — the cache key cannot detect content changes
    /// behind the version (known limitation, see `requires` in
    /// [`BuildClosure`]).
    pub hash: Option<String>,
}

/// The canonical build-input closure: every input that can change the built
/// artifact (gap-analysis §4.3, Phase 22 task 1).
///
/// Serialized to deterministic JSON (sorted keys via serde_json's BTreeMap,
/// `requires` sorted by name and deduplicated):
///
/// ```json
/// {
///   "format_version": 2,
///   "parts": "<canonical parts JSON>",
///   "requires": [{"hash": "…|null", "name": "…", "pin": "…|null"}],
///   "source": "<sha256 of name:version:url, or none>",
///   "target": "<triplet or native>"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BuildClosure {
    /// SHA-256 over `name:version:url` (`none` for meta/store packages).
    /// The tarball content hash is pinned separately in `shuttle.lock` and
    /// verified at download time, so the key never needs the download.
    pub source: String,
    /// Canonical parts JSON ([`canonical_parts_json`]); empty when no parts.
    pub parts: String,
    /// Cross-compilation target triplet, or `native`.
    pub target: String,
    /// Resolved requires closure, sorted by name, deduplicated.
    pub requires: Vec<RequiresMember>,
}

impl BuildClosure {
    /// Build the closure for a snap meta from resolved requires members.
    /// Members are sorted by name and deduplicated so dependency traversal
    /// order never affects the key.
    pub fn for_meta(meta: &SnapMeta, requires: Vec<RequiresMember>) -> Self {
        let mut requires = requires;
        requires.sort_by(|a, b| a.name.cmp(&b.name));
        requires.dedup_by(|a, b| a.name == b.name);
        let parts = meta
            .parts
            .as_ref()
            .map(canonical_parts_json)
            .unwrap_or_default();
        BuildClosure {
            source: source_identity_hash(meta),
            parts,
            target: meta
                .target
                .clone()
                .unwrap_or_else(|| NATIVE_TARGET.to_string()),
            requires,
        }
    }

    /// Deterministic canonical JSON serialization of the closure.
    pub fn canonical_json(&self) -> String {
        let requires: Vec<serde_json::Value> = self
            .requires
            .iter()
            .map(|m| serde_json::json!({ "name": m.name, "pin": m.pin, "hash": m.hash }))
            .collect();
        serde_json::json!({
            "format_version": CLOSURE_FORMAT_VERSION,
            "source": self.source,
            "parts": self.parts,
            "target": self.target,
            "requires": requires,
        })
        .to_string()
    }

    /// Version-prefixed cache key: `v2:<sha256 of canonical JSON>`.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", KEY_PREFIX, sha256_hex(&self.canonical_json()))
    }
}

/// Resolve a requires member from lockfile data only (no I/O, safe offline).
/// Returns `None` when the snap has no lock pin — the caller falls back to
/// declared-version pinning with `hash: None`.
pub fn pinned_member(name: &str, lock: &crate::lock::LockFile) -> Option<RequiresMember> {
    lock.snaps.get(name).map(|snap| RequiresMember {
        name: name.to_string(),
        pin: Some(snap.revision.to_string()),
        hash: Some(snap.sha3_384.clone()),
    })
}

/// SHA-256 over the source identity: `name:version:url` (or `none` for
/// meta/store packages). This is the source component of the closure — the
/// parts spec is hashed separately, and the downloaded tarball's content
/// hash is pinned in `shuttle.lock` and verified at download time.
fn source_identity_hash(meta: &SnapMeta) -> String {
    match meta.type_ {
        Some(ref t) if t == "source" => {
            let url = meta
                .source
                .as_ref()
                .map(|s| s.url().to_string())
                .unwrap_or_default();
            sha256_hex(&format!("{}:{}:{}", meta.name, meta.version, url))
        }
        _ => NO_SOURCE_HASH.to_string(),
    }
}

/// Canonical JSON for a parts spec, used in cache keys: parts sorted by
/// name (BTreeMap order), each with its command and `after` edges. Any
/// change to names, commands, or edges changes the key. Plugin parts
/// additionally fold in the plugin name, the plugin registry version, and
/// the canonical (sorted-key) options map, so any option change invalidates
/// the cache (ADR-0014 Decision 5). Parts without a plugin serialize exactly
/// as before — single-command specs keep byte-identical keys.
fn canonical_parts_json(parts: &std::collections::BTreeMap<String, SnapPart>) -> String {
    let items: Vec<serde_json::Value> = parts
        .iter()
        .map(|(name, part)| {
            let mut obj =
                serde_json::json!({ "name": name, "build": part.build, "after": part.after });
            if let Some(plugin) = &part.plugin {
                obj["plugin"] = serde_json::Value::String(plugin.clone());
                obj["plugin_version"] =
                    serde_json::Value::String(crate::plugins::REGISTRY_VERSION.to_string());
                if let Some(options) = &part.plugin_options {
                    obj["options"] = serde_json::Value::Object(
                        options
                            .iter()
                            .map(|(key, value)| (key.clone(), value.to_json()))
                            .collect(),
                    );
                }
            }
            obj
        })
        .collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "unserializable".to_string())
}

/// Binary package cache for built snaps.
#[derive(Debug, Clone)]
pub struct PackageCache {
    root: PathBuf,
    /// Maximum cache size in bytes. When exceeded, oldest entries are pruned
    /// automatically on store. `None` means unlimited.
    max_size: Option<u64>,
}

impl PackageCache {
    /// Create a new cache at the specified directory.
    ///
    /// If `dir` is `None`, defaults to `~/.cache/shuttle/pkgs/`.
    pub fn new(dir: Option<PathBuf>) -> Self {
        let root = dir.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home)
                .join(".cache")
                .join("shuttle")
                .join(DEFAULT_CACHE_SUBDIR)
        });
        PackageCache {
            root,
            max_size: None,
        }
    }

    /// Set maximum cache size in bytes. Auto-prune triggers on store()
    /// when total size exceeds this threshold.
    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    /// Get the cache root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Check if a snap is already cached for the given architecture under the
    /// given build-input closure.
    ///
    /// Returns `Some(path)` if the cached snap exists, `None` otherwise.
    pub fn lookup(&self, meta: &SnapMeta, arch: &str, closure: &BuildClosure) -> Option<PathBuf> {
        // adopt-info snaps have no version until build time: their closure
        // key hashes the placeholder, which cannot distinguish two upstream
        // versions behind one URL. Never serve them from cache — a
        // placeholder-keyed hit could be a wrong-version serve.
        if meta.adopt_info.is_some() {
            return None;
        }
        let cached = self
            .root
            .join(closure.cache_key())
            .join(format!("{}_{}_{}.snap", meta.name, meta.version, arch));
        if cached.exists() {
            Some(cached)
        } else {
            None
        }
    }

    /// Store a built snap in the cache under its build-input closure.
    ///
    /// Copies the built snap file from `result.snap_filename` (in the output
    /// directory where it was built) into the cache tree. No-op for meta/store
    /// packages (closure source `none`) — they are trivial and always rebuilt.
    /// Also a no-op for adopt-info snaps: their placeholder closure key cannot
    /// distinguish upstream versions, so caching them risks a wrong-version
    /// serve (they are rebuilt every time instead).
    pub fn store(
        &self,
        meta: &SnapMeta,
        result: &BuildResult,
        output_dir: &Path,
        closure: &BuildClosure,
    ) -> miette::Result<()> {
        // Don't cache meta/store packages (they're empty/trivial)
        if closure.source == NO_SOURCE_HASH || meta.adopt_info.is_some() {
            return Ok(());
        }

        let cache_dir = self.root.join(closure.cache_key());
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| miette::miette!("failed to create cache dir {:?}: {}", cache_dir, e))?;

        let src = output_dir.join(&result.snap_filename);
        let dst = cache_dir.join(&result.snap_filename);

        if src.exists() {
            std::fs::copy(&src, &dst).map_err(|e| {
                miette::miette!(
                    "failed to cache {} -> {:?}: {}",
                    result.snap_filename,
                    dst,
                    e
                )
            })?;
        }

        // Auto-prune if max_size is configured
        if let Some(max) = self.max_size {
            if let Ok(info) = self.info() {
                if info.size_bytes > max {
                    let _ = self.prune_stale(max);
                }
            }
        }

        Ok(())
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) -> miette::Result<()> {
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root)
                .map_err(|e| miette::miette!("failed to clear cache {:?}: {}", self.root, e))?;
        }
        Ok(())
    }

    /// Gather cache statistics.
    pub fn info(&self) -> miette::Result<CacheInfo> {
        let mut entries = 0usize;
        let mut packages = 0usize;
        let mut size_bytes = 0u64;

        if self.root.exists() {
            for entry in std::fs::read_dir(&self.root)
                .map_err(|e| miette::miette!("failed to read cache {:?}: {}", self.root, e))?
            {
                let entry =
                    entry.map_err(|e| miette::miette!("failed to read cache entry: {}", e))?;
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    entries += 1;
                    let dir = entry.path();
                    for file in std::fs::read_dir(&dir)
                        .map_err(|e| miette::miette!("failed to read cache dir: {}", e))?
                    {
                        let file =
                            file.map_err(|e| miette::miette!("failed to read cache file: {}", e))?;
                        if file.file_type().is_ok_and(|t| t.is_file()) {
                            packages += 1;
                            size_bytes += file.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                    }
                }
            }
        }

        Ok(CacheInfo {
            entries,
            packages,
            size_bytes,
            root: self.root.clone(),
        })
    }

    /// Prune cache entries not accessed in `max_days` days.
    /// Removes entire hash directories for stale sources.
    pub fn prune(&self, max_days: u64) -> miette::Result<u64> {
        let now = std::time::SystemTime::now();
        let max_age = std::time::Duration::from_secs(max_days * 86400);
        let mut removed = 0u64;

        if self.root.exists() {
            for entry in std::fs::read_dir(&self.root)
                .map_err(|e| miette::miette!("failed to read cache {:?}: {}", self.root, e))?
            {
                let entry =
                    entry.map_err(|e| miette::miette!("failed to read cache entry: {}", e))?;
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    // Check access time of the directory itself
                    if let Ok(modified) = entry.path().metadata().and_then(|m| m.modified()) {
                        if now.duration_since(modified).unwrap_or_default() > max_age {
                            std::fs::remove_dir_all(entry.path()).map_err(|e| {
                                miette::miette!("failed to remove {:?}: {}", entry.path(), e)
                            })?;
                            removed += 1;
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    /// Prune oldest entries until total size is under `target_bytes`.
    /// Removes entire source-hash directories (one entry = all cached packages
    /// built from one source tarball), oldest modification time first.
    fn prune_stale(&self, target_bytes: u64) -> miette::Result<u64> {
        let mut removed = 0u64;

        if !self.root.exists() {
            return Ok(0);
        }

        // Collect entries with their modification times and sizes
        let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf, u64)> = Vec::new();
        for entry in std::fs::read_dir(&self.root)
            .map_err(|e| miette::miette!("failed to read cache: {}", e))?
        {
            let entry = entry.map_err(|e| miette::miette!("failed to read cache entry: {}", e))?;
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                let mut dir_size = 0u64;
                if let Ok(files) = std::fs::read_dir(entry.path()) {
                    for file in files.flatten() {
                        if file.file_type().is_ok_and(|t| t.is_file()) {
                            dir_size += file.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                    }
                }
                let modified = entry
                    .path()
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                entries.push((modified, entry.path(), dir_size));
            }
        }

        // Sort by modification time (oldest first)
        entries.sort_by_key(|(m, _, _)| *m);

        // Remove oldest entries until under target
        let mut total: u64 = entries.iter().map(|(_, _, s)| s).sum();
        for (_, path, size) in &entries {
            if total <= target_bytes {
                break;
            }
            std::fs::remove_dir_all(path)
                .map_err(|e| miette::miette!("failed to remove {:?}: {}", path, e))?;
            total -= size;
            removed += 1;
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source_meta(name: &str, url: &str) -> SnapMeta {
        SnapMeta {
            name: name.into(),
            version: "1.0".into(),
            summary: None,
            description: None,
            license: None,
            source: Some(crate::snap::SourceSpec::Unverified(url.into())),
            build: Some("make".into()),
            parts: None,
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: Some("source".into()),
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
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: std::collections::HashMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn make_meta_meta(name: &str) -> SnapMeta {
        SnapMeta {
            name: name.into(),
            version: "1.0".into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            build: None,
            parts: None,
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: Some("meta".into()),
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
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: std::collections::HashMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    #[test]
    fn test_cache_default_dir() {
        let cache = PackageCache::new(None);
        let expected = Path::new(&std::env::var("HOME").unwrap())
            .join(".cache")
            .join("shuttle")
            .join("pkgs");
        assert_eq!(cache.root(), expected);
    }

    #[test]
    fn test_cache_custom_dir() {
        let cache = PackageCache::new(Some(PathBuf::from("/tmp/test-cache")));
        assert_eq!(cache.root(), Path::new("/tmp/test-cache"));
    }

    #[test]
    fn test_closure_source_meta_package() {
        let meta = make_meta_meta("build-deps");
        let closure = BuildClosure::for_meta(&meta, vec![]);
        assert_eq!(closure.source, "none");
    }

    #[test]
    fn test_closure_key_format_v2() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let key = BuildClosure::for_meta(&meta, vec![]).cache_key();
        // "v2:" prefix + 64-char hex digest
        let hex = key.strip_prefix("v2:").expect("key must be v2-prefixed");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_closure_canonical_json_schema() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(
            &meta,
            vec![RequiresMember {
                name: "zlib".into(),
                pin: Some("1.3".into()),
                hash: None,
            }],
        );
        let expected_source = sha256_hex("hello:1.0:https://example.com/hello.tar.gz");
        // Locks the exact deterministic schema: sorted keys, null hashes.
        assert_eq!(
            closure.canonical_json(),
            format!(
                r#"{{"format_version":2,"parts":"","requires":[{{"hash":null,"name":"zlib","pin":"1.3"}}],"source":"{expected_source}","target":"native"}}"#
            )
        );
    }

    #[test]
    fn test_closure_key_stable_when_nothing_changes() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let requires = vec![RequiresMember {
            name: "zlib".into(),
            pin: Some("1.3".into()),
            hash: Some("abc".into()),
        }];
        let key1 = BuildClosure::for_meta(&meta, requires.clone()).cache_key();
        let key2 = BuildClosure::for_meta(&meta, requires).cache_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_closure_key_varies_with_source_change() {
        // The old format test pinned byte-compat with the pre-closure key;
        // v2 deliberately breaks that (one cold-cache rebuild on upgrade).
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let changed = make_source_meta("hello", "https://example.com/hello-v2.tar.gz");
        assert_ne!(
            BuildClosure::for_meta(&meta, vec![]).cache_key(),
            BuildClosure::for_meta(&changed, vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_key_varies_with_parts_spec() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.build = None;
        meta.parts = Some(
            [(
                "core",
                SnapPart {
                    build: "make".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            )]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        );
        let with_parts = BuildClosure::for_meta(&meta, vec![]).cache_key();

        // Different command → different key
        let mut meta2 = meta.clone();
        if let Some(parts) = &mut meta2.parts {
            parts.get_mut("core").unwrap().build = "make all".into();
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta2, vec![]).cache_key()
        );

        // New part name → different key
        let mut meta3 = meta.clone();
        if let Some(parts) = &mut meta3.parts {
            parts.insert(
                "ui".into(),
                SnapPart {
                    build: "npm build".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            );
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta3, vec![]).cache_key()
        );

        // Added `after` edge → different key
        let mut meta4 = meta.clone();
        if let Some(parts) = &mut meta4.parts {
            parts.get_mut("core").unwrap().after = vec!["ui".into()];
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta4, vec![]).cache_key()
        );

        // No parts at all → different key again
        let mut meta5 = meta.clone();
        meta5.parts = None;
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta5, vec![]).cache_key()
        );
    }

    #[test]
    fn test_canonical_parts_json_locked_for_command_parts() {
        // Parts without a plugin must serialize byte-identically to the
        // pre-plugin format (serde_json's default map sorts keys).
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: "make".into(),
                after: vec!["libs".into()],
                plugin: None,
                plugin_options: None,
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":["libs"],"build":"make","name":"core"}]"#
        );
    }

    #[test]
    fn test_canonical_parts_json_folds_plugin_identity_and_options() {
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
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
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":[],"build":"","name":"core","options":{"target":"all"},"plugin":"make","plugin_version":"2"}]"#
        );
    }

    #[test]
    fn test_canonical_parts_json_make_growth_options_canonical() {
        // Registry-v2 options fold in canonically: option keys sorted,
        // `variables` map sorted, booleans as JSON booleans.
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [
                        (
                            "variables".to_string(),
                            crate::plugins::PluginValue::Map(
                                [
                                    ("ZED".to_string(), "1".to_string()),
                                    ("ALPHA".to_string(), "2".to_string()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        ),
                        (
                            "install".to_string(),
                            crate::plugins::PluginValue::Bool(false),
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
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":[],"build":"","name":"core","options":{"install":false,"variables":{"ALPHA":"2","ZED":"1"}},"plugin":"make","plugin_version":"2"}]"#
        );
    }

    #[test]
    fn test_closure_key_varies_with_plugin_and_options() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.build = None;
        meta.parts = Some(
            [(
                "core",
                SnapPart {
                    build: String::new(),
                    after: vec![],
                    plugin: Some("make".into()),
                    plugin_options: None,
                },
            )]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        );
        let base = BuildClosure::for_meta(&meta, vec![]).cache_key();

        // Different plugin → different key
        let mut meta2 = meta.clone();
        meta2
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin = Some("cmake".into());
        assert_ne!(base, BuildClosure::for_meta(&meta2, vec![]).cache_key());

        // Option added → different key
        let mut meta3 = meta.clone();
        meta3
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin_options = Some(
            [(
                "target".to_string(),
                crate::plugins::PluginValue::Str("all".into()),
            )]
            .into(),
        );
        let with_options = BuildClosure::for_meta(&meta3, vec![]).cache_key();
        assert_ne!(base, with_options);

        // Option value changed → different key
        let mut meta4 = meta3.clone();
        meta4
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin_options = Some(
            [(
                "target".to_string(),
                crate::plugins::PluginValue::Str("install".into()),
            )]
            .into(),
        );
        assert_ne!(
            with_options,
            BuildClosure::for_meta(&meta4, vec![]).cache_key()
        );

        // Identical options → same key
        assert_eq!(
            with_options,
            BuildClosure::for_meta(&meta3, vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_key_varies_with_make_variables() {
        // Registry-v2 make options: `variables` (and booleans like `install`)
        // must fold into the key like any other option.
        let make_part = |options| SnapPart {
            build: String::new(),
            after: vec![],
            plugin: Some("make".into()),
            plugin_options: options,
        };
        let variables = |value: &str| {
            Some(
                [(
                    "variables".to_string(),
                    crate::plugins::PluginValue::Map(
                        [("CFLAGS".to_string(), value.to_string())]
                            .into_iter()
                            .collect(),
                    ),
                )]
                .into_iter()
                .collect(),
            )
        };

        let meta = |part: SnapPart| {
            let mut m = make_source_meta("hello", "https://example.com/hello.tar.gz");
            m.build = None;
            m.parts = Some([("core".to_string(), part)].into_iter().collect());
            BuildClosure::for_meta(&m, vec![]).cache_key()
        };

        let base = meta(make_part(None));
        let with_vars = meta(make_part(variables("-O2")));
        assert_ne!(base, with_vars, "adding variables must change the key");

        let changed = meta(make_part(variables("-O3")));
        assert_ne!(with_vars, changed, "a variable value change must rekey");

        assert_eq!(
            meta(make_part(variables("-O2"))),
            with_vars,
            "identical variables must keep the key warm"
        );

        // install = false changes the expansion → must change the key.
        let mut part = make_part(None);
        part.plugin_options = Some(
            [(
                "install".to_string(),
                crate::plugins::PluginValue::Bool(false),
            )]
            .into_iter()
            .collect(),
        );
        assert_ne!(base, meta(part));
    }

    #[test]
    fn test_closure_key_varies_with_target() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.target = None;
        let native = BuildClosure::for_meta(&meta, vec![]).cache_key();

        meta.target = Some("aarch64-linux-gnu".into());
        let aarch64 = BuildClosure::for_meta(&meta, vec![]).cache_key();

        meta.target = Some("x86_64-linux-gnu".into());
        let x86_64 = BuildClosure::for_meta(&meta, vec![]).cache_key();

        assert_ne!(native, aarch64);
        assert_ne!(native, x86_64);
        assert_ne!(aarch64, x86_64);

        // No target → stable "native" default
        meta.target = None;
        assert_eq!(native, BuildClosure::for_meta(&meta, vec![]).cache_key());
    }

    #[test]
    fn test_closure_key_varies_with_require_revision() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let member = |pin: Option<&str>, hash: Option<&str>| RequiresMember {
            name: "zlib".into(),
            pin: pin.map(str::to_string),
            hash: hash.map(str::to_string),
        };

        let base = BuildClosure::for_meta(&meta, vec![member(Some("1.3"), None)]).cache_key();

        // Pin (revision/version) changed → different key
        let repinned = BuildClosure::for_meta(&meta, vec![member(Some("1.3.1"), None)]).cache_key();
        assert_ne!(base, repinned);

        // Lock hash appeared for the same pin → different key
        let hashed =
            BuildClosure::for_meta(&meta, vec![member(Some("1.3"), Some("aa"))]).cache_key();
        assert_ne!(base, hashed);

        // New dep in the closure → different key
        let mut two = vec![member(Some("1.3"), None)];
        two.push(RequiresMember {
            name: "gmp".into(),
            pin: Some("6.3".into()),
            hash: None,
        });
        assert_ne!(base, BuildClosure::for_meta(&meta, two.clone()).cache_key());

        // Same members → same key
        assert_eq!(
            BuildClosure::for_meta(&meta, two.clone()).cache_key(),
            BuildClosure::for_meta(&meta, two).cache_key()
        );
    }

    #[test]
    fn test_closure_requires_sorted_and_deduplicated() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let member = |name: &str| RequiresMember {
            name: name.to_string(),
            pin: None,
            hash: None,
        };

        // Same deps in different traversal order → identical key
        let order_a = vec![member("zlib"), member("gmp"), member("mpfr")];
        let order_b = vec![member("mpfr"), member("zlib"), member("gmp")];
        assert_eq!(
            BuildClosure::for_meta(&meta, order_a).cache_key(),
            BuildClosure::for_meta(&meta, order_b).cache_key()
        );

        // Duplicates collapse to one member
        let dup = vec![member("zlib"), member("zlib")];
        let closure = BuildClosure::for_meta(&meta, dup);
        assert_eq!(closure.requires.len(), 1);
        assert_eq!(closure.requires[0].name, "zlib");
    }

    #[test]
    fn test_pinned_member_from_lock_data() {
        // Lock-only data (no I/O, works offline) resolves pin + content hash.
        let mut lock = crate::lock::LockFile {
            version: 1,
            sources: std::collections::HashMap::new(),
            snaps: std::collections::HashMap::new(),
            inputs: std::collections::HashMap::new(),
            packages: std::collections::HashMap::new(),
        };
        lock.record_snap(&crate::snap::SnapRef {
            name: "core22".into(),
            revision: Some(1847),
            sha3_384: Some("abc123".into()),
        });

        let member = pinned_member("core22", &lock).expect("pinned snap resolves");
        assert_eq!(member.name, "core22");
        assert_eq!(member.pin.as_deref(), Some("1847"));
        assert_eq!(member.hash.as_deref(), Some("abc123"));

        // Unpinned snap → None (caller falls back to version-pin, hash null)
        assert!(pinned_member("unknown", &lock).is_none());
    }

    #[test]
    fn test_lookup_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("missing", "https://example.com/missing.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![]);
        assert!(cache.lookup(&meta, "amd64", &closure).is_none());
    }

    #[test]
    fn test_store_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![]);

        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();

        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_info: None,
        };

        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        let cached = cache.lookup(&meta, "amd64", &closure);
        assert!(cached.is_some(), "should find cached snap");
        assert!(cached.unwrap().exists(), "cached file should exist");
        // Cached under the closure key directory
        assert!(dir
            .path()
            .join(closure.cache_key())
            .join("hello_1.0_amd64.snap")
            .exists());
    }

    #[test]
    fn test_lookup_differs_by_target_and_requires() {
        // Same meta, different closure → different key dir → no stale hits.
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();
        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_info: None,
        };

        let closure = BuildClosure::for_meta(&meta, vec![]);
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();
        assert!(cache.lookup(&meta, "amd64", &closure).is_some());

        // Target change → miss
        meta.target = Some("aarch64-linux-gnu".into());
        let other_target = BuildClosure::for_meta(&meta, vec![]);
        assert!(cache.lookup(&meta, "amd64", &other_target).is_none());

        // Requires revision change → miss
        meta.target = None;
        let other_reqs = BuildClosure::for_meta(
            &meta,
            vec![RequiresMember {
                name: "zlib".into(),
                pin: Some("1.3".into()),
                hash: None,
            }],
        );
        assert!(cache.lookup(&meta, "amd64", &other_reqs).is_none());
    }

    #[test]
    fn test_meta_package_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_meta_meta("build-deps");
        let closure = BuildClosure::for_meta(&meta, vec![]);

        // store should be a no-op for meta packages
        let output_dir = tempfile::tempdir().unwrap();
        // BuildResult with any filename (won't be stored)
        let result = BuildResult {
            snap_filename: "build-deps_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_info: None,
        };
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        // Should not find it
        assert!(cache.lookup(&meta, "amd64", &closure).is_none());
    }

    #[test]
    fn test_clear_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));

        // Store something
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![]);
        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();
        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_info: None,
        };
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        // Verify it's there
        assert!(cache.lookup(&meta, "amd64", &closure).is_some());

        // Clear
        cache.clear().unwrap();
        assert!(!dir.path().join("pkgs").exists());
    }
}
