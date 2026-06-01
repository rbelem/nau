//! Binary package cache — store and retrieve built `.snap` files by source hash.
//!
//! The cache lives at `~/.cache/shoot/pkgs/` (configurable via `--cache`).
//! Each cached snap is stored as:
//!
//! ```text
//! <cache_dir>/<source_sha256>/<name>_<version>_<arch>.snap
//! ```
//!
//! The source SHA-256 is the hash of the downloaded source tarball (or `none`
//! for meta/store packages that have no source). This means:
//! - Same source tarball → same hash → cached build reused
//! - Source changes → new hash → fresh build
//! - No source (meta packages) → always rebuilt (fast, no-op)
//!
//! Usage:
//! ```rust,ignore
//! let cache = PackageCache::new(Some("/path/to/cache"));
//! if let Some(path) = cache.lookup(&meta, "amd64") {
//!     // use cached build
//! } else {
//!     let result = build_snap(&meta, ...)?;
//!     cache.store(&meta, &result, "amd64")?;
//! }
//! ```

use std::path::{Path, PathBuf};

use sha2::Digest;

use crate::snap::{BuildResult, SnapMeta};

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheInfo {
    pub entries: usize,
    pub packages: usize,
    pub size_bytes: u64,
    pub root: std::path::PathBuf,
}

/// Default cache directory name under `~/.cache/shoot/`.
const DEFAULT_CACHE_SUBDIR: &str = "pkgs";

/// Magic string for packages without source (meta/store types).
const NO_SOURCE_HASH: &str = "none";

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
    /// If `dir` is `None`, defaults to `~/.cache/shoot/pkgs/`.
    pub fn new(dir: Option<PathBuf>) -> Self {
        let root = dir.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home)
                .join(".cache")
                .join("shoot")
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

    /// Compute the source hash key for a snap meta.
    ///
    /// For source packages, this is the SHA-256 of the source URL + version
    /// (since we haven't downloaded the source yet at check time).
    /// For meta/store packages, returns `"none"`.
    fn source_key(meta: &SnapMeta) -> String {
        match meta.type_ {
            Some(ref t) if t == "source" => {
                // Hash the source URL + version to get a cache key
                let url = meta
                    .source
                    .as_ref()
                    .map(|s| s.url().to_string())
                    .unwrap_or_default();
                let input = format!("{}:{}:{}", meta.name, meta.version, url);
                let hash = sha2::Sha256::digest(input.as_bytes());
                hash.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            }
            _ => NO_SOURCE_HASH.to_string(),
        }
    }

    /// Check if a snap is already cached for the given architecture.
    ///
    /// Returns `Some(path)` if the cached snap exists, `None` otherwise.
    pub fn lookup(&self, meta: &SnapMeta, arch: &str) -> Option<PathBuf> {
        let key = Self::source_key(meta);
        let cached = self
            .root
            .join(&key)
            .join(format!("{}_{}_{}.snap", meta.name, meta.version, arch));
        if cached.exists() {
            Some(cached)
        } else {
            None
        }
    }

    /// Store a built snap in the cache.
    ///
    /// Copies the built snap file from `result.snap_filename` (in the output
    /// directory where it was built) into the cache tree.
    pub fn store(
        &self,
        meta: &SnapMeta,
        result: &BuildResult,
        _arch: &str,
        output_dir: &Path,
    ) -> miette::Result<()> {
        let key = Self::source_key(meta);

        // Don't cache meta/store packages (they're empty/trivial)
        if key == NO_SOURCE_HASH {
            return Ok(());
        }

        let cache_dir = self.root.join(&key);
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
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: Some("source".into()),
            aliases: vec![],
            requires: vec![],
            target: None,
            toolchain: None,
            apps: std::collections::HashMap::new(),
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
            architectures: Some(vec!["amd64".into()]),
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: Some("meta".into()),
            aliases: vec![],
            requires: vec![],
            target: None,
            toolchain: None,
            apps: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_cache_default_dir() {
        let cache = PackageCache::new(None);
        let expected = Path::new(&std::env::var("HOME").unwrap())
            .join(".cache")
            .join("shoot")
            .join("pkgs");
        assert_eq!(cache.root(), expected);
    }

    #[test]
    fn test_cache_custom_dir() {
        let cache = PackageCache::new(Some(PathBuf::from("/tmp/test-cache")));
        assert_eq!(cache.root(), Path::new("/tmp/test-cache"));
    }

    #[test]
    fn test_source_key_meta_package() {
        let meta = make_meta_meta("build-deps");
        assert_eq!(PackageCache::source_key(&meta), "none");
    }

    #[test]
    fn test_source_key_source_package() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let key = PackageCache::source_key(&meta);
        // Should be a 64-char hex string
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_source_key_deterministic() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let key1 = PackageCache::source_key(&meta);
        let key2 = PackageCache::source_key(&meta);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_lookup_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("missing", "https://example.com/missing.tar.gz");
        assert!(cache.lookup(&meta, "amd64").is_none());
    }

    #[test]
    fn test_store_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");

        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();

        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            source_info: None,
        };

        cache
            .store(&meta, &result, "amd64", output_dir.path())
            .unwrap();

        let cached = cache.lookup(&meta, "amd64");
        assert!(cached.is_some(), "should find cached snap");
        assert!(cached.unwrap().exists(), "cached file should exist");
    }

    #[test]
    fn test_meta_package_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_meta_meta("build-deps");

        // store should be a no-op for meta packages
        let output_dir = tempfile::tempdir().unwrap();
        // BuildResult with any filename (won't be stored)
        let result = BuildResult {
            snap_filename: "build-deps_1.0_amd64.snap".into(),
            source_info: None,
        };
        cache
            .store(&meta, &result, "amd64", output_dir.path())
            .unwrap();

        // Should not find it
        assert!(cache.lookup(&meta, "amd64").is_none());
    }

    #[test]
    fn test_clear_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));

        // Store something
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();
        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            source_info: None,
        };
        cache
            .store(&meta, &result, "amd64", output_dir.path())
            .unwrap();

        // Verify it's there
        assert!(cache.lookup(&meta, "amd64").is_some());

        // Clear
        cache.clear().unwrap();
        assert!(!dir.path().join("pkgs").exists());
    }
}
