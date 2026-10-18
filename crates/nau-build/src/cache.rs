//! Binary package cache — store and retrieve built `.snap` files by
//! build-input closure hash.
//!
//! The cache lives at `~/.cache/nau/pkgs/` (configurable via `--cache`).
//! Each cached snap is stored as:
//!
//! ```text
//! <cache_dir>/v4:<closure_sha256>/<name>_<version>_<arch>.snap
//! ```
//!
//! The directory key is `v4:` + SHA-256 over the canonical build-input
//! closure ([`BuildClosure`]): source identity, parts spec (including the
//! single-command `build` form), cross-compilation target, and the resolved
//! `requires` closure. Any change to any of these changes the key and forces
//! a fresh build (gap-analysis §4.3: the cache is keyed by the full input
//! closure, not just the source tarball). The `v4:` prefix version-bumps
//! deliberately: keys from older formats simply miss once and rebuild — an
//! accepted one-time cold-cache break.
//! Meta/store packages (closure source `none`) are never cached.
//!
//! Usage:
//! ```rust,ignore
//! let cache = PackageCache::new(Some("/path/to/cache"));
//! let closure = BuildClosure::for_meta(&meta, requires, build_deps);
//! if let Some(path) = cache.lookup(&meta, "amd64", &closure) {
//!     // use cached build
//! } else {
//!     let result = build_snap(&meta, ...)?;
//!     cache.store(&meta, &result, &result_dir, &closure)?;
//! }
//! ```

use std::path::{Path, PathBuf};

use nau_core::cache_key::NO_SOURCE_HASH;
#[cfg(test)]
use nau_core::cache_key::{canonical_parts_json, sha256_hex};

#[cfg(test)]
use crate::snap::SnapPart;
use crate::snap::{BuildResult, SnapMeta};

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheInfo {
    pub entries: usize,
    pub packages: usize,
    pub size_bytes: u64,
    pub root: std::path::PathBuf,
}

/// Default cache directory name under `~/.cache/nau/`.
const DEFAULT_CACHE_SUBDIR: &str = "pkgs";

// The canonical build-input closure vocabulary moved down to nau-core
// (ADR-0051 Decision 3: the chart manifest derives cache keys too).
// Re-exported so every `crate::cache::BuildClosure`-style path keeps
// resolving unchanged.
pub use nau_core::cache_key::{BuildClosure, RequiresMember, SourceClosureMember};

// `pinned_member` lives with the lockfile vocabulary it reads
// (nau-chart::lock, issue #326); re-exported for the build path.
pub use nau_core::lock::pinned_member;

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
    /// If `dir` is `None`, defaults to `~/.cache/nau/pkgs/`.
    pub fn new(dir: Option<PathBuf>) -> Self {
        let root = dir.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            Path::new(&home)
                .join(".cache")
                .join("nau")
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
mod tests;
