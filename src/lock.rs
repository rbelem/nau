use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::snap::SnapRef;

/// A lockfile captures resolved hashes of all build inputs for reproducibility.
///
/// On first build: creates `shoot.lock` with SHA-256 of every downloaded source
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
}

/// A single source entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLockEntry {
    pub sha256: String,
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
}

/// `skip_serializing_if` helper: omit `local = false` from the lockfile.
fn is_false(b: &bool) -> bool {
    !*b
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
    pub const FILENAME: &'static str = "shoot.lock";

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

    /// Save lockfile to disk.
    pub fn save(&self, path: &Path) -> miette::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("failed to serialize lockfile: {}", e))?;
        let content = content + "\n";
        std::fs::write(path, &content)
            .map_err(|e| miette::miette!("failed to write {}: {}", path.display(), e))?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_roundtrip() {
        let mut sources = HashMap::new();
        sources.insert(
            "https://example.com/src.tar.gz".to_string(),
            SourceLockEntry {
                sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
            },
        );

        let mut snaps = HashMap::new();
        snaps.insert(
            "core22".to_string(),
            SnapLockEntry {
                revision: 1847,
                sha3_384: "d53e1c8a66cb03a99aed76f03c49c55ec6110e33c8cb4a12fb2c8715c9349a29321e877483a7bc7718fe552f2533397d".into(),
            },
        );

        let lock = LockFile {
            version: 1,
            sources,
            snaps,
            inputs: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        let deserialized: LockFile = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.sources.len(), 1);
        assert_eq!(deserialized.snaps.len(), 1);
        assert_eq!(
            deserialized.snaps.get("core22").map(|e| e.revision),
            Some(1847)
        );
    }

    #[test]
    fn test_lockfile_load_nonexistent() {
        let result = LockFile::load(Path::new("/tmp/nonexistent-lock-test-12345.lock"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_lockfile_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shoot.lock");

        let mut sources = HashMap::new();
        sources.insert(
            "https://example.com/pkg.tar.gz".to_string(),
            SourceLockEntry {
                sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            },
        );

        let lock = LockFile {
            version: 1,
            sources,
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };

        lock.save(&path).unwrap();

        let loaded = LockFile::load(&path).unwrap().expect("should exist");
        assert_eq!(loaded.version, 1);
        assert_eq!(
            loaded.lookup_source("https://example.com/pkg.tar.gz"),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert!(loaded
            .lookup_source("https://unknown.example.com")
            .is_none());
    }

    #[test]
    fn test_lockfile_record_and_lookup_snap() {
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };

        let snap = SnapRef {
            name: "core22".into(),
            revision: Some(1847),
            sha3_384: Some("abc123".into()),
        };

        lock.record_snap(&snap);
        assert_eq!(lock.snaps.len(), 1);

        let looked_up = lock.lookup_snap("core22").unwrap();
        assert_eq!(looked_up.revision, Some(1847));
        assert_eq!(looked_up.sha3_384.as_deref(), Some("abc123"));

        // Recording same snap again should not duplicate
        lock.record_snap(&snap);
        assert_eq!(lock.snaps.len(), 1);
    }

    #[test]
    fn test_lockfile_serialization_format() {
        let mut snaps = HashMap::new();
        snaps.insert(
            "core22".into(),
            SnapLockEntry {
                revision: 1847,
                sha3_384: "d53e1c8a66cb03a99aed76f03c49c55ec6110e33c8cb4a12fb2c8715c9349a29321e877483a7bc7718fe552f2533397d".into(),
            },
        );

        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps,
            inputs: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        // Verify the output format includes "sha3-384" key
        assert!(
            json.contains("sha3-384"),
            "JSON should contain sha3-384 key"
        );
        assert!(json.contains("revision"), "JSON should contain revision");
        assert!(json.contains("core22"));
    }

    #[test]
    fn test_input_lock_roundtrip() {
        let mut inputs = HashMap::new();
        inputs.insert(
            "packages".to_string(),
            InputLockEntry {
                revision: Some("c0ffee1234567890c0ffee1234567890c0ffee123".to_string()),
                sha256: Some(
                    "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef".to_string(),
                ),
                local: false,
            },
        );
        inputs.insert(
            "local-pkgs".to_string(),
            InputLockEntry {
                revision: None,
                sha256: None,
                local: true,
            },
        );

        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs,
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        assert!(json.contains("\"inputs\""), "should contain inputs section");
        assert!(json.contains("revision"));
        assert!(json.contains("local"));
        // local = false is skipped to keep the file readable
        assert!(!json.contains("false"), "local=false should be omitted");

        let back: LockFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.inputs.len(), 2);
        assert_eq!(
            back.inputs["packages"].revision.as_deref(),
            Some("c0ffee1234567890c0ffee1234567890c0ffee123")
        );
        assert_eq!(
            back.inputs["packages"].sha256.as_deref(),
            Some("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
        );
        assert!(!back.inputs["packages"].local);
        assert!(back.inputs["local-pkgs"].local);
        assert!(back.inputs["local-pkgs"].revision.is_none());
    }

    #[test]
    fn test_lockfile_without_inputs_backcompat() {
        // Pre-Phase-16 lockfiles have no `inputs` key — must still load.
        let json = r#"{ "version": 1, "sources": {}, "snaps": {} }"#;
        let lock: LockFile = serde_json::from_str(json).unwrap();
        assert_eq!(lock.version, 1);
        assert!(lock.inputs.is_empty());
    }
}
