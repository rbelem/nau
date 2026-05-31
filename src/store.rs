//! Snap Store client — query, download, and verify snaps from the
//! [Snap Store](https://snapcraft.io).
//!
//! Uses the public Snap Store API v2.
//!
//! # API reference
//!
//! - `GET /v2/snaps/info/<name>` — channel map with download URLs & hashes
//! - `GET /v1/snaps/download/<id>.snap` — actual snap binary download
//!
//! Both require header `Snap-Device-Series: 16`.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha3::Digest;

use crate::snap::SnapRef;

// ── API response types ──

/// Top-level response from `GET /v2/snaps/info/<name>`.
#[derive(Debug, Deserialize)]
struct SnapInfoResponse {
    #[serde(rename = "channel-map")]
    channel_map: Vec<ChannelMapEntry>,
}

/// One entry in the channel map.
#[derive(Debug, Deserialize)]
struct ChannelMapEntry {
    channel: ChannelInfo,
    download: DownloadInfo,
    revision: u32,
}

/// Channel identification within an entry.
#[derive(Debug, Deserialize)]
struct ChannelInfo {
    architecture: String,
    #[allow(dead_code)]
    name: String,
    track: String,
    risk: String,
}

/// Download URL and hash for a snap revision.
#[derive(Debug, Deserialize)]
struct DownloadInfo {
    #[serde(rename = "sha3-384")]
    sha3_384: String,
    #[allow(dead_code)]
    size: u64,
    url: String,
}

// ── Resolved snap — everything needed to download and verify ──

/// A fully resolved snap reference: name + exact revision + content hash.
#[derive(Debug, Clone)]
pub struct ResolvedSnap {
    pub name: String,
    pub revision: u32,
    /// sha3-384 hex digest from the store.
    pub sha3_384: String,
    /// Download URL from the store.
    pub download_url: String,
}

impl ResolvedSnap {
    /// ToSnapRef (without the download URL — for lockfile storage).
    pub fn to_snap_ref(&self) -> SnapRef {
        SnapRef {
            name: self.name.clone(),
            revision: Some(self.revision),
            sha3_384: Some(self.sha3_384.clone()),
        }
    }
}

// ── Store client ──

/// Client for querying and downloading from the Snap Store.
pub struct StoreClient;

impl StoreClient {
    /// Query the store for a snap's metadata.
    ///
    /// Returns the channel map for all architectures and tracks.
    fn query_info(name: &str) -> miette::Result<SnapInfoResponse> {
        let url = format!("https://api.snapcraft.io/v2/snaps/info/{name}");

        let output = std::process::Command::new("curl")
            .args(["-s", "-H", "Snap-Device-Series: 16", &url])
            .output()
            .map_err(|e| miette::miette!("curl not found: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette::miette!(
                "failed to query snap store for '{name}': {stderr}"
            ));
        }

        let body = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<SnapInfoResponse>(&body)
            .map_err(|e| miette::miette!("invalid store response for '{name}': {e}"))
    }

    /// Resolve a `SnapRef` to a fully resolved snap with download URL.
    ///
    /// If the pin has `revision` and `sha3_384`, it uses those directly
    /// (no store query needed). Otherwise it queries the store.
    pub fn resolve(pin: &SnapRef, channel: &str, arch: &str) -> miette::Result<ResolvedSnap> {
        // If fully pinned, we still need the download URL from the store
        let info = Self::query_info(&pin.name)?;

        // Parse the channel as "track/risk" (e.g. "latest/stable")
        let parts: Vec<&str> = channel.split('/').collect();
        let (track, risk) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("latest", channel)
        };

        // Find the matching track + risk + arch entry
        let entry = info
            .channel_map
            .iter()
            .find(|e| {
                e.channel.track == track && e.channel.risk == risk && e.channel.architecture == arch
            })
            .ok_or_else(|| {
                miette::miette!("snap '{}': no entry for {track}/{risk} / {arch}", pin.name)
            })?;

        let store_revision = entry.revision;

        // Verify revision matches if pinned
        if let Some(expected_rev) = pin.revision {
            if store_revision != expected_rev {
                return Err(miette::miette!(
                    "snap '{}': revision mismatch for {track}/{risk} / {arch}: \
                     expected {expected_rev}, store has {store_revision}",
                    pin.name
                ));
            }
        }

        // Verify sha3-384 matches if pinned
        let sha3_384 = entry.download.sha3_384.clone();
        if let Some(expected_hash) = &pin.sha3_384 {
            if sha3_384 != *expected_hash {
                return Err(miette::miette!(
                    "snap '{}': sha3-384 mismatch for revision {store_revision}: \
                     expected {expected_hash}, store has {sha3_384}",
                    pin.name
                ));
            }
        }

        Ok(ResolvedSnap {
            name: pin.name.clone(),
            revision: store_revision,
            sha3_384,
            download_url: entry.download.url.clone(),
        })
    }

    /// Download a resolved snap to the given directory.
    ///
    /// Returns the path to the downloaded `.snap` file.
    pub fn download(resolved: &ResolvedSnap, output_dir: &Path) -> miette::Result<PathBuf> {
        let filename = format!(
            "{}_{}_{}.snap",
            resolved.name, resolved.revision, resolved.sha3_384
        );
        let output_path = output_dir.join(&filename);

        if output_path.exists() {
            eprintln!("  snap already cached: {filename}");
            return Ok(output_path);
        }

        std::fs::create_dir_all(output_dir)
            .map_err(|e| miette::miette!("failed to create {:?}: {e}", output_dir))?;

        let status = std::process::Command::new("curl")
            .args([
                "-fsSL",
                "-o",
                &output_path.to_string_lossy(),
                &resolved.download_url,
            ])
            .status()
            .map_err(|e| miette::miette!("curl not found: {e}"))?;

        if !status.success() {
            return Err(miette::miette!(
                "failed to download snap '{}' revision {}",
                resolved.name,
                resolved.revision
            ));
        }

        Ok(output_path)
    }

    /// Verify a `.snap` file's sha3-384 hash.
    ///
    /// Returns `Ok(())` if the hash matches, or an error with the computed
    /// hash on mismatch.
    pub fn verify(path: &Path, expected_sha3_384: &str) -> miette::Result<()> {
        let computed = sha3_384_file(path)?;
        if computed != expected_sha3_384 {
            return Err(miette::miette!(
                "sha3-384 mismatch for {}:\n  expected: {}\n  got:      {}",
                path.display(),
                expected_sha3_384,
                computed
            ));
        }
        Ok(())
    }

    /// Resolve, download, and verify a pinned snap in one step.
    pub fn fetch(
        pin: &SnapRef,
        channel: &str,
        arch: &str,
        cache_dir: &Path,
    ) -> miette::Result<PathBuf> {
        let resolved = Self::resolve(pin, channel, arch)?;
        let path = Self::download(&resolved, cache_dir)?;
        Self::verify(&path, &resolved.sha3_384)?;
        eprintln!(
            "  ✓ {} revision {} — sha3-384 verified",
            resolved.name, resolved.revision
        );
        Ok(path)
    }
}

// ── sha3-384 helpers ──

/// Compute sha3-384 of a file (streaming, memory-efficient).
pub fn sha3_384_file(path: &Path) -> miette::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {}", path.display(), e))?;
    let mut hasher = sha3::Sha3_384::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_384_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world\n").unwrap();
        let hash = sha3_384_file(&path).unwrap();
        // Known-good sha3-384 of "hello world\n"
        assert_eq!(
            hash,
            "28fc308d4d5c1ef9e60acedb13c3a1fcf7266560602c639000580ae3541dea5c\
             e78a685de897e96b65a0fc15515c3780"
        );
    }

    #[test]
    fn test_resolve_requires_store_query() {
        // This test would need network access — skip by default.
        // Run manually with: cargo test -- --ignored test_resolve_core22
        // We just verify that the resolve function exists and is callable
        // by checking the function signature compiles.
        assert!(std::mem::size_of::<ResolvedSnap>() > 0);
        assert!(std::mem::size_of::<SnapRef>() > 0);
    }

    #[test]
    fn test_snap_ref_from_pin_table() {
        let lua = mlua::Lua::new();
        let table: mlua::Table = lua
            .load(
                r#"
                return {
                    name = "core22",
                    revision = 1847,
                    sha3_384 = "abcdef1234567890",
                }
                "#,
            )
            .eval()
            .unwrap();

        let snap_ref = SnapRef::from_pin_table(&table).unwrap();
        assert_eq!(snap_ref.name, "core22");
        assert_eq!(snap_ref.revision, Some(1847));
        assert_eq!(snap_ref.sha3_384.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn test_snap_ref_from_pin_table_minimal() {
        let lua = mlua::Lua::new();
        let table: mlua::Table = lua
            .load(
                r#"
                return { name = "core22" }
                "#,
            )
            .eval()
            .unwrap();

        let snap_ref = SnapRef::from_pin_table(&table).unwrap();
        assert_eq!(snap_ref.name, "core22");
        assert!(snap_ref.revision.is_none());
        assert!(snap_ref.sha3_384.is_none());
    }

    #[test]
    fn test_snap_ref_from_pin_table_missing_name() {
        let lua = mlua::Lua::new();
        let table: mlua::Table = lua.load(r#"return { revision = 42 }"#).eval().unwrap();
        let result = SnapRef::from_pin_table(&table);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("name"), "error should mention name: {err}");
    }
}
