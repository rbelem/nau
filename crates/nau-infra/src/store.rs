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

use crate::command::CommandRunner;
use nau_core::snap_types::SnapRef;

// ── API response types ──

/// Top-level response from `GET /v2/snaps/info/<name>`.
#[derive(Debug, Deserialize)]
struct SnapInfoResponse {
    #[serde(rename = "channel-map")]
    channel_map: Vec<ChannelMapEntry>,
    /// Store snap id (top-level `snap-id`); bound by the snap-revision
    /// assertion cross-check when present.
    #[serde(rename = "snap-id", default)]
    snap_id: Option<String>,
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
    size: u64,
    url: String,
}

// ── Resolved snap — everything needed to download and verify ──

// The resolved-snap record moved DOWN into `nau_core::store` (issue #326
// PR 3 down-move): plain vocabulary over `SnapRef` that the image domain
// and the app-runtime emitter name, while the client (queries, curl, the
// assertion gate) stays root. Re-exported so every `crate::store::
// ResolvedSnap` path keeps resolving.
pub use nau_core::store::ResolvedSnap;

// ── Store client ──

/// `NAU_SNAP_IDS` override: `name=id` pairs (comma/whitespace
/// separated), consulted before any store query.
fn env_snap_id(name: &str) -> Option<String> {
    let spec = std::env::var("NAU_SNAP_IDS").ok()?;
    for pair in spec.split([',', ' ', '\t']) {
        let pair = pair.trim();
        if let Some((n, id)) = pair.split_once('=') {
            if n.trim() == name && !id.trim().is_empty() {
                return Some(id.trim().to_string());
            }
        }
    }
    None
}

/// Client for querying and downloading from the Snap Store.
pub struct StoreClient;

/// The curl binary path through the tools module (issue #101): curl
/// resolves PATH-first with the provisioned fallback, and `ensure` is its
/// mid-build entry (for curl it is the resolve path).
fn curl_tool() -> miette::Result<PathBuf> {
    let resolved = crate::tools::ensure(crate::tools::ToolName::Curl)
        .map_err(|e| miette::miette!("resolve curl: {e}"))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path,
    })
}

impl StoreClient {
    /// Query the store for a snap's metadata.
    ///
    /// Returns the channel map for all architectures and tracks.
    fn query_info_with(runner: &dyn CommandRunner, name: &str) -> miette::Result<SnapInfoResponse> {
        let url = format!("https://api.snapcraft.io/v2/snaps/info/{name}");

        let argv = vec![
            curl_tool()?.to_string_lossy().into_owned(),
            "-s".to_string(),
            "-H".to_string(),
            "Snap-Device-Series: 16".to_string(),
            url,
        ];
        let output = runner
            .run(&argv)
            .map_err(|e| miette::miette!("curl not found: {e}"))?;

        if output.code != 0 {
            return Err(miette::miette!(
                "failed to query snap store for '{name}': {}",
                output.stderr.trim()
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
        Self::resolve_with(&crate::command::RealRunner, pin, channel, arch)
    }

    /// The store snap-id for one snap name (the top-level `snap-id` of the
    /// `/v2/snaps/info` response) — the identity UC model assertions and
    /// seed.yaml carry for every system snap. `NAU_SNAP_IDS` entries
    /// (`name=id`, comma- or whitespace-separated) override per-name, so an
    /// offline build can pin the identities it already knows.
    pub fn snap_id_with(runner: &dyn CommandRunner, name: &str) -> miette::Result<String> {
        if let Some(id) = env_snap_id(name) {
            return Ok(id);
        }
        let info = Self::query_info_with(runner, name)?;
        info.snap_id.ok_or_else(|| {
            miette::miette!(
                "store returned no snap-id for '{name}' — the UC seed identifies every \
                 system snap by snap-id (or set NAU_SNAP_IDS='{name}=<snap-id>')"
            )
        })
    }

    /// [`Self::resolve`] with the host tool runner injected.
    pub fn resolve_with(
        runner: &dyn CommandRunner,
        pin: &SnapRef,
        channel: &str,
        arch: &str,
    ) -> miette::Result<ResolvedSnap> {
        // If fully pinned, we still need the download URL from the store
        let info = Self::query_info_with(runner, &pin.name)?;

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

        // ADR-0011 step (b): the digest and URL above come from one unsigned
        // channel-map response (TOFU). Break it by requiring a signed
        // snap-revision assertion binding digest → (snap-id, revision, size)
        // under the Canonical-rooted key chain before the URL is trusted.
        let pinned_by_user = pin.revision.is_some() && pin.sha3_384.is_some();
        if let Err(e) = crate::r#assert::verify_revision_with(
            runner,
            &pin.name,
            info.snap_id.as_deref(),
            store_revision,
            &sha3_384,
            Some(entry.download.size),
        ) {
            match e {
                crate::r#assert::AssertError::Network { .. } if pinned_by_user => {
                    eprintln!(
                        "warning: snap '{}': assertion store unreachable ({e}); \
                         proceeding on the explicit lockfile/index pin — \
                         first-seen continuity only, not cryptographic proof",
                        pin.name
                    );
                }
                _ => {
                    return Err(miette::miette!(
                        "snap '{}': refusing to trust the store response: {e}",
                        pin.name
                    ));
                }
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
    pub fn download(
        runner: &dyn CommandRunner,
        resolved: &ResolvedSnap,
        output_dir: &Path,
    ) -> miette::Result<PathBuf> {
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

        let argv = vec![
            curl_tool()?.to_string_lossy().into_owned(),
            "-fsSL".to_string(),
            "-o".to_string(),
            output_path.to_string_lossy().into_owned(),
            resolved.download_url.clone(),
        ];
        let out = runner
            .run(&argv)
            .map_err(|e| miette::miette!("curl not found: {e}"))?;

        if out.code != 0 {
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
        runner: &dyn CommandRunner,
        pin: &SnapRef,
        channel: &str,
        arch: &str,
        cache_dir: &Path,
    ) -> miette::Result<PathBuf> {
        let resolved = Self::resolve(pin, channel, arch)?;
        let path = Self::download(runner, &resolved, cache_dir)?;
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
