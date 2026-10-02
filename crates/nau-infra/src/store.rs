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

    /// The deterministic cache filename [`Self::download`] writes —
    /// shared so a pin-first lookup can never drift from it (issue
    /// #331).
    fn cached_snap_filename(name: &str, revision: u32, sha3_384: &str) -> String {
        format!("{name}_{revision}_{sha3_384}.snap")
    }

    /// Pin-first local resolution (issue #331, elimination family): a
    /// FULLY pinned ref (revision + sha3-384) whose payload is already
    /// in the cache under the deterministic download filename — and
    /// whose bytes still hash to the pinned digest — IS the resolution.
    /// Returns the verified cached path with zero store routes.
    ///
    /// `None` falls back to the store-verify path, never a guess: an
    /// incomplete pin (resolving it IS the store query — channel head,
    /// refresh) or a missing local blob. A PRESENT blob whose bytes
    /// mismatch the pin fails closed HERE: the store path would not
    /// re-download (the cached filename exists) and would fail the same
    /// digest check at [`Self::fetch`]'s final verify — after the
    /// resolve's round trips were spent for nothing.
    pub fn pinned_cached_payload(
        pin: &SnapRef,
        cache_dir: &Path,
    ) -> Option<miette::Result<PathBuf>> {
        let (revision, sha3_384) = match (pin.revision, pin.sha3_384.as_deref()) {
            (Some(rev), Some(sha)) => (rev, sha),
            _ => return None,
        };
        let path = cache_dir.join(Self::cached_snap_filename(&pin.name, revision, sha3_384));
        if !path.exists() {
            return None;
        }
        let computed = match sha3_384_file(&path) {
            Ok(computed) => computed,
            Err(e) => return Some(Err(e)),
        };
        if computed != sha3_384 {
            return Some(Err(miette::miette!(
                "cached payload {} no longer matches its pin: sha3-384 mismatch \
                 (expected {sha3_384}, got {computed}) — remove the file and re-fetch",
                path.display()
            )));
        }
        Some(Ok(path))
    }

    /// [`Self::resolve_with`] with the pin-first cache check (issue
    /// #331): a fully-pinned ref whose payload is already cached
    /// resolves locally with zero store routes; anything else takes the
    /// store-verify path unchanged. The local hit's `download_url` is
    /// empty — [`Self::download`] short-circuits on the same
    /// deterministic path, so it is never consulted (the same shape as
    /// the image staging index-pin hit).
    pub fn resolve_cached_with(
        runner: &dyn CommandRunner,
        pin: &SnapRef,
        channel: &str,
        arch: &str,
        cache_dir: &Path,
    ) -> miette::Result<ResolvedSnap> {
        match Self::pinned_cached_payload(pin, cache_dir) {
            Some(Ok(_)) => {
                eprintln!(
                    "  ✓ {} — pin held at cached payload (no store query)",
                    pin.name
                );
                Ok(ResolvedSnap {
                    name: pin.name.clone(),
                    revision: pin.revision.unwrap_or_default(),
                    sha3_384: pin.sha3_384.clone().unwrap_or_default(),
                    download_url: String::new(),
                })
            }
            // A present-but-corrupt cached payload fails closed without
            // network contact (see [`Self::pinned_cached_payload`]).
            Some(Err(e)) => Err(e),
            None => Self::resolve_with(runner, pin, channel, arch),
        }
    }

    /// [`Self::resolve_cached_with`] with the host tool runner.
    pub fn resolve_cached(
        pin: &SnapRef,
        channel: &str,
        arch: &str,
        cache_dir: &Path,
    ) -> miette::Result<ResolvedSnap> {
        Self::resolve_cached_with(&crate::command::RealRunner, pin, channel, arch, cache_dir)
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
        let filename =
            Self::cached_snap_filename(&resolved.name, resolved.revision, &resolved.sha3_384);
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
    ///
    /// Pin-first (issue #331): a fully-pinned ref whose payload is
    /// already cached — and whose bytes still verify against the pin —
    /// returns the cached path with zero store routes; everything else
    /// takes the resolve → download → verify path.
    pub fn fetch(
        runner: &dyn CommandRunner,
        pin: &SnapRef,
        channel: &str,
        arch: &str,
        cache_dir: &Path,
    ) -> miette::Result<PathBuf> {
        if let Some(verified) = Self::pinned_cached_payload(pin, cache_dir) {
            let path = verified?;
            eprintln!(
                "  ✓ {} revision {} — pin held at cached payload — sha3-384 verified",
                pin.name,
                pin.revision.unwrap_or_default()
            );
            return Ok(path);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use std::sync::Mutex;

    // ── pin-first local resolution (issue #331): the route-count seam ──
    //
    // A fully-pinned ref whose payload is already cached IS the
    // resolution: zero store routes. Baseline (before the pin-first
    // helper) every fully-pinned resolve spent the same three routes —
    // info + snap-revision + account-key — re-verifying an unchanged
    // pin; the tests below pin the after-number at 0 and keep the
    // fail-closed fallbacks (missing blob, incomplete pin) on the
    // store-verify path.

    const HELLO_SNAP_ID: &str = "buPKUD3TKqCOgLEjjHx5kSiCpIs5cMuQ";
    const HELLO_DIGEST_HEX: &str =
        "b07bdb78e762c2e6020c75fafc92055b323a6f8da3ab42a3963da5ade386aba11f77e3c8f919b8aa23f3aa5c06c844f9";
    const HELLO_SIZE: u64 = 20480;
    const SNAP_REVISION: &str =
        include_str!("../../../tests/fixtures/assertions/hello-world-rev29.snap-revision.assert");
    const STORE_ACCOUNT_KEY: &str =
        include_str!("../../../tests/fixtures/assertions/store.account-key.assert");

    struct Reply {
        code: i32,
        stdout: String,
        stderr: String,
    }

    fn ok_json(body: impl Into<String>) -> Reply {
        Reply {
            code: 0,
            stdout: body.into(),
            stderr: String::new(),
        }
    }

    fn hello_channel_map(track: &str, risk: &str) -> String {
        format!(
            r#"{{
                "channel-map": [
                    {{
                        "channel": {{"architecture": "amd64", "name": "{risk}", "track": "{track}", "risk": "{risk}"}},
                        "download": {{"sha3-384": "{HELLO_DIGEST_HEX}", "size": {HELLO_SIZE}, "url": "https://cdn.example/hello_29.snap"}},
                        "revision": 29
                    }}
                ],
                "snap-id": "{HELLO_SNAP_ID}"
            }}"#
        )
    }

    /// Scripted curl: the first route whose URL substring matches
    /// answers; no match panics (unexpected call). Every invocation is
    /// recorded — the route counter the #331 assertions read.
    struct FakeStore {
        routes: Mutex<Vec<(&'static str, Reply)>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeStore {
        fn new() -> FakeStore {
            FakeStore {
                routes: Mutex::new(Vec::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn route(self, url_part: &'static str, reply: Reply) -> FakeStore {
            self.routes.lock().unwrap().push((url_part, reply));
            self
        }

        fn snap_info(self, track: &str, risk: &str) -> FakeStore {
            self.route("snaps/info/", ok_json(hello_channel_map(track, risk)))
        }

        fn assertion_chain(self) -> FakeStore {
            self.route("snap-revision/", ok_json(SNAP_REVISION))
                .route("account-key/", ok_json(STORE_ACCOUNT_KEY))
        }

        /// How many curl invocations the client made (every `run` call
        /// — one subprocess per store route).
        fn route_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl CommandRunner for FakeStore {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(argv.last().cloned().unwrap_or_default());
            let url = argv.last().unwrap();
            for (part, reply) in self.routes.lock().unwrap().iter() {
                if url.contains(part) {
                    return Ok(RunnerOutput {
                        code: reply.code,
                        stdout: reply.stdout.clone().into_bytes(),
                        stderr: reply.stderr.clone(),
                    });
                }
            }
            panic!("unexpected curl invocation: {argv:?}");
        }
    }

    /// Runner for paths that must not shell out at all (short-circuits).
    struct NoRunner;

    impl CommandRunner for NoRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            panic!("no subprocess expected: {argv:?}");
        }
    }

    /// The sha3-384 of `b"hello world\n"`, used as the fixture pin
    /// digest (the bytes the cache helper writes below hash to it).
    fn hello_payload_sha() -> &'static str {
        "28fc308d4d5c1ef9e60acedb13c3a1fcf7266560602c639000580ae3541dea5c\
         e78a685de897e96b65a0fc15515c3780"
    }

    fn hello_pin(revision: Option<u32>, sha3_384: Option<&str>) -> SnapRef {
        SnapRef {
            name: "hello-world".into(),
            revision,
            sha3_384: sha3_384.map(str::to_string),
        }
    }

    /// Cache the fixture payload under the deterministic download
    /// filename for `revision`, returning the fully-pinned ref + path.
    fn cache_hello_payload(dir: &Path, revision: u32) -> (SnapRef, PathBuf) {
        let sha = hello_payload_sha();
        let pin = hello_pin(Some(revision), Some(sha));
        let path = dir.join(format!("hello-world_{revision}_{sha}.snap"));
        std::fs::write(&path, b"hello world\n").unwrap();
        (pin, path)
    }

    #[test]
    fn pinned_cached_hit_resolves_with_zero_store_routes() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, _) = cache_hello_payload(dir.path(), 29);
        let resolved =
            StoreClient::resolve_cached_with(&NoRunner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        assert_eq!(resolved.sha3_384, hello_payload_sha());
        // The local hit needs no download URL: download() short-circuits
        // on the same deterministic path.
        assert_eq!(resolved.download_url, "");
    }

    #[test]
    fn pinned_cache_miss_falls_back_to_the_store_verify_path() {
        let dir = tempfile::tempdir().unwrap();
        // Same pin shape, nothing cached: the blob is missing, so the
        // store-verify path must run (never a local guess).
        let pin = hello_pin(Some(29), Some(HELLO_DIGEST_HEX));
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_cached_with(&runner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        // The baseline re-verify cost, unchanged for the fallback: info
        // + snap-revision + account-key.
        assert_eq!(runner.route_count(), 3);
    }

    #[test]
    fn pinned_corrupt_cache_fails_closed_without_store_contact() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, cached) = cache_hello_payload(dir.path(), 29);
        std::fs::write(&cached, b"corrupted bytes").unwrap();
        let err =
            StoreClient::resolve_cached_with(&NoRunner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap_err()
                .to_string();
        assert!(err.contains("sha3-384 mismatch"), "{err}");
        assert!(err.contains("remove the file"), "{err}");
    }

    #[test]
    fn incomplete_pin_ignores_the_cache_and_takes_the_store_path() {
        let dir = tempfile::tempdir().unwrap();
        // A payload IS cached — but the pin carries no revision/digest,
        // so resolving it is the store query's job (channel head).
        let _ = cache_hello_payload(dir.path(), 29);
        let pin = hello_pin(None, None);
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_cached_with(&runner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        assert_eq!(runner.route_count(), 3);
    }

    #[test]
    fn fetch_of_a_pinned_cached_snap_makes_no_store_routes() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, cached) = cache_hello_payload(dir.path(), 29);
        let path =
            StoreClient::fetch(&NoRunner, &pin, "latest/stable", "amd64", dir.path()).unwrap();
        assert_eq!(path, cached);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world\n");
    }
}
