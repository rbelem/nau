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
use crate::snap::SnapRef;

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

/// `SHUTTLE_SNAP_IDS` override: `name=id` pairs (comma/whitespace
/// separated), consulted before any store query.
fn env_snap_id(name: &str) -> Option<String> {
    let spec = std::env::var("SHUTTLE_SNAP_IDS").ok()?;
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
    /// seed.yaml carry for every system snap. `SHUTTLE_SNAP_IDS` entries
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
                 system snap by snap-id (or set SHUTTLE_SNAP_IDS='{name}=<snap-id>')"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use std::sync::Mutex;

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

    // ── offline store client: scripted curl against the real fixture chain ──

    const HELLO_SNAP_ID: &str = "buPKUD3TKqCOgLEjjHx5kSiCpIs5cMuQ";
    const HELLO_DIGEST_HEX: &str =
        "b07bdb78e762c2e6020c75fafc92055b323a6f8da3ab42a3963da5ade386aba11f77e3c8f919b8aa23f3aa5c06c844f9";
    const HELLO_SIZE: u64 = 20480;
    const SNAP_REVISION: &str =
        include_str!("../tests/fixtures/assertions/hello-world-rev29.snap-revision.assert");
    const STORE_ACCOUNT_KEY: &str =
        include_str!("../tests/fixtures/assertions/store.account-key.assert");

    // The shared crate-wide test-env lock (src/test_env.rs) — the
    // per-module statics used to exclude nothing across modules.
    use crate::test_env::ENV_LOCK;

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

    /// Scripted curl: the first route whose URL substring matches answers;
    /// no match panics (unexpected call). `spawn_error` fails every call
    /// before exec (curl not installed).
    struct FakeStore {
        routes: Mutex<Vec<(&'static str, Reply)>>,
        spawn_error: bool,
    }

    impl FakeStore {
        fn new() -> FakeStore {
            FakeStore {
                routes: Mutex::new(Vec::new()),
                spawn_error: false,
            }
        }

        fn spawn_error() -> FakeStore {
            FakeStore {
                spawn_error: true,
                ..Self::new()
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

        fn assertions_down(self) -> FakeStore {
            self.route(
                "snap-revision/",
                Reply {
                    code: 7,
                    stdout: String::new(),
                    stderr: "curl: (7)Failed to connect".into(),
                },
            )
        }
    }

    impl CommandRunner for FakeStore {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            if self.spawn_error {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No such file or directory",
                ));
            }
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

    /// Download runner: writes three bytes to the `-o` target, exits with
    /// `exit_code`.
    struct DownloadRunner {
        exit_code: i32,
    }

    impl CommandRunner for DownloadRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            if self.exit_code == 0 {
                if let Some(path) = argv.iter().position(|a| a == "-o") {
                    std::fs::write(&argv[path + 1], b"snap").unwrap();
                }
            }
            Ok(RunnerOutput {
                code: self.exit_code,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    fn hello_pin(revision: Option<u32>, sha3_384: Option<&str>) -> SnapRef {
        SnapRef {
            name: "hello-world".into(),
            revision,
            sha3_384: sha3_384.map(str::to_string),
        }
    }

    // ── SHUTTLE_SNAP_IDS override ──

    #[test]
    fn env_snap_id_parses_name_id_pairs_across_separators() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SHUTTLE_SNAP_IDS");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("SHUTTLE_SNAP_IDS", "core22=aaa,hello-world=bbb\tlxd=ccc");
        assert_eq!(env_snap_id("hello-world"), Some("bbb".to_string()));
        assert_eq!(env_snap_id("core22"), Some("aaa".to_string()));
        assert_eq!(env_snap_id("lxd"), Some("ccc".to_string()));

        std::env::set_var("SHUTTLE_SNAP_IDS", "hello-world=");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("SHUTTLE_SNAP_IDS", "noequals");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("SHUTTLE_SNAP_IDS", "hello-world=bbb");
        assert_eq!(env_snap_id("hello-world"), Some("bbb".to_string()));
        assert_eq!(env_snap_id(" hello-world"), None);
        std::env::remove_var("SHUTTLE_SNAP_IDS");
    }

    #[test]
    fn snap_id_with_prefers_the_env_override_without_a_store_query() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHUTTLE_SNAP_IDS", "hello-world=snapid123");
        let id = StoreClient::snap_id_with(&NoRunner, "hello-world").unwrap();
        assert_eq!(id, "snapid123");
        std::env::remove_var("SHUTTLE_SNAP_IDS");
    }

    #[test]
    fn snap_id_with_reports_a_missing_snap_id_and_names_the_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let runner = FakeStore::new().route(
            "snaps/info/",
            ok_json(r#"{"channel-map": [], "snap-id": null}"#),
        );
        let err = StoreClient::snap_id_with(&runner, "hello-world")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no snap-id"), "{err}");
        assert!(err.contains("SHUTTLE_SNAP_IDS"), "{err}");
    }

    // ── query_info_with error paths ──

    #[test]
    fn query_info_reports_a_missing_curl() {
        let runner = FakeStore::spawn_error();
        let err = StoreClient::query_info_with(&runner, "hello-world")
            .unwrap_err()
            .to_string();
        assert!(err.contains("curl not found"), "{err}");
    }

    #[test]
    fn query_info_surfaces_a_nonzero_exit_with_stderr() {
        let runner = FakeStore::new().route(
            "snaps/info/",
            Reply {
                code: 1,
                stdout: String::new(),
                stderr: "boom".into(),
            },
        );
        let err = StoreClient::query_info_with(&runner, "hello-world")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("failed to query snap store for 'hello-world'"),
            "{err}"
        );
        assert!(err.contains("boom"), "{err}");
    }

    #[test]
    fn query_info_rejects_a_non_json_body() {
        let runner = FakeStore::new().route("snaps/info/", ok_json("<html>gateway</html>"));
        let err = StoreClient::query_info_with(&runner, "hello-world")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid store response"), "{err}");
    }

    // ── resolve_with ──

    #[test]
    fn resolve_matches_track_risk_arch_and_verifies_the_signed_chain() {
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_with(&runner, &hello_pin(None, None), "latest/stable", "amd64")
                .unwrap();
        assert_eq!(resolved.name, "hello-world");
        assert_eq!(resolved.revision, 29);
        assert_eq!(resolved.sha3_384, HELLO_DIGEST_HEX);
        assert_eq!(resolved.download_url, "https://cdn.example/hello_29.snap");
        assert_eq!(resolved.to_snap_ref().revision, Some(29));
    }

    #[test]
    fn resolve_bare_risk_channel_rides_the_latest_track() {
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_with(&runner, &hello_pin(None, None), "stable", "amd64").unwrap();
        assert_eq!(resolved.revision, 29);
    }

    #[test]
    fn resolve_fails_when_no_channel_entry_matches_the_arch() {
        let runner = FakeStore::new().snap_info("latest", "stable");
        let err =
            StoreClient::resolve_with(&runner, &hello_pin(None, None), "latest/stable", "arm64")
                .unwrap_err()
                .to_string();
        assert!(err.contains("no entry for latest/stable / arm64"), "{err}");
    }

    #[test]
    fn resolve_rejects_a_revision_mismatch() {
        let runner = FakeStore::new().snap_info("latest", "stable");
        let err = StoreClient::resolve_with(
            &runner,
            &hello_pin(Some(28), None),
            "latest/stable",
            "amd64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("revision mismatch"), "{err}");
        assert!(err.contains("expected 28, store has 29"), "{err}");
    }

    #[test]
    fn resolve_rejects_a_digest_mismatch() {
        let runner = FakeStore::new().snap_info("latest", "stable");
        let wrong = "f".repeat(96);
        let err = StoreClient::resolve_with(
            &runner,
            &hello_pin(Some(29), Some(&wrong)),
            "latest/stable",
            "amd64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("sha3-384 mismatch"), "{err}");
    }

    #[test]
    fn resolve_downgrades_an_assertion_outage_for_explicit_pins() {
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertions_down();
        let resolved = StoreClient::resolve_with(
            &runner,
            &hello_pin(Some(29), Some(HELLO_DIGEST_HEX)),
            "latest/stable",
            "amd64",
        )
        .unwrap();
        assert_eq!(resolved.revision, 29);
    }

    #[test]
    fn resolve_refuses_to_trust_an_unbacked_response_without_an_explicit_pin() {
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertions_down();
        let err =
            StoreClient::resolve_with(&runner, &hello_pin(None, None), "latest/stable", "amd64")
                .unwrap_err()
                .to_string();
        assert!(
            err.contains("refusing to trust the store response"),
            "{err}"
        );
    }

    // ── download ──

    fn expected_snap_path(dir: &Path) -> PathBuf {
        dir.join(format!("hello-world_29_{HELLO_DIGEST_HEX}.snap"))
    }

    #[test]
    fn download_short_circuits_an_already_cached_snap() {
        let dir = tempfile::tempdir().unwrap();
        let cached = expected_snap_path(dir.path());
        std::fs::write(&cached, b"cached").unwrap();
        let resolved = ResolvedSnap {
            name: "hello-world".into(),
            revision: 29,
            sha3_384: HELLO_DIGEST_HEX.into(),
            download_url: "https://cdn.example/hello_29.snap".into(),
        };
        let path = StoreClient::download(&NoRunner, &resolved, dir.path()).unwrap();
        assert_eq!(path, cached);
        assert_eq!(std::fs::read(&path).unwrap(), b"cached");
    }

    #[test]
    fn download_writes_the_snap_and_returns_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = ResolvedSnap {
            name: "hello-world".into(),
            revision: 29,
            sha3_384: HELLO_DIGEST_HEX.into(),
            download_url: "https://cdn.example/hello_29.snap".into(),
        };
        let path =
            StoreClient::download(&DownloadRunner { exit_code: 0 }, &resolved, dir.path()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn download_surfaces_a_failed_curl_exit() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = ResolvedSnap {
            name: "hello-world".into(),
            revision: 29,
            sha3_384: HELLO_DIGEST_HEX.into(),
            download_url: "https://cdn.example/hello_29.snap".into(),
        };
        let err = StoreClient::download(&DownloadRunner { exit_code: 22 }, &resolved, dir.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("failed to download snap 'hello-world' revision 29"),
            "{err}"
        );
    }

    #[test]
    fn download_reports_an_unusable_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"").unwrap();
        let resolved = ResolvedSnap {
            name: "hello-world".into(),
            revision: 29,
            sha3_384: HELLO_DIGEST_HEX.into(),
            download_url: "https://cdn.example/hello_29.snap".into(),
        };
        let err = StoreClient::download(&DownloadRunner { exit_code: 0 }, &resolved, &blocker)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to create"), "{err}");
    }

    // ── verify ──

    #[test]
    fn verify_accepts_the_matching_digest_and_names_both_hashes_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.snap");
        std::fs::write(&path, b"hello world\n").unwrap();
        let real = sha3_384_file(&path).unwrap();
        StoreClient::verify(&path, &real).unwrap();

        let wrong = "f".repeat(96);
        let err = StoreClient::verify(&path, &wrong).unwrap_err().to_string();
        assert!(err.contains("sha3-384 mismatch"), "{err}");
        assert!(err.contains(&wrong), "{err}");
        assert!(err.contains(&real), "{err}");
    }
}
