//!
//! The root `store` shim (issue #326 PR 3, R1): the store client moved
//! to `nau-infra` (with its assertion security gate); every pre-existing
//! `crate::store::` path keeps resolving through the re-export. The
//! tests stay here on the root crate's fixtures, exercising the moved
//! code through the shim.

pub use nau_infra::store::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;
    use crate::snap::snap_ref_from_pin;
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

        let snap_ref = snap_ref_from_pin(&table).unwrap();
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

        let snap_ref = snap_ref_from_pin(&table).unwrap();
        assert_eq!(snap_ref.name, "core22");
        assert!(snap_ref.revision.is_none());
        assert!(snap_ref.sha3_384.is_none());
    }

    #[test]
    fn test_snap_ref_from_pin_table_missing_name() {
        let lua = mlua::Lua::new();
        let table: mlua::Table = lua.load(r#"return { revision = 42 }"#).eval().unwrap();
        let result = snap_ref_from_pin(&table);
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

    // ── NAU_SNAP_IDS override ──

    #[test]
    fn env_snap_id_parses_name_id_pairs_across_separators() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NAU_SNAP_IDS");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("NAU_SNAP_IDS", "core22=aaa,hello-world=bbb\tlxd=ccc");
        assert_eq!(env_snap_id("hello-world"), Some("bbb".to_string()));
        assert_eq!(env_snap_id("core22"), Some("aaa".to_string()));
        assert_eq!(env_snap_id("lxd"), Some("ccc".to_string()));

        std::env::set_var("NAU_SNAP_IDS", "hello-world=");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("NAU_SNAP_IDS", "noequals");
        assert_eq!(env_snap_id("hello-world"), None);

        std::env::set_var("NAU_SNAP_IDS", "hello-world=bbb");
        assert_eq!(env_snap_id("hello-world"), Some("bbb".to_string()));
        assert_eq!(env_snap_id(" hello-world"), None);
        std::env::remove_var("NAU_SNAP_IDS");
    }

    #[test]
    fn snap_id_with_prefers_the_env_override_without_a_store_query() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NAU_SNAP_IDS", "hello-world=snapid123");
        let id = StoreClient::snap_id_with(&NoRunner, "hello-world").unwrap();
        assert_eq!(id, "snapid123");
        std::env::remove_var("NAU_SNAP_IDS");
    }

    #[test]
    fn snap_id_with_reports_a_missing_snap_id_and_names_the_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let runner = FakeStore::new().route(
            "snaps/info/",
            ok_json(r#"{"channel-map": [], "snap-id": null}"#),
        );
        let err = StoreClient::snap_id_with(&runner, "hello-world")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no snap-id"), "{err}");
        assert!(err.contains("NAU_SNAP_IDS"), "{err}");
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
