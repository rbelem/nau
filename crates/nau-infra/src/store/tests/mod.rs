
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
        include_str!("../../../../../tests/fixtures/assertions/hello-world-rev29.snap-revision.assert");
    const STORE_ACCOUNT_KEY: &str =
        include_str!("../../../../../tests/fixtures/assertions/store.account-key.assert");

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


mod pinned_cached;
