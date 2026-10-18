
    use super::*;
    use nau_infra::command::RunnerOutput;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// A runner that fails the test the moment anything is executed —
    /// proves the skip paths never shell out.
    struct NeverRunner;

    impl CommandRunner for NeverRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            panic!("no subprocess expected, got {argv:?}");
        }
    }

    /// Routes on argv[1] (`status` / `funnel`) or argv[0] (`curl`),
    /// the exact surface the funnel steps drive.
    struct FakeTailscale {
        /// The `tailscale status --json` document (the DNS name source).
        status_json: &'static str,
        /// Exit code + stderr for `tailscale funnel ...` calls.
        funnel_code: i32,
        funnel_stderr: &'static str,
        /// Exit code + stdout for `curl` calls (the -w status line).
        curl_code: i32,
        curl_status_line: &'static str,
        calls: Mutex<Vec<String>>,
    }

    impl FakeTailscale {
        fn new(status_json: &'static str) -> Self {
            FakeTailscale {
                status_json,
                funnel_code: 0,
                funnel_stderr: "",
                curl_code: 0,
                curl_status_line: "200",
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_curl(mut self, code: i32, status_line: &'static str) -> Self {
            self.curl_code = code;
            self.curl_status_line = status_line;
            self
        }

        fn with_funnel(mut self, code: i32, stderr: &'static str) -> Self {
            self.funnel_code = code;
            self.funnel_stderr = stderr;
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn summary(&self) -> String {
            self.calls().join(" | ")
        }
    }

    impl CommandRunner for FakeTailscale {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.join(" "));
            match argv[0].as_str() {
                "tailscale" => {
                    match (argv[1].as_str(), argv.get(2).map(|s| s.as_str())) {
                        // `tailscale status --json` (DNS name) and
                        // `tailscale funnel status --json` (the serve
                        // config — the live CLI shows the merged view)
                        // both read the status document.
                        ("status", _) | ("funnel", Some("status")) => Ok(RunnerOutput {
                            code: 0,
                            stdout: self.status_json.as_bytes().to_vec(),
                            stderr: String::new(),
                        }),
                        ("funnel", _) => Ok(RunnerOutput {
                            code: self.funnel_code,
                            stdout: Vec::new(),
                            stderr: self.funnel_stderr.to_string(),
                        }),
                        other => panic!("unexpected tailscale subcommand {other:?}"),
                    }
                }
                "curl" => Ok(RunnerOutput {
                    code: self.curl_code,
                    stdout: self.curl_status_line.as_bytes().to_vec(),
                    stderr: String::new(),
                }),
                other => panic!("unexpected program {other}"),
            }
        }
    }

    /// This host's shape: DNSName carries a trailing dot, as tailscale
    /// reports it.
    const STATUS_JSON: &str = r#"{"Self":{"DNSName":"book3.tail9e1045.ts.net.","Online":true}}"#;

    /// A serve config holding ONLY a 443 tailnet-only entry — the port
    /// the funnel code must never touch.
    const STATUS_443_SERVE_JSON: &str = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"book3.tail9e1045.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9119"}}}}}"#;

    /// The funnel config nau owns: 8443 fronting the front port.
    const STATUS_8443_FUNNEL_JSON: &str = r#"{"TCP":{"8443":{"HTTPS":true,"Funnel":true}},"Web":{"book3.tail9e1045.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8477"}}}}}"#;

    const PUBLISH_URL: &str = "https://book3.tail9e1045.ts.net:8443/publish";

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("nau.lua");
        std::fs::write(
            &path,
            format!(
                "-- operator stuff\n{begin}\nworkers = workers or {{}}\n{body}{end}\n",
                begin = super::super::BLOCK_BEGIN,
                body = body,
                end = super::super::BLOCK_END
            ),
        )
        .unwrap();
        path
    }

    const ENTRY_LINE: &str =
        "table.insert(workers, { address = \"ssh://root@1.2.3.4\", host_key = \"SHA256:abc\" })\n";


mod window_up;
