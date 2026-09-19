//! The `fetch()` DSL global: eval-time HTTP GET for floating upstream
//! version resolution (opencode-bin pattern).
//!
//! Proven with a loopback HTTP server: the worker subprocess curls the
//! server, the definition parses the body, and the resolved value lands
//! in the snap's version. Also proves the named refusal when
//! `SHUTTLE_OFFLINE` gates the eval, and that the loopback response
//! shape round-trips through the worker IPC unharmed.

use std::io::{Read, Write};
use std::net::TcpListener;

/// Serve one JSON body on a loopback port, then keep accepting until the
/// process ends (the worker curls exactly once per eval).
fn spawn_loopback(body: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn eval_version(source: &str) -> Result<String, String> {
    let outputs =
        shuttle::lua::evaluate_string("fetch-test", source).map_err(|e| format!("{e:#}"))?;
    outputs
        .get("default")
        .map(|meta| meta.version.clone())
        .ok_or_else(|| "no default output".to_string())
}

#[test]
fn fetch_resolves_version_from_loopback_json() {
    let port = spawn_loopback(r#"{"channel":"latest","name":"cli","version":"9.9.9"}"#);
    let source = format!(
        r#"
        local body = fetch("http://127.0.0.1:{port}/update/api/latest/cli/npm")
        local ver = string.match(body, '"version":"([%w%.]+)"')
        assert(ver and #ver > 0, "no version in fetched body")
        return {{
            default = snap {{
                name = "fetch-probe",
                version = ver,
            }},
        }}
        "#
    );
    let version = eval_version(&source).expect("fetch-based eval must succeed");
    assert_eq!(version, "9.9.9", "the fetched version must reach snap.yaml");
}

#[test]
fn fetch_is_refused_by_name_when_disallowed() {
    // Drives the worker directly with allow_fetch: false — the hermetic
    // path (attack-isolation requests, --offline via the CLI's env gate)
    // — so no process-global env mutation races the sibling tests.
    let req = shuttle::isolate::EvalRequest {
        prelude: shuttle::dsl::INIT_LUA.to_string(),
        index_data: serde_json::json!({ "version": 1, "snaps": [] }),
        arch: "amd64".into(),
        sources: Default::default(),
        entry: r#"
            return {{
                default = snap {{
                    name = "fetch-offline",
                    version = fetch("http://127.0.0.1:1/x"),
                }},
            }}
        "#
        .to_string(),
        entry_label: "fetch-offline".into(),
        allow_fetch: false,
    };
    let err = match shuttle::isolate::run_eval(&req) {
        Err(e) => format!("{e:#}"),
        Ok(ok) => match ok.diagnostics.first() {
            Some(d) => d.clone(),
            None => panic!("expected a refusal, got clean eval"),
        },
    };
    assert!(
        err.contains("fetch() is disabled"),
        "refusal must be named, got: {err}"
    );
}

#[test]
fn fetch_refuses_non_http_schemes() {
    let result = eval_version(
        r#"
        return {{
            default = snap {{
                name = "fetch-scheme",
                version = fetch("file:///etc/passwd"),
            }},
        }}
        "#,
    );
    let err = result.expect_err("non-http(s) schemes must be refused");
    assert!(
        err.contains("only http(s) URLs"),
        "refusal must name the scheme rule, got: {err}"
    );
}
