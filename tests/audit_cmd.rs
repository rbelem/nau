//! `shuttle audit` integration tests (issue #52).
//!
//! Drives the real binary over fixture lockfiles against a mock OSV
//! querybatch server (an in-test TCP listener speaking just enough HTTP
//! for curl): confirmed version-matched hits gate the exit code, name-only
//! snap hits and offline degradation never do, the response cache serves
//! repeat audits with the network down, and `--update` bypasses it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// What the mock OSV server knows. `lodash_vuln` models the database
/// CHANGING between runs (a new advisory published); `requests` counts
/// network passes (cache-bypass proof).
#[derive(Default)]
struct MockState {
    requests: usize,
    lodash_vuln: bool,
}

type SharedState = Arc<Mutex<MockState>>;

/// Serve one HTTP request per connection until the test process exits:
/// parse the querybatch POST, answer per query from `state`.
fn mock_result(q: &serde_json::Value, state: &MockState) -> serde_json::Value {
    let name = q
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");
    let version = q
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let vuln = |id: &str, cve: &str, summary: &str| serde_json::json!({"id": id, "aliases": [cve], "summary": summary});
    match (name, version) {
        ("lodash", "4.17.20") if state.lodash_vuln => serde_json::json!({
            "vulns": [vuln("GHSA-p6mc-mr8w-3g3r", "CVE-2020-8203",
                           "Prototype pollution in lodash")]
        }),
        ("core22", "") => {
            // Distinct ids per ecosystem — multi-ecosystem name matches
            // must count separately in the summary.
            let id = if q["package"]["ecosystem"] == "Ubuntu" {
                "GHSA-ubu-core22"
            } else {
                "GHSA-deb-core22"
            };
            serde_json::json!({
                "vulns": [vuln(id, "CVE-2026-9999", "speculative core22 advisory")]
            })
        }
        _ => serde_json::json!({}),
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut body_start = None;
    let mut total = 0;
    // Headers first (they arrive in one packet for curl-sized requests).
    loop {
        let n = stream.read(&mut buf[total..]).ok()?;
        if n == 0 {
            return None;
        }
        total += n;
        if body_start.is_none() {
            if let Some(pos) = find_subsequence(&buf[..total], b"\r\n\r\n") {
                body_start = Some(pos + 4);
            }
        }
        if let Some(start) = body_start {
            let head = String::from_utf8_lossy(&buf[..start]);
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())
                })
                .flatten()
                .unwrap_or(0);
            if total >= start + len {
                return Some(buf[start..start + len].to_vec());
            }
        }
        if total == buf.len() {
            buf.resize(total * 2, 0);
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn serve_connection(mut stream: std::net::TcpStream, state: SharedState) {
    let Some(body) = read_request(&mut stream) else {
        return;
    };
    let queries: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::json!({"queries": []}));
    let mut state = state.lock().unwrap();
    state.requests += 1;
    let results: Vec<serde_json::Value> = queries["queries"]
        .as_array()
        .map(|qs| qs.iter().map(|q| mock_result(q, &state)).collect())
        .unwrap_or_default();
    let response = serde_json::json!({ "results": results });
    let body = serde_json::to_string(&response).unwrap_or_default();
    let http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(http.as_bytes());
    let _ = stream.flush();
}

/// Spawn the mock; returns (url, state). The accept thread detaches —
/// it dies with the test process.
fn spawn_mock() -> (String, SharedState) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let state: SharedState = Arc::new(Mutex::new(MockState::default()));
    let thread_state = Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => serve_connection(s, Arc::clone(&thread_state)),
                Err(_) => continue,
            }
        }
    });
    (format!("http://127.0.0.1:{port}/v1/querybatch"), state)
}

/// A URL whose server does not exist: bind a port, then drop the
/// listener — connections refuse instantly (the offline simulation).
fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}/v1/querybatch")
}

/// Fixture lockfile: one registry-proven source pin, one deps-bearing
/// pod package, one store snap.
fn write_lockfile(root: &std::path::Path) -> String {
    let path = root.join("shuttle.lock");
    std::fs::write(
        &path,
        r#"{
  "version": 1,
  "sources": {
    "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz": { "sha256": "aa" }
  },
  "packages": {
    "lodash": {
      "version": "4.17.20",
      "constraint": "^4.0.0",
      "deps": { "deps_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abcd", "fetched_at": "2026-01-01" }
    }
  },
  "snaps": {
    "core22": { "revision": 1847, "sha3-384": "d53e1c8a66cb03a99aed76f03c49c55ec6110e33c8cb4a12fb2c8715c9349a29321e877483a7bc7718fe552f2533397d" }
  }
}"#,
    )
    .unwrap();
    path.to_str().unwrap().to_string()
}

struct AuditRun {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_audit(lockfile: &str, url: &str, cache_dir: &std::path::Path, extra: &[&str]) -> AuditRun {
    let bin = env!("CARGO_BIN_EXE_shuttle");
    let mut cmd = Command::new(bin);
    cmd.arg("audit")
        .arg("--lockfile")
        .arg(lockfile)
        .args(extra)
        .env("SHUTTLE_OSV_URL", url)
        .env("SHUTTLE_AUDIT_CACHE", cache_dir)
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    let out = cmd.output().expect("failed to spawn shuttle audit");
    AuditRun {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn fresh_cache() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// A confirmed version-matched advisory is an ERROR finding and gates the
/// exit code; the deps-closure under-report is surfaced alongside it.
#[test]
fn audit_confirmed_vuln_errors_and_exits_nonzero() {
    let (url, state) = spawn_mock();
    state.lock().unwrap().lodash_vuln = true;
    let dir = tempfile::tempdir().unwrap();
    let lockfile = write_lockfile(dir.path());
    let cache = fresh_cache();

    let run = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout)
        .unwrap_or_else(|e| panic!("--json must emit valid JSON ({e}): {}", run.stdout));
    assert_eq!(report["ok"], serde_json::Value::Bool(false));
    assert_eq!(report["errors"], 1);
    let findings = report["findings"].as_array().expect("findings array");
    let confirmed = findings
        .iter()
        .find(|f| f["severity"] == "error")
        .expect("one confirmed error");
    assert_eq!(confirmed["check"], "osv");
    assert_eq!(confirmed["package"], "lodash");
    let msg = confirmed["message"].as_str().unwrap();
    assert!(
        msg.contains("GHSA-p6mc-mr8w-3g3r")
            && msg.contains("CVE-2020-8203")
            && msg.contains("lodash 4.17.20")
            && msg.contains("resolved version pinned in the lockfile"),
        "{msg}"
    );
    // The closure under-report warning ships beside the confirmed hit.
    assert!(
        findings.iter().any(|f| f["severity"] == "warn"
            && f["message"]
                .as_str()
                .is_some_and(|m| m.contains("dependency closure"))),
        "{findings:?}"
    );
}

/// A name-only snap hit is ONE bounded summary WARNING naming the
/// revision gap — it never gates the exit code, however many advisories
/// name-match.
#[test]
fn audit_name_only_snap_hit_warns_and_exits_zero() {
    let (url, _) = spawn_mock();
    let dir = tempfile::tempdir().unwrap();
    let lockfile = write_lockfile(dir.path());
    let cache = fresh_cache();

    let run = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let snap_findings: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["package"] == "core22")
        .collect();
    assert_eq!(
        snap_findings.len(),
        1,
        "one summary per snap: {snap_findings:?}"
    );
    assert_eq!(snap_findings[0]["severity"], "warn");
    let msg = snap_findings[0]["message"].as_str().unwrap();
    assert!(
        msg.contains("2 advisories name-match snap 'core22'")
            && msg.contains("Debian 1")
            && msg.contains("Ubuntu 1")
            && msg.contains("1847")
            && msg.contains("NONE can be confirmed"),
        "{msg}"
    );
}

/// Offline with an empty cache: every queryable pin degrades to a named
/// unaudited warning carrying the `--update` hint; exit stays 0.
#[test]
fn audit_offline_degrades_to_update_hint_warnings() {
    let url = dead_url();
    let dir = tempfile::tempdir().unwrap();
    let lockfile = write_lockfile(dir.path());
    let cache = fresh_cache();

    let run = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(
        report["database"]["degraded"],
        serde_json::Value::Bool(true)
    );
    let findings = report["findings"].as_array().unwrap();
    // lodash (version query) + core22 (name query) unaudited; the
    // registry source left-pad is clean-parseable and also unaudited.
    let unaudited: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| {
            f["message"]
                .as_str()
                .is_some_and(|m| m.contains("unaudited"))
        })
        .collect();
    assert_eq!(unaudited.len(), 3, "{findings:?}");
    for f in &unaudited {
        assert!(
            f["hint"].as_str().is_some_and(|h| h.contains("--update")),
            "{f}"
        );
    }
}

/// Cache roundtrip: an online audit primes the cache; a follow-up audit
/// with the network down still reports the confirmed finding (stale but
/// gating), tagged with its fetch date.
#[test]
fn audit_cached_results_serve_offline_and_stay_error() {
    let (url, state) = spawn_mock();
    state.lock().unwrap().lodash_vuln = true;
    let dir = tempfile::tempdir().unwrap();
    let lockfile = write_lockfile(dir.path());
    let cache = fresh_cache();

    let first = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(first.code, Some(1), "{}{}", first.stdout, first.stderr);

    let second = run_audit(&lockfile, &dead_url(), cache.path(), &["--json"]);
    assert_eq!(
        second.code,
        Some(1),
        "cache-served confirmed findings still gate: {}{}",
        second.stdout,
        second.stderr
    );
    let report: serde_json::Value = serde_json::from_str(&second.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let confirmed = findings
        .iter()
        .find(|f| f["severity"] == "error")
        .expect("cache-served confirmed error");
    assert!(
        confirmed["message"]
            .as_str()
            .is_some_and(|m| m.contains("OSV data ")),
        "stale data must be dated: {confirmed}"
    );
    // No unaudited warnings: every query was served from cache.
    assert_eq!(report["database"]["unaudited"], 0);
}

/// The cache answers repeat audits without touching the network;
/// `--update` forces a fresh network pass even on a warm cache.
#[test]
fn audit_update_flag_bypasses_a_warm_cache() {
    let (url, state) = spawn_mock();
    let dir = tempfile::tempdir().unwrap();
    let lockfile = write_lockfile(dir.path());
    let cache = fresh_cache();

    let run = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(0));
    assert_eq!(
        state.lock().unwrap().requests,
        1,
        "first audit hits the API"
    );

    let run = run_audit(&lockfile, &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(0));
    assert_eq!(
        state.lock().unwrap().requests,
        1,
        "warm cache must not re-query"
    );

    let run = run_audit(&lockfile, &url, cache.path(), &["--json", "--update"]);
    assert_eq!(run.code, Some(0));
    assert_eq!(
        state.lock().unwrap().requests,
        2,
        "--update must bypass the cache"
    );
}

/// An unmapped source pin (nothing derivable) warns explicitly and never
/// gates.
#[test]
fn audit_unmapped_source_pin_warns() {
    let (url, _) = spawn_mock();
    let dir = tempfile::tempdir().unwrap();
    let lockfile = dir.path().join("shuttle.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "version": 1,
  "sources": { "https://example.com/downloads/blob.tar.gz": { "sha256": "bb" } }
}"#,
    )
    .unwrap();
    let cache = fresh_cache();
    let run = run_audit(lockfile.to_str().unwrap(), &url, cache.path(), &["--json"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let unmapped = findings
        .iter()
        .find(|f| f["package"] == "https://example.com/downloads/blob.tar.gz")
        .expect("unmapped finding");
    assert_eq!(unmapped["severity"], "warn");
    assert!(
        unmapped["message"]
            .as_str()
            .is_some_and(|m| m.contains("cannot audit")),
        "{unmapped}"
    );
}

/// A tampered lockfile (invalid JSON) is a hard error, not a clean
/// report.
#[test]
fn audit_tampered_lockfile_fails_hard() {
    let (url, _) = spawn_mock();
    let dir = tempfile::tempdir().unwrap();
    let lockfile = dir.path().join("shuttle.lock");
    std::fs::write(&lockfile, "{ definitely not json").unwrap();
    let cache = fresh_cache();
    let run = run_audit(
        lockfile.to_str().unwrap(),
        &url,
        cache.path(),
        &[] as &[&str],
    );
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr.contains("invalid lockfile"),
        "must name the lockfile problem: {}",
        run.stderr
    );
}
