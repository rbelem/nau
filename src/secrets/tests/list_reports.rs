use super::*;

#[test]
fn list_reports_references_and_cache_state_never_values() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp, _counter) = list_fixture();
    let cache = tmp.path().join("cache");
    // Miss before resolve.
    let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.cache == "miss"));
    assert_eq!(
        rows.iter().find(|r| r.key == "ENV_VAR").unwrap().reference,
        "env NAU_SECRETS_TEST_LIST"
    );
    // Resolve (warms the entry at generation 3), then hit.
    std::env::set_var("NAU_SECRETS_TEST_LIST", SENTINEL);
    let refs = folded_refs(tmp.path(), "work");
    let pod_dir = tmp.path().join("work");
    resolve_references(&pod_dir, "work", 3, &refs, Some(&cache)).unwrap();
    let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
    assert!(rows.iter().all(|r| r.cache == "hit"));
    // An entry recorded for an older generation lists as stale.
    let hash = decl_hash(&refs).unwrap();
    write_cache_entry(
        &pod_cache_entry_path(&cache, "work", &hash),
        &CacheEntry {
            generation: 9,
            values: BTreeMap::new(),
        },
    )
    .unwrap();
    let rows = list_pod(tmp.path(), "work", Some(&cache)).unwrap();
    std::env::remove_var("NAU_SECRETS_TEST_LIST");
    assert!(rows.iter().all(|r| r.cache == "stale"));
    // The rendered output must not carry a single value substring.
    let text = render_list_rows("work", &rows);
    assert!(!text.contains(SENTINEL), "value leaked into list output");
    assert!(text.contains("EXEC_VAR") && text.contains("ENV_VAR"));
    assert!(text.contains("hit") && text.contains("stale"));
}

// ── vault (issue #186): loopback KV v2 harness ──

#[test]
fn vault_happy_path_reads_field_through_the_kv_v2_route() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
    let _env = VaultEnv::new(Some(&server.addr), Some("caller-token"));
    let refs = vault_refs();
    let values = resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(values.get("V_TOKEN").map(String::as_str), Some(SENTINEL));
    // The wire shape: KV v2 route + the token header.
    assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
    assert_eq!(server.token_header(), "caller-token");
}

#[test]
fn vault_wrong_token_403_fails_named_and_the_body_never_leaks() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    // The canned body carries the sentinel AND the "wrong" token:
    // neither may reach the error string (D8).
    let server = VaultServer::start(
        "403 Forbidden",
        &format!("permission denied: {SENTINEL} token-t suspects"),
    );
    let _env = VaultEnv::new(Some(&server.addr), Some("wrong-token"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("403"), "{err}");
    assert!(err.contains("Forbidden"), "{err}");
    assert!(err.contains("source 'vault'"), "{err}");
    assert!(
        !err.contains(SENTINEL),
        "response body leaked into the error: {err}"
    );
    assert!(!err.contains("wrong-token"), "token leaked: {err}");
}

#[test]
fn vault_missing_path_404_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let server = VaultServer::start("404 Not Found", &format!("no such path {SENTINEL}"));
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("404"), "{err}");
    assert!(
        !err.contains(SENTINEL),
        "response body leaked into the error: {err}"
    );
}

#[test]
fn vault_missing_field_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    // The sentinel hides in a DIFFERENT field of the same secret.
    let body = format!(r#"{{"data":{{"data":{{"other":"{SENTINEL}"}}}}}}"#);
    let server = VaultServer::start("200 OK", &body);
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("no 'token' field"), "{err}");
    assert!(
        !err.contains(SENTINEL),
        "other field's value leaked into the error: {err}"
    );
}

#[test]
fn vault_non_string_field_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let body = format!(r#"{{"data":{{"data":{{"token":42,"other":"{SENTINEL}"}}}}}}"#);
    let server = VaultServer::start("200 OK", &body);
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("not a string"), "{err}");
    assert!(!err.contains(SENTINEL), "value leaked: {err}");
}

#[test]
fn vault_empty_field_fails_named_never_an_empty_value() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let server = VaultServer::start("200 OK", &vault_body(""));
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn vault_malformed_json_body_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let server = VaultServer::start("200 OK", &format!("totally not json {SENTINEL}"));
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("not valid JSON"), "{err}");
    assert!(
        !err.contains(SENTINEL),
        "body content leaked into the error: {err}"
    );
}

#[test]
fn vault_data_levels_missing_or_non_object_fail_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let cases: [(&str, String); 4] = [
        ("no .data", "{}".to_string()),
        (".data not an object", r#"{"data":42}"#.to_string()),
        (
            "no .data.data",
            r#"{"data":{"metadata":{"version":2}}}"#.to_string(),
        ),
        (
            ".data.data not an object",
            r#"{"data":{"data":"flat"}}"#.to_string(),
        ),
    ];
    for (what, body) in cases {
        let server = VaultServer::start("200 OK", &body);
        let _env = VaultEnv::new(Some(&server.addr), Some("t"));
        let err = format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        );
        assert!(
            err.contains(".data"),
            "{what}: failure must name the JSON shape: {err}"
        );
    }
}

#[test]
fn vault_trailing_slash_addr_is_normalized_before_joining() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
    // A double slash would hit /v1//secret/... and 404 on real
    // Vault — the normalization must prevent it.
    let _env = VaultEnv::new(Some(&format!("{}/", server.addr)), Some("t"));
    resolve_references(
        &pod,
        "p",
        3,
        &vault_refs(),
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(
        server.request_line(),
        "GET /v1/secret/data/app HTTP/1.1",
        "no doubled slash in the request line"
    );
}

#[test]
fn vault_addr_and_token_missing_or_empty_fail_named_separately() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let resolve_err = || -> String {
        format!(
            "{}",
            resolve_references(
                &pod,
                "p",
                3,
                &vault_refs(),
                Some(tmp.path().join("cache").as_path()),
            )
            .unwrap_err()
        )
    };
    // (a) both unset → the ADDR failure is named first.
    let _env = VaultEnv::new(None, None);
    let err = resolve_err();
    assert!(err.contains("VAULT_ADDR is not set"), "{err}");
    assert!(!err.contains("VAULT_TOKEN"), "{err}");
    // (b) addr set, token unset → the TOKEN failure, distinctly.
    let _env = VaultEnv::new(Some("http://127.0.0.1:1"), None);
    let err = resolve_err();
    assert!(err.contains("VAULT_TOKEN is not set"), "{err}");
    assert!(
        !err.contains("VAULT_ADDR"),
        "the addr failure must not be named for a token failure: {err}"
    );
    // (c) addr set-but-empty.
    let _env = VaultEnv::new(Some(""), Some("t"));
    let err = resolve_err();
    assert!(err.contains("VAULT_ADDR is set but empty"), "{err}");
    // (d) token set-but-empty.
    let _env = VaultEnv::new(Some("http://127.0.0.1:1"), Some(""));
    let err = resolve_err();
    assert!(err.contains("VAULT_TOKEN is set but empty"), "{err}");
}

#[test]
fn vault_transport_failure_fails_named_without_touching_values() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    // Port 1: nothing listens — a fast, deterministic refusal.
    let _env = VaultEnv::new(Some("http://127.0.0.1:1"), Some("t"));
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &vault_refs(),
            Some(tmp.path().join("cache").as_path()),
        )
        .unwrap_err()
    );
    assert!(err.contains("transport failure"), "{err}");
    assert!(err.contains("source 'vault'"), "{err}");
}

#[test]
fn vault_interior_newlines_in_the_value_survive() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let body = r#"{"data":{"data":{"token":"-----BEGIN\nLINE2\n-----END"}}}"#;
    let server = VaultServer::start("200 OK", body);
    let _env = VaultEnv::new(Some(&server.addr), Some("t"));
    let values = resolve_references(
        &pod,
        "p",
        3,
        &vault_refs(),
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(
        values.get("V_TOKEN").map(String::as_str),
        Some("-----BEGIN\nLINE2\n-----END"),
        "PEM shape rides verbatim (ADR-0042 D4)"
    );
}

// ── verbs: check ──

#[test]
fn check_reports_per_source_health_and_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (tmp, server, _env) = check_fixture();
    std::env::remove_var("NAU_SECRETS_TEST_CHECK");
    let rows = check_pod(tmp.path(), "work").unwrap();
    assert_eq!(rows.len(), 3);
    let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
    assert_eq!(by_key("VAULT_ITEM").status, "ok");
    assert_eq!(by_key("ENV_VAR").status, "failed");
    assert!(
        by_key("ENV_VAR").note.contains("NAU_SECRETS_TEST_CHECK"),
        "{}",
        by_key("ENV_VAR").note
    );
    assert_eq!(by_key("EXEC_VAR").status, "ok");
    assert!(!check_healthy(&rows), "a failing reference means exit 1");
    // The vault probe really hit the KV v2 route with the token header.
    assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
    assert_eq!(server.token_header(), "caller-token");
    // No value reaches any report row (D8).
    let text = render_check_rows("work", &rows);
    assert!(!text.contains(SENTINEL), "value leaked into check output");
    // Everything goes green once the env var exists (exit-0 shape).
    std::env::set_var("NAU_SECRETS_TEST_CHECK", SENTINEL);
    let rows = check_pod(tmp.path(), "work").unwrap();
    std::env::remove_var("NAU_SECRETS_TEST_CHECK");
    assert!(
        check_healthy(&rows),
        "all three D4 sources are live → exit 0: {rows:?}"
    );
    assert!(
        !render_check_rows("work", &rows).contains(SENTINEL),
        "value leaked into check output"
    );
}

#[test]
fn verbs_refuse_unknown_pods_and_generation_less_pods() {
    let tmp = tempfile::tempdir().unwrap();
    let err = format!(
        "{}",
        list_pod(
            tmp.path(),
            "ghost",
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("has no state"), "{err}");
    seed_pod(tmp.path(), "cold", "pod {}");
    let err = format!(
        "{}",
        list_pod(tmp.path(), "cold", Some(tmp.path().join("cache").as_path())).unwrap_err()
    );
    assert!(err.contains("no active generation"), "{err}");
}

#[test]
fn refresh_with_no_references_needs_no_runtime_dir() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("XDG_RUNTIME_DIR").ok();
    std::env::remove_var("XDG_RUNTIME_DIR");
    let tmp = tempfile::tempdir().unwrap();
    seed_pod(tmp.path(), "cold", "pod {}");
    activate(tmp.path(), "cold");
    let report = refresh_pod(
        tmp.path(),
        "cold",
        None,
        &crate::runtime::RuntimeTools::default(),
    );
    if let Some(dir) = saved {
        std::env::set_var("XDG_RUNTIME_DIR", dir);
    }
    assert_eq!(report.unwrap(), SecretsRefreshReport::default());
}

// ── bitwarden (issue #185): fake bws on the host PATH ──

#[test]
fn bitwarden_happy_path_extracts_the_json_value_field() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let counter = tmp.path().join("calls");
    let body = format!(r#"{{"id":"8848da48","value":"{SENTINEL}"}}"#);
    let _bws = bws_script(tmp.path(), &body, 0, Some(&counter));
    let _env = BwsEnv::new(tmp.path(), Some("caller-token"));
    let refs = bitwarden_refs("8848da48");
    let values = resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(values.get("BW_TOKEN").map(String::as_str), Some(SENTINEL));
    assert_eq!(calls(&counter), 1, "exactly one bws invocation");
}
