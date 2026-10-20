use super::*;

#[test]
fn bitwarden_calls_bws_with_the_exact_argv_shape() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let argv = tmp.path().join("argv");
    let body = r#"{"value":"v"}"#;
    script(
        tmp.path(),
        "bws",
        &format!(
            "printf '%s ' \"$@\" > {}\nprintf '%s\\n' '{body}'\n",
            argv.display()
        ),
    );
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("8848da48-aa");
    resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&argv).unwrap(),
        "secret get 8848da48-aa ",
        "`bws secret get <id>` — argv array, no shell, no extra words"
    );
}

#[test]
fn bitwarden_interior_newlines_in_the_value_survive() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    // The \n inside the literal is the JSON escape: the parsed
    // value carries the real newline (PEM shape). Only the stdout
    // EDGES are trimmed.
    let _bws = bws_script(tmp.path(), r#"{"value":"line1\nline2"}"#, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let values = resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    assert_eq!(
        values.get("BW_TOKEN").map(String::as_str),
        Some("line1\nline2")
    );
}

#[test]
fn bitwarden_nonzero_exit_fails_named_and_suppresses_stderr() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    // The failing fake leaks the sentinel on BOTH stderr and
    // stdout — neither may reach our error (D8).
    script(
        tmp.path(),
        "bws",
        &format!("printf '{SENTINEL}' >&2\nprintf '{SENTINEL}'\nexit 3\n"),
    );
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("8848da48");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("secret 'BW_TOKEN'"), "{err}");
    assert!(err.contains("source 'bitwarden'"), "{err}");
    assert!(err.contains("exited with"), "{err}");
    assert!(err.contains("3"), "exit status not named: {err}");
    assert!(!err.contains(SENTINEL), "provider output leaked: {err}");
}

#[test]
fn bitwarden_malformed_json_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let _bws = bws_script(tmp.path(), "not json at all", 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("valid JSON"), "{err}");
    assert!(err.contains("source 'bitwarden'"), "{err}");
}

#[test]
fn bitwarden_missing_value_field_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let _bws = bws_script(tmp.path(), r#"{"id":"8848"}"#, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("no '.value'"), "{err}");
}

#[test]
fn bitwarden_non_string_value_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let _bws = bws_script(tmp.path(), r#"{"value":42}"#, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("not a string"), "{err}");
}

#[test]
fn bitwarden_empty_value_fails_named_never_an_empty_secret() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let _bws = bws_script(tmp.path(), r#"{"value":""}"#, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn bitwarden_missing_token_fails_named_before_bws_runs() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let counter = tmp.path().join("calls");
    let body = format!(r#"{{"value":"{SENTINEL}"}}"#);
    let _bws = bws_script(tmp.path(), &body, 0, Some(&counter));
    let _env = BwsEnv::new(tmp.path(), None);
    let refs = bitwarden_refs("8848da48");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("BWS_ACCESS_TOKEN"), "{err}");
    assert!(err.contains("not set"), "{err}");
    assert!(
        !counter.is_file(),
        "the counter stays unwritten — bws must not run without a token"
    );
    assert!(!err.contains(SENTINEL), "{err}");
}

#[test]
fn bitwarden_empty_token_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let _bws = bws_script(tmp.path(), r#"{"value":"v"}"#, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some(""));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("BWS_ACCESS_TOKEN"), "{err}");
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn bitwarden_bws_missing_from_the_host_path_fails_named() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let empty = tempfile::tempdir().unwrap();
    let _env = BwsEnv::path_without_bws(empty.path(), Some("t"));
    let refs = bitwarden_refs("x");
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("not found on the host PATH"), "{err}");
    assert!(err.contains("'bws'"), "{err}");
    assert!(err.contains("source 'bitwarden'"), "{err}");
}

// ── libsecret (issue #185): the Secret Service seam fake ──

#[test]
fn libsecret_set_then_resolve_round_trips_through_the_seam() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let attrs = seed_fake_store(&[("bitwarden", "sm-access-token")], SENTINEL.as_bytes());
    let previous = reseat_lookup(fake_lookup);
    let refs = BTreeMap::from([(
        "LS_TOKEN".to_string(),
        SecretSource::Libsecret { attributes: attrs },
    )]);
    let values = resolve_references(
        &pod,
        "p",
        3,
        &refs,
        Some(tmp.path().join("cache").as_path()),
    )
    .unwrap();
    reseat_lookup(previous);
    FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert_eq!(
        values.get("LS_TOKEN").map(String::as_str),
        Some(SENTINEL),
        "the setup-bws interop shape reads back through the seam"
    );
}

#[test]
fn libsecret_missing_entry_fails_named_and_distinct_from_transport() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let previous = reseat_lookup(fake_lookup);
    // (a) No such entry — the store is empty.
    let refs = BTreeMap::from([(
        "LS_TOKEN".to_string(),
        libsecret_ref(&[("bitwarden", "no-such-token")]),
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("no Secret Service entry matches"), "{err}");
    assert!(err.contains("LS_TOKEN"), "{err}");
    assert!(err.contains("source 'libsecret'"), "{err}");
    // (b) Transport failure — a DIFFERENT named failure.
    reseat_lookup(failing_lookup);
    let refs = BTreeMap::from([(
        "LS_TOKEN".to_string(),
        libsecret_ref(&[("bitwarden", "sm-access-token")]),
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    reseat_lookup(previous);
    FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert!(err.contains("bus hole"), "{err}");
    assert!(!err.contains("no Secret Service entry"), "{err}");
}

#[test]
fn libsecret_non_utf8_and_empty_content_fail_named_without_the_content() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let pod = pod_state_root(tmp.path());
    let previous = reseat_lookup(fake_lookup);
    let non_utf8 = seed_fake_store(&[("k", "non-utf8")], &[0xff, 0xfe]);
    let refs = BTreeMap::from([(
        "LS_TOKEN".to_string(),
        SecretSource::Libsecret {
            attributes: non_utf8,
        },
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    assert!(err.contains("not UTF-8"), "{err}");
    let empty = seed_fake_store(&[("k", "empty")], &[]);
    let refs = BTreeMap::from([(
        "LS_TOKEN".to_string(),
        SecretSource::Libsecret { attributes: empty },
    )]);
    let err = format!(
        "{}",
        resolve_references(
            &pod,
            "p",
            3,
            &refs,
            Some(tmp.path().join("cache").as_path())
        )
        .unwrap_err()
    );
    reseat_lookup(previous);
    FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert!(err.contains("empty"), "{err}");
}

/// Live-bus gate: NAU_SECRETS_LIVE_DBUS=1 opts into a REAL
/// session bus + unlocked keyring. Writes a uniquely-attributed
/// item, reads it back through the PRODUCTION seam fn, deletes it.
#[test]
fn live_dbus_secret_service_round_trip_when_gated_on() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var("NAU_SECRETS_LIVE_DBUS").as_deref() != Ok("1") {
        return;
    }
    use dbus_secret_service::{EncryptionType, SecretService};
    let attrs: BTreeMap<String, String> = BTreeMap::from([
        ("nau-test".to_string(), "issue-185".to_string()),
        ("nonce".to_string(), std::process::id().to_string()),
    ]);
    let pairs: std::collections::HashMap<&str, &str> = attrs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let service = SecretService::connect(EncryptionType::Dh).unwrap();
    let collection = service.get_default_collection().unwrap();
    let item = collection
        .create_item(
            "nau issue-185 live test",
            pairs,
            SENTINEL.as_bytes(),
            true,
            "text/plain",
        )
        .unwrap();
    let found = secret_service_lookup(&attrs).unwrap();
    item.delete().unwrap();
    assert_eq!(found.as_deref(), Some(SENTINEL.as_bytes()));
}

// ── pod secrets check end-to-end (issue #185 scope 5, #186) ──

/// One pod, three sources: bitwarden resolves through the fake bws,
/// libsecret through the seam fake, vault through the loopback KV v2
/// server — every D4 source is live since #186, so the healthy row
/// set is the exit-0 shape.
#[test]
fn check_pod_end_to_end_bitwarden_libsecret_vault_ok_exit_0() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    seed_pod(
        tmp.path(),
        "work",
        r#"pod {
    secrets = {
        BW_ITEM    = { source = "bitwarden", id = "8848da48" },
        LS_TOKEN   = { source = "libsecret", attributes = { bitwarden = "sm-access-token" } },
        VAULT_ITEM = { source = "vault", mount = "secret", path = "app", field = "token" },
    },
}
"#,
    );
    activate(tmp.path(), "work");
    let body = format!(r#"{{"value":"{SENTINEL}"}}"#);
    let _bws = bws_script(tmp.path(), &body, 0, None);
    let _env = BwsEnv::new(tmp.path(), Some("caller-token"));
    let server = VaultServer::start("200 OK", &vault_body(SENTINEL));
    let _venv = VaultEnv::new(Some(&server.addr), Some("vault-caller-token"));
    let previous = reseat_lookup(fake_lookup);
    seed_fake_store(&[("bitwarden", "sm-access-token")], b"ring-stored");
    let rows = check_pod(tmp.path(), "work").unwrap();
    reseat_lookup(previous);
    FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
    assert_eq!(by_key("BW_ITEM").status, "ok");
    assert_eq!(by_key("LS_TOKEN").status, "ok");
    assert_eq!(by_key("VAULT_ITEM").status, "ok");
    assert!(check_healthy(&rows), "every D4 source live → exit 0");
    // The vault probe hit the KV v2 route with the token header.
    assert_eq!(server.request_line(), "GET /v1/secret/data/app HTTP/1.1");
    assert_eq!(server.token_header(), "vault-caller-token");
    // No resolved value reaches any check output (D8).
    let text = render_check_rows("work", &rows);
    assert!(!text.contains(SENTINEL), "bitwarden value leaked: {text}");
    assert!(
        !text.contains("ring-stored"),
        "keyring value leaked: {text}"
    );
}
