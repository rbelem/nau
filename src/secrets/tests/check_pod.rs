use super::*;

    /// The exit-1 shape survives #186 — the stub row is gone, so its
    /// story re-points at the transport-failure path: a dead
    /// VAULT_ADDR fails its row named while the other two stay green.
    #[test]
    fn check_pod_end_to_end_vault_transport_failure_is_the_exit_1_shape() {
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
        // Port 1: nothing listens there — connection refused.
        let _venv = VaultEnv::new(Some("http://127.0.0.1:1"), Some("t"));
        let previous = reseat_lookup(fake_lookup);
        seed_fake_store(&[("bitwarden", "sm-access-token")], b"ring-stored");
        let rows = check_pod(tmp.path(), "work").unwrap();
        reseat_lookup(previous);
        FAKE_STORE.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let by_key = |k: &str| rows.iter().find(|r| r.key == k).unwrap();
        assert_eq!(by_key("BW_ITEM").status, "ok");
        assert_eq!(by_key("LS_TOKEN").status, "ok");
        let vault = by_key("VAULT_ITEM");
        assert_eq!(vault.status, "failed");
        assert!(vault.note.contains("transport failure"), "{}", vault.note);
        assert!(!check_healthy(&rows), "this row set is the exit-1 shape");
        // The transport failure text carries no values (D8).
        let text = render_check_rows("work", &rows);
        assert!(!text.contains(SENTINEL), "value leaked: {text}");
        assert!(
            !text.contains("ring-stored"),
            "keyring value leaked: {text}"
        );
    }
