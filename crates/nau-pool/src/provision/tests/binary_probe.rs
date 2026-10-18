use super::*;

    #[test]
    fn binary_probe_accepts_a_2xx_front() {
        let ok = FakeCurl {
            code: 0,
            status_line: "200",
        };
        probe_binary_url(&ok, "https://front.example/bin/nau-amd64").expect("a 2xx front installs");
    }

    #[test]
    fn binary_probe_accepts_a_redirect_to_a_2xx_target() {
        // curl -L collapses the chain; -w reports the FINAL hop's code.
        let ok = FakeCurl {
            code: 0,
            status_line: "200",
        };
        probe_binary_url(
            &ok,
            "https://github.example/x/y/releases/download/v0.1.0/nau-amd64",
        )
        .expect("a redirect chain ending 2xx installs");
    }

    #[test]
    fn binary_probe_refuses_a_404_before_any_server_exists() {
        let gone = FakeCurl {
            code: 0,
            status_line: "404",
        };
        let err = probe_binary_url(
            &gone,
            "https://github.example/rbelem/nau/releases/download/v0.1.0/nau-amd64",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("is not servable"), "{err}");
        assert!(
            err.contains("NAU_WORKER_BINARY_URL"),
            "names the override: {err}"
        );
    }

    #[test]
    fn binary_probe_refuses_an_unreachable_front() {
        let dead = FakeCurl {
            code: 7,
            status_line: "000",
        };
        let err = probe_binary_url(&dead, "http://10.255.255.1/bin/nau-amd64")
            .unwrap_err()
            .to_string();
        assert!(err.contains("curl exit 7"), "{err}");
    }

    #[test]
    fn ttl_parses_single_unit_durations() {
        assert_eq!(parse_ttl("4h").unwrap(), 14_400);
        assert_eq!(parse_ttl("24h").unwrap(), 86_400);
        assert_eq!(parse_ttl("30m").unwrap(), 1_800);
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("4x").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("-4h").is_err());
    }

    #[test]
    fn iso8601_utc_formats_the_human_display_shape() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(86_400), "1970-01-02T00:00:00Z");
        // Leap-year day (2024-02-29).
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn destroy_summary_reports_an_absent_entry_honestly() {
        assert_eq!(
            destroy_summary("nau-worker-x-01", true),
            "destroyed worker 'nau-worker-x-01' and evicted its config entry"
        );
        let absent = destroy_summary("nau-worker-x-01", false);
        assert!(absent.contains("not managed by nau"), "{absent}");
        assert!(absent.contains("nothing evicted"), "{absent}");
    }

    #[test]
    fn token_from_env_trims_and_treats_empty_as_absent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY (test-only): single-threaded under ENV_LOCK.
        std::env::remove_var("HCLOUD_TOKEN");
        assert!(token_from_env().is_none());
        std::env::set_var("HCLOUD_TOKEN", "   ");
        assert!(token_from_env().is_none());
        std::env::set_var("HCLOUD_TOKEN", " tok ");
        assert_eq!(token_from_env().as_deref(), Some("tok"));
        std::env::remove_var("HCLOUD_TOKEN");
    }

    #[test]
    fn operator_key_resolves_from_the_explicit_file() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("op.pub");
        std::fs::write(&key, "ssh-ed25519 AAAAoperator test@host\n").unwrap();
        std::env::set_var("NAU_OPERATOR_KEY", &key);
        assert_eq!(
            resolve_operator_key().unwrap(),
            "ssh-ed25519 AAAAoperator test@host"
        );
        std::env::remove_var("NAU_OPERATOR_KEY");
    }

    #[test]
    fn operator_key_refusal_names_what_was_tried() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // SAFETY (test-only): single-threaded under ENV_LOCK.
        std::env::set_var("NAU_OPERATOR_KEY", dir.path().join("absent.pub"));
        let err = format!("{}", resolve_operator_key().unwrap_err());
        std::env::remove_var("NAU_OPERATOR_KEY");
        assert!(err.contains("absent.pub"), "refusal names the file: {err}");
        assert!(err.contains("NAU_OPERATOR_KEY"), "{err}");
    }
