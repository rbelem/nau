use super::*;

    #[test]
    fn window_up_stands_the_funnel_and_preflights_in_order() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "404");
        let url = funnel_window_up(&fake, PUBLISH_URL, 1, Duration::ZERO)
            .expect("a funnel-fronted window stands up")
            .expect("this publish URL is this node's funnel");
        assert_eq!(url, "https://book3.tail9e1045.ts.net:8443");
        let calls = fake.summary();
        assert!(
            calls.contains("tailscale status --json"),
            "resolves the DNS name first: {calls}"
        );
        assert!(
            calls.contains("tailscale funnel --bg --https=8443 127.0.0.1:8477"),
            "re-asserts the serve spec: {calls}"
        );
        assert!(
            calls.contains("curl"),
            "preflights before returning: {calls}"
        );
        // Status before funnel, funnel before curl.
        let s = calls.find("status --json").unwrap();
        let f = calls.find("funnel --bg").unwrap();
        let c = calls.find("curl").unwrap();
        assert!(s < f && f < c, "up → preflight order: {calls}");
    }

    #[test]
    fn window_up_skips_without_shelling_out_for_a_non_tailnet_front() {
        let skipped = funnel_window_up(
            &NeverRunner,
            "https://front.example.com:8443/publish",
            1,
            Duration::ZERO,
        )
        .expect("a non-tailscale front is skipped");
        assert!(skipped.is_none(), "nothing to own");
    }

    #[test]
    fn window_up_skips_a_foreign_ts_net_front_without_touching_the_local_funnel() {
        let fake = FakeTailscale::new(STATUS_JSON);
        let skipped = funnel_window_up(
            &fake,
            "https://other.tail9e1045.ts.net:8443/publish",
            1,
            Duration::ZERO,
        )
        .expect("resolution succeeds");
        assert!(skipped.is_none(), "a foreign funnel is not nau's");
        assert_eq!(
            fake.calls().len(),
            1,
            "only the DNS resolution ran, never an up: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn window_up_refuses_a_same_host_publish_url_on_a_forbidden_port() {
        let fake = FakeTailscale::new(STATUS_JSON);
        let err = funnel_window_up(
            &fake,
            "https://book3.tail9e1045.ts.net:443/publish",
            1,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("8443"), "names the public port: {err}");
        assert!(err.contains("443"), "names the forbidden port: {err}");
        assert!(
            !fake.summary().contains("funnel --bg"),
            "never stands anything up on a refused port: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn funnel_up_failure_names_the_daemon_question() {
        let mut fake = FakeTailscale::new(STATUS_JSON);
        fake.funnel_code = 1;
        fake.funnel_stderr = "funnel requires MagicDNS";
        let err = funnel_up(&fake).unwrap_err().to_string();
        assert!(err.contains("tailscaled"), "{err}");
        assert!(err.contains("MagicDNS"), "carries the CLI stderr: {err}");
    }

    #[test]
    fn preflight_accepts_any_real_http_answer_including_the_shim_404() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "404");
        funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            1,
            Duration::ZERO,
        )
        .expect("a 404 proves the channel serves");
    }

    #[test]
    fn preflight_refuses_a_5xx_front_before_any_api_spend() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(0, "502");
        let err = funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            1,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not serve"), "{err}");
        assert!(err.contains("502"), "{err}");
        assert!(
            err.contains("127.0.0.1:8477"),
            "names the front port: {err}"
        );
    }

    #[test]
    fn preflight_refuses_a_dead_funnel_and_exhausts_its_budget_exactly() {
        let fake = FakeTailscale::new(STATUS_JSON).with_curl(7, "000");
        let err = funnel_preflight(
            &fake,
            "https://book3.tail9e1045.ts.net:8443",
            3,
            Duration::ZERO,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("curl exit 7"), "{err}");
        assert!(err.contains("after 3 tries"), "{err}");
        assert_eq!(
            fake.calls()
                .iter()
                .filter(|c| c.starts_with("curl"))
                .count(),
            3,
            "exactly the budget: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn down_closes_only_8443_and_never_a_443_tailnet_entry() {
        // The host serves 443 tailnet-only → nothing funnel-owned → no
        // `off` call at all.
        let fake = FakeTailscale::new(STATUS_443_SERVE_JSON);
        funnel_down(&fake).expect("a 443-only host has no funnel residue");
        assert!(
            !fake.summary().contains("off"),
            "443 must stay tailnet-only: {:?}",
            fake.calls()
        );

        // The funnel nau owns → port-scoped off.
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON);
        funnel_down(&fake).expect("the owned funnel closes");
        let calls = fake.summary();
        assert!(
            calls.contains("tailscale funnel --https=8443 off"),
            "port-scoped teardown: {calls}"
        );
        assert!(!calls.contains("--https=443"), "{calls}");
    }

    #[test]
    fn down_is_a_no_op_when_nothing_is_served() {
        let fake = FakeTailscale::new(r#"{}"#);
        funnel_down(&fake).expect("nothing served — no residue possible");
        assert!(
            !fake.summary().contains("off"),
            "the gate skips the non-idempotent off: {:?}",
            fake.calls()
        );
    }

    #[test]
    fn down_failure_names_the_hand_remedy() {
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON).with_funnel(1, "permission denied");
        let err = funnel_down(&fake).unwrap_err().to_string();
        assert!(err.contains("residue"), "{err}");
        assert!(err.contains("tailscale funnel --https=8443 off"), "{err}");
    }

    #[test]
    fn down_reads_unspawnable_tailscale_as_nothing_served() {
        struct SpawnError;
        impl CommandRunner for SpawnError {
            fn run(&self, _: &[String]) -> std::io::Result<RunnerOutput> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no such file",
                ))
            }
        }
        funnel_down(&SpawnError).expect("a host that cannot answer status serves nothing");
    }

    #[test]
    fn down_if_drained_closes_the_funnel_only_when_the_block_emptied() {
        let dir = tempfile::tempdir().unwrap();

        // A worker still pinned → the channel stays up, tailscale is
        // never consulted.
        let config = write_config(dir.path(), ENTRY_LINE);
        funnel_down_drained(&NeverRunner, &config)
            .expect("workers remain — the funnel must stay up");

        // Drained → the funnel closes.
        let config = write_config(dir.path(), "");
        let fake = FakeTailscale::new(STATUS_8443_FUNNEL_JSON);
        funnel_down_drained(&fake, &config).expect("the drained window closes its funnel");
        assert!(
            fake.summary().contains("tailscale funnel --https=8443 off"),
            "{:?}",
            fake.calls()
        );
    }
