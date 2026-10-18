use super::*;

    #[test]
    fn identity_validation_mirrors_the_server_gate() {
        assert!(validate_identity("hello-world", "1.2.3").is_ok());
        let err = validate_identity("Hello_World", "1.2.3").unwrap_err();
        assert!(err.to_string().contains("[a-z0-9-]"), "{err}");
        let err = validate_identity("hello", "1.2").unwrap_err();
        assert!(err.to_string().contains("triple"), "{err}");
    }

    #[test]
    fn token_sanitization_refuses_the_wire_hostile_shapes() {
        assert_eq!(sanitize_token("  tok \n").unwrap(), "tok");
        assert!(sanitize_token("").is_err());
        assert!(sanitize_token("  \n").is_err());
        let err = sanitize_token("to\nken").unwrap_err();
        assert!(err.to_string().contains("control"), "{err}");
    }

    // ── Server resolution order (ADR-0052 Decision 6) ──

    #[test]
    fn pod_override_wins_over_the_system_list_wholesale() {
        let pod = vec!["https://pod.example/nau".to_string()];
        let system = vec![front("https://system.example/nau")];
        let resolved = resolve_server_fronts(Some(&pod), &system, "git").unwrap();
        assert_eq!(
            resolved.as_ref(),
            &["https://pod.example/nau".to_string()],
            "the pod override REPLACES the system list"
        );
    }

    #[test]
    fn an_empty_pod_override_falls_through_to_the_system_list_in_order() {
        let pod: Vec<String> = Vec::new();
        let system = vec![
            front("https://first.example/nau"),
            front("http://second.example:7780"),
        ];
        let resolved = resolve_server_fronts(Some(&pod), &system, "git").unwrap();
        assert_eq!(
            resolved.as_ref(),
            &[
                "https://first.example/nau".to_string(),
                "http://second.example:7780".to_string()
            ],
            "declaration order IS the try order"
        );
    }

    #[test]
    fn no_config_anywhere_names_the_package_and_the_remedy() {
        let err = resolve_server_fronts(None, &[], "opencode-bin").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("opencode-bin"), "names the package: {msg}");
        assert!(msg.contains("servers"), "hints at the config key: {msg}");
    }

    // ── Recipe resolution (the pkgs/<letter>/<name>.lua layout) ──

    #[test]
    fn recipe_resolution_follows_the_collection_layout() {
        let root = tempfile::tempdir().unwrap();
        let single = root.path().join("t").join("testpkg.lua");
        std::fs::create_dir_all(single.parent().unwrap()).unwrap();
        std::fs::write(&single, "-- recipe").unwrap();
        assert_eq!(
            resolve_recipe(root.path(), "testpkg").unwrap(),
            single,
            "single-file form resolves first"
        );

        let dir_form_root = tempfile::tempdir().unwrap();
        let init = dir_form_root
            .path()
            .join("d")
            .join("dirpkg")
            .join("init.lua");
        std::fs::create_dir_all(init.parent().unwrap()).unwrap();
        std::fs::write(&init, "-- recipe").unwrap();
        assert_eq!(
            resolve_recipe(dir_form_root.path(), "dirpkg").unwrap(),
            init,
            "the <name>/init.lua form resolves too"
        );
    }

    #[test]
    fn missing_recipes_are_named_by_path() {
        let root = tempfile::tempdir().unwrap();
        let err = resolve_recipe(root.path(), "ghost").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "{msg}");
        assert!(
            msg.contains(
                &root
                    .path()
                    .join("g")
                    .join("ghost.lua")
                    .display()
                    .to_string()
            ),
            "names the expected path: {msg}"
        );
        let err = resolve_recipe(root.path(), "../escape").unwrap_err();
        assert!(err.to_string().contains("[a-z0-9-]"), "{err}");
    }

    // ── Drain plumbing over the seams (no eval here — the eval-backed
    // happy path lives in tests/build_request.rs) ──

    #[test]
    fn release_config_assembles_the_release_input_and_names_gaps() {
        let cfg = release_cfg();
        let input = cfg
            .build_input(Path::new("/out/x_1.2.3_amd64.snap"), "x", "1.2.3")
            .unwrap();
        assert_eq!(input.package, "x");
        assert_eq!(input.version, "1.2.3");
        assert_eq!(input.s3.bucket, "nau-tree");

        let err = ReleaseConfig::default()
            .build_input(Path::new("/out/x.snap"), "x", "1.2.3")
            .unwrap_err();
        assert!(err.to_string().contains("release not configured"), "{err}");
    }

    // The eval-backed drain tests live in tests/build_request.rs: they
    // run the REAL bounded-subprocess eval worker, which re-executes
    // CARGO_BIN_EXE_nau — a binary only the integration suite has.
