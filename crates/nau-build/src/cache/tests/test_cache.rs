use super::*;

    #[test]
    fn test_cache_default_dir() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // One observation: read HOME first, construct from it immediately.
        // The image command-seam test mutates HOME in this same process —
        // reading it on both sides of `PackageCache::new` (which resolves
        // HOME internally) could straddle that mutation (issue #149).
        let home = std::env::var("HOME").unwrap();
        let cache = PackageCache::new(None);
        let expected = Path::new(&home).join(".cache").join("nau").join("pkgs");
        assert_eq!(cache.root(), expected);
    }

    #[test]
    fn test_cache_custom_dir() {
        let cache = PackageCache::new(Some(PathBuf::from("/tmp/test-cache")));
        assert_eq!(cache.root(), Path::new("/tmp/test-cache"));
    }

    #[test]
    fn test_closure_source_meta_package() {
        let meta = make_meta_meta("build-deps");
        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);
        assert_eq!(closure.source, "none");
    }

    #[test]
    fn test_closure_key_format_v4() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let key = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();
        // "v4:" prefix + 64-char hex digest (v4 folds the single-command
        // `build` field into the key; v3 added build_deps).
        let hex = key.strip_prefix("v4:").expect("key must be v4-prefixed");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_closure_key_varies_with_single_build_command() {
        // v4 regression: the pre-parts form `build = "..."` (no `parts`
        // table) must participate in the cache key. Before v4, a changed
        // build script with an unchanged source produced an identical key
        // and served a stale artifact (issue: cache-key hole).
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        assert_eq!(meta.parts, None);
        let original = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        let mut changed = meta.clone();
        changed.build = Some("make all".into());
        let changed_key = BuildClosure::for_meta(&changed, vec![], vec![]).cache_key();

        assert_ne!(
            original, changed_key,
            "a changed single-command build script must rekey"
        );
        // Same build script → stable key.
        assert_eq!(
            original,
            BuildClosure::for_meta(&meta, vec![], vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_canonical_json_schema() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(
            &meta,
            vec![RequiresMember {
                name: "zlib".into(),
                pin: Some("1.3".into()),
                hash: None,
            }],
            vec![],
        );
        let expected_source = sha256_hex("hello:1.0:https://example.com/hello.tar.gz");
        // Locks the exact deterministic schema: sorted keys, null hashes.
        // v4: the single-command `build` field folds into `parts` (the
        // pre-parts form), so a changed build script invalidates the key.
        assert_eq!(
            closure.canonical_json(),
            format!(
                r#"{{"build_deps":[],"format_version":4,"parts":"[{{\"after\":[],\"build\":\"make\",\"name\":\"core\"}}]","requires":[{{"hash":null,"name":"zlib","pin":"1.3"}}],"source":"{expected_source}","target":"native"}}"#
            )
        );
    }

    #[test]
    fn test_closure_key_stable_when_nothing_changes() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let requires = vec![RequiresMember {
            name: "zlib".into(),
            pin: Some("1.3".into()),
            hash: Some("abc".into()),
        }];
        let key1 = BuildClosure::for_meta(&meta, requires.clone(), vec![]).cache_key();
        let key2 = BuildClosure::for_meta(&meta, requires, vec![]).cache_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_closure_key_varies_with_build_deps() {
        // ADR-0018 Decision 4 (issue #22): a changed build dependency
        // invalidates the cache key, forcing a rebuild. The build_deps
        // member mirrors the requires member shape (pin + content hash).
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let dep = |pin: Option<&str>, hash: Option<&str>| RequiresMember {
            name: "pkgconf".into(),
            pin: pin.map(str::to_string),
            hash: hash.map(str::to_string),
        };
        let no_deps = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();
        let with_dep =
            BuildClosure::for_meta(&meta, vec![], vec![dep(Some("2.2"), None)]).cache_key();
        assert_ne!(no_deps, with_dep, "a build_dep must change the key");

        let repinned =
            BuildClosure::for_meta(&meta, vec![], vec![dep(Some("2.3"), None)]).cache_key();
        assert_ne!(
            with_dep, repinned,
            "a build_dep pin change must change the key"
        );

        // Same build_dep → identical key (sorted, deduplicated).
        let again = BuildClosure::for_meta(&meta, vec![], vec![dep(Some("2.2"), None)]).cache_key();
        assert_eq!(with_dep, again);
    }

    #[test]
    fn test_closure_key_varies_with_source_change() {
        // The old format test pinned byte-compat with the pre-closure key;
        // v2 deliberately breaks that (one cold-cache rebuild on upgrade).
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let changed = make_source_meta("hello", "https://example.com/hello-v2.tar.gz");
        assert_ne!(
            BuildClosure::for_meta(&meta, vec![], vec![]).cache_key(),
            BuildClosure::for_meta(&changed, vec![], vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_key_varies_with_multi_source_change() {
        use std::collections::BTreeMap;
        let make_multi = |one_hash: &str| {
            let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
            meta.source = None;
            meta.sources = Some(BTreeMap::from([
                (
                    "one".into(),
                    crate::snap::SourceSpec::Pinned {
                        url: "https://example.com/one.tar.gz".into(),
                        sha256: one_hash.into(),
                    },
                ),
                (
                    "two".into(),
                    crate::snap::SourceSpec::Pinned {
                        url: "https://example.com/two.tar.gz".into(),
                        sha256: "bbbb".into(),
                    },
                ),
            ]));
            meta
        };
        let changed =
            make_multi("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let original =
            make_multi("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        let key_orig = BuildClosure::for_meta(&original, vec![], vec![]).cache_key();
        let key_changed = BuildClosure::for_meta(&changed, vec![], vec![]).cache_key();
        // One source's pin change invalidates the key.
        assert_ne!(key_orig, key_changed);
        // Both keys are deterministic.
        assert_eq!(
            key_orig,
            BuildClosure::for_meta(&original, vec![], vec![]).cache_key()
        );
        // The canonical JSON carries the explicit per-source pins (sorted
        // by name), so a key diff is legible.
        let json = BuildClosure::for_meta(&original, vec![], vec![]).canonical_json();
        assert!(json.contains("\"one\""), "json: {json}");
        assert!(json.contains("\"two\""), "json: {json}");
    }

    #[test]
    fn test_closure_key_varies_with_parts_spec() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.build = None;
        meta.parts = Some(
            [(
                "core",
                SnapPart {
                    build: "make".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            )]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        );
        let with_parts = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        // Different command → different key
        let mut meta2 = meta.clone();
        if let Some(parts) = &mut meta2.parts {
            parts.get_mut("core").unwrap().build = "make all".into();
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta2, vec![], vec![]).cache_key()
        );

        // New part name → different key
        let mut meta3 = meta.clone();
        if let Some(parts) = &mut meta3.parts {
            parts.insert(
                "ui".into(),
                SnapPart {
                    build: "npm build".into(),
                    after: vec![],
                    plugin: None,
                    plugin_options: None,
                },
            );
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta3, vec![], vec![]).cache_key()
        );

        // Added `after` edge → different key
        let mut meta4 = meta.clone();
        if let Some(parts) = &mut meta4.parts {
            parts.get_mut("core").unwrap().after = vec!["ui".into()];
        }
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta4, vec![], vec![]).cache_key()
        );

        // No parts at all → different key again
        let mut meta5 = meta.clone();
        meta5.parts = None;
        assert_ne!(
            with_parts,
            BuildClosure::for_meta(&meta5, vec![], vec![]).cache_key()
        );
    }

    #[test]
    fn test_canonical_parts_json_locked_for_command_parts() {
        // Parts without a plugin must serialize byte-identically to the
        // pre-plugin format (serde_json's default map sorts keys).
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: "make".into(),
                after: vec!["libs".into()],
                plugin: None,
                plugin_options: None,
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":["libs"],"build":"make","name":"core"}]"#
        );
    }

    #[test]
    fn test_canonical_parts_json_folds_plugin_identity_and_options() {
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [(
                        "target".to_string(),
                        nau_core::plugins::PluginValue::Str("all".into()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":[],"build":"","name":"core","options":{"target":"all"},"plugin":"make","plugin_version":"2"}]"#
        );
    }

    #[test]
    fn test_canonical_parts_json_make_growth_options_canonical() {
        // Registry-v2 options fold in canonically: option keys sorted,
        // `variables` map sorted, booleans as JSON booleans.
        let parts: std::collections::BTreeMap<String, SnapPart> = [(
            "core",
            SnapPart {
                build: String::new(),
                after: vec![],
                plugin: Some("make".into()),
                plugin_options: Some(
                    [
                        (
                            "variables".to_string(),
                            nau_core::plugins::PluginValue::Map(
                                [
                                    ("ZED".to_string(), "1".to_string()),
                                    ("ALPHA".to_string(), "2".to_string()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        ),
                        (
                            "install".to_string(),
                            nau_core::plugins::PluginValue::Bool(false),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        )]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            super::canonical_parts_json(&parts),
            r#"[{"after":[],"build":"","name":"core","options":{"install":false,"variables":{"ALPHA":"2","ZED":"1"}},"plugin":"make","plugin_version":"2"}]"#
        );
    }

    #[test]
    fn test_closure_key_varies_with_plugin_and_options() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.build = None;
        meta.parts = Some(
            [(
                "core",
                SnapPart {
                    build: String::new(),
                    after: vec![],
                    plugin: Some("make".into()),
                    plugin_options: None,
                },
            )]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        );
        let base = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        // Different plugin → different key
        let mut meta2 = meta.clone();
        meta2
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin = Some("cmake".into());
        assert_ne!(
            base,
            BuildClosure::for_meta(&meta2, vec![], vec![]).cache_key()
        );

        // Option added → different key
        let mut meta3 = meta.clone();
        meta3
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin_options = Some(
            [(
                "target".to_string(),
                nau_core::plugins::PluginValue::Str("all".into()),
            )]
            .into(),
        );
        let with_options = BuildClosure::for_meta(&meta3, vec![], vec![]).cache_key();
        assert_ne!(base, with_options);

        // Option value changed → different key
        let mut meta4 = meta3.clone();
        meta4
            .parts
            .as_mut()
            .unwrap()
            .get_mut("core")
            .unwrap()
            .plugin_options = Some(
            [(
                "target".to_string(),
                nau_core::plugins::PluginValue::Str("install".into()),
            )]
            .into(),
        );
        assert_ne!(
            with_options,
            BuildClosure::for_meta(&meta4, vec![], vec![]).cache_key()
        );

        // Identical options → same key
        assert_eq!(
            with_options,
            BuildClosure::for_meta(&meta3, vec![], vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_key_varies_with_make_variables() {
        // Registry-v2 make options: `variables` (and booleans like `install`)
        // must fold into the key like any other option.
        let make_part = |options| SnapPart {
            build: String::new(),
            after: vec![],
            plugin: Some("make".into()),
            plugin_options: options,
        };
        let variables = |value: &str| {
            Some(
                [(
                    "variables".to_string(),
                    nau_core::plugins::PluginValue::Map(
                        [("CFLAGS".to_string(), value.to_string())]
                            .into_iter()
                            .collect(),
                    ),
                )]
                .into_iter()
                .collect(),
            )
        };

        let meta = |part: SnapPart| {
            let mut m = make_source_meta("hello", "https://example.com/hello.tar.gz");
            m.build = None;
            m.parts = Some([("core".to_string(), part)].into_iter().collect());
            BuildClosure::for_meta(&m, vec![], vec![]).cache_key()
        };

        let base = meta(make_part(None));
        let with_vars = meta(make_part(variables("-O2")));
        assert_ne!(base, with_vars, "adding variables must change the key");

        let changed = meta(make_part(variables("-O3")));
        assert_ne!(with_vars, changed, "a variable value change must rekey");

        assert_eq!(
            meta(make_part(variables("-O2"))),
            with_vars,
            "identical variables must keep the key warm"
        );

        // install = false changes the expansion → must change the key.
        let mut part = make_part(None);
        part.plugin_options = Some(
            [(
                "install".to_string(),
                nau_core::plugins::PluginValue::Bool(false),
            )]
            .into_iter()
            .collect(),
        );
        assert_ne!(base, meta(part));
    }

