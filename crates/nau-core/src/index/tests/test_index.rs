use super::*;

    #[test]
    fn test_index_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-index.json");

        let index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };
        index.save(&path).unwrap();

        let loaded = PackageIndex::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.snaps.len(), 1);
        assert_eq!(loaded.snaps[0].name, "core22");
        assert_eq!(loaded.snaps[0].pins.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_index_find() {
        let index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };

        let found = index.find("core22").unwrap();
        assert_eq!(found.name, "core22");
        assert!(index.find("nonexistent").is_none());
    }

    #[test]
    fn test_index_upsert_adds_new() {
        let mut index = PackageIndex {
            version: 1,
            snaps: vec![],
        };

        index.upsert(sample_entry());
        assert_eq!(index.snaps.len(), 1);
    }

    #[test]
    fn test_index_upsert_replaces_existing() {
        let mut index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };

        let mut modified = sample_entry();
        modified.summary = Some("Updated".into());
        index.upsert(modified);

        assert_eq!(index.snaps.len(), 1);
        assert_eq!(
            index.find("core22").unwrap().summary.as_deref(),
            Some("Updated")
        );
    }

    #[test]
    fn test_default_entries_exist() {
        let entries = default_entries();
        assert!(entries.iter().any(|e| e.name == "core22"));
        assert!(entries.iter().any(|e| e.name == "pc-kernel"));
        assert!(entries.iter().any(|e| e.name == "pi-gadget"));
        assert!(entries.iter().any(|e| e.name == "lxd"));
    }

    #[test]
    fn test_entry_to_snap_meta_source() {
        let entry = IndexEntry {
            name: "hello".into(),
            summary: Some("GNU Hello".into()),
            store: None,
            pins: None,
            source: Some(SourceDef {
                url: "https://example.com/hello.tar.gz".into(),
                sha256: Some("abcdef".into()),
            }),
            build: Some("./configure && make install".into()),
            apps: Some(
                [(
                    "hello".into(),
                    IndexApp {
                        command: "bin/hello".into(),
                        daemon: None,
                        plugs: None,
                        slots: None,
                        desktop: None,
                    },
                )]
                .into(),
            ),
            aliases: vec![],
        };

        let meta = PackageIndex::entry_to_snap_meta(&entry).unwrap();
        assert_eq!(meta.name, "hello");
        assert!(meta.build.is_some());
        assert_eq!(meta.apps.len(), 1);
        assert_eq!(meta.apps["hello"].command, "bin/hello");
    }

    #[test]
    fn test_entry_to_snap_meta_no_source() {
        let entry = IndexEntry {
            name: "core22".into(),
            summary: None,
            store: Some(StoreRef {
                name: None,
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        };

        // Store-only entries have no source, so to_snap_meta returns None
        assert!(PackageIndex::entry_to_snap_meta(&entry).is_none());
    }

    #[test]
    fn test_index_load_or_default_creates_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent-index.json");

        let index = PackageIndex::load_or_default(&path).unwrap();
        assert_eq!(index.version, 1);
        assert!(!index.snaps.is_empty());
        // Should have default entries
        assert!(index.snaps.iter().any(|e| e.name == "core22"));
    }

    // ── Channel-keyed pins (issue #69) ──

    #[test]
    fn test_channel_pin_matches_keyed_entry() {
        let pins = pins_with(vec![(
            "amd64@22/stable".into(),
            pin(3654, Some("22/stable")),
        )]);
        let got = PackageIndex::channel_pin(&pins, "amd64", "22/stable").unwrap();
        assert_eq!(got.revision, 3654);
        // A different derived channel must not see this pin.
        assert!(PackageIndex::channel_pin(&pins, "amd64", "26/stable").is_none());
    }

    #[test]
    fn test_channel_pin_rejects_legacy_bare_pin_on_derived_channel() {
        // A bare pin with no recorded channel is an unknown-channel pin:
        // never trusted on a derived channel (#69).
        let pins = pins_with(vec![("amd64".into(), pin(103, None))]);
        assert!(PackageIndex::channel_pin(&pins, "amd64", "22/stable").is_none());
        assert!(PackageIndex::channel_pin(&pins, "amd64", "latest/stable").is_none());
    }

    #[test]
    fn test_channel_pin_accepts_bare_pin_with_matching_channel() {
        let pins = pins_with(vec![("amd64".into(), pin(2411, Some("latest/stable")))]);
        assert!(
            PackageIndex::channel_pin(&pins, "amd64", "latest/stable").is_some(),
            "a bare pin that records its channel is usable on that channel"
        );
    }

    #[test]
    fn test_has_arch_pins_sees_keyed_and_bare() {
        let pins = pins_with(vec![
            ("amd64@22/stable".into(), pin(1, Some("22/stable"))),
            ("arm64".into(), pin(2, None)),
        ]);
        assert!(PackageIndex::has_arch_pins(&pins, "amd64"));
        assert!(PackageIndex::has_arch_pins(&pins, "arm64"));
        assert!(!PackageIndex::has_arch_pins(&pins, "armhf"));
    }

    #[test]
    fn test_pin_entry_channel_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-index.json");

        let index = PackageIndex {
            version: 1,
            snaps: vec![IndexEntry {
                name: "pc-kernel".into(),
                summary: None,
                store: None,
                pins: Some(pins_with(vec![(
                    "amd64@26/stable".into(),
                    pin(3699, Some("26/stable")),
                )])),
                source: None,
                build: None,
                apps: None,
                aliases: vec![],
            }],
        };
        index.save(&path).unwrap();
        let loaded = PackageIndex::load(&path).unwrap();
        let pins = loaded.snaps[0].pins.as_ref().unwrap();
        let got = PackageIndex::channel_pin(pins, "amd64", "26/stable").unwrap();
        assert_eq!(got.revision, 3699);
        assert_eq!(got.channel.as_deref(), Some("26/stable"));
    }

    #[test]
    fn entry_to_snap_meta_marks_a_source_without_sha256_unverified() {
        let entry = IndexEntry {
            name: "hello".into(),
            summary: None,
            store: None,
            pins: None,
            source: Some(SourceDef {
                url: "https://example.com/hello.tar.gz".into(),
                sha256: None,
            }),
            build: None,
            apps: None,
            aliases: vec![],
        };
        let meta = PackageIndex::entry_to_snap_meta(&entry).unwrap();
        match meta.source {
            Some(crate::snap_types::SourceSpec::Unverified(url)) => {
                assert_eq!(url, "https://example.com/hello.tar.gz");
            }
            other => panic!("expected an unverified source, got {other:?}"),
        }
    }
