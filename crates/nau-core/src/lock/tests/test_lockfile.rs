use super::*;

    #[test]
    fn test_lockfile_roundtrip() {
        let mut sources = HashMap::new();
        sources.insert(
            "https://example.com/src.tar.gz".to_string(),
            SourceLockEntry {
                sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
                etag: None,
                validated_at: None,
            },
        );

        let mut snaps = HashMap::new();
        snaps.insert(
            "core22".to_string(),
            SnapLockEntry {
                revision: 1847,
                sha3_384: "d53e1c8a66cb03a99aed76f03c49c55ec6110e33c8cb4a12fb2c8715c9349a29321e877483a7bc7718fe552f2533397d".into(),
            },
        );

        let lock = LockFile {
            version: 1,
            sources,
            snaps,
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        let deserialized: LockFile = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.sources.len(), 1);
        assert_eq!(deserialized.snaps.len(), 1);
        assert_eq!(
            deserialized.snaps.get("core22").map(|e| e.revision),
            Some(1847)
        );
    }

    #[test]
    fn test_lockfile_load_nonexistent() {
        let result = LockFile::load(Path::new("/tmp/nonexistent-lock-test-12345.lock"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_lockfile_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nau.lock");

        let mut sources = HashMap::new();
        sources.insert(
            "https://example.com/pkg.tar.gz".to_string(),
            SourceLockEntry {
                sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
                etag: None,
                validated_at: None,
            },
        );

        let lock = LockFile {
            version: 1,
            sources,
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        lock.save(&path).unwrap();

        let loaded = LockFile::load(&path).unwrap().expect("should exist");
        assert_eq!(loaded.version, 1);
        assert_eq!(
            loaded.lookup_source("https://example.com/pkg.tar.gz"),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        assert!(loaded
            .lookup_source("https://unknown.example.com")
            .is_none());
    }

    #[test]
    fn test_lockfile_record_and_lookup_snap() {
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        let snap = SnapRef {
            name: "core22".into(),
            revision: Some(1847),
            sha3_384: Some("abc123".into()),
        };

        lock.record_snap(&snap);
        assert_eq!(lock.snaps.len(), 1);

        let looked_up = lock.lookup_snap("core22").unwrap();
        assert_eq!(looked_up.revision, Some(1847));
        assert_eq!(looked_up.sha3_384.as_deref(), Some("abc123"));

        // Recording same snap again should not duplicate
        lock.record_snap(&snap);
        assert_eq!(lock.snaps.len(), 1);
    }

    #[test]
    fn test_build_deps_lock_record_and_lookup() {
        // ADR-0018 Decision 4 (issue #22): build_deps are pinned in the
        // lockfile — the lockfile IS the pin record.
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        lock.record_build_dep(
            "ncurses",
            &BuildDepPin {
                pin: Some("6.4".into()),
                hash: Some("abc123".into()),
            },
        );
        assert_eq!(lock.build_deps.len(), 1);
        let looked = lock.lookup_build_dep("ncurses").unwrap();
        assert_eq!(looked.pin.as_deref(), Some("6.4"));
        assert_eq!(looked.hash.as_deref(), Some("abc123"));

        // Recording again does not overwrite (record-once).
        lock.record_build_dep(
            "ncurses",
            &BuildDepPin {
                pin: Some("6.5".into()),
                hash: None,
            },
        );
        assert_eq!(lock.build_deps.len(), 1);
        assert_eq!(
            lock.lookup_build_dep("ncurses").unwrap().pin.as_deref(),
            Some("6.4")
        );

        // Lookup miss → None.
        assert!(lock.lookup_build_dep("missing").is_none());
    }

    #[test]
    fn test_build_deps_serialization_and_backcompat() {
        let mut build_deps = HashMap::new();
        build_deps.insert(
            "pkgconf".to_string(),
            BuildDepsLockEntry {
                pin: Some("2.2".into()),
                hash: None,
            },
        );
        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps,
        };
        let json = serde_json::to_string_pretty(&lock).unwrap();
        assert!(json.contains("build_deps"), "should serialize build_deps");
        assert!(json.contains("pkgconf"));
        let back: LockFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.build_deps.len(), 1);

        // Pre-ADR-0018 lockfile (no build_deps key) still loads.
        let legacy = r#"{ "version": 1, "sources": {}, "snaps": {} }"#;
        let old: LockFile = serde_json::from_str(legacy).unwrap();
        assert!(old.build_deps.is_empty());
    }

    #[test]
    fn test_lockfile_serialization_format() {
        let mut snaps = HashMap::new();
        snaps.insert(
            "core22".into(),
            SnapLockEntry {
                revision: 1847,
                sha3_384: "d53e1c8a66cb03a99aed76f03c49c55ec6110e33c8cb4a12fb2c8715c9349a29321e877483a7bc7718fe552f2533397d".into(),
            },
        );

        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps,
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        // Verify the output format includes "sha3-384" key
        assert!(
            json.contains("sha3-384"),
            "JSON should contain sha3-384 key"
        );
        assert!(json.contains("revision"), "JSON should contain revision");
        assert!(json.contains("core22"));
    }

    #[test]
    fn test_input_lock_roundtrip() {
        let mut inputs = HashMap::new();
        inputs.insert(
            "packages".to_string(),
            InputLockEntry {
                revision: Some("c0ffee1234567890c0ffee1234567890c0ffee123".to_string()),
                sha256: Some(
                    "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef".to_string(),
                ),
                local: false,
                submodules: None,
            },
        );
        inputs.insert(
            "local-pkgs".to_string(),
            InputLockEntry {
                revision: None,
                sha256: None,
                local: true,
                submodules: None,
            },
        );

        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs,
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        assert!(json.contains("\"inputs\""), "should contain inputs section");
        assert!(json.contains("revision"));
        assert!(json.contains("local"));
        // local = false is skipped to keep the file readable
        assert!(!json.contains("false"), "local=false should be omitted");

        let back: LockFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.inputs.len(), 2);
        assert_eq!(
            back.inputs["packages"].revision.as_deref(),
            Some("c0ffee1234567890c0ffee1234567890c0ffee123")
        );
        assert_eq!(
            back.inputs["packages"].sha256.as_deref(),
            Some("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
        );
        assert!(!back.inputs["packages"].local);
        assert!(back.inputs["local-pkgs"].local);
        assert!(back.inputs["local-pkgs"].revision.is_none());
    }

    #[test]
    fn test_lockfile_without_inputs_backcompat() {
        // Pre-Phase-16 lockfiles have no `inputs` key — must still load.
        let json = r#"{ "version": 1, "sources": {}, "snaps": {} }"#;
        let lock: LockFile = serde_json::from_str(json).unwrap();
        assert_eq!(lock.version, 1);
        assert!(lock.inputs.is_empty());
    }

    #[test]
    fn test_input_entry_without_submodule_fields_backcompat() {
        // Pre-#43 input entries have no `submodules` key — must still load,
        // reading as "no submodule pins" (parent tree only).
        let json = r#"{
            "version": 1,
            "inputs": {
                "packages": {
                    "revision": "c0ffee1234567890c0ffee1234567890c0ffee123",
                    "sha256": "beef",
                    "local": false
                }
            }
        }"#;
        let lock: LockFile = serde_json::from_str(json).unwrap();
        let entry = &lock.inputs["packages"];
        assert_eq!(
            entry.revision.as_deref(),
            Some("c0ffee1234567890c0ffee1234567890c0ffee123")
        );
        assert!(entry.submodules.is_none(), "absent field loads as None");
    }

    #[test]
    fn test_input_entry_submodule_pins_roundtrip() {
        // Issue #43: parent rev + submodule name → submodule rev. The pin
        // map lives inside the input entry and round-trips through JSON.
        let mut subs = HashMap::new();
        subs.insert(
            "mylib".to_string(),
            SubmoduleLockEntry {
                path: "vendor/mylib".to_string(),
                revision: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
                sha256: "cafe".to_string(),
            },
        );
        let mut inputs = HashMap::new();
        inputs.insert(
            "valkey".to_string(),
            InputLockEntry {
                revision: Some("c0ffee1234567890c0ffee1234567890c0ffee123".to_string()),
                sha256: Some("beef".to_string()),
                local: false,
                submodules: Some(subs),
            },
        );
        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs,
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&lock).unwrap();
        assert!(json.contains("submodules"), "pins serialize");
        assert!(json.contains("vendor/mylib"), "path recorded");
        assert!(json.contains("fedcba9876543210fedcba9876543210fedcba98"));

        let back: LockFile = serde_json::from_str(&json).unwrap();
        let entry = &back.inputs["valkey"];
        let sub = &entry.submodules.as_ref().unwrap()["mylib"];
        assert_eq!(sub.path, "vendor/mylib");
        assert_eq!(sub.revision, "fedcba9876543210fedcba9876543210fedcba98");
        assert_eq!(sub.sha256, "cafe");

        // An entry without pins serializes no `submodules` key at all.
        let mut plain = HashMap::new();
        plain.insert(
            "local".to_string(),
            InputLockEntry {
                revision: None,
                sha256: None,
                local: true,
                submodules: None,
            },
        );
        let bare = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: plain,
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };
        let json = serde_json::to_string(&bare).unwrap();
        assert!(
            !json.contains("submodules"),
            "no submodule pins → no submodule key, got: {json}"
        );
    }

    #[test]
    fn test_save_atomic_no_temp_residue_and_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nau.lock");

        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };
        lock.save(&path).unwrap();
        assert!(path.exists());

        // Saving again (replace) must still leave exactly one file in the
        // directory: the lockfile itself. No `.tmp-*` residue may survive.
        lock.save(&path).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["nau.lock".to_string()], "no temp residue");
    }

    #[test]
    fn test_save_failure_leaves_existing_lockfile_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nau.lock");
        let lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };
        lock.save(&path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // A save whose temp file cannot be created (parent "dir" is a file)
        // must fail without touching the existing lockfile or leaving residue
        // next to it.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let bad_path = blocker.join("nested").join("nau.lock");
        assert!(lock.save(&bad_path).is_err());

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "failed save must not modify the lockfile");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 2, "only lockfile + blocker, no temp residue");
    }

    #[test]
    fn test_source_entry_without_validator_fields_backcompat() {
        // Pre-304-plan source entries carry no etag/validated_at — they
        // must still load, reading as "no probe validator" (full GET).
        let json = r#"{
            "version": 1,
            "sources": {
                "https://example.com/src.tar.gz": {
                    "sha256": "abc123"
                }
            }
        }"#;
        let lock: LockFile = serde_json::from_str(json).unwrap();
        let entry = &lock.sources["https://example.com/src.tar.gz"];
        assert_eq!(entry.sha256, "abc123");
        assert!(entry.etag.is_none(), "absent etag loads as None");
        assert!(entry.validated_at.is_none(), "absent stamp loads as None");
        assert!(
            entry.validators(now_unix()).is_none(),
            "no validator fields → no probe validators"
        );
    }

    #[test]
    fn test_source_entry_validator_fields_roundtrip_verbatim() {
        // The etag is stored verbatim (quoted form included, never
        // normalized) beside its validation stamp, and survives a
        // serialize → parse round-trip unchanged.
        let mut sources = HashMap::new();
        sources.insert(
            "https://example.com/src.tar.gz".to_string(),
            SourceLockEntry {
                sha256: "abc123".to_string(),
                etag: Some("\"33a64df551425fcc\"".to_string()),
                validated_at: Some(1_800_000_000),
            },
        );
        let lock = LockFile {
            version: 1,
            sources,
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        };
        let json = serde_json::to_string_pretty(&lock).unwrap();
        assert!(json.contains("\"etag\""), "etag serializes");
        assert!(json.contains("\"validated_at\""), "stamp serializes");
        assert!(
            json.contains("\\\"33a64df551425fcc\\\""),
            "the quoted etag form must survive verbatim: {json}"
        );
        let back: LockFile = serde_json::from_str(&json).unwrap();
        let entry = &back.sources["https://example.com/src.tar.gz"];
        assert_eq!(entry.etag.as_deref(), Some("\"33a64df551425fcc\""));
        assert_eq!(entry.validated_at, Some(1_800_000_000));

        // A fresh entry's validators carry the etag + the recorded sha.
        let validators = entry.validators(1_800_000_100).unwrap();
        assert_eq!(validators.etag, "\"33a64df551425fcc\"");
        assert_eq!(validators.recorded_sha256, "abc123");
    }

