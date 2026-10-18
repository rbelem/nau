use super::*;

    #[test]
    fn test_closure_key_varies_with_target() {
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        meta.target = None;
        let native = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        meta.target = Some("aarch64-linux-gnu".into());
        let aarch64 = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        meta.target = Some("x86_64-linux-gnu".into());
        let x86_64 = BuildClosure::for_meta(&meta, vec![], vec![]).cache_key();

        assert_ne!(native, aarch64);
        assert_ne!(native, x86_64);
        assert_ne!(aarch64, x86_64);

        // No target → stable "native" default
        meta.target = None;
        assert_eq!(
            native,
            BuildClosure::for_meta(&meta, vec![], vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_key_varies_with_require_revision() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let member = |pin: Option<&str>, hash: Option<&str>| RequiresMember {
            name: "zlib".into(),
            pin: pin.map(str::to_string),
            hash: hash.map(str::to_string),
        };

        let base =
            BuildClosure::for_meta(&meta, vec![member(Some("1.3"), None)], vec![]).cache_key();

        // Pin (revision/version) changed → different key
        let repinned =
            BuildClosure::for_meta(&meta, vec![member(Some("1.3.1"), None)], vec![]).cache_key();
        assert_ne!(base, repinned);

        // Lock hash appeared for the same pin → different key
        let hashed = BuildClosure::for_meta(&meta, vec![member(Some("1.3"), Some("aa"))], vec![])
            .cache_key();
        assert_ne!(base, hashed);

        // New dep in the closure → different key
        let mut two = vec![member(Some("1.3"), None)];
        two.push(RequiresMember {
            name: "gmp".into(),
            pin: Some("6.3".into()),
            hash: None,
        });
        assert_ne!(
            base,
            BuildClosure::for_meta(&meta, two.clone(), vec![]).cache_key()
        );

        // Same members → same key
        assert_eq!(
            BuildClosure::for_meta(&meta, two.clone(), vec![]).cache_key(),
            BuildClosure::for_meta(&meta, two, vec![]).cache_key()
        );
    }

    #[test]
    fn test_closure_requires_sorted_and_deduplicated() {
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let member = |name: &str| RequiresMember {
            name: name.to_string(),
            pin: None,
            hash: None,
        };

        // Same deps in different traversal order → identical key
        let order_a = vec![member("zlib"), member("gmp"), member("mpfr")];
        let order_b = vec![member("mpfr"), member("zlib"), member("gmp")];
        assert_eq!(
            BuildClosure::for_meta(&meta, order_a, vec![]).cache_key(),
            BuildClosure::for_meta(&meta, order_b, vec![]).cache_key()
        );

        // Duplicates collapse to one member
        let dup = vec![member("zlib"), member("zlib")];
        let closure = BuildClosure::for_meta(&meta, dup, vec![]);
        assert_eq!(closure.requires.len(), 1);
        assert_eq!(closure.requires[0].name, "zlib");
    }

    #[test]
    fn test_pinned_member_from_lock_data() {
        // Lock-only data (no I/O, works offline) resolves pin + content hash.
        let mut lock = nau_core::lock::LockFile {
            version: 1,
            sources: std::collections::HashMap::new(),
            snaps: std::collections::HashMap::new(),
            inputs: std::collections::HashMap::new(),
            packages: std::collections::HashMap::new(),
            build_deps: std::collections::HashMap::new(),
        };
        lock.record_snap(&crate::snap::SnapRef {
            name: "core22".into(),
            revision: Some(1847),
            sha3_384: Some("abc123".into()),
        });

        let member = pinned_member("core22", &lock).expect("pinned snap resolves");
        assert_eq!(member.name, "core22");
        assert_eq!(member.pin.as_deref(), Some("1847"));
        assert_eq!(member.hash.as_deref(), Some("abc123"));

        // Unpinned snap → None (caller falls back to version-pin, hash null)
        assert!(pinned_member("unknown", &lock).is_none());
    }

    #[test]
    fn test_lookup_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("missing", "https://example.com/missing.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);
        assert!(cache.lookup(&meta, "amd64", &closure).is_none());
    }

    #[test]
    fn test_store_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);

        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();

        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_infos: Vec::new(),
        };

        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        let cached = cache.lookup(&meta, "amd64", &closure);
        assert!(cached.is_some(), "should find cached snap");
        assert!(cached.unwrap().exists(), "cached file should exist");
        // Cached under the closure key directory
        assert!(dir
            .path()
            .join(closure.cache_key())
            .join("hello_1.0_amd64.snap")
            .exists());
    }

    #[test]
    fn test_lookup_differs_by_target_and_requires() {
        // Same meta, different closure → different key dir → no stale hits.
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let mut meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();
        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_infos: Vec::new(),
        };

        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();
        assert!(cache.lookup(&meta, "amd64", &closure).is_some());

        // Target change → miss
        meta.target = Some("aarch64-linux-gnu".into());
        let other_target = BuildClosure::for_meta(&meta, vec![], vec![]);
        assert!(cache.lookup(&meta, "amd64", &other_target).is_none());

        // Requires revision change → miss
        meta.target = None;
        let other_reqs = BuildClosure::for_meta(
            &meta,
            vec![RequiresMember {
                name: "zlib".into(),
                pin: Some("1.3".into()),
                hash: None,
            }],
            vec![],
        );
        assert!(cache.lookup(&meta, "amd64", &other_reqs).is_none());
    }

    #[test]
    fn test_meta_package_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));
        let meta = make_meta_meta("build-deps");
        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);

        // store should be a no-op for meta packages
        let output_dir = tempfile::tempdir().unwrap();
        // BuildResult with any filename (won't be stored)
        let result = BuildResult {
            snap_filename: "build-deps_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_infos: Vec::new(),
        };
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        // Should not find it
        assert!(cache.lookup(&meta, "amd64", &closure).is_none());
    }

    #[test]
    fn test_clear_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackageCache::new(Some(dir.path().to_path_buf()));

        // Store something
        let meta = make_source_meta("hello", "https://example.com/hello.tar.gz");
        let closure = BuildClosure::for_meta(&meta, vec![], vec![]);
        let output_dir = tempfile::tempdir().unwrap();
        let snap_path = output_dir.path().join("hello_1.0_amd64.snap");
        std::fs::write(&snap_path, b"fake snap content").unwrap();
        let result = BuildResult {
            snap_filename: "hello_1.0_amd64.snap".into(),
            version: "1.0".into(),
            source_infos: Vec::new(),
        };
        cache
            .store(&meta, &result, output_dir.path(), &closure)
            .unwrap();

        // Verify it's there
        assert!(cache.lookup(&meta, "amd64", &closure).is_some());

        // Clear
        cache.clear().unwrap();
        assert!(!dir.path().join("pkgs").exists());
    }
