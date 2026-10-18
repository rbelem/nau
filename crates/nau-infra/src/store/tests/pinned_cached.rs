use super::*;

    #[test]
    fn pinned_cached_hit_resolves_with_zero_store_routes() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, _) = cache_hello_payload(dir.path(), 29);
        let resolved =
            StoreClient::resolve_cached_with(&NoRunner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        assert_eq!(resolved.sha3_384, hello_payload_sha());
        // The local hit needs no download URL: download() short-circuits
        // on the same deterministic path.
        assert_eq!(resolved.download_url, "");
    }

    #[test]
    fn pinned_cache_miss_falls_back_to_the_store_verify_path() {
        let dir = tempfile::tempdir().unwrap();
        // Same pin shape, nothing cached: the blob is missing, so the
        // store-verify path must run (never a local guess).
        let pin = hello_pin(Some(29), Some(HELLO_DIGEST_HEX));
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_cached_with(&runner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        // The baseline re-verify cost, unchanged for the fallback: info
        // + snap-revision + account-key.
        assert_eq!(runner.route_count(), 3);
    }

    #[test]
    fn pinned_corrupt_cache_fails_closed_without_store_contact() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, cached) = cache_hello_payload(dir.path(), 29);
        std::fs::write(&cached, b"corrupted bytes").unwrap();
        let err =
            StoreClient::resolve_cached_with(&NoRunner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap_err()
                .to_string();
        assert!(err.contains("sha3-384 mismatch"), "{err}");
        assert!(err.contains("remove the file"), "{err}");
    }

    #[test]
    fn incomplete_pin_ignores_the_cache_and_takes_the_store_path() {
        let dir = tempfile::tempdir().unwrap();
        // A payload IS cached — but the pin carries no revision/digest,
        // so resolving it is the store query's job (channel head).
        let _ = cache_hello_payload(dir.path(), 29);
        let pin = hello_pin(None, None);
        let runner = FakeStore::new()
            .snap_info("latest", "stable")
            .assertion_chain();
        let resolved =
            StoreClient::resolve_cached_with(&runner, &pin, "latest/stable", "amd64", dir.path())
                .unwrap();
        assert_eq!(resolved.revision, 29);
        assert_eq!(runner.route_count(), 3);
    }

    #[test]
    fn fetch_of_a_pinned_cached_snap_makes_no_store_routes() {
        let dir = tempfile::tempdir().unwrap();
        let (pin, cached) = cache_hello_payload(dir.path(), 29);
        let path =
            StoreClient::fetch(&NoRunner, &pin, "latest/stable", "amd64", dir.path()).unwrap();
        assert_eq!(path, cached);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world\n");
    }
