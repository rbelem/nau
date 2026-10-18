use super::*;

    #[test]
    fn downgrade_is_refused_naming_both_revisions() {
        let err = check_downgrade(Some(9), 5, false).expect_err("newer installed must refuse");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "names both: {msg}");
        assert!(msg.contains("--allow-downgrade"), "names the escape: {msg}");
    }

    #[test]
    fn downgrade_allowed_only_when_explicit() {
        check_downgrade(Some(9), 5, true).expect("explicit --allow-downgrade lifts the rule");
        check_downgrade(Some(7), 7, false).expect("equal revision is not a downgrade");
        check_downgrade(Some(3), 7, false).expect("newer incoming is fine");
        check_downgrade(None, 1, false).expect("nothing installed — nothing to regress");
    }

    // ── Pure: URL mapping ──

    #[test]
    fn peer_urls_follow_the_wire_grammar() {
        let r = peer_ref();
        assert_eq!(
            manifest_url(&r, "hello").unwrap(),
            "http://peer.test:7780/manifests/hello"
        );
        assert_eq!(
            blob_url(&r, "hello", &"ab".repeat(32)).unwrap(),
            format!("http://peer.test:7780/blobs/{}", "ab".repeat(32))
        );
    }

    /// Bracketed IPv6 literals: the parsed host is the bare literal and
    /// the built URLs re-bracket it (an unbracketed `::1` in an http
    /// URL is not parseable by curl).
    #[test]
    fn bracketed_ipv6_references_map_to_bracketed_urls() {
        let r = PullRef::parse("nau://[::1]:7780/hello").unwrap();
        match &r {
            PullRef::Peer { host, port, pkg } => {
                assert_eq!(host, "::1");
                assert_eq!(*port, 7780);
                assert_eq!(pkg, "hello");
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        let default = PullRef::parse("nau://[::1]/hello").unwrap();
        match &default {
            PullRef::Peer { host, port, .. } => {
                assert_eq!(host, "::1");
                assert_eq!(*port, crate::pull_ref::DEFAULT_PEER_PORT);
            }
            other => panic!("expected Peer, got {other:?}"),
        }
        assert_eq!(
            manifest_url(&default, "hello").unwrap(),
            "http://[::1]:7780/manifests/hello"
        );
        assert_eq!(reference_string(&r), "nau://[::1]:7780/hello");
    }

    #[test]
    fn static_urls_derive_the_export_tree_dir() {
        let r = PullRef::parse("http://mirror.test:9000/mirror/vim").unwrap();
        assert_eq!(
            manifest_url(&r, "vim").unwrap(),
            "http://mirror.test:9000/mirror/manifests/vim.json"
        );
        assert_eq!(
            blob_url(&r, "vim", &"cd".repeat(32)).unwrap(),
            format!("http://mirror.test:9000/mirror/blobs/{}", "cd".repeat(32))
        );
        let nested = PullRef::parse("https://mirror.example/nau/ghi").unwrap();
        assert_eq!(
            manifest_url(&nested, "ghi").unwrap(),
            "https://mirror.example/nau/manifests/ghi.json"
        );
    }

    // ── Integration: the staged pipeline over a fake transport ──

    #[test]
    fn happy_path_stages_manifest_and_blob_then_dedups() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let report = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("a signed, fresh manifest stages");
        assert_eq!(report.fetched.len(), 1);
        assert_eq!(report.already_present.len(), 0);
        assert_eq!(report.signer, kp.key_id());
        assert_eq!(report.lane, "peer");
        assert_eq!(report.manifest_digest, sha256_hex(manifest_source(&pkg)));
        assert!(fx.store.blob_path(&blob_sha()).exists(), "blob landed");
        let inbox = crate::pkg_manifest::manifest_path(fx.store.root(), "hello");
        assert!(inbox.exists(), "manifest staged in the inbox");
        let round: PackageManifest =
            serde_json::from_slice(&std::fs::read(&inbox).unwrap()).unwrap();
        assert_eq!(round, pkg);

        // Re-pull: the blob is already present (re-verified, skipped).
        let again = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("re-pull dedups");
        assert_eq!(again.fetched.len(), 0);
        assert_eq!(again.already_present.len(), 1);
    }

    /// The manifest's `executable: true` survives staging (live
    /// 2026-10-02: the codecanary farm entry died with EACCES — the
    /// store write defaulted to 0644). The already-present arm runs the
    /// same mark, so a blob staged by an older build self-heals on the
    /// next pull.
    #[test]
    fn staged_blobs_carry_the_manifest_executable_bit() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("a signed, fresh manifest stages");
        let blob = fx.store.blob_path(&blob_sha());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&blob).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "executable manifest entry: {mode:o}");

        // Self-heal: a 0644 blob left by an older build is re-marked on
        // the next pull (dedup re-verifies, then re-marks).
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o644)).unwrap();
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("re-pull re-marks");
        let healed = std::fs::metadata(&blob).unwrap().permissions().mode();
        assert_eq!(healed & 0o111, 0o111, "self-healed: {healed:o}");
    }

    /// The staging inbox is single-file-per-package
    /// ([`crate::pkg_manifest::manifest_path`]): staging revision N
    /// OVERWRITES the same package's older entry — that overwrite IS
    /// the same-package sweep the ADR approved (ADR-0033 Decision 5).
    #[test]
    fn restaging_a_newer_revision_overwrites_the_inbox_entry() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);

        let older = signed_manifest(&kp); // revision 7
        let fetch_old = FakeFetch::peer(&manifest_source(&older), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch_old,
        )
        .expect("revision 7 stages");

        let mut newer = signed_manifest(&kp);
        newer.revision = 9;
        crate::pkg_manifest::sign(&mut newer, &kp).unwrap();
        let fetch_new = FakeFetch::peer(&manifest_source(&newer), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch_new,
        )
        .expect("revision 9 stages");

        let inbox = crate::pkg_manifest::manifest_path(fx.store.root(), "hello");
        let staged: PackageManifest =
            serde_json::from_slice(&std::fs::read(&inbox).unwrap()).unwrap();
        assert_eq!(staged.revision, 9, "the newer revision owns the file");

        let siblings: Vec<String> = std::fs::read_dir(inbox.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            siblings,
            vec!["hello.json".to_string()],
            "no sibling inbox entries may appear"
        );
    }

    #[test]
    fn tampered_blob_is_refused_naming_expected_and_actual() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let evil = b"tampered-payload!!".to_vec();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), evil)]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a flipped blob must be refused");
        let msg = err.to_string();
        assert!(msg.contains(&blob_sha()), "names expected: {msg}");
        assert!(
            msg.contains(&sha256_hex(b"tampered-payload!!")),
            "names actual: {msg}"
        );
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    #[test]
    fn corrupt_preexisting_store_blob_is_refused() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let dest = fx.store.blob_path(&blob_sha());
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"bitrot").unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("corrupt store content must refuse");
        assert!(err.to_string().contains("corrupt"), "{err}");
    }

    #[test]
    fn wrong_key_manifest_is_refused_naming_the_key() {
        let trusted = test_kp(1);
        let impostor = test_kp(2);
        let fx = Fixture::with_trust(&trusted);
        let pkg = signed_manifest(&impostor);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an untrusted signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id()), "names the key: {msg}");
        assert!(msg.contains("TOFU") || msg.contains("never"), "{msg}");
    }

    #[test]
    fn revoked_key_manifest_is_refused_via_the_revocation_list() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.list_operator_revoked(&kp.key_id());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a revoked signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REVOKED"), "{msg}");
        assert!(msg.contains(&kp.key_id()), "names the key: {msg}");
    }

    /// The union rule: a key the DEVICE image revokes is refused even
    /// though the operator keychain still trusts it — either list is
    /// sufficient, neither can mask the other.
    #[test]
    fn device_revocation_refuses_even_when_the_operator_keychain_trusts() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp); // operator keychain HAS kp
        fx.list_device_revoked(&kp.key_id()); // device list revokes it
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a device-revoked signer must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REVOKED"), "{msg}");
        assert!(msg.contains(&kp.key_id()), "names the key: {msg}");
    }

    /// The device image-baked anchor set verifies a manifest on its
    /// own: an empty operator keychain is not a refusal when the image
    /// anchors carry the key (Decision 7 consults BOTH sources).
    #[test]
    fn device_image_anchor_verifies_with_an_empty_operator_keychain() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.clear_operator_keychain();
        fx.install_device_anchor(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let report = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("the image-baked anchor verifies without operator keys");
        assert_eq!(report.signer, kp.key_id());
    }

    /// Nothing anchored anywhere — empty device set, empty keychain —
    /// is a named fail-closed refusal.
    #[test]
    fn no_anchors_anywhere_fails_closed_naming_both_sources() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.clear_operator_keychain();
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an empty trust chain must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("fail closed"), "{msg}");
        assert!(
            msg.contains(
                &fx.anchor_dir
                    .join("trusted-keys")
                    .to_string_lossy()
                    .to_string()
            ),
            "names the device anchors: {msg}"
        );
        assert!(
            msg.contains(&fx.keys.to_string_lossy().to_string()),
            "names the keychain: {msg}"
        );
    }

    #[test]
    fn unsigned_manifest_is_refused() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.signature.clear();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        assert!(
            pull_into_store(
                &fx.blobs(),
                fx.installed("hello"),
                &peer_ref(),
                &fx.anchor,
                &fx.keys,
                false,
                &fetch
            )
            .is_err(),
            "an unsigned manifest never stages"
        );
    }

    #[test]
    fn empty_keychain_fails_closed() {
        let kp = test_kp(1);
        let store_dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap(); // exists, but no anchors
        let anchor_dir = tempfile::tempdir().unwrap();
        let anchor = anchor_dir.path().join("update-key.pub");
        let fx_store = RuntimeStore::new(store_dir.path().to_path_buf());
        let pkg = signed_manifest(&kp);
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx_store.blob_store(),
            None,
            &peer_ref(),
            &anchor,
            keys_dir.path(),
            false,
            &fetch,
        )
        .expect_err("an empty trust chain must fail closed");
        assert!(err.to_string().contains("fail closed"), "{err}");
    }

    #[test]
    fn downgrade_gate_reads_the_pod_generation() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 9);
        let mut pkg = signed_manifest(&kp);
        pkg.revision = 5;
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("revision 5 over installed 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('5'), "{msg}");

        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            true,
            &fetch,
        )
        .expect("--allow-downgrade lifts the gate");
    }

    #[test]
    fn newer_and_equal_revisions_pass_the_gate() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        fx.seed_installed("hello", 7);
        let pkg = signed_manifest(&kp); // revision 7 == installed
        let fetch = FakeFetch::peer(&manifest_source(&pkg), &[(&blob_sha(), blob_bytes())]);
        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("equal revision is not a downgrade");
    }

