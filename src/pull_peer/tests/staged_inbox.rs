use super::*;

    /// The gate reads the max of installed and STAGED revisions: a
    /// newer manifest sitting in the pull inbox blocks an older,
    /// validly-signed incoming one unless `--allow-downgrade` says
    /// otherwise — without this, a peer could silently walk a staged
    /// revision back.
    #[test]
    fn staged_inbox_revision_gates_the_downgrade_too() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);

        let mut staged = signed_manifest(&kp); // revision 7
        staged.revision = 9;
        crate::pkg_manifest::sign(&mut staged, &kp).unwrap();
        fx.stage_inbox(&staged);

        let older = signed_manifest(&kp); // revision 7, validly signed
        let fetch = FakeFetch::peer(&manifest_source(&older), &[(&blob_sha(), blob_bytes())]);

        let err = pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("revision 7 over staged 9 is a downgrade");
        let msg = err.to_string();
        assert!(msg.contains('9') && msg.contains('7'), "{msg}");

        pull_into_store(
            &fx.blobs(),
            fx.installed("hello"),
            &peer_ref(),
            &fx.anchor,
            &fx.keys,
            true,
            &fetch,
        )
        .expect("--allow-downgrade lifts the staged gate too");
    }

    /// A manifest built for another GNU triplet is refused before any
    /// blob downloads — the fetch carries no blob routes, so reaching
    /// the target error proves the download never started.
    #[test]
    fn foreign_target_manifest_is_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.target = "mips64-unknown-linux-gnu".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
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
        .expect_err("a foreign-target manifest must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("mips64-unknown-linux-gnu"),
            "names the manifest target: {msg}"
        );
        assert!(
            msg.contains(&crate::pkg_manifest::host_target()),
            "names the host target: {msg}"
        );
        assert!(
            !fx.store.blob_path(&blob_sha()).exists(),
            "nothing staged for a foreign target"
        );
    }

    /// Boundary validation of the declared payload paths (defense for
    /// the future install-from-inbox consumer): absolute paths and
    /// `..` segments are refused, naming the file.
    #[test]
    fn unsafe_payload_paths_are_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        for bad in ["/etc/passwd", "../../etc/passwd", "usr/../../etc/passwd"] {
            let mut pkg = signed_manifest(&kp);
            pkg.files[0].path = bad.to_string();
            crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
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
            .expect_err("an unsafe payload path must be refused");
            let msg = err.to_string();
            assert!(msg.contains("unsafe path"), "names the rule: {msg}");
            assert!(msg.contains(bad), "names the file: {msg}");
            assert!(
                !fx.store.blob_path(&blob_sha()).exists(),
                "nothing staged for an unsafe path"
            );
        }
    }

    // ── Static-tree fixtures (Decision 10: index + manifest + blobs) ──

    #[test]
    fn static_lane_stages_through_the_same_pipeline() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(
            &pkg,
            &[(&blob_sha(), blob_bytes())],
            Some(agreeing_index(&pkg)),
        );

        let report = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect("the static lane shares the peer verification path");
        assert_eq!(report.lane, "static");
        assert!(fx.store.blob_path(&blob_sha()).exists());
        assert!(
            crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "the verified manifest staged"
        );
    }

    /// A corrupted blob served by the public tree is refused at the
    /// hash gate: the mirror is untrusted infrastructure, so every
    /// byte is re-hashed against the signed manifest (the same gate
    /// the peer lane exercises in
    /// `tampered_blob_is_refused_naming_expected_and_actual`).
    #[test]
    fn static_lane_corrupted_blob_fails_closed_naming_expected_and_actual() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let evil = b"mirror-supplied-bytes!!".to_vec();
        let fetch = static_fetch(&pkg, &[(&blob_sha(), evil)], Some(agreeing_index(&pkg)));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a corrupted blob from the tree must refuse");
        let msg = err.to_string();
        assert!(msg.contains(&blob_sha()), "names expected: {msg}");
        assert!(
            msg.contains(&sha256_hex(b"mirror-supplied-bytes!!")),
            "names actual: {msg}"
        );
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "the manifest never stages when a blob fails"
        );
    }

    /// A tampered index.json — the revision walked back — refuses the
    /// pull: the signed manifest is the authority and the tree's own
    /// index must agree with it (Decision 10 end-to-end).
    #[test]
    fn tampered_index_revision_fails_closed_naming_both_sides() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp); // revision 7
        let index = index_json(&[("hello", "2.10", 6)]); // tampered down
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an index/manifest revision divergence must refuse");
        let msg = err.to_string();
        assert!(msg.contains("rev 6") && msg.contains("rev 7"), "{msg}");
        assert!(msg.contains("divergence"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "nothing staged"
        );
    }

    /// The index gate is a consistency gate, not the freshness policy:
    /// `--allow-downgrade` cannot pull from a tree whose index diverges
    /// from its own signed manifest.
    #[test]
    fn tampered_index_refuses_even_with_allow_downgrade() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let index = index_json(&[("hello", "2.10", 6)]);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        assert!(
            pull_into_store(
                &fx.store.blob_store(),
                fx.installed("hello"),
                &static_ref(),
                &fx.anchor,
                &fx.keys,
                true,
                &fetch
            )
            .is_err(),
            "allow-downgrade must not lift the index gate"
        );
    }

    #[test]
    fn tampered_index_version_fails_closed_naming_both_versions() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp); // version 2.10
        let index = index_json(&[("hello", "9.9", 7)]); // tampered version
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("an index/manifest version divergence must refuse");
        let msg = err.to_string();
        assert!(msg.contains("9.9") && msg.contains("2.10"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// An index that drops the package (the mirror "unlisting" content
    /// whose manifest still serves) diverges → refuse.
    #[test]
    fn index_missing_the_package_fails_closed() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let index = index_json(&[("other", "1.0", 1)]);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], Some(index));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a missing index row must refuse");
        let msg = err.to_string();
        assert!(msg.contains("does not list"), "{msg}");
        assert!(msg.contains("hello"), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// A mirror fronted by an error page answering 200 with HTML: the
    /// index does not parse, so the pull refuses instead of trusting a
    /// tree that cannot describe itself.
    #[test]
    fn unparseable_index_fails_closed_naming_the_url() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(
            &pkg,
            &[(&blob_sha(), blob_bytes())],
            Some(b"<html>502 Bad Gateway</html>".to_vec()),
        );

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a non-JSON index must refuse");
        let msg = err.to_string();
        assert!(msg.contains("not a valid index.json"), "{msg}");
        assert!(msg.contains(index_route().as_str()), "{msg}");
        assert!(!fx.store.blob_path(&blob_sha()).exists(), "nothing staged");
    }

    /// The gate is not optional: a static tree that cannot serve
    /// index.json at all (a 404 becomes a fetch error through the curl
    /// seam) refuses the pull.
    #[test]
    fn static_pull_without_a_served_index_fails_closed() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let pkg = signed_manifest(&kp);
        let fetch = static_fetch(&pkg, &[(&blob_sha(), blob_bytes())], None);

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a tree with no index must refuse");
        assert!(err.to_string().contains("fetching the tree index"), "{err}");
    }

    /// Manifest-layer fail-closed at the pull surface: flipping a byte
    /// of a signed manifest's body invalidates the signature → refused
    /// before any download (the fetch carries no blob routes — reaching
    /// the trust error proves nothing was fetched, nothing staged).
    #[test]
    fn tampered_manifest_body_fails_closed_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.files[0].sha256 = "ee".repeat(32); // tampered AFTER signing
        let fetch = static_fetch(&pkg, &[], Some(agreeing_index(&pkg)));

        let err = pull_into_store(
            &fx.store.blob_store(),
            None,
            &static_ref(),
            &fx.anchor,
            &fx.keys,
            false,
            &fetch,
        )
        .expect_err("a tampered manifest body must refuse");
        let msg = err.to_string();
        assert!(msg.contains("no trusted anchor"), "{msg}");
        assert!(
            !fx.store.blob_path(&"ee".repeat(32)).exists(),
            "nothing staged"
        );
        assert!(
            !crate::pkg_manifest::manifest_path(fx.store.root(), "hello").exists(),
            "nothing staged"
        );
    }

    #[test]
    fn malformed_declared_sha_is_refused_before_any_download() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.files[0].sha256 = "../../etc/passwd".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
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
        .expect_err("a non-hex blob address must be refused");
        assert!(err.to_string().contains("64 lowercase hex"), "{err}");
        // The manifest route existed but NO blob route did — reaching
        // the sha error proves the refusal happened before any fetch.
        assert!(!fx.store.blob_path(&pkg.files[0].sha256).exists());
    }

    #[test]
    fn manifest_name_must_match_the_reference() {
        let kp = test_kp(1);
        let fx = Fixture::with_trust(&kp);
        let mut pkg = signed_manifest(&kp);
        pkg.name = "other".to_string();
        crate::pkg_manifest::sign(&mut pkg, &kp).unwrap();
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
        .expect_err("a manifest naming another package must refuse");
        assert!(err.to_string().contains("'other'"), "{err}");
    }

    // ── One real loopback curl test (bounded, local socket only) ──

    #[test]
    fn curl_fetch_speaks_http_to_a_loopback_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let body = b"loopback-blob".to_vec();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("one connection");
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf); // the request line; not parsed
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).unwrap();
            sock.write_all(&body).unwrap();
        });
        let got = CurlFetch
            .get(&format!(
                "http://127.0.0.1:{port}/blobs/{}",
                "aa".repeat(32)
            ))
            .expect("curl fetches from the loopback server");
        server.join().unwrap();
        assert_eq!(got, b"loopback-blob");
    }
