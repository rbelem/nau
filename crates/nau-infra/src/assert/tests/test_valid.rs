use super::*;

    #[test]
    fn test_valid_chain_verifies() {
        chain(29).unwrap_or_else(|e| panic!("valid chain must verify: {e}"));
    }

    #[test]
    fn test_tampered_revision_header_fails_signature() {
        // Cross-checks are aligned with the tampered header, so only the
        // signature over the content can catch the flip.
        let tampered = SNAP_REVISION.replace("snap-revision: 29", "snap-revision: 28");
        let err = verify_chain(
            "hello-world",
            &tampered,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            28,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn test_tampered_account_key_body_fails() {
        let tampered = tamper_body_first_char(STORE_ACCOUNT_KEY);
        let err = chain_with(29, &tampered).unwrap_err();
        assert!(err.to_string().contains("untrusted"), "got: {err}");
    }

    #[test]
    fn test_wrong_revision_fails_cross_check() {
        let err = chain(28).unwrap_err();
        assert!(err.to_string().contains("revision"), "got: {err}");
    }

    #[test]
    fn test_wrong_digest_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            29,
            &hex_decode("hello-world", "digest", &"ab".repeat(48)).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains(SHA3_384), "got: {err}");
    }

    #[test]
    fn test_wrong_snap_id_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some("not-the-snap-id"),
            29,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE),
        )
        .unwrap_err();
        assert!(err.to_string().contains("snap id"), "got: {err}");
    }

    #[test]
    fn test_wrong_size_fails_cross_check() {
        let err = verify_chain(
            "hello-world",
            SNAP_REVISION,
            STORE_ACCOUNT_KEY,
            Some(HELLO_SNAP_ID),
            29,
            &hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap(),
            Some(HELLO_SIZE + 1),
        )
        .unwrap_err();
        assert!(err.to_string().contains("size"), "got: {err}");
    }

    #[test]
    fn test_unbound_account_key_fails() {
        // The root key is a valid account-key assertion, but the
        // snap-revision was signed by the store key — the id binding must
        // refuse it.
        let err = chain_with(29, TRUSTED_ROOT_ACCOUNT_KEY).unwrap_err();
        assert!(err.to_string().contains("sign-key-sha3-384"), "got: {err}");
    }

    #[test]
    fn test_digest_encoding_canonicalization() {
        // The store channel-map digest is hex; the assertion binds the same
        // bytes URL-safe-base64 encoded. Byte comparison must accept that.
        let hex = hex_decode("hello-world", "digest", HELLO_DIGEST_HEX).unwrap();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hex);
        let asserted = parse_assertion("hello-world", SNAP_REVISION).unwrap();
        assert_eq!(
            b64,
            asserted.header("snap-sha3-384").unwrap(),
            "same bytes, different encodings"
        );
    }

    #[test]
    fn test_parse_epoch() {
        assert_eq!(parse_epoch("2016-04-01T00:00:00.0Z"), Some(1_459_468_800));
        assert_eq!(
            parse_epoch("2019-04-17T16:44:02.929465Z"),
            Some(1_555_519_442)
        );
        assert_eq!(parse_epoch("nonsense"), None);
    }
