use super::*;

    #[test]
    fn sysupdate_manifest_signature_roundtrips_through_the_device_anchor() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();
        let sig = sign_sysupdate_manifest(&kp, &sums).unwrap();
        let pubring = import_pubring_pgp(&kp).unwrap();

        let fingerprint = verify_sysupdate_manifest_signature(&pubring, &sums, &sig).unwrap();
        assert_eq!(fingerprint, {
            use pgp::composed::Deserializable;
            use pgp::types::KeyDetails;
            let tpk = SignedPublicKey::from_bytes(std::io::Cursor::new(&pubring)).unwrap();
            tpk.primary_key.fingerprint().to_string()
        });
        // Deterministic: same key + same body → same detached signature
        // (the release media byte-identity property).
        assert_eq!(sign_sysupdate_manifest(&kp, &sums).unwrap(), sig);
    }

    /// Runs `f` with `SOURCE_DATE_EPOCH` pinned to `secs`, restoring the
    /// prior env afterwards. The env lock serializes the window against
    /// the other sysupdate tests in this module; no other test in the
    /// binary asserts env-derived values.

    #[test]
    fn sysupdate_anchor_identity_is_epoch_stable_cross_epoch_roundtrip() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();

        // Epoch A: the anchor a device's image baked at build time, and
        // the signature of the release it shipped with.
        let (anchor_a, sig_a) = with_source_date_epoch(1_700_000_000, || {
            (
                import_pubring_pgp(&kp).unwrap(),
                sign_sysupdate_manifest(&kp, &sums).unwrap(),
            )
        });
        // Epoch B ≠ A: the NEXT release, built on another machine, another
        // year, another SOURCE_DATE_EPOCH.
        let (anchor_b, sig_b) = with_source_date_epoch(1_900_000_000, || {
            (
                import_pubring_pgp(&kp).unwrap(),
                sign_sysupdate_manifest(&kp, &sums).unwrap(),
            )
        });

        // Identity stability: the anchor bytes (key packet + user id +
        // certification — everything the fingerprint hashes over) are
        // byte-identical across epochs. A moved fingerprint here IS the
        // fleet-wide refusal.
        assert_eq!(
            anchor_a, anchor_b,
            "the device trust anchor must not move with SOURCE_DATE_EPOCH (#289)"
        );
        // The detached signature is byte-identical too (deterministic
        // EdDSA over an epoch-free subpacket set).
        assert_eq!(
            sig_a, sig_b,
            "SHA256SUMS.gpg must be byte-identical across release epochs (#289)"
        );

        // The fleet scenario, both directions: verify the epoch-B release
        // signature against the epoch-A anchor a fielded device carries —
        // and the mirror leg.
        verify_sysupdate_manifest_signature(&anchor_a, &sums, &sig_b)
            .expect("a release signed at epoch B verifies under an anchor baked at epoch A");
        verify_sysupdate_manifest_signature(&anchor_b, &sums, &sig_a)
            .expect("a release signed at epoch A verifies under an anchor baked at epoch B");
    }

    #[test]
    fn tampered_sysupdate_manifest_is_refused_by_name() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();
        let sig = sign_sysupdate_manifest(&kp, &sums).unwrap();
        let pubring = import_pubring_pgp(&kp).unwrap();

        let mut tampered = sums.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        let err = verify_sysupdate_manifest_signature(&pubring, &tampered, &sig).unwrap_err();
        assert!(
            format!("{err:#}").contains("SHA256SUMS"),
            "the refusal names the manifest: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("FAILED"),
            "the refusal is a verification failure, not a parse error: {err:#}"
        );
    }

    #[test]
    fn unsigned_sysupdate_manifest_is_refused_by_name() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();
        let pubring = import_pubring_pgp(&kp).unwrap();

        for sig in [Vec::new(), b"not an openpgp signature".to_vec()] {
            let err = verify_sysupdate_manifest_signature(&pubring, &sums, &sig).unwrap_err();
            assert!(
                format!("{err:#}").contains("SHA256SUMS"),
                "the refusal names the manifest: {err:#}"
            );
        }
    }

    // ── Sysupdate/pgp suite (image-policy-coupled; stays root) ──

    /// THE #289 invariant: the sysupdate anchor identity is EPOCH-STABLE.
    /// A device's trust anchor is baked into its rootfs at its image's
    /// build epoch; a later `--release` under a DIFFERENT SOURCE_DATE_EPOCH
    /// must carry the SAME key id (the v4 fingerprint is hashed over the
    /// key packet's creation time), or gpg's issuer lookup dies with
    /// "No public key" and the whole fleet refuses its updates. Both legs
    /// sit away from the anchor constant on purpose: the layer must not
    /// read the per-release epoch AT ALL.
    #[test]
    fn sysupdate_manifest_signed_by_a_foreign_key_is_refused() {
        let (_, signer) = temp_keypair();
        let (_, anchor_key) = temp_keypair();
        let sums = sysupdate_sums();
        let sig = sign_sysupdate_manifest(&signer, &sums).unwrap();
        let pubring = import_pubring_pgp(&anchor_key).unwrap();
        let err = verify_sysupdate_manifest_signature(&pubring, &sums, &sig).unwrap_err();
        assert!(
            format!("{err:#}").contains("SHA256SUMS"),
            "the refusal names the manifest: {err:#}"
        );
    }

    #[test]
    fn broken_trust_anchor_is_a_named_refusal() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();
        let sig = sign_sysupdate_manifest(&kp, &sums).unwrap();
        let err = verify_sysupdate_manifest_signature(b"garbage", &sums, &sig).unwrap_err();
        assert!(
            format!("{err:#}").contains("import-pubring.pgp"),
            "the refusal names the anchor: {err:#}"
        );
    }

    // ── Sysupdate pubring trust SET — the rotation story (#290) ──

    /// THE #290 overlap-window round-trip: after rotate+promote, the
    /// embedded pubring is the SET {old, successor} and the device-side
    /// verify accepts a signature from EITHER key, while a third/
    /// unknown key still refuses. Both ceremony fragments were persisted
    /// at mint time and re-derived identically.
    #[test]
    fn sysupdate_trust_set_accepts_signatures_from_both_overlap_keys() {
        let (home, dir, old, successor) = promoted_overlap_fixture();
        let pubring = sysupdate_pubring_pgp(&successor, home.path()).unwrap();

        // Two members, and they are exactly the two ceremony keys'
        // identities (order: sorted by key id).
        let mut members = pubring_members(&pubring);
        members.sort();
        let mut want = vec![openpgp_public(&old), openpgp_public(&successor)];
        want.sort();
        assert_eq!(members, want, "the set is exactly the old + successor keys");

        // Each member's fragment is byte-identical to a fresh derivation
        // — the stored bytes ARE the epoch-stable identity.
        assert_eq!(
            std::fs::read(dir.join(format!("{}.pgp", old.key_id()))).unwrap(),
            import_pubring_pgp(&old).unwrap()
        );
        assert_eq!(
            std::fs::read(dir.join(format!("{}.pgp", successor.key_id()))).unwrap(),
            import_pubring_pgp(&successor).unwrap()
        );

        // Signatures from BOTH keys verify against the set.
        let sums = sysupdate_sums();
        let old_sig = sign_sysupdate_manifest(&old, &sums).unwrap();
        let new_sig = sign_sysupdate_manifest(&successor, &sums).unwrap();
        verify_sysupdate_manifest_signature(&pubring, &sums, &old_sig).unwrap();
        verify_sysupdate_manifest_signature(&pubring, &sums, &new_sig).unwrap();

        // A third/unknown key still refuses, by name.
        let (_, stranger) = temp_keypair();
        let stranger_sig = sign_sysupdate_manifest(&stranger, &sums).unwrap();
        let err = verify_sysupdate_manifest_signature(&pubring, &sums, &stranger_sig).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("SHA256SUMS"), "{msg}");
        assert!(msg.contains("FAILED"), "{msg}");

        // A tampered manifest refuses under the set too.
        let mut tampered = sums.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        let err = verify_sysupdate_manifest_signature(&pubring, &tampered, &new_sig).unwrap_err();
        assert!(format!("{err:#}").contains("FAILED"), "{err:#}");
    }

    /// The ROLLOUT half of #290: the window opens at `key rotate` —
    /// BEFORE promotion — because the transition release must be signed
    /// under the key fielded devices already trust while ALREADY carrying
    /// the successor's identity. A pubring built pre-promotion accepts
    /// both the old-key signature (what devices verify today) and the
    /// successor's (what they must accept after `promote`).
    #[test]
    fn designated_successor_rides_the_pubring_before_promotion() {
        let home = tempfile::tempdir().unwrap();
        let old = create_secret_key(home.path()).unwrap();
        let successor = mint_rotation_key(home.path()).unwrap();
        let _dir = keys_dir(home.path());

        // Active is STILL the old key; the successor is designated only
        // (secret-key.new, no anchor yet).
        assert_eq!(load_secret_key(home.path()).unwrap().unwrap(), old);

        let pubring = sysupdate_pubring_pgp(&old, home.path()).unwrap();
        let mut members = pubring_members(&pubring);
        members.sort();
        let mut want = vec![openpgp_public(&old), openpgp_public(&successor)];
        want.sort();
        assert_eq!(
            members, want,
            "pre-promotion set is the current + designated keys"
        );

        let sums = sysupdate_sums();
        verify_sysupdate_manifest_signature(
            &pubring,
            &sums,
            &sign_sysupdate_manifest(&old, &sums).unwrap(),
        )
        .expect("the transition release (signed under the current key) verifies");
        verify_sysupdate_manifest_signature(
            &pubring,
            &sums,
            &sign_sysupdate_manifest(&successor, &sums).unwrap(),
        )
        .expect("the pubring pre-provisions the designated successor");
    }

    /// Backward compatibility pinned byte-for-byte: with no rotation in
    /// flight, the trust set IS the legacy single-key pubring
    /// ([`import_pubring_pgp`]) — the single-key case works exactly as
    /// today.
    #[test]
    fn sysupdate_trust_set_without_a_rotation_is_the_legacy_single_key_pubring() {
        let (home, kp) = temp_keypair();
        // No keys-dir contents at all (no anchor even).
        let legacy = import_pubring_pgp(&kp).unwrap();
        assert_eq!(
            sysupdate_pubring_pgp(&kp, home.path()).unwrap(),
            legacy,
            "no anchors, no pending rotation → exactly the legacy bytes"
        );
        // With the anchor installed (the usual keygen state): same.
        install_public_key(&kp, &keys_dir(home.path())).unwrap();
        assert_eq!(sysupdate_pubring_pgp(&kp, home.path()).unwrap(), legacy);
        // And the device verify path is unchanged for it.
        let sums = sysupdate_sums();
        verify_sysupdate_manifest_signature(
            &legacy,
            &sums,
            &sign_sysupdate_manifest(&kp, &sums).unwrap(),
        )
        .unwrap();
    }

    /// Post-overlap semantics, mirroring the Ed25519 closed set: `key
    /// revoke <old>` closes the window — the old anchor AND fragment drop
    /// out, the set narrows to the successor alone, and an old-key
    /// signature refuses.
    #[test]
    fn sysupdate_trust_set_narrows_when_the_overlap_window_closes() {
        let (home, dir, old, successor) = promoted_overlap_fixture();
        let full = sysupdate_pubring_pgp(&successor, home.path()).unwrap();
        assert_eq!(pubring_members(&full).len(), 2);

        revoke_local(&dir, &old.key_id()).unwrap();
        assert!(
            !dir.join(format!("{}.pgp", old.key_id())).exists(),
            "revocation drops the fragment: the key cannot re-enter the set"
        );

        let narrowed = sysupdate_pubring_pgp(&successor, home.path()).unwrap();
        assert_eq!(
            narrowed,
            import_pubring_pgp(&successor).unwrap(),
            "post-revoke the set is the successor's solo (legacy-shaped) pubring"
        );
        assert_ne!(full, narrowed);

        let sums = sysupdate_sums();
        verify_sysupdate_manifest_signature(
            &narrowed,
            &sums,
            &sign_sysupdate_manifest(&successor, &sums).unwrap(),
        )
        .unwrap();
        let err = verify_sysupdate_manifest_signature(
            &narrowed,
            &sums,
            &sign_sysupdate_manifest(&old, &sums).unwrap(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("FAILED"),
            "old-key signature refuses after the window closes: {err:#}"
        );
    }

    /// Fail closed: a trusted anchor whose fragment is tampered (unparsable
    /// bytes, or a DIFFERENT key's identity under the anchor's id) refuses
    /// the whole set — never a silent skip that would narrow trust.
    #[test]
    fn sysupdate_trust_set_refuses_tampered_or_mismatched_fragments() {
        let (home, dir, old, successor) = promoted_overlap_fixture();
        let fragment = dir.join(format!("{}.pgp", old.key_id()));

        std::fs::write(&fragment, b"not openpgp").unwrap();
        let err = sysupdate_pubring_pgp(&successor, home.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not parse"),
            "unparsable fragment named: {err:#}"
        );

        // A valid-but-foreign identity under old's id: parses and
        // self-certifies, but the material does not match the anchor.
        let (_, impostor) = temp_keypair();
        std::fs::write(&fragment, import_pubring_pgp(&impostor).unwrap()).unwrap();
        let err = sysupdate_pubring_pgp(&successor, home.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("different key material"), "{msg}");
        assert!(msg.contains(&old.key_id()), "names the anchor: {msg}");
    }

    /// Fail closed: a trusted anchor with NO fragment refuses the build,
    /// naming the key and both remedies (re-run the rotation while the
    /// key is active, or revoke it).
    #[test]
    fn sysupdate_trust_set_refuses_a_missing_fragment_by_name() {
        let (home, dir, old, successor) = promoted_overlap_fixture();
        std::fs::remove_file(dir.join(format!("{}.pgp", old.key_id()))).unwrap();
        let err = sysupdate_pubring_pgp(&successor, home.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing"), "{msg}");
        assert!(msg.contains(&old.key_id()), "names the key: {msg}");
        assert!(msg.contains("revoke"), "names the remedy: {msg}");
    }

    /// Fail closed (device side): a pubring with no keys at all refuses —
    /// an empty trust set verifies nothing, even a valid signature.
    #[test]
    fn empty_pubring_set_is_a_named_refusal() {
        let (_, kp) = temp_keypair();
        let sums = sysupdate_sums();
        let sig = sign_sysupdate_manifest(&kp, &sums).unwrap();
        let err = verify_sysupdate_manifest_signature(b"", &sums, &sig).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("import-pubring.pgp"), "{msg}");
        assert!(msg.contains("EMPTY"), "{msg}");
    }

    /// #290 on #289's contract: the whole trust SET is epoch-stable —
    /// stored fragments are fixed bytes and the fresh derivations pin
    /// [`SYSUPDATE_OPENPGP_EPOCH`], so the embedded keyring is
    /// byte-identical across release epochs.
    #[test]
    fn sysupdate_trust_set_is_epoch_stable_across_release_epochs() {
        let (home, _dir, _old, successor) = promoted_overlap_fixture();
        let at_epoch = |secs: u64| {
            with_source_date_epoch(secs, || {
                sysupdate_pubring_pgp(&successor, home.path()).unwrap()
            })
        };
        assert_eq!(
            at_epoch(1_700_000_000),
            at_epoch(1_900_000_000),
            "the trust set must not move with SOURCE_DATE_EPOCH (#290 on #289's contract)"
        );
    }
