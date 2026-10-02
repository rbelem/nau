//! The update-manifest signing ceremony's ROOT shim (issue #326 PR 8):
//! the ceremony POLICY moved into `nau-trust` ([`nau_trust::sign`]) and
//! the on-device verify cluster into [`nau_trust::verify`]; the
//! keychain CORE is `nau_core::sign` (PR 3 down-move). This file
//! re-exports both so every pre-existing `crate::sign::` path — the
//! commands, the image verify path, tests/key_ceremony.rs — keeps
//! resolving, and keeps the two test clusters whose dependencies stayed
//! root: the eval-coupled provenance/attestation flows (chart's
//! `build_manifest`) and the sysupdate-image pgp suite (nau-image's
//! policy layer).

pub use nau_core::sign::{
    ceremony_ledger_path, create_secret_key, derive_pair, entry_signed_payload, from_hex32,
    install_public_key, keys_dir, load_secret_key, now_rfc3339, now_unix, parse_secret_key,
    provenance_bytes, public_key_file, read_revoked_keys, read_urandom32, reject_revoked,
    revoke_local, rfc3339_to_unix, rotation_key_path, secret_key_path, sign_bytes, subject_digest,
    sysupdate_fragment_path, to_hex, unix_to_rfc3339, verify, verify_keychain, verify_one,
    verify_trust_set, write_secret_key_at, CeremonyLedger, Invocation, KeyPair, Keychain,
    LedgerEntry, Provenance, SignatureEntry, SignatureEnvelope, Subject, CEREMONY_LEDGER_VERSION,
    DEFAULT_WINDOW_DAYS, PUBKEY_EMBED_PATH, PUBLIC_COMMENT, REVOKED_KEYS_EMBED_PATH,
    TRUSTED_KEYS_EMBED_DIR,
};

pub use nau_core::manifest_ir::eval_manifest_canonical_bytes;

// The ceremony policy + the verify cluster (issue #326 PR 8).
pub use nau_trust::sign::{
    attest_eval, builder_id, check_provenance, cosign, cosign_reattaching_provenance,
    mint_rotation_key, promote_rotation_key, provenance_for_manifest, revoke, rotate,
    sign_attested, verify_with_ledger, verify_with_ledger_now, LedgerVerification,
    PROVENANCE_VERSION,
};

// ── Sysupdate manifest signing (ADR-0024 §4, #267) ──
//
// systemd-sysupdate enforces the update channel ITSELF: a url-file
// transfer with `Verify=yes` fetches the release media's `SHA256SUMS`
// manifest plus a detached OpenPGP signature (`SHA256SUMS.gpg`) and
// verifies the signature with gpg against the keyring at
// `/usr/lib/systemd/import-pubring.pgp` inside the running rootfs
// (sysupdate.d(5) — the device's verity-protected copy of the file is the
// trust anchor). This layer produces exactly those artifacts:
//
// - [`sysupdate_pubring_pgp`] — the device trust SET: the active ceremony
//   key, its designated successor while a rotation is pending, and every
//   rotated-out key whose anchor still stands (the overlap window,
//   #290). Each member's secret half IS a ceremony seed (the v4
//   EdDSALegacy framing of the same ed25519 keys that sign image
//   manifests) — one secret, two encodings — but the SET, not the single
//   key, is the unit of trust: the channel can only deliver new trust
//   through images the receiver already accepts.
// - [`import_pubring_pgp`] — ONE member's identity (key packet + user id
//   + certification); also the legacy single-key spelling of the pubring
//   that [`sysupdate_pubring_pgp`] reduces to when no rotation exists.
// - [`sign_sysupdate_manifest`] — the `SHA256SUMS.gpg` detached
//   signature over the manifest's RAW bytes. No canonicalization exists
//   or may exist here: the signed body is byte-for-byte what sysupdate
//   downloads, so there is no third scheme alongside the eval-manifest
//   and image-manifest canonicalizations (their rule — one canonical
//   definition per manifest type — stays intact; this layer has none).
//
// Determinism: the key derivation is direct (no rng), and every OpenPGP
// creation time — the v4 key packet's, the certification's, the detached
// signature's — pins to a FIXED anchor epoch
// ([`SYSUPDATE_OPENPGP_EPOCH`]), deliberately DECOUPLED from the
// per-release `SOURCE_DATE_EPOCH` (#289): the v4 fingerprint is hashed
// over the key packet's creation time, and that fingerprint is the
// identity fielded devices resolve — derive it from a per-release epoch
// and the first differently-epoch'd release re-keys the fleet out of its
// own updates (gpg "No public key", every update refused). The pubring
// and signature bytes are byte-identical across epochs for the same
// ceremony key. (The release media's own byte-determinism pin — image
// timestamps under SOURCE_DATE_EPOCH — is a different contract, unchanged.)
//
// The layer's fns + consts moved to `nau-image` (`sysupdate` module,
// issue #326 PR 3, R3 — release-flow-only consumers) and are re-exported
// below; `write_sysupdate_fragment` stays root beside the rotation
// ceremony that calls it at exactly the mint/promote moments.

// The OpenPGP user id carried by the ceremony key's sysupdate identity
// (`import-pubring.pgp`). Pinned — it is part of the key's fingerprint
// material, so a change re-fingerprints the device keyring.
pub use nau_image::sysupdate::{
    import_pubring_pgp, load_rotation_key, load_sysupdate_fragment, parse_pubring_set,
    sign_sysupdate_manifest, sysupdate_openpgp_created, sysupdate_openpgp_packets,
    sysupdate_pubring_pgp, verify_sysupdate_manifest_signature, IMPORT_PUBRING_EMBED_PATH,
    SYSUPDATE_MANIFEST_NAME, SYSUPDATE_MANIFEST_SIGNATURE_NAME, SYSUPDATE_OPENPGP_EPOCH,
    SYSUPDATE_OPENPGP_USER_ID,
};

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::manifest_ir::ImageManifest;
    use std::collections::BTreeMap;

    const T0: i64 = 1_700_000_000;
    const DAY: i64 = 86_400;

    use ed25519_dalek::SigningKey;
    use pgp::composed::SignedPublicKey;
    use std::path::PathBuf;

    /// Per-crate copy (ADR-0053 ruling 6): the crate-side suite owns the
    /// original; the root ceremony tests stage keys through the same
    /// shape.
    fn temp_keypair() -> (tempfile::TempDir, KeyPair) {
        let home = tempfile::tempdir().unwrap();
        let kp = create_secret_key(home.path()).unwrap();
        (home, kp)
    }

    #[test]
    fn full_lifecycle_gen_sign_rotate_dual_verify_revoke() {
        // gen: the key is minted AND recorded in the ledger.
        let (home, old) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        install_public_key(&old, dir.path()).unwrap();
        let mut ledger = CeremonyLedger::load(dir.path()).unwrap();
        ledger.record_created(&old, &unix_to_rfc3339(T0));
        ledger.save(dir.path()).unwrap();

        // sign: the old key attests the manifest (issue #56 envelope).
        let mut manifest = manifest_with_github_input();
        attest_eval(
            &mut manifest,
            &old,
            "9.9.9",
            "amd64",
            "latest/stable",
            false,
        )
        .unwrap();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();

        // Either-key rule pre-rotation: the only signer verifies.
        let chain = Keychain::load_dir(dir.path()).unwrap();
        let out = verify_with_ledger(&body, &manifest.signatures, &chain, &ledger, &[], T0 + DAY)
            .unwrap();
        assert_eq!(out.key_id, old.key_id());
        assert!(out.warnings.is_empty());

        // rotate: successor minted, generation chain recorded, manifest
        // dual-signed with provenance re-attachment.
        let successor = mint_rotation_key(home.path()).unwrap();
        ledger.record_rotation(&old, &successor, &unix_to_rfc3339(T0), 30);
        ledger.save(dir.path()).unwrap();
        cosign_reattaching_provenance(&mut manifest, &successor).unwrap();
        assert!(manifest.signatures.contains_key(&old.key_id()));
        assert!(manifest.signatures.contains_key(&successor.key_id()));
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();

        // The window accepts either key: old-only, new-only, both.
        for anchored in [vec![&old], vec![&successor], vec![&old, &successor]] {
            let d = tempfile::tempdir().unwrap();
            let chain = chain_with(d.path(), &anchored);
            let out =
                verify_with_ledger(&body, &manifest.signatures, &chain, &ledger, &[], T0 + DAY)
                    .unwrap();
            assert!(out.warnings.is_empty(), "inside the window: no warning");
        }

        // revoke the old key: anchor removed, listed, dated in the ledger.
        install_public_key(&successor, dir.path()).unwrap();
        revoke_local(dir.path(), &old.key_id()).unwrap();
        ledger.record_revocation(&old.key_id(), &unix_to_rfc3339(T0 + DAY));
        ledger.save(dir.path()).unwrap();
        let revoked = read_revoked_keys(dir.path()).unwrap();
        assert_eq!(revoked, vec![old.key_id()]);

        // The dual-signed manifest keeps verifying through the live key —
        // revocation is not retroactive breakage.
        let chain = Keychain::load_dir(dir.path()).unwrap();
        let out = verify_with_ledger(
            &body,
            &manifest.signatures,
            &chain,
            &ledger,
            &revoked,
            T0 + 2 * DAY,
        )
        .unwrap();
        assert_eq!(out.key_id, successor.key_id());

        // A manifest signed ONLY by the revoked key fails with the named
        // error, which names the key.
        let mut old_only = manifest.clone();
        old_only.signatures.remove(&successor.key_id());
        let old_only_body = eval_manifest_canonical_bytes(&old_only).unwrap();
        let err = verify_with_ledger(
            &old_only_body,
            &old_only.signatures,
            &chain,
            &ledger,
            &revoked,
            T0 + 2 * DAY,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("REVOKED"), "named revocation error: {msg}");
        assert!(msg.contains(&old.key_id()), "names the revoked key: {msg}");
    }

    #[test]
    fn transition_window_warns_after_expiry_when_old_key_only() {
        let (home, old) = temp_keypair();
        let successor = mint_rotation_key(home.path()).unwrap();
        let mut ledger = CeremonyLedger::default();
        ledger.record_created(&old, &unix_to_rfc3339(T0));
        ledger.record_rotation(&old, &successor, &unix_to_rfc3339(T0), 30);

        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &old).unwrap();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let chain = chain_with(dir.path(), &[&old, &successor]);

        // Inside the window: clean verify, no warning.
        let out = verify_with_ledger(
            &body,
            &manifest.signatures,
            &chain,
            &ledger,
            &[],
            T0 + 10 * DAY,
        )
        .unwrap();
        assert_eq!(out.key_id, old.key_id());
        assert!(out.warnings.is_empty());

        // Past the window: still verifies (warn, never fail) — but the
        // operator is told the artifact carries only the rotated-out key.
        let out = verify_with_ledger(
            &body,
            &manifest.signatures,
            &chain,
            &ledger,
            &[],
            T0 + 31 * DAY,
        )
        .unwrap();
        assert_eq!(out.key_id, old.key_id());
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(out.warnings[0].contains("transition window expired"));
        assert!(out.warnings[0].contains(&successor.key_id()));

        // A dual-signed manifest past the window verifies through the
        // live key with no warning — the fresh signature wins.
        cosign(&mut manifest, &successor).unwrap();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let out = verify_with_ledger(
            &body,
            &manifest.signatures,
            &chain,
            &ledger,
            &[],
            T0 + 31 * DAY,
        )
        .unwrap();
        assert_eq!(out.key_id, successor.key_id());
        assert!(out.warnings.is_empty());
    }

    #[test]
    fn rotation_resign_reattaches_provenance_verbatim() {
        let (_, old) = temp_keypair();
        let (_, successor) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &old, "9.9.9", "amd64", "latest/stable", true).unwrap();
        let old_entry = manifest.signatures[&old.key_id()].clone();
        let old_prov = check_provenance(&old_entry, &manifest.inputs)
            .unwrap()
            .expect("attested");

        cosign_reattaching_provenance(&mut manifest, &successor).unwrap();

        // The old entry is untouched; the successor's carries the SAME
        // claims under a NEW signature (materials unchanged → same
        // attestation, new signature).
        assert_eq!(manifest.signatures[&old.key_id()], old_entry);
        let succ_entry = &manifest.signatures[&successor.key_id()];
        let succ_prov = check_provenance(succ_entry, &manifest.inputs)
            .unwrap()
            .expect("re-attached attestation");
        assert_eq!(succ_prov, old_prov);
        assert_ne!(
            succ_entry, &old_entry,
            "the envelope itself differs (new signer)"
        );

        // Both verify over the unchanged canonical body.
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        verify(&body, &manifest.signatures, &old.public_hex()).unwrap();
        verify(&body, &manifest.signatures, &successor.public_hex()).unwrap();
    }

    #[test]
    fn resign_refuses_stale_provenance_subject() {
        let (_, kp) = temp_keypair();
        let (_, successor) = temp_keypair();
        // An attestation minted over a DIFFERENT body than the manifest
        // it is attached to: re-attaching it would lie about the bytes.
        let mut other = manifest_with_github_input();
        attest_eval(&mut other, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
        let prov: Provenance = {
            let parsed: SignatureEntry =
                serde_json::from_value(other.signatures[&kp.key_id()].clone()).unwrap();
            parsed.provenance().unwrap().clone()
        };

        let mut target = minimal_manifest();
        sign_attested(&mut target, &kp, &prov).unwrap();
        let err = cosign_reattaching_provenance(&mut target, &successor).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not bind the current manifest bytes"),
            "stale claims refused: {msg}"
        );
        assert!(
            !target.signatures.contains_key(&successor.key_id()),
            "no signature was added on refusal"
        );
    }

    /// A minimal eval manifest (per-crate copy, ADR-0053 ruling 6 — the
    /// crate-side suite owns the original).
    fn minimal_manifest() -> ImageManifest {
        ImageManifest {
            manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        }
    }

    fn chain_with(dir: &std::path::Path, kps: &[&KeyPair]) -> Keychain {
        for kp in kps {
            install_public_key(kp, dir).unwrap();
        }
        Keychain::load_dir(dir).unwrap()
    }

    fn manifest_with_github_input() -> ImageManifest {
        let declared = std::collections::HashMap::from([(
            "pkgs".to_string(),
            crate::snap::PackageInput {
                url: "github:owner/repo/main".into(),
                submodules: None,
            },
        )]);
        let mut lockfile = crate::lock::LockFile {
            version: 1,
            sources: std::collections::HashMap::new(),
            snaps: std::collections::HashMap::new(),
            inputs: std::collections::HashMap::new(),
            packages: std::collections::HashMap::new(),
            build_deps: std::collections::HashMap::new(),
        };
        lockfile.inputs.insert(
            "pkgs".into(),
            crate::lock::InputLockEntry {
                revision: Some("c0ffee".into()),
                sha256: Some("beef".into()),
                local: false,
                submodules: None,
            },
        );
        crate::manifest::build_manifest(
            &crate::lua::Outputs::new(),
            &std::collections::HashMap::new(),
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap()
    }

    /// Deterministic keypair so the golden envelope test is stable.
    fn fixed_kp() -> KeyPair {
        let seed = [0x42u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        KeyPair {
            seed,
            public: signing.verifying_key().to_bytes(),
        }
    }

    /// Flip one provenance field inside the stored entry and write it
    /// back — the tamper an attacker (or a lying signer) produces.
    fn tamper_provenance(manifest: &mut ImageManifest, key_id: &str) {
        let mut entry: SignatureEntry =
            serde_json::from_value(manifest.signatures[key_id].clone()).unwrap();
        match &mut entry {
            SignatureEntry::Attested { provenance, .. } => {
                provenance.as_mut().unwrap().builder_id = "nau:0.0.0-lies".into();
            }
            SignatureEntry::Bare(_) => panic!("expected an attested entry"),
        }
        manifest
            .signatures
            .insert(key_id.to_string(), serde_json::to_value(&entry).unwrap());
    }

    #[test]
    fn attested_signature_verifies_and_binds_the_body() {
        let (_, kp) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();

        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        verify(&body, &manifest.signatures, &kp.public_hex()).unwrap();

        // The entry is an attested envelope whose subject digests the body.
        let parsed: SignatureEntry =
            serde_json::from_value(manifest.signatures[&kp.key_id()].clone()).unwrap();
        let prov = parsed.provenance().expect("attested entry carries claims");
        assert_eq!(prov.version, PROVENANCE_VERSION);
        assert_eq!(prov.builder_id, "nau:9.9.9");
        assert_eq!(prov.invocation.arch, "amd64");
        assert_eq!(prov.invocation.channel, "latest/stable");
        assert!(!prov.invocation.offline);
        assert_eq!(prov.subject.manifest_sha3_384, subject_digest(&body));
        assert_eq!(
            prov.subject.name, "manifest",
            "the attested output is the canonical manifest body"
        );
    }

    #[test]
    fn tampered_provenance_fails_verification() {
        let (_, kp) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
        let key_id = kp.key_id();
        tamper_provenance(&mut manifest, &key_id);

        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let err = verify(&body, &manifest.signatures, &kp.public_hex()).unwrap_err();
        assert!(
            format!("{err:#}").contains("FAILED"),
            "any provenance flip must break the signature: {err:#}"
        );
    }

    #[test]
    fn legacy_bare_signatures_still_verify_beside_attested() {
        let (home_a, a) = temp_keypair();
        let (_, b) = temp_keypair();
        let _ = home_a;
        let mut manifest = manifest_with_github_input();
        // `a` signs the old way (bare string entry, body-only coverage) —
        // an old manifest or an old signer must keep verifying.
        cosign(&mut manifest, &a).unwrap();
        // `b` signs the new way (attested envelope) beside it.
        attest_eval(&mut manifest, &b, "9.9.9", "amd64", "latest/stable", false).unwrap();

        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        verify(&body, &manifest.signatures, &a.public_hex()).unwrap();
        verify(&body, &manifest.signatures, &b.public_hex()).unwrap();

        // The bare entry carries no claims; check_provenance says so.
        let bare = check_provenance(&manifest.signatures[&a.key_id()], &manifest.inputs).unwrap();
        assert!(bare.is_none(), "legacy entries are claim-free");
        let attested =
            check_provenance(&manifest.signatures[&b.key_id()], &manifest.inputs).unwrap();
        assert!(attested.is_some(), "attested entries surface their claims");
    }

    #[test]
    fn provenance_subject_mismatch_is_a_named_error() {
        let (_, kp) = temp_keypair();
        let mut a = manifest_with_github_input();
        attest_eval(&mut a, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
        let prov: Provenance = {
            let parsed: SignatureEntry =
                serde_json::from_value(a.signatures[&kp.key_id()].clone()).unwrap();
            parsed.provenance().unwrap().clone()
        };

        // Attach a's attestation to a DIFFERENT body: the signature still
        // covers the pair, but the claims do not bind these bytes —
        // refused by name before the Ed25519 check.
        let mut b = minimal_manifest();
        sign_attested(&mut b, &kp, &prov).unwrap();
        let body_b = eval_manifest_canonical_bytes(&b).unwrap();
        let err = verify(&body_b, &b.signatures, &kp.public_hex()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not bind these manifest bytes"),
            "subject mismatch must be named: {msg}"
        );
        assert!(
            msg.contains(&prov.subject.manifest_sha3_384),
            "attested digest named: {msg}"
        );
    }

    #[test]
    fn check_provenance_requires_materials_to_match_manifest_inputs() {
        let (_, kp) = temp_keypair();
        let mut signed = manifest_with_github_input();
        attest_eval(&mut signed, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
        let entry = signed.signatures[&kp.key_id()].clone();

        // The attestation mirrors the manifest it rode in on: equal inputs pass.
        check_provenance(&entry, &signed.inputs).unwrap();

        // A manifest with a DIFFERENT input inventory: the attestation is
        // a lie about its materials — refused.
        let bare_manifest = minimal_manifest();
        let err = check_provenance(&entry, &bare_manifest.inputs).unwrap_err();
        assert!(
            format!("{err:#}").contains("materials do not match the manifest inputs"),
            "{err:#}"
        );
    }

    #[test]
    fn attested_envelope_json_is_a_deliberate_golden() {
        let mut manifest = manifest_with_github_input();
        let kp = fixed_kp();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let entry = &manifest.signatures[&kp.key_id()];
        let sig = entry["signature"].as_str().expect("signature field");
        let json = serde_json::to_string(entry).unwrap();
        // The stored entry is a serde_json::Value (BTreeMap keys), so the
        // envelope's key order is sorted-deterministic — this literal is
        // the deliberate golden; update it only with the schema.
        let want = format!(
            concat!(
                r#"{{"provenance":{{"builder_id":"nau:9.9.9","#,
                r#""invocation":{{"arch":"amd64","channel":"latest/stable","offline":false}},"#,
                r#""materials":{{"pkgs":{{"revision":"c0ffee","sha256":"beef","#,
                r#""url":"github:owner/repo/main"}}}},"#,
                r#""subject":{{"manifest_sha3_384":"{digest}","name":"manifest"}},"version":1}},"#,
                r#""signature":"{sig}"}}"#
            ),
            sig = sig,
            digest = subject_digest(&body),
        );
        assert_eq!(
            json, want,
            "envelope shape is a deliberate golden — update it only with the schema"
        );
    }

    #[test]
    fn attested_signatures_stay_out_of_eval_manifest_canonical_bytes() {
        let (_, kp) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", true).unwrap();
        // Byte-identical eval is the hard constraint (issue #56): a fully
        // attested manifest's canonical bytes are exactly the unsigned
        // golden — builder/host facts never enter the body.
        assert_eq!(
            eval_manifest_canonical_bytes(&manifest).unwrap(),
            eval_manifest_canonical_bytes(&manifest_with_github_input()).unwrap()
        );
    }

    #[test]
    fn keychain_verifies_attested_entries_and_fails_on_tamper() {
        let (_, kp) = temp_keypair();
        let (_, other) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", true).unwrap();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let chain = chain_with(dir.path(), &[&kp, &other]);

        let verified = verify_keychain(&body, &manifest.signatures, &chain).unwrap();
        assert_eq!(verified, kp.key_id());

        let key_id = kp.key_id();
        tamper_provenance(&mut manifest, &key_id);
        let err = verify_keychain(&body, &manifest.signatures, &chain).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted signature verifies"),
            "tampered provenance fails the whole chain: {err:#}"
        );
    }

    #[test]
    fn import_pubring_is_deterministic_and_self_certified() {
        let (_, kp) = temp_keypair();
        let first = import_pubring_pgp(&kp).unwrap();
        let second = import_pubring_pgp(&kp).unwrap();
        // Byte-stable derivation: the release determinism property (two
        // builds at the same epoch embed identical keyrings).
        assert_eq!(first, second);
        // Parses as a transferable public key whose self-certification
        // holds — the fail-closed precondition of the verify path.
        use pgp::composed::Deserializable;
        let tpk = SignedPublicKey::from_bytes(std::io::Cursor::new(&first)).unwrap();
        tpk.verify_bindings().unwrap();
    }

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

    fn sysupdate_sums() -> Vec<u8> {
        b"1111...  nau-cassini-1.0.0-amd64.img\n\
          2222...  nau-cassini-1.0.0-amd64.manifest.json\n"
            .to_vec()
    }

    fn with_source_date_epoch<T>(secs: u64, f: impl FnOnce() -> T) -> T {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _held = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("SOURCE_DATE_EPOCH").ok();
        std::env::set_var("SOURCE_DATE_EPOCH", secs.to_string());
        let out = f();
        match prior {
            Some(v) => std::env::set_var("SOURCE_DATE_EPOCH", v),
            None => std::env::remove_var("SOURCE_DATE_EPOCH"),
        }
        out
    }

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

    /// The parsed members of a pubring blob: (fingerprint, Ed25519 public
    /// bytes) per transferable key, refusing on anything unparsable.
    fn pubring_members(pubring: &[u8]) -> Vec<[u8; 32]> {
        use pgp::composed::PublicOrSecret;
        use pgp::types::{EddsaLegacyPublicParams, KeyDetails, PublicParams};
        PublicOrSecret::from_bytes_many(std::io::Cursor::new(pubring))
            .unwrap()
            .map(|k| k.unwrap())
            .map(|k| match k {
                PublicOrSecret::Public(tpk) => match tpk.primary_key.public_params() {
                    PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
                        *key.as_bytes()
                    }
                    other => panic!("non-Ed25519 member: {other:?}"),
                },
                PublicOrSecret::Secret(_) => panic!("secret key in a device pubring"),
            })
            .collect()
    }

    /// Drive the real ceremony to the POST-PROMOTION overlap state: `old`
    /// created and anchored (as `key keygen` does), successor minted
    /// (fragments persisted), successor promoted (active; old anchor left
    /// standing). Returns the temp home (keep alive!), the keys dir, and
    /// both keys.
    fn promoted_overlap_fixture() -> (tempfile::TempDir, PathBuf, KeyPair, KeyPair) {
        let home = tempfile::tempdir().unwrap();
        let old = create_secret_key(home.path()).unwrap();
        let dir = keys_dir(home.path());
        install_public_key(&old, &dir).unwrap();
        let successor = mint_rotation_key(home.path()).unwrap();
        promote_rotation_key(home.path(), &dir).unwrap();
        (home, dir, old, successor)
    }

    fn openpgp_public(kp: &KeyPair) -> [u8; 32] {
        kp.public
    }

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
}
