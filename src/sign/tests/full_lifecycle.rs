use super::*;

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
    let out =
        verify_with_ledger(&body, &manifest.signatures, &chain, &ledger, &[], T0 + DAY).unwrap();
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
        let out = verify_with_ledger(&body, &manifest.signatures, &chain, &ledger, &[], T0 + DAY)
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
    let attested = check_provenance(&manifest.signatures[&b.key_id()], &manifest.inputs).unwrap();
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
