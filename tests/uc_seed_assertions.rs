//! UC seed-assertion verification tests (issue #326 PR 3): these two
//! tests drive uc's emitted assertions through `assert`'s snapd-grammar
//! verifier — a cross-crate surface (`nau_image::uc` → `nau_infra::
//! assert`) that unit tests inside the image crate cannot reach (the
//! `crate::assert::` paths stopped resolving there when the assertion
//! machinery moved to nau-infra with the store client). Relocated to the
//! root crate verbatim, assertions unchanged; `test_key`/`snap_ids` are
//! local copies of the uc test fixtures they used.

use base64::Engine;
use std::collections::BTreeMap;

fn test_key() -> nau::uc::SnapdAssertionKey {
    let mut rng = rand::thread_rng();
    let secret = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    nau::uc::SnapdAssertionKey::from_secret(secret).unwrap()
}

fn snap_ids() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("core24".into(), "CQaUVdoKPUs8ekLmXsVwYGbTqUuDnyt2".into()),
        ("snapd".into(), "PMrrV4nl8Bewqvd2qJfWq0rkGODW30if".into()),
        (
            "pc-kernel".into(),
            "DjYcoStxHLAaZ86Rln_XYVbYwLr0S2mZ".into(),
        ),
        ("pc".into(), "99T7MUlRhtI3U0QFgl5mXXESAiSwt776".into()),
        (
            "network-manager".into(),
            "B9B7uy4iTkTVp9Sxr4HbLK0UXDTKsJwN".into(),
        ),
    ])
}

#[test]
fn signed_assertion_matches_the_snapd_wire_format() {
    let key = test_key();
    let image = nau::image::test_support::sample_image();
    let model = nau::uc::ModelAssertion::from_image(&image, "amd64", &snap_ids()).unwrap();
    let assert_text = model.to_assert(&key).unwrap();

    // Split at the LAST header's newline + the blank separator.
    // (`to_assert` stamps the key id header last — everything before it
    // is covered by the signature; everything after is the envelope.)
    let key_id = key.key_id();
    let header_tail = format!("sign-key-sha3-384: {key_id}\n");
    let pos = assert_text
        .find(&header_tail)
        .expect("stamped key id header present");
    let headers_end = pos + header_tail.len();
    // No body: the signed content ends at the LAST HEADER'S VALUE —
    // the separator after it supplies the final newline (snapd's
    // writer convention, matches the store's own wire samples).
    let content = &assert_text[..headers_end - 1];
    let rest = &assert_text[headers_end - 1..];
    assert!(
        rest.starts_with("\n\n"),
        "the blank separator completes the content/signature split"
    );

    // Envelope: base64( [0x01] ++ OpenPGP v4 RSA-SHA512 signature
    // packet ), verified with the public key — snapd's exact verify
    // path (content hash + signature trailer + RSA). assert.rs's
    // parser can't handle the model's multi-line `snaps:` list header
    // (store assertions have none), so assemble the verifier input
    // directly: content bytes + 0x01-stripped OpenPGP packets.
    let sig_text = rest[1..].trim_end();
    let joined: String = sig_text.split_whitespace().collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(joined.as_bytes())
        .unwrap();
    assert_eq!(raw[0], 1, "x/crypto v1 envelope prefix");
    let assertion = nau::assert::Assertion {
        assertion_type: "model".into(),
        authority_id: model.brand_id.clone(),
        sign_key_id: key_id,
        headers: BTreeMap::new(),
        content: content.as_bytes().to_vec(),
        body: Vec::new(),
        signature_packets: raw[1..].to_vec(),
    };
    nau::assert::verify_signature("model", "model", &assertion, &key.public_key().unwrap())
        .unwrap();
}

#[test]
fn account_chain_bootstraps_the_brand_trust() {
    let key = test_key();
    let brand = "test-brand";
    let ts = "2026-01-01T00:00:00.0Z";
    let ak = nau::uc::account_key_assertion(&key, brand, ts).unwrap();
    let acc = nau::uc::account_assertion(&key, brand, ts).unwrap();
    // Drive OUR OWN snapd-grammar verifier over the emitted bytes —
    // the same parse + envelope + OpenPGP verification assert.rs runs
    // against Store assertions.
    let ak_parsed = nau::assert::parse_assertion("account-key", &ak).unwrap();
    assert_eq!(ak_parsed.assertion_type, "account-key");
    // The body carries the public key packet (0x01 ‖ packet).
    assert!(!ak_parsed.body.is_empty(), "account-key body present");
    let pk = nau::assert::public_key_from_body("account-key", "body", &ak_parsed.body).unwrap();
    nau::assert::verify_signature("account-key", "self", &ak_parsed, &pk).unwrap();
    // The account-key id header matches snapd's derivation over the body key.
    assert!(ak.contains(&format!("public-key-sha3-384: {}\n", key.key_id())));
    assert!(ak.contains("body-length: "));

    // The account is signed by the SAME key and verifies against it.
    let acc_parsed = nau::assert::parse_assertion("account", &acc).unwrap();
    assert!(acc.contains("validation: certified\n"));
    nau::assert::verify_signature("account", "account", &acc_parsed, &pk).unwrap();
}
