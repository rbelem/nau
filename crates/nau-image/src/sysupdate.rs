//! The sysupdate OpenPGP signing layer (ADR-0024 §4, #267; issue #326
//! PR 3, R3): the release-media artifacts systemd-sysupdate verifies —
//! the device trust set, the per-key import pubring, the detached
//! `SHA256SUMS.gpg` — plus the stored-fragment loading/proving they
//! are built from. Release-flow-only consumers (image release/boot);
//! the root `sign` module re-exports this module for its ceremony
//! tests. `write_sysupdate_fragment` stays beside the root rotation
//! ceremony, which is its only writer.

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};
use pgp::composed::{DetachedSignature, SignedPublicKey};

use nau_core::sign::{
    keys_dir, parse_secret_key, rotation_key_path, sysupdate_fragment_path, KeyPair, Keychain,
};

// The OpenPGP PRIMITIVES (epoch pin, v4 EdDSALegacy packet framing,
// the import-pubring serialization) moved DOWN into `nau_infra::pgp`
// (issue #326 PR 8, the primitive/policy split); re-exported here —
// this module keeps the POLICY: what the release signs, where fragments
// persist, and what the device trusts.
pub use nau_infra::pgp::{
    import_pubring_pgp, sysupdate_openpgp_created, sysupdate_openpgp_packets,
    SYSUPDATE_OPENPGP_EPOCH, SYSUPDATE_OPENPGP_USER_ID,
};

/// Where the device trust anchor lives inside the staged rootfs — the
/// path systemd-sysupdate reads for `Verify=yes` (sysupdate.d(5)).
pub const IMPORT_PUBRING_EMBED_PATH: &str = "usr/lib/systemd/import-pubring.pgp";

/// The sysupdate manifest name (what the release publishes and what the
/// transfers' `Verify=` layer protects). Refusals name it.
pub const SYSUPDATE_MANIFEST_NAME: &str = "SHA256SUMS";

/// The detached signature sysupdate fetches beside [`SYSUPDATE_MANIFEST_NAME`].
pub const SYSUPDATE_MANIFEST_SIGNATURE_NAME: &str = "SHA256SUMS.gpg";

/// Load the pending rotation successor (`secret-key.new`).
/// `Ok(None)` when absent — no rotation is pending. A present-but-
/// unparseable file is a named error: corrupt ceremony state must never
/// silently drop the designated successor from the trust set.
pub fn load_rotation_key(home: &Path) -> miette::Result<Option<KeyPair>> {
    let path = rotation_key_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    parse_secret_key(&text)
        .map(Some)
        .wrap_err_with(|| format!("parsing {}", path.display()))
}

/// Persist `kp`'s sysupdate pubring fragment (the [`import_pubring_pgp`]
/// bytes) beside the trust anchors. The bytes are deterministic → the
/// write is an idempotent overwrite. Only possible while `kp`'s SEED
/// exists — the rotation ceremony writes each key's fragment at exactly
/// EXACTLY the anchor key's material (the same 32-byte Ed25519 public
/// point — the same seed's framing, hence the same fingerprint the epoch
/// contract pins). Any deviation is a named refusal, never a skip: a
/// trust set that cannot be fully certified must not be silently
/// narrowed to its remaining members.
pub fn load_sysupdate_fragment(
    keys_dir: &Path,
    key_id: &str,
    anchor_public: &[u8; 32],
) -> miette::Result<Vec<u8>> {
    use pgp::composed::Deserializable;
    use pgp::types::{EddsaLegacyPublicParams, KeyDetails, PublicParams};

    let path = sysupdate_fragment_path(keys_dir, key_id);
    let bytes = std::fs::read(&path).map_err(|e| {
        miette::miette!(
            "sysupdate pubring fragment for key {key_id} is missing at {} — the sysupdate \
             trust set is incomplete (fail closed); it is minted by `nau key rotate` \
             while that key is active, so re-run the rotation for it, or \
             `nau key revoke {key_id}` if the key is retired: {e}",
            path.display()
        )
    })?;
    let tpk = SignedPublicKey::from_bytes(std::io::Cursor::new(&bytes)).map_err(|e| {
        miette::miette!(
            "sysupdate pubring fragment {} does not parse as an OpenPGP public key — \
             refusing (fail closed): {e}",
            path.display()
        )
    })?;
    tpk.verify_bindings().map_err(|e| {
        miette::miette!(
            "sysupdate pubring fragment {} fails its own self-certification — refusing \
             (fail closed): {e}",
            path.display()
        )
    })?;
    match tpk.primary_key.public_params() {
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
            if key.as_bytes() != anchor_public {
                return Err(miette::miette!(
                    "sysupdate pubring fragment {} carries different key material than \
                     anchor {key_id}.pub — refusing (fail closed)",
                    path.display()
                ));
            }
        }
        _ => {
            return Err(miette::miette!(
                "sysupdate pubring fragment {} is not an Ed25519 (EdDSALegacy) key — \
                 refusing (fail closed)",
                path.display()
            ));
        }
    }
    Ok(bytes)
}

/// The device trust SET for `Verify=yes` (issue #290): every key the
/// ceremony has put in the trust path, each as a transferable OpenPGP
/// identity, concatenated into the single keyring embedded at
/// [`IMPORT_PUBRING_EMBED_PATH`] — the sysupdate analogue of the Ed25519
/// trusted-keys directory. Members:
///
/// - the ACTIVE ceremony key (always; derived fresh from its seed),
/// - the DESIGNATED successor while a rotation is pending
///   (`secret-key.new`, derived fresh from its seed),
/// - every trusted anchor `keys/<id>.pub` (the rotated-out keys of the
///   overlap window), from their stored fragments `keys/<id>.pgp`.
///
/// # The overlap window (ADR-0024 §4, mirrored from the Ed25519 ledger)
///
/// `nau key rotate` OPENS it: the successor is designated, and the
/// NEXT build embeds {current, successor} — while releases still SIGN
/// under the current key. That pre-provisioning is what makes rotation
/// survivable at all: the update channel can only deliver trust through
/// images the receiver already trusts, so a successor that first appears
/// in the pubring after `promote` (when it is already the signing key)
/// could never reach a fielded device — every post-promote release would
/// be refused by a single-key device, and the fleet would be bricked
/// until reflash (the exact failure this closes). `nau key promote`
/// flips the SIGNING key without changing pubring membership; `nau
/// key revoke <old>` CLOSES the window — the old anchor and fragment
/// drop out and the set narrows to the successor. (The Ed25519 keychain
/// deliberately stays stricter — a successor is not trusted until
/// promoted — because its verify path is operator-side and does not need
/// to bootstrap itself through the channel it protects.)
///
/// Deterministic (sorted key ids, epoch-stable identities per
/// [`SYSUPDATE_OPENPGP_EPOCH`]). Fail closed: a trusted anchor whose
/// fragment is missing, unparsable, unproven, or does not match its
/// anchor's material refuses the whole set ([`load_sysupdate_fragment`]).
pub fn sysupdate_pubring_pgp(active: &KeyPair, home: &Path) -> miette::Result<Vec<u8>> {
    let keys_dir = keys_dir(home);
    // The trusted anchors are the SAME set the Ed25519 embed copies —
    // `keys/*.pub`, malformed anchors refusing (fail closed).
    let chain = Keychain::load_dir(&keys_dir)?;
    let mut publics: std::collections::BTreeMap<String, [u8; 32]> =
        std::collections::BTreeMap::new();
    for (id, public) in chain.entries_for_verify() {
        publics.entry(id).or_insert(public);
    }

    // (key id, identity bytes) per member, sorted by id for byte-stable
    // keyrings.
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(pending) = load_rotation_key(home)? {
        let id = pending.key_id();
        if id != active.key_id() && !publics.contains_key(&id) {
            members.push((id, import_pubring_pgp(&pending)?));
        }
    }
    for (id, public) in &publics {
        if *id == active.key_id() {
            continue;
        }
        members.push((id.clone(), load_sysupdate_fragment(&keys_dir, id, public)?));
    }
    members.push((active.key_id(), import_pubring_pgp(active)?));
    members.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for (_, identity) in &members {
        out.extend_from_slice(identity);
    }
    Ok(out)
}

/// Sign the sysupdate manifest ([`SYSUPDATE_MANIFEST_NAME`], raw bytes)
/// under the ceremony key's OpenPGP identity; returns the detached
/// signature bytes for [`SYSUPDATE_MANIFEST_SIGNATURE_NAME`].
/// Deterministic — see the section docs.
pub fn sign_sysupdate_manifest(kp: &KeyPair, manifest_sums: &[u8]) -> miette::Result<Vec<u8>> {
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::ser::Serialize;
    use pgp::types::KeyDetails;

    let (secret, _) = sysupdate_openpgp_packets(kp)?;
    let created = sysupdate_openpgp_created()?;
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| miette::miette!("creation-time subpacket: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret.fingerprint()))
            .map_err(|e| miette::miette!("issuer-fingerprint subpacket: {e}"))?,
    ];
    config.unhashed_subpackets =
        vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(secret.legacy_key_id()))
                .map_err(|e| miette::miette!("issuer-key-id subpacket: {e}"))?,
        ];

    let signature = config
        .sign(
            &secret,
            &pgp::types::Password::empty(),
            std::io::Cursor::new(manifest_sums),
        )
        .map_err(|e| miette::miette!("signing {SYSUPDATE_MANIFEST_NAME}: {e}"))?;
    DetachedSignature::new(signature)
        .to_bytes()
        .map_err(|e| miette::miette!("serializing {SYSUPDATE_MANIFEST_SIGNATURE_NAME}: {e}"))
}

/// Device-side enforcement, mirrored from what systemd-sysupdate's gpg
/// step does with `Verify=yes`: parse the trust anchor
/// ([`sysupdate_pubring_pgp`] bytes) as a SET of transferable public
/// keys — fail closed on anything unparsable, on a set carrying secret
/// material, on an empty set, or on any member without a valid
/// self-certification — parse the detached signature (an empty or
/// unparsable one is an UNSIGNED manifest — a named refusal, never a
/// pass), and verify it over the manifest's raw bytes under ANY member
/// (the overlap window: gpg accepts signatures from either key). A
/// failed check names [`SYSUPDATE_MANIFEST_NAME`] — the operator sees
/// WHICH artifact refused. Returns the verifying key's OpenPGP
/// fingerprint.
pub fn verify_sysupdate_manifest_signature(
    pubring: &[u8],
    manifest_sums: &[u8],
    signature: &[u8],
) -> miette::Result<String> {
    use pgp::composed::Deserializable;
    use pgp::types::KeyDetails;

    if signature.is_empty() {
        return Err(miette::miette!(
            "{SYSUPDATE_MANIFEST_NAME} carries no signature — refusing an unsigned \
             sysupdate manifest (fail closed: {SYSUPDATE_MANIFEST_SIGNATURE_NAME} must \
             verify against import-pubring.pgp; ADR-0024 §4)"
        ));
    }
    let anchors = parse_pubring_set(pubring)?;
    for anchor in &anchors {
        anchor.verify_bindings().map_err(|e| {
            miette::miette!(
                "import-pubring.pgp carries a key that fails its own self-certification — \
                 refusing to verify {SYSUPDATE_MANIFEST_NAME} against an unproven trust \
                 anchor: {e}"
            )
        })?;
    }
    let detached = DetachedSignature::from_bytes(std::io::Cursor::new(signature)).map_err(|e| {
        miette::miette!(
            "{SYSUPDATE_MANIFEST_SIGNATURE_NAME} does not parse as an OpenPGP signature — \
             treating {SYSUPDATE_MANIFEST_NAME} as unsigned (fail closed): {e}"
        )
    })?;
    for anchor in &anchors {
        if detached.verify(&anchor.primary_key, manifest_sums).is_ok() {
            return Ok(anchor.primary_key.fingerprint().to_string());
        }
    }
    Err(miette::miette!(
        "{SYSUPDATE_MANIFEST_NAME} signature verification FAILED — the manifest \
         does not match {SYSUPDATE_MANIFEST_SIGNATURE_NAME} under any key in \
         import-pubring.pgp; refusing a tampered sysupdate manifest (ADR-0024 §4)"
    ))
}

/// Parse the embedded trust anchor as a SET of transferable PUBLIC keys
/// (issue #290): one OpenPGP identity per ceremony key, back to back.
/// Every parse error, a secret key (a device anchor is public material —
/// a secret packet here is a leak AND a broken anchor), or a set with no
/// members at all is a named refusal — an anchor that cannot be fully
/// parsed never verifies anything.
pub fn parse_pubring_set(pubring: &[u8]) -> miette::Result<Vec<SignedPublicKey>> {
    use pgp::composed::PublicOrSecret;

    let members = PublicOrSecret::from_bytes_many(std::io::Cursor::new(pubring)).map_err(|e| {
        miette::miette!(
            "import-pubring.pgp does not parse as an OpenPGP public key set — refusing \
             to verify {SYSUPDATE_MANIFEST_NAME} against a broken trust anchor: {e}"
        )
    })?;
    let mut anchors = Vec::new();
    for parsed in members {
        let key = parsed.map_err(|e| {
            miette::miette!(
                "import-pubring.pgp does not parse as an OpenPGP public key set — refusing \
                 to verify {SYSUPDATE_MANIFEST_NAME} against a broken trust anchor: {e}"
            )
        })?;
        match key {
            PublicOrSecret::Public(tpk) => anchors.push(tpk),
            PublicOrSecret::Secret(_) => {
                return Err(miette::miette!(
                    "import-pubring.pgp carries a SECRET key — a device trust anchor is \
                     public material only; refusing to verify {SYSUPDATE_MANIFEST_NAME} \
                     (fail closed)"
                ));
            }
        }
    }
    if anchors.is_empty() {
        return Err(miette::miette!(
            "import-pubring.pgp carries no OpenPGP keys — refusing an EMPTY trust set \
             (fail closed): {SYSUPDATE_MANIFEST_NAME} cannot verify"
        ));
    }
    Ok(anchors)
}
