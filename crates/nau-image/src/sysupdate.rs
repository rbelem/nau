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

pub const SYSUPDATE_OPENPGP_USER_ID: &str =
    "nau sysupdate signing (ADR-0024 §4 import-pubring.pgp)";

/// Where the device trust anchor lives inside the staged rootfs — the
/// path systemd-sysupdate reads for `Verify=yes` (sysupdate.d(5)).
pub const IMPORT_PUBRING_EMBED_PATH: &str = "usr/lib/systemd/import-pubring.pgp";

/// The sysupdate manifest name (what the release publishes and what the
/// transfers' `Verify=` layer protects). Refusals name it.
pub const SYSUPDATE_MANIFEST_NAME: &str = "SHA256SUMS";

/// The detached signature sysupdate fetches beside [`SYSUPDATE_MANIFEST_NAME`].
pub const SYSUPDATE_MANIFEST_SIGNATURE_NAME: &str = "SHA256SUMS.gpg";

/// The epoch-stable creation time of the sysupdate OpenPGP identity
/// (2026-01-01T00:00:00Z, the seed-epoch default): every v4 key packet,
/// certification, and signature subpacket pins THIS constant, never the
/// per-release `SOURCE_DATE_EPOCH` (#289). The v4 fingerprint is a hash
/// over the key packet's creation time, and the fingerprint is the
/// identity a fielded device's gpg resolves — per-release epochs would
/// re-fingerprint the key on the first differently-epoch'd release and
/// refuse every fleet update. This constant keeps the value anchors
/// baked at the default epoch already carry. The release media's
/// byte-determinism pin (SOURCE_DATE_EPOCH-clamped image timestamps) is
/// a separate contract and stays as-is.
pub const SYSUPDATE_OPENPGP_EPOCH: u64 = 1_767_225_600;

/// The OpenPGP creation time pinned into every sysupdate-signature
/// subpacket AND the key packet: [`SYSUPDATE_OPENPGP_EPOCH`], a fixed
/// constant — deliberately NOT the per-release `SOURCE_DATE_EPOCH`
/// (see the constant's docs; #289).
pub fn sysupdate_openpgp_created() -> miette::Result<pgp::types::Timestamp> {
    pgp::types::Timestamp::try_from(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(SYSUPDATE_OPENPGP_EPOCH),
    )
    .map_err(|e| miette::miette!("anchor epoch out of OpenPGP timestamp range: {e}"))
}

/// The sysupdate OpenPGP key pair built from the ceremony seed: the v4
/// EdDSALegacy framing (algorithm 22, curve Ed25519) — the framing every
/// gpg since 2.1 verifies, unlike the RFC 9580 v6 framing. Returns the
/// secret-key packet (the signer) and its public-key packet (the
/// certification signee). The ed25519 secret IS the ceremony seed — no
/// second key exists to guard, mint, or rotate.
pub fn sysupdate_openpgp_packets(
    kp: &KeyPair,
) -> miette::Result<(pgp::packet::SecretKey, pgp::packet::PublicKey)> {
    use pgp::crypto::ed25519::Mode;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::types::{KeyVersion, PublicParams, SecretParams};

    let secret = pgp::crypto::ed25519::SecretKey::try_from_bytes(kp.seed, Mode::EdDSALegacy)
        .map_err(|e| miette::miette!("ceremony seed as OpenPGP Ed25519: {e}"))?;
    let public_params = PublicParams::EdDSALegacy((&secret).into());
    let secret_params = SecretParams::Plain(pgp::types::PlainSecretParams::EdDSALegacy(
        pgp::crypto::eddsa_legacy::SecretKey::Ed25519(secret),
    ));
    let created = sysupdate_openpgp_created()?;
    let inner = pgp::packet::PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        created,
        None,
        public_params,
    )
    .map_err(|e| miette::miette!("sysupdate OpenPGP public key packet: {e}"))?;
    let public = pgp::packet::PublicKey::from_inner(inner)
        .map_err(|e| miette::miette!("sysupdate OpenPGP public key packet: {e}"))?;
    let secret_packet = pgp::packet::SecretKey::new(public.clone(), secret_params)
        .map_err(|e| miette::miette!("sysupdate OpenPGP secret key packet: {e}"))?;
    Ok((secret_packet, public))
}

/// The device trust anchor for `Verify=yes`: the ceremony key as a
/// transferable OpenPGP public key (public-key packet + user id +
/// positive-certification self-signature), ready to embed at
/// [`IMPORT_PUBRING_EMBED_PATH`]. Deterministic — see the section docs.
pub fn import_pubring_pgp(kp: &KeyPair) -> miette::Result<Vec<u8>> {
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::packet::{
        KeyFlags, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId,
    };
    use pgp::types::KeyDetails;

    let (secret, public) = sysupdate_openpgp_packets(kp)?;
    let created = sysupdate_openpgp_created()?;
    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);

    let mut config = SignatureConfig::v4(
        SignatureType::CertPositive,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created))
            .map_err(|e| miette::miette!("creation-time subpacket: {e}"))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret.fingerprint()))
            .map_err(|e| miette::miette!("issuer-fingerprint subpacket: {e}"))?,
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))
            .map_err(|e| miette::miette!("key-flags subpacket: {e}"))?,
    ];
    config.unhashed_subpackets = vec![];

    let user_id = UserId::from_str(Default::default(), SYSUPDATE_OPENPGP_USER_ID)
        .map_err(|e| miette::miette!("sysupdate OpenPGP user id: {e}"))?;
    let cert = config
        .sign_certification(
            &secret,
            &public,
            &pgp::types::Password::empty(),
            pgp::types::Tag::UserId,
            &user_id,
        )
        .map_err(|e| miette::miette!("sysupdate key self-certification: {e}"))?;

    // Old-style keyring layout: a plain packet stream (key, id, cert).
    let mut out = Vec::new();
    public
        .to_writer_with_header(&mut out)
        .map_err(|e| miette::miette!("serializing the pubring key packet: {e}"))?;
    user_id
        .to_writer_with_header(&mut out)
        .map_err(|e| miette::miette!("serializing the pubring user id: {e}"))?;
    cert.to_writer_with_header(&mut out)
        .map_err(|e| miette::miette!("serializing the pubring certification: {e}"))?;
    Ok(out)
}

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
