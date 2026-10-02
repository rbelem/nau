//! OpenPGP PRIMITIVES for the sysupdate trust anchor (issue #326 PR 8,
//! the primitive/policy split): deterministic packet serialization —
//! the v4 EdDSALegacy framing of the ceremony seed as a transferable
//! public key. NO policy: what gets signed, where fragments persist,
//! and what the device trusts are the calling domains' decisions
//! (nau-image's sysupdate layer, the `nau key` ceremony in nau-trust).
//!
//! Determinism contract (#289): every packet pins
//! [`SYSUPDATE_OPENPGP_EPOCH`], a fixed constant — deliberately NOT the
//! per-release `SOURCE_DATE_EPOCH`. The v4 fingerprint is a hash over
//! the key packet's creation time, and the fingerprint is the identity
//! a fielded device's gpg resolves — per-release epochs would
//! re-fingerprint the key on the first differently-epoch'd release and
//! refuse every fleet update.

use nau_core::sign::KeyPair;

/// The sysupdate OpenPGP identity's user id.
pub const SYSUPDATE_OPENPGP_USER_ID: &str =
    "nau sysupdate signing (ADR-0024 §4 import-pubring.pgp)";

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
/// positive-certification self-signature), ready to embed at the
/// image layer's `IMPORT_PUBRING_EMBED_PATH`. Deterministic — see the
/// module docs.
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
