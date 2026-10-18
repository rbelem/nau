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
mod tests;
