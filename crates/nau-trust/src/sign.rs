//! The update-manifest signing ceremony — the trust POLICY half
//! (ADR-0024 §4, ADR-0011 step (d); issue #326 PR 8 crate extraction).
//!
//! The keychain CORE (key material, on-disk layout, revocation list,
//! ceremony ledger, time/hex helpers) lives in `nau_core::sign` (PR 3
//! down-move) — imported, never duplicated. This module owns the
//! CEREMONY POLICY: SLSA-lite provenance (issue #56), the
//! attest/cosign pair, rotation (mint/promote/revoke with the dual-trust
//! overlap window), the ledger-policy verify cluster (issue #51), and
//! the sysupdate pubring-fragment persistence (the packet primitives
//! are `nau_infra::pgp`'s — the primitive/policy split, PR 8).
//!
//! The on-device verify cluster lives in [`crate::verify`].

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};
use nau_core::manifest_ir::{eval_manifest_canonical_bytes, ImageManifest, ManifestInput};
// The keychain core: the moved fns were written against the root
// sign.rs's full re-export scope — mirrored here as a glob (no name
// collides: the ceremony-policy names are this module's own).
use nau_core::sign::*;
use serde::Serialize;

// ── SLSA-lite provenance (issue #56) ──

// ── SLSA-lite provenance (issue #56) ──

/// Provenance payload schema version — independent of the manifest schema,
/// bumped when the attestation claims change meaning.
pub const PROVENANCE_VERSION: u32 = 1;

/// The subject name recorded in every provenance: the attested output IS
/// the canonical manifest body (not a blob — the pins inside it address
/// those).
const SUBJECT_NAME: &str = "manifest";

/// The builder id for a nau version.
pub fn builder_id(nau_version: &str) -> String {
    format!("nau:{nau_version}")
}

/// Build the SLSA-lite attestation for an eval-produced manifest:
/// builder `nau:<version>`, the invocation flags, the declared
/// inputs as materials, and the sha3-384 subject over `body` (the
/// canonical bytes [`eval_manifest_canonical_bytes`] produced).
///
/// A free fn (was `Provenance::for_manifest`): the provenance type
/// moved to `nau_core::sign` (issue #326 PR 3, R2), and an inherent
/// impl of a core type cannot live in this crate (orphan rule). Both
/// callers were already root-side.
pub fn provenance_for_manifest(
    nau_version: &str,
    arch: &str,
    channel: &str,
    offline: bool,
    manifest: &ImageManifest,
    body: &[u8],
) -> miette::Result<Provenance> {
    Ok(Provenance {
        version: PROVENANCE_VERSION,
        builder_id: builder_id(nau_version),
        invocation: Invocation {
            arch: arch.to_string(),
            channel: channel.to_string(),
            offline,
        },
        materials: manifest.inputs.clone(),
        subject: Subject {
            name: SUBJECT_NAME.to_string(),
            manifest_sha3_384: subject_digest(body),
        },
    })
}

/// Attach `provenance` under a fresh signature by `kp`: the Ed25519
/// signature covers canonical body bytes ++ provenance bytes, and the
/// envelope lands in the signatures map keyed by key id. Prior
/// signatures keep verifying (they cover different bytes by design).
pub fn sign_attested(
    manifest: &mut ImageManifest,
    kp: &KeyPair,
    provenance: &Provenance,
) -> miette::Result<()> {
    let mut payload = eval_manifest_canonical_bytes(manifest)?;
    payload.extend_from_slice(&provenance_bytes(provenance)?);
    let signature = sign_bytes(&payload, kp);
    manifest.signatures.insert(
        kp.key_id(),
        serde_json::to_value(SignatureEntry::Attested {
            signature,
            provenance: Some(provenance.clone()),
        })
        .map_err(|e| miette::miette!("signature envelope serialization: {e}"))?,
    );
    Ok(())
}

/// Eval-time attestation (issue #56): sign the manifest and attach the
/// SLSA-lite provenance under the signature — builder `nau:<version>`,
/// invocation = the eval flags, materials = the declared inputs, subject =
/// the body's sha3-384. The provenance lives inside the signatures-map
/// entry, never in the canonical body, so byte-identical eval is
/// preserved.
pub fn attest_eval(
    manifest: &mut ImageManifest,
    kp: &KeyPair,
    nau_version: &str,
    arch: &str,
    channel: &str,
    offline: bool,
) -> miette::Result<()> {
    let body = eval_manifest_canonical_bytes(manifest)?;
    let provenance = provenance_for_manifest(nau_version, arch, channel, offline, manifest, &body)?;
    sign_attested(manifest, kp, &provenance)
}

/// The materials half of the provenance binding: an attested entry's
/// materials must EQUAL the manifest's declared inputs — the attestation
/// claims "built from these inputs", so a mirror that diverges from the
/// manifest it rides is a refused lie. Entries without provenance are
/// `Ok(None)` (legacy bare signatures carry no claims). The signature and
/// subject halves of the binding are enforced inside [`verify`] and
/// [`verify_keychain`] unconditionally; call this wherever the parsed
/// manifest is in hand (the device verify path does).
pub fn check_provenance(
    entry: &serde_json::Value,
    inputs: &std::collections::BTreeMap<String, ManifestInput>,
) -> miette::Result<Option<Provenance>> {
    let parsed: SignatureEntry = serde_json::from_value(entry.clone())
        .map_err(|e| miette::miette!("signature entry is not a valid signature envelope: {e}"))?;
    let Some(provenance) = parsed.provenance() else {
        return Ok(None);
    };
    if &provenance.materials != inputs {
        return Err(miette::miette!(
            "provenance materials do not match the manifest inputs — the attestation \
             claims a different input inventory than the manifest carries; refusing"
        ));
    }
    Ok(Some(provenance.clone()))
}

/// Add `kp`'s signature to the manifest's signatures map beside any
/// existing ones (DUAL/multi-signature). Canonical bytes never include
/// the map, so prior signatures keep verifying untouched.
pub fn cosign(manifest: &mut ImageManifest, kp: &KeyPair) -> miette::Result<()> {
    let bytes = eval_manifest_canonical_bytes(manifest)?;
    manifest.signatures.insert(
        kp.key_id(),
        serde_json::Value::String(sign_bytes(&bytes, kp)),
    );
    Ok(())
}

/// Rotation ceremony: mint a successor keypair alongside the current
/// secret and DUAL-sign `manifest`.
///
/// - The current `secret-key` is never read-modified or removed —
///   rotation coexists until the promotion step.
/// - The successor secret is persisted at `secret-key.new` (0600),
///   refusing to overwrite an existing one.
/// - `manifest` gains the successor's signature beside the existing
///   ones, so a keychain carrying old-or-new verifies either way.
///
/// Requires an existing secret key — rotating nothing is a named error,
/// not an accident.
pub fn rotate(home: &Path, manifest: &mut ImageManifest) -> miette::Result<KeyPair> {
    let successor = mint_rotation_key(home)?;
    cosign(manifest, &successor)?;
    Ok(successor)
}

/// Mint the rotation successor (`secret-key.new`) WITHOUT signing — the
/// CLI's `nau key rotate`, where no manifest is in hand.
///
/// `rotate` is split this way because its signing half needs an
/// [`ImageManifest`] and the operator CLI has none: fabricating one just
/// to carry a signature would be a lie, and a bare `nau key rotate`
/// is exactly the "mint the successor" ceremony. `rotate` keeps its
/// dual-sign contract for the build path by calling this, then cosigning.
///
/// Requires an existing `secret-key`; refuses to overwrite an existing
/// `secret-key.new`. The successor is NOT trusted until promoted (its
/// `keys/<id>.pub` anchor is installed by [`promote_rotation_key`]).
///
/// The sysupdate half of the transition (issue #290): both keys' seeds
/// exist only right now — the old one dies at `promote`, the successor's
/// moves into `secret-key` — so each key's pubring fragment is persisted
/// HERE, while it can be certified. The next build embeds the SET
/// {current, designated successor} ([`sysupdate_pubring_pgp`]).
pub fn mint_rotation_key(home: &Path) -> miette::Result<KeyPair> {
    let old = load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "no signing key at {} — nothing to rotate (run `nau key keygen` first)",
            secret_key_path(home).display()
        )
    })?;
    let successor = derive_pair(&read_urandom32()?);
    let new_path = rotation_key_path(home);
    if new_path.exists() {
        return Err(miette::miette!(
            "rotation key already exists at {} — refusing to overwrite (promote it with \
             `nau key promote`, or remove it to abandon the pending rotation)",
            new_path.display()
        ));
    }
    let dir = keys_dir(home);
    write_sysupdate_fragment(&old, &dir)?;
    write_sysupdate_fragment(&successor, &dir)?;
    write_secret_key_at(&new_path, &successor)?;
    eprintln!(
        "  ✓ rotation key minted: {} (key id {}) — not trusted until promoted",
        new_path.display(),
        successor.key_id()
    );
    Ok(successor)
}

/// Promotion ceremony: move the successor over the active secret key.
///
/// This is the half that makes rotation mean anything: until it runs, a
/// successor minted at `secret-key.new` has no `keys/<id>.pub` anchor, so
/// the keychain never contains it and [`verify_keychain`] cannot accept
/// its signature. Promote moves `secret-key.new` → `secret-key`
/// (overwriting the old secret), then installs the successor's public key
/// as a trust anchor in `dir`.
///
/// Fails closed: absent `secret-key.new` or a malformed successor is a
/// named error and leaves the existing secret untouched. The old key's
/// anchor is deliberately left in place — the dual-trust overlap window —
/// and stays revocable with [`revoke`].
pub fn promote_rotation_key(home: &Path, dir: &Path) -> miette::Result<KeyPair> {
    let new_path = rotation_key_path(home);
    if !new_path.exists() {
        return Err(miette::miette!(
            "no rotation key at {} — nothing to promote (mint one with `nau key rotate`)",
            new_path.display()
        ));
    }
    // Parse BEFORE touching the active secret: a malformed `.new` must
    // never clobber a working key.
    let text = std::fs::read_to_string(&new_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", new_path.display()))?;
    let successor = parse_secret_key(&text).wrap_err_with(|| {
        format!(
            "rotation key at {} is not a valid secret key — refusing to promote",
            new_path.display()
        )
    })?;

    // The sysupdate half of the promotion (issue #290): the successor's
    // pubring fragment is (re)written from the parsed `.new` — the bytes
    // are deterministic, so this repairs a fragment missing from an older
    // ceremony — and the rotated-out key's fragment is repaired while its
    // secret is still on disk (the rename below destroys it).
    write_sysupdate_fragment(&successor, dir)?;
    match load_secret_key(home) {
        Ok(Some(old)) => write_sysupdate_fragment(&old, dir)?,
        Ok(None) | Err(_) => eprintln!(
            "  ⚠ cannot read the rotated-out key's secret at {} — its sysupdate pubring \
             fragment may be missing and the next image build will refuse until the old \
             anchor is revoked (`nau key revoke <old-key-id>`)",
            secret_key_path(home).display()
        ),
    }

    let active = secret_key_path(home);
    std::fs::rename(&new_path, &active)
        .into_diagnostic()
        .wrap_err_with(|| format!("promoting {} to {}", new_path.display(), active.display()))?;
    let anchor = install_public_key(&successor, dir)?;
    eprintln!(
        "  ✓ rotation promoted: {} → {} (key id {}; anchor {})",
        new_path.display(),
        active.display(),
        successor.key_id(),
        anchor.display()
    );
    Ok(successor)
}

/// Revocation ceremony: drop `key_id` — remove its trust-anchor file
/// from `dir` and strip its signature entry from the manifest. The
/// pubkey file must exist (revoking an untrusted key is a named error,
/// never a silent no-op); an absent signature entry is fine (idempotent
/// second pass over an already-stripped manifest).
pub fn revoke(dir: &Path, manifest: &mut ImageManifest, key_id: &str) -> miette::Result<()> {
    let pub_path = dir.join(format!("{key_id}.pub"));
    if !pub_path.exists() {
        return Err(miette::miette!(
            "cannot revoke {key_id}: no trust anchor at {}",
            pub_path.display()
        ));
    }
    std::fs::remove_file(&pub_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("removing {}", pub_path.display()))?;
    manifest.signatures.remove(key_id);
    eprintln!("  ✓ key {key_id} revoked: anchor removed, signature stripped");
    Ok(())
}

/// Multi-key verify: accept when ANY signature whose key id is in the
/// Rotation re-sign (issue #51): add `kp`'s signature to the manifest
/// BESIDE the existing ones, re-attaching provenance when the manifest
/// already carries an attested entry — the claims (builder, invocation,
/// materials, subject digest over the unchanged canonical body) are
/// reused verbatim, so the successor's envelope attests exactly what the
/// old one did, under the new key. A manifest with no attestation gets a
/// bare cosign. An existing attestation that does not bind the current
/// body is a named error: re-attaching stale claims would lie.
pub fn cosign_reattaching_provenance(
    manifest: &mut ImageManifest,
    kp: &KeyPair,
) -> miette::Result<()> {
    let body = eval_manifest_canonical_bytes(manifest)?;
    let existing = manifest.signatures.values().find_map(|v| {
        serde_json::from_value::<SignatureEntry>(v.clone())
            .ok()
            .and_then(|e| e.provenance().cloned())
    });
    match existing {
        Some(prov) => {
            if prov.subject.manifest_sha3_384 != subject_digest(&body) {
                return Err(miette::miette!(
                    "the existing provenance does not bind the current manifest bytes — \
                     refusing to re-attach stale claims under key {} (re-run `nau eval` \
                     to re-attest, then rotate)",
                    kp.key_id()
                ));
            }
            sign_attested(manifest, kp, &prov)
        }
        None => cosign(manifest, kp),
    }
}

/// The outcome of [`verify_with_ledger`]: the key id that verified plus
/// any transition-window warnings the operator should see.
#[derive(Debug, Serialize)]
pub struct LedgerVerification {
    pub key_id: String,
    pub warnings: Vec<String>,
}

/// Ceremony-policy verify (issue #51): the keychain's ANY-signature rule
/// with the ledger's lifecycle layered on top.
///
/// - A revoked key is never a candidate. Dual-signed artifacts keep
///   verifying through their live key — revocation must not retroactively
///   break manifests that were re-signed during the window (unlike the
///   device-side [`verify_trust_set`], which refuses any revoked-signed
///   artifact outright).
/// - A rotated-out key whose overlap window has expired still verifies,
///   but the outcome carries a warning: the manifest is signed only by a
///   key the ceremony already replaced. A live-key signature on the same
///   manifest wins, so no warning is surfaced.
/// - Manifests signed ONLY by revoked keys fail with a named error.
pub fn verify_with_ledger(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
    ledger: &CeremonyLedger,
    extra_revoked: &[String],
    now: i64,
) -> miette::Result<LedgerVerification> {
    if chain.is_empty() {
        return Err(miette::miette!(
            "empty trust chain — no public keys loaded, refusing to verify (fail closed)"
        ));
    }
    let revoked = revoked_set(ledger, extra_revoked);
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    let mut live: Vec<String> = Vec::new();
    let mut stale: Vec<(String, String)> = Vec::new();
    for (key_id, public) in &chain.entries {
        match classify_against_ledger(
            manifest_bytes,
            signatures,
            key_id,
            public,
            &revoked,
            ledger,
            now,
        )? {
            Classification::Revoked => {}
            Classification::Missing => missing.push(key_id.clone()),
            Classification::Failed => failed.push(key_id.clone()),
            Classification::Live => live.push(key_id.clone()),
            Classification::Stale(warning) => stale.push((key_id.clone(), warning)),
        }
    }
    pick_verification_outcome(signatures, &revoked, missing, failed, live, stale)
}

/// The ledger's revoked ids unioned with an externally supplied list
/// (`keys/revoked-keys` — the device-carried spelling of the same fact).
fn revoked_set(
    ledger: &CeremonyLedger,
    extra_revoked: &[String],
) -> std::collections::BTreeSet<String> {
    let mut revoked: std::collections::BTreeSet<String> =
        ledger.revoked_ids().into_iter().collect();
    revoked.extend(extra_revoked.iter().cloned());
    revoked
}

/// How one keychain entry relates to a signature map under ledger policy.
enum Classification {
    /// Key is revoked — never a candidate.
    Revoked,
    /// No signature entry for this key.
    Missing,
    /// Signature present but does not verify.
    Failed,
    /// Verifies under a live (non-rotated or in-window) key.
    Live,
    /// Verifies under a rotated-out key past its window.
    Stale(String),
}

/// Walk one chain entry through the revocation → presence → signature →
/// window policy.
fn classify_against_ledger(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    key_id: &str,
    public: &[u8; 32],
    revoked: &std::collections::BTreeSet<String>,
    ledger: &CeremonyLedger,
    now: i64,
) -> miette::Result<Classification> {
    if revoked.contains(key_id) {
        return Ok(Classification::Revoked);
    }
    let Some(entry) = signatures.get(key_id) else {
        return Ok(Classification::Missing);
    };
    let payload_ok = entry_signed_payload(manifest_bytes, key_id, entry)
        .and_then(|(payload, raw)| verify_one(&payload, key_id, &raw, public));
    if payload_ok.is_err() {
        return Ok(Classification::Failed);
    }
    match stale_rotation_warning(ledger, key_id, now)? {
        Some(warning) => Ok(Classification::Stale(warning)),
        None => Ok(Classification::Live),
    }
}

/// Choose the outcome: a live signature always wins; a window-expired one
/// verifies with a warning; only-revoked signatures are a named error.
fn pick_verification_outcome(
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    revoked: &std::collections::BTreeSet<String>,
    missing: Vec<String>,
    failed: Vec<String>,
    live: Vec<String>,
    stale: Vec<(String, String)>,
) -> miette::Result<LedgerVerification> {
    if let Some(key_id) = live.first().cloned() {
        return Ok(LedgerVerification {
            key_id,
            warnings: Vec::new(),
        });
    }
    if let Some((key_id, warning)) = stale.first().cloned() {
        return Ok(LedgerVerification {
            key_id,
            warnings: vec![warning],
        });
    }
    let signed_revoked: Vec<String> = signatures
        .keys()
        .filter(|id| revoked.contains(*id))
        .cloned()
        .collect();
    if !signed_revoked.is_empty() {
        return Err(miette::miette!(
            "manifest is signed only by REVOKED key(s) {} and carries no valid signature \
             under a live key — refusing to verify",
            signed_revoked.join(", ")
        ));
    }
    Err(miette::miette!(
        "no trusted signature verifies: missing entries for {missing:?}, failed for {failed:?} \
         — refusing to verify"
    ))
}

/// [`verify_with_ledger`] at the current time.
pub fn verify_with_ledger_now(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
    ledger: &CeremonyLedger,
    extra_revoked: &[String],
) -> miette::Result<LedgerVerification> {
    verify_with_ledger(
        manifest_bytes,
        signatures,
        chain,
        ledger,
        extra_revoked,
        now_unix(),
    )
}

/// The window warning for a verified rotated-out key, `None` while the
/// overlap window is still open (or for keys never rotated).
fn stale_rotation_warning(
    ledger: &CeremonyLedger,
    key_id: &str,
    now: i64,
) -> miette::Result<Option<String>> {
    if !ledger.rotation_window_expired(key_id, now)? {
        return Ok(None);
    }
    let entry = &ledger.keys[key_id];
    Ok(Some(format!(
        "transition window expired: key {key_id} was rotated out on {} (window {} days) and \
         this manifest still carries only its signature — re-sign under its successor {} \
         and revoke {key_id} when no old artifacts remain",
        entry.rotated_at.as_deref().unwrap_or("?"),
        entry.window_days.unwrap_or(DEFAULT_WINDOW_DAYS),
        entry.replaced_by.as_deref().unwrap_or("?"),
    )))
}

fn write_sysupdate_fragment(kp: &KeyPair, keys_dir: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(keys_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", keys_dir.display()))?;
    let path = sysupdate_fragment_path(keys_dir, &kp.key_id());
    let bytes = nau_infra::pgp::import_pubring_pgp(kp)?;
    std::fs::write(&path, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

// `load_sysupdate_fragment` and the rest of the sysupdate OpenPGP layer
// moved to `nau_image::sysupdate` (R3, issue #326 PR 3); re-exported
// above.

// ── Tests (the ceremony/keychain suite; the eval-coupled and
// sysupdate-image suites stay root, where their dependencies live) ──

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const DAY: i64 = 86_400;

    fn minimal_manifest() -> ImageManifest {
        ImageManifest {
            manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        }
    }

    fn temp_keypair() -> (tempfile::TempDir, KeyPair) {
        let home = tempfile::tempdir().unwrap();
        let kp = create_secret_key(home.path()).unwrap();
        (home, kp)
    }

    #[test]
    fn canonical_bytes_exclude_signatures_and_are_deterministic() {
        let mut m = minimal_manifest();
        let before = eval_manifest_canonical_bytes(&m).unwrap();
        m.signatures.insert(
            "deadbeef00112233".into(),
            serde_json::Value::String("x".into()),
        );
        // A populated signatures map changes to_json but never the
        // canonical bytes — a signature never covers itself.
        assert_ne!(
            serde_json::to_vec(&m).unwrap(),
            serde_json::to_vec(&minimal_manifest()).unwrap()
        );
        assert_eq!(eval_manifest_canonical_bytes(&m).unwrap(), before);
        // Empty map serializes as {} deterministically (BTreeMap order).
        assert_eq!(
            eval_manifest_canonical_bytes(&minimal_manifest()).unwrap(),
            br#"{"manifest_version":1,"inputs":{},"outputs":{},"images":{},"signatures":{}}"#
                .to_vec()
        );
    }

    #[test]
    fn keypair_create_then_load_roundtrips() {
        let (home, kp) = temp_keypair();
        let loaded = load_secret_key(home.path()).unwrap().expect("key exists");
        assert_eq!(loaded, kp);
        assert_eq!(
            loaded.public_hex(),
            kp.public_hex(),
            "public key derived from the stored seed"
        );
    }

    #[test]
    fn keypair_file_is_mode_0600() {
        let (home, _) = temp_keypair();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(secret_key_path(home.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "secret key must not be group/world readable"
        );
    }

    #[test]
    fn keypair_creation_refuses_to_overwrite() {
        let (home, kp) = temp_keypair();
        let err = create_secret_key(home.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to overwrite"),
            "overwrite must be named: {err:#}"
        );
        assert_eq!(
            load_secret_key(home.path()).unwrap().unwrap(),
            kp,
            "original key untouched"
        );
    }

    #[test]
    fn load_is_none_without_a_key() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_secret_key(home.path()).unwrap().is_none());
    }

    #[test]
    fn key_id_is_pubkey_prefix() {
        let (_, kp) = temp_keypair();
        assert_eq!(kp.key_id(), kp.public_hex()[..16]);
        assert_eq!(kp.key_id().len(), 16);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (home, kp) = temp_keypair();
        let _ = home;
        let manifest = minimal_manifest();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(
            kp.key_id(),
            serde_json::Value::String(sign_bytes(&bytes, &kp)),
        );
        verify(&bytes, &sigs, &kp.public_hex()).unwrap();
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let (home, kp) = temp_keypair();
        let _ = home;
        let manifest = minimal_manifest();
        let mut bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        // Flip one payload byte — the signature must stop holding.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let mut sigs = BTreeMap::new();
        let intact = eval_manifest_canonical_bytes(&manifest).unwrap();
        sigs.insert(
            kp.key_id(),
            serde_json::Value::String(sign_bytes(&intact, &kp)),
        );
        let err = verify(&bytes, &sigs, &kp.public_hex()).unwrap_err();
        assert!(
            format!("{err:#}").contains("FAILED"),
            "tamper must fail loudly: {err:#}"
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (_, kp) = temp_keypair();
        let (home2, impostor) = temp_keypair();
        let _ = home2;
        let manifest = minimal_manifest();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(
            kp.key_id(),
            serde_json::Value::String(sign_bytes(&bytes, &impostor)),
        );
        assert!(verify(&bytes, &sigs, &kp.public_hex()).is_err());
        // And a signature absent under the checked key id is a named error.
        let empty: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let err = verify(&bytes, &empty, &kp.public_hex()).unwrap_err();
        assert!(
            format!("{err:#}").contains("no signature for key id"),
            "{err:#}"
        );
    }

    #[test]
    fn public_key_file_carries_comment_and_hex() {
        let (_, kp) = temp_keypair();
        let file = public_key_file(&kp);
        let mut lines = file.lines();
        assert!(lines.next().unwrap().starts_with("untrusted comment:"));
        assert_eq!(lines.next().unwrap(), kp.public_hex());
        assert_eq!(lines.next(), None);
    }

    // ── Key ceremony (step (e)): keychain, rotation, revocation ──

    fn signed_manifest(kp: &KeyPair) -> (Vec<u8>, BTreeMap<String, serde_json::Value>) {
        let manifest = minimal_manifest();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(
            kp.key_id(),
            serde_json::Value::String(sign_bytes(&bytes, kp)),
        );
        (bytes, sigs)
    }

    fn chain_with(dir: &std::path::Path, kps: &[&KeyPair]) -> Keychain {
        for kp in kps {
            install_public_key(kp, dir).unwrap();
        }
        Keychain::load_dir(dir).unwrap()
    }

    #[test]
    fn keychain_loads_every_pub_file_and_lists_ids() {
        let (_, a) = temp_keypair();
        let (_, b) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        let chain = chain_with(dir.path(), &[&a, &b]);
        let mut ids = chain.key_ids();
        ids.sort();
        let mut want = vec![a.key_id(), b.key_id()];
        want.sort();
        assert_eq!(ids, want);
        assert!(!chain.is_empty());
    }

    #[test]
    fn empty_keychain_fails_closed() {
        let (_, kp) = temp_keypair();
        let (bytes, sigs) = signed_manifest(&kp);
        let empty_dir = tempfile::tempdir().unwrap();
        let chain = Keychain::load_dir(empty_dir.path()).unwrap();
        assert!(chain.is_empty());
        let err = verify_keychain(&bytes, &sigs, &chain).unwrap_err();
        assert!(
            format!("{err:#}").contains("empty trust chain"),
            "fail closed must be named: {err:#}"
        );
        // Even a valid signature under the presented key is refused —
        // the chain, not the signature map, defines trust.
        let single = Keychain {
            entries: Vec::new(),
        };
        assert!(verify_keychain(&bytes, &sigs, &single).is_err());
    }

    #[test]
    fn keychain_accepts_any_trusted_signature() {
        let (_, old) = temp_keypair();
        let (_, other) = temp_keypair();
        let (bytes, sigs) = signed_manifest(&old);
        let dir = tempfile::tempdir().unwrap();
        // The chain carries two keys; only `old` has a signature entry —
        // ANY-entry semantics must accept it.
        let chain = chain_with(dir.path(), &[&old, &other]);
        let verified = verify_keychain(&bytes, &sigs, &chain).unwrap();
        assert_eq!(verified, old.key_id());
    }

    #[test]
    fn keychain_tamper_fails_for_every_trusted_key() {
        let (_, a) = temp_keypair();
        let (_, b) = temp_keypair();
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &a).unwrap();
        cosign(&mut manifest, &b).unwrap();
        let mut bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let sigs = manifest.signatures.clone();
        let dir = tempfile::tempdir().unwrap();
        let chain = chain_with(dir.path(), &[&a, &b]);
        let err = verify_keychain(&bytes, &sigs, &chain).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted signature verifies"),
            "tamper must fail loudly: {err:#}"
        );
    }

    #[test]
    fn keychain_ignores_signatures_from_untrusted_keys() {
        let (_, trusted) = temp_keypair();
        let (_, impostor) = temp_keypair();
        let (bytes, sigs) = signed_manifest(&impostor);
        let dir = tempfile::tempdir().unwrap();
        let chain = chain_with(dir.path(), &[&trusted]);
        let err = verify_keychain(&bytes, &sigs, &chain).unwrap_err();
        assert!(
            format!("{err:#}").contains(&trusted.key_id()),
            "error names the missing trusted key: {err:#}"
        );
    }

    #[test]
    fn rotate_dual_signs_and_old_key_is_untouched() {
        let (home, old) = temp_keypair();
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &old).unwrap();
        let before = load_secret_key(home.path()).unwrap().unwrap();
        assert_eq!(before, old);

        let successor = rotate(home.path(), &mut manifest).unwrap();
        assert_ne!(successor, old, "successor is a fresh key");

        // The old secret is untouched; the successor lives at secret-key.new.
        assert_eq!(load_secret_key(home.path()).unwrap().unwrap(), old);
        let new_path = home.path().join(".config/nau/secret-key.new");
        let loaded_new = std::fs::read_to_string(&new_path).unwrap();
        assert!(
            loaded_new.contains(&successor.seed_hex()),
            "successor seed persisted"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&new_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "rotation secret is 0600");

        // DUAL signatures present.
        assert!(manifest.signatures.contains_key(&old.key_id()));
        assert!(manifest.signatures.contains_key(&successor.key_id()));

        // Canonical bytes exclude the map — the old signature still holds.
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        assert_eq!(
            bytes,
            eval_manifest_canonical_bytes(&minimal_manifest()).unwrap()
        );

        // Verify passes under old-only, new-only, and both-key chains.
        let old_dir = tempfile::tempdir().unwrap();
        let verified = verify_keychain(
            &bytes,
            &manifest.signatures,
            &chain_with(old_dir.path(), &[&old]),
        )
        .unwrap();
        assert_eq!(verified, old.key_id());
        let new_dir = tempfile::tempdir().unwrap();
        let verified = verify_keychain(
            &bytes,
            &manifest.signatures,
            &chain_with(new_dir.path(), &[&successor]),
        )
        .unwrap();
        assert_eq!(verified, successor.key_id());
        let both_dir = tempfile::tempdir().unwrap();
        verify_keychain(
            &bytes,
            &manifest.signatures,
            &chain_with(both_dir.path(), &[&old, &successor]),
        )
        .unwrap();
    }

    #[test]
    fn rotate_requires_an_existing_key_and_refuses_overwrite() {
        let empty = tempfile::tempdir().unwrap();
        let mut manifest = minimal_manifest();
        let err = rotate(empty.path(), &mut manifest).unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing to rotate"),
            "rotating nothing is named: {err:#}"
        );

        let (home, _) = temp_keypair();
        let first = rotate(home.path(), &mut manifest).unwrap();
        let err = rotate(home.path(), &mut manifest).unwrap_err();
        assert!(
            format!("{err:#}").contains("refusing to overwrite"),
            "pending rotation blocks a second: {err:#}"
        );
        // The failed second rotation did not clobber the first successor.
        let stored =
            std::fs::read_to_string(home.path().join(".config/nau/secret-key.new")).unwrap();
        assert!(stored.contains(&first.seed_hex()));
    }

    #[test]
    fn revoke_drops_anchor_and_signature_and_old_fails_new_passes() {
        let (home, old) = temp_keypair();
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &old).unwrap();
        let successor = rotate(home.path(), &mut manifest).unwrap();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();

        let dir = tempfile::tempdir().unwrap();
        install_public_key(&old, dir.path()).unwrap();
        install_public_key(&successor, dir.path()).unwrap();

        // Sanity: dual-signed + dual-anchored verifies.
        verify_keychain(
            &bytes,
            &manifest.signatures,
            &Keychain::load_dir(dir.path()).unwrap(),
        )
        .unwrap();

        // Revoke the old key: anchor file removed, signature stripped.
        revoke(dir.path(), &mut manifest, &old.key_id()).unwrap();
        assert!(!dir.path().join(format!("{}.pub", old.key_id())).exists());
        assert!(!manifest.signatures.contains_key(&old.key_id()));

        let remaining = Keychain::load_dir(dir.path()).unwrap();
        assert_eq!(remaining.key_ids(), vec![successor.key_id()]);

        // Verification under the remaining set passes.
        let bytes_after = eval_manifest_canonical_bytes(&manifest).unwrap();
        let verified = verify_keychain(&bytes_after, &manifest.signatures, &remaining).unwrap();
        assert_eq!(verified, successor.key_id());

        // Under the revoked key it fails — signature gone, anchor gone.
        assert!(verify(&bytes_after, &manifest.signatures, &old.public_hex()).is_err());
        let revoked_chain = Keychain {
            entries: vec![(old.key_id(), old.public)],
        };
        let err = verify_keychain(&bytes_after, &manifest.signatures, &revoked_chain).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted signature verifies"),
            "revoked-key verify must fail: {err:#}"
        );

        // Revoking an untrusted key id is a named error.
        let (_, stranger) = temp_keypair();
        let err = revoke(dir.path(), &mut manifest, &stranger.key_id()).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trust anchor"),
            "absent anchor named: {err:#}"
        );
    }

    #[test]
    fn malformed_pub_file_is_a_named_error_not_a_skip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.pub"), "untrusted comment: x\nzzzz\n").unwrap();
        let err = Keychain::load_dir(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("bad.pub"),
            "corrupt anchor named: {err:#}"
        );
    }

    // ── ssh-format anchors ──

    /// Serialize `kp.public` as an `ssh-ed25519` public line — the wire
    /// blob is u32be(11) ++ "ssh-ed25519" ++ u32be(32) ++ key (51 bytes).
    fn ssh_pub_line(kp: &KeyPair) -> String {
        use base64::Engine as _;
        let mut blob = Vec::with_capacity(51);
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&kp.public);
        format!(
            "ssh-ed25519 {} nau-test-anchor",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    #[test]
    fn ssh_format_anchor_is_parsed_as_a_trust_anchor() {
        let (_, kp) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("operator.pub"),
            format!("{}\n", ssh_pub_line(&kp)),
        )
        .unwrap();
        let chain = Keychain::load_dir(dir.path()).unwrap();
        assert!(
            chain.key_ids().contains(&kp.key_id()),
            "ssh-format anchor lands under the same key id: {:?}",
            chain.key_ids()
        );
        // The decoded 32 bytes are THE key: a manifest it signed verifies.
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &kp).unwrap();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let verified = verify_keychain(&bytes, &manifest.signatures, &chain).unwrap();
        assert_eq!(verified, kp.key_id());
    }

    #[test]
    fn ssh_format_non_ed25519_refuses_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rsa.pub"),
            "ssh-rsa AAAAB3NzaC1yc2E alice@host\n",
        )
        .unwrap();
        let err = Keychain::load_dir(dir.path()).unwrap_err().to_string();
        assert!(err.contains("rsa.pub"), "names the file: {err}");
        assert!(err.contains("ssh-rsa"), "names the key type: {err}");
    }

    #[test]
    fn ssh_format_corrupt_body_refuses_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("broken.pub"),
            "ssh-ed25519 !!!not-base64!!! x@y\n",
        )
        .unwrap();
        let err = Keychain::load_dir(dir.path()).unwrap_err().to_string();
        assert!(err.contains("broken.pub"), "names the file: {err}");
    }

    #[test]
    fn legacy_single_anchor_accepts_ssh_format() {
        let (_, kp) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("downloaded.pub");
        std::fs::write(&path, format!("{}\n", ssh_pub_line(&kp))).unwrap();
        let chain = Keychain::load_pub_file(&path).unwrap();
        assert_eq!(chain.key_ids(), vec![kp.key_id()]);
    }

    // ── Rotation promotion (ADR-0024 §4) ──

    #[test]
    fn unpromoted_rotation_is_not_trusted_until_promoted() {
        let (home, old) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        install_public_key(&old, dir.path()).unwrap();

        // Mint the successor WITHOUT promoting (the CLI's `key rotate`).
        let successor = mint_rotation_key(home.path()).unwrap();
        assert_ne!(successor, old);

        // The active secret is still the old key; `.new` is pending.
        assert_eq!(load_secret_key(home.path()).unwrap().unwrap(), old);
        assert!(home.path().join(".config/nau/secret-key.new").exists());

        // Before promotion the successor has NO anchor, so a manifest it
        // signed cannot verify under the keychain.
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &successor).unwrap();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let chain = Keychain::load_dir(dir.path()).unwrap();
        let err = verify_keychain(&bytes, &manifest.signatures, &chain).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted signature verifies"),
            "unpromoted rotation must not be trusted: {err:#}"
        );

        // Promote flips it: the successor becomes the signing key and its
        // anchor is installed.
        let promoted = promote_rotation_key(home.path(), dir.path()).unwrap();
        assert_eq!(promoted, successor);
        assert_eq!(load_secret_key(home.path()).unwrap().unwrap(), successor);
        assert!(!home.path().join(".config/nau/secret-key.new").exists());
        assert!(dir
            .path()
            .join(format!("{}.pub", successor.key_id()))
            .exists());
        let chain = Keychain::load_dir(dir.path()).unwrap();
        assert!(chain.key_ids().contains(&successor.key_id()));
        let verified = verify_keychain(&bytes, &manifest.signatures, &chain).unwrap();
        assert_eq!(verified, successor.key_id());

        // The old key's anchor was left in place (dual-trust window) and
        // is still revocable.
        assert!(dir.path().join(format!("{}.pub", old.key_id())).exists());
    }

    #[test]
    fn promote_without_a_rotation_key_is_a_named_error() {
        let (home, _) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        let err = promote_rotation_key(home.path(), dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("no rotation key"),
            "absent rotation key named: {err:#}"
        );
    }

    #[test]
    fn promote_a_malformed_rotation_key_is_refused_and_leaves_active_key() {
        let (home, old) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        // A `.new` that carries no key material must never clobber the
        // active secret.
        std::fs::write(
            home.path().join(".config/nau/secret-key.new"),
            "untrusted comment: x\nzzzz\n",
        )
        .unwrap();
        let err = promote_rotation_key(home.path(), dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a valid secret key"),
            "malformed rotation key named: {err:#}"
        );
        assert_eq!(
            load_secret_key(home.path()).unwrap().unwrap(),
            old,
            "the active key survived the failed promotion"
        );
        assert!(
            home.path().join(".config/nau/secret-key.new").exists(),
            "the malformed .new is left for the operator to inspect"
        );
    }

    // ── Trust set: closed key set, revocation, overlap window ──

    #[test]
    fn closed_key_set_rejects_an_unknown_signer() {
        let (_, trusted) = temp_keypair();
        let (_, stranger) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        install_public_key(&trusted, dir.path()).unwrap();

        let (bytes, sigs) = signed_manifest(&stranger);
        let chain = Keychain::load_dir(dir.path()).unwrap();
        let err = verify_trust_set(&bytes, &sigs, &chain, &[]).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted signature verifies"),
            "unknown signer rejected: {err:#}"
        );
    }

    #[test]
    fn revoked_key_is_rejected_by_name_even_when_another_key_signed() {
        let (_, revoked) = temp_keypair();
        let (_, trusted) = temp_keypair();
        let dir = tempfile::tempdir().unwrap();
        install_public_key(&revoked, dir.path()).unwrap();
        install_public_key(&trusted, dir.path()).unwrap();

        // Dual-signed: the revoked key AND a still-trusted key.
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &revoked).unwrap();
        cosign(&mut manifest, &trusted).unwrap();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();
        let chain = Keychain::load_dir(dir.path()).unwrap();

        // Without the revocation list the trusted signature verifies.
        verify_trust_set(&bytes, &manifest.signatures, &chain, &[]).unwrap();

        // With it, the revoked signer is refused BY NAME before anything
        // else — a revoked key is never trusted again, dual-sign or not.
        let err = verify_trust_set(&bytes, &manifest.signatures, &chain, &[revoked.key_id()])
            .unwrap_err();
        assert!(
            format!("{err:#}").contains(&revoked.key_id()),
            "revoked id named: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("REVOKED"),
            "revocation refusal is explicit: {err:#}"
        );
    }

    #[test]
    fn rotation_overlap_window_then_revoke_old_narrows_to_new() {
        let (home, old) = temp_keypair();
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &old).unwrap();
        let successor = mint_rotation_key(home.path()).unwrap();
        cosign(&mut manifest, &successor).unwrap();
        let bytes = eval_manifest_canonical_bytes(&manifest).unwrap();

        // Both anchors present: either signature verifies (the overlap
        // window a rotation needs to roll out without a flag day).
        let dir = tempfile::tempdir().unwrap();
        install_public_key(&old, dir.path()).unwrap();
        install_public_key(&successor, dir.path()).unwrap();
        let chain = Keychain::load_dir(dir.path()).unwrap();
        verify_trust_set(&bytes, &manifest.signatures, &chain, &[]).unwrap();

        // Promote the new key, then revoke the old one.
        promote_rotation_key(home.path(), dir.path()).unwrap();
        revoke_local(dir.path(), &old.key_id()).unwrap();
        assert!(!dir.path().join(format!("{}.pub", old.key_id())).exists());
        assert_eq!(read_revoked_keys(dir.path()).unwrap(), vec![old.key_id()]);

        // New-only now: the successor verifies, the old fails.
        let chain = Keychain::load_dir(dir.path()).unwrap();
        let verified = verify_keychain(&bytes, &manifest.signatures, &chain).unwrap();
        assert_eq!(verified, successor.key_id());

        // And the revoked id is refused explicitly even though its anchor
        // is gone (closed set would say "never trusted"; the list says
        // "revoked").
        let revoked = read_revoked_keys(dir.path()).unwrap();
        let err = verify_trust_set(&bytes, &manifest.signatures, &chain, &revoked).unwrap_err();
        assert!(
            format!("{err:#}").contains(&old.key_id()),
            "old key named after revoke: {err:#}"
        );
    }

    #[test]
    fn revoke_local_is_named_for_an_unknown_key_and_idempotent_once_listed() {
        let dir = tempfile::tempdir().unwrap();
        let err = revoke_local(dir.path(), "deadbeef00112233").unwrap_err();
        assert!(
            format!("{err:#}").contains("no trust anchor"),
            "unknown revocation named: {err:#}"
        );

        let (_, kp) = temp_keypair();
        install_public_key(&kp, dir.path()).unwrap();
        revoke_local(dir.path(), &kp.key_id()).unwrap();
        // A second pass over an already-listed, anchor-less id is fine.
        revoke_local(dir.path(), &kp.key_id()).unwrap();
        assert_eq!(read_revoked_keys(dir.path()).unwrap(), vec![kp.key_id()]);
    }

    #[test]
    fn malformed_revocation_list_is_a_named_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("revoked-keys"), "not-a-key-id\n").unwrap();
        let err = read_revoked_keys(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("revoked-keys"),
            "corrupt revocation list named: {err:#}"
        );
    }

    // ── Ceremony ledger + transition window (issue #51, ADR-0011 §4e) ──

    /// A fixed epoch to build deterministic RFC3339 dates from.

    #[test]
    fn tampered_ceremony_ledger_is_a_named_error() {
        let dir = tempfile::tempdir().unwrap();
        // Not JSON at all.
        std::fs::write(ceremony_ledger_path(dir.path()), "not json {").unwrap();
        let err = CeremonyLedger::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("corrupt"), "{err:#}");

        // Public-key material that does not hash to its own id — the
        // tamper an attacker (or a fat-fingered edit) produces.
        let mut ledger = CeremonyLedger {
            version: CEREMONY_LEDGER_VERSION,
            keys: std::collections::BTreeMap::new(),
        };
        ledger.keys.insert(
            "aaaaaaaaaaaaaaaa".into(),
            LedgerEntry {
                public_key: Some("ff".repeat(32)),
                ..LedgerEntry::default()
            },
        );
        std::fs::write(
            ceremony_ledger_path(dir.path()),
            serde_json::to_string(&ledger).unwrap(),
        )
        .unwrap();
        let err = CeremonyLedger::load(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not hash to its own id"),
            "{err:#}"
        );

        // A malformed date.
        ledger.keys.get_mut("aaaaaaaaaaaaaaaa").unwrap().public_key = None;
        ledger.keys.get_mut("aaaaaaaaaaaaaaaa").unwrap().created = Some("yesterday".into());
        std::fs::write(
            ceremony_ledger_path(dir.path()),
            serde_json::to_string(&ledger).unwrap(),
        )
        .unwrap();
        let err = CeremonyLedger::load(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("malformed created date"),
            "{err:#}"
        );

        // A dangling chain link.
        ledger.keys.get_mut("aaaaaaaaaaaaaaaa").unwrap().created = None;
        ledger.keys.get_mut("aaaaaaaaaaaaaaaa").unwrap().replaced_by =
            Some("bbbbbbbbbbbbbbbb".into());
        std::fs::write(
            ceremony_ledger_path(dir.path()),
            serde_json::to_string(&ledger).unwrap(),
        )
        .unwrap();
        let err = CeremonyLedger::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("no ledger entry"), "{err:#}");

        // An unknown future version.
        ledger.keys.get_mut("aaaaaaaaaaaaaaaa").unwrap().replaced_by = None;
        ledger.version = 99;
        std::fs::write(
            ceremony_ledger_path(dir.path()),
            serde_json::to_string(&ledger).unwrap(),
        )
        .unwrap();
        let err = CeremonyLedger::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("newer"), "{err:#}");
    }

    #[test]
    fn ceremony_ledger_is_compat_with_missing_and_minimal_files() {
        // No ledger file at all: pre-ceremony keychains are valid state.
        let dir = tempfile::tempdir().unwrap();
        let ledger = CeremonyLedger::load(dir.path()).unwrap();
        assert!(ledger.keys.is_empty());
        assert!(ledger.revoked_ids().is_empty());

        // A minimal, partial entry (serde-default on every field) parses.
        std::fs::write(
            ceremony_ledger_path(dir.path()),
            r#"{"version":1,"keys":{"aaaaaaaaaaaaaaaa":{}}}"#,
        )
        .unwrap();
        let ledger = CeremonyLedger::load(dir.path()).unwrap();
        let entry = ledger.keys.get("aaaaaaaaaaaaaaaa").expect("entry loaded");
        assert_eq!(entry, &LedgerEntry::default());
        assert!(ledger.revoked_ids().is_empty());
    }

    #[test]
    fn rfc3339_roundtrip_and_rejects_impossible_dates() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_to_unix("1970-01-02T00:00:00Z").unwrap(), DAY);
        // Leap day exists in 2024 (19782 days after the epoch, +12:34:56).
        assert_eq!(
            rfc3339_to_unix("2024-02-29T12:34:56Z").unwrap(),
            1_709_210_096
        );
        assert_eq!(
            unix_to_rfc3339(rfc3339_to_unix("2024-02-29T12:34:56Z").unwrap()),
            "2024-02-29T12:34:56Z"
        );
        for bad in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-14T25:00:00Z",
            "not-a-date",
            "2026-09-14 12:00:00Z",
            "",
        ] {
            assert!(rfc3339_to_unix(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    // ── SLSA-lite provenance under the signature (issue #56) ──

    /// A manifest with one lockfile-pinned github input — the materials
    /// mirror has real content to assert against.
    #[test]
    fn malformed_envelope_is_a_named_error() {
        let (_, kp) = temp_keypair();
        let manifest = minimal_manifest();
        let body = eval_manifest_canonical_bytes(&manifest).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(kp.key_id(), serde_json::json!({ "signature": 123 }));
        let err = verify(&body, &sigs, &kp.public_hex()).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a valid signature envelope"),
            "{err:#}"
        );
    }
}
