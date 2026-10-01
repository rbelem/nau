//! Self-managed update-manifest signing (ADR-0011 step (d)).
//!
//! A separate module — not folded into [`crate::manifest`] — because
//! manifest.rs is pure IR construction while this is an optional post-pass
//! over canonical bytes, shared by `nau eval` (signatures map) and image
//! builds (pubkey embedding at `/etc/nau/update-key.pub`).
//!
//! # Format
//!
//! minisign-style Ed25519, implemented over `ed25519-dalek` (already locked
//! transitively — no new dependency surface; the `minisign` crate would
//! pull bs58 & co. for no verify-path gain). Key files are two-line text:
//! an untrusted comment line, then lowercase hex of the key material
//! (secret file: the 32-byte seed; public file: the 32-byte public key).
//!
//! - Secret key: `$HOME/.config/nau/secret-key` (mode 0600). Keygen
//!   draws 32 bytes from `/dev/urandom` (Linux-only per project
//!   constraints). Creation refuses to overwrite an existing key —
//!   rotation/revocation is the key ceremony below (step (e)).
//! - Trusted public keys: `$HOME/.config/nau/keys/<key-id>.pub` —
//!   every `*.pub` file is a trust anchor for multi-key verification.
//! - Public key in images: `/etc/nau/update-key.pub` — the anchor the
//!   device-side verify path checks manifest signatures against.
//! - Trusted key SET in images: `/etc/nau/trusted-keys/<key-id>.pub`
//!   plus `/etc/nau/revoked-keys` (one revoked id per line) — so a
//!   device can tell "not trusted anymore" from "never trusted"
//!   (ADR-0024 §4).
//!
//! # Canonical bytes
//!
//! Signature input is `serde_json::to_vec` of the manifest **with the
//! `signatures` map emptied** — the map is deterministic (`BTreeMap`, `{}`
//! when empty), so the canonical bytes are byte-stable and a signature
//! never covers itself. Signatures attach into that same map keyed by key
//! id (first 16 hex chars of the public key) without bumping the manifest
//! schema.
//!
//! # Provenance under the signature (SLSA-lite, issue #56)
//!
//! A signature entry may carry a SLSA-lite provenance attestation: what
//! was built (the sha3-384 subject digest over the canonical body bytes),
//! from which inputs (the declared materials at their lockfile pins), and
//! by which builder (`nau:<version>` + the eval invocation flags).
//! The provenance lives INSIDE the signatures-map entry —
//! `{"signature": …, "provenance": …}` — never in the canonical body, so
//! it is covered by the signature (tamper breaks verify) while
//! byte-identical eval is preserved (the body the eval property asserts
//! on never changes).
//!
//! Verification assembles the signed payload as body bytes ++ provenance
//! bytes and refuses, before the Ed25519 check, a provenance whose
//! subject digest does not bind the body it travels with. The materials
//! half of the binding ([`check_provenance`]) needs the parsed manifest
//! and is enforced by callers that hold one (the device verify path) and
//! offered to every other consumer.
//!
//! Deliberately omitted (the "lite"): no full SLSA levels, no transparency
//! log, no external rekor/keyling infrastructure, no independent builder
//! identity — the builder id is nau's own version, self-asserted
//! under the operator's key. The claim is only as strong as the signing
//! key; that is the issue's stated bar.
//!
//! # The ceremony ledger (issue #51, ADR-0011 §4e)
//!
//! `keys/ceremony.json` records the ceremony as a first-class thing: one
//! entry per key with its created/rotated/revoked dates and the
//! generation chain (key id → `replaced_by` → date → overlap window).
//! [`verify_with_ledger`] layers transition-window policy on top of the
//! keychain's ANY-signature rule: either key verifies during the window;
//! after it expires a manifest signed only by the rotated-out key still
//! verifies but carries a warning; a manifest signed only by revoked
//! keys is a named error, while one re-signed under a live key keeps
//! verifying (no retroactive breakage). The device-side trust set
//! ([`verify_trust_set`]) keeps ADR-0024's stricter rule — any revoked
//! signature is refused — because a device's job is enforcement, not
//! rollout.
//!
//! # Distinction from sysupdate's own verification
//!
//! systemd-sysupdate verifies the update payload's SHA256SUMS with its GPG
//! keyring at update time (device provisioning — step (e)/24b). THIS
//! signature is nau's own manifest attestation, delivered now.

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use crate::manifest::{ImageManifest, ManifestInput};

// The generic keychain half (key material, on-disk layout, trust anchors,
// revocation list, ceremony ledger, time/hex helpers) moved DOWN into
// `nau_core::sign` (issue #326 PR 3 down-move). Re-exported so every
// `crate::sign::` path — this module's remaining ceremony, the image
// verify path, and the tests — keeps resolving.
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

/// Canonical signature input for the EVAL manifest
/// ([`crate::manifest::ImageManifest`]): serialized with `signatures`
/// emptied (see the module docs — a signature never covers itself; the map
/// is deterministic, so the bytes are byte-stable).
///
/// Named `eval_manifest_…` deliberately (#266): the IMAGE manifest's
/// canonical bytes are a separate scheme —
/// [`crate::image::verify::image_manifest_canonical_bytes`] — and the
/// two must never be confused when signing/verifying.
pub fn eval_manifest_canonical_bytes(manifest: &ImageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = manifest.clone();
    clean.signatures.clear();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Persist `kp`'s sysupdate pubring fragment (the [`import_pubring_pgp`]
/// bytes) beside the trust anchors. The bytes are deterministic → the
/// write is an idempotent overwrite. Only possible while `kp`'s SEED
/// exists — the rotation ceremony writes each key's fragment at exactly
/// those moments (mint: old + successor; promote: repairs from `.new`).
fn write_sysupdate_fragment(kp: &KeyPair, keys_dir: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(keys_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", keys_dir.display()))?;
    let path = sysupdate_fragment_path(keys_dir, &kp.key_id());
    let bytes = import_pubring_pgp(kp)?;
    std::fs::write(&path, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

// `load_sysupdate_fragment` and the rest of the sysupdate OpenPGP layer
// moved to `nau_image::sysupdate` (R3, issue #326 PR 3); re-exported
// above.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use ed25519_dalek::SigningKey;
    use pgp::composed::SignedPublicKey;

    fn minimal_manifest() -> ImageManifest {
        ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
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
    const T0: i64 = 1_700_000_000;
    const DAY: i64 = 86_400;

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

    // ── Sysupdate manifest signing (#267) ──

    /// The sums-like sysupdate manifest body the tests sign/verify.
    fn sysupdate_sums() -> Vec<u8> {
        b"1111...  nau-cassini-1.0.0-amd64.img\n\
          2222...  nau-cassini-1.0.0-amd64.manifest.json\n"
            .to_vec()
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
