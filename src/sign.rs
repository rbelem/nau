//! Self-managed update-manifest signing (ADR-0011 step (d)).
//!
//! A separate module — not folded into [`crate::manifest`] — because
//! manifest.rs is pure IR construction while this is an optional post-pass
//! over canonical bytes, shared by `shuttle eval` (signatures map) and image
//! builds (pubkey embedding at `/etc/shuttle/update-key.pub`).
//!
//! # Format
//!
//! minisign-style Ed25519, implemented over `ed25519-dalek` (already locked
//! transitively — no new dependency surface; the `minisign` crate would
//! pull bs58 & co. for no verify-path gain). Key files are two-line text:
//! an untrusted comment line, then lowercase hex of the key material
//! (secret file: the 32-byte seed; public file: the 32-byte public key).
//!
//! - Secret key: `$HOME/.config/shuttle/secret-key` (mode 0600). Keygen
//!   draws 32 bytes from `/dev/urandom` (Linux-only per project
//!   constraints). Creation refuses to overwrite an existing key —
//!   rotation/revocation is the key ceremony below (step (e)).
//! - Trusted public keys: `$HOME/.config/shuttle/keys/<key-id>.pub` —
//!   every `*.pub` file is a trust anchor for multi-key verification.
//! - Public key in images: `/etc/shuttle/update-key.pub` — the anchor the
//!   device-side verify path checks manifest signatures against.
//! - Trusted key SET in images: `/etc/shuttle/trusted-keys/<key-id>.pub`
//!   plus `/etc/shuttle/revoked-keys` (one revoked id per line) — so a
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
//! by which builder (`shuttle:<version>` + the eval invocation flags).
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
//! identity — the builder id is shuttle's own version, self-asserted
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
//! signature is shuttle's own manifest attestation, delivered now.

use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use miette::{IntoDiagnostic, WrapErr};

use crate::manifest::{ImageManifest, ManifestInput};

/// Untrusted-comment header on the secret key file.
const SECRET_COMMENT: &str = "untrusted comment: shuttle signing secret key (ed25519)";

/// Untrusted-comment header on embedded public keys.
pub const PUBLIC_COMMENT: &str = "untrusted comment: shuttle update public key (ed25519)";

/// Public key file embedded into image builds when signing is engaged.
pub const PUBKEY_EMBED_PATH: &str = "etc/shuttle/update-key.pub";

/// Trusted-key-set directory embedded into image builds (ADR-0024 §4).
/// Every `<key-id>.pub` in it is an anchor the device-side verify path
/// accepts. The current signing key is also copied to
/// [`PUBKEY_EMBED_PATH`] for backward compatibility with anchors that
/// predate the trust-set shape.
pub const TRUSTED_KEYS_EMBED_DIR: &str = "etc/shuttle/trusted-keys";

/// Revocation list embedded into image builds (ADR-0024 §4): one key id
/// per line. A device-side verifier consults it so "revoked" is
/// distinguishable from "never trusted".
pub const REVOKED_KEYS_EMBED_PATH: &str = "etc/shuttle/revoked-keys";

/// Secret key location under the user's home (`~/.config/shuttle/`).
pub fn secret_key_path(home: &Path) -> PathBuf {
    home.join(".config").join("shuttle").join("secret-key")
}

/// Rotation successor secret location under `home`
/// (`~/.config/shuttle/secret-key.new`, 0600): minted by rotation, moved
/// into place by promotion.
pub fn rotation_key_path(home: &Path) -> PathBuf {
    home.join(".config").join("shuttle").join("secret-key.new")
}

/// An Ed25519 signing key pair: the seed and its derived public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub seed: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    /// Short public identifier for the signatures map — the first 16 hex
    /// chars of the public key.
    pub fn key_id(&self) -> String {
        to_hex(&self.public)[..16].to_string()
    }

    /// Lowercase hex of the public key (the on-disk pubkey payload).
    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// Sign `bytes` and return the base64 signature string stored in the
/// signatures map.
pub fn sign_bytes(bytes: &[u8], kp: &KeyPair) -> String {
    let sig = kp.signing_key().sign(bytes);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

/// Verify `manifest_bytes` against the `signatures` map using the public
/// key `public_hex`. The entry is looked up by the key id derived from that
/// public key; a missing entry, undecodable signature, provenance that
/// does not bind the bytes, or failed Ed25519 check is a named error
/// (fail closed). Attested entries verify over body ++ provenance bytes
/// (issue #56); legacy bare entries over the body alone.
pub fn verify(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    public_hex: &str,
) -> miette::Result<()> {
    let public = from_hex32(public_hex).wrap_err("update public key is not 64 hex chars")?;
    let key_id = to_hex(&public)[..16].to_string();
    let entry = signatures.get(&key_id).ok_or_else(|| {
        miette::miette!("manifest carries no signature for key id {key_id} — refusing to verify")
    })?;
    let (payload, raw) = entry_signed_payload(manifest_bytes, &key_id, entry)?;
    verify_one(&payload, &key_id, &raw, &public)
}

/// Canonical signature input: the manifest serialized with `signatures`
/// emptied (see the module docs — a signature never covers itself; the map
/// is deterministic, so the bytes are byte-stable).
pub fn canonical_bytes(manifest: &ImageManifest) -> miette::Result<Vec<u8>> {
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

/// One signatures-map entry. Two shapes, both verify:
///
/// - `Bare` — the legacy plain base64 signature over the canonical body
///   bytes only (every manifest signed before issue #56).
/// - `Attested` — the signature over body bytes ++ provenance bytes,
///   with the SLSA-lite claims riding inside the entry (under the
///   signature, never in the canonical body). `provenance` is optional so
///   an envelope object without claims still verifies over the body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum SignatureEntry {
    Bare(String),
    Attested {
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance: Option<Provenance>,
    },
}

impl SignatureEntry {
    /// The attested claims, when the entry carries them.
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            SignatureEntry::Bare(_) => None,
            SignatureEntry::Attested { provenance, .. } => provenance.as_ref(),
        }
    }
}

/// The eval invocation a provenance attests: the flags that shaped pin
/// resolution (and that are deliberately kept OUT of the canonical body —
/// they are builder facts, not definition facts).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invocation {
    pub arch: String,
    pub channel: String,
    /// True when eval ran with `--offline` (resolution was forbidden to
    /// touch the network).
    pub offline: bool,
}

/// The attested output: the sha3-384 of the canonical body bytes. The
/// same content-address family the image snap pins use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Subject {
    pub name: String,
    pub manifest_sha3_384: String,
}

/// SLSA-lite provenance, attached under a signature entry (issue #56).
/// What was built (subject), from which verified inputs (materials), by
/// which builder (builder id + invocation).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub version: u32,

    /// Builder identity — `shuttle:<CARGO_PKG_VERSION>`. Self-asserted
    /// under the signing key; there is no independent builder registry
    /// (the "lite").
    pub builder_id: String,

    /// The invocation flags of the eval that produced the manifest.
    pub invocation: Invocation,

    /// The definition's declared inputs at their lockfile pins — a mirror
    /// of `ImageManifest.inputs`. The full input inventory (including
    /// every image snap pin) is already inside the signed body; the
    /// materials claim re-asserts the source-input half so a verifier
    /// holding only the attestation can read it, and
    /// [`check_provenance`] refuses a mirror that diverges from the
    /// manifest it rides.
    pub materials: std::collections::BTreeMap<String, ManifestInput>,

    /// The output digest binding: sha3-384 over the canonical body bytes
    /// the signature covers. Enforced at verify time before the Ed25519
    /// check — an attestation that does not bind its bytes is refused.
    pub subject: Subject,
}

/// The builder id for a shuttle version.
pub fn builder_id(shuttle_version: &str) -> String {
    format!("shuttle:{shuttle_version}")
}

/// SHA3-384 hex over the canonical body bytes — the provenance subject
/// digest.
pub fn subject_digest(body: &[u8]) -> String {
    use sha3::Digest;
    to_hex(&sha3::Sha3_384::digest(body))
}

/// The deterministic bytes a provenance contributes to the signed
/// payload (appended after the canonical body bytes).
pub fn provenance_bytes(provenance: &Provenance) -> miette::Result<Vec<u8>> {
    serde_json::to_vec(provenance).map_err(|e| miette::miette!("provenance serialization: {e}"))
}

impl Provenance {
    /// Build the SLSA-lite attestation for an eval-produced manifest:
    /// builder `shuttle:<version>`, the invocation flags, the declared
    /// inputs as materials, and the sha3-384 subject over `body` (the
    /// canonical bytes [`canonical_bytes`] produced).
    pub fn for_manifest(
        shuttle_version: &str,
        arch: &str,
        channel: &str,
        offline: bool,
        manifest: &ImageManifest,
        body: &[u8],
    ) -> miette::Result<Provenance> {
        Ok(Provenance {
            version: PROVENANCE_VERSION,
            builder_id: builder_id(shuttle_version),
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
    let mut payload = canonical_bytes(manifest)?;
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
/// SLSA-lite provenance under the signature — builder `shuttle:<version>`,
/// invocation = the eval flags, materials = the declared inputs, subject =
/// the body's sha3-384. The provenance lives inside the signatures-map
/// entry, never in the canonical body, so byte-identical eval is
/// preserved.
pub fn attest_eval(
    manifest: &mut ImageManifest,
    kp: &KeyPair,
    shuttle_version: &str,
    arch: &str,
    channel: &str,
    offline: bool,
) -> miette::Result<()> {
    let body = canonical_bytes(manifest)?;
    let provenance =
        Provenance::for_manifest(shuttle_version, arch, channel, offline, manifest, &body)?;
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

/// Decode one signatures-map entry and assemble the exact bytes its
/// Ed25519 signature covers (issue #56): the canonical body bytes, plus
/// the entry's provenance bytes when the entry carries them. A provenance
/// whose subject digest does not bind `body` is a named error BEFORE the
/// Ed25519 check — an attestation detached from its bytes must not pass
/// even with a valid signature over the pair.
fn entry_signed_payload(
    body: &[u8],
    key_id: &str,
    entry: &serde_json::Value,
) -> miette::Result<(Vec<u8>, String)> {
    let parsed: SignatureEntry = serde_json::from_value(entry.clone()).map_err(|e| {
        miette::miette!("signature entry for {key_id} is not a valid signature envelope: {e}")
    })?;
    match parsed {
        SignatureEntry::Bare(raw) => Ok((body.to_vec(), raw)),
        SignatureEntry::Attested {
            signature,
            provenance,
        } => {
            let Some(provenance) = provenance else {
                return Ok((body.to_vec(), signature));
            };
            let actual = subject_digest(body);
            if actual != provenance.subject.manifest_sha3_384 {
                return Err(miette::miette!(
                    "provenance subject digest does not bind these manifest bytes \
                     (attested {}, actual {}) — refusing to verify",
                    provenance.subject.manifest_sha3_384,
                    actual
                ));
            }
            let mut payload = body.to_vec();
            payload.extend_from_slice(&provenance_bytes(&provenance)?);
            Ok((payload, signature))
        }
    }
}

/// Create (never overwrite) the secret key under `home`. The 32 seed bytes
/// come from `/dev/urandom`; the file is written 0600. Existing keys abort
/// with a named error — rotation is step (e) ceremony, never an accident.
pub fn create_secret_key(home: &Path) -> miette::Result<KeyPair> {
    let path = secret_key_path(home);
    if path.exists() {
        return Err(miette::miette!(
            "signing key already exists at {} — refusing to overwrite (rotation is a \
             deliberate ceremony, not a side effect)",
            path.display()
        ));
    }
    let seed = read_urandom32()?;
    let kp = derive_pair(&seed);
    write_secret_key_at(&path, &kp)?;
    eprintln!("  ✓ signing key created: {}", path.display());
    Ok(kp)
}

/// Load the secret key under `home`. `Ok(None)` when absent — signing is
/// opt-in (step (d)); a present-but-unparseable key is a named error.
pub fn load_secret_key(home: &Path) -> miette::Result<Option<KeyPair>> {
    let path = secret_key_path(home);
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

/// Serialize the public key for embedding (`/etc/shuttle/update-key.pub`)
/// and for trust-anchor files (`~/.config/shuttle/keys/<key-id>.pub`).
pub fn public_key_file(kp: &KeyPair) -> String {
    format!("{}\n{}\n", PUBLIC_COMMENT, kp.public_hex())
}

// ── Key ceremony (ADR-0011 step (e)): keychain, rotation, revocation ──
//
// Paths (documented contract — `shuttle key keygen|rotate|promote|revoke|
// list|verify` is the operator surface, the device half consumes the
// embedded copies from the image build):
//
// - Secret key:            `~/.config/shuttle/secret-key`   (0600)
// - Rotation secret:       `~/.config/shuttle/secret-key.new` (0600)
// - Trusted public keys:   `~/.config/shuttle/keys/<key-id>.pub`
//   (every `*.pub` file is a trust anchor; same two-line format as the
//   embedded `/etc/shuttle/update-key.pub`).
// - Ceremony ledger:       `~/.config/shuttle/keys/ceremony.json` — the
//   audit trail (issue #51): created/rotated/revoked dates and the
//   generation chain (key id → replaced-by → date → window). The
//   ceremony as a first-class thing, not just the crypto.

/// Trusted public-key directory under the user's home:
/// `~/.config/shuttle/keys/`.
pub fn keys_dir(home: &Path) -> PathBuf {
    home.join(".config").join("shuttle").join("keys")
}

/// A set of trusted public keys (the verification trust anchors).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keychain {
    /// (key id, public key) pairs, in file order — order-insensitive at
    /// verify time (ANY trusted signature verifies).
    entries: Vec<(String, [u8; 32])>,
}

impl Keychain {
    /// Load every `*.pub` file in `dir` as a trust anchor. A missing
    /// directory is an empty chain (verify fails closed); a present but
    /// unparseable anchor is a named error — corrupt trust anchors are
    /// never silently skipped.
    pub fn load_dir(dir: &Path) -> miette::Result<Keychain> {
        let mut chain = Keychain::default();
        let Ok(read) = std::fs::read_dir(dir) else {
            return Ok(chain);
        };
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in read {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", dir.display()))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pub") {
                paths.push(path);
            }
        }
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .into_diagnostic()
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            let public_hex = text
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
                .ok_or_else(|| {
                    miette::miette!("public key file {} carries no key material", path.display())
                })?;
            let public =
                from_hex32(public_hex).wrap_err_with(|| format!("parsing {}", path.display()))?;
            chain
                .entries
                .push((to_hex(&public)[..16].to_string(), public));
        }
        Ok(chain)
    }

    /// True when no trust anchors are loaded — verification under an
    /// empty chain always fails closed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The trusted key ids.
    pub fn key_ids(&self) -> Vec<String> {
        self.entries.iter().map(|(id, _)| id.clone()).collect()
    }

    /// (key id, public key) pairs for callers that verify entry-by-entry
    /// outside [`verify_keychain`]'s all-or-nothing message (the device
    /// path tries the embedded set, the legacy anchor, then the operator
    /// keychain).
    pub fn entries_for_verify(&self) -> Vec<(String, [u8; 32])> {
        self.entries.clone()
    }
}

/// Install a public key into `dir` as `<key-id>.pub` (the trust-anchor
/// ceremony step). Returns the written path.
pub fn install_public_key(kp: &KeyPair, dir: &Path) -> miette::Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.pub", kp.key_id()));
    std::fs::write(&path, public_key_file(kp))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Add `kp`'s signature to the manifest's signatures map beside any
/// existing ones (DUAL/multi-signature). Canonical bytes never include
/// the map, so prior signatures keep verifying untouched.
pub fn cosign(manifest: &mut ImageManifest, kp: &KeyPair) -> miette::Result<()> {
    let bytes = canonical_bytes(manifest)?;
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
/// CLI's `shuttle key rotate`, where no manifest is in hand.
///
/// `rotate` is split this way because its signing half needs an
/// [`ImageManifest`] and the operator CLI has none: fabricating one just
/// to carry a signature would be a lie, and a bare `shuttle key rotate`
/// is exactly the "mint the successor" ceremony. `rotate` keeps its
/// dual-sign contract for the build path by calling this, then cosigning.
///
/// Requires an existing `secret-key`; refuses to overwrite an existing
/// `secret-key.new`. The successor is NOT trusted until promoted (its
/// `keys/<id>.pub` anchor is installed by [`promote_rotation_key`]).
pub fn mint_rotation_key(home: &Path) -> miette::Result<KeyPair> {
    if load_secret_key(home)?.is_none() {
        return Err(miette::miette!(
            "no signing key at {} — nothing to rotate (run `shuttle key keygen` first)",
            secret_key_path(home).display()
        ));
    }
    let successor = derive_pair(&read_urandom32()?);
    let new_path = rotation_key_path(home);
    if new_path.exists() {
        return Err(miette::miette!(
            "rotation key already exists at {} — refusing to overwrite (promote it with \
             `shuttle key promote`, or remove it to abandon the pending rotation)",
            new_path.display()
        ));
    }
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
            "no rotation key at {} — nothing to promote (mint one with `shuttle key rotate`)",
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

/// Operator-surface revocation: drop the local trust anchor for `key_id`
/// and record it in the local revocation list at `dir/revoked-keys`.
///
/// Distinct from [`revoke`] in that it names the key even after the
/// anchor is gone: the local `revoked-keys` file is what the image build
/// copies into `etc/shuttle/revoked-keys` so a device can tell "revoked"
/// (anchor absent *and* listed) apart from "never trusted" (anchor absent,
/// not listed). `revoking an absent anchor is refused unless it is
/// already listed` — a named error, never a silent no-op.
pub fn revoke_local(dir: &Path, key_id: &str) -> miette::Result<()> {
    let pub_path = dir.join(format!("{key_id}.pub"));
    let listed = read_revoked_keys(dir)?.iter().any(|id| id == key_id);
    if !pub_path.exists() && !listed {
        return Err(miette::miette!(
            "cannot revoke {key_id}: no trust anchor at {} and it is not in the \
             revocation list",
            pub_path.display()
        ));
    }
    if pub_path.exists() {
        std::fs::remove_file(&pub_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("removing {}", pub_path.display()))?;
    }
    if !listed {
        write_revoked_keys(dir, &{
            let mut ids = read_revoked_keys(dir)?;
            ids.push(key_id.to_string());
            ids
        })?;
    }
    eprintln!("  ✓ key {key_id} revoked: anchor removed, listed in revoked-keys");
    Ok(())
}

/// Read the `<dir>/revoked-keys` list (one key id per line). A missing
/// file is an empty list; malformed lines are named errors — a corrupt
/// revocation list must never be silently treated as empty.
pub fn read_revoked_keys(dir: &Path) -> miette::Result<Vec<String>> {
    let path = dir.join("revoked-keys");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() != 16 || !line.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(miette::miette!(
                "revocation list {} line {} is not a 16-hex key id: {line:?}",
                path.display(),
                n + 1
            ));
        }
        ids.push(line.to_ascii_lowercase());
    }
    Ok(ids)
}

/// Write the `<dir>/revoked-keys` list, one key id per line, sorted and
/// deduplicated (deterministic for byte-stable images).
fn write_revoked_keys(dir: &Path, ids: &[String]) -> miette::Result<()> {
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    let mut ids: Vec<String> = ids.iter().map(|id| id.to_ascii_lowercase()).collect();
    ids.sort();
    ids.dedup();
    let body: String = ids.iter().map(|id| format!("{id}\n")).collect();
    let path = dir.join("revoked-keys");
    std::fs::write(&path, body)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Reject a signature set made under any revoked key id. A signature
/// entry whose key id appears in `revoked` is a hard refusal BEFORE any
/// anchor check — "this key was trusted once and is trusted no longer"
/// must not be masked by a dual-signed manifest that a revoked key also
/// signed.
pub fn reject_revoked(
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    revoked: &[String],
) -> miette::Result<()> {
    for key_id in revoked {
        if signatures.contains_key(key_id) {
            return Err(miette::miette!(
                "artifact carries a signature from REVOKED key id {key_id} — refusing to \
                 install (revoked keys are never trusted again)"
            ));
        }
    }
    Ok(())
}

/// Multi-key verify: accept when ANY signature whose key id is in the
/// trusted set verifies over `manifest_bytes`. Attested entries verify
/// over body ++ provenance bytes with the subject binding enforced
/// (issue #56); a malformed envelope counts as failed, not missing. An
/// empty chain fails closed; so does a chain where no trusted key has a
/// verifiable signature. Returns the key id that verified.
pub fn verify_keychain(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
) -> miette::Result<String> {
    if chain.is_empty() {
        return Err(miette::miette!(
            "empty trust chain — no public keys loaded, refusing to verify (fail closed)"
        ));
    }
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    for (key_id, public) in &chain.entries {
        let Some(entry) = signatures.get(key_id) else {
            missing.push(key_id.clone());
            continue;
        };
        let checked = entry_signed_payload(manifest_bytes, key_id, entry)
            .and_then(|(payload, raw)| verify_one(&payload, key_id, &raw, public));
        match checked {
            Ok(()) => return Ok(key_id.clone()),
            Err(_) => failed.push(key_id.clone()),
        }
    }
    Err(miette::miette!(
        "no trusted signature verifies: missing entries for {:?}, failed for {:?} \
         — refusing to verify",
        missing,
        failed
    ))
}

/// The device-side trust policy (ADR-0024 §4): a closed key set plus an
/// explicit revocation list.
///
/// - [`reject_revoked`] runs first: a signature under a revoked id is a
///   hard refusal even if another, still-trusted key also signed.
/// - Then [`verify_keychain`] over the trusted set: a signature under an
///   id absent from the set is "never trusted" and fails closed.
///
/// Both halves are needed for "revoked" to be distinguishable from
/// "never trusted": without the revocation list, stripping an anchor is
/// indistinguishable from never having carried it.
pub fn verify_trust_set(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    chain: &Keychain,
    revoked: &[String],
) -> miette::Result<String> {
    reject_revoked(signatures, revoked)?;
    verify_keychain(manifest_bytes, signatures, chain)
}

// ── Ceremony ledger (issue #51, ADR-0011 §4e): the auditable key chain ──

/// Ceremony ledger schema version.
pub const CEREMONY_LEDGER_VERSION: u32 = 1;

/// Default overlap window, in days, recorded at rotation: how long a
/// rotated-out key's signatures stay first-class during the rollout of
/// its successor. Expired windows downgrade to a verify warning — the
/// artifact still verifies, the operator is told to re-sign.
pub const DEFAULT_WINDOW_DAYS: u32 = 30;

/// The ceremony ledger: `keys/ceremony.json` beside the trust anchors.
/// One entry per key the ceremony ever touched, carrying its dates and
/// its chain link (`replaced_by`), so a rotation/revocation is auditable
/// after the fact and [`verify_with_ledger`] can apply transition-window
/// policy. Every field is `#[serde(default)]`: ledgers written before a
/// field existed (and hand-minimal ones) keep parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CeremonyLedger {
    #[serde(default)]
    pub version: u32,
    /// Key id → ceremony record, sorted for byte-stable rewrites.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, LedgerEntry>,
}

/// One key's ceremony record (issue #51): when it was created, which key
/// replaced it and when (the generation chain), the overlap window that
/// rotation granted it, and when it was revoked. Absent fields are
/// genuinely unknown (e.g. revoking a key minted on another machine).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    /// Lowercase hex of the public key (64 chars), when known. Load-time
    /// validation pins its 16-char prefix to the map key — a tampered
    /// entry whose material disagrees with its id is a named error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// RFC3339 UTC creation date (keygen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// The successor key id this key was rotated out for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,

    /// RFC3339 UTC date the rotation was minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,

    /// Overlap window in days from `rotated_at`
    /// (default [`DEFAULT_WINDOW_DAYS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_days: Option<u32>,

    /// RFC3339 UTC date the key was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// The ledger file beside the trust anchors: `<keys-dir>/ceremony.json`.
pub fn ceremony_ledger_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join("ceremony.json")
}

impl CeremonyLedger {
    /// Load `<keys-dir>/ceremony.json`. A missing file is an empty ledger
    /// (keychains predating the ceremony are valid state); anything
    /// present is validated — corrupt JSON, a bad date, a key-id
    /// prefix/material mismatch, a dangling chain link, or an unknown
    /// future version is a named error. Trust-adjacent bookkeeping fails
    /// closed, never silently skips.
    pub fn load(keys_dir: &Path) -> miette::Result<CeremonyLedger> {
        let path = ceremony_ledger_path(keys_dir);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(CeremonyLedger::default());
        };
        let ledger: CeremonyLedger = serde_json::from_str(&text).map_err(|e| {
            miette::miette!(
                "key ceremony ledger {} is corrupt: {e} — refusing to interpret it",
                path.display()
            )
        })?;
        ledger
            .validate()
            .wrap_err_with(|| format!("key ceremony ledger {}", path.display()))?;
        Ok(ledger)
    }

    /// Write the ledger back (sorted ids, deterministic bytes).
    pub fn save(&self, keys_dir: &Path) -> miette::Result<()> {
        std::fs::create_dir_all(keys_dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", keys_dir.display()))?;
        let path = ceremony_ledger_path(keys_dir);
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("ledger serialization: {e}"))?;
        std::fs::write(&path, body + "\n")
            .into_diagnostic()
            .wrap_err_with(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Record a freshly created key (keygen). An existing entry for the
    /// id is never overwritten — the first record of a key wins.
    pub fn record_created(&mut self, kp: &KeyPair, created: &str) {
        self.keys.entry(kp.key_id()).or_insert_with(|| LedgerEntry {
            public_key: Some(kp.public_hex()),
            created: Some(created.to_string()),
            ..LedgerEntry::default()
        });
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Record the generation chain of a rotation: `old` was replaced by
    /// `successor` at `rotated_at`, with an overlap window of
    /// `window_days` days. `old`'s entry is created on the spot when the
    /// ledger never saw its keygen (pre-ceremony keychain).
    pub fn record_rotation(
        &mut self,
        old: &KeyPair,
        successor: &KeyPair,
        rotated_at: &str,
        window_days: u32,
    ) {
        let old_entry = self.keys.entry(old.key_id()).or_default();
        if old_entry.public_key.is_none() {
            old_entry.public_key = Some(old.public_hex());
        }
        if old_entry.created.is_none() {
            old_entry.created = Some(rotated_at.to_string());
        }
        old_entry.replaced_by = Some(successor.key_id());
        old_entry.rotated_at = Some(rotated_at.to_string());
        old_entry.window_days = Some(window_days);
        self.keys
            .entry(successor.key_id())
            .or_insert_with(|| LedgerEntry {
                public_key: Some(successor.public_hex()),
                created: Some(rotated_at.to_string()),
                ..LedgerEntry::default()
            });
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Record a revocation (the date is the audit trail; the enforcement
    /// half — anchor removal + `revoked-keys` — is [`revoke_local`]'s).
    pub fn record_revocation(&mut self, key_id: &str, revoked_at: &str) {
        let entry = self.keys.entry(key_id.to_string()).or_default();
        entry.revoked_at = Some(revoked_at.to_string());
        self.version = CEREMONY_LEDGER_VERSION;
    }

    /// Key ids carrying a revocation date.
    pub fn revoked_ids(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, e)| e.revoked_at.is_some())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// True when `key_id` was rotated out and its overlap window has
    /// passed by `now` (unix seconds). Keys without a recorded rotation
    /// are never stale; a recorded date that cannot parse is a named
    /// error — but [`CeremonyLedger::load`] validates dates up front, so
    /// this only fires for in-memory tampering.
    pub fn rotation_window_expired(&self, key_id: &str, now: i64) -> miette::Result<bool> {
        let Some(entry) = self.keys.get(key_id) else {
            return Ok(false);
        };
        let Some(rotated_at) = entry.rotated_at.as_deref() else {
            return Ok(false);
        };
        if entry.replaced_by.is_none() {
            return Ok(false);
        }
        let days = i64::from(entry.window_days.unwrap_or(DEFAULT_WINDOW_DAYS));
        let end = rfc3339_to_unix(rotated_at)? + days * 86_400;
        Ok(now > end)
    }

    /// Structural validation (see [`CeremonyLedger::load`]).
    fn validate(&self) -> miette::Result<()> {
        if self.version > CEREMONY_LEDGER_VERSION {
            return Err(miette::miette!(
                "ledger version {} is newer than this shuttle understands ({})",
                self.version,
                CEREMONY_LEDGER_VERSION
            ));
        }
        for (id, entry) in &self.keys {
            validate_entry(self, id, entry)?;
        }
        Ok(())
    }
}

/// Validate one ledger entry: key-id shape, material↔id agreement, date
/// parseability, and a chain link that resolves inside the ledger.
fn validate_entry(ledger: &CeremonyLedger, id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    if !is_key_id(id) {
        return Err(miette::miette!(
            "entry key id {id:?} is not a 16-hex key id"
        ));
    }
    validate_entry_material(id, entry)?;
    validate_entry_dates(id, entry)?;
    validate_entry_chain(ledger, id, entry)
}

/// The recorded public key material must be 64-hex whose own id prefix is
/// the entry's map key — a tampered entry cannot move the material
/// without tripping this.
fn validate_entry_material(id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    let Some(pk) = &entry.public_key else {
        return Ok(());
    };
    let agrees = match from_hex32(pk) {
        Ok(bytes) => to_hex(&bytes)[..16] == *id,
        Err(_) => false,
    };
    if agrees {
        return Ok(());
    }
    Err(miette::miette!(
        "entry {id} carries public key material that does not hash to its own id"
    ))
}

/// Every recorded date must parse as RFC3339 UTC.
fn validate_entry_dates(id: &str, entry: &LedgerEntry) -> miette::Result<()> {
    for (label, date) in [
        ("created", &entry.created),
        ("rotated_at", &entry.rotated_at),
        ("revoked_at", &entry.revoked_at),
    ] {
        if let Some(date) = date {
            rfc3339_to_unix(date)
                .map_err(|e| miette::miette!("entry {id} has a malformed {label} date: {e}"))?;
        }
    }
    Ok(())
}

/// A chain link must be a real key id with its own entry.
fn validate_entry_chain(
    ledger: &CeremonyLedger,
    id: &str,
    entry: &LedgerEntry,
) -> miette::Result<()> {
    let Some(succ) = &entry.replaced_by else {
        return Ok(());
    };
    if !is_key_id(succ) {
        return Err(miette::miette!(
            "entry {id} chains to {succ:?}, which is not a 16-hex key id"
        ));
    }
    if !ledger.keys.contains_key(succ) {
        return Err(miette::miette!(
            "entry {id} chains to successor {succ}, which has no ledger entry"
        ));
    }
    Ok(())
}

/// True when `s` is a well-formed 16-hex key id.
fn is_key_id(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The current time as unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The current time, RFC3339 UTC.
pub fn now_rfc3339() -> String {
    unix_to_rfc3339(now_unix())
}

/// Render unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (RFC3339 UTC). Civil
/// date from days via the standard era algorithm — no timestamp
/// dependency; the format is exactly what [`rfc3339_to_unix`] parses.
pub fn unix_to_rfc3339(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parse our own `YYYY-MM-DDTHH:MM:SSZ` rendering back to unix seconds.
/// Strict shape first, then a round-trip re-render must reproduce the
/// input — which rejects impossible dates (Feb 30, month 13, hour 27)
/// without a calendar table.
pub fn rfc3339_to_unix(s: &str) -> miette::Result<i64> {
    let b = s.as_bytes();
    let shape_ok = b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && b.iter()
            .enumerate()
            .all(|(i, c)| (0x30..=0x39).contains(c) || [4usize, 7, 10, 13, 16, 19].contains(&i));
    if !shape_ok {
        return Err(miette::miette!("expected YYYY-MM-DDTHH:MM:SSZ, got {s:?}"));
    }
    let num = |a: usize, z: usize| -> i64 {
        s[a..z].parse().expect("shape check made this ascii digits")
    };
    let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
    let (h, mi, sec) = (num(11, 13), num(14, 16), num(17, 19));
    let t = days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + sec;
    if unix_to_rfc3339(t) != s {
        return Err(miette::miette!("not a real UTC datetime: {s:?}"));
    }
    Ok(t)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

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
    let body = canonical_bytes(manifest)?;
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
                     refusing to re-attach stale claims under key {} (re-run `shuttle eval` \
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

/// Verify one base64 signature string under one public key (the single
/// entry path shared by [`verify`] and [`verify_keychain`]).
fn verify_one(
    manifest_bytes: &[u8],
    key_id: &str,
    raw: &str,
    public: &[u8; 32],
) -> miette::Result<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| miette::miette!("signature for {key_id} is not valid base64: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| miette::miette!("signature for {key_id} is malformed: {e}"))?;
    let vk = VerifyingKey::from_bytes(public)
        .map_err(|e| miette::miette!("public key {key_id} is malformed: {e}"))?;
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| miette::miette!("signature verification FAILED for key id {key_id}"))
}

fn write_secret_key_at(path: &Path, kp: &KeyPair) -> miette::Result<()> {
    let dir = path.parent().expect("secret key path has a parent");
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    std::fs::write(path, format!("{SECRET_COMMENT}\n{}\n", kp.seed_hex()))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

fn derive_pair(seed: &[u8; 32]) -> KeyPair {
    let signing = SigningKey::from_bytes(seed);
    KeyPair {
        seed: *seed,
        public: signing.verifying_key().to_bytes(),
    }
}

fn parse_secret_key(text: &str) -> miette::Result<KeyPair> {
    let seed_hex = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .ok_or_else(|| miette::miette!("secret key file carries no key material"))?;
    let seed = from_hex32(seed_hex)?;
    Ok(derive_pair(&seed))
}

fn read_urandom32() -> miette::Result<[u8; 32]> {
    use std::io::Read;
    // read_exact — /dev/urandom never EOFs, so read-to-end would block
    // forever.
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| miette::miette!("cannot open /dev/urandom: {e}"))?;
    let mut out = [0u8; 32];
    f.read_exact(&mut out)
        .map_err(|e| miette::miette!("cannot read 32 bytes from /dev/urandom: {e}"))?;
    Ok(out)
}

impl KeyPair {
    fn seed_hex(&self) -> String {
        to_hex(&self.seed)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex32(s: &str) -> miette::Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(miette::miette!("expected 64 hex chars, got {s:?}"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| miette::miette!("bad hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

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
        let before = canonical_bytes(&m).unwrap();
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
        assert_eq!(canonical_bytes(&m).unwrap(), before);
        // Empty map serializes as {} deterministically (BTreeMap order).
        assert_eq!(
            canonical_bytes(&minimal_manifest()).unwrap(),
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
        let bytes = canonical_bytes(&manifest).unwrap();
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
        let mut bytes = canonical_bytes(&manifest).unwrap();
        // Flip one payload byte — the signature must stop holding.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let mut sigs = BTreeMap::new();
        let intact = canonical_bytes(&manifest).unwrap();
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
        let bytes = canonical_bytes(&manifest).unwrap();
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
        let bytes = canonical_bytes(&manifest).unwrap();
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
        let mut bytes = canonical_bytes(&manifest).unwrap();
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
        let new_path = home.path().join(".config/shuttle/secret-key.new");
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
        let bytes = canonical_bytes(&manifest).unwrap();
        assert_eq!(bytes, canonical_bytes(&minimal_manifest()).unwrap());

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
            std::fs::read_to_string(home.path().join(".config/shuttle/secret-key.new")).unwrap();
        assert!(stored.contains(&first.seed_hex()));
    }

    #[test]
    fn revoke_drops_anchor_and_signature_and_old_fails_new_passes() {
        let (home, old) = temp_keypair();
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &old).unwrap();
        let successor = rotate(home.path(), &mut manifest).unwrap();
        let bytes = canonical_bytes(&manifest).unwrap();

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
        let bytes_after = canonical_bytes(&manifest).unwrap();
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
        assert!(home.path().join(".config/shuttle/secret-key.new").exists());

        // Before promotion the successor has NO anchor, so a manifest it
        // signed cannot verify under the keychain.
        let mut manifest = minimal_manifest();
        cosign(&mut manifest, &successor).unwrap();
        let bytes = canonical_bytes(&manifest).unwrap();
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
        assert!(!home.path().join(".config/shuttle/secret-key.new").exists());
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
            home.path().join(".config/shuttle/secret-key.new"),
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
            home.path().join(".config/shuttle/secret-key.new").exists(),
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
        let bytes = canonical_bytes(&manifest).unwrap();
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
        let bytes = canonical_bytes(&manifest).unwrap();

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
        let body = canonical_bytes(&manifest).unwrap();

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
        let body = canonical_bytes(&manifest).unwrap();

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
        let old_only_body = canonical_bytes(&old_only).unwrap();
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
        let body = canonical_bytes(&manifest).unwrap();
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
        let body = canonical_bytes(&manifest).unwrap();
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
        let body = canonical_bytes(&manifest).unwrap();
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
                provenance.as_mut().unwrap().builder_id = "shuttle:0.0.0-lies".into();
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

        let body = canonical_bytes(&manifest).unwrap();
        verify(&body, &manifest.signatures, &kp.public_hex()).unwrap();

        // The entry is an attested envelope whose subject digests the body.
        let parsed: SignatureEntry =
            serde_json::from_value(manifest.signatures[&kp.key_id()].clone()).unwrap();
        let prov = parsed.provenance().expect("attested entry carries claims");
        assert_eq!(prov.version, PROVENANCE_VERSION);
        assert_eq!(prov.builder_id, "shuttle:9.9.9");
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

        let body = canonical_bytes(&manifest).unwrap();
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

        let body = canonical_bytes(&manifest).unwrap();
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
        let body_b = canonical_bytes(&b).unwrap();
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
        let body = canonical_bytes(&manifest).unwrap();
        let entry = &manifest.signatures[&kp.key_id()];
        let sig = entry["signature"].as_str().expect("signature field");
        let json = serde_json::to_string(entry).unwrap();
        // The stored entry is a serde_json::Value (BTreeMap keys), so the
        // envelope's key order is sorted-deterministic — this literal is
        // the deliberate golden; update it only with the schema.
        let want = format!(
            concat!(
                r#"{{"provenance":{{"builder_id":"shuttle:9.9.9","#,
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
    fn attested_signatures_stay_out_of_canonical_bytes() {
        let (_, kp) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", true).unwrap();
        // Byte-identical eval is the hard constraint (issue #56): a fully
        // attested manifest's canonical bytes are exactly the unsigned
        // golden — builder/host facts never enter the body.
        assert_eq!(
            canonical_bytes(&manifest).unwrap(),
            canonical_bytes(&manifest_with_github_input()).unwrap()
        );
    }

    #[test]
    fn keychain_verifies_attested_entries_and_fails_on_tamper() {
        let (_, kp) = temp_keypair();
        let (_, other) = temp_keypair();
        let mut manifest = manifest_with_github_input();
        attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", true).unwrap();
        let body = canonical_bytes(&manifest).unwrap();
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
        let body = canonical_bytes(&manifest).unwrap();
        let mut sigs = BTreeMap::new();
        sigs.insert(kp.key_id(), serde_json::json!({ "signature": 123 }));
        let err = verify(&body, &sigs, &kp.public_hex()).unwrap_err();
        assert!(
            format!("{err:#}").contains("not a valid signature envelope"),
            "{err:#}"
        );
    }
}
