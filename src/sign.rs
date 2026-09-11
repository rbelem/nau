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
//! # Distinction from sysupdate's own verification
//!
//! systemd-sysupdate verifies the update payload's SHA256SUMS with its GPG
//! keyring at update time (device provisioning — step (e)/24b). THIS
//! signature is shuttle's own manifest attestation, delivered now.

use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use miette::{IntoDiagnostic, WrapErr};

use crate::manifest::ImageManifest;

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
/// public key; a missing entry, undecodable signature, or failed Ed25519
/// check is a named error (fail closed).
pub fn verify(
    manifest_bytes: &[u8],
    signatures: &std::collections::BTreeMap<String, serde_json::Value>,
    public_hex: &str,
) -> miette::Result<()> {
    let public = from_hex32(public_hex).wrap_err("update public key is not 64 hex chars")?;
    let key_id = to_hex(&public)[..16].to_string();
    let raw = signatures
        .get(&key_id)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            miette::miette!(
                "manifest carries no signature for key id {key_id} — refusing to verify"
            )
        })?;
    verify_one(manifest_bytes, &key_id, raw, &public)
}

/// Canonical signature input: the manifest serialized with `signatures`
/// emptied (see the module docs — a signature never covers itself; the map
/// is deterministic, so the bytes are byte-stable).
pub fn canonical_bytes(manifest: &ImageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = manifest.clone();
    clean.signatures.clear();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
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
// Paths (documented contract, no CLI surface yet — the updater of
// Phase 24b consumes these):
//
// - Secret key:            `~/.config/shuttle/secret-key`   (0600)
// - Rotation secret:       `~/.config/shuttle/secret-key.new` (0600)
// - Trusted public keys:   `~/.config/shuttle/keys/<key-id>.pub`
//   (every `*.pub` file is a trust anchor; same two-line format as the
//   embedded `/etc/shuttle/update-key.pub`).

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
/// trusted set verifies over `manifest_bytes`. An empty chain fails
/// closed; so does a chain where no trusted key has a verifiable
/// signature. Returns the key id that verified.
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
        let Some(raw) = signatures.get(key_id).and_then(|v| v.as_str()) else {
            missing.push(key_id.clone());
            continue;
        };
        match verify_one(manifest_bytes, key_id, raw, public) {
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
}
