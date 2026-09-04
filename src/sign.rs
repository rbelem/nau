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

/// Secret key location under the user's home (`~/.config/shuttle/`).
pub fn secret_key_path(home: &Path) -> PathBuf {
    home.join(".config").join("shuttle").join("secret-key")
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
    if load_secret_key(home)?.is_none() {
        return Err(miette::miette!(
            "no signing key at {} — nothing to rotate",
            secret_key_path(home).display()
        ));
    }
    let successor = derive_pair(&read_urandom32()?);
    let new_path = home.join(".config").join("shuttle").join("secret-key.new");
    if new_path.exists() {
        return Err(miette::miette!(
            "rotation key already exists at {} — refusing to overwrite (finish or abandon \
             the pending rotation first)",
            new_path.display()
        ));
    }
    write_secret_key_at(&new_path, &successor)?;
    eprintln!(
        "  ✓ rotation key minted: {} (key id {})",
        new_path.display(),
        successor.key_id()
    );
    cosign(manifest, &successor)?;
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
}
