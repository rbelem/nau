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
//!   rotation/revocation is ceremony territory (step (e)).
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
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| miette::miette!("signature for {key_id} is not valid base64: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| miette::miette!("signature for {key_id} is malformed: {e}"))?;
    let vk = VerifyingKey::from_bytes(&public)
        .map_err(|e| miette::miette!("public key {key_id} is malformed: {e}"))?;
    vk.verify(manifest_bytes, &sig)
        .map_err(|_| miette::miette!("signature verification FAILED for key id {key_id}"))
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
    let dir = path.parent().expect("secret key path has a parent");
    std::fs::create_dir_all(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dir.display()))?;
    std::fs::write(&path, format!("{SECRET_COMMENT}\n{}\n", kp.seed_hex()))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("chmod 0600 {}", path.display()))?;
    }
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

/// Serialize the public key for embedding (`/etc/shuttle/update-key.pub`).
pub fn public_key_file(kp: &KeyPair) -> String {
    format!("{}\n{}\n", PUBLIC_COMMENT, kp.public_hex())
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
}
