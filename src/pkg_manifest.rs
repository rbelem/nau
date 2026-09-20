//! The signed per-package shareable manifest (ADR-0033 Decision 2) — the
//! one genuinely new artifact peer sharing introduces.
//!
//! What traveled before was not enough: the generation `manifest.json`
//! (`src/runtime.rs`) records per-file sha256 hashes but is unsigned
//! derived local state; `ImageManifest` (`src/manifest.rs`) signs
//! image-level eval output against sha3-384 Snap Store pins, not store
//! blobs. A receiving peer must reconstruct an installable entry from
//! the manifest ALONE, so the snap.yaml-derived install metadata
//! recorded at install time (apps, launchers, services, confinement,
//! and the other install-time records `InstalledPackage` carries) has
//! to travel with the file hashes — metadata must travel, never be
//! re-derived.
//!
//! # Canonical bytes
//!
//! Signature input is `serde_json::to_vec` of the manifest **with the
//! `signature` field emptied** — mirroring `src/sign.rs`
//! (`canonical_bytes`, where the signatures map is emptied in place).
//! The field stays present (empty string) so the shape is byte-stable
//! and a signature never covers itself.
//!
//! Minting (who signs) is the serve/export/pull lanes' business; this
//! module owns the schema, the canonical bytes, and the sign/verify
//! wrapping over `crate::sign`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sign::KeyPair;

/// One store file of a shared package: the payload path it occupied at
/// install time, the sha256 of its content-addressed blob in the store
/// (the ADR-0012 blob set — `store/<aa>/<sha256>`), and whether the
/// installed file carried the executable bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// The file's path within the installed payload tree.
    pub path: String,
    /// sha256 of the store blob — the pull lane hash-checks every
    /// fetched blob against this.
    pub sha256: String,
    /// Whether the installed file was executable.
    pub executable: bool,
}

/// The install-time metadata a receiving peer needs to reconstruct an
/// installable entry from the manifest alone (ADR-0033 Decision 2):
/// exactly what `InstalledPackage` (`src/runtime.rs`) records from the
/// payload's snap.yaml at install time, minus the identity fields
/// (name/version/revision live on [`PackageManifest`]) and the per-file
/// hash list (promoted to [`ManifestFile`] with paths and the
/// executable bit). Typed throughout — no raw passthrough.
///
/// Every field carries the same serde defaults as its
/// `InstalledPackage` counterpart, so manifests minted before a field
/// existed — and minimal ones — keep parsing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InstallMeta {
    /// Daemon unit names this package contributed (empty for plain
    /// apps) — mirrored from `InstalledPackage::units`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// App name → sha256 of the app's command binary in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub apps: BTreeMap<String, String>,
    /// App name → sha256 of the app's confined-launcher wrapper blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub launchers: BTreeMap<String, String>,
    /// Multi-file app payloads: app name → the app's in-payload binary
    /// path plus sibling content recorded beside it at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub assembly: BTreeMap<String, crate::farm::AppAssembly>,
    /// Package-level confinement declaration (ADR-0016): `Some` =
    /// confined, `None` = unconfined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<crate::snap::Confinement>,
    /// Per-app confinement overrides: app name → grants, only for apps
    /// whose `confined` differs from the package default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, crate::snap::Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from
    /// the package's `.desktop` file at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, crate::runtime::DesktopLauncher>,
    /// Payload font files: path under the payload's `usr/share/fonts`
    /// → sha256 (issue #29 cutover).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fonts: BTreeMap<String, String>,
    /// Service declarations (ADR-0032) recorded verbatim from the
    /// payload's snap.yaml: service name → decl.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, crate::snap::ServiceDecl>,
    /// Service name → sha256 of the service's command binary blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_bins: BTreeMap<String, String>,
    /// The package's declared runtime requires (ADR-0018), recorded so
    /// a receiving peer knows the package needs the emit-time LD
    /// wrapper without re-reading a pool it does not have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

/// A signed, per-package, shareable manifest (ADR-0033 Decision 2):
/// what travels between peers, beside the store blobs it references.
/// The store's first per-package signed artifact — canonicalized and
/// signed with the same machinery as the image manifest (`crate::sign`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Snap/package name (the store key; `[a-z0-9-]` per the ADR-0032
    /// collision-classifier charset the wire grammar reuses).
    pub name: String,
    pub version: String,
    /// Monotonic per name — the freshness rule (ADR-0033 Decision 7)
    /// refuses older revisions unless `--allow-downgrade` is explicit.
    pub revision: u32,
    /// GNU target triplet the payload was built for.
    pub target: String,
    /// The store blob set: every file the package contributes, with
    /// its sha256 and executable bit.
    pub files: Vec<ManifestFile>,
    /// The snap.yaml-derived install metadata (see [`InstallMeta`]).
    #[serde(default)]
    pub install: InstallMeta,
    /// The signing key id (first 16 hex chars of the public key) —
    /// verifiers match it against their trusted-key set (the peer lane
    /// enforces fail-closed `verify_trust_set` semantics).
    #[serde(default)]
    pub signer: String,
    /// The ed25519 signature over [`canonical_bytes`], as
    /// [`crate::sign::sign_bytes`] emits it (standard base64 — the
    /// encoding `crate::sign::verify` decodes).
    #[serde(default)]
    pub signature: String,
}

/// Canonical signature input: the manifest serialized with `signature`
/// emptied (see the module docs — a signature never covers itself; the
/// emptied field keeps the bytes byte-stable, the same rule
/// `crate::sign::canonical_bytes` applies to the image manifest).
pub fn canonical_bytes(pkg: &PackageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = pkg.clone();
    clean.signature = String::new();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

/// Sign `pkg` in place under `kp`: the ed25519 signature over the
/// canonical bytes, with the signer key id recorded beside it. Re-signing
/// replaces any previous signature — a manifest carries one author's
/// signature; multi-key trust is the verifier-side keychain's job.
pub fn sign(pkg: &mut PackageManifest, kp: &KeyPair) -> miette::Result<()> {
    // The signer id is part of the canonical body (only `signature`
    // empties out), so it is stamped BEFORE the signed bytes exist —
    // the signature binds who signed, not just what.
    pkg.signer = kp.key_id();
    let bytes = canonical_bytes(pkg)?;
    pkg.signature = crate::sign::sign_bytes(&bytes, kp);
    Ok(())
}

/// Verify `pkg`'s signature against the full public key `public_hex`
/// (64 hex chars — the manifest carries only the 16-hex key id). A
/// tampered field (canonical bytes changed), a signature that does not
/// decode, or a key whose id is not the recorded `signer` fails closed.
/// Trust (is this key BELIEVED?) is the caller's keychain decision —
/// this checks self-consistency only, wrapping [`crate::sign::verify`].
pub fn verify(pkg: &PackageManifest, public_hex: &str) -> miette::Result<()> {
    let mut signatures = BTreeMap::new();
    signatures.insert(
        pkg.signer.clone(),
        serde_json::Value::String(pkg.signature.clone()),
    );
    crate::sign::verify(&canonical_bytes(pkg)?, &signatures, public_hex)
}

/// Load the operator's signing key for manifest minting. Unlike
/// [`crate::sign::load_secret_key`] — whose `Ok(None)` means signing is
/// opt-out — minting REQUIRES a key: unsigned store entries are never
/// served (ADR-0033 Decision 2). Absence is a named error pointing at
/// the `shuttle key` ceremony.
pub fn load_signing_key(home: &Path) -> miette::Result<KeyPair> {
    crate::sign::load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "no signing key at {} — shareable package manifests are always signed; \
             run `shuttle key keygen` first (see `shuttle key list` for the ceremony ledger)",
            crate::sign::secret_key_path(home).display()
        )
    })
}

/// The pull-staging inbox path for one package's signed manifest:
/// `<root>/store/manifests/<pkg>.json`, where `root` is the state root
/// whose `store/` holds the content blobs.
///
/// Invariant (ADR-0033 Decision 5): `serve` and `export` publish the
/// UNION of the generation-derived manifests and this inbox — an inbox
/// entry whose name is not in the current generation is still visible.
/// This is how `pull` stages verified peer content without installing:
/// the manifest lands here, the blobs in the store, and installation
/// stays the pod workflow.
pub fn manifest_path(store_root: &Path, pkg: &str) -> PathBuf {
    store_root
        .join("store")
        .join("manifests")
        .join(format!("{pkg}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic keypair from a single seed byte (test-only).
    fn test_kp(seed_byte: u8) -> KeyPair {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
        KeyPair {
            seed: sk.to_bytes(),
            public: sk.verifying_key().to_bytes(),
        }
    }

    fn sample() -> PackageManifest {
        let mut apps = BTreeMap::new();
        apps.insert("hello".to_string(), "ab".repeat(32));
        let services: BTreeMap<String, crate::snap::ServiceDecl> = serde_json::from_value(
            serde_json::json!({ "srv": { "command": "bin/srv", "daemon": "simple" } }),
        )
        .unwrap();
        let confined: crate::snap::Confinement =
            serde_json::from_value(serde_json::json!({})).unwrap();
        PackageManifest {
            name: "hello".to_string(),
            version: "2.10".to_string(),
            revision: 7,
            target: "x86_64-linux-gnu".to_string(),
            files: vec![ManifestFile {
                path: "usr/bin/hello".to_string(),
                sha256: "cd".repeat(32),
                executable: true,
            }],
            install: InstallMeta {
                apps,
                services,
                confined: Some(confined),
                requires: vec!["libc6".to_string()],
                ..Default::default()
            },
            signer: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn roundtrip_preserves_manifest() {
        let pkg = sample();
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: PackageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pkg);
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_the_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let canonical = canonical_bytes(&pkg).unwrap();

        // Byte-stable across calls…
        assert_eq!(canonical_bytes(&pkg).unwrap(), canonical);
        // …and identical to the unsigned shape: the signature field is
        // emptied, not removed, so re-serializing the unsigned manifest
        // matches.
        let mut unsigned = pkg.clone();
        unsigned.signature = String::new();
        assert_eq!(serde_json::to_vec(&unsigned).unwrap(), canonical);
        assert_ne!(serde_json::to_vec(&pkg).unwrap(), canonical);
    }

    #[test]
    fn verify_accepts_signed_manifest_and_refuses_tampered_signature() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let public = test_kp(1).public_hex();
        verify(&pkg, &public).expect("a freshly signed manifest must verify");

        let mut tampered = pkg.clone();
        tampered.signature.push('x');
        assert!(
            verify(&tampered, &public).is_err(),
            "a flipped signature must be refused"
        );

        // Content tampering changes the canonical bytes → refused too.
        let mut tampered = pkg.clone();
        tampered.files[0].sha256 = "ff".repeat(32);
        assert!(verify(&tampered, &public).is_err());
    }

    #[test]
    fn verify_refuses_a_different_key() {
        let mut pkg = sample();
        sign(&mut pkg, &test_kp(1)).unwrap();
        let other = test_kp(2).public_hex();
        assert!(
            verify(&pkg, &other).is_err(),
            "verifying under the wrong public key must fail closed"
        );
    }

    #[test]
    fn inbox_path_is_store_scoped_per_package() {
        let root = Path::new("/srv/shuttle-state");
        assert_eq!(
            manifest_path(root, "hello"),
            PathBuf::from("/srv/shuttle-state/store/manifests/hello.json")
        );
    }
}
