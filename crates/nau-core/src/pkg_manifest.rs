//! The per-package install-record vocabulary + the signed shareable
//! manifest (issue #326 PR 4 down-moves). Shapes recorded at install
//! time and shared by the pod runtime, the farm emitter, the pull
//! lanes, and the shareable package manifest. The root crate's
//! `pkg_manifest` module keeps the minting half (who signs is the
//! serve/export/pull lanes' business) and re-exports everything here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use miette::bail;
use serde::{Deserialize, Serialize};

use crate::sign::KeyPair;
use crate::snap_types::{Confinement, ServiceDecl};

// ── Install-time records ──

/// One app's multi-file payload assembly (issue #37): the app binary's
/// in-payload path plus the content that ships beside it (same payload
/// directory, recursively), recorded at install time from the walked
/// payload tree. Paths under `files`/`links` are relative to the
/// binary's directory and reproduce the payload layout the binary
/// resolves against. Empty maps mean the payload ships the binary
/// alone — nothing recorded, the farm keeps the bare direct link.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppAssembly {
    /// In-payload path of the app's command binary (e.g.
    /// `usr/bin/git-credential-manager`).
    pub binary: String,
    /// Files beside the binary: path relative to the binary's payload
    /// directory → sha256 of the content blob in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// Symlinks beside the binary, recreated verbatim: relative path →
    /// link target (never followed — payload links stay payload-scoped).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

impl AppAssembly {
    /// Whether the payload ships this app's binary alone.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.links.is_empty()
    }
}

/// One GUI app's desktop-launcher metadata (issue #7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopLauncher {
    /// `Name=` of the source `.desktop` file (falls back to the app id
    /// in the generated entry when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `GenericName=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generic_name: Option<String>,
    /// `Comment=` of the source file, passed through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Menu categories, split from the source file's `Categories=`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// `Icon=` of the source file, passed through ONLY when the package
    /// ships no icon blob (a theme icon name); when the package ships
    /// one, the emitter substitutes the pod-namespaced link name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_ref: Option<String>,
    /// The package's shipped icon, ingested into the store at install
    /// time and linked by the launcher emitter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<DesktopIcon>,
}

/// An icon blob in the content store plus its file extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIcon {
    pub sha256: String,
    pub ext: String,
}

/// The install-side metadata half of a [`PackageManifest`] — the
/// snap.yaml-derived claims a receiving peer needs to reconstruct the
/// install-time records without the payload's yaml (mirrored field by
/// field from the runtime's `InstalledPackage`, so manifests minted
/// before a field existed — and minimal ones — keep parsing).
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
    pub assembly: BTreeMap<String, AppAssembly>,
    /// Package-level confinement declaration (ADR-0016): `Some` =
    /// confined, `None` = unconfined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confined: Option<Confinement>,
    /// Per-app confinement overrides: app name → grants, only for apps
    /// whose `confined` differs from the package default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_confined: BTreeMap<String, Confinement>,
    /// Desktop-launcher metadata per GUI app (issue #7), parsed from
    /// the package's `.desktop` file at install time.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub desktops: BTreeMap<String, DesktopLauncher>,
    /// Payload font files: path under the payload's `usr/share/fonts`
    /// → sha256 (issue #29 cutover).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fonts: BTreeMap<String, String>,
    /// Service declarations (ADR-0032) recorded verbatim from the
    /// payload's snap.yaml: service name → decl.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, ServiceDecl>,
    /// Service name → sha256 of the service's command binary blob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_bins: BTreeMap<String, String>,
    /// The package's declared runtime requires (ADR-0018), recorded so
    /// a receiving peer knows the package needs the emit-time LD
    /// wrapper without re-reading a pool it does not have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
}

// ── The signed wire schema (issue #326 PR 4 down-move) ──

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

/// A signed, per-package, shareable manifest (ADR-0033 Decision 2):
/// what travels between peers, beside the store blobs it references.
/// The store's first per-package signed artifact — canonicalized and
/// signed with the same machinery as the image manifest
/// ([`crate::sign`]).
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
/// emptied (a signature never covers itself; the emptied field keeps
/// the bytes byte-stable — the same rule
/// [`crate::sign::eval_manifest_canonical_bytes`] applies to the eval
/// manifest and the image one to theirs).
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

/// Host GNU triplet for minted `target` fields — the best target record
/// available at mint time (the pod store keeps no per-package build
/// triplet; payloads are host-arch glibc binaries).
pub fn host_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

/// The publishing-host identity `/info` and `index.json` carry: the
/// kernel hostname, read at `/proc/sys/kernel/hostname` (std fs, no new
/// deps). `unknown` when unreadable or empty — a label, never trust
/// state. `serve` prefers the configured `node.name` over this.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

// ── Trust-boundary validation of manifest contents ──

/// The sha256 discipline: exactly 64 lowercase hex chars — the same
/// content-address rule the store and the wire grammar use; anything
/// else is refused before it can reach a path.
pub fn validate_sha256(file: &ManifestFile) -> miette::Result<()> {
    let malformed = file.sha256.len() != 64
        || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || file.sha256.bytes().any(|b| b.is_ascii_uppercase());
    if malformed {
        bail!(
            "manifest file '{}' carries malformed sha256 {:?} — expected 64 lowercase hex chars",
            file.path,
            file.sha256
        );
    }
    Ok(())
}

/// Boundary validation of a manifest's declared payload path: no
/// absolute paths, no `..` segments — a manifest is untrusted wire
/// input and its paths are only ever joined under the payload root by
/// the (future) install-from-inbox consumer.
pub fn validate_payload_path(file: &ManifestFile) -> miette::Result<()> {
    use std::path::Component;
    let unsafe_path = file.path.starts_with('/')
        || Path::new(&file.path)
            .components()
            .any(|c| c == Component::ParentDir);
    if unsafe_path {
        bail!(
            "manifest file carries an unsafe path {:?} — absolute paths and '..' \
             segments are refused",
            file.path
        );
    }
    Ok(())
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
        let services: BTreeMap<String, ServiceDecl> = serde_json::from_value(
            serde_json::json!({ "srv": { "command": "bin/srv", "daemon": "simple" } }),
        )
        .unwrap();
        let confined: Confinement = serde_json::from_value(serde_json::json!({})).unwrap();
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
        let root = Path::new("/srv/nau-state");
        assert_eq!(
            manifest_path(root, "hello"),
            PathBuf::from("/srv/nau-state/store/manifests/hello.json")
        );
    }

    #[test]
    fn sha_validation_demands_64_lowercase_hex() {
        let ok = ManifestFile {
            path: "ab".repeat(32),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_sha256(&ok).unwrap();
        for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
            let file = ManifestFile {
                path: bad.clone(),
                sha256: bad,
                executable: false,
            };
            assert!(validate_sha256(&file).is_err(), "{:?}", file.sha256);
        }
    }

    #[test]
    fn payload_path_validation_refuses_absolute_and_parent_segments() {
        let file = |path: &str| ManifestFile {
            path: path.to_string(),
            sha256: "ab".repeat(32),
            executable: false,
        };
        validate_payload_path(&file("usr/bin/hello")).unwrap();
        validate_payload_path(&file("ab".repeat(32).as_str())).unwrap();
        for bad in [
            "/etc/passwd",
            "../../etc/passwd",
            "usr/../../etc/passwd",
            "..",
        ] {
            let err = validate_payload_path(&file(bad)).expect_err(bad);
            assert!(err.to_string().contains(bad), "{err}");
        }
    }
}
