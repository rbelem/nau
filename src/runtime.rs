//! The on-device runtime's ROOT shim (issue #326 PR 7): the domain —
//! [`nau_runtime::runtime`]'s generations/content-store machinery and
//! [`nau_runtime::slot_recovery`] — moved into the `nau-runtime`
//! crate; this file re-exports it (the pull_peer glue-file precedent)
//! and keeps the TRUST half that stayed root: the ADR-0011
//! eval-manifest signature verify cluster (`verify_signatures`/
//! `_at`/`against_anchors` + the key-file helpers) and its
//! cosign/attest suite — chart-manifest + root-sign coupled; the
//! trust domain (nau-trust) is a later crate. `install_batch` takes
//! the gate as an injected verifier (the 9c loader-seam precedent);
//! root callers pass [`verify_signatures`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// The runtime domain: plain re-export so every pre-existing
// `crate::runtime::` path — pod_store ctors, the pod/secrets/doctor
// orchestrators, the oci shim, the commands — keeps resolving.
pub use nau_runtime::runtime::*;

// The default-path vocabulary moved DOWN into `nau_core::paths` (issue
// #326 PR 3, R4); re-exported for the same paths as before.
pub use nau_core::paths::{DEFAULT_EXTENSIONS_LINK_DIR, DEFAULT_STATE_DIR};

/// On-device trust anchor embedded at image build time (ADR-0011 step
/// (d)). Lives in `nau_core::paths` (issue #326 PR 4).
pub use nau_core::paths::DEVICE_ANCHOR;

// The install-record cluster lives in `nau_core::pkg_manifest` (PR 5
// down-move, amendment 8); re-exported.
pub use nau_core::pkg_manifest::{DesktopIcon, DesktopLauncher, Generation, InstalledPackage};

/// A channel-side manifest signature envelope (ADR-0011 step (d)).
/// Lives in `nau_core::sign` (PR 7, amendment 7's envelope clause).
pub use nau_core::sign::SignatureEnvelope;

// ── Signature verification (STAYS ROOT — the trust domain) ──

/// Verify a channel manifest's signatures (ADR-0011 step (d)) against
/// the on-device anchors. `Ok(None)` = unsigned (proceed with a note);
/// `Ok(Some(key_id))` = verified under that key; `Err` = signed but no
/// trusted signature verifies — fail closed.
pub fn verify_signatures(
    canonical: &[u8],
    signatures: &BTreeMap<String, serde_json::Value>,
) -> miette::Result<Option<String>> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let anchor = PathBuf::from(DEVICE_ANCHOR);
    let keys = crate::sign::keys_dir(&home);
    verify_signatures_at(canonical, signatures, &anchor, &keys)
}

pub fn verify_signatures_at(
    canonical: &[u8],
    signatures: &BTreeMap<String, serde_json::Value>,
    anchor: &Path,
    keys: &Path,
) -> miette::Result<Option<String>> {
    if signatures.is_empty() {
        return Ok(None);
    }
    // 0. ADR-0024 §4 revocation gate. The embedded revocation list lives
    // beside the device anchor (/etc/nau/revoked-keys); the operator
    // list lives under the keychain dir (~/.config/nau/keys/
    // revoked-keys). A signature under a revoked id is refused BEFORE any
    // anchor check, so "trusted once, revoked now" cannot be masked by a
    // dual-signed manifest that a still-trusted key also signed.
    let revoked = embedded_revoked_keys(anchor, keys)?;
    crate::sign::reject_revoked(signatures, &revoked)?;

    let verified = verify_against_anchors(canonical, signatures, anchor, keys)?;

    // Issue #56: the entry that verified may carry SLSA-lite provenance.
    // The signature and subject halves of the binding are enforced inside
    // sign::verify / verify_keychain; here, with the manifest in hand, the
    // attested materials must equal the manifest's declared inputs. A
    // body that does not parse as a manifest has no inventory to bind, so
    // the check is skipped for it.
    if let Some(key_id) = &verified {
        if let Some(entry) = signatures.get(key_id) {
            if let Ok(manifest) =
                serde_json::from_slice::<crate::manifest::ImageManifest>(canonical)
            {
                crate::sign::check_provenance(entry, &manifest.inputs)?;
            }
        }
    }
    Ok(verified)
}

/// The anchor walk behind [`verify_signatures_at`]: embedded trust set,
/// single-anchor fallback, then the operator keychain.
fn verify_against_anchors(
    canonical: &[u8],
    signatures: &BTreeMap<String, serde_json::Value>,
    anchor: &Path,
    keys: &Path,
) -> miette::Result<Option<String>> {
    // 1. The embedded device trust set (/etc/nau/trusted-keys/*.pub),
    //    plus the single-anchor fallback (/etc/nau/update-key.pub) for
    //    images built before the set shape existed.
    let embedded_chain = crate::sign::Keychain::load_dir(&trusted_keys_dir(anchor))?;
    for (key_id, public) in embedded_chain.entries_for_verify() {
        if crate::sign::verify(canonical, signatures, &to_hex(&public)).is_ok() {
            return Ok(Some(key_id));
        }
    }
    if let Ok(text) = std::fs::read_to_string(anchor) {
        if let Some(public_hex) = key_line(&text) {
            if crate::sign::verify(canonical, signatures, public_hex).is_ok() {
                return Ok(Some(key_id_of(public_hex)));
            }
        }
    }

    // 2. The operator keychain (~/.config/nau/keys/*.pub). The
    //    revocation gate ran above, so the closed-set verify is enough.
    let chain = crate::sign::Keychain::load_dir(keys)?;
    match crate::sign::verify_keychain(canonical, signatures, &chain) {
        Ok(key_id) => Ok(Some(key_id)),
        Err(e) => Err(miette::miette!(
            "manifest carries signatures but no trusted anchor verifies them \
             (anchor: {}, keychain: {}): {e}",
            anchor.display(),
            keys.display()
        )),
    }
}

// The embedded-key-set walk moved DOWN into `nau_core::sign` (issue
// #326 PR 4): the peer pull lane polices the same unioned revocation
// view. Re-exported so every `crate::runtime::` path keeps resolving.
pub use nau_core::sign::{embedded_revoked_keys, trusted_keys_dir};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// First non-comment, non-empty line of a two-line public key file.
fn key_line(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
}

fn key_id_of(public_hex: &str) -> String {
    public_hex.chars().take(16).collect()
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn unsigned_envelope_proceeds_with_none() {
        let sigs = BTreeMap::new();
        assert_eq!(
            verify_signatures_at(b"x", &sigs, Path::new("/nope"), Path::new("/nope")).unwrap(),
            None
        );
    }

    #[test]
    fn signed_without_anchors_fails_closed() {
        let mut sigs = BTreeMap::new();
        sigs.insert(
            "deadbeef00112233".to_string(),
            serde_json::Value::String("not-a-real-signature".into()),
        );
        let err =
            verify_signatures_at(b"x", &sigs, Path::new("/nope"), Path::new("/nope")).unwrap_err();
        assert!(
            format!("{err:#}").contains("no trusted anchor verifies"),
            "fail-closed error must be named: {err:#}"
        );
    }

    #[test]
    fn signed_manifest_verifies_under_the_keychain() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        crate::sign::install_public_key(&kp, &keys).unwrap();
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &kp).unwrap();
        let canonical = crate::sign::eval_manifest_canonical_bytes(&manifest).unwrap();
        let verified = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            Path::new("/definitely/not/here"),
            &keys,
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));
    }

    #[test]
    fn attested_manifest_verifies_and_divergent_materials_fail() {
        let home = tempfile::tempdir().unwrap();
        let keys = home.path().join("keys");
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        crate::sign::install_public_key(&kp, &keys).unwrap();

        // A manifest with one pinned github input.
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
        let mut manifest = crate::manifest::build_manifest(
            &crate::lua::Outputs::new(),
            &std::collections::HashMap::new(),
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
        .unwrap();

        // The honest attestation verifies on the device path.
        crate::sign::attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", false)
            .unwrap();
        let canonical = crate::sign::eval_manifest_canonical_bytes(&manifest).unwrap();
        let verified = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            Path::new("/definitely/not/here"),
            &keys,
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));

        // A materials claim that diverges from the manifest's own inputs:
        // the signature is valid (it covers body ++ provenance) and the
        // subject digest binds the body — only the materials lie. The
        // device path must refuse the attestation by name.
        let mut lying = crate::sign::provenance_for_manifest(
            "9.9.9",
            "amd64",
            "latest/stable",
            false,
            &manifest,
            &canonical,
        )
        .unwrap();
        lying.materials.insert(
            "extra".into(),
            crate::manifest::ManifestInput {
                url: "github:evil/injected/main".into(),
                revision: Some("deadbeef".into()),
                sha256: None,
                local: false,
            },
        );
        let mut forged = manifest.clone();
        crate::sign::sign_attested(&mut forged, &kp, &lying).unwrap();
        let canonical_forged = crate::sign::eval_manifest_canonical_bytes(&forged).unwrap();
        let err = verify_signatures_at(
            &canonical_forged,
            &forged.signatures,
            Path::new("/definitely/not/here"),
            &keys,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("materials do not match the manifest inputs"),
            "divergent materials must be named: {err:#}"
        );
    }

    /// A minimal manifest signed by `kp`.
    fn manifest_signed_by(
        kp: &crate::sign::KeyPair,
    ) -> (Vec<u8>, BTreeMap<String, serde_json::Value>) {
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, kp).unwrap();
        let canonical = crate::sign::eval_manifest_canonical_bytes(&manifest).unwrap();
        (canonical, manifest.signatures)
    }

    #[test]
    fn device_trust_set_accepts_an_embedded_anchor() {
        let home = tempfile::tempdir().unwrap();
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        // The image-embedded shape: anchor dir beside update-key.pub.
        let anchor_dir = home.path().join("etc/nau");
        crate::sign::install_public_key(&kp, &anchor_dir.join("trusted-keys")).unwrap();
        let (canonical, sigs) = manifest_signed_by(&kp);
        let verified = verify_signatures_at(
            &canonical,
            &sigs,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));
    }

    #[test]
    fn device_revocation_list_refuses_a_revoked_signer() {
        let home = tempfile::tempdir().unwrap();
        let revoked = crate::sign::create_secret_key(home.path()).unwrap();
        let anchor_dir = home.path().join("etc/nau");
        crate::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
        // The device carries the revocation list beside the anchor.
        std::fs::write(
            anchor_dir.join("revoked-keys"),
            format!("{}\n", revoked.key_id()),
        )
        .unwrap();

        let (canonical, sigs) = manifest_signed_by(&revoked);
        let err = verify_signatures_at(
            &canonical,
            &sigs,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&revoked.key_id()),
            "revoked signer refused by id: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("REVOKED"),
            "refusal is explicit: {err:#}"
        );
    }

    #[test]
    fn device_revocation_refuses_even_when_a_trusted_key_also_signed() {
        let home = tempfile::tempdir().unwrap();
        let revoked = crate::sign::create_secret_key(home.path()).unwrap();
        let trusted = crate::sign::create_secret_key(&home.path().join("other")).unwrap();
        let anchor_dir = home.path().join("etc/nau");
        crate::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
        crate::sign::install_public_key(&trusted, &anchor_dir.join("trusted-keys")).unwrap();
        std::fs::write(
            anchor_dir.join("revoked-keys"),
            format!("{}\n", revoked.key_id()),
        )
        .unwrap();

        // Dual-signed: revoked + trusted. The trusted signature alone
        // would verify — revocation must still refuse.
        let mut manifest = crate::manifest::ImageManifest {
            manifest_version: crate::manifest::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &revoked).unwrap();
        crate::sign::cosign(&mut manifest, &trusted).unwrap();
        let canonical = crate::sign::eval_manifest_canonical_bytes(&manifest).unwrap();
        let err = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            &anchor_dir.join("update-key.pub"),
            Path::new("/definitely/not/here"),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&revoked.key_id()),
            "revoked signer wins over the trusted co-signer: {err:#}"
        );
    }
}
