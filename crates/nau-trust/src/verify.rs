//! The on-device verify cluster (ADR-0011 step (d), issue #326 PR 8):
//! the trust WALK a device performs over a channel manifest's
//! signatures — revocation gate first (ADR-0024 §4), then the
//! embedded-anchor / single-anchor-fallback / operator-keychain
//! ladder. Consumed via INJECTION (`install_batch`'s `verify`
//! parameter — the 9c loader-seam precedent); the root crate passes
//! [`verify_signatures`]. The SLSA-lite provenance binding check
//! rides the walk (issue #56): a verifying entry's attested
//! materials must equal the manifest's declared inputs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nau_core::paths::DEVICE_ANCHOR;
// The keychain core: the cluster was written against the root sign.rs's
// full re-export scope — mirrored here as a glob (check_provenance is
// this crate's own `sign` module's).
use crate::sign::check_provenance;
use nau_core::sign::*;

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
    let keys = nau_core::sign::keys_dir(&home);
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
    nau_core::sign::reject_revoked(signatures, &revoked)?;

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
                serde_json::from_slice::<nau_core::manifest_ir::ImageManifest>(canonical)
            {
                check_provenance(entry, &manifest.inputs)?;
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
    let embedded_chain = nau_core::sign::Keychain::load_dir(&trusted_keys_dir(anchor))?;
    for (key_id, public) in embedded_chain.entries_for_verify() {
        if nau_core::sign::verify(canonical, signatures, &to_hex(&public)).is_ok() {
            return Ok(Some(key_id));
        }
    }
    if let Ok(text) = std::fs::read_to_string(anchor) {
        if let Some(public_hex) = key_line(&text) {
            if nau_core::sign::verify(canonical, signatures, public_hex).is_ok() {
                return Ok(Some(key_id_of(public_hex)));
            }
        }
    }

    // 2. The operator keychain (~/.config/nau/keys/*.pub). The
    //    revocation gate ran above, so the closed-set verify is enough.
    let chain = nau_core::sign::Keychain::load_dir(keys)?;
    match nau_core::sign::verify_keychain(canonical, signatures, &chain) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let kp = nau_core::sign::create_secret_key(home.path()).unwrap();
        nau_core::sign::install_public_key(&kp, &keys).unwrap();
        let mut manifest = nau_core::manifest_ir::ImageManifest {
            manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &kp).unwrap();
        let canonical = nau_core::manifest_ir::eval_manifest_canonical_bytes(&manifest).unwrap();
        let verified = verify_signatures_at(
            &canonical,
            &manifest.signatures,
            Path::new("/definitely/not/here"),
            &keys,
        )
        .unwrap();
        assert_eq!(verified.as_deref(), Some(kp.key_id().as_str()));
    }

    /// A minimal manifest signed by `kp`.
    fn manifest_signed_by(
        kp: &nau_core::sign::KeyPair,
    ) -> (Vec<u8>, BTreeMap<String, serde_json::Value>) {
        let mut manifest = nau_core::manifest_ir::ImageManifest {
            manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, kp).unwrap();
        let canonical = nau_core::manifest_ir::eval_manifest_canonical_bytes(&manifest).unwrap();
        (canonical, manifest.signatures)
    }

    #[test]
    fn device_trust_set_accepts_an_embedded_anchor() {
        let home = tempfile::tempdir().unwrap();
        let kp = nau_core::sign::create_secret_key(home.path()).unwrap();
        // The image-embedded shape: anchor dir beside update-key.pub.
        let anchor_dir = home.path().join("etc/nau");
        nau_core::sign::install_public_key(&kp, &anchor_dir.join("trusted-keys")).unwrap();
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
        let revoked = nau_core::sign::create_secret_key(home.path()).unwrap();
        let anchor_dir = home.path().join("etc/nau");
        nau_core::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
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
        let revoked = nau_core::sign::create_secret_key(home.path()).unwrap();
        let trusted = nau_core::sign::create_secret_key(&home.path().join("other")).unwrap();
        let anchor_dir = home.path().join("etc/nau");
        nau_core::sign::install_public_key(&revoked, &anchor_dir.join("trusted-keys")).unwrap();
        nau_core::sign::install_public_key(&trusted, &anchor_dir.join("trusted-keys")).unwrap();
        std::fs::write(
            anchor_dir.join("revoked-keys"),
            format!("{}\n", revoked.key_id()),
        )
        .unwrap();

        // Dual-signed: revoked + trusted. The trusted signature alone
        // would verify — revocation must still refuse.
        let mut manifest = nau_core::manifest_ir::ImageManifest {
            manifest_version: nau_core::manifest_ir::MANIFEST_VERSION,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            images: BTreeMap::new(),
            signatures: BTreeMap::new(),
        };
        crate::sign::cosign(&mut manifest, &revoked).unwrap();
        crate::sign::cosign(&mut manifest, &trusted).unwrap();
        let canonical = nau_core::manifest_ir::eval_manifest_canonical_bytes(&manifest).unwrap();
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
