//! The on-device runtime's ROOT shim (issue #326 PR 7, amended PR 8):
//! the domain lives in [`nau_runtime::runtime`] and
//! [`nau_runtime::slot_recovery`]; the TRUST half (the verify cluster +
//! its suite) moved into `nau-trust` ([`nau_trust::verify`]) — this
//! file re-exports both, so every pre-existing `crate::runtime::` path
//! (the injected verifier at the commands' install sites,
//! byte-identical) keeps resolving.

pub use nau_runtime::runtime::*;
pub use nau_trust::verify::{verify_signatures, verify_signatures_at};

// The default-path vocabulary lives in `nau_core::paths` (PR 3);
// re-exported for the same paths as before.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
}
