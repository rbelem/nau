//! The eval-manifest attestation × device-verify cluster (root-side:
//! the flows ride chart's `build_manifest` and the trust verify
//! cluster). Dissolved out of the src/runtime.rs and src/sign.rs shims
//! when their re-exports went away (#326 finish).
//!
//! - The honest attestation verifies on the device path
//!   ([`nau_trust::verify`]).
//! - A materials claim that diverges from the manifest's own inputs is
//!   refused BY NAME: the signature is valid (it covers body ++
//!   provenance) and the subject digest binds the body — only the
//!   materials lie.

use std::collections::HashMap;
use std::path::Path;

use nau_chart::lua::Outputs;
use nau_chart::manifest::build_manifest;
use nau_core::lock::{InputLockEntry, LockFile};
use nau_core::manifest_ir::{eval_manifest_canonical_bytes, ManifestInput};
use nau_core::sign::{create_secret_key, install_public_key};
use nau_core::snap_types::PackageInput;
use nau_trust::sign::{attest_eval, provenance_for_manifest, sign_attested};
use nau_trust::verify::verify_signatures_at;

#[test]
fn attested_manifest_verifies_and_divergent_materials_fail() {
    let home = tempfile::tempdir().unwrap();
    let keys = home.path().join("keys");
    let kp = create_secret_key(home.path()).unwrap();
    install_public_key(&kp, &keys).unwrap();

    // A manifest with one pinned github input.
    let declared = HashMap::from([(
        "pkgs".to_string(),
        PackageInput {
            url: "github:owner/repo/main".into(),
            submodules: None,
        },
    )]);
    let mut lockfile = LockFile {
        version: 1,
        sources: HashMap::new(),
        snaps: HashMap::new(),
        inputs: HashMap::new(),
        packages: HashMap::new(),
        build_deps: HashMap::new(),
    };
    lockfile.inputs.insert(
        "pkgs".into(),
        InputLockEntry {
            revision: Some("c0ffee".into()),
            sha256: Some("beef".into()),
            local: false,
            submodules: None,
        },
    );
    let mut manifest = build_manifest(
        &Outputs::new(),
        &HashMap::new(),
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();

    // The honest attestation verifies on the device path.
    attest_eval(&mut manifest, &kp, "9.9.9", "amd64", "latest/stable", false).unwrap();
    let canonical = eval_manifest_canonical_bytes(&manifest).unwrap();
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
    let mut lying = provenance_for_manifest(
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
        ManifestInput {
            url: "github:evil/injected/main".into(),
            revision: Some("deadbeef".into()),
            sha256: None,
            local: false,
        },
    );
    let mut forged = manifest.clone();
    sign_attested(&mut forged, &kp, &lying).unwrap();
    let canonical_forged = eval_manifest_canonical_bytes(&forged).unwrap();
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
