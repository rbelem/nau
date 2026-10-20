//! Fail-closed paths: a bad staged hash, a missing store blob, an
//! empty store. Each must name what is wrong and write nothing.

use super::*;

/// A staged inbox manifest carrying a malformed blob address is
/// refused BEFORE the address becomes a store path — trust-
/// boundary validation on export's verbatim-inbox lane.
#[test]
fn export_refuses_a_staged_manifest_with_malformed_blob_hashes() {
    let fx = fabricate();
    let inbox_path = nau_core::pkg_manifest::manifest_path(&fx.state_root, "gamma");
    let mut gamma: PackageManifest =
        serde_json::from_str(&std::fs::read_to_string(&inbox_path).unwrap()).unwrap();
    gamma.files[0].sha256 = "../../etc/passwd".to_string();
    std::fs::write(&inbox_path, serde_json::to_vec(&gamma).unwrap()).unwrap();

    let err = run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("64 lowercase hex"), "names the rule: {msg}");
    assert!(msg.contains("gamma"), "names the package: {msg}");
    assert!(
        !fx.out.join("manifests").join("gamma.json").exists(),
        "nothing copied for a malformed staged manifest"
    );
}

#[test]
fn missing_blob_names_package_and_hash() {
    let fx = fabricate();
    let alpha_hash = h(ALPHA_ONLY);
    std::fs::remove_file(fx.blobs.blob_path(&alpha_hash)).unwrap();

    let err = run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("alpha"), "error must name the package: {msg}");
    assert!(msg.contains(&alpha_hash), "error must name the hash: {msg}");
}

#[test]
fn empty_store_is_a_clear_error_not_an_empty_tree() {
    let state = tempfile::tempdir().unwrap();
    let blobs = BlobStore::new(state.path().join("store"));
    let home = tempfile::tempdir().unwrap();
    let out = state.path().join("tree");

    let err = run_at(&out, state.path(), &blobs, home.path(), None).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("empty"), "error must say empty: {msg}");
    assert!(
        !out.join("index.json").exists(),
        "no tree may be written for an empty store"
    );
}
