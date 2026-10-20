//! The tree's shape after one export: index rows, signed manifests,
//! and the deduped blob set.

use super::*;

#[test]
fn tree_shape_index_manifests_and_deduped_blobs() {
    let fx = fabricate();
    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

    // index.json parses and lists every exportable package.
    let index: IndexJson =
        serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap()).unwrap();
    assert!(!index.name.is_empty());
    let rows: Vec<(&str, &str, u32)> = index
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.version.as_str(), p.revision))
        .collect();
    assert_eq!(
        rows,
        vec![("alpha", "1.0", 4), ("beta", "2.1", 9), ("gamma", "0.4", 3),]
    );

    // Generation manifests verify under the operator key; the
    // verbatim inbox manifest under its original peer key.
    let operator = fx.kp.public_hex();
    let peer = inbox_kp(9).public_hex();
    for (name, key) in [("alpha", &operator), ("beta", &operator), ("gamma", &peer)] {
        let manifest: PackageManifest = serde_json::from_str(
            &std::fs::read_to_string(fx.out.join("manifests").join(format!("{name}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.name, name);
        nau_core::pkg_manifest::verify(&manifest, key)
            .unwrap_or_else(|e| panic!("{name} must verify: {e}"));
    }

    // Blobs: exactly the union set — the shared blob copied ONCE —
    // and every file's bytes hash to its content address.
    let mut blobs: Vec<String> = std::fs::read_dir(fx.out.join("blobs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    blobs.sort();
    let mut expected = vec![h(SHARED), h(ALPHA_ONLY), h(BETA_ONLY), h(GAMMA_BLOB)];
    expected.sort();
    assert_eq!(blobs, expected, "shared blob must be copied exactly once");

    for name in &blobs {
        let bytes = std::fs::read(fx.out.join("blobs").join(name)).unwrap();
        let digest = sha2::Sha256::digest(&bytes);
        assert_eq!(format!("{digest:x}"), *name, "blob {name} bytes mismatch");
    }
}
