//! The mint's install-metadata travel: what the generation record
//! carries must appear in the signed manifest.

use super::*;

/// The minted manifest carries the generation record's install
/// metadata (Decision 2: metadata must travel) — spot-check via the
/// apps map and the record's `requires`.
#[test]
fn minted_manifest_travels_install_metadata() {
    let shared = h(SHARED);
    let bin_hash = h(b"hello-bin-bytes");
    let mut apps = BTreeMap::new();
    apps.insert("hello".to_string(), bin_hash.clone());
    let mut rec = record("alpha", "1.0", 4, vec![shared, bin_hash.clone()]);
    rec.apps = apps.clone();
    rec.requires = vec!["libc6".into()];

    let manifest = nau_core::pkg_manifest::mint_manifest(&rec);
    assert_eq!(manifest.install.apps, apps);
    assert_eq!(manifest.install.requires, vec!["libc6".to_string()]);
    // The command binary is the one file marked executable.
    let exe: Vec<&ManifestFile> = manifest.files.iter().filter(|f| f.executable).collect();
    assert_eq!(exe.len(), 1);
    assert_eq!(exe[0].sha256, bin_hash);
}
