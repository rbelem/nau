//! Re-export behavior against an existing out directory: idempotence,
//! owned-tree pruning, and the foreign directory that is only claimed.

use super::*;
use crate::export::ownership::MARKER_VERSION;

#[test]
fn run_is_idempotent_and_never_clears_out() {
    let fx = fabricate();
    let keep = fx.out.join("operator-file.txt");
    std::fs::create_dir_all(&fx.out).unwrap();
    std::fs::write(&keep, b"mine").unwrap();

    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

    assert_eq!(std::fs::read(&keep).unwrap(), b"mine");
    assert_eq!(
        std::fs::read(fx.out.join("blobs").join(h(SHARED))).unwrap(),
        b"shared-blob-bytes"
    );
}

/// An owned tree (marker present) prunes on re-export: a package
/// removed from the store loses its manifest and its no-longer-
/// shared blobs; survivors stay byte-intact (ADR-0033 Decision 10).
#[test]
fn owned_reexport_prunes_removed_packages() {
    let fx = fabricate();
    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.out.join(MARKER_FILE))
            .unwrap()
            .trim(),
        MARKER_VERSION,
        "every export writes the ownership marker"
    );

    // beta leaves the store: generation 1 is rewritten with alpha.
    let gen_dir = nau_core::generation_view::generation_dir(&fx.state_root, 1);
    let mut gen: nau_core::pkg_manifest::Generation =
        serde_json::from_str(&std::fs::read_to_string(gen_dir.join("manifest.json")).unwrap())
            .unwrap();
    gen.packages.remove("beta");
    std::fs::write(
        gen_dir.join("manifest.json"),
        serde_json::to_vec(&gen).unwrap(),
    )
    .unwrap();

    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();

    assert!(
        !fx.out.join("manifests").join("beta.json").exists(),
        "stale manifest pruned"
    );
    assert!(
        !fx.out.join("blobs").join(h(BETA_ONLY)).exists(),
        "stale blob pruned"
    );
    assert!(
        fx.out.join("manifests").join("alpha.json").exists()
            && fx.out.join("manifests").join("gamma.json").exists(),
        "surviving manifests intact"
    );
    for keep in [h(SHARED), h(ALPHA_ONLY), h(GAMMA_BLOB)] {
        assert!(
            fx.out.join("blobs").join(&keep).exists(),
            "surviving blob {keep} intact"
        );
    }
    let index: IndexJson =
        serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap()).unwrap();
    assert!(index.packages.iter().all(|p| p.name != "beta"));
}

/// A directory without the marker is foreign: re-export accumulates
/// and deletes nothing (a stray manifest and blob pre-seeded beside
/// the operator's file survive) — and it is claimed by the marker,
/// so the NEXT export prunes those stragglers.
#[test]
fn foreign_directory_accumulates_then_gets_claimed() {
    let fx = fabricate();
    std::fs::create_dir_all(fx.out.join("manifests")).unwrap();
    std::fs::create_dir_all(fx.out.join("blobs")).unwrap();
    let foreign = fx.out.join("operator-file.txt");
    std::fs::write(&foreign, b"mine").unwrap();
    let stray_manifest = fx.out.join("manifests").join("ghost.json");
    let stray_blob = fx.out.join("blobs").join("0".repeat(64));
    std::fs::write(&stray_manifest, b"{}").unwrap();
    std::fs::write(&stray_blob, b"stray").unwrap();

    // First export: no marker found → zero deletions.
    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
    assert_eq!(std::fs::read(&foreign).unwrap(), b"mine");
    assert!(stray_manifest.exists(), "marker-less dir: no deletions");
    assert!(stray_blob.exists(), "marker-less dir: no deletions");

    // Claimed by the first export: the next one prunes the strays.
    run_at(&fx.out, &fx.state_root, &fx.blobs, fx._home.path(), None).unwrap();
    assert!(!stray_manifest.exists(), "owned now: stale manifest pruned");
    assert!(!stray_blob.exists(), "owned now: stale blob pruned");
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"mine",
        "out-root files are never touched"
    );
}
