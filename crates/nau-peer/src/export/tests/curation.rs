//! The per-mission mirror (#275): the pin set, what a curated export
//! writes, and byte-identical re-exports.

use super::*;
use nau_core::manifest_ir::{ImageDeclaration, KernelEntry};
use nau_core::snap_types::SnapRef;

/// A mission declaration in the image-module test shape: base +
/// kernel + one extra snap. The pin set export curates from — the
/// same `image()` schema `nau image` consumes, no new format.
fn mission() -> ImageDeclaration {
    ImageDeclaration {
        name: "workstation".into(),
        version: "1.0".into(),
        base: SnapRef {
            name: "alpha".into(),
            revision: None,
            sha3_384: None,
        },
        kernel: Some(KernelEntry {
            snap: SnapRef {
                name: "beta".into(),
                revision: None,
                sha3_384: None,
            },
            params: vec![],
            modules: vec![],
            modprobe_config: None,
            channel: None,
        }),
        gadget: None,
        gadget_channel: None,
        extra_snaps: vec![SnapRef {
            name: "gamma".into(),
            revision: None,
            sha3_384: None,
        }],
        bootloader: None,
        disk: None,
        sysctl: vec![],
        update_source: None,
        files: vec![],
        boot_health_exec: None,
    }
}

fn set(names: &[&str]) -> Curation {
    names.iter().map(|n| n.to_string()).collect()
}

/// Recursive map of every file under `dir`: relative path → bytes.
/// The byte-for-byte comparison the determinism test asserts on.
fn tree_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                files.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(dir, dir, &mut files);
    files
}

#[test]
fn mission_curation_collects_the_pinned_names() {
    let curation = mission_curation(&mission());
    assert_eq!(
        curation,
        set(&["alpha", "beta", "gamma"]),
        "base + kernel + declared snaps, set-deduped"
    );
}

/// A curated export writes ONLY the pinned packages: index rows,
/// manifests, and blobs exactly the pin set — the unpinned
/// generation packages and the staged inbox manifest never appear.
#[test]
fn curated_export_writes_only_the_pinned_pool() {
    let fx = fabricate();
    let curation = set(&["alpha"]);
    run_at(
        &fx.out,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap();

    let index: IndexJson =
        serde_json::from_str(&std::fs::read_to_string(fx.out.join("index.json")).unwrap()).unwrap();
    let rows: Vec<&str> = index.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(rows, vec!["alpha"], "index carries exactly the pins");

    let manifests: Vec<String> = std::fs::read_dir(fx.out.join("manifests"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(manifests, vec!["alpha.json"], "unpinned + staged: absent");

    let mut blobs: Vec<String> = std::fs::read_dir(fx.out.join("blobs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    // read_dir order belongs to the FILESYSTEM, not to the exporter: a
    // tmpfs hands back creation order, ext4 a per-instance hash seed,
    // btrfs yet another. The exporter wrote both blobs deterministically
    // and the filesystem may still list them either way, so the listing
    // has to be sorted too — otherwise this assertion passes or fails on
    // whichever disk the test happens to land on (it failed on CI run
    // 39366545411, tmpfs order, and passed twenty runs on btrfs).
    blobs.sort();
    let mut expected = vec![h(SHARED), h(ALPHA_ONLY)];
    expected.sort();
    assert_eq!(blobs, expected, "exactly the pinned package's blobs");
}

/// A pin the pool does not hold fails the export BEFORE anything is
/// written — a mirror missing a mission's pinned package would hand
/// its users an unverifiable tree.
#[test]
fn curated_export_missing_pin_fails_closed_before_writing() {
    let fx = fabricate();
    let curation = set(&["alpha", "ghost"]);
    let err = run_at(
        &fx.out,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("ghost"), "names the missing pin: {msg}");
    assert!(
        msg.contains("missing pinned package"),
        "names the rule: {msg}"
    );
    assert!(
        !fx.out.join("index.json").exists(),
        "no tree may be written for unresolved pins"
    );
    assert!(
        !fx.out.join("manifests").join("alpha.json").exists(),
        "nothing copied for unresolved pins"
    );
}

#[test]
fn empty_curation_is_an_error() {
    let fx = fabricate();
    let curation = Curation::new();
    let err = run_at(
        &fx.out,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("pins no packages"), "names the rule: {msg}");
}

/// Re-export of the same pool + mission is byte-identical: two
/// fresh exports AND a re-export into an already-owned tree produce
/// the same bytes everywhere (BTreeMap order, struct-order JSON,
/// deterministic ed25519).
#[test]
fn curated_reexport_is_byte_identical() {
    let fx = fabricate();
    let curation = set(&["alpha"]);
    let out_b = fx.out.parent().unwrap().join("tree-b");

    run_at(
        &fx.out,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap();
    run_at(
        &out_b,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap();
    assert_eq!(
        tree_bytes(&fx.out),
        tree_bytes(&out_b),
        "two fresh exports of one pool+mission: identical bytes"
    );

    // Re-export into the owned tree: still identical (pruning
    // rewrites nothing that survives).
    run_at(
        &fx.out,
        &fx.state_root,
        &fx.blobs,
        fx._home.path(),
        Some(&curation),
    )
    .unwrap();
    assert_eq!(
        tree_bytes(&fx.out),
        tree_bytes(&out_b),
        "re-export into an owned tree: identical bytes"
    );
}
