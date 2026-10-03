//! A2 gate test, first unit: packing-layer determinism.
//!
//! The forensics behind ADR-0017 Decision 4a found hermes-agent's stable
//! tag producing ALTERNATING payload digests across four syncs while
//! `meta_digest` stayed constant — inputs stable, build output bistable.
//! Candidate causes were "tempdir vs mksquashfs time". These arms
//! EXONERATE the packing layer: mksquashfs (devbox tools) packs
//! byte-identical payloads across fresh mtimes, creation-order swaps,
//! and a 4000-file parallel-compression tree, with SOURCE_DATE_EPOCH
//! reaching the child. The bistability therefore enters in the BUILD
//! phase upstream of packing (run_build environment paths, patchelf/
//! wrapper writes, closure mounts) — reproducing it needs a real
//! package build with network sources, tracked as the follow-up unit.
//! The follow-up unit has landed (c55bcef fixed the serialization
//! order; payload_reproducibility_build.rs pins the full pipeline), so
//! the output-compare paths (refresh churn guard, rollback trust,
//! ADR-0033/ADR-0043) are load-bearing again; these gates keep the
//! pack layer honest under that trust (the rollback-chain gate is
//! `refresh_diverge_then_rollback_restores_prior_generation` in
//! tests/pod_refresh.rs).

use std::path::Path;
use std::process::Command;

use nau_build::snap::{build_snap, StagePolicy};
use nau_core::snap_types::SnapMeta;
fn real_mksquashfs_available() -> bool {
    Command::new("which")
        .arg("mksquashfs")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A stage with stable CONTENT: two files and a subdir, byte-identical
/// across calls. `fresh_mtimes` controls the one deliberately varying
/// input: the stage files' timestamps (a fresh build's stage always has
/// fresh mtimes; a reproducible pack must not care).
fn write_stage(stage: &Path, fresh_mtimes: bool) {
    std::fs::create_dir_all(stage.join("bin")).unwrap();
    std::fs::write(stage.join("bin/tool"), b"#!/bin/sh\necho stable\n").unwrap();
    std::fs::write(stage.join("README"), b"stable content\n").unwrap();
    std::fs::create_dir_all(stage.join("share/doc")).unwrap();
    std::fs::write(stage.join("share/doc/note.txt"), b"doc bytes\n").unwrap();
    if !fresh_mtimes {
        // `touch -d` keeps this dep-free: the gate env carries coreutils.
        for path in [
            stage.join("bin/tool"),
            stage.join("README"),
            stage.join("share/doc/note.txt"),
            stage.join("bin"),
            stage.join("share"),
            stage.join("share/doc"),
        ] {
            let status = Command::new("touch")
                .args(["-d", "@946684800"])
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success(), "touch failed on {}", path.display());
        }
    }
}

fn trivial_meta() -> SnapMeta {
    // Mirror of the pod.rs unit-test fixture: SnapMeta has no Default and
    // is Serialize-only, so enumerate the fields.
    SnapMeta {
        name: "repro".into(),
        version: "1.0".into(),
        summary: None,
        description: Some("same-tree-twice reproducibility fixture".into()),
        license: None,
        source: None,
        sources: None,
        build: None,
        parts: None,
        architectures: None,
        grade: "stable".into(),
        confinement: "strict".into(),
        type_: None,
        adopt_info: None,
        version_adopted: false,
        icon_source: None,
        icon: None,
        compression: None,
        compression_level: None,
        environment: None,
        layout: None,
        hooks: None,
        plugs: None,
        slots: None,
        aliases: vec![],
        requires: vec![],
        build_deps: vec![],
        leaks_ok: vec![],
        target: None,
        toolchain: None,
        inputs: None,
        confined: None,
        apps: std::collections::BTreeMap::new(),
        services: std::collections::BTreeMap::new(),
        deps: None,
        floating: false,
        definition_dir: None,
    }
}

fn build_once(fresh_mtimes: bool) -> String {
    let meta = trivial_meta();
    let work = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let stage = work.path().join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    write_stage(&stage, fresh_mtimes);
    let result = build_snap(
        &meta,
        &stage,
        out.path(),
        "x86_64",
        StagePolicy::Default,
        None,
        None,
        None,
        None,
        false,
        None,
    )
    .unwrap();
    let payload = out.path().join(&result.snap_filename);
    let digest = sha3_384_hex(&payload);
    // Keep both payloads around for a byte-diff when the assertion fires.
    let keep = std::env::temp_dir().join(format!("nau-a2-{}-{}", fresh_mtimes, std::process::id()));
    let _ = std::fs::remove_dir_all(&keep);
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::copy(&payload, keep.join(&result.snap_filename)).unwrap();
    digest
}

fn sha3_384_hex(path: &Path) -> String {
    use sha2::Digest;
    let bytes = std::fs::read(path).unwrap();
    format!("{:x}", sha3::Sha3_384::digest(&bytes))
}

/// The production condition: fresh stage mtimes on every build (a real
/// build's stage is written minutes apart). Identical CONTENT must pack
/// to identical bytes regardless.
#[test]
fn same_tree_twice_packs_identical_payloads_with_fresh_mtimes() {
    if !real_mksquashfs_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }
    let a = build_once(true);
    let b = build_once(true);
    assert_eq!(
        a, b,
        "fresh-mtime builds diverged — packing is not reproducible"
    );
}

/// The isolation arm: epoch-clamped stage mtimes. If this passes while
/// the fresh-mtime arm fails, the cause is timestamp handling (SDE not
/// reaching mksquashfs or being ignored); if both fail, the cause is
/// order/mkfs-time/path leakage.
#[test]
fn same_tree_twice_packs_identical_payloads_with_fixed_mtimes() {
    if !real_mksquashfs_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }
    let a = build_once(false);
    let b = build_once(false);
    assert_eq!(
        a, b,
        "fixed-mtime builds diverged — cause is not stage mtimes"
    );
}

/// The order arm: IDENTICAL content created in a DIFFERENT directory
/// order between the two builds. Real builds write their stage through
/// parallel resolvers, so creation order varies run to run; if readdir
/// order leaks into the squashfs bytes, this arm diverges while the
/// same-order arms pass — pinning the bistability on tree-order
/// sensitivity, not on content.
#[test]
fn same_tree_different_creation_order_packs_identically() {
    if !real_mksquashfs_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();

    // Build A: alphabetical-ish creation order.
    let stage_a = work.path().join("stage-a");
    std::fs::create_dir_all(stage_a.join("bin")).unwrap();
    std::fs::create_dir_all(stage_a.join("share/doc")).unwrap();
    std::fs::write(stage_a.join("README"), b"stable content\n").unwrap();
    std::fs::write(stage_a.join("bin/tool"), b"#!/bin/sh\necho stable\n").unwrap();
    std::fs::write(stage_a.join("share/doc/note.txt"), b"doc bytes\n").unwrap();

    // Build B: reversed creation order, same bytes, same names.
    let stage_b = work.path().join("stage-b");
    std::fs::create_dir_all(stage_b.join("share/doc")).unwrap();
    std::fs::create_dir_all(stage_b.join("bin")).unwrap();
    std::fs::write(stage_b.join("share/doc/note.txt"), b"doc bytes\n").unwrap();
    std::fs::write(stage_b.join("bin/tool"), b"#!/bin/sh\necho stable\n").unwrap();
    std::fs::write(stage_b.join("README"), b"stable content\n").unwrap();

    let mut digests = Vec::new();
    for stage in [stage_a, stage_b] {
        let result = build_snap(
            &trivial_meta(),
            &stage,
            out.path(),
            "x86_64",
            StagePolicy::Default,
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        let payload = out.path().join(&result.snap_filename);
        digests.push(sha3_384_hex(&payload));
    }
    assert_eq!(
        digests[0], digests[1],
        "creation order leaked into payload bytes — the squashfs pack is tree-order sensitive"
    );
}

/// The scale arm: a LARGE tree (thousands of files, varied sizes) packed
/// twice from the identical stage. Small trees never leave mksquashfs's
/// deterministic paths; multi-fragment packs engage the parallel reader
/// machinery, and a reader race would reproduce exactly the bistability
/// the gen-109..112 forensics measured on deepsec-sized payloads
/// (identical inputs, alternating digests).
#[test]
fn same_large_tree_twice_packs_identically() {
    if !real_mksquashfs_available() {
        eprintln!("skipping: mksquashfs unavailable");
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let mut digests = Vec::new();
    for run in 0..2 {
        let stage = work.path().join(format!("stage-{run}"));
        std::fs::create_dir_all(stage.join("lib")).unwrap();
        std::fs::create_dir_all(stage.join("share/man")).unwrap();
        for i in 0..4000u32 {
            let dir = if i % 2 == 0 {
                stage.join("lib")
            } else {
                stage.join("share/man")
            };
            // Size varies with i so fragments get mixed content.
            let body = vec![(i % 251) as u8; 512 + (i as usize % 4096)];
            std::fs::write(dir.join(format!("file-{i:05}.bin")), body).unwrap();
        }
        let result = build_snap(
            &trivial_meta(),
            &stage,
            out.path(),
            "x86_64",
            StagePolicy::Default,
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        digests.push(sha3_384_hex(&out.path().join(&result.snap_filename)));
    }
    assert_eq!(
        digests[0], digests[1],
        "large-tree builds diverged — mksquashfs parallelism is order-unstable (A2 root cause)"
    );
}
