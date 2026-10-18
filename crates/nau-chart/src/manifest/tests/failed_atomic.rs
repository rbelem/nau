use super::*;

#[test]
fn failed_atomic_write_leaves_previous_manifest_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.json");
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    m.write_atomic(&path).unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    // A write whose temp file cannot be created (parent "dir" is a file)
    // must fail without touching the existing manifest or leaving residue.
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").unwrap();
    let bad_path = blocker.join("nested").join("image.json");
    assert!(m.write_atomic(&bad_path).is_err());

    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(before, after, "failed write must not modify the manifest");
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(entries.len(), 2, "only manifest + blocker, no temp residue");
}

#[test]
fn end_to_end_manifest_roundtrips_through_serde() {
    let mut outputs = Outputs::new();
    outputs.insert("app".to_string(), bare_meta("demo-app", "1.2.3"));
    let images = HashMap::from([(
        "system".to_string(),
        image_with_snaps(pinned("core22", 1847, HASH_A), vec![]),
    )]);
    let m = build_manifest(
        &outputs,
        &images,
        &HashMap::new(),
        &empty_lockfile(),
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let json = m.to_json().unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.manifest_version, MANIFEST_VERSION);
    assert_eq!(back.images["system"].snaps, m.images["system"].snaps);
    assert_eq!(back.to_json().unwrap(), json, "roundtrip is byte-stable");
}
