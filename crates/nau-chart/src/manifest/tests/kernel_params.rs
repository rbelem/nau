use super::*;

#[test]
fn kernel_params_modules_modprobe_survive_image_entry() {
    let m = manifest_for(HashMap::from([("system".to_string(), kernel_image())])).unwrap();
    let entry = m.images.get("system").unwrap();
    assert_eq!(
        entry.kernel_params,
        Some(vec!["quiet".to_string(), "console=ttyS0".to_string()])
    );
    assert_eq!(entry.kernel_modules, Some(vec!["btrfs".to_string()]));
    assert_eq!(
        entry.kernel_modprobe_config.as_deref(),
        Some("options btrfs workspace_mirror=/vols\n")
    );
}

// ── Update config echo (ADR-0011 step (d)) ──

#[test]
fn ab_and_update_source_echo_when_declared_and_stay_absent_otherwise() {
    // Default: both fields omitted — single-slot manifests are
    // byte-identical to pre-(d) output.
    let plain = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&plain.to_json().unwrap()).unwrap();
    assert!(v["images"]["system"].get("disk_ab").is_none(), "{v}");
    assert!(v["images"]["system"].get("update_source").is_none(), "{v}");

    // Declared: echoed so downstream consumers see the update config.
    let mut decl = image_with_snaps(pinned("core22", 1847, HASH_A), vec![]);
    decl.update_source = Some("https://updates.example.com/os/".into());
    decl.disk = Some(nau_core::manifest_ir::DiskLayout {
        label: "gpt".into(),
        partitions: vec![],
        swap: None,
        ab: true,
    });
    let m = manifest_for(HashMap::from([("system".to_string(), decl)])).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert_eq!(v["images"]["system"]["disk_ab"], true, "{v}");
    assert_eq!(
        v["images"]["system"]["update_source"],
        "https://updates.example.com/os/"
    );

    // Roundtrip stays byte-stable with the new fields present.
    let back: ImageManifest = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert_eq!(back.to_json().unwrap(), m.to_json().unwrap());
}

#[test]
fn kernel_build_facts_stay_skipped_from_eval() {
    let m = manifest_for(HashMap::from([("system".to_string(), kernel_image())])).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    let img = &v["images"]["system"];
    for field in [
        "kernel_version",
        "cmdline",
        "uki",
        "esp_partuuid",
        "roothash",
    ] {
        assert!(img.get(field).is_none(), "{field} must be skipped: {img}");
    }
}

#[test]
fn kernel_free_image_omits_every_kernel_field() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    let img = &v["images"]["system"];
    for field in [
        "kernel_params",
        "kernel_modules",
        "kernel_modprobe_config",
        "kernel_version",
        "cmdline",
        "uki",
        "esp_partuuid",
        "roothash",
    ] {
        assert!(img.get(field).is_none(), "{field} must be skipped: {img}");
    }
}

// ── Schema ──

#[test]
fn manifest_version_field_is_present() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert_eq!(v["manifest_version"], 1, "schema version must be present");
}

#[test]
fn signatures_is_a_reserved_empty_object() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert!(
        v.get("signatures").is_some(),
        "signatures reservation must always serialize: {v}"
    );
    assert_eq!(
        v["signatures"].as_object().map(|o| o.len()),
        Some(0),
        "v1 never populates signatures: {v}"
    );
}

#[test]
fn artifacts_are_explicitly_unbuilt() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert_eq!(v["images"]["system"]["artifact"]["state"], "unbuilt");
    assert!(
        v["images"]["system"]["artifact"].get("sha256").is_none()
            && v["images"]["system"]["artifact"].get("path").is_none(),
        "no invented hashes or paths on unbuilt artifacts: {v}"
    );
}

#[test]
fn built_artifact_serializes_blobs_unbuilt_stays_omitted() {
    // Built (host-side records only): state + per-blob facts round-trip.
    let built = Artifact {
        state: ArtifactState::Built,
        blobs: vec![BuiltBlob {
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 7,
            media_type: "application/vnd.nau.snap.v1".into(),
        }],
    };
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&built).unwrap()).unwrap();
    assert_eq!(v["state"], "built");
    assert_eq!(
        v["blobs"][0]["digest"],
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(v["blobs"][0]["size"], 7);
    assert_eq!(v["blobs"][0]["media_type"], "application/vnd.nau.snap.v1");

    // Unbuilt (eval): the blobs list must NOT appear — eval manifests
    // stay byte-identical (byte-stability + sign canonical tests).
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&Artifact::unbuilt()).unwrap()).unwrap();
    assert_eq!(v["state"], "unbuilt");
    assert!(
        v.get("blobs").is_none(),
        "unbuilt artifact must not emit blobs: {v}"
    );
}

#[test]
fn image_snap_carries_full_pin_and_source() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    let snap = &v["images"]["system"]["snaps"][0];
    assert_eq!(snap["role"], "base");
    assert_eq!(snap["name"], "core22");
    assert_eq!(snap["revision"], 1847);
    assert_eq!(snap["sha3_384"], HASH_A);
    assert_eq!(snap["pin_source"], "definition");
}

// ── Determinism ──

#[test]
fn same_inputs_produce_byte_identical_json() {
    let build = || {
        let mut extras = vec![pinned("zz-extra", 3, HASH_B), pinned("aa-extra", 2, HASH_A)];
        extras.reverse();
        let m = manifest_with_image(pinned("core22", 1847, HASH_A), extras).unwrap();
        m.to_json().unwrap()
    };
    assert_eq!(build(), build(), "same data must give byte-identical JSON");
}

#[test]
fn image_snaps_use_fixed_role_order_with_sorted_extras() {
    let m = manifest_with_image(
        pinned("core22", 1847, HASH_A),
        vec![pinned("zz-extra", 3, HASH_B), pinned("aa-extra", 2, HASH_B)],
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    let snaps = v["images"]["system"]["snaps"].as_array().unwrap();
    let roles: Vec<&str> = snaps.iter().map(|s| s["role"].as_str().unwrap()).collect();
    assert_eq!(
        roles,
        vec!["base", "extra", "extra"],
        "fixed role order: {v}"
    );
    assert_eq!(snaps[1]["name"], "aa-extra", "extras sorted by name: {v}");
    assert_eq!(snaps[2]["name"], "zz-extra");
}

#[test]
fn no_host_paths_or_timestamps_in_output() {
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();
    let json = m.to_json().unwrap();
    assert!(!json.contains(std::env::temp_dir().to_str().unwrap()));
    for banned in ["/home/", "/tmp/", "timestamp", "generated_at"] {
        assert!(
            !json.contains(banned),
            "manifest must not carry {banned}: {json}"
        );
    }
}

// ── Fail-closed resolution ──

#[test]
fn unpinned_image_snap_fails_closed_with_named_error() {
    let err = manifest_with_image(
        SnapRef {
            name: "core22".into(),
            revision: None,
            sha3_384: None,
        },
        vec![],
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("core22"), "error must name the snap: {msg}");
    assert!(
        msg.contains("unresolved"),
        "error must state resolution failure: {msg}"
    );
    assert!(msg.contains("amd64"), "error must name the arch: {msg}");
}

#[test]
fn partial_definition_pin_without_lockfile_fails_closed() {
    // revision pinned but no content hash: unresolved without data.
    let err = manifest_with_image(
        SnapRef {
            name: "core22".into(),
            revision: Some(1847),
            sha3_384: None,
        },
        vec![],
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("unresolved"));
}

#[test]
fn partial_definition_pin_defers_to_lockfile() {
    let mut lockfile = empty_lockfile();
    lockfile.snaps.insert(
        "core22".into(),
        crate::lock::SnapLockEntry {
            revision: 1847,
            sha3_384: HASH_B.into(),
        },
    );
    let images = HashMap::from([(
        "system".to_string(),
        image_with_snaps(
            SnapRef {
                name: "core22".into(),
                revision: Some(1847),
                sha3_384: None,
            },
            vec![],
        ),
    )]);
    let outputs = Outputs::new();
    let declared = HashMap::new();
    let m = build_manifest(
        &outputs,
        &images,
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let snap = &m.images["system"].snaps[0];
    assert_eq!(snap.pin_source, PinSource::Lockfile);
    assert_eq!(snap.sha3_384, HASH_B);
}

#[test]
fn github_input_without_lockfile_pin_fails_closed() {
    let declared = HashMap::from([(
        "pkgs".to_string(),
        PackageInput {
            url: "github:owner/repo/main".into(),
            submodules: None,
        },
    )]);
    let images = HashMap::new();
    let outputs = Outputs::new();
    let lockfile = empty_lockfile();
    let err = build_manifest(
        &outputs,
        &images,
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("pkgs"), "error must name the input: {msg}");
    assert!(
        msg.contains("no lockfile pin"),
        "named failure required: {msg}"
    );
}

#[test]
fn path_input_is_local_without_a_lockfile_entry() {
    let declared = HashMap::from([(
        "vendored".to_string(),
        PackageInput {
            url: "path:vendor".into(),
            submodules: None,
        },
    )]);
    let lockfile = empty_lockfile();
    let images = HashMap::new();
    let outputs = Outputs::new();
    let m = build_manifest(
        &outputs,
        &images,
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let input = &m.inputs["vendored"];
    assert!(input.local);
    assert!(input.revision.is_none() && input.sha256.is_none());
    assert_eq!(input.url, "path:vendor");
}

#[test]
fn github_input_serializes_revision_and_sha256() {
    let mut lockfile = empty_lockfile();
    lockfile.inputs.insert(
        "pkgs".into(),
        crate::lock::InputLockEntry {
            revision: Some("c0ffee".into()),
            sha256: Some("beef".into()),
            local: false,
            submodules: None,
        },
    );
    let declared = HashMap::from([(
        "pkgs".to_string(),
        PackageInput {
            url: "github:owner/repo/main".into(),
            submodules: None,
        },
    )]);
    let m = build_manifest(
        &Outputs::new(),
        &HashMap::new(),
        &declared,
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&m.to_json().unwrap()).unwrap();
    assert_eq!(v["inputs"]["pkgs"]["revision"], "c0ffee");
    assert_eq!(v["inputs"]["pkgs"]["sha256"], "beef");
    assert!(
        v["inputs"]["pkgs"].get("local").is_none(),
        "local=false omitted"
    );
}

// ── Outputs section ──

#[test]
fn snap_output_carries_closure_key_and_identity() {
    let mut outputs = Outputs::new();
    outputs.insert("app".to_string(), bare_meta("demo-app", "1.2.3"));
    let lockfile = empty_lockfile();
    let m = build_manifest(
        &outputs,
        &HashMap::new(),
        &HashMap::new(),
        &lockfile,
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let entry = &m.outputs["app"];
    assert_eq!(entry.name, "demo-app");
    assert_eq!(entry.version.as_deref(), Some("1.2.3"));
    let key = entry.closure_key.as_deref().unwrap();
    assert!(
        key.starts_with("v4:"),
        "Phase 22a closure key required: {key}"
    );
    assert_eq!(entry.artifact.state, ArtifactState::Unbuilt);
}

#[test]
fn adopt_info_output_omits_version_and_marks_adopted() {
    let mut meta = bare_meta("adopted", "0");
    meta.adopt_info = Some("part".into());
    meta.version_adopted = true;
    let mut outputs = Outputs::new();
    outputs.insert("app".to_string(), meta);
    let m = build_manifest(
        &outputs,
        &HashMap::new(),
        &HashMap::new(),
        &empty_lockfile(),
        "amd64",
        "latest/stable",
        None,
    )
    .unwrap();
    let entry = &m.outputs["app"];
    assert!(
        entry.version.is_none(),
        "placeholder must not read as a version"
    );
    assert!(entry.version_adopted);
}

#[test]
fn select_filters_outputs_and_errors_on_unknown_name() {
    let mut outputs = Outputs::new();
    outputs.insert("app".to_string(), bare_meta("demo-app", "1.0"));
    let lockfile = empty_lockfile();
    let m = build_manifest(
        &outputs,
        &HashMap::new(),
        &HashMap::new(),
        &lockfile,
        "amd64",
        "latest/stable",
        Some("app"),
    )
    .unwrap();
    assert_eq!(m.outputs.len(), 1);

    let err = build_manifest(
        &Outputs::new(),
        &HashMap::new(),
        &HashMap::new(),
        &lockfile,
        "amd64",
        "latest/stable",
        Some("nope"),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("'nope' not found"));
}

#[test]
fn image_declarations_do_not_leak_into_outputs_section() {
    // The same table key converts both as SnapMeta (images carry name +
    // version) and as an ImageDeclaration. The key must appear under
    // `images` only.
    let mut outputs = Outputs::new();
    outputs.insert("system".to_string(), bare_meta("demo-system", "2.0.0"));
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
    assert!(
        !m.outputs.contains_key("system"),
        "image key must not appear as a snap output: {m:?}"
    );
    assert!(m.images.contains_key("system"));
}

// ── Atomic write ──

#[test]
fn write_atomic_replaces_content_without_residue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.json");
    let m = manifest_with_image(pinned("core22", 1847, HASH_A), vec![]).unwrap();

    m.write_atomic(&path).unwrap();
    m.write_atomic(&path).unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(entries, vec!["image.json".to_string()], "no temp residue");

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert_eq!(on_disk, m.to_json().unwrap(), "bytes on disk == to_json");
}
