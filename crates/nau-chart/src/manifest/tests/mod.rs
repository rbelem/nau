
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Bare SnapMeta with every optional field empty (mirrors the test
    /// helpers in cache.rs).
    fn bare_meta(name: &str, version: &str) -> SnapMeta {
        SnapMeta {
            name: name.into(),
            version: version.into(),
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            build: None,
            parts: None,
            architectures: Some(vec!["amd64".into()]),
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
            apps: BTreeMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn pinned(name: &str, revision: u32, hash: &str) -> SnapRef {
        SnapRef {
            name: name.into(),
            revision: Some(revision),
            sha3_384: Some(hash.into()),
        }
    }

    fn empty_lockfile() -> LockFile {
        LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
            packages: HashMap::new(),
            build_deps: HashMap::new(),
        }
    }

    fn image_with_snaps(base: SnapRef, extras: Vec<SnapRef>) -> ImageDeclaration {
        ImageDeclaration {
            name: "test-system".into(),
            version: "1.0.0".into(),
            base,
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: extras,
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
            files: vec![],
            boot_health_exec: None,
        }
    }

    fn manifest_with_image(base: SnapRef, extras: Vec<SnapRef>) -> miette::Result<ImageManifest> {
        let images = HashMap::from([("system".to_string(), image_with_snaps(base, extras))]);
        let outputs = Outputs::new();
        let lockfile = empty_lockfile();
        let declared = HashMap::new();
        build_manifest(
            &outputs,
            &images,
            &declared,
            &lockfile,
            "amd64",
            "latest/stable",
            None,
        )
    }

    // ── Kernel config threading (ADR-0011 step (a)) ──

    fn kernel_image() -> ImageDeclaration {
        ImageDeclaration {
            name: "kernel-system".into(),
            version: "2.0.0".into(),
            base: pinned("core22", 1847, HASH_A),
            kernel: Some(nau_core::manifest_ir::KernelEntry {
                snap: pinned("pc-kernel", 1241, HASH_B),
                params: vec!["quiet".into(), "console=ttyS0".into()],
                modules: vec!["btrfs".into()],
                modprobe_config: Some("options btrfs workspace_mirror=/vols\n".into()),
                channel: None,
            }),
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
            files: vec![],
            boot_health_exec: None,
        }
    }

    fn manifest_for(images: HashMap<String, ImageDeclaration>) -> miette::Result<ImageManifest> {
        build_manifest(
            &Outputs::new(),
            &images,
            &HashMap::new(),
            &empty_lockfile(),
            "amd64",
            "latest/stable",
            None,
        )
    }


mod kernel_params;
mod failed_atomic;
