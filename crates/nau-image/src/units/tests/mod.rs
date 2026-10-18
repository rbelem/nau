
    use super::*;
    use std::collections::BTreeMap;

    use nau_core::units::{resolve_command_path, AppUnitSpec, PlugRef};

    /// A floor-tool spawn (issue #101 seam) for gated fixtures: resolves
    /// through the tools module (provisioned-first, PATH fallback);
    /// callers gate availability first.
    fn floor_tool(tool: nau_infra::tools::ToolName) -> std::process::Command {
        let path = match nau_infra::tools::resolve(tool) {
            Ok(
                nau_infra::tools::ResolvedTool::Provisioned { path, .. }
                | nau_infra::tools::ResolvedTool::Path { path, .. },
            ) => path,
            Err(_) => panic!("{tool} unavailable"),
        };
        std::process::Command::new(path)
    }

    fn daemon_spec() -> AppUnitSpec {
        let mut env = BTreeMap::new();
        env.insert("GREETING".to_string(), "hello world".to_string());
        AppUnitSpec {
            snap: "mysnap".into(),
            app: "srv".into(),
            command: "bin/myservice --listen :80".into(),
            daemon: true,
            app_plugs: vec!["network".into()],
            environment: env,
            snap_plugs: vec![PlugRef::new("network", "network")],
        }
    }

    fn plain_spec() -> AppUnitSpec {
        AppUnitSpec {
            snap: "hello".into(),
            app: "hello".into(),
            command: "bin/hello".into(),
            daemon: false,
            app_plugs: vec![],
            environment: BTreeMap::new(),
            snap_plugs: vec![],
        }
    }

    // ── Golden unit text ──

    /// Pack a minimal shoot-built payload (daemon app + binary) with
    /// mksquashfs; returns the payload path.
    fn pack_payload(dir: &std::path::Path) -> Option<std::path::PathBuf> {
        let has = |tool: &str| {
            std::process::Command::new("which")
                .arg(tool)
                .output()
                .ok()
                .is_some_and(|o| o.status.success())
        };
        if !has("unsquashfs") || !has("mksquashfs") {
            eprintln!("skipping: unsquashfs/mksquashfs unavailable");
            return None;
        }
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("meta")).unwrap();
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::write(
            tree.join("meta/snap.yaml"),
            "\
name: my-snap
version: '1.0'
confinement: strict
apps:
  srv:
    command: bin/myservice --listen :80
    daemon: simple
    plugs: [network, bus]
    environment:
      GREETING: hi
plugs:
  network: network
  bus:
    interface: dbus
    name: com.example.Srv
",
        )
        .unwrap();
        std::fs::write(tree.join("bin/myservice"), "#!/bin/sh\nexec true\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                tree.join("bin/myservice"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let payload = dir.join("my-snap_1_abc.snap");
        let status = floor_tool(nau_infra::tools::ToolName::Mksquashfs)
            .arg(&tree)
            .arg(&payload)
            .arg("-noappend")
            .arg("-all-root")
            .output()
            .unwrap();
        assert!(status.status.success(), "mksquashfs failed");
        Some(payload)
    }


mod daemon_unit;
