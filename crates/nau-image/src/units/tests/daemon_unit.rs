use super::*;

#[test]
fn daemon_unit_golden_text_with_profile_and_env() {
    let plan = plan_app(&daemon_spec());
    let unit = plan.daemon.as_ref().expect("daemon app has a unit");
    assert_eq!(unit.unit_name, "mysnap-srv.service");
    let expected = "\
[Unit]
Description=nau: mysnap (srv)

[Service]
Type=exec
ExecStart=/usr/bin/mysnap-srv
Environment=\"GREETING=hello world\"
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=
StateDirectory=mysnap
CacheDirectory=mysnap
LogsDirectory=mysnap

[Install]
WantedBy=multi-user.target
";
    assert_eq!(unit.text, expected);
    // Binary-only facts still planned for extraction.
    assert_eq!(plan.in_snap_binary, "bin/myservice");
}

#[test]
fn dbus_plug_emits_busname_and_warns_no_mediation() {
    let mut spec = daemon_spec();
    spec.app_plugs = vec!["bus".into()];
    spec.snap_plugs = vec![PlugRef::new("bus", "dbus").with_attr("name", "com.example.Srv")];
    let plan = plan_app(&spec);
    let unit = plan.daemon.as_ref().unwrap();
    assert!(
        unit.text.contains("BusName=com.example.Srv\n"),
        "BusName emitted when the dbus plug carries a name: {}",
        unit.text
    );
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("dbus") && w.contains("mediation is not enforced")),
        "D-Bus mediation warning required: {:?}",
        plan.warnings
    );
}

#[test]
fn device_plug_omits_private_devices_and_warns() {
    let mut spec = daemon_spec();
    spec.app_plugs = vec!["gpu".into()];
    spec.snap_plugs = vec![PlugRef::new("gpu", "gpu-2404")];
    let plan = plan_app(&spec);
    let unit = plan.daemon.as_ref().unwrap();
    assert!(
        !unit.text.contains("PrivateDevices"),
        "PrivateDevices must be omitted for device plugs: {}",
        unit.text
    );
    assert!(
        unit.text.contains("ProtectHome=true"),
        "home hardening untouched: {}",
        unit.text
    );
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("gpu") && w.contains("unconfined")),
        "device-access warning required: {:?}",
        plan.warnings
    );
}

#[test]
fn home_plug_downgrades_protecthome_to_read_only() {
    let mut spec = daemon_spec();
    spec.app_plugs = vec!["docs".into()];
    spec.snap_plugs = vec![PlugRef::new("docs", "home")];
    let plan = plan_app(&spec);
    let unit = plan.daemon.as_ref().unwrap();
    assert!(unit.text.contains("ProtectHome=read-only"));
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("home") && w.contains("not delivered")),
        "home-remap warning required: {:?}",
        plan.warnings
    );
}

// ── Plain (non-daemon) apps ──

#[test]
fn plain_app_gets_binary_only_no_unit() {
    let plan = plan_app(&plain_spec());
    assert!(plan.daemon.is_none(), "no unit for a non-daemon app");
    assert_eq!(plan.in_snap_binary, "bin/hello");
}

// ── Warn-and-drop ──

#[test]
fn unknown_interface_is_warned_and_dropped_by_name() {
    let mut spec = daemon_spec();
    spec.app_plugs = vec!["weird-plug".into()];
    spec.snap_plugs = vec![PlugRef::new("weird-plug", "some-future-interface")];
    let plan = plan_app(&spec);
    let unit = plan.daemon.as_ref().unwrap();
    // The unit is otherwise untouched.
    assert!(unit.text.contains("PrivateDevices=yes"));
    assert!(
        plan.warnings
            .iter()
            .any(|w| { w.contains("weird-plug") && w.contains("some-future-interface") }),
        "dropped plug must be named: {:?}",
        plan.warnings
    );
}

#[test]
fn undeclared_app_plug_is_warned_and_dropped_by_name() {
    let mut spec = daemon_spec();
    spec.app_plugs = vec!["ghost".into()];
    spec.snap_plugs = vec![];
    let plan = plan_app(&spec);
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("ghost") && w.contains("not declared")),
        "undeclared plug must be named: {:?}",
        plan.warnings
    );
}

#[test]
fn network_plug_is_a_noted_noop() {
    let plan = plan_app(&daemon_spec());
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("network") && w.contains("allowed by default")),
        "network plug noted: {:?}",
        plan.warnings
    );
}

// ── Command path resolution ──

#[test]
fn command_path_takes_first_token_and_strips_prefixes() {
    assert_eq!(
        resolve_command_path("bin/hello").as_deref(),
        Some("bin/hello")
    );
    assert_eq!(
        resolve_command_path("bin/serve --port 80").as_deref(),
        Some("bin/serve")
    );
    assert_eq!(
        resolve_command_path("$SNAP/bin/x").as_deref(),
        Some("bin/x")
    );
    assert_eq!(
        resolve_command_path("/usr/bin/env sh").as_deref(),
        Some("usr/bin/env")
    );
    assert_eq!(resolve_command_path(""), None);
}

#[test]
fn tier1_directives_survive_every_translation() {
    // The Tier-1 hardening set must be present regardless of plug
    // effects (only PrivateDevices is omittable, and only for
    // device interfaces).
    for plugs in [
        vec![],
        vec![PlugRef::new("g", "gpu-2404")],
        vec![PlugRef::new("h", "home")],
        vec![PlugRef::new("b", "dbus").with_attr("name", "x.Y")],
    ] {
        let mut spec = daemon_spec();
        spec.app_plugs = plugs.iter().map(|p| p.name.clone()).collect();
        spec.snap_plugs = plugs;
        let unit = plan_app(&spec).daemon.unwrap();
        for directive in [
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "PrivateTmp=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
            "ProtectControlGroups=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "RestrictRealtime=yes",
            "SystemCallFilter=@system-service",
            "CapabilityBoundingSet=",
            "Type=exec",
            "StateDirectory=mysnap",
            "WantedBy=multi-user.target",
        ] {
            assert!(
                unit.text.contains(directive),
                "{directive} missing from:\n{}",
                unit.text
            );
        }
    }
}

// ── IO path (gated: needs unsquashfs + mksquashfs) ──

#[test]
fn emit_app_runtime_stages_binary_and_daemon_unit() {
    let _lock = crate::test_env::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let work = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let Some(payload) = pack_payload(work.path()) else {
        return; // gated
    };
    let cache = tempfile::tempdir().unwrap();
    std::fs::copy(&payload, cache.path().join("my-snap_1_abc.snap")).unwrap();

    let snap_paths: Vec<(String, ResolvedSnap)> = vec![(
        "my-snap".to_string(),
        ResolvedSnap {
            name: "my-snap".into(),
            revision: 1,
            sha3_384: "abc".into(),
            download_url: String::new(),
        },
    )];

    let root = tempfile::tempdir().unwrap();
    let warnings = emit_app_runtime(
        &nau_infra::command::RealRunner,
        &snap_paths,
        cache.path(),
        root.path(),
        true,
    )
    .unwrap();

    // Binary staged at the documented path, executable.
    let staged = root.path().join("usr/bin/my-snap-srv");
    assert!(staged.exists(), "binary staged at /usr/bin/my-snap-srv");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
    assert_eq!(mode & 0o111, 0o111, "staged binary is executable");

    // Daemon unit written with BusName (dbus plug) and enabled.
    let unit = root
        .path()
        .join("usr/lib/systemd/system/my-snap-srv.service");
    let text = std::fs::read_to_string(&unit).unwrap();
    assert!(text.contains("ExecStart=/usr/bin/my-snap-srv"));
    assert!(text.contains("BusName=com.example.Srv"));
    assert!(text.contains("Environment=\"GREETING=hi\""));
    let wants = root
        .path()
        .join("etc/systemd/system/multi-user.target.wants/my-snap-srv.service");
    assert!(
        std::fs::symlink_metadata(&wants).is_ok(),
        "enablement symlink present"
    );

    // D-Bus mediation warning surfaced for the build log.
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("dbus") && w.contains("mediation")),
        "{warnings:?}"
    );

    // The binary actually runs.
    let out = std::process::Command::new(&staged).status().unwrap();
    assert!(out.success());
}

#[test]
fn emit_app_runtime_skips_store_payloads_with_note() {
    let _lock = crate::test_env::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let work = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    if pack_payload(work.path()).is_none() {
        return; // gated
    }
    // Rewrite the payload metadata as type=store (the skip class).
    let tree = work.path().join("tree");
    let yaml = std::fs::read_to_string(tree.join("meta/snap.yaml"))
        .unwrap()
        .replace("name: my-snap", "name: store-snap\ntype: store");
    std::fs::write(tree.join("meta/snap.yaml"), yaml).unwrap();
    let payload = work.path().join("store_1_def.snap");
    let status = floor_tool(nau_infra::tools::ToolName::Mksquashfs)
        .arg(tree)
        .arg(&payload)
        .arg("-noappend")
        .arg("-all-root")
        .output()
        .unwrap();
    assert!(status.status.success());
    let cache = tempfile::tempdir().unwrap();
    std::fs::copy(&payload, cache.path().join("store-snap_1_def.snap")).unwrap();
    let snap_paths: Vec<(String, ResolvedSnap)> = vec![(
        "store-snap".to_string(),
        ResolvedSnap {
            name: "store-snap".into(),
            revision: 1,
            sha3_384: "def".into(),
            download_url: String::new(),
        },
    )];

    let root = tempfile::tempdir().unwrap();
    let warnings = emit_app_runtime(
        &nau_infra::command::RealRunner,
        &snap_paths,
        cache.path(),
        root.path(),
        true,
    )
    .unwrap();
    assert!(warnings.is_empty());
    assert!(
        !root.path().join("usr/bin").exists(),
        "store payload stages nothing"
    );
}

#[test]
fn emit_app_runtime_without_unsquashfs_is_an_explicit_skip() {
    let cache = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let snap_paths: Vec<(String, ResolvedSnap)> = vec![(
        "hello".to_string(),
        ResolvedSnap {
            name: "hello".into(),
            revision: 1,
            sha3_384: "abc".into(),
            download_url: String::new(),
        },
    )];
    let warnings = emit_app_runtime(
        &nau_infra::command::RealRunner,
        &snap_paths,
        cache.path(),
        root.path(),
        false,
    )
    .unwrap();
    assert!(warnings.is_empty());
    assert!(!root.path().join("usr/bin").exists(), "nothing staged");
}
