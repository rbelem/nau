//! App execution — hardened systemd units for shoot-built snaps
//! (ADR-0011 step (f), Phase 24a).
//!
//! In the native snapd-free target nothing mounts or executes the staged
//! `.snap` payloads: app runtime must be materialized into the rootfs
//! itself. For every shoot-built app snap in an image this module
//!
//! 1. reads `meta/snap.yaml` out of the payload (`unsquashfs`, the same
//!    external tool the base-rootfs extraction already uses),
//! 2. extracts each app's command binary to `/usr/bin/<snap>-<app>`
//!    (documented naming: avoids collisions, PATH-clean),
//! 3. and — only for daemon-bearing apps (`daemon = "…"`) — emits a
//!    hardened unit `/usr/lib/systemd/system/<snap>-<app>.service` plus
//!    its `multi-user.target.wants` enablement symlink.
//!
//! # Scope: shoot-built snaps only
//!
//! The payload's `type` field classifies the snap (see
//! [`classify`]): snapd infrastructure types (`base`, `gadget`,
//! `kernel`, `snapd`) are skipped quietly, a `type = "store"` payload is
//! skipped with an explicit build note (never silently), and everything
//! else — shoot-built `source`/`meta` snaps and the snapd default
//! (no `type`, an app payload; every shoot-built payload serializes
//! without `type`, see `skip_internal_or_default_type` in snap.rs) —
//! receives app runtime.
//!
//! # Confinement posture (honest)
//!
//! The default profile below is static systemd hardening. snapd's
//! dynamic confinement — interface composition, D-Bus mediation, home
//! remapping — is NOT delivered; declared plugs are translated to the
//! few directives that exist, and everything else is explicitly
//! warn-and-dropped. The build-time lint in [`crate::lint`] surfaces the
//! gap for `confinement = "strict"` snaps.
//!
//! # Write-before-hash
//!
//! Emission happens in `build_disk_image` after payload staging and
//! BEFORE root populate + dm-verity: binaries and units must be inside
//! the hashed tree (same constraint as the image manifest).

use std::collections::BTreeMap;
use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};
use serde::Deserialize;

use crate::command::CommandRunner;
use crate::store::ResolvedSnap;

// ── Planner (moved down to nau-core, ADR-0051 Decision 3) ──
//
// The pure unit planner — shared vocabulary of the image emitter and the
// chart confinement lint — lives in `nau_core::units`. Re-exported so
// every `crate::units::plan_app`-style path keeps resolving unchanged.
pub use nau_core::units::{
    plan_app, resolve_command_path, spec_from_snap_app, staged_binary_rel, unit_name, AppPlan,
    AppUnitSpec, DaemonUnit, PlugRef,
};

/// (used by the image-build emission path).
pub fn spec_from_payload_app(
    snap: &str,
    app_name: &str,
    app: &PayloadApp,
    snap_plugs: Vec<PlugRef>,
) -> AppUnitSpec {
    AppUnitSpec {
        snap: snap.to_string(),
        app: app_name.to_string(),
        command: app.command.clone(),
        daemon: app.daemon.is_some(),
        app_plugs: app.plugs.clone(),
        environment: app.environment.clone(),
        snap_plugs,
    }
}

// ── Payload meta/snap.yaml parsing (serde side) ──

/// The subset of a payload's `meta/snap.yaml` the runtime emitter needs.
#[derive(Debug, Deserialize)]
pub struct PayloadSnap {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "type", default)]
    pub snap_type: Option<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub confinement: Option<String>,
    /// The snap-level icon target inside the payload (e.g.
    /// `meta/gui/icon.png`) — the icon the desktop launcher links
    /// alongside the generated entry (issue #7).
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub apps: BTreeMap<String, PayloadApp>,
    #[serde(default)]
    pub plugs: BTreeMap<String, PayloadPlug>,
    /// Runtime confinement grants (ADR-0016, ticket #11): the package-level
    /// `confined` declaration, preserved in snap.yaml so the runtime
    /// emitter records it in the generation manifest. Absent = unconfined.
    #[serde(default)]
    pub confined: Option<crate::snap::Confinement>,
    /// Services declared by this package (ADR-0032, issue #105), carried
    /// through meta/snap.yaml (written by SnapMeta's Serialize) so the
    /// runtime planner records them in the generation manifest at
    /// install time (issue #106).
    #[serde(default)]
    pub services: BTreeMap<String, crate::snap::ServiceDecl>,
}

/// One app entry in a payload `meta/snap.yaml`.
#[derive(Debug, Deserialize)]
pub struct PayloadApp {
    pub command: String,
    /// Presence makes the app daemon-bearing; the value (simple,
    /// forking, notify, …) does not change the emitted unit shape.
    #[serde(default)]
    pub daemon: Option<String>,
    #[serde(default)]
    pub plugs: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Path to the app's `.desktop` file inside the payload (issue #7,
    /// like snapd's `desktop:` app key) — the launcher's metadata source.
    #[serde(default)]
    pub desktop: Option<String>,
    /// Per-app runtime confinement override (ticket #11): wins over the
    /// snap-level `confined`. Absent = inherit the snap's.
    #[serde(default)]
    pub confined: Option<crate::snap::Confinement>,
}

/// A snap-level plug value in a payload `meta/snap.yaml`: a bare
/// interface string or an attribute table with `interface` + attrs.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PayloadPlug {
    Interface(String),
    Typed {
        interface: String,
        #[serde(flatten)]
        attributes: BTreeMap<String, serde_yaml::Value>,
    },
}

impl PayloadPlug {
    /// Coerce to the planner's plug shape, keeping only string-valued
    /// attributes (real-world snap.yaml attributes can be ints/bools).
    pub fn to_plug_ref(&self, name: &str) -> PlugRef {
        match self {
            PayloadPlug::Interface(interface) => PlugRef::new(name, interface),
            PayloadPlug::Typed {
                interface,
                attributes,
            } => {
                let mut plug = PlugRef::new(name, interface);
                for (k, v) in attributes {
                    if let serde_yaml::Value::String(s) = v {
                        plug.attributes.insert(k.clone(), s.clone());
                    }
                }
                plug
            }
        }
    }
}

// ── Classification ──

/// How the runtime emitter treats one staged payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeClass {
    /// Shoot-built app payload — receive binaries + units.
    ShootBuilt,
    /// `type = "store"` — skipped, with an explicit build note.
    Store,
    /// snapd infrastructure (`base`/`gadget`/`kernel`/`snapd`) — no app
    /// runtime, skipped quietly.
    Infrastructure,
}

/// Classify a payload by its `type` field. An absent type is the snapd
/// app default — and the shape every shoot-built payload serializes
/// with (nau never emits `source`/`meta` into snap.yaml), so it is
/// shoot-built.
pub fn classify(snap_type: Option<&str>) -> RuntimeClass {
    match snap_type {
        Some("base" | "gadget" | "kernel" | "snapd") => RuntimeClass::Infrastructure,
        Some("store") => RuntimeClass::Store,
        _ => RuntimeClass::ShootBuilt,
    }
}

// ── Emission (image-build path) ──

/// Emit app runtime for every staged snap into the rootfs at `root`.
///
/// For each payload in `cache_dir` (named `<name>_<rev>_<sha3>.snap`,
/// the sha3-384-verified download): read `meta/snap.yaml`, classify,
/// extract app binaries to `usr/bin/<snap>-<app>`, and write hardened
/// units + enablement symlinks for daemon-bearing apps. Returns every
/// per-app warning for the build log.
///
/// Per-payload problems (missing metadata, unparseable yaml, missing
/// binary) are warn-and-continue — one inert snap never fails an image
/// build. Staged-rootfs write failures are hard errors.
pub fn emit_app_runtime(
    runner: &dyn CommandRunner,
    snaps: &[(String, ResolvedSnap)],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
) -> miette::Result<Vec<String>> {
    if !has_unsquashfs {
        eprintln!(
            "  ⚠ unsquashfs not found — app execution skipped (no binaries, no units emitted)"
        );
        return Ok(Vec::new());
    }

    let mut all_warnings = Vec::new();
    for (name, snap) in snaps {
        let payload = cache_dir.join(format!("{}_{}_{}.snap", name, snap.revision, snap.sha3_384));
        if !payload.exists() {
            eprintln!("  ⚠ {name}: payload missing from cache — app execution skipped");
            continue;
        }
        match emit_one_snap(runner, name, &payload, root) {
            Ok(warnings) => {
                for w in &warnings {
                    eprintln!("  ⚠ {w}");
                }
                all_warnings.extend(warnings);
            }
            Err(e) => {
                eprintln!("  ⚠ {name}: app execution skipped: {e:#}");
            }
        }
    }
    Ok(all_warnings)
}

/// The unsquashfs argv[0] (issue #101 seam): resolved through the tools
/// module (provisioned-first, PATH fallback). A resolution failure means
/// the emit cannot extract — the per-payload skip path reports it.
fn unsquashfs_argv0() -> miette::Result<String> {
    let resolved = crate::tools::resolve(crate::tools::ToolName::Unsquashfs)
        .map_err(|e| miette::miette!("resolve unsquashfs: {e}"))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path.to_string_lossy().into_owned(),
    })
}

/// Emit runtime for one payload: classify, extract binaries, write
/// units. Warnings are returned; hard failures mean the rootfs cannot
/// be written and abort the build.
fn emit_one_snap(
    runner: &dyn CommandRunner,
    name: &str,
    payload: &Path,
    root: &Path,
) -> miette::Result<Vec<String>> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let extract_dir = work.path().join("extract");

    // 1. Read meta/snap.yaml out of the payload (single-file
    //    extraction, same tool + flags as the base-rootfs flow).
    let argv = vec![
        unsquashfs_argv0()?,
        "-no-xattrs".to_string(),
        "-d".to_string(),
        extract_dir.to_string_lossy().into_owned(),
        payload.to_string_lossy().into_owned(),
        "meta/snap.yaml".to_string(),
    ];
    let status = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    let yaml_path = extract_dir.join("meta").join("snap.yaml");
    if status.code != 0 || !yaml_path.exists() {
        return Err(miette::miette!("meta/snap.yaml not extractable"));
    }
    let yaml_text = std::fs::read_to_string(&yaml_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", yaml_path.display()))?;
    let meta: PayloadSnap = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml parse: {e}"))?;

    // 2. Classify — store payloads are skipped with an explicit note.
    let snap_name = meta.name.as_deref().unwrap_or(name);
    match classify(meta.snap_type.as_deref()) {
        RuntimeClass::Infrastructure => return Ok(Vec::new()),
        RuntimeClass::Store => {
            eprintln!(
                "  ℹ {snap_name}: type=store — app execution skipped (store snaps keep \
                 their own runtime)"
            );
            return Ok(Vec::new());
        }
        RuntimeClass::ShootBuilt => {}
    }
    if meta.apps.is_empty() {
        return Ok(Vec::new());
    }

    // 3. Plan every app.
    let snap_plugs: Vec<PlugRef> = meta
        .plugs
        .iter()
        .map(|(plug_name, plug)| plug.to_plug_ref(plug_name))
        .collect();
    let plans: Vec<AppPlan> = meta
        .apps
        .iter()
        .map(|(app_name, app)| {
            let spec = spec_from_payload_app(snap_name, app_name, app, snap_plugs.clone());
            plan_app(&spec)
        })
        .collect();

    // 4. Extract every app binary in one unsquashfs call.
    let mut file_args: Vec<String> = Vec::new();
    for plan in &plans {
        file_args.push(plan.in_snap_binary.clone());
    }
    let mut argv = vec![
        unsquashfs_argv0()?,
        "-no-xattrs".to_string(),
        "-d".to_string(),
        extract_dir.join("files").to_string_lossy().into_owned(),
        payload.to_string_lossy().into_owned(),
    ];
    argv.extend(file_args.iter().cloned());
    let status = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if status.code != 0 {
        return Err(miette::miette!(
            "app binaries not extractable ({} …)",
            file_args.first().map(String::as_str).unwrap_or("?")
        ));
    }
    let files_dir = extract_dir.join("files");
    let bin_dir = root.join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir)
        .into_diagnostic()
        .wrap_err("creating /usr/bin")?;
    for plan in &plans {
        let src = files_dir.join(&plan.in_snap_binary);
        if !src.exists() {
            return Err(miette::miette!(
                "command binary '{}' not found in payload",
                plan.in_snap_binary
            ));
        }
        let dest = bin_dir.join(format!("{}-{}", plan.snap, plan.app));
        std::fs::copy(&src, &dest)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging {}", dest.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
                .into_diagnostic()
                .wrap_err_with(|| format!("chmod 0755 {}", dest.display()))?;
        }
    }

    // 5. Units + enablement for daemon-bearing apps.
    for plan in &plans {
        let Some(unit) = &plan.daemon else {
            // Plain app: binary only, no unit.
            continue;
        };
        let unit_rel = Path::new("usr/lib/systemd/system").join(&unit.unit_name);
        crate::emit::write_unit(root, &unit_rel, &unit.text)?;
        // Build-time enablement: multi-user.target.wants symlink.
        crate::emit::enable_unit(root, "multi-user.target", &unit.unit_name)?;
    }

    Ok(plans.into_iter().flat_map(|p| p.warnings).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A floor-tool spawn (issue #101 seam) for gated fixtures: resolves
    /// through the tools module (provisioned-first, PATH fallback);
    /// callers gate availability first.
    fn floor_tool(tool: crate::tools::ToolName) -> std::process::Command {
        let path = match crate::tools::resolve(tool) {
            Ok(
                crate::tools::ResolvedTool::Provisioned { path, .. }
                | crate::tools::ResolvedTool::Path { path, .. },
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

    // ── Classification ──

    #[test]
    fn classification_follows_the_type_field() {
        assert_eq!(classify(None), RuntimeClass::ShootBuilt);
        assert_eq!(classify(Some("source")), RuntimeClass::ShootBuilt);
        assert_eq!(classify(Some("meta")), RuntimeClass::ShootBuilt);
        assert_eq!(classify(Some("store")), RuntimeClass::Store);
        assert_eq!(classify(Some("base")), RuntimeClass::Infrastructure);
        assert_eq!(classify(Some("gadget")), RuntimeClass::Infrastructure);
        assert_eq!(classify(Some("kernel")), RuntimeClass::Infrastructure);
        assert_eq!(classify(Some("snapd")), RuntimeClass::Infrastructure);
    }

    // ── Payload yaml parsing ──

    #[test]
    fn payload_yaml_with_typed_plugs_parses() {
        let yaml = "\
name: my-snap
version: '1.0'
confinement: strict
apps:
  srv:
    command: bin/serve --port 80
    daemon: simple
    plugs: [network, bus]
    environment:
      GREETING: hi
plugs:
  network: network
  bus:
    interface: dbus
    name: com.example.Srv
";
        let meta: PayloadSnap = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(meta.name.as_deref(), Some("my-snap"));
        assert_eq!(meta.snap_type, None);
        assert_eq!(meta.confinement.as_deref(), Some("strict"));
        let app = meta.apps.get("srv").unwrap();
        assert_eq!(app.command, "bin/serve --port 80");
        assert!(app.daemon.is_some());
        assert_eq!(app.plugs, vec!["network".to_string(), "bus".to_string()]);
        let bus = meta.plugs.get("bus").unwrap().to_plug_ref("bus");
        assert_eq!(bus.interface, "dbus");
        assert_eq!(
            bus.attributes.get("name").map(String::as_str),
            Some("com.example.Srv")
        );
        let spec = spec_from_payload_app(
            "my-snap",
            "srv",
            app,
            vec![
                meta.plugs.get("network").unwrap().to_plug_ref("network"),
                bus,
            ],
        );
        let plan = plan_app(&spec);
        assert!(plan.daemon.is_some());
        assert!(plan
            .daemon
            .as_ref()
            .unwrap()
            .text
            .contains("BusName=com.example.Srv"));
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
        let status = floor_tool(crate::tools::ToolName::Mksquashfs)
            .arg(&tree)
            .arg(&payload)
            .arg("-noappend")
            .arg("-all-root")
            .output()
            .unwrap();
        assert!(status.status.success(), "mksquashfs failed");
        Some(payload)
    }

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
            &crate::command::RealRunner,
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
        let status = floor_tool(crate::tools::ToolName::Mksquashfs)
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
            &crate::command::RealRunner,
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
            &crate::command::RealRunner,
            &snap_paths,
            cache.path(),
            root.path(),
            false,
        )
        .unwrap();
        assert!(warnings.is_empty());
        assert!(!root.path().join("usr/bin").exists(), "nothing staged");
    }
}
