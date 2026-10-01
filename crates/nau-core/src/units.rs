//! The pure app-runtime unit planner — hardened systemd-unit vocabulary
//! shared by the image emitter and the chart confinement lint (ADR-0051
//! Decision 3). Pure computation over [`crate::snap_types`] values: no
//! I/O, no runner, no presentation.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::snap_types::{Confinement, ServiceDecl};

// ── Planner input/output ──

/// One snap-level plug as the unit planner sees it: the plug name plus
/// its interface and string attributes.
#[derive(Debug, Clone, PartialEq)]
pub struct PlugRef {
    pub name: String,
    pub interface: String,
    pub attributes: BTreeMap<String, String>,
}

impl PlugRef {
    pub fn new(name: &str, interface: &str) -> Self {
        PlugRef {
            name: name.to_string(),
            interface: interface.to_string(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

/// Everything needed to plan one app's runtime.
#[derive(Debug, Clone)]
pub struct AppUnitSpec {
    pub snap: String,
    pub app: String,
    pub command: String,
    /// `daemon = "…"` present (any value — the unit shape is the same).
    pub daemon: bool,
    /// App-level plug names (references into `snap_plugs`).
    pub app_plugs: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub snap_plugs: Vec<PlugRef>,
}

/// A rendered daemon unit.
#[derive(Debug, Clone, PartialEq)]
pub struct DaemonUnit {
    /// `<snap>-<app>.service`.
    pub unit_name: String,
    /// The exact `.service` text written to the staged rootfs.
    pub text: String,
}

/// The planned runtime for one app.
#[derive(Debug, Clone)]
pub struct AppPlan {
    pub snap: String,
    pub app: String,
    /// The command binary's path inside the snap (e.g. `bin/hello`).
    pub in_snap_binary: String,
    /// Rendered unit — `None` for plain (non-daemon) apps, which get the
    /// binary only.
    pub daemon: Option<DaemonUnit>,
    /// Per-app warnings for the build log (plug translations,
    /// warn-and-drop notes).
    pub warnings: Vec<String>,
}

/// Unit filename for one app: `<snap>-<app>.service`.
pub fn unit_name(snap: &str, app: &str) -> String {
    format!("{snap}-{app}.service")
}

/// Staged binary path inside the rootfs: `/usr/bin/<snap>-<app>`
/// (documented naming — avoids collisions, PATH-clean).
pub fn staged_binary_rel(snap: &str, app: &str) -> String {
    format!("usr/bin/{snap}-{app}")
}

/// Resolve the in-snap binary path from an app `command`. The command
/// may carry arguments (`bin/foo --bar`) — only the first token is a
/// path; a leading `$SNAP/` or `/` is stripped.
pub fn resolve_command_path(command: &str) -> Option<String> {
    let first = command.split_whitespace().next()?;
    let stripped = first.strip_prefix("$SNAP/").unwrap_or(first);
    let trimmed = stripped.trim_start_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ── Plug translation table ──

/// Interfaces whose device access forces `PrivateDevices` to be omitted
/// (GPU / audio): `opengl`, `gpu*`, `audio-*`.
fn is_device_interface(interface: &str) -> bool {
    interface == "opengl" || interface.starts_with("gpu") || interface.starts_with("audio-")
}

/// Interfaces allowed by default (no directive needed).
fn is_allowlisted_network(interface: &str) -> bool {
    interface == "network" || interface == "network-bind"
}

/// Outcome of translating one app's plugs into directives.
struct PlugEffects {
    protect_home: &'static str,
    private_devices: bool,
    bus_name: Option<String>,
    dropped: Vec<String>,
}

fn apply_plugs(spec: &AppUnitSpec) -> PlugEffects {
    let mut effects = PlugEffects {
        protect_home: "true",
        private_devices: true,
        bus_name: None,
        dropped: Vec::new(),
    };
    for plug_name in &spec.app_plugs {
        let Some(plug) = spec.snap_plugs.iter().find(|p| &p.name == plug_name) else {
            effects.dropped.push(format!("{plug_name} (undeclared)"));
            continue;
        };
        let iface = plug.interface.as_str();
        if is_allowlisted_network(iface) {
            // Allowed by default under the hardened profile — noted, not
            // dropped.
            continue;
        }
        if iface == "home" {
            effects.protect_home = "read-only";
            continue;
        }
        if is_device_interface(iface) {
            effects.private_devices = false;
            continue;
        }
        if iface == "dbus" {
            // BusName= is ordering-only: stock systemd has no D-Bus
            // mediation. Emit the name when declared, always warn.
            effects.bus_name = plug.attributes.get("name").cloned();
            continue;
        }
        // Everything else: explicit warn-and-drop, naming the plug.
        effects
            .dropped
            .push(format!("{} (interface '{iface}')", plug.name));
    }
    effects
}

/// Render the daemon unit text for one app.
fn render_unit(spec: &AppUnitSpec, effects: &PlugEffects) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("[Unit]".into());
    lines.push(format!("Description=nau: {} ({})", spec.snap, spec.app));
    lines.push(String::new());
    lines.push("[Service]".into());
    lines.push("Type=exec".into());
    lines.push(format!(
        "ExecStart=/{}",
        staged_binary_rel(&spec.snap, &spec.app)
    ));
    for (k, v) in &spec.environment {
        lines.push(format!("Environment=\"{k}={v}\""));
    }
    lines.push("NoNewPrivileges=yes".into());
    lines.push("ProtectSystem=strict".into());
    lines.push(format!("ProtectHome={}", effects.protect_home));
    lines.push("PrivateTmp=yes".into());
    if effects.private_devices {
        lines.push("PrivateDevices=yes".into());
    }
    lines.push("ProtectKernelTunables=yes".into());
    lines.push("ProtectKernelModules=yes".into());
    lines.push("ProtectKernelLogs=yes".into());
    lines.push("ProtectControlGroups=yes".into());
    lines.push("ProtectClock=yes".into());
    lines.push("ProtectHostname=yes".into());
    lines.push("RestrictSUIDSGID=yes".into());
    lines.push("LockPersonality=yes".into());
    lines.push("RestrictRealtime=yes".into());
    lines.push("SystemCallFilter=@system-service".into());
    // Empty bounding set: drop every capability.
    lines.push("CapabilityBoundingSet=".into());
    lines.push(format!("StateDirectory={}", spec.snap));
    lines.push(format!("CacheDirectory={}", spec.snap));
    lines.push(format!("LogsDirectory={}", spec.snap));
    if let Some(name) = &effects.bus_name {
        lines.push(format!("BusName={name}"));
    }
    lines.push(String::new());
    lines.push("[Install]".into());
    lines.push("WantedBy=multi-user.target".into());
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// Plan one app's runtime: the staged binary path, the daemon unit when
/// the app is daemon-bearing, and the per-app plug warnings.
pub fn plan_app(spec: &AppUnitSpec) -> AppPlan {
    let in_snap_binary =
        resolve_command_path(&spec.command).unwrap_or_else(|| spec.command.clone());
    let effects = apply_plugs(spec);

    let mut warnings = Vec::new();
    for plug_name in &spec.app_plugs {
        let Some(plug) = spec.snap_plugs.iter().find(|p| &p.name == plug_name) else {
            warnings.push(format!(
                "app '{}': plug '{plug_name}' is not declared at snap level — warn-and-dropped",
                spec.app
            ));
            continue;
        };
        let iface = plug.interface.as_str();
        if is_allowlisted_network(iface) {
            warnings.push(format!(
                "app '{}': plug '{plug_name}' ({iface}) — allowed by default, no directive needed",
                spec.app
            ));
        } else if iface == "home" {
            warnings.push(format!(
                "app '{}': plug '{plug_name}' (home) — home remap not delivered, downgraded to \
                 ProtectHome=read-only; $HOME writes outside StateDirectory are absent",
                spec.app
            ));
        } else if is_device_interface(iface) {
            warnings.push(format!(
                "app '{}': plug '{plug_name}' ({iface}) — PrivateDevices omitted, device access \
                 is unconfined",
                spec.app
            ));
        } else if iface == "dbus" {
            warnings.push(format!(
                "app '{}': plug '{plug_name}' (dbus) — D-Bus mediation is not enforced by stock \
                 systemd; BusName= is ordering-only",
                spec.app
            ));
        }
    }
    for dropped in &effects.dropped {
        warnings.push(format!(
            "app '{}': plug {dropped} — warn-and-dropped (no systemd directive exists)",
            spec.app
        ));
    }

    let daemon = if spec.daemon {
        let text = render_unit(spec, &effects);
        let unit_name = unit_name(&spec.snap, &spec.app);
        Some(DaemonUnit { unit_name, text })
    } else {
        None
    };

    AppPlan {
        snap: spec.snap.clone(),
        app: spec.app.clone(),
        in_snap_binary,
        daemon,
        warnings,
    }
}

// ── Conversion from the eval-side schema (SnapMeta / SnapApp) ──

/// Build a planner spec from the Rust schema types (used by the
/// confinement lint over evaluated outputs).
pub fn spec_from_snap_app(
    snap: &str,
    app_name: &str,
    app: &crate::snap_types::SnapApp,
    snap_plugs: Vec<PlugRef>,
) -> AppUnitSpec {
    AppUnitSpec {
        snap: snap.to_string(),
        app: app_name.to_string(),
        command: app.command.clone(),
        daemon: app.daemon.is_some(),
        app_plugs: app.plugs.clone().unwrap_or_default(),
        environment: app.environment.clone().unwrap_or_default(),
        snap_plugs,
    }
}

// ── Payload meta/snap.yaml parsing (serde side, PR-3 down-move) ──
//
// The payload-facing vocabulary of the runtime emitter: the subset of a
// payload's `meta/snap.yaml` the emitter needs, plus the type-field
// classification. Pure data + pure classification over `snap_types`
// values — the image emitter and the runtime domain name both, so they
// are shared vocabulary (ADR-0051 Decision 3).

/// Build a planner spec from a parsed payload app (used by the
/// image-build emission path).
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
    pub confined: Option<Confinement>,
    /// Services declared by this package (ADR-0032, issue #105), carried
    /// through meta/snap.yaml (written by SnapMeta's Serialize) so the
    /// runtime planner records them in the generation manifest at
    /// install time (issue #106).
    #[serde(default)]
    pub services: BTreeMap<String, ServiceDecl>,
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
    pub confined: Option<Confinement>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
