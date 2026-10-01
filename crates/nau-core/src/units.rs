//! The pure app-runtime unit planner — hardened systemd-unit vocabulary
//! shared by the image emitter and the chart confinement lint (ADR-0051
//! Decision 3). Pure computation over [`crate::snap_types`] values: no
//! I/O, no runner, no presentation.

use std::collections::BTreeMap;

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
