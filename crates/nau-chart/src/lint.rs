//! Confinement lint (ADR-0011 step (g), decision 3).
//!
//! Rust-side `nau check` stage-2 pass over the evaluated outputs:
//! when a snap declares `confinement = "strict"` — the default, so this
//! fires often — it warns that snapd's dynamic strict confinement is
//! formally not delivered (interface composition, D-Bus mediation, home
//! remapping), lists dropped plugs, and — best-effort, when the binary
//! exists — runs `systemd-analyze security --offline` over each
//! generated unit shape, surfacing the exposure score.
//!
//! # Severity
//!
//! WARNING, never error: the lint adds NO failure modes. `nau
//! check`'s ok/fail computation never consults these warnings; they are
//! reported through the warn channel (human mode) and the `"lint"` JSON
//! array (machine mode). The oracle is absent-binary-safe: without
//! `systemd-analyze` the lint falls back to a static Tier-1 presence
//! assertion over the rendered unit.

use std::collections::BTreeMap;

use crate::lua::Outputs;
use nau_core::snap_types::SnapPlug;
use nau_core::units::{self, AppUnitSpec, DaemonUnit, PlugRef};

/// One lint finding: the output key it belongs to plus the message.
#[derive(Debug, Clone, PartialEq)]
pub struct LintWarning {
    pub key: String,
    pub message: String,
}

/// Tier-1 directives every emitted unit must carry (the private_devices
/// omission for device interfaces is the only sanctioned gap and is
/// asserted separately).
const TIER1_DIRECTIVES: [&str; 15] = [
    "Type=exec",
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
];

/// Tier-1 directives missing from a rendered unit — empty for every
/// unit this crate renders (a regression guard, and the static
/// fallback note when the oracle binary is absent).
pub fn tier1_missing(unit: &DaemonUnit) -> Vec<String> {
    TIER1_DIRECTIVES
        .iter()
        .filter(|d| !unit.text.contains(*d))
        .map(|d| (*d).to_string())
        .collect()
}

/// Convert a snap's typed plugs into planner plug refs.
fn plug_refs(meta: &nau_core::snap_types::SnapMeta) -> Vec<PlugRef> {
    let mut refs = Vec::new();
    for (name, plug) in meta.plugs.iter().flatten() {
        match plug {
            SnapPlug::Name(interface) => refs.push(PlugRef::new(name, interface)),
            SnapPlug::Typed(slot) => {
                let mut r = PlugRef::new(name, &slot.interface);
                for (k, v) in &slot.attributes {
                    r.attributes.insert(k.clone(), v.clone());
                }
                refs.push(r);
            }
        }
    }
    refs
}

/// Run the confinement lint over evaluated outputs. Deterministic:
/// outputs are visited in sorted key order and the oracle runs
/// per daemon app in sorted app order.
pub fn confinement_lint(outputs: &Outputs) -> Vec<LintWarning> {
    let mut warnings = Vec::new();
    let mut keys: Vec<&String> = outputs.keys().collect();
    keys.sort();
    for key in keys {
        let meta = &outputs[key];
        if meta.confinement != "strict" {
            continue;
        }
        warnings.push(lint_one(key, meta));
    }
    warnings
}

/// Lint one strict-confinement snap.
fn lint_one(key: &str, meta: &nau_core::snap_types::SnapMeta) -> LintWarning {
    let snap_plugs = plug_refs(meta);
    let mut dropped: Vec<String> = Vec::new();
    let mut oracle_notes: Vec<String> = Vec::new();

    // Deterministic app order.
    let mut apps: Vec<(&String, &nau_core::snap_types::SnapApp)> = meta.apps.iter().collect();
    apps.sort_by(|a, b| a.0.cmp(b.0));

    for (app_name, app) in &apps {
        let spec: AppUnitSpec =
            units::spec_from_snap_app(&meta.name, app_name, app, snap_plugs.clone());
        let plan = units::plan_app(&spec);
        for warning in &plan.warnings {
            if warning.contains("warn-and-dropped") {
                dropped.push(format!("{app_name}: {warning}"));
            }
        }
        if let Some(unit) = &plan.daemon {
            oracle_notes.push(oracle_note(unit));
        }
    }

    let mut message = format!(
        "confinement 'strict' for '{}' is not fully delivered: dynamic interface composition, \
         D-Bus mediation, and home remapping are not enforced (ADR-0011)",
        meta.name
    );
    if !dropped.is_empty() {
        message.push_str(&format!("; dropped plugs: {}", dropped.join(", ")));
    }
    for note in &oracle_notes {
        message.push_str("; ");
        message.push_str(note);
    }

    LintWarning {
        key: key.to_string(),
        message,
    }
}

/// Best-effort `systemd-analyze security --offline` over one rendered
/// unit. Returns the exposure score when the oracle exists; otherwise a
/// static Tier-1 note. Never errors — an oracle failure degrades to the
/// static note.
fn oracle_note(unit: &DaemonUnit) -> String {
    let present = std::process::Command::new("which")
        .arg("systemd-analyze")
        .output()
        .ok()
        .is_some_and(|o| o.status.success());
    if !present {
        let missing = tier1_missing(unit);
        return if missing.is_empty() {
            format!(
                "{}: systemd-analyze not found — static lint only (Tier-1 directives asserted present)",
                unit.unit_name
            )
        } else {
            format!(
                "{}: systemd-analyze not found — static lint only (Tier-1 directives missing: {})",
                unit.unit_name,
                missing.join(", ")
            )
        };
    }

    let run = (|| -> Option<String> {
        let dir = tempfile::tempdir().ok()?;
        let path = dir.path().join(&unit.unit_name);
        std::fs::write(&path, &unit.text).ok()?;
        // --threshold takes an integer on current systemd ("5.0" fails
        // to parse); non-zero exit above threshold, exposure 0-10.
        let out = std::process::Command::new("systemd-analyze")
            .args(["security", "--offline=true", "--threshold=5"])
            .arg(&path)
            .output()
            .ok()?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let score = combined
            .lines()
            .find_map(|l| {
                // The line carries a status-arrow prefix ("→ Overall
                // exposure level for X.service: 3.4 OK 🙂") — locate
                // the sentence, don't strip-prefix the line.
                let idx = l.find("Overall exposure level for ")?;
                let rest = &l[idx + "Overall exposure level for ".len()..];
                let colon = rest.find(": ")?;
                rest[colon + 2..]
                    .split_whitespace()
                    .next()
                    .map(String::from)
            })
            .unwrap_or_else(|| "unparsed".into());
        Some(format!(
            "{}: systemd-analyze security exposure {score}/10 (offline, threshold 5)",
            unit.unit_name
        ))
    })();
    run.unwrap_or_else(|| {
        let missing = tier1_missing(unit);
        if missing.is_empty() {
            format!(
                "{}: systemd-analyze failed — static lint only (Tier-1 asserted)",
                unit.unit_name
            )
        } else {
            format!(
                "{}: systemd-analyze failed — static lint only (Tier-1 directives missing: {})",
                unit.unit_name,
                missing.join(", ")
            )
        }
    })
}

// ── Version-suffix lint (ADR-0047 D5, issue #260) ──

/// Split a `<base><digits>` name into its base — moved DOWN into
/// `nau_core::snap_types` (issue #326 PR 6: the pod farm's collision
/// classifier consumes it too); re-exported so the lint and every
/// `nau_chart::lint::split_version_suffix` path keeps resolving.
pub use nau_core::snap_types::split_version_suffix;

/// The eval lint (ADR-0047 Decision 5, #260): warn when a package name
/// matches `<base><digits>` AND its unsuffixed base is also in the
/// evaluated set — a suffixed sibling renaming itself to dodge its own
/// base is the warnable anti-pattern shape. A `<base><digits>` name with
/// no base sibling in the set survives cleanly: a genuinely different
/// product may deliberately own the name (the anti-pattern's documented
/// escape hatch), so this is a WARNING, never an error — the message
/// points at `name@constraint` (ADR-0047), the only spelling of a second
/// version line.
pub fn version_suffix_lint(outputs: &Outputs) -> Vec<LintWarning> {
    let names: std::collections::BTreeSet<&str> =
        outputs.values().map(|m| m.name.as_str()).collect();
    let mut warnings = Vec::new();
    let mut keys: Vec<&String> = outputs.keys().collect();
    keys.sort();
    for key in keys {
        let meta = &outputs[key];
        let Some(base) = split_version_suffix(&meta.name) else {
            continue;
        };
        if !names.contains(base) {
            continue;
        }
        warnings.push(LintWarning {
            key: key.clone(),
            message: format!(
                "package '{}' reads as the version-suffix anti-pattern — a second \
                 version line is `{base}@constraint` in another pod; see ADR-0047",
                meta.name
            ),
        });
    }
    warnings
}

/// Convenience for `nau check`: lint warnings keyed for the JSON
/// report (`{"key", "message"}` pairs).
pub fn lint_json(warnings: &[LintWarning]) -> Vec<BTreeMap<&'static str, String>> {
    warnings
        .iter()
        .map(|w| BTreeMap::from([("key", w.key.clone()), ("message", w.message.clone())]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::snap_types::{SnapApp, SnapMeta};
    use std::collections::HashMap;

    fn strict_meta(name: &str) -> SnapMeta {
        SnapMeta {
            name: name.to_string(),
            version: "1.0".into(),
            version_adopted: false,
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            architectures: None,
            build: None,
            parts: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
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
            apps: HashMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn daemon_app(command: &str, plugs: Option<Vec<String>>) -> SnapApp {
        SnapApp {
            command: command.to_string(),
            daemon: Some("simple".into()),
            plugs,
            slots: None,
            environment: None,
            desktop: None,
            interpreter: None,
            confined: None,
        }
    }

    #[test]
    fn strict_confinement_produces_a_warning() {
        let mut outputs = Outputs::new();
        let mut meta = strict_meta("my-snap");
        meta.apps.insert("main".into(), daemon_app("bin/srv", None));
        outputs.insert("default".into(), meta);
        let lint = confinement_lint(&outputs);
        assert_eq!(lint.len(), 1);
        assert_eq!(lint[0].key, "default");
        assert!(
            lint[0].message.contains("strict")
                && lint[0].message.contains("not fully delivered")
                && lint[0].message.contains("D-Bus mediation"),
            "warning must name the gap: {}",
            lint[0].message
        );
    }

    #[test]
    fn non_strict_confinement_is_silent() {
        let mut outputs = Outputs::new();
        let mut meta = strict_meta("classic-snap");
        meta.confinement = "classic".into();
        meta.apps.insert("main".into(), daemon_app("bin/srv", None));
        outputs.insert("default".into(), meta);
        assert!(confinement_lint(&outputs).is_empty());
    }

    #[test]
    fn dropped_plugs_are_listed_in_the_warning() {
        let mut outputs = Outputs::new();
        let mut meta = strict_meta("gui-snap");
        meta.plugs = Some(BTreeMap::from([
            ("network".into(), SnapPlug::Name("network".into())),
            (
                "weird".into(),
                SnapPlug::Name("some-exotic-interface".into()),
            ),
        ]));
        meta.apps.insert(
            "main".into(),
            daemon_app("bin/srv", Some(vec!["weird".into(), "ghost".into()])),
        );
        outputs.insert("default".into(), meta);
        let lint = confinement_lint(&outputs);
        assert_eq!(lint.len(), 1);
        let msg = &lint[0].message;
        assert!(
            msg.contains("dropped plugs:")
                && msg.contains("weird")
                && msg.contains("some-exotic-interface")
                && msg.contains("ghost"),
            "dropped plugs (named) must be listed: {msg}"
        );
        // Allowed-by-default plugs are never dropped.
        assert!(
            !msg.contains("network ("),
            "network must not appear as dropped: {msg}"
        );
    }

    #[test]
    fn oracle_note_is_static_when_binary_absent_or_fails() {
        // Unit shape straight from the planner — either the oracle ran
        // (score surfaced) or the static fallback fired; both must name
        // the unit.
        let spec = AppUnitSpec {
            snap: "s".into(),
            app: "a".into(),
            command: "bin/x".into(),
            daemon: true,
            app_plugs: vec![],
            environment: BTreeMap::new(),
            snap_plugs: vec![],
        };
        let unit = units::plan_app(&spec).daemon.unwrap();
        let note = oracle_note(&unit);
        assert!(note.starts_with("s-a.service: "), "{note}");
        let oracle_ran = note.contains("exposure");
        let static_fired = note.contains("static lint only");
        assert!(
            oracle_ran ^ static_fired,
            "exactly one of oracle/static must fire: {note}"
        );
    }

    #[test]
    fn tier1_missing_catches_a_stripped_unit() {
        let spec = AppUnitSpec {
            snap: "s".into(),
            app: "a".into(),
            command: "bin/x".into(),
            daemon: true,
            app_plugs: vec![],
            environment: BTreeMap::new(),
            snap_plugs: vec![],
        };
        let mut unit = units::plan_app(&spec).daemon.unwrap();
        assert!(tier1_missing(&unit).is_empty());
        unit.text = unit.text.replace("NoNewPrivileges=yes\n", "");
        assert_eq!(
            tier1_missing(&unit),
            vec!["NoNewPrivileges=yes".to_string()]
        );
    }

    #[test]
    fn lint_json_pairs_keep_key_and_message() {
        let warnings = vec![LintWarning {
            key: "k".into(),
            message: "m".into(),
        }];
        let json = lint_json(&warnings);
        assert_eq!(json[0]["key"], "k");
        assert_eq!(json[0]["message"], "m");
    }

    // ── version_suffix_lint (ADR-0047 D5, #260) ──

    #[test]
    fn suffixed_sibling_name_warns_with_the_adr_pointer() {
        let mut outputs = Outputs::new();
        outputs.insert("default".into(), strict_meta("node"));
        outputs.insert("lts".into(), strict_meta("node22"));
        let lint = version_suffix_lint(&outputs);
        assert_eq!(lint.len(), 1, "only the suffixed sibling warns: {lint:?}");
        assert_eq!(lint[0].key, "lts");
        let msg = &lint[0].message;
        assert!(
            msg.contains("a second version line is `node@constraint` in another pod")
                && msg.contains("ADR-0047"),
            "warning must carry the name@constraint remedy and the ADR pointer: {msg}"
        );
    }

    #[test]
    fn unsuffixed_names_and_baseless_suffixed_names_survive() {
        // foo2 has no `foo` sibling in the set: a legitimate non-version
        // name (the escape hatch) — silent.
        let mut outputs = Outputs::new();
        outputs.insert("default".into(), strict_meta("foo2"));
        outputs.insert("other".into(), strict_meta("bar"));
        assert!(
            version_suffix_lint(&outputs).is_empty(),
            "a <base><digits> name with no base sibling must survive"
        );
        // A plain unsuffixed set is silent.
        let mut outputs = Outputs::new();
        outputs.insert("default".into(), strict_meta("node"));
        assert!(version_suffix_lint(&outputs).is_empty());
        // Digits-only and non-trailing-digit names have no base to dodge.
        let mut outputs = Outputs::new();
        outputs.insert("a".into(), strict_meta("22"));
        outputs.insert("b".into(), strict_meta("foo2bar"));
        assert!(version_suffix_lint(&outputs).is_empty());
    }

    #[test]
    fn split_version_suffix_shape() {
        assert_eq!(super::split_version_suffix("node22"), Some("node"));
        assert_eq!(super::split_version_suffix("gtk3"), Some("gtk"));
        assert_eq!(super::split_version_suffix("node"), None);
        assert_eq!(super::split_version_suffix("22"), None);
        assert_eq!(super::split_version_suffix("foo2bar"), None);
        assert_eq!(super::split_version_suffix(""), None);
    }
}
