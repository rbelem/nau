//! `pod list`'s version resolution and rendering (issue #3).
//!
//! A listed version has three possible provenances, in falling order of
//! authority:
//!
//! 1. **installed** — the pod's active generation recorded it as
//!    installed ([`nau_core::generation_view::active_generation`]). This
//!    is what the pod actually runs.
//! 2. **pinned** — the pod's lockfile resolved and pinned it, but the
//!    pod has never installed it (or the active generation predates the
//!    package).
//! 3. **recipe** — only the package recipe declares it; nothing has
//!    resolved it for this pod yet.
//!
//! Before the three-way split, a pod with no readable lockfile reported
//! the recipe version forever, so an installed pod could drift from its
//! recipe with nothing reporting it. The source is rendered beside each
//! version so the operator can tell which of the three was shown.
//!
//! The state-directory reconciliation the same issue observed (nau and
//! shuttle roots coexisting, extensions symlinked across them) is a data
//! migration, not a read-path change; it is untouched here.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{
    evaluate_pod_file, load_pod_lock, load_spec_meta, parse_pod_package, pod_dir, pod_lua_path,
    validate_pod_name, PodListEntry,
};

/// Where a `pod list` version came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionSource {
    /// The active generation's manifest records the package installed.
    Installed,
    /// The pod lockfile pins it; nothing installed it yet.
    Pinned,
    /// Only the recipe declares it.
    Recipe,
    /// No recipe resolved and no installed record.
    Unresolved,
}

impl VersionSource {
    /// The word rendered in the output's source column (JSON uses the
    /// same lowercase spelling).
    pub fn tag(self) -> &'static str {
        match self {
            VersionSource::Installed => "installed",
            VersionSource::Pinned => "pinned",
            VersionSource::Recipe => "recipe",
            VersionSource::Unresolved => "unresolved",
        }
    }
}

/// The versions a pod's ACTIVE generation records, keyed by package
/// name. A pod with no active generation yields an empty map.
pub struct InstalledVersions(BTreeMap<String, String>);

impl InstalledVersions {
    /// Read the active generation's installed versions.
    ///
    /// A missing `active` link is "nothing installed" (`Ok(empty)`). A
    /// present-but-unreadable generation is an error, not a silent
    /// fallback to recipe versions — that fallback is the bug this
    /// module exists to fix.
    pub fn load(state_root: &Path) -> miette::Result<InstalledVersions> {
        let active = nau_core::generation_view::active_generation(state_root)?;
        Ok(InstalledVersions(
            active
                .map(|gen| {
                    gen.packages
                        .into_iter()
                        .map(|(name, pkg)| (name, pkg.version))
                        .collect()
                })
                .unwrap_or_default(),
        ))
    }

    /// Installed version of `name`, when the active generation has it.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// Resolve one package's version in authority order: installed, then
/// lockfile pin, then recipe. `recipe` is a closure so a pinned and
/// installed package never pays for a collection lookup.
pub fn resolve(
    pin: Option<&str>,
    installed: Option<&str>,
    recipe: impl FnOnce() -> Option<String>,
) -> (Option<String>, VersionSource) {
    if let Some(version) = installed {
        return (Some(version.to_string()), VersionSource::Installed);
    }
    if let Some(version) = pin {
        return (Some(version.to_string()), VersionSource::Pinned);
    }
    match recipe() {
        Some(version) => (Some(version), VersionSource::Recipe),
        None => (None, VersionSource::Unresolved),
    }
}

/// List a pod's packages with resolved versions, at the authority order
/// above. Read verbs do not initialize pods: an unknown pod (no
/// `pod.lua`) is a clear error — `nau pod add` is what initializes a
/// pod. Moved here from `src/pod.rs` (issue #3): the file is over the
/// token budget and this is its own job.
pub fn list_packages(root: &Path, pod_name: &str) -> miette::Result<Vec<PodListEntry>> {
    validate_pod_name(pod_name)?;
    let decl_path = pod_lua_path(root, pod_name);
    if !decl_path.exists() {
        miette::bail!(
            "pod '{pod_name}' has no declaration at {} (read verbs do not \
             initialize pods; `nau pod --name {pod_name} add <package>` does)",
            decl_path.display()
        );
    }
    let decl = evaluate_pod_file(&decl_path)?;
    let lock = load_pod_lock(root, pod_name)?;
    let installed = InstalledVersions::load(&pod_dir(root, pod_name))?;

    let mut entries = Vec::new();
    for spec_str in &decl.packages {
        let spec = parse_pod_package(spec_str)?;
        let pin = lock
            .as_ref()
            .and_then(|l| l.packages.get(&spec.name))
            .map(|e| e.version.as_str());
        let (version, source) = resolve(pin, installed.get(&spec.name), || {
            load_spec_meta(&spec).ok().map(|m| m.version)
        });
        // Float marking (ADR-0017): the overlay wins, else the
        // declaration itself. Resolution failure is not a float.
        let floating = match decl
            .overlay
            .get(&spec.name)
            .and_then(|p| p.get("floating"))
            .and_then(|v| v.as_bool())
        {
            Some(b) => b,
            None => load_spec_meta(&spec).map(|m| m.floating).unwrap_or(false),
        };
        entries.push(PodListEntry {
            spec: spec_str.clone(),
            name: spec.name,
            constraint: spec.constraint,
            version,
            pinned: source == VersionSource::Pinned,
            source,
            floating,
        });
    }
    Ok(entries)
}


/// Render `nau pod list`: one `spec  version  source` row per package,
/// with the ADR-0017 float marking kept as the trailing `(float)`.
/// Columns are space-separated and the source word is drawn from a
/// fixed vocabulary, so the output stays parseable.
pub fn print(pod_name: &str, entries: &[PodListEntry]) {
    if entries.is_empty() {
        crate::output::info(format!("pod '{pod_name}' has no packages"));
        return;
    }
    let width = entries.iter().map(|e| e.spec.len()).max().unwrap_or(0);
    let version_width = entries
        .iter()
        .map(|e| e.version.as_deref().unwrap_or("(unresolved)").len())
        .max()
        .unwrap_or(0);
    for entry in entries {
        let version = entry.version.as_deref().unwrap_or("(unresolved)");
        // Float marking (ADR-0017): floating packages say so, last.
        let tag = if entry.floating { " (float)" } else { "" };
        crate::output::status(format!(
            "{:<width$}  {:<version_width$}  {}{}",
            entry.spec,
            version,
            entry.source.tag(),
            tag,
            width = width,
            version_width = version_width,
        ));
    }
}
