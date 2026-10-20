//! The per-mission curation list (#275): the package names one
//! mission pins, and their resolution against the pod's generation.
//!
//! The pin set is the mission's existing `image()` declaration — the
//! names [`ImageDeclaration::all_snaps`] collects (base, kernel, gadget,
//! declared snaps) — no new schema. A pinned name the pool does not hold
//! is a hard, named error BEFORE anything is written: a mirror missing a
//! mission's pinned package would hand its users an unverifiable tree.
//! The pull-staging inbox is out of scope for a curated export — a
//! mission pins a closed set; staged peer content is not the released
//! pool.

use std::collections::BTreeSet;

use nau_core::manifest_ir::ImageDeclaration;
use nau_core::pkg_manifest::Generation;

/// The per-mission curation list (#275): the package names one mission
/// pins, applied at export time. A set — the base/kernel/gadget refs
/// may repeat a name, and set semantics keep the resolved pin set
/// canonical.
pub type Curation = BTreeSet<String>;

/// The curation list of one mission: the names its `image()`
/// declaration pins. This is the existing mission schema — the same
/// declaration `nau image --output-name` builds from; export adds
/// no new pin format.
pub fn mission_curation(image: &ImageDeclaration) -> Curation {
    image
        .all_snaps()
        .into_iter()
        .map(|snap| snap.name.clone())
        .collect()
}

/// Resolve a curation list against the pool's generation: every pinned
/// name must be exportable, fail-closed (naming the missing pins —
/// sorted, since `Curation` iteration is ordered). Returns the keep
/// set the generation walk filters on.
pub(super) fn resolve_pins(
    generation: &Option<Generation>,
    pins: &Curation,
) -> miette::Result<BTreeSet<String>> {
    if pins.is_empty() {
        miette::bail!("mission pins no packages — nothing to curate");
    }
    let mut resolved = BTreeSet::new();
    let mut missing = Vec::new();
    for name in pins {
        if generation
            .as_ref()
            .is_some_and(|g| g.packages.contains_key(name))
        {
            resolved.insert(name.clone());
        } else {
            missing.push(name.clone());
        }
    }
    if !missing.is_empty() {
        miette::bail!(
            "mission pool is missing pinned package(s): {} — refusing \
             to export an incomplete curated tree",
            missing.join(", ")
        );
    }
    Ok(resolved)
}
