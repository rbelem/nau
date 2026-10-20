//! Which packages one export publishes.
//!
//! # Union rule (ADR-0033 Decision 5 invariant)
//!
//! Export publishes the UNION of the active generation's packages and
//! the pull-staging inbox (`nau_core::pkg_manifest::manifest_path`): an
//! inbox manifest whose name is not in the generation is still visible,
//! copied VERBATIM (it arrived signed from a peer — re-signing it here
//! would rewrite provenance). Names present in the generation are
//! minted fresh from the generation records and signed under this
//! host's key.
//!
//! # Fail-closed
//!
//! An empty store (no generation packages, no inbox) is a clear error,
//! not an empty tree.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nau_core::pkg_manifest::{self, Generation};

/// The exportable pool split for this run: the staged-inbox additions
/// (empty under curation — a mission pins a closed set, staged peer
/// content is not the released pool) and whether the generation itself
/// carries anything to export.
pub(super) fn select_pool(
    state_root: &Path,
    generation: &Option<Generation>,
    keep: &Option<BTreeSet<String>>,
) -> miette::Result<(Vec<(String, PathBuf)>, bool)> {
    match keep {
        Some(keep) => Ok((Vec::new(), !keep.is_empty())),
        None => {
            let inbox = pkg_manifest::inbox_manifests(state_root)?;
            let generation_has_packages =
                generation.as_ref().is_some_and(|g| !g.packages.is_empty());
            Ok((inbox, generation_has_packages))
        }
    }
}

/// An empty store is a clear error, not an empty tree: nothing is
/// exportable when the generation carries no packages AND the inbox is
/// empty. `generation_has_packages` arrives pre-computed (under
/// curation it reflects the resolved keep set, not the raw generation).
pub(super) fn ensure_exportable(
    store_root: &Path,
    generation_has_packages: bool,
    inbox_only: &[&(String, PathBuf)],
) -> miette::Result<()> {
    if !generation_has_packages && inbox_only.is_empty() {
        miette::bail!(
            "pod store {} is empty — no installed packages and no staged \
             peer manifests; nothing to export",
            store_root.display()
        );
    }
    Ok(())
}
