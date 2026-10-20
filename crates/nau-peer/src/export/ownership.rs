//! Ownership and pruning (ADR-0033 Decision 10): the `.nau-export`
//! marker and the stale-entry cleanup its presence licenses.
//!
//! Every export writes a `.nau-export` marker at the out root
//! (content: the tree format version). On a re-export of a directory
//! that HAS the marker, stale entries are pruned: manifests and blobs
//! no longer part of the exportable set are removed, so a mirror never
//! advertises packages the pod dropped. A directory WITHOUT the marker
//! was not written by nau — it accumulates exactly as before, deleting
//! nothing it did not write (and gets claimed by the marker from that
//! export on).

use std::collections::BTreeSet;
use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use super::layout::IndexPackage;

/// The ownership marker written at the out root on every export
/// (ADR-0033 Decision 10): its presence proves nau wrote the tree,
/// licensing re-export pruning.
pub(super) const MARKER_FILE: &str = ".nau-export";

/// The marker's content: the export-tree format version, one line.
pub(super) const MARKER_VERSION: &str = "v1";

/// Claim (or re-assert) ownership of `out`: the marker is written on
/// EVERY export, so the next export may prune (ADR-0033 Decision 10).
/// A first export into a foreign directory claims it from then on.
pub(super) fn write_marker(out: &Path) -> miette::Result<()> {
    let path = out.join(MARKER_FILE);
    std::fs::write(&path, format!("{MARKER_VERSION}\n"))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))
}

/// The manifest file names the current exportable set owns — the keep
/// set for `manifests/` pruning.
pub(super) fn manifest_names(packages: &[IndexPackage]) -> BTreeSet<String> {
    packages
        .iter()
        .map(|p| format!("{}.json", p.name))
        .collect()
}

/// Remove manifests and blobs left over from earlier exports that the
/// current exportable set no longer covers. Only ever called on an
/// owned tree (the [`MARKER_FILE`] gate): entries the current export
/// wrote are exactly the keep sets, everything else is a straggler.
pub(super) fn prune_stale(
    manifests_dir: &Path,
    blobs_dir: &Path,
    keep_manifests: &BTreeSet<String>,
    keep_blobs: &BTreeSet<String>,
) -> miette::Result<()> {
    prune_dir(manifests_dir, keep_manifests)?;
    prune_dir(blobs_dir, keep_blobs)
}

/// Remove the plain files of `dir` whose names are not in `keep`.
/// Anything not a plain file (a foreign subdirectory, say) is left
/// alone — pruning reclaims nau's own stale entries, nothing else.
fn prune_dir(dir: &Path, keep: &BTreeSet<String>) -> miette::Result<()> {
    for entry in std::fs::read_dir(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", dir.display()))?
    {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if keep.contains(&name) || !is_file {
            continue;
        }
        std::fs::remove_file(entry.path())
            .into_diagnostic()
            .wrap_err_with(|| format!("pruning stale export entry {}", entry.path().display()))?;
    }
    Ok(())
}
