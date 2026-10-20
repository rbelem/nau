//! The frozen tree's on-disk shape: `index.json` and its rows, the
//! two content directories, and the deterministic JSON writer.
//!
//! `index.json` is the static mirror's `/info` payload (ADR-0033
//! Decision 10) and the manifest/blob directories are the same layout
//! `serve` exposes, one to one.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use serde::{Deserialize, Serialize};

/// One package row of `index.json`.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct IndexPackage {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) revision: u32,
}

/// `index.json` — the static mirror's `/info` payload (ADR-0033
/// Decision 10): the publishing host name plus every exportable
/// package.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct IndexJson {
    pub(super) name: String,
    pub(super) packages: Vec<IndexPackage>,
}

/// Create the tree's directories. Idempotent: create and overwrite in
/// place; never clear `out` — an operator may hold unrelated files
/// beside the tree.
pub(super) fn prepare_dirs(out: &Path) -> miette::Result<(PathBuf, PathBuf)> {
    let manifests_dir = out.join("manifests");
    let blobs_dir = out.join("blobs");
    std::fs::create_dir_all(&manifests_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", manifests_dir.display()))?;
    std::fs::create_dir_all(&blobs_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", blobs_dir.display()))?;
    Ok((manifests_dir, blobs_dir))
}

// Minting lives in [`pkg_manifest::mint_manifest`] — the one mint both
// serve and export call, so a mirror's `manifests/<pkg>.json` is byte-
// identical to what `/manifests/<pkg>` serves (ADR-0033 Decision 2).
// The inbox listing is [`pkg_manifest::inbox_manifests`] and the
// publishing host name [`pkg_manifest::hostname`] — both shared with
// `serve /info`.

/// Stable serde JSON to disk (struct field order + BTreeMap key order =
/// deterministic bytes; pretty-printed for mirror inspection).
pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> miette::Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| miette::miette!("serialize {}: {e}", path.display()))?;
    std::fs::write(path, bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", path.display()))
}
