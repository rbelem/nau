//! The verbatim pull-staging inbox lane: copy a peer's staged manifest
//! unchanged, plus its blobs.
//!
//! The stored manifest is read only to learn the blob set and index row
//! — it is never altered or re-signed (it arrived signed from a peer).
//! Its declared blob addresses are still trust-boundary-validated
//! before anything touches `store.blob_path` — a malformed sha256 in a
//! staged manifest never becomes a path.

use std::collections::BTreeSet;
use std::path::PathBuf;

use miette::{IntoDiagnostic, WrapErr};
use nau_core::blob_store::BlobStore;
use nau_core::pkg_manifest::{self, PackageManifest};

use super::layout::IndexPackage;
use super::write::{copy_blob, Sinks};

/// Copy the inbox-only manifests VERBATIM plus their blobs.
pub(super) fn export_inbox(
    blobs: &BlobStore,
    sinks: &Sinks,
    inbox_only: &[&(String, PathBuf)],
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    for (name, path) in inbox_only {
        export_one_staged(blobs, sinks, name, path, copied, packages)?;
    }
    Ok(())
}

/// One staged manifest, verbatim + its blob set, into the tree.
fn export_one_staged(
    blobs: &BlobStore,
    sinks: &Sinks,
    name: &str,
    path: &PathBuf,
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    let raw = std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading staged manifest {}", path.display()))?;
    let manifest: PackageManifest = serde_json::from_slice(&raw).map_err(|e| {
        miette::miette!(
            "staged manifest {} for package '{name}' does not parse: {e}",
            path.display()
        )
    })?;
    validate_staged_hashes(name, &manifest)?;
    std::fs::copy(path, sinks.manifests.join(format!("{name}.json")))
        .into_diagnostic()
        .wrap_err_with(|| format!("copying staged manifest for '{name}'"))?;
    for file in &manifest.files {
        copy_blob(blobs, sinks.blobs, &file.sha256, name, copied)?;
    }
    packages.push(IndexPackage {
        name: name.to_string(),
        version: manifest.version,
        revision: manifest.revision,
    });
    Ok(())
}

/// Trust-boundary validation of a staged manifest's declared blob
/// addresses BEFORE any of them becomes a path: 64 lowercase hex, each.
fn validate_staged_hashes(name: &str, manifest: &PackageManifest) -> miette::Result<()> {
    for file in &manifest.files {
        pkg_manifest::validate_sha256(file)
            .wrap_err_with(|| format!("staged manifest for package '{name}'"))?;
    }
    Ok(())
}
