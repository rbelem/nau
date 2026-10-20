//! The walk that fills the tree: mint + sign the generation's
//! manifests, copy the staged ones, and copy every blob once.
//!
//! ADR-0033 Decision 2: unsigned store entries are never served — the
//! signing key is required and its absence is a named error.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use nau_core::blob_store::BlobStore;
use nau_core::pkg_manifest::{self, Generation};
use nau_core::sign::KeyPair;

use super::layout::{write_json, IndexPackage};
use super::staged::export_inbox;

/// The write destinations of one export run: the tree's `manifests/`
/// and `blobs/` directories plus the signing-key home. Bundled so the
/// walk helpers take one destination argument, not three.
pub(super) struct Sinks<'a> {
    pub(super) manifests: &'a Path,
    pub(super) blobs: &'a Path,
    pub(super) home: &'a Path,
}

/// Export every manifest + blob of the current exportable set into the
/// tree. Returns the copied blob hashes (the `blobs/` keep set) and
/// the index rows (from which the `manifests/` keep set derives).
pub(super) fn write_tree(
    blobs: &BlobStore,
    sinks: &Sinks,
    generation: &Option<Generation>,
    inbox_only: &[&(String, PathBuf)],
    keep: Option<&BTreeSet<String>>,
) -> miette::Result<(BTreeSet<String>, Vec<IndexPackage>)> {
    // Dedup across packages: a shared blob is copied once (content
    // addressing makes re-copies byte-identical, so this is purely
    // fewer syscalls — never a divergence risk).
    let mut copied: BTreeSet<String> = BTreeSet::new();
    let mut packages: Vec<IndexPackage> = Vec::new();

    if let Some(gen) = generation {
        export_generation(blobs, sinks, gen, keep, &mut copied, &mut packages)?;
    }
    export_inbox(blobs, sinks, inbox_only, &mut copied, &mut packages)?;
    Ok((copied, packages))
}

/// Mint + sign one manifest per generation package and copy its blobs
/// (ADR-0033 Decision 2: unsigned store entries are never served — the
/// signing key is required and its absence is a named error). `keep`
/// narrows the walk to a mission's pinned names (`None` = all).
fn export_generation(
    blobs: &BlobStore,
    sinks: &Sinks,
    gen: &Generation,
    keep: Option<&BTreeSet<String>>,
    copied: &mut BTreeSet<String>,
    packages: &mut Vec<IndexPackage>,
) -> miette::Result<()> {
    let mut signing: Option<KeyPair> = None;
    // BTreeMap iteration: sorted by name — deterministic tree, and the
    // first missing-blob error is the alphabetically first package.
    for record in gen.packages.values() {
        if let Some(keep) = keep {
            if !keep.contains(&record.name) {
                continue;
            }
        }
        if signing.is_none() {
            signing = Some(pkg_manifest::load_signing_key(sinks.home)?);
        }
        let mut manifest = pkg_manifest::mint_manifest(record);
        pkg_manifest::sign(&mut manifest, signing.as_ref().expect("key loaded above"))?;
        write_json(
            &sinks.manifests.join(format!("{}.json", record.name)),
            &manifest,
        )?;
        for hash in &record.files {
            copy_blob(blobs, sinks.blobs, hash, &record.name, copied)?;
        }
        packages.push(IndexPackage {
            name: record.name.clone(),
            version: record.version.clone(),
            revision: record.revision,
        });
    }
    Ok(())
}

/// Copy one content blob from the store into the tree. Already-copied
/// hashes are skipped (dedup); a missing source is a HARD error naming
/// the package and hash — a partial tree must never be published
/// (fail-closed, ADR-0033 Decision 10).
pub(super) fn copy_blob(
    blobs: &BlobStore,
    blobs_dir: &Path,
    sha256: &str,
    pkg: &str,
    copied: &mut BTreeSet<String>,
) -> miette::Result<()> {
    if !copied.insert(sha256.to_string()) {
        return Ok(());
    }
    let src = blobs.blob_path(sha256);
    if !src.exists() {
        miette::bail!(
            "package '{pkg}': store blob {sha256} is missing at {} — \
             refusing to export an incomplete tree",
            src.display()
        );
    }
    let dst = blobs_dir.join(sha256);
    std::fs::copy(&src, &dst)
        .into_diagnostic()
        .wrap_err_with(|| format!("copying blob {} → {}", src.display(), dst.display()))?;
    Ok(())
}
