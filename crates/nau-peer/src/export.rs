//! `nau export` — the static-HTTP lane (ADR-0033 Decision 10):
//! freeze a pod store's shareable content as a plain directory tree
//! (`index.json`, `manifests/<pkg>.json`, `blobs/<sha256>`) any web
//! server can serve — the same layout the `serve` endpoints expose, one
//! to one. `index.json` is the `/info` payload; the manifests are
//! signed [`PackageManifest`]s (ADR-0033 Decision 2); the blobs are the
//! content-addressed store set, copied (never moved — the store keeps
//! its own copies).
//!
//! # Module map
//!
//! Grouped by job, one item family per file:
//!
//! - [`mission`] — the per-mission curation list (#275) and its
//!   resolution against the pool.
//! - [`pool`] — which packages this run publishes (the union rule) and
//!   the empty-store refusal.
//! - [`layout`] — the tree's on-disk shape: `index.json`'s rows, the
//!   directories, and the deterministic JSON writer.
//! - [`ownership`] — the `.nau-export` marker and the stale-entry
//!   pruning its presence licenses.
//! - [`staged`] — the verbatim pull-staging inbox lane and the
//!   trust-boundary validation of the addresses it carries.
//! - [`write`] — the walk that mints, copies, and dedups the blob set.
//!
//! `run`/`run_mission` keep the ADR-0033 Decision 10 fail-closed
//! contract at the top: curation resolves before the tree is touched,
//! the ownership decision is taken from the directory AS FOUND, pruning
//! lands before the index, and `index.json` is written LAST.
//!
//! # Determinism
//!
//! A re-export of the same pool + mission is byte-identical: packages
//! iterate in `BTreeMap` order, JSON is written in struct field order,
//! and the ed25519 signature is deterministic (RFC 8032) — same store,
//! same key, same bytes.
//!
//! Issue #326 PR 5 (crate extraction): the env-reading pod roots stay
//! root — the caller resolves `pod_root(None)` and hands it in; the
//! store view consumed here is the narrow core seam
//! ([`nau_core::blob_store::BlobStore`] + the generation view), never
//! the root `RuntimeStore`.

use std::path::{Path, PathBuf};

use nau_core::blob_store::BlobStore;
use nau_core::generation_view;

mod layout;
mod mission;
mod ownership;
mod pool;
mod staged;
mod write;

#[cfg(test)]
mod tests;

use layout::{prepare_dirs, write_json, IndexJson};
use mission::resolve_pins;
use ownership::{manifest_names, prune_stale, write_marker, MARKER_FILE};
use pool::{ensure_exportable, select_pool};
use write::{write_tree, Sinks};

// The root crate's `commands.rs` reaches these three through
// `crate::export`; nothing else crosses the crate boundary.
pub use mission::{mission_curation, Curation};

/// Run `nau export` into `out` for the named pod (`None` = the
/// default pod). `pod_root` is the pod state root the flag resolves
/// under — resolved by the root glue (the env-reading `pod_root` stays
/// root).
pub fn run(out: &str, pod_root: &Path, pod: Option<&str>) -> miette::Result<()> {
    export_at(out, pod_root, pod, None)
}

/// Run a CURATED `nau export` (#275): only the packages `curation`
/// pins, for the named pod. Every pinned name must be in the pool —
/// anything else is a named, fail-closed error before the tree is
/// touched.
pub fn run_mission(
    out: &str,
    pod_root: &Path,
    pod: Option<&str>,
    curation: &Curation,
) -> miette::Result<()> {
    export_at(out, pod_root, pod, Some(curation))
}

fn export_at(
    out: &str,
    pod_root: &Path,
    pod: Option<&str>,
    curation: Option<&Curation>,
) -> miette::Result<()> {
    let pod_name = pod.unwrap_or(nau_core::paths::DEFAULT_POD);
    let dir = nau_core::paths::pod_dir(pod_root, pod_name);
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    run_at(
        Path::new(out),
        &dir,
        // The store dir half of the runtime state layout
        // (`<state root>/store` — the component the inbox helpers
        // derive from), built straight over it via the core seam.
        &BlobStore::new(dir.join("store")),
        &home,
        curation,
    )
}

/// Export the pod store rooted at `state_root` into `out`, signing
/// minted manifests with the operator key under `home`. Split from
/// [`run`] so tests can inject the store root and signing-key home.
/// `curation` narrows the export to a mission's pinned set (`None` =
/// the whole exportable store, the historical behavior).
fn run_at(
    out: &Path,
    state_root: &Path,
    blobs: &BlobStore,
    home: &Path,
    curation: Option<&Curation>,
) -> miette::Result<()> {
    let generation = generation_view::active_generation(state_root)?;
    // Curation resolves BEFORE the tree is touched: a mission pinning a
    // package the pool does not hold is a named error, never a partial
    // mirror.
    let keep = curation
        .map(|pins| resolve_pins(&generation, pins))
        .transpose()?;
    let (inbox, generation_has_packages) = select_pool(state_root, &generation, &keep)?;
    let inbox_only = nau_core::pkg_manifest::union_inbox(&generation, &inbox);
    ensure_exportable(state_root, generation_has_packages, &inbox_only)?;
    let (manifests_dir, blobs_dir) = prepare_dirs(out)?;
    // Ownership is decided from the directory AS FOUND: a tree nau
    // wrote before (marker present) gets stale-entry pruning this
    // export; a foreign directory accumulates, deleting nothing.
    let owned = out.join(MARKER_FILE).exists();

    let (copied, mut packages) = write_tree(
        blobs,
        &Sinks {
            manifests: &manifests_dir,
            blobs: &blobs_dir,
            home,
        },
        &generation,
        &inbox_only,
        keep.as_ref(),
    )?;

    // Canonical index order regardless of generation-vs-inbox split.
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    // Prune BEFORE the index lands: an owned tree briefly carrying a
    // fresh index beside stale entries is the one state that lets a
    // mirror advertise content the pod dropped.
    if owned {
        prune_stale(
            &manifests_dir,
            &blobs_dir,
            &manifest_names(&packages),
            &copied,
        )?;
    }
    write_marker(out)?;

    // index.json is written LAST: a half-updated mirror never advertises
    // packages whose manifests/blobs have not landed yet.
    let index = IndexJson {
        name: nau_core::pkg_manifest::hostname(),
        packages,
    };
    write_json(&out.join("index.json"), &index)
}
