//! A narrow read-only view over a runtime state root (issue #326 PR 5
//! store seam — the `blob_path` → `BlobStore` precedent): the
//! generation-layout knowledge the peer lanes need — which generation
//! is active, where a generation's directory lives — without importing
//! the root runtime domain. The root `RuntimeStore` delegates its own
//! methods here, so there is exactly one on-disk truth.
//!
//! Issue #326 PR 6 promotes the `(state root, blob store)` pair into
//! [`StoreView`] (amendment 8: "promote the pair to a struct if more
//! consumers appear") — the pod emit family (farm/desktop/fonts) and
//! `nau run`'s confinement resolve consume the view instead of the root
//! `RuntimeStore`. The pairing invariant: the blob store is the
//! `<state-root>/store` directory of the same state root.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use crate::blob_store::BlobStore;
use crate::pkg_manifest::Generation;

/// Directory of generation `n` under `state_root`:
/// `<state_root>/generations/<n>` (manifest + per-package extension
/// trees + the farm). The pod farm emitter hangs per-generation
/// artifacts off it.
pub fn generation_dir(state_root: &Path, n: u64) -> PathBuf {
    state_root.join("generations").join(n.to_string())
}

/// The generation `active` points at, or `None` when nothing is
/// installed yet. Extracted verbatim from the root
/// `RuntimeStore::active_generation` (issue #326 PR 5), which delegates
/// here.
pub fn active_generation(state_root: &Path) -> miette::Result<Option<Generation>> {
    let link = state_root.join("active");
    let target = match std::fs::read_link(&link) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
        return Err(miette::miette!(
            "active symlink {} points at a non-generation target {:?}",
            link.display(),
            target
        ));
    };
    let n: u64 = name
        .parse()
        .map_err(|_| miette::miette!("active symlink points at non-numeric generation {name:?}"))?;
    let manifest = generation_dir(state_root, n).join("manifest.json");
    let text = std::fs::read_to_string(&manifest)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", manifest.display()))?;
    let gen = serde_json::from_str(&text)
        .map_err(|e| miette::miette!("corrupt generation manifest {}: {e}", manifest.display()))?;
    Ok(Some(gen))
}

/// The narrow read-only store view over one state root (issue #326 PR
/// 6): the generation-read seam plus its PAIRED content-blob store (the
/// `<state-root>/store` invariant, amendment 8) — what the pod emit
/// family and the peer lanes consume in place of the root
/// `RuntimeStore`. Every method delegates to the free fns above /
/// [`BlobStore`]: one on-disk truth, two shapes.
#[derive(Debug, Clone)]
pub struct StoreView {
    state_root: PathBuf,
    blob_store: BlobStore,
}

impl StoreView {
    /// View over `state_root` with its paired content-blob store (the
    /// `<state-root>/store` directory of the same root).
    pub fn new(state_root: impl Into<PathBuf>, blob_store: BlobStore) -> StoreView {
        StoreView {
            state_root: state_root.into(),
            blob_store,
        }
    }

    /// The state root this view reads (generation manifests, the
    /// `active` link, the manifest inbox).
    pub fn root(&self) -> &Path {
        &self.state_root
    }

    /// Directory of generation `n` under this view's state root.
    pub fn generation_dir(&self, n: u64) -> PathBuf {
        generation_dir(&self.state_root, n)
    }

    /// The generation `active` points at, or `None` when nothing is
    /// installed yet.
    pub fn active_generation(&self) -> miette::Result<Option<Generation>> {
        active_generation(&self.state_root)
    }

    /// Path of the content blob with hash `sha256` in the paired store.
    pub fn blob_path(&self, sha256: &str) -> PathBuf {
        self.blob_store.blob_path(sha256)
    }

    /// The paired content-blob store handle (for lanes that need the
    /// [`BlobStore`] itself — `write_blob`, the dep-fetcher seam).
    pub fn blobs(&self) -> &BlobStore {
        &self.blob_store
    }
}
