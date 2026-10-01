//! A narrow read-only view over a runtime state root (issue #326 PR 5
//! store seam — the `blob_path` → `BlobStore` precedent): the
//! generation-layout knowledge the peer lanes need — which generation
//! is active, where a generation's directory lives — without importing
//! the root runtime domain. The root `RuntimeStore` delegates its own
//! methods here, so there is exactly one on-disk truth.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

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
