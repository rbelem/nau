//! The store's shared data record (issue #326 PR 3 down-move).
//!
//! `ResolvedSnap` — the download-and-verify tuple every domain names
//! (image staging, the app-runtime emitter, lockfile recording) — is
//! plain vocabulary over [`crate::snap_types::SnapRef`]: it moves DOWN
//! into the spine (ADR-0051 Decision 3) so the image crate consumes it
//! without a store-client edge. The store CLIENT (queries, curl, the
//! revision-assertion gate) stays in the root package, whose
//! `crate::store` re-exports this type.

use std::path::Path;

use crate::snap_types::SnapRef;

/// A fully resolved snap reference: name + exact revision + content hash.
#[derive(Debug, Clone)]
pub struct ResolvedSnap {
    pub name: String,
    pub revision: u32,
    /// sha3-384 hex digest from the store.
    pub sha3_384: String,
    /// Download URL from the store.
    pub download_url: String,
}

impl ResolvedSnap {
    /// ToSnapRef (without the download URL — for lockfile storage).
    pub fn to_snap_ref(&self) -> SnapRef {
        SnapRef {
            name: self.name.clone(),
            revision: Some(self.revision),
            sha3_384: Some(self.sha3_384.clone()),
        }
    }
}

/// Derive `(name, version, arch?)` from `{name}_{version}_{arch}.snap` /
/// `.img`, or `(name, version)` from `{name}_{version}.img` (issue #326
/// PR 4 down-move: the store-artifact naming grammar, beside
/// [`ResolvedSnap`]).
///
/// Underscore-separated parts beyond the third are ambiguous (a version
/// like `1.0_beta` breaks the shape) and are rejected — push those with
/// an explicit `--tag` instead.
pub fn parse_artifact_filename(path: &Path) -> miette::Result<(String, String, Option<String>)> {
    let file = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| miette::miette!("{}: non-UTF-8 file name", path.display()))?;
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    let parts: Vec<&str> = stem.split('_').collect();
    let (name, version, arch) = match parts.as_slice() {
        [n, v] => (*n, *v, None),
        [n, v, a] => (*n, *v, Some(*a)),
        _ => miette::bail!(
            "{file}: cannot derive name/version/arch — expected \
             {{name}}_{{version}}_{{arch}}.snap or {{name}}_{{version}}.img \
             (file names with extra '_' components are ambiguous; push with \
             an explicit --tag)"
        ),
    };
    if name.is_empty() || version.is_empty() {
        miette::bail!("{file}: empty name or version component");
    }
    Ok((
        name.to_string(),
        version.to_string(),
        arch.map(str::to_string),
    ))
}
