//! The store's shared data record (issue #326 PR 3 down-move).
//!
//! `ResolvedSnap` — the download-and-verify tuple every domain names
//! (image staging, the app-runtime emitter, lockfile recording) — is
//! plain vocabulary over [`crate::snap_types::SnapRef`]: it moves DOWN
//! into the spine (ADR-0051 Decision 3) so the image crate consumes it
//! without a store-client edge. The store CLIENT (queries, curl, the
//! revision-assertion gate) stays in the root package, whose
//! `crate::store` re-exports this type.

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
