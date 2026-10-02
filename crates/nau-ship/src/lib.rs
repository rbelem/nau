//! nau-ship — nau's ship domain (issue #326 crate extraction).
//!
//! Hosts the OCI registry client ([`oci`]: push/pull/mount over the
//! registry wire grammar, with the curl-behind-the-command-seam
//! transport), the pull reference grammar ([`pull_ref`]: the
//! `nau://peer` / `http(s)://tree` / registry lanes), the peer and
//! static pull transport lane ([`pull_peer`]: fail-closed trust walk,
//! tree-index gate, blob staging into the store's manifest inbox), the
//! rustfs SigV4 client ([`s3`]), and the release seam ([`release`]:
//! ADR-0052 Decision 5 — `.snap` → signed manifest + blobs in the
//! static tree the pull lane consumes).
//! Depends on `nau-core` (the shared spine) and `nau-infra`
//! (mechanism) — never sideways (ADR-0051 Decision 3).
//!
//! The root `nau` package re-exports these modules so every
//! pre-existing `nau::<module>` path keeps resolving without churn.
//! The `pull --install` revision resolution stays in the root crate
//! (its `pending_from_blob` rides the runtime's lockfile records and
//! install batch).

pub mod oci;
pub mod pull_peer;
pub mod pull_ref;
pub mod release;
pub mod s3;
