//! nau-build — nau's build domain (issue #326 crate extraction).
//!
//! Hosts the snap build machinery (`snap`: the staging/pack/wrapper path
//! from `build_snap` down to mksquashfs), the build cache (`cache`), the
//! merged build prefix (`build_prefix`), the post-build leak scan
//! (`leak_scan`), and the content-addressed source cache
//! (`source_cache`). Depends on `nau-core` (the shared spine) and
//! `nau-infra` (presentation + tool provisioning + the archive quad) —
//! never sideways (ADR-0051 Decision 3).
//!
//! The root `nau` package re-exports these modules so every pre-existing
//! `nau::<module>` path keeps resolving without churn.
//!
//! Tests here drive the Lua constructors through the §4 sanctioned
//! dev-edge on `nau-chart` (ADR-0053) — the edge expires at the final
//! reconciliation PR.

pub mod build_prefix;
pub mod cache;
pub mod leak_scan;
pub mod snap;
pub mod source_cache;
pub mod source_fetch;

pub use source_fetch::SourceFetcher;

#[cfg(test)]
pub(crate) mod test_env;
