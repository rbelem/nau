//! nau-core — the shared spine of the `nau` workspace (ADR-0051).
//!
//! Deliberately dependency-light: std, serde, serde_json, sha2, and
//! miette only. Every other workspace member may depend on this crate;
//! it depends on none of them. Domain vocabulary lives here the moment
//! two domains need to talk (ADR-0051 Decision 3).
//!
//! The root `nau` package re-exports these modules (`pub use nau_core::…`
//! in its lib) so every pre-existing `crate::snap_types::` /
//! `crate::manifest_ir::` path keeps resolving without churn.

pub mod blob_store;
pub mod cache_key;
pub mod channels;
pub mod index;
pub mod lock;
pub mod manifest_ir;
pub mod pkg_source;
pub mod plugins;
pub mod snap;
pub mod snap_types;
pub mod units;

/// The parallel build-phase worker budget (ADR-0022). The constant is
/// vocabulary shared by the build scheduler and the chart eval engine's
/// default worker config (issue #326), so it lives in the spine; the
/// root `build_sched` re-exports it.
pub const MAX_PARALLEL_BUILD_WORKERS: usize = 3;

#[cfg(test)]
pub(crate) mod test_env;
