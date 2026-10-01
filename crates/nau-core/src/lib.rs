//! nau-core — the shared spine of the `nau` workspace (ADR-0051).
//!
//! Deliberately dependency-light: std, serde, and serde_json only. Every
//! other workspace member may depend on this crate; it depends on none of
//! them. Domain vocabulary lives here the moment two domains need to talk.
//!
//! The root `nau` package re-exports these modules (`pub use nau_core::…`
//! in its lib) so every pre-existing `crate::snap_types::` /
//! `crate::manifest_ir::` path keeps resolving without churn.

pub mod manifest_ir;
pub mod snap_types;
