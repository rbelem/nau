//! nau-chart — nau's definition/eval domain (ADR-0049 chart verbs;
//! issue #326 crate extraction).
//!
//! Hosts the Lua DSL prelude, the eval engine, the bounded subprocess
//! workers, the Luau strict-analyzer gate, the check/lint/audit
//! batteries, lockfiles, the package index, and the dependency
//! resolver/fetcher. Depends on `nau-core` (the shared spine) and
//! `nau-infra` (presentation + tool provisioning) — never sideways
//! (ADR-0051 Decision 3).
//!
//! The root `nau` package re-exports these modules (`pub use
//! nau_chart::…` in its lib) so every pre-existing `nau::<module>` path
//! keeps resolving without churn.

pub mod analysis;
pub mod audit;
pub mod checks;
pub mod commands;
pub mod dep_fetch;
pub mod deps;
pub mod dsl;
pub mod index;
pub mod isolate;
pub mod lint;
pub use nau_core::lock;
pub mod lua;
pub mod manifest;
pub use nau_core::pkg_source;
pub mod snap_lua;

pub use snap_lua::{FromLuaTable, FromLuaTableNamed, FromLuaValue, FromPinTable};
