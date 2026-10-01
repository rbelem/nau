pub use nau_infra::{output, tools};

pub use nau_chart::{
    analysis, audit, checks, dep_fetch, deps, dsl, index, isolate, lint, lock, lua, manifest,
    pkg_source,
};

pub mod assert;
pub mod boot_test;
pub mod build_orch;
pub mod build_sched;
pub mod ca;
pub mod cli;
pub mod command;
pub mod commands;
pub mod confine;
pub mod coordinator;
pub mod desktop;
pub mod discovery;
pub mod doctor;
pub mod emit;
pub mod esp;
pub mod export;
pub mod farm;
pub mod farm_dispatch;
pub mod fonts;
pub mod image;
pub mod leak_scan;
pub mod oci;
pub mod pkg_manifest;
pub mod plugins;
pub mod pod;
pub mod provision;
pub mod pull_peer;
pub mod pull_ref;
pub mod runtime;
pub mod secrets;
pub mod serve;
pub mod services;
pub mod sign;
pub mod slot_recovery;
// The build domain (issue #326 PR 2): snap/cache/build_prefix/
// source_cache moved to nau-build; the plain re-export keeps every
// `crate::<module>::` path resolving. snap and leak_scan stay root shim
// FILES instead (they also carry chart-side re-exports, respectively the
// root-only `listings_for_build`) — see src/snap.rs, src/leak_scan.rs.
pub use nau_build::{build_prefix, cache, source_cache};
pub use nau_core::manifest_ir;
pub use nau_core::snap_types;
pub mod snap;
pub mod ssh_exec;
pub mod store;
#[cfg(test)]
pub(crate) mod test_env;
pub mod uc;
pub mod units;
pub mod worker;
