//! The root `leak_scan` shim (issue #326 PR 2): the scan machinery moved
//! to `nau-build` (`crates/nau-build/src/leak_scan.rs`); every
//! pre-existing `crate::leak_scan::` path keeps resolving through the
//! re-export below.
//!
//! `listings_for_build` stays ROOT, verbatim: it resolves the runtime
//! closure through `nau-chart`'s `deps` module, and a `nau-build`
//! → nau-chart edge on the normal axis would breach the dep-direction
//! table ({nau-core, nau-infra} only). Its consumers are all root-side
//! (pod.rs, worker.rs, build_orch.rs), so the function did not need to
//! move with the scanner. The reconciliation PR that dissolves the
//! §4 chart dev-edge should revisit this placement.

pub use nau_build::leak_scan::*;

/// The leak-scan resolution data (ADR-0018 Decision 3, issue #22) for one
/// build: every payload the merged build prefix materialized (`requires` ∪
/// `build_deps`), split into runtime-closure members (transitive
/// `requires`) vs build-only. A DT_NEEDED soname must resolve into a
/// runtime payload or the package's own stage — never a build-only one.
pub fn listings_for_build(
    meta: &crate::snap::SnapMeta,
    prefix: &crate::build_prefix::MergedPrefix,
) -> miette::Result<PayloadListings> {
    let mut listings = PayloadListings::default();
    if !meta.requires.is_empty() {
        listings.runtime = crate::deps::resolve_dep_names(&meta.requires, true)?
            .into_iter()
            .collect();
    }
    for (pkg, files) in prefix.payload_files() {
        listings.payloads.insert(pkg, files);
    }
    Ok(listings)
}
