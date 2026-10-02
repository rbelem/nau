pub use nau_infra::{command, output, store, tools};

pub use nau_chart::{
    analysis, audit, checks, dep_fetch, deps, dsl, index, isolate, lint, lock, lua, manifest,
    pkg_source,
};

pub mod assert;
pub mod build_orch;
pub mod build_sched;
pub mod cli;
pub mod commands;
pub mod coordinator;
pub mod doctor;
pub mod farm_dispatch;
pub mod leak_scan;
pub mod pkg_manifest;
pub mod plugins;
pub mod pod;
pub mod provision;
pub mod pull_peer;
pub mod runtime;
pub mod secrets;
pub mod services;
pub mod sign;
// The build domain (issue #326 PR 2): snap/cache/build_prefix/
// source_cache moved to nau-build; the plain re-export keeps every
// `crate::<module>::` path resolving. snap and leak_scan stay root shim
// FILES instead (they also carry chart-side re-exports, respectively the
// root-only `listings_for_build`) — see src/snap.rs, src/leak_scan.rs.
pub use nau_build::{build_prefix, cache, source_cache};
pub use nau_core::manifest_ir;
pub use nau_core::snap_types;
// The image domain (issue #326 PR 3): image/uc/boot_test/esp/emit moved
// to nau-image; units stays a root shim FILE (it carries the unit
// vocabulary re-export; the emission half lives in nau-image::units).
pub use nau_image::{boot_test, emit, esp, image, uc};
// The ship domain (issue #326 PR 4): oci stays a root shim FILE (it
// carries the root-side `pending_from_blob` — the pull --install
// revision resolution rides the runtime's lockfile records); pull_ref
// and the peer-lane glue re-export from nau-ship.
pub use nau_ship::pull_ref;
// The peer domain (issue #326 PR 5): discovery/serve/export moved
// whole (the serve/export signatures now take the resolved pod roots —
// the env-reading `pod_root`/`pod_store` stay root); the plain
// re-export keeps every `crate::<module>::` path resolving.
pub use nau_peer::{discovery, export, serve};
// The pod domain (issue #326 PR 6): confine/desktop/fonts/farm moved
// whole (emitters take the core `StoreView` seam); `secrets` stays a
// root shim FILE (it keeps the `pod secrets` verb layer + its suite —
// see src/secrets.rs); the pod grammar's pure halves re-export from
// src/pod.rs, which remains the orchestrator file.
pub use nau_pod::{confine, desktop, farm, fonts};
// The runtime domain (issue #326 PR 7): RuntimeStore + the mutation
// machinery + slot_recovery moved to nau-runtime; src/runtime.rs stays
// a real shim FILE (the verify cluster + its cosign/attest suite —
// the trust domain, later crate) re-exporting the moved names.
pub use nau_runtime::slot_recovery;
// The trust domain (issue #326 PR 8): the signing ceremony policy, the
// device verify cluster, and the SSH host-CA ceremony. sign.rs and
// runtime.rs stay real shim FILES (the eval-coupled test clusters live
// there); ca is a pure re-export.
pub use nau_trust::ca;
pub mod oci;
pub mod snap;
pub mod ssh_exec;
#[cfg(test)]
pub(crate) mod test_env;
pub mod units;
pub mod worker;
