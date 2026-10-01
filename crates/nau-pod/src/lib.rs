//! nau-pod — nau's pod domain (issue #326 crate extraction).
//!
//! Hosts the pod's per-generation emit family — the bin farm
//! ([`farm`], direct store symlinks + the `current` activation link),
//! the user-level launchers ([`desktop`]) and fonts ([`fonts`]) — the
//! `nau run` confinement backend ([`confine`]: bwrap/AppArmor, fail
//! closed), pod secret resolution ([`secrets`]: ADR-0042's one resolve
//! entry point + the tmpfs session cache), and the pod grammar's PURE
//! halves ([`pod`]: declaration/lockfile paths, package specs, the
//! `PodDeclaration` shape, `pod.lua` rendering, the load-graph walks,
//! env/secrets folding, the interactive shellenv).
//!
//! Depends on `nau-core` (the shared spine) and `nau-infra`
//! (mechanism) — never sideways (ADR-0051 Decision 3). The
//! eval-coupled and lifecycle halves of the root `pod` module stay
//! root (PR-1/PR-4 orchestrator precedent): `pod_root` (env-reading —
//! the ratified amendment-8 ruling), declaration EVAL (mlua), the
//! overlays, all mutating verbs, and the service-override validation;
//! this crate's load-graph walks take the declaration loader as a
//! parameter so the eval-coupled loader stays root-injected.
//!
//! The emitter signatures take [`nau_core::generation_view::StoreView`]
//! (the narrow read-only generation+blob view, amendment 8) instead of
//! the root `RuntimeStore`; the root glue converts via
//! `RuntimeStore::store_view()`.

pub mod confine;
pub mod desktop;
pub mod farm;
pub mod fonts;
pub mod pod;
pub mod secrets;

#[cfg(test)]
pub(crate) mod test_env;
