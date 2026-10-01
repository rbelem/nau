//! App execution — the unit vocabulary shim (issue #326 PR 3).
//!
//! The pure planner AND the payload meta/snap.yaml vocabulary live in
//! `nau_core::units`; the image-build emission half moved to `nau-image`
//! (`nau_image::units`). This root module re-exports the vocabulary so
//! every pre-existing `crate::units::` path keeps resolving.

pub use nau_core::units::{
    classify, plan_app, resolve_command_path, spec_from_payload_app, spec_from_snap_app,
    staged_binary_rel, unit_name, AppPlan, AppUnitSpec, DaemonUnit, PayloadApp, PayloadPlug,
    PayloadSnap, PlugRef, RuntimeClass,
};
