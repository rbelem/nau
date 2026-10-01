//! On-disk location vocabulary (issue #326 PR 3, R4 down-move).
//!
//! The documented default roots the runtime store and the image state
//! layer both name. Plain `&'static str` constants — shared vocabulary
//! (ADR-0051 Decision 3), so the image crate consumes them from the
//! spine instead of the runtime domain. `RuntimeStore` re-exports them
//! from the root crate.

/// Default state root for generations + the content store.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/nau";

/// Sysext link directory the extensions link dir defaults to.
pub const DEFAULT_EXTENSIONS_LINK_DIR: &str = "/var/lib/extensions";
