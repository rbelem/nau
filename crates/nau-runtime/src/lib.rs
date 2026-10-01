//! nau-runtime — nau's on-device runtime domain (issue #326 crate
//! extraction).
//!
//! Hosts the generation/content-store machinery ([`runtime`]:
//! [`runtime::RuntimeStore`] — install/remove/rollback/gc, the
//! crash-recovery journal, sysext presentation + activation, the
//! payload-tree recording that turns a squashfs payload into
//! content-addressed blobs, and the injected-verifier install gate) and
//! the A/B slot-recovery assessment ([`slot_recovery`], issue #80: the
//! factory device's stranded-slot walk).
//!
//! Layout truth stays in `nau_core` (amendments 8/9): every read path
//! delegates to [`nau_core::generation_view::StoreView`] /
//! [`nau_core::blob_store::BlobStore`] — the crate owns the MUTATION
//! machinery, never a second copy of the on-disk grammar. The
//! ADR-0011 eval-manifest signature gate is INJECTED into
//! `install_batch` (the 9c loader-seam precedent): the trust domain
//! (verify cluster, cosign/attest) stays in the root crate until
//! nau-trust extracts. RuntimeTools (systemctl actuation + squashfs
//! resolution) moved with the runtime; `services.rs` stays root and
//! consumes it via the root re-export (amendment 9a, root composes
//! all).
//!
//! The root `nau` package keeps `src/runtime.rs` as a real shim file
//! (the verify cluster + its cosign/attest suite) re-exporting
//! everything here, so every pre-existing `crate::runtime::` path keeps
//! resolving without churn.

pub mod runtime;
pub mod slot_recovery;

#[cfg(test)]
pub(crate) mod test_env;
