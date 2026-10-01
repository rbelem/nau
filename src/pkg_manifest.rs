//! The signed per-package shareable manifest (ADR-0033 Decision 2) — the
//! one genuinely new artifact peer sharing introduces.
//!
//! Issue #326 PR 4 moved the wire half (the schema, canonical bytes, and
//! the sign/verify wrapping) DOWN into `nau_core::pkg_manifest`; PR 5
//! moved the MINTING half (`mint_manifest`, `load_signing_key`,
//! `inbox_manifests`, `union_inbox`) down too — once the install records
//! (`InstalledPackage`, `Generation`) landed in core, the whole module
//! is core vocabulary. This root module is a pure re-export shim; every
//! pre-existing `crate::pkg_manifest::` path keeps resolving.

pub use nau_core::pkg_manifest::{
    canonical_bytes, host_target, hostname, inbox_manifests, load_signing_key, manifest_path,
    mint_manifest, sign, union_inbox, validate_payload_path, validate_sha256, verify, AppAssembly,
    DesktopIcon, DesktopLauncher, InstallMeta, ManifestFile, PackageManifest,
};
