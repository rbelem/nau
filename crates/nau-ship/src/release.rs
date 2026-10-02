//! The release seam (ADR-0052 Decision 5): turn a built `.snap` into a
//! signed `PackageManifest` plus blobs uploaded to rustfs (S3 API), served
//! by the Caddy front as the static tree `nau pull` already consumes.
//!
//! This file is the CONTRACT for #328 lane B; the drain (lane A) consumes
//! exactly these names. Bodies are stubs until lane B lands.

use std::path::PathBuf;

/// One rustfs (S3-compatible) target: the API endpoint base, the bucket
/// that backs the static tree, and the credentials the drain's release
/// step signs requests with.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct S3Target {
    /// S3 API base, e.g. `https://s3.internal.example` (no bucket path).
    pub endpoint: String,
    pub bucket: String,
    /// SigV4 region string (rustfs accepts any consistent value).
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
}

/// Everything the drain hands to [`release`]: the built artifact, its
/// identity, the update-manifest signing key, the S3 target, and the
/// public base URL the Caddy front serves the tree under (what
/// `manifest_url`/`blob_urls` are reported against).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReleaseInput {
    /// Built `.snap` artifact to publish.
    pub snap_path: PathBuf,
    /// Package name (e.g. `opencode-bin`).
    pub package: String,
    /// Released version (must match the snap's declared version).
    pub version: String,
    /// Update-manifest signing key material (the trust root the puller
    /// already verifies against; see `pull_peer::verify_trust`).
    pub signing_key: PathBuf,
    pub s3: S3Target,
    /// Public static-tree base, e.g. `https://download.example/nau`.
    pub tree_base: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReleaseOutput {
    /// URL the signed PackageManifest is served at.
    pub manifest_url: String,
    /// URLs every uploaded blob is served at (sha256-addressed).
    pub blob_urls: Vec<String>,
}

/// Sign and publish one artifact: verify the snap's identity against
/// `input.package`/`input.version`, build the `PackageManifest` with
/// sha256-addressed blobs, sign it with the update-manifest key, upload
/// manifest + blobs to rustfs (SigV4 PUT), and report the public URLs.
///
/// Fail-closed rules mirror the puller's verify chain: a manifest that
/// would not pass `pull_peer`'s parse/target/trust gates is never
/// uploaded. Partial uploads are harmless (orphaned blobs, no manifest).
pub fn release(input: &ReleaseInput) -> miette::Result<ReleaseOutput> {
    let _ = input;
    miette::bail!("release: not implemented (#328 lane B)")
}
