//! Injected source-fetch capability for multi-source builds.
//!
//! ADR-0053 keeps nau-build network-free (the crate charter: core +
//! infra only), but multi-source builds must download tarballs. The
//! consumer-side trait lives here; the root composition injects an
//! implementation backed by nau-chart's retrying curl seam (429 backoff
//! with UA, the 0afc6e8 policy). `None` at any call site keeps the
//! built-in raw-curl one-shot fallback: today's behavior, and what the
//! unit tests exercise.

use std::path::Path;

/// Fetch `url` into `dest` atomically (a failure must not leave a
/// partial file at `dest`) and fail loud on any non-2xx, naming the
/// status. Implementations carry the network policy; the build path
/// owns only pin enforcement afterwards.
pub trait SourceFetcher {
    fn fetch(&self, url: &str, dest: &Path) -> miette::Result<()>;
}
