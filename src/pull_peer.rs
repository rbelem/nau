//! Peer and static-lane `pull` (ADR-0033 Decisions 5, 7, 10): fetch a
//! signed [`crate::pkg_manifest::PackageManifest`] plus its missing
//! blobs from a `shuttle://` peer or an `http(s)://` export tree,
//! verify fail-closed (signature first against the trusted-key set,
//! then every blob hash), and stage into the named pod's store — the
//! pull-staging inbox (`crate::pkg_manifest::manifest_path`).
//! Installation stays the pod workflow, never a pull side effect. This
//! skeleton only pins the entry signature `main.rs` dispatches to; the
//! pull lane fills the body in.

use crate::pull_ref::PullRef;

/// Run a peer or static pull for `source` into the named pod (`None` =
/// the default pod). `allow_downgrade` lifts the freshness rule's
/// older-revision refusal (ADR-0033 Decision 7).
pub fn run(source: &PullRef, pod: Option<&str>, allow_downgrade: bool) -> miette::Result<()> {
    let _ = (source, pod, allow_downgrade);
    miette::bail!("not implemented: implemented by the pull lane")
}
