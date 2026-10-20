//! Peer and static-lane `pull` (ADR-0033 Decisions 5, 7, 10) — the
//! ROOT-side command glue (issue #326 PR 4): the transport lane itself
//! (fetch, trust walk, tree-index gate, staging) moved to `nau-ship`
//! (`nau_ship::pull_peer`, re-exported below). This module keeps what
//! rides the pod boundary: the pod-store resolution (`run`), the
//! operator keychain location, the report printing, and the lane's
//! tests — whose fixtures drive the REAL runtime store
//! (`RuntimeStore`/`Generation`), which never enters the ship crate.

use std::path::PathBuf;

pub use nau_ship::pull_peer::*;

use crate::pod;
use crate::pull_ref::PullRef;

/// The operator's keychain dir (`~/.config/nau/keys`, HOME resolved —
/// `.` when unreadable, matching `crate::sign::keys_dir`).
fn operator_keys_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    nau_core::sign::keys_dir(&PathBuf::from(home))
}

/// Run a peer or static pull for `source` into the named pod (`None` =
/// the default pod). `allow_downgrade` lifts the freshness rule's
/// older-revision refusal (ADR-0033 Decision 7). Trust anchors come
/// from the device image (`/etc/nau/update-key.pub` — the runtime
/// anchor) AND the operator keychain. Verifies and stages;
/// installation stays the pod workflow.
///
/// Root-side because it resolves the pod's runtime store: the freshness
/// gate's installed-revision input is read HERE (the ship crate takes
/// it as a parameter — its `BlobStore` view cannot see generations).
pub fn run(source: &PullRef, pod: Option<&str>, allow_downgrade: bool) -> miette::Result<()> {
    let store = pod::resolve_pod_store(pod)?;
    let keys = operator_keys_dir();
    let anchor = PathBuf::from(crate::runtime::DEVICE_ANCHOR);
    let pkg = pkg_name(source)?.to_string();
    let installed = store
        .active_generation()?
        .and_then(|g| g.packages.get(&pkg).map(|p| p.revision));
    let blob_store = store.blob_store();
    let report = pull_into_store(
        &blob_store,
        installed,
        source,
        &anchor,
        &keys,
        allow_downgrade,
        &CurlFetch,
    )?;
    print_report(&report);
    Ok(())
}

/// JSON when `--json` set the global mode; a human summary otherwise.
fn print_report(report: &PullPeerReport) {
    if crate::output::is_json() {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_default()
        );
        return;
    }
    crate::output::ok(format!(
        "staged {} {} revision {} from {} {} — signature verified (key {})",
        report.package,
        report.version,
        report.revision,
        report.lane,
        report.reference,
        report.signer
    ));
    crate::output::info(format!(
        "blobs: {} fetched, {} already in store",
        report.fetched.len(),
        report.already_present.len()
    ));
    crate::output::info(format!(
        "manifest staged at {} — install stays the pod workflow",
        report.staged_manifest
    ));
}

#[cfg(test)]
mod tests;
