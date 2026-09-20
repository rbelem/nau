//! `shuttle export` — the static-HTTP lane (ADR-0033 Decision 10):
//! freeze a pod store's shareable content as a plain directory tree
//! (`index.json`, `manifests/<pkg>.json`, `blobs/<sha256>`) any web
//! server can serve — the same layout the `serve` endpoints expose, one
//! to one. This skeleton only pins the entry signature `main.rs`
//! dispatches to; the export lane fills the body in.

/// Run `shuttle export` into `out` for the named pod (`None` = the
/// default pod).
pub fn run(out: &str, pod: Option<&str>) -> miette::Result<()> {
    let _ = (out, pod);
    miette::bail!("not implemented: implemented by the export lane")
}
