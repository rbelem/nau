//! `shuttle serve` — the peer lane's read-only serving surface
//! (ADR-0033 Decisions 4+5): plain TCP with a minimal HTTP/1.1 subset
//! over the pod store (`GET /info`, `GET /manifests/<pkg>`,
//! `GET /blobs/<sha256>`), foreground until interrupted. This skeleton
//! only pins the entry signature `main.rs` dispatches to so the CLI
//! surface lands before the implementation; the serve lane fills the
//! body in.

/// Run `shuttle serve` with the CLI's bind overrides. `address`/`port`
/// are `None` when the operator gave no flag — the defaults come from
/// `node {}` (`serve.address`) and the ADR's loopback default.
pub fn run(address: Option<&str>, port: Option<u16>) -> miette::Result<()> {
    let _ = (address, port);
    miette::bail!("not implemented: implemented by the serve lane")
}
