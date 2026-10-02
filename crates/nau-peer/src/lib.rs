//! nau-peer — nau's peer domain (issue #326 crate extraction).
//!
//! Hosts the mDNS peer discovery ([`discovery`]: `nau serve` announces
//! the pod store as `_nau._tcp.local.`, `nau peers` browses), the
//! serving surface ([`serve`]: `GET /info`, `GET /manifests/<pkg>`,
//! `GET /blobs/<sha256>` over the pod store, normative wire grammar,
//! plus the ONE token-gated write route `POST /build-requests`,
//! ADR-0052 Decision 4), the build-request queue that route feeds
//! ([`queue`]: file-backed, atomic writes, claim-by-rename), and the
//! static export lane ([`export`]: the frozen directory tree any web
//! server can serve — the same union rule and the same one-mint helper
//! as `serve`). Depends on `nau-core` (the shared spine) and
//! `nau-infra` (mechanism) — never sideways (ADR-0051 Decision 3).
//!
//! The env-reading pod roots (`pod_root`/`pod_store`) stay in the root
//! crate: the root glue resolves them and hands the roots down. The
//! CLI grammar (`cli.rs` — frozen) and the `commands.rs` orchestrators
//! stay root too; the domain logic is fully in this crate.

pub mod discovery;
pub mod export;
pub mod queue;
pub mod serve;
