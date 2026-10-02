//! nau-trust — nau's trust domain (issue #326 crate extraction).
//!
//! Hosts the ADR-0024 §4 update-manifest signing ceremony's POLICY half
//! ([`sign`]: SLSA-lite provenance, attest/cosign/rotate/revoke, the
//! ledger-policy verify cluster, the sysupdate pubring-fragment
//! persistence), the on-device verify cluster ([`verify`]:
//! `verify_signatures(_at)` — the embedded-anchor walk the install gate
//! consumes via injection), and the coordinator SSH host-CA ceremony
//! ([`ca`], ADR-0045 amendment). Depends on `nau-core` (the keychain
//! core + the eval-manifest schema) and `nau-infra` (the OpenPGP packet
//! primitives, the command seam) — never sideways (ADR-0051 Decision 3).
//!
//! What stayed where: the keychain CORE (key material, on-disk layout,
//! revocation list, ceremony ledger) lives in `nau_core::sign` (PR 3
//! down-move); the OpenPGP packet primitives live in `nau_infra::pgp`
//! (PR 8's primitive/policy split); the image-side sysupdate policy
//! (what the release signs) stays in nau-image; the eval-side
//! CONSTRUCTION (`build_manifest`) stays in nau-chart — the two
//! eval-coupled test clusters accordingly stay in the root crate, whose
//! `sign`/`runtime` modules remain real shim files re-exporting
//! everything here.

pub mod ca;
pub mod sign;
pub mod verify;
