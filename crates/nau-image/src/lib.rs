//! nau-image — nau's image domain (issue #326 crate extraction).
//!
//! Hosts the UC image build (`image`: staging, partitioning, boot
//! assembly, initramfs, verity, mounts, the UC seed, piboot, release
//! media, state, verify), the disk-image emitter (`emit`), the ESP
//! plumbing (`esp`), the boot-test harness (`boot_test`), the UC seed
//! assertion machinery (`uc`), the app-runtime unit emission
//! (`units`), the image-layout audits (`audit`), and the sysupdate
//! OpenPGP signing layer (`sysupdate`). Depends on `nau-core` (the
//! shared spine) and `nau-infra` (mechanism) — never sideways
//! (ADR-0051 Decision 3).
//!
//! The root `nau` package re-exports these modules so every
//! pre-existing `nau::<module>` path keeps resolving without churn.

pub mod audit;
pub mod boot_test;
pub mod emit;
pub mod esp;
pub mod image;
pub mod sysupdate;
pub mod uc;
pub mod units;

#[cfg(test)]
pub(crate) mod test_env;
