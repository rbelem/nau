//! nau-pool — the pool/farm domain (issue #326 PR 9, ADR-0053).
//!
//! The worker fleet: the SSH transport ([`ssh_exec`]) that drives one
//! Worker over bounded argv, the farm build scheduler ([`build_sched`])
//! that spreads the ready set across coordinator slots + SSH channels,
//! the machine provisioning lane ([`provision`]) — providers, the
//! publish/issue/pickup ceremony, the burst window, the managed
//! `workers` block — and the worker wire protocol ([`worker`]): the
//! `jm1:`-identified job manifests, capability documents, and result
//! documents that cross the channel.
//!
//! Depends on `nau-core` + `nau-infra` only — never sideways; the root
//! composes every domain (ADR-0051 dependency direction; asserted by
//! the gate's dep-direction pass).

pub mod build_sched;
pub mod provision;
pub mod ssh_exec;
pub mod worker;
