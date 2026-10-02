//! nau-infra — nau's non-domain mechanism leaf (issue #326).
//!
//! Non-domain mechanism leaf; may be depended on by any crate; depends
//! only on `nau-core` (store/assert consume spine vocabulary — R1/R5,
//! issue #326 PR 3); hosts terminal presentation ([`output`]), external
//! tool provisioning ([`tools`]), the command seam ([`command`]), the
//! SSH CA material primitives ([`ssh_ca`]), the store client +
//! assertion gate ([`assert`], [`store`]), and generic PATH search
//! ([`pathsearch`]).
//!
//! Deliberately dependency-light: the only in-workspace dependency is
//! `nau-core` (store/assert consume spine vocabulary — R1/R5, issue #326
//! PR 3); no other nau-* crate may appear in this crate's dependency
//! graph (ADR-0051 dependency direction; asserted by the gate's
//! dep-direction pass).

pub mod archive;
pub mod assert;
pub mod command;
pub mod output;
pub mod pathsearch;
pub mod pgp;
pub mod ssh_ca;
pub mod store;
pub mod tools;

#[cfg(test)]
pub(crate) mod test_env;
