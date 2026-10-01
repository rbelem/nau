//! nau-infra — nau's non-domain leaf (issue #326).
//!
//! Non-domain leaf; may be depended on by any crate; depends on nothing
//! in-workspace; hosts terminal presentation ([`output`]) and
//! external-tool provisioning ([`tools`]).
//!
//! Deliberately dependency-light and workspace-free: no nau-* crate may
//! appear in this crate's dependency graph (ADR-0051 dependency
//! direction; asserted by the gate's dep-direction pass).

pub mod archive;
pub mod output;
pub mod tools;

#[cfg(test)]
pub(crate) mod test_env;
