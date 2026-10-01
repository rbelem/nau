//! The root `assert` shim (issue #326 PR 3, R1): the Snap Store
//! assertion machinery moved to `nau-infra` beside the store client
//! (its only production consumer). Every pre-existing `crate::assert::`
//! path keeps resolving through the re-export; the tests stay here on
//! the root crate's captured-assertion fixtures, exercising the moved
//! code through the shim.

pub use nau_infra::assert::*;
