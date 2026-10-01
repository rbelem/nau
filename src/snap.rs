//! The root `snap` shim (issue #326 PR 2): the build machinery moved to
//! `nau-build` (`crates/nau-build/src/snap.rs`); every pre-existing
//! `crate::snap::` path keeps resolving through the re-exports below.
//!
//! The chart-side names (`validate_*`, the `FromLua*`/`FromPinTable`
//! extension traits, the Lua constructors) are re-exported HERE, from
//! `nau-chart` — `nau-build` may not carry them on its normal axis (the
//! dep-direction table allows it only {nau-core, nau-infra}), and their
//! root consumers (pod.rs, image/) stay root. The §4 reconciliation PR
//! dissolves these traits into nau-core, at which point this block
//! simplifies to a core re-export like the rest.

pub use nau_build::snap::*;

pub use nau_chart::snap_lua::validate_service_name;
pub use nau_chart::snap_lua::{
    confinement_from_lua, deps_lock_spec_from_lua, image_declaration_from_lua,
    parse_submodule_spec, service_decl_from_lua_table, snap_app_from_lua_table,
    snap_meta_from_lua_table, snap_ref_from_pin, FromLuaTable, FromLuaTableNamed, FromLuaValue,
    FromPinTable,
};
pub use nau_chart::snap_lua::{validate_exec_text, validate_service_interpolation};
