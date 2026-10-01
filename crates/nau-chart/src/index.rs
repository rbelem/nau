//! Package index — a local registry of known snaps with pre-resolved pins.
//!
//! The index file (`package-index.json`) stores snap definitions that can be
//! used as shorthand in `nau.lua` via the `index()` DSL function.
//!
//! # Index format
//!
//! ```json
//! {
//!   "version": 1,
//!   "snaps": [
//!     {
//!       "name": "core22",
//!       "summary": "Runtime environment based on Ubuntu 22.04",
//!       "store": { "name": "core22", "channel": "latest/stable" },
//!       "pins": {
//!         "amd64@latest/stable": { "revision": 2411, "sha3-384": "e7bb...", "channel": "latest/stable" },
//!         "amd64@22/stable": { "revision": 2404, "sha3-384": "5a85...", "channel": "22/stable" }
//!       }
//!     },
//!     {
//!       "name": "hello",
//!       "summary": "GNU Hello",
//!       "source": {
//!         "url": "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
//!         "sha256": "abc..."
//!       },
//!       "build": "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
//!       "apps": { "hello": { "command": "bin/hello" } }
//!     }
//!   ]
//! }
//! ```
//!
//! Pins are keyed `"<arch>@<channel>"` and record their channel (issue #69):
//! kernel/gadget snaps ride the image base's store track (ADR-0019), so the
//! same snap legitimately needs different pins per track, and the build
//! refuses a pin whose channel disagrees with the channel it derived. The
//! bare `"<arch>"` key is legacy ("channel unknown") and is never trusted
//! on a derived channel.
//!
//! The pure index vocabulary (types, load/save, pin resolution) lives in
//! [`nau_core::index`]; this module re-exports it so every `nau_chart::index::`
//! and `nau::index::` path keeps resolving, and hosts only the mlua seam:
//! the `index()` DSL table generation (ADR-0053 pre-PR-2 down-moves).

pub use nau_core::index;

use std::path::PathBuf;

// Every index vocabulary item re-exported so `crate::index::<Item>` /
// `nau::index::<Item>` paths keep resolving through the shim.
pub use nau_core::index::*;

/// Generate a pin table entry for the DSL from an index entry.
/// Returns a Lua table `{ name }`.
///
/// Deliberately name-only (issue #69): a store pin resolved on one
/// channel baked into a declaration would be re-verified by the build
/// against the channel it DERIVES (ADR-0019) — for base-tracked
/// kernel/gadget snaps those disagree, and the build fails on a pin the
/// author never chose. Resolution happens at build time on the derived
/// channel; deliberate pinning is the lockfile's job.
pub fn index_entry_to_lua_table(
    entry: &IndexEntry,
    _arch: &str,
    lua: &mlua::Lua,
) -> mlua::Result<mlua::Table> {
    let table = lua.create_table()?;
    table.set("name", entry.name.as_str())?;
    Ok(table)
}

/// Look up a snap name in the index and return a Lua pin table.
/// Called from Lua via the `index()` DSL global.
pub fn lua_index_entry(
    lua: &mlua::Lua,
    name: String,
    arch: String,
    index_path: PathBuf,
) -> mlua::Result<mlua::Table> {
    let index = PackageIndex::load_or_default(&index_path).map_err(mlua::Error::external)?;

    let entry = index.find_by_name_or_alias(&name).ok_or_else(|| {
        mlua::Error::external(miette::miette!(
            "snap '{}' not found in package index",
            name
        ))
    })?;

    index_entry_to_lua_table(entry, &arch, lua)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_entry() -> IndexEntry {
        IndexEntry {
            name: "core22".into(),
            summary: Some("Ubuntu 22.04 base".into()),
            store: Some(nau_core::index::StoreRef {
                name: Some("core22".into()),
                channel: "latest/stable".into(),
            }),
            pins: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "amd64".into(),
                    nau_core::index::PinEntry {
                        revision: 2411,
                        sha3_384: "e7bba49dc406968eb0a127e2c405c268c4abe875120f2c4930129800624bd937618069adbcc47cf3762aceddd1c4b977".into(),
                        channel: Some("latest/stable".into()),
                    },
                );
                Some(map)
            },
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        }
    }

    #[test]
    fn test_entry_to_lua_table_is_name_only() {
        let lua = mlua::Lua::new();
        let entry = sample_entry();
        // Even with a pin for the arch, the DSL table carries the name only:
        // baked pins would be re-verified against the build's derived
        // channel and fail there (#69).
        let table = index_entry_to_lua_table(&entry, "amd64", &lua).unwrap();
        assert_eq!(table.get::<String>("name").unwrap(), entry.name.clone());
        assert!(!table.contains_key("revision").unwrap());
        assert!(!table.contains_key("sha3_384").unwrap());
    }

    // ── the index() DSL seam ──

    fn index_file_with(entry: IndexEntry) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join(DEFAULT_INDEX);
        PackageIndex {
            version: 1,
            snaps: vec![entry],
        }
        .save(&path)
        .unwrap();
        (dir, path)
    }

    #[test]
    fn lua_index_entry_serves_the_name_table_for_an_alias() {
        let mut entry = sample_entry();
        entry.aliases = vec!["core".into()];
        let (_dir, path) = index_file_with(entry);
        let lua = mlua::Lua::new();

        let by_name = lua_index_entry(&lua, "core22".into(), "amd64".into(), path.clone()).unwrap();
        assert_eq!(by_name.get::<String>("name").unwrap(), "core22");
        let by_alias = lua_index_entry(&lua, "core".into(), "amd64".into(), path).unwrap();
        assert_eq!(by_alias.get::<String>("name").unwrap(), "core22");
    }

    #[test]
    fn lua_index_entry_names_the_missing_snap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(DEFAULT_INDEX);
        PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        }
        .save(&path)
        .unwrap();
        let lua = mlua::Lua::new();
        let err = lua_index_entry(&lua, "nope".into(), "amd64".into(), path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("'nope' not found in package index"), "{err}");
    }

    #[test]
    fn lua_index_entry_falls_back_to_the_bundled_default_index() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let lua = mlua::Lua::new();
        let table = lua_index_entry(&lua, "pc-kernel".into(), "amd64".into(), path).unwrap();
        assert_eq!(table.get::<String>("name").unwrap(), "pc-kernel");
    }
}
