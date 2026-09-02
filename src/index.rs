//! Package index — a local registry of known snaps with pre-resolved pins.
//!
//! The index file (`package-index.json`) stores snap definitions that can be
//! used as shorthand in `shuttle.lua` via the `index()` DSL function.
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
//!         "amd64": { "revision": 2411, "sha3-384": "e7bb..." },
//!         "arm64": { "revision": 2412, "sha3-384": "5a85..." }
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::snap::{SnapApp, SnapMeta, SourceSpec};
use crate::store::StoreClient;

/// Default filename for the package index.
pub const DEFAULT_INDEX: &str = "package-index.json";

/// Top-level package index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageIndex {
    pub version: u32,
    pub snaps: Vec<IndexEntry>,
}

/// One snap entry in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// If the snap comes from the Snap Store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreRef>,

    /// Pre-resolved pins by architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pins: Option<HashMap<String, PinEntry>>,

    /// If the snap is built from source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceDef>,

    /// Build command (for source-based snaps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,

    /// App declarations (for source-based snaps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apps: Option<HashMap<String, IndexApp>>,

    /// Alternative names this package is known by.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

/// A reference to a snap in the Snap Store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreRef {
    /// Snap name in the store (defaults to entry name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Default channel (e.g. "latest/stable").
    #[serde(default = "default_channel")]
    pub channel: String,
}

fn default_channel() -> String {
    "latest/stable".into()
}

/// A pre-resolved pin for one architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinEntry {
    pub revision: u32,
    #[serde(rename = "sha3-384")]
    pub sha3_384: String,
}

/// Source definition for a source-based snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDef {
    pub url: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// App declaration in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexApp {
    pub command: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugs: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<Vec<String>>,
}

// ── Default index (bundled with shuttle) ──

/// Built-in index entries for well-known snaps.
pub fn default_entries() -> Vec<IndexEntry> {
    vec![
        IndexEntry {
            name: "core22".into(),
            summary: Some("Runtime environment based on Ubuntu 22.04".into()),
            store: Some(StoreRef {
                name: Some("core22".into()),
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        },
        IndexEntry {
            name: "pc-kernel".into(),
            summary: Some("Generic PC kernel snap".into()),
            store: Some(StoreRef {
                name: Some("pc-kernel".into()),
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        },
        IndexEntry {
            name: "pi-gadget".into(),
            summary: Some("Raspberry Pi gadget snap".into()),
            store: Some(StoreRef {
                name: Some("pi-gadget".into()),
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        },
        IndexEntry {
            name: "lxd".into(),
            summary: Some("System container manager".into()),
            store: Some(StoreRef {
                name: Some("lxd".into()),
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        },
    ]
}

// ── Index operations ──

impl PackageIndex {
    /// Load index from file, or create default if file doesn't exist.
    pub fn load_or_default(path: &Path) -> miette::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self {
                version: 1,
                snaps: default_entries(),
            })
        }
    }

    /// Load index from file.
    pub fn load(path: &Path) -> miette::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| miette::miette!("failed to read {}: {}", path.display(), e))?;
        serde_json::from_str(&content)
            .map_err(|e| miette::miette!("invalid package index '{}': {}", path.display(), e))
    }

    /// Save index to file.
    pub fn save(&self, path: &Path) -> miette::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| miette::miette!("failed to serialize index: {}", e))?;
        std::fs::write(path, &content)
            .map_err(|e| miette::miette!("failed to write {}: {}", path.display(), e))?;
        Ok(())
    }

    /// Find an entry by name.
    pub fn find(&self, name: &str) -> Option<&IndexEntry> {
        self.snaps.iter().find(|e| e.name == name)
    }

    /// Find an entry by name or alias.
    pub fn find_by_name_or_alias(&self, name: &str) -> Option<&IndexEntry> {
        self.find(name).or_else(|| {
            self.snaps
                .iter()
                .find(|e| e.aliases.iter().any(|a| a == name))
        })
    }

    /// Find an entry by name (mutable).
    pub fn find_mut(&mut self, name: &str) -> Option<&mut IndexEntry> {
        self.snaps.iter_mut().find(|e| e.name == name)
    }

    /// Add or update an entry.
    pub fn upsert(&mut self, entry: IndexEntry) {
        if let Some(existing) = self.find_mut(&entry.name) {
            *existing = entry;
        } else {
            self.snaps.push(entry);
        }
    }

    /// Resolve all store-based snaps in the index: query the store for each
    /// architecture and record the latest revision + sha3-384.
    pub fn resolve_all(&mut self, channel: &str) -> miette::Result<()> {
        let archs = ["amd64", "arm64", "armhf"];
        // Collect entry info before any mutable borrow
        let entries: Vec<(String, String)> = self
            .snaps
            .iter()
            .filter(|e| e.store.is_some())
            .map(|e| {
                let store_name = e
                    .store
                    .as_ref()
                    .and_then(|s| s.name.as_deref())
                    .unwrap_or(&e.name)
                    .to_string();
                (e.name.clone(), store_name)
            })
            .collect();

        for (name, store_name) in &entries {
            for arch in &archs {
                let pin = crate::snap::SnapRef {
                    name: store_name.to_string(),
                    revision: None,
                    sha3_384: None,
                };

                match StoreClient::resolve(&pin, channel, arch) {
                    Ok(resolved) => {
                        let entry = self.find_mut(name).unwrap();
                        let pins = entry.pins.get_or_insert_with(HashMap::new);
                        if !pins.contains_key(*arch) {
                            pins.insert(
                                arch.to_string(),
                                PinEntry {
                                    revision: resolved.revision,
                                    sha3_384: resolved.sha3_384,
                                },
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("  ⚠ could not resolve {} for {}: {e}", name, arch);
                    }
                }
            }

            let pin_count = self
                .find(name)
                .and_then(|e| e.pins.as_ref())
                .map(|p| p.len())
                .unwrap_or(0);
            eprintln!("  ✓ {} resolved for {} arch(s)", name, pin_count);
        }

        Ok(())
    }

    /// Convert an index entry to a SnapMeta (for source-based snaps).
    pub fn entry_to_snap_meta(entry: &IndexEntry) -> Option<SnapMeta> {
        let source = entry.source.as_ref()?;
        let apps = entry
            .apps
            .as_ref()
            .map(|a| {
                a.iter()
                    .map(|(name, app)| {
                        (
                            name.clone(),
                            SnapApp {
                                command: app.command.clone(),
                                daemon: app.daemon.clone(),
                                plugs: app.plugs.clone(),
                                slots: app.slots.clone(),
                                environment: None,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(SnapMeta {
            name: entry.name.clone(),
            version: "0.0.0".into(),
            summary: entry.summary.clone(),
            description: None,
            license: None,
            source: source
                .sha256
                .clone()
                .map(|sha| SourceSpec::Pinned {
                    url: source.url.clone(),
                    sha256: sha,
                })
                .or_else(|| Some(SourceSpec::Unverified(source.url.clone()))),
            build: entry.build.clone(),
            parts: None,
            architectures: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            icon_source: None,
            icon: None,
            compression: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            apps,
            definition_dir: None,
        })
    }

    /// Generate a pin table entry for the DSL from an index entry.
    /// Returns a Lua table `{ name, revision?, sha3_384? }`.
    pub fn entry_to_lua_table(
        entry: &IndexEntry,
        arch: &str,
        lua: &mlua::Lua,
    ) -> mlua::Result<mlua::Table> {
        let table = lua.create_table()?;
        table.set("name", entry.name.as_str())?;

        // If we have a pre-resolved pin for this arch, use it
        if let Some(ref pins) = entry.pins {
            if let Some(pin) = pins.get(arch) {
                table.set("revision", pin.revision)?;
                table.set("sha3_384", pin.sha3_384.as_str())?;
            }
        }

        Ok(table)
    }
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

    PackageIndex::entry_to_lua_table(entry, &arch, lua)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_entry() -> IndexEntry {
        IndexEntry {
            name: "core22".into(),
            summary: Some("Ubuntu 22.04 base".into()),
            store: Some(StoreRef {
                name: Some("core22".into()),
                channel: "latest/stable".into(),
            }),
            pins: {
                let mut map = HashMap::new();
                map.insert(
                    "amd64".into(),
                    PinEntry {
                        revision: 2411,
                        sha3_384: "e7bba49dc406968eb0a127e2c405c268c4abe875120f2c4930129800624bd937618069adbcc47cf3762aceddd1c4b977".into(),
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
    fn test_index_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-index.json");

        let index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };
        index.save(&path).unwrap();

        let loaded = PackageIndex::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.snaps.len(), 1);
        assert_eq!(loaded.snaps[0].name, "core22");
        assert_eq!(loaded.snaps[0].pins.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_index_find() {
        let index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };

        let found = index.find("core22").unwrap();
        assert_eq!(found.name, "core22");
        assert!(index.find("nonexistent").is_none());
    }

    #[test]
    fn test_index_upsert_adds_new() {
        let mut index = PackageIndex {
            version: 1,
            snaps: vec![],
        };

        index.upsert(sample_entry());
        assert_eq!(index.snaps.len(), 1);
    }

    #[test]
    fn test_index_upsert_replaces_existing() {
        let mut index = PackageIndex {
            version: 1,
            snaps: vec![sample_entry()],
        };

        let mut modified = sample_entry();
        modified.summary = Some("Updated".into());
        index.upsert(modified);

        assert_eq!(index.snaps.len(), 1);
        assert_eq!(
            index.find("core22").unwrap().summary.as_deref(),
            Some("Updated")
        );
    }

    #[test]
    fn test_default_entries_exist() {
        let entries = default_entries();
        assert!(entries.iter().any(|e| e.name == "core22"));
        assert!(entries.iter().any(|e| e.name == "pc-kernel"));
        assert!(entries.iter().any(|e| e.name == "pi-gadget"));
        assert!(entries.iter().any(|e| e.name == "lxd"));
    }

    #[test]
    fn test_entry_to_snap_meta_source() {
        let entry = IndexEntry {
            name: "hello".into(),
            summary: Some("GNU Hello".into()),
            store: None,
            pins: None,
            source: Some(SourceDef {
                url: "https://example.com/hello.tar.gz".into(),
                sha256: Some("abcdef".into()),
            }),
            build: Some("./configure && make install".into()),
            apps: Some(
                [(
                    "hello".into(),
                    IndexApp {
                        command: "bin/hello".into(),
                        daemon: None,
                        plugs: None,
                        slots: None,
                    },
                )]
                .into(),
            ),
            aliases: vec![],
        };

        let meta = PackageIndex::entry_to_snap_meta(&entry).unwrap();
        assert_eq!(meta.name, "hello");
        assert!(meta.build.is_some());
        assert_eq!(meta.apps.len(), 1);
        assert_eq!(meta.apps["hello"].command, "bin/hello");
    }

    #[test]
    fn test_entry_to_snap_meta_no_source() {
        let entry = IndexEntry {
            name: "core22".into(),
            summary: None,
            store: Some(StoreRef {
                name: None,
                channel: "latest/stable".into(),
            }),
            pins: None,
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        };

        // Store-only entries have no source, so to_snap_meta returns None
        assert!(PackageIndex::entry_to_snap_meta(&entry).is_none());
    }

    #[test]
    fn test_index_load_or_default_creates_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent-index.json");

        let index = PackageIndex::load_or_default(&path).unwrap();
        assert_eq!(index.version, 1);
        assert!(!index.snaps.is_empty());
        // Should have default entries
        assert!(index.snaps.iter().any(|e| e.name == "core22"));
    }
}
