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

/// A pre-resolved pin for one architecture and channel.
///
/// Pins are keyed `"<arch>@<channel>"` (e.g. `"amd64@22/stable"`) so a
/// base-tracked snap (kernel/gadget, ADR-0019) can carry one pin per store
/// track — a `latest/stable` pin and a `22/stable` pin are different blobs.
/// The bare `"<arch>"` key is the legacy spelling and means "channel
/// unknown" (issue #69): the build never silently uses such a pin on a
/// derived channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinEntry {
    pub revision: u32,
    #[serde(rename = "sha3-384")]
    pub sha3_384: String,
    /// The store channel this pin was resolved from (e.g. "22/stable").
    /// Recorded so a pin whose channel disagrees with the build's derived
    /// channel is detectable instead of silently trusted (#69).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
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

    /// Path to the app's `.desktop` file inside the snap (issue #7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,
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
                // #68: the store snap is named 'pi' — 'pi-gadget' does not
                // exist in series 16.
                name: Some("pi".into()),
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

    /// Resolve store-based snaps in the index: query the Snap Store for each
    /// architecture and record the latest revision + sha3-384, keyed by
    /// channel (issue #69).
    ///
    /// Two kinds of passes run:
    ///
    /// - the **default pass** resolves every store entry on `channel`
    ///   (default `latest/stable`), pinning under `"<arch>@<channel>"`;
    /// - each entry of `bases` (an image base name like `"core22"`) with a
    ///   numeric series adds a **base pass**: kernel/gadget snaps ride the
    ///   base's store track at build time (ADR-0019), so resolve bakes pins
    ///   for the very channel the build will derive — `--base core22`
    ///   resolves every entry on `22/stable` and pins under
    ///   `"<arch>@22/stable"`. Entries that have no such track (a core22
    ///   base asked for `22/stable`) warn and are skipped for that pass.
    ///
    /// Pins carry their channel; the image build refuses a pin whose
    /// recorded channel differs from the channel it derived (#69).
    pub fn resolve_all(&mut self, channel: &str, bases: &[String]) -> miette::Result<()> {
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

        // (channel, label) for each pass; the label names the pass in logs.
        let mut passes: Vec<(String, String)> = vec![(channel.to_string(), "default".into())];
        for base in bases {
            match crate::image::staging::base_track(base) {
                Some(track) => {
                    let pass_channel = crate::image::staging::channel_on_track(channel, track);
                    passes.push((pass_channel, format!("base {base}")));
                }
                None => eprintln!(
                    "  ⚠ base '{base}' has no numeric series — no base-track pass \
                     (ADR-0019 derives nothing from it)"
                ),
            }
        }

        for (name, store_name) in &entries {
            for (pass_channel, pass_label) in &passes {
                for arch in &archs {
                    let pin = crate::snap::SnapRef {
                        name: store_name.to_string(),
                        revision: None,
                        sha3_384: None,
                    };

                    match StoreClient::resolve(&pin, pass_channel, arch) {
                        Ok(resolved) => {
                            let entry = self.find_mut(name).unwrap();
                            let pins = entry.pins.get_or_insert_with(HashMap::new);
                            let key = format!("{arch}@{pass_channel}");
                            pins.entry(key).or_insert_with(|| PinEntry {
                                revision: resolved.revision,
                                sha3_384: resolved.sha3_384,
                                channel: Some(pass_channel.clone()),
                            });
                        }
                        Err(e) => {
                            eprintln!(
                                "  ⚠ could not resolve {name} for {arch} \
                                 [{pass_label}, {pass_channel}]: {e}"
                            );
                        }
                    }
                }
            }

            let pin_count = self
                .find(name)
                .and_then(|e| e.pins.as_ref())
                .map(|p| p.len())
                .unwrap_or(0);
            eprintln!("  ✓ {name} resolved ({pin_count} channel pins)");
        }

        Ok(())
    }

    /// The index pin to use for `arch` on `channel`, or `None`.
    ///
    /// Only pins recorded FOR the channel are returned: the keyed
    /// `"<arch>@<channel>"` entry, or a bare `"<arch>"` pin that itself
    /// records a matching channel. A legacy bare pin with no channel means
    /// "resolved from an unknown channel" and is never returned — the build
    /// must not trust it on a derived channel (#69).
    pub fn channel_pin<'a>(
        pins: &'a HashMap<String, PinEntry>,
        arch: &str,
        channel: &str,
    ) -> Option<&'a PinEntry> {
        let keyed = pins.get(&format!("{arch}@{channel}"));
        keyed.or_else(|| {
            pins.get(arch)
                .filter(|p| p.channel.as_deref() == Some(channel))
        })
    }

    /// Whether `pins` carries any pin for `arch` at all (keyed or bare).
    pub fn has_arch_pins(pins: &HashMap<String, PinEntry>, arch: &str) -> bool {
        pins.keys().any(|k| {
            k == arch
                || k.strip_prefix(arch)
                    .is_some_and(|rest| rest.starts_with('@'))
        })
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
                                desktop: app.desktop.clone(),
                                interpreter: None,
                                confined: None,
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
            sources: None,
            build: entry.build.clone(),
            parts: None,
            architectures: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            version_adopted: false,
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
            build_deps: vec![],
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps,
            deps: None,
            floating: false,
            definition_dir: None,
        })
    }

    /// Generate a pin table entry for the DSL from an index entry.
    /// Returns a Lua table `{ name }`.
    ///
    /// Deliberately name-only (issue #69): a store pin resolved on one
    /// channel baked into a declaration would be re-verified by the build
    /// against the channel it DERIVES (ADR-0019) — for base-tracked
    /// kernel/gadget snaps those disagree, and the build fails on a pin the
    /// author never chose. Resolution happens at build time on the derived
    /// channel; deliberate pinning is the lockfile's job.
    pub fn entry_to_lua_table(
        entry: &IndexEntry,
        _arch: &str,
        lua: &mlua::Lua,
    ) -> mlua::Result<mlua::Table> {
        let table = lua.create_table()?;
        table.set("name", entry.name.as_str())?;
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
                        desktop: None,
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

    // ── Channel-keyed pins (issue #69) ──

    fn pin(revision: u32, channel: Option<&str>) -> PinEntry {
        PinEntry {
            revision,
            sha3_384: "a".repeat(96),
            channel: channel.map(str::to_string),
        }
    }

    fn pins_with(entries: Vec<(String, PinEntry)>) -> HashMap<String, PinEntry> {
        entries.into_iter().collect()
    }

    #[test]
    fn test_channel_pin_matches_keyed_entry() {
        let pins = pins_with(vec![(
            "amd64@22/stable".into(),
            pin(3654, Some("22/stable")),
        )]);
        let got = PackageIndex::channel_pin(&pins, "amd64", "22/stable").unwrap();
        assert_eq!(got.revision, 3654);
        // A different derived channel must not see this pin.
        assert!(PackageIndex::channel_pin(&pins, "amd64", "26/stable").is_none());
    }

    #[test]
    fn test_channel_pin_rejects_legacy_bare_pin_on_derived_channel() {
        // A bare pin with no recorded channel is an unknown-channel pin:
        // never trusted on a derived channel (#69).
        let pins = pins_with(vec![("amd64".into(), pin(103, None))]);
        assert!(PackageIndex::channel_pin(&pins, "amd64", "22/stable").is_none());
        assert!(PackageIndex::channel_pin(&pins, "amd64", "latest/stable").is_none());
    }

    #[test]
    fn test_channel_pin_accepts_bare_pin_with_matching_channel() {
        let pins = pins_with(vec![("amd64".into(), pin(2411, Some("latest/stable")))]);
        assert!(
            PackageIndex::channel_pin(&pins, "amd64", "latest/stable").is_some(),
            "a bare pin that records its channel is usable on that channel"
        );
    }

    #[test]
    fn test_has_arch_pins_sees_keyed_and_bare() {
        let pins = pins_with(vec![
            ("amd64@22/stable".into(), pin(1, Some("22/stable"))),
            ("arm64".into(), pin(2, None)),
        ]);
        assert!(PackageIndex::has_arch_pins(&pins, "amd64"));
        assert!(PackageIndex::has_arch_pins(&pins, "arm64"));
        assert!(!PackageIndex::has_arch_pins(&pins, "armhf"));
    }

    #[test]
    fn test_pin_entry_channel_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-index.json");

        let index = PackageIndex {
            version: 1,
            snaps: vec![IndexEntry {
                name: "pc-kernel".into(),
                summary: None,
                store: None,
                pins: Some(pins_with(vec![(
                    "amd64@26/stable".into(),
                    pin(3699, Some("26/stable")),
                )])),
                source: None,
                build: None,
                apps: None,
                aliases: vec![],
            }],
        };
        index.save(&path).unwrap();
        let loaded = PackageIndex::load(&path).unwrap();
        let pins = loaded.snaps[0].pins.as_ref().unwrap();
        let got = PackageIndex::channel_pin(pins, "amd64", "26/stable").unwrap();
        assert_eq!(got.revision, 3699);
        assert_eq!(got.channel.as_deref(), Some("26/stable"));
    }

    #[test]
    fn test_entry_to_lua_table_is_name_only() {
        let lua = mlua::Lua::new();
        let entry = sample_entry();
        // Even with a pin for the arch, the DSL table carries the name only:
        // baked pins would be re-verified against the build's derived
        // channel and fail there (#69).
        let table = PackageIndex::entry_to_lua_table(&entry, "amd64", &lua).unwrap();
        assert_eq!(table.get::<String>("name").unwrap(), entry.name.clone());
        assert!(!table.contains_key("revision").unwrap());
        assert!(!table.contains_key("sha3_384").unwrap());
    }
}
