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

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::snap_types::{SnapApp, SnapMeta, SnapRef, SourceSpec};

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

// ── Default index (bundled with nau) ──

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

/// One store-resolved pin as the index records it. The resolver is
/// injected (see [`PackageIndex::resolve_all`]) so this module never
/// imports the Snap Store client — ADR-0051: the store domain stays
/// root-side; nau-chart depends only on nau-core and nau-infra.
pub struct PinResolution {
    pub revision: u32,
    /// sha3-384 hex digest from the store.
    pub sha3_384: String,
}

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
    pub fn resolve_all(
        &mut self,
        channel: &str,
        bases: &[String],
        resolve_pin: &dyn Fn(&SnapRef, &str, &str) -> miette::Result<PinResolution>,
    ) -> miette::Result<()> {
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
            match crate::channels::base_track(base) {
                Some(track) => {
                    let pass_channel = crate::channels::channel_on_track(channel, track);
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
                    let pin = crate::snap_types::SnapRef {
                        name: store_name.to_string(),
                        revision: None,
                        sha3_384: None,
                    };

                    match resolve_pin(&pin, pass_channel, arch) {
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
            compression_level: None,
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
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        })
    }
}

#[cfg(test)]
mod tests;
