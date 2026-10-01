//! The canonical build-input closure and its cache key (gap-analysis
//! §4.3, Phase 22 task 1) — shared vocabulary of the build cache and the
//! chart manifest path (ADR-0051 Decision 3).
//!
//! `pinned_member` stays with the lockfile it reads (nau-chart::lock);
//! everything derivable from a `SnapMeta` alone lives here.

use sha2::Digest;

use crate::snap_types::{SnapMeta, SnapPart};

/// Magic string for packages without source (meta/store types).
pub const NO_SOURCE_HASH: &str = "none";

/// Closure format version and cache-key prefix. These MUST move together:
/// bump both when the closure schema changes so old entries can never be
/// served for a new format (no silent key collisions across formats).
///
/// v3 adds `build_deps` to the closure (ADR-0018 Decision 4, issue #22):
/// a changed build dependency must invalidate the cache key.
///
/// v4 folds the single-command `build` field into the `parts` component
/// when a snap has no `parts` table (the pre-parts form `build = "..."`).
/// Before v4 a changed build script with a constant source/version/url
/// produced an identical cache key and served a stale artifact. The `v4:`
/// prefix cold-misses old v3 entries once.
const CLOSURE_FORMAT_VERSION: u32 = 4;
const KEY_PREFIX: &str = "v4";

/// Target value for builds without an explicit cross-compilation triplet.
const NATIVE_TARGET: &str = "native";

/// SHA-256 hex digest of a string.
pub fn sha256_hex(input: &str) -> String {
    let hash = sha2::Sha256::digest(input.as_bytes());
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// One member of the resolved `requires` closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiresMember {
    pub name: String,
    /// Resolved revision (lockfile pin) or declared version, when known.
    pub pin: Option<String>,
    /// Content hash of the dependency, when available from lockfile data.
    ///
    /// `None` marks an unpinned store dependency: its reproducibility is
    /// version-pinned at best — the cache key cannot detect content changes
    /// behind the version (known limitation, see `requires` in
    /// [`BuildClosure`]).
    pub hash: Option<String>,
}

/// The canonical build-input closure: every input that can change the built
/// artifact (gap-analysis §4.3, Phase 22 task 1).
///
/// Serialized to deterministic JSON (sorted keys via serde_json's BTreeMap,
/// `requires` sorted by name and deduplicated):
///
/// ```json
/// {
///   "format_version": 4,
///   "parts": "<canonical parts JSON>",
///   "requires": [{"hash": "…|null", "name": "…", "pin": "…|null"}],
///   "build_deps": [{"hash": "…|null", "name": "…", "pin": "…|null"}],
///   "source": "<sha256 of name:version:url, or none>",
///   "target": "<triplet or native>"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BuildClosure {
    /// SHA-256 over `name:version:url` (`none` for meta/store packages).
    /// The tarball content hash is pinned separately in `nau.lock` and
    /// verified at download time, so the key never needs the download.
    /// Multi-source snaps (issue #41) fold every named source's
    /// name/url/hash into this component.
    pub source: String,
    /// Multi-source closure members (issue #41), sorted by name — the
    /// explicit, diff-legible mirror of the identity folded into
    /// `source`. Empty for single-source and meta/store packages (kept
    /// out of the canonical JSON so their keys stay byte-identical).
    pub sources: Vec<SourceClosureMember>,
    /// Canonical parts JSON ([`canonical_parts_json`]); empty when no parts.
    /// When a snap has no `parts` table, carries the single-command `build`
    /// field in the same one-element-parts shape (v4), so a changed build
    /// script invalidates the key.
    pub parts: String,
    /// Cross-compilation target triplet, or `native`.
    pub target: String,
    /// Resolved requires closure, sorted by name, deduplicated.
    pub requires: Vec<RequiresMember>,
    /// Resolved build_deps closure (ADR-0018 Decision 4), sorted by name,
    /// deduplicated. A changed build dependency invalidates the key.
    pub build_deps: Vec<RequiresMember>,
}

impl BuildClosure {
    /// Build the closure for a snap meta from resolved requires members.
    /// Members are sorted by name and deduplicated so dependency traversal
    /// order never affects the key.
    pub fn for_meta(
        meta: &SnapMeta,
        requires: Vec<RequiresMember>,
        build_deps: Vec<RequiresMember>,
    ) -> Self {
        let mut requires = requires;
        requires.sort_by(|a, b| a.name.cmp(&b.name));
        requires.dedup_by(|a, b| a.name == b.name);
        let mut build_deps = build_deps;
        build_deps.sort_by(|a, b| a.name.cmp(&b.name));
        build_deps.dedup_by(|a, b| a.name == b.name);
        let parts = match meta.parts.as_ref() {
            Some(parts) => canonical_parts_json(parts),
            // Pre-parts single-command form (`build = "..."`): the build
            // script IS the build spec, so it must participate in the key
            // (v4). Serialize in the same `[{name,build,after}]` shape as a
            // one-element parts table so a snap that migrates from
            // `build = "x"` to `parts = { core = { build = "x" } }` keeps
            // as much key stability as the format allows.
            None => meta
                .build
                .as_ref()
                .map(|build| {
                    serde_json::to_string(&vec![serde_json::json!({
                        "name": "core",
                        "build": build,
                        "after": Vec::<String>::new(),
                    })])
                    .unwrap_or_else(|_| "unserializable".to_string())
                })
                .unwrap_or_default(),
        };
        // Multi-source identity (issue #41): every named source's url +
        // pinned hash joins the closure, so a changed or swapped source
        // invalidates the key. BTreeMap iteration is sorted, so the JSON
        // is canonical.
        let sources: Vec<SourceClosureMember> = meta
            .sources
            .iter()
            .flatten()
            .map(|(name, spec)| SourceClosureMember {
                name: name.clone(),
                url: spec.url().to_string(),
                sha256: spec.expected_sha256().unwrap_or_default().to_string(),
            })
            .collect();
        BuildClosure {
            source: source_identity_hash(meta),
            sources,
            parts,
            target: meta
                .target
                .clone()
                .unwrap_or_else(|| NATIVE_TARGET.to_string()),
            requires,
            build_deps,
        }
    }

    /// Deterministic canonical JSON serialization of the closure.
    pub fn canonical_json(&self) -> String {
        let member = |m: &RequiresMember| serde_json::json!({ "name": m.name, "pin": m.pin, "hash": m.hash });
        let requires: Vec<serde_json::Value> = self.requires.iter().map(member).collect();
        let build_deps: Vec<serde_json::Value> = self.build_deps.iter().map(member).collect();
        let mut json = serde_json::json!({
            "format_version": CLOSURE_FORMAT_VERSION,
            "source": self.source,
            "parts": self.parts,
            "target": self.target,
            "requires": requires,
            "build_deps": build_deps,
        });
        // Multi-source members fold in only when present: single-source
        // packages keep byte-identical keys (and the `source` component
        // already hashes multi-source identity via
        // [`source_identity_hash`], so the explicit list is redundancy
        // that makes key diffs legible, not correctness load-bearing).
        if !self.sources.is_empty() {
            json["sources"] = serde_json::Value::Array(
                self.sources
                    .iter()
                    .map(
                        |s| serde_json::json!({ "name": s.name, "url": s.url, "sha256": s.sha256 }),
                    )
                    .collect(),
            );
        }
        json.to_string()
    }

    /// Version-prefixed cache key: `v4:<sha256 of canonical JSON>`.
    pub fn cache_key(&self) -> String {
        format!("{}:{}", KEY_PREFIX, sha256_hex(&self.canonical_json()))
    }
}

/// One multi-source closure member (issue #41): a named source's identity
/// as it participates in the cache key.
#[derive(Debug, Clone)]
pub struct SourceClosureMember {
    pub name: String,
    pub url: String,
    pub sha256: String,
}

/// SHA-256 over the source identity: `name:version:url` (or `none` for
/// meta/store packages). This is the source component of the closure — the
/// parts spec is hashed separately, and the downloaded tarball's content
/// hash is pinned in `nau.lock` and verified at download time.
///
/// Multi-source snaps (issue #41) fold each named source's
/// `name=url:sha256` into the identity (sorted, BTreeMap order): every
/// entry is hash-pinned by definition, so a changed pin invalidates the
/// key even before any download happens.
fn source_identity_hash(meta: &SnapMeta) -> String {
    match meta.type_ {
        Some(ref t) if t == "source" => {
            if let Some(sources) = &meta.sources {
                let mut acc = format!("{}:{}", meta.name, meta.version);
                for (name, spec) in sources {
                    acc.push_str(&format!(
                        "|{name}={}:{}",
                        spec.url(),
                        spec.expected_sha256().unwrap_or_default()
                    ));
                }
                return sha256_hex(&acc);
            }
            let url = meta
                .source
                .as_ref()
                .map(|s| s.url().to_string())
                .unwrap_or_default();
            sha256_hex(&format!("{}:{}:{}", meta.name, meta.version, url))
        }
        _ => NO_SOURCE_HASH.to_string(),
    }
}

/// Canonical JSON for a parts spec, used in cache keys: parts sorted by
/// name (BTreeMap order), each with its command and `after` edges. Any
/// change to names, commands, or edges changes the key. Plugin parts
/// additionally fold in the plugin name, the plugin registry version, and
/// the canonical (sorted-key) options map, so any option change invalidates
/// the cache (ADR-0014 Decision 5). Parts without a plugin serialize exactly
/// as before — single-command specs keep byte-identical keys.
pub fn canonical_parts_json(parts: &std::collections::BTreeMap<String, SnapPart>) -> String {
    let items: Vec<serde_json::Value> = parts
        .iter()
        .map(|(name, part)| {
            let mut obj =
                serde_json::json!({ "name": name, "build": part.build, "after": part.after });
            if let Some(plugin) = &part.plugin {
                obj["plugin"] = serde_json::Value::String(plugin.clone());
                obj["plugin_version"] =
                    serde_json::Value::String(crate::plugins::REGISTRY_VERSION.to_string());
                if let Some(options) = &part.plugin_options {
                    obj["options"] = serde_json::Value::Object(
                        options
                            .iter()
                            .map(|(key, value)| (key.clone(), value.to_json()))
                            .collect(),
                    );
                }
            }
            obj
        })
        .collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "unserializable".to_string())
}
