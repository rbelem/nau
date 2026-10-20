//! Freshness of a cached dependency payload (issues #344 + #5).
//!
//! A dep payload's bytes are determined by a recipe *closure*: the
//! member's own recipe plus every `build_deps` member's, walked
//! recursively ([`dep_content_key`]). The key over that closure is
//! written beside the payload at build time (`.content-key`) and
//! compared on every reuse. It is the payload-level counterpart of the
//! lockfile's `recipe_sha256` drift stamps: the stamps say what a
//! *declared* package's closure looked like, the key says what a
//! *payload* was built from.
//!
//! Both mechanisms must agree about what "stale" means, and they scope
//! differently. A normal sync rebuilds a payload whose key moved; a
//! `pod refresh` reconcile must never churn a member it was not asked
//! about (issue #177), so there the mismatch is named loudly and the
//! cached payload is reused — the next normal sync's strict check
//! rebuilds it. [`ContentCheck::for_lane`] is that mapping.
//!
//! A payload with no recorded key (pre-#344) BASELINES loudly and
//! reuses under the strict lane: forcing a rebuild there would break
//! dead-source members on every sync. Under the report lane the
//! baseline stays silent — it belongs to the next normal sync.
//!
//! [`decide`] is pure and [`ContentCheck`] is a plain lane policy, so
//! the rule is unit-tested without a recipe tree. [`apply`] does the
//! sidecar I/O the decision asks for.

use std::path::{Path, PathBuf};

/// How the content-key half of a cached dep payload's reuse check runs.
///
/// - `Strict` (a normal sync): a present key that differs is stale →
///   loud status + REBUILD.
/// - `Report` (a `pod refresh` reconcile, issue #177): a present key
///   that differs → loud status + REUSE. A refresh never churns a
///   member it was not asked about; the next normal sync rebuilds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentCheck {
    Strict,
    Report,
}

impl ContentCheck {
    /// The lane policy: a normal reconcile is strict, a refresh
    /// reconcile is report-only. Both lanes name a stale payload; only
    /// the strict lane acts on it.
    pub(crate) fn for_lane(normal_sync: bool) -> Self {
        if normal_sync {
            Self::Strict
        } else {
            Self::Report
        }
    }

    pub(crate) fn is_strict(self) -> bool {
        matches!(self, Self::Strict)
    }
}

/// What the content key says about a cached payload, before any I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContentDecision {
    /// Recorded key equals the current one: reuse silently.
    Reuse,
    /// Recorded key moved and the lane is strict: name it and rebuild.
    Rebuild,
    /// Recorded key moved and the lane is report-only: name it, reuse.
    ReuseAndReport,
    /// No recorded key (pre-#344 payload): stamp the current key loudly
    /// and reuse — a forced rebuild here is unbounded damage on
    /// dead-source members.
    BaselineAndReuse,
}

/// The pure decision: recorded key (if any) against the freshly computed
/// one, under the caller's lane policy.
pub(crate) fn decide(
    recorded: Option<&str>,
    current: &str,
    check: ContentCheck,
) -> ContentDecision {
    match recorded {
        Some(recorded) if recorded == current => ContentDecision::Reuse,
        Some(_) => match check {
            ContentCheck::Strict => ContentDecision::Rebuild,
            ContentCheck::Report => ContentDecision::ReuseAndReport,
        },
        // The baseline belongs to a normal sync; a refresh reconcile
        // stays silent about a payload it could not have known better
        // than the pre-#344 cache.
        None => match check {
            ContentCheck::Strict => ContentDecision::BaselineAndReuse,
            ContentCheck::Report => ContentDecision::Reuse,
        },
    }
}

/// Run a decision against the cached payload: report, record the
/// baseline when asked, and answer whether the caller may reuse it.
pub(crate) fn apply(
    existing: &Path,
    name: &str,
    version: &str,
    current_key: &str,
    decision: ContentDecision,
) -> miette::Result<bool> {
    match decision {
        ContentDecision::Reuse => Ok(true),
        ContentDecision::ReuseAndReport => {
            crate::output::status(format!(
                "dep payload {name} {version} is stale (recipe or closure content changed) — \
                 reusing cached payload; run `nau pod refresh {name}` to rebuild it \
                 from its current recipe"
            ));
            Ok(true)
        }
        ContentDecision::Rebuild => {
            crate::output::status(format!(
                "dep payload {name} {version} is stale (recipe or closure content changed) — rebuilding"
            ));
            Ok(false)
        }
        ContentDecision::BaselineAndReuse => {
            record_content_key_at(existing, current_key)?;
            crate::output::status(format!(
                "baseline recorded for '{name}': pre-#344 payload carries no content key — \
                 a recipe edit predating it is unrecoverable from the cache; run \
                 `nau pod refresh {name}` to rebuild from its current recipe"
            ));
            Ok(true)
        }
    }
}

/// The reuse decision for a cached dep payload: `true` reuses the cache,
/// `false` falls through to a rebuild. Split from
/// [`crate::pod::ensure_pod_dep_payload`] so the lane gate lives in one
/// small function.
pub(crate) fn reuse_ok(
    existing: &Path,
    name: &str,
    dep_meta: &crate::snap::SnapMeta,
    check: ContentCheck,
) -> miette::Result<bool> {
    let current = dep_content_key(name, dep_meta)?;
    let decision = decide(read_dep_content_key(existing).as_deref(), &current, check);
    apply(existing, name, &dep_meta.version, &current, decision)
}

/// Recompute and record a payload's content key (the post-build half of
/// the contract shared by the dep-ensure path and the top-level build
/// path).
pub(crate) fn record_content_key(
    payload: &Path,
    name: &str,
    meta: &crate::snap::SnapMeta,
) -> miette::Result<()> {
    record_content_key_at(payload, &dep_content_key(name, meta)?)
}

/// The sidecar carrying a built dep payload's CONTENT KEY (issue #344):
/// `<payload>.content-key` beside the payload. The key is the drift
/// detector's recipe-closure hash over the dep's own recipe bytes plus
/// its `build_deps` members' — everything that determines the payload
/// bytes — so a recipe-content fix or a member edit mints a new key and
/// invalidates the cache with no operator rm.
fn dep_content_key_path(payload: &Path) -> PathBuf {
    let mut name = payload.as_os_str().to_os_string();
    name.push(".content-key");
    PathBuf::from(name)
}

/// Compute a dep payload's content key: [`recipe_closure_hash`] (the
/// drift scheme — one canonicalization, not two) over the dep's own
/// recipe bytes followed by its `build_deps` members'. Same recipes →
/// same key; any content edit → a different key.
fn dep_content_key(name: &str, dep_meta: &crate::snap::SnapMeta) -> miette::Result<String> {
    let own = own_recipe_bytes(name)?;
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    let seeds = crate::deps::build_dep_seeds(dep_meta);
    if !seeds.is_empty() {
        for member in crate::deps::resolve_dep_specs(&seeds, true)? {
            if let Some(bytes) = recipe_bytes(&member.name) {
                members.push((member.name, bytes));
            }
        }
    }
    Ok(content_key(name, &own, members))
}

/// The dependency-free key composition: the member's own
/// `(name, recipe bytes)` entry plus its closure's, sorted by name and
/// hashed. Exposed to the module's tests so an own-recipe edit and a
/// closure edit can be told apart without a collection on disk.
fn content_key(name: &str, own: &[u8], mut members: Vec<(String, Vec<u8>)>) -> String {
    members.push((name.to_string(), own.to_vec()));
    members.sort_by(|a, b| a.0.cmp(&b.0));
    recipe_closure_hash(&members)
}

/// One recipe's bytes, resolved the way the drift probe resolves them:
/// file path or collection content. `None` when unresolvable — the
/// caller skips such members (the drift probe's behavior too).
fn recipe_bytes(name: &str) -> Option<Vec<u8>> {
    match crate::pkg_source::resolve_pkg(name) {
        crate::pkg_source::PkgResult::File(path) => std::fs::read(&path).ok(),
        crate::pkg_source::PkgResult::Found { content, .. } => Some(content.into_bytes()),
        crate::pkg_source::PkgResult::NotFound => None,
    }
}

/// The dep's OWN recipe bytes — a dep without a resolvable recipe cannot
/// have a content key at all.
fn own_recipe_bytes(name: &str) -> miette::Result<Vec<u8>> {
    recipe_bytes(name)
        .ok_or_else(|| miette::miette!("recipe of '{name}' not found for the content-key probe"))
}

/// Read a payload's recorded content key; `None` when absent or empty
/// (payloads written before content keys existed — those BASELINE, never
/// adopt: re-adopting possibly-stale bytes is the bug this fixes).
fn read_dep_content_key(payload: &Path) -> Option<String> {
    std::fs::read_to_string(dep_content_key_path(payload))
        .ok()
        .map(|recorded| recorded.trim().to_string())
        .filter(|recorded| !recorded.is_empty())
}

/// Record a payload's content key into its sidecar (same atomic
/// temp-file + rename pattern as the digest sidecar).
fn record_content_key_at(payload: &Path, key: &str) -> miette::Result<()> {
    let key_path = dep_content_key_path(payload);
    let tmp = payload.with_file_name(format!(
        ".{}.tmp-{}",
        key_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("payload.content-key"),
        std::process::id()
    ));
    std::fs::write(&tmp, key).map_err(|e| miette::miette!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &key_path)
        .map_err(|e| miette::miette!("finalizing {}: {e}", key_path.display()))?;
    Ok(())
}

/// SHA-256 over the canonical listing the caller feeds (issues #142 +
/// #172): entries sorted by member name (sorted by the caller), each
/// fed into one running hash as `name \0 <length> \0 bytes` — the
/// NAR-style convention of [`crate::pkg_source::content_hash`] (sorted
/// paths + contents), lifted one level: the members are the paths, the
/// recipe bytes the contents. The length prefix keeps adjacent entries
/// unambiguous. Under the v2 scheme the listing leads with the
/// package's own `(name, recipe_bytes)` entry, so an own-recipe edit
/// moves the digest exactly like a member edit.
pub(crate) fn recipe_closure_hash(entries: &[(String, Vec<u8>)]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    for (name, bytes) in entries {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, bytes: &[u8]) -> (String, Vec<u8>) {
        (name.to_string(), bytes.to_vec())
    }

    fn temp_payload() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = dir.path().join("member_1.0_amd64.snap");
        std::fs::write(&payload, b"payload-bytes").expect("write payload");
        (dir, payload)
    }

    /// A member whose OWN recipe changed: the key moves, and a normal
    /// sync's strict check rebuilds it.
    #[test]
    fn own_recipe_edit_moves_the_key_and_rebuilds() {
        let before = content_key("member", b"recipe-v1", Vec::new());
        let after = content_key("member", b"recipe-v2", Vec::new());
        assert_ne!(before, after, "an own-recipe edit must move the key");
        assert_eq!(
            decide(Some(&before), &after, ContentCheck::Strict),
            ContentDecision::Rebuild
        );
    }

    /// A member whose closure changed while its own recipe did not: the
    /// key still moves (the closure is hashed into it). Strict rebuilds;
    /// a refresh reconcile reports and reuses (#177 scoping).
    #[test]
    fn closure_edit_with_unchanged_own_recipe_follows_the_lane_rule() {
        let before = content_key("member", b"own", vec![member("dep", b"dep-v1")]);
        let after = content_key("member", b"own", vec![member("dep", b"dep-v2")]);
        assert_ne!(
            before, after,
            "a closure member edit must move the key even when the own recipe is unchanged"
        );
        assert_eq!(
            decide(Some(&before), &after, ContentCheck::Strict),
            ContentDecision::Rebuild,
            "a normal sync must rebuild a payload whose closure moved"
        );
        assert_eq!(
            decide(Some(&before), &after, ContentCheck::Report),
            ContentDecision::ReuseAndReport,
            "a refresh names the stale member and still reuses it"
        );
    }

    /// The same closure and own recipe hash to the same key, regardless
    /// of the order the closure resolved in.
    #[test]
    fn key_is_order_independent() {
        let a = content_key(
            "member",
            b"own",
            vec![member("b", b"bb"), member("a", b"aa")],
        );
        let b = content_key(
            "member",
            b"own",
            vec![member("a", b"aa"), member("b", b"bb")],
        );
        assert_eq!(a, b);
        assert_eq!(
            decide(Some(&a), &b, ContentCheck::Strict),
            ContentDecision::Reuse
        );
    }

    /// A pre-#344 payload has no key. The strict lane BASELINES loudly
    /// and reuses, and the baseline sidecar is written so the next sync
    /// compares against it.
    #[test]
    fn missing_key_baselines_loudly_and_reuses() {
        let (_dir, payload) = temp_payload();
        let key = content_key("member", b"recipe", Vec::new());
        assert_eq!(read_dep_content_key(&payload), None);
        assert_eq!(
            decide(None, &key, ContentCheck::Strict),
            ContentDecision::BaselineAndReuse
        );

        let reuse = apply(
            &payload,
            "member",
            "1.0",
            &key,
            ContentDecision::BaselineAndReuse,
        )
        .expect("baseline");
        assert!(reuse, "the baseline arm reuses the cached payload");
        assert_eq!(
            read_dep_content_key(&payload).as_deref(),
            Some(key.as_str()),
            "the baseline must be recorded for the next sync"
        );
    }

    /// A refresh reconcile leaves a pre-#344 payload alone: the baseline
    /// belongs to the next normal sync, so no sidecar is written here.
    #[test]
    fn refresh_does_not_baseline_a_missing_key() {
        let (_dir, payload) = temp_payload();
        let key = content_key("member", b"recipe", Vec::new());
        assert_eq!(
            decide(None, &key, ContentCheck::Report),
            ContentDecision::Reuse
        );
        let reuse = apply(&payload, "member", "1.0", &key, ContentDecision::Reuse).expect("reuse");
        assert!(reuse);
        assert_eq!(
            read_dep_content_key(&payload),
            None,
            "a refresh must not stamp a baseline it did not verify"
        );
    }

    /// The lane mapping: normal reconcile strict, refresh report-only. A
    /// refresh therefore never rebuilds an unrelated stale member.
    #[test]
    fn lane_scoping_never_churns_a_refresh_member() {
        assert_eq!(ContentCheck::for_lane(true), ContentCheck::Strict);
        assert_eq!(ContentCheck::for_lane(false), ContentCheck::Report);
        assert!(ContentCheck::for_lane(true).is_strict());
        assert!(!ContentCheck::for_lane(false).is_strict());
        assert_eq!(
            decide(Some("old"), "new", ContentCheck::for_lane(false)),
            ContentDecision::ReuseAndReport
        );
    }

    /// A recorded key that still matches is silent under both lanes.
    #[test]
    fn matching_key_reuses_silently_in_both_lanes() {
        assert_eq!(
            decide(Some("same"), "same", ContentCheck::Strict),
            ContentDecision::Reuse
        );
        assert_eq!(
            decide(Some("same"), "same", ContentCheck::Report),
            ContentDecision::Reuse
        );
    }

    /// The sidecar is file-level: absent/empty reads as None, recording
    /// is atomic, and a recorded key reads back.
    #[test]
    fn content_key_sidecar_roundtrip() {
        let (_dir, payload) = temp_payload();
        assert!(read_dep_content_key(&payload).is_none(), "absent → None");
        record_content_key_at(&payload, "abc123").expect("record");
        assert_eq!(read_dep_content_key(&payload).as_deref(), Some("abc123"));
    }
}
