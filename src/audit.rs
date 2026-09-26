//! `shuttle audit` — OSV/CVE scanning over lockfiles (issue #52).
//!
//! Shuttle fetches npm/pip/cargo/go dependency closures (ADR-0017), so it
//! owns a supply chain the Snap Store review does not cover. `shuttle
//! audit` checks every pinned entry of a lockfile — the project's
//! `shuttle.lock` or a pod's — against the OSV vulnerability database.
//!
//! # Why a sibling command, not a registry check
//!
//! The #53 check battery documents an OFFLINE guarantee ("every check
//! consumes only local data") and consumes declaration evals, not
//! lockfiles. The audit's whole point is a bounded network pass with a
//! local cache fallback, over resolved pins — a different contract on
//! both axes, so it ships as a sibling command that reuses the
//! [`crate::checks::Finding`]/[`Severity`] shape and the `--json` report
//! shape verbatim.
//!
//! # Confidence model (the store-revision caveat)
//!
//! The issue's council review flags the hard part: `store`-type pins are
//! keyed by Snap Store revision, which no OSV ecosystem speaks. Every
//! audited entry therefore carries an explicit confidence:
//!
//! - [`Confidence::Exact`] — ecosystem proven by a registry URL (npm,
//!   PyPI, crates.io, Go proxy) plus a version from that URL. A hit is a
//!   confirmed CVE in a pinned version → **error**.
//! - [`Confidence::Extracted`] — a version exists (declared in the
//!   definition, resolved in the lockfile, or extracted from a GitHub
//!   tag) but no OSV ecosystem. The OSV API rejects ecosystem-less
//!   queries, so the target fans out over the candidate ecosystems
//!   ([`EXTRACTED_ECOSYSTEMS`]), version-filtered; a hit is
//!   version-matched → **error**, naming the ecosystem it matched by
//!   (the lockfile proves the version, not the ecosystem).
//! - [`Confidence::NameOnly`] — store snaps: only a name and a store
//!   revision. Name-matched against the Debian/Ubuntu OSV databases;
//!   every advisory for the name counts into ONE bounded summary
//!   warning per snap — NEVER a confirmed CVE → **warning** naming the
//!   revision gap.
//! - [`Confidence::Unmapped`] — nothing queryable derivable → **warning**;
//!   the pin is reported as unauditable rather than silently skipped.
//!
//! Dependency closures (ADR-0017) are pinned by content hash only — the
//! lockfile does not enumerate their transitive packages — so each
//! deps-bearing package carries one explicit under-report warning.
//!
//! # Offline-first
//!
//! Online, queries go to `POST /v1/querybatch` (curl, one batch per ≤1000
//! queries) and every per-query response is cached under the shuttle
//! cache dir keyed by the canonical query JSON. Offline, cached responses
//! still produce findings (tagged with their fetch date); queries with
//! neither cache nor network degrade to a named `shuttle audit
//! --update` warning. Exit 1 only on confirmed findings — an audit that
//! hard-requires the network, or that fails on a stale database, is an
//! audit nobody runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::checks::{Finding, Severity};
use crate::lock::LockFile;

/// The stable check name on every audit finding.
pub const CHECK: &str = "osv";

/// Default OSV batch-query endpoint.
pub const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// The OSV API caps one querybatch request at 1000 queries.
const BATCH_CHUNK: usize = 1000;

// ── Targets ──

/// How confidently a lockfile entry maps to a queryable OSV identity.
/// Drives both the query shape and the ceiling severity of any hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Ecosystem proven (registry URL) + version from that URL: a hit is
    /// a confirmed CVE in a pinned version.
    Exact,
    /// A version exists (declared, resolved, or URL-extracted) but no OSV
    /// ecosystem: queried as upstream name+version.
    Extracted,
    /// No version derivable (store snaps pin revisions): name-only query.
    NameOnly,
    /// Nothing queryable derivable: reported unauditable.
    Unmapped,
}

/// One auditable lockfile entry.
#[derive(Debug, Clone)]
pub struct AuditTarget {
    /// Finding label: the declaration output key when known, else the
    /// extracted name, else the raw URL.
    pub package: String,
    /// Lockfile section the entry came from: `"source"`, `"package"`, or
    /// `"snap"`.
    pub kind: &'static str,
    /// The name sent to OSV (empty only when unmapped).
    pub name: String,
    pub version: Option<String>,
    /// OSV ecosystem, only when a registry URL proves it.
    pub ecosystem: Option<&'static str>,
    /// Snap Store revision (snaps only).
    pub revision: Option<u32>,
    pub confidence: Confidence,
    /// Where name/version came from — surfaced verbatim in findings.
    pub provenance: String,
}

/// (name, version, ecosystem) extracted from a source pin URL.
type UrlParts = (Option<String>, Option<String>, Option<&'static str>);

/// Classify a source pin URL into (name, version, ecosystem). Registry
/// hosts yield full triples or nothing (a half-parse would query garbage);
/// GitHub yields (repo, tag version); anything else is unmapped.
fn classify_source_url(url: &str) -> UrlParts {
    if url.contains("registry.npmjs.org") {
        return npm_source(url);
    }
    if url.contains("files.pythonhosted.org") || url.contains("pypi.org") {
        return pypi_source(url);
    }
    if url.contains("crates.io") {
        return crates_source(url);
    }
    if url.contains("proxy.golang.org") {
        return golang_source(url);
    }
    if url.contains("github.com") || url.contains("githubusercontent.com") {
        return github_source(url);
    }
    (None, None, None)
}

/// `https://registry.npmjs.org/[@scope/]name/-/name-1.2.3.tgz`
fn npm_source(url: &str) -> UrlParts {
    let Some(path) = url.split("registry.npmjs.org").nth(1) else {
        return (None, None, None);
    };
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (name, file) = match segs.as_slice() {
        [scope, n, dash, f] if scope.starts_with('@') && *dash == "-" => {
            (format!("{scope}/{n}"), *f)
        }
        [n, dash, f] if *dash == "-" => ((*n).to_string(), *f),
        _ => return (None, None, None),
    };
    // Tarball filenames use the UNSCOPED name ("core-7.23.0.tgz" for
    // "@babel/core") — the base is the name's last path segment.
    let base = name.rsplit('/').next().unwrap_or(&name);
    let version = file
        .strip_prefix(&format!("{base}-"))
        .and_then(|v| v.strip_suffix(".tgz"))
        .map(String::from);
    match version {
        Some(v) => (Some(name), Some(v), Some("npm")),
        None => (None, None, None),
    }
}

/// PyPI distribution filenames: `<name>-<version>.{whl,tar.gz,zip}`.
/// Names are normalized (PEP 503) so OSV matches them.
fn pypi_source(url: &str) -> UrlParts {
    let Some(file) = url.rsplit('/').next() else {
        return (None, None, None);
    };
    let lower = file.to_lowercase();
    if let Some(stem) = lower.strip_suffix(".whl") {
        // PEP 427 wheel: name-version-pytag-abitag-plattag.whl
        let mut parts = stem.splitn(3, '-');
        if let (Some(n), Some(v)) = (parts.next(), parts.next()) {
            return (Some(pypi_normalize(n)), Some(v.to_string()), Some("PyPI"));
        }
        return (None, None, None);
    }
    for ext in [".tar.gz", ".zip"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            if let Some((n, v)) = stem.rsplit_once('-') {
                return (Some(pypi_normalize(n)), Some(v.to_string()), Some("PyPI"));
            }
        }
    }
    (None, None, None)
}

/// PEP 503 name normalization: lowercase, runs of `-_.` → `-`.
fn pypi_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// crates.io shapes: `crates.io/api/v1/crates/{name}/{version}/download`
/// and `static.crates.io/crates/{name}/{name}-{version}.crate`.
fn crates_source(url: &str) -> UrlParts {
    if let Some(rest) = url.split("/api/v1/crates/").nth(1) {
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        if let [name, version, ..] = segs.as_slice() {
            return (
                Some((*name).to_string()),
                Some((*version).to_string()),
                Some("crates.io"),
            );
        }
        return (None, None, None);
    }
    let Some(rest) = url.split("/crates/").nth(1) else {
        return (None, None, None);
    };
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let [name, file] = segs.as_slice() else {
        return (None, None, None);
    };
    let version = file
        .strip_prefix(&format!("{name}-"))
        .and_then(|v| v.strip_suffix(".crate"))
        .map(String::from);
    match version {
        Some(v) => (Some((*name).to_string()), Some(v), Some("crates.io")),
        None => (None, None, None),
    }
}

/// Go module proxy: `proxy.golang.org/{module}/@v/{version}.{zip,info,mod}`.
/// The version is kept verbatim (v-prefixed, as the proxy serves it).
fn golang_source(url: &str) -> UrlParts {
    let Some(path) = url.split("proxy.golang.org").nth(1) else {
        return (None, None, None);
    };
    let Some((module, vfile)) = path.rsplit_once("/@v/") else {
        return (None, None, None);
    };
    let module = module.trim_start_matches('/');
    if module.is_empty() {
        return (None, None, None);
    }
    // Versions carry dots ("v0.17.0.zip") — strip known suffixes, never
    // split on '.'.
    let stem = vfile
        .strip_suffix(".zip")
        .or_else(|| vfile.strip_suffix(".info"))
        .or_else(|| vfile.strip_suffix(".mod"))
        .unwrap_or(vfile);
    if stem.is_empty() {
        return (None, None, None);
    }
    (Some(module.to_string()), Some(stem.to_string()), Some("Go"))
}

/// GitHub URLs. Archive/release URLs carry the tag (version); any other
/// github.com URL still yields the repo name (no version) so the declared
/// enrichment can apply. githubusercontent blob/raw shapes vary too much
/// to name reliably — those stay unmapped unless a marker matches.
fn github_source(url: &str) -> UrlParts {
    if let Some(parts) = github_marker_source(url) {
        return parts;
    }
    if url.contains("github.com") {
        if let Some(path) = url.split("github.com").nth(1) {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if let [_, repo, ..] = segs.as_slice() {
                return (Some((*repo).to_string()), None, None);
            }
        }
    }
    (None, None, None)
}

/// The `/archive/` and `/releases/download/` URL shapes, which carry a
/// tag: `/{owner}/{repo}/archive/refs/tags/v1.2.3.tar.gz` and
/// `/{owner}/{repo}/releases/download/v1.2.3/{file}`.
fn github_marker_source(url: &str) -> Option<UrlParts> {
    for marker in ["/archive/", "/releases/download/"] {
        let Some((before, after)) = url.split_once(marker) else {
            continue;
        };
        let repo = before.rsplit('/').find(|s| !s.is_empty())?;
        if repo.is_empty() {
            continue;
        }
        let tagged = after.strip_prefix("refs/tags/").unwrap_or(after);
        let mut tag = tagged.split('/').find(|s| !s.is_empty()).unwrap_or("");
        // Archive URLs name the file after the tag ("v6.1.tar.gz") —
        // strip the archive suffix; release-download tags are bare dirs.
        for ext in [".tar.gz", ".tgz", ".zip"] {
            if let Some(stem) = tag.strip_suffix(ext) {
                tag = stem;
                break;
            }
        }
        // Strip a leading `v` only when a version follows it ("v6.1" →
        // "6.1"); plain tags ("2.3.4") pass through verbatim.
        let version = tag
            .strip_prefix('v')
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(tag);
        let version = (!version.is_empty()).then(|| version.to_string());
        return Some((Some(repo.to_string()), version, None));
    }
    None
}

/// A source URL's declared context, read off a raw eval output: the
/// output key (the finding label), the snap name, and the declared
/// version.
#[derive(Debug, Clone)]
struct Declared {
    key: String,
    version: Option<String>,
}

/// Map every source URL declared by a raw eval output to its declared
/// context. First output (sorted key order) wins on duplicate URLs.
fn declared_sources(raw: &BTreeMap<String, serde_json::Value>) -> BTreeMap<String, Declared> {
    let mut out: BTreeMap<String, Declared> = BTreeMap::new();
    for (key, value) in raw {
        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);
        let mut urls: Vec<String> = Vec::new();
        if let Some(s) = value.get("source").and_then(|s| s.as_str()) {
            urls.push(s.to_string());
        }
        if let Some(list) = value.get("sources").and_then(|s| s.as_array()) {
            urls.extend(list.iter().filter_map(|s| s.as_str()).map(String::from));
        }
        for url in urls {
            out.entry(url).or_insert(Declared {
                key: key.clone(),
                version: version.clone(),
            });
        }
    }
    out
}

/// Sorted lockfile map keys — the deterministic iteration order.
fn sorted_keys<T>(map: &std::collections::HashMap<String, T>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    keys
}

/// Build the audit target for one `sources` entry. Registry-derived
/// identities win (they prove the ecosystem); otherwise the declared
/// version, else the URL tag; a versionless non-registry URL stays
/// unmapped rather than queried name-only (name-only queries are
/// reserved for store snaps, whose names are canonical upstream names).
fn source_target(url: &str, declared: Option<&Declared>) -> AuditTarget {
    let (name, url_version, ecosystem) = classify_source_url(url);
    let package = declared
        .map(|d| d.key.clone())
        .or_else(|| name.clone())
        .unwrap_or_else(|| url.to_string());
    match (name, ecosystem) {
        (Some(name), Some(eco)) => AuditTarget {
            package,
            kind: "source",
            name,
            version: url_version,
            ecosystem: Some(eco),
            revision: None,
            confidence: Confidence::Exact,
            provenance: format!("version from the {eco} registry URL"),
        },
        (Some(name), None) => {
            let effective = url_version
                .clone()
                .or_else(|| declared.and_then(|d| d.version.clone()));
            match effective {
                Some(version) => {
                    let provenance = if url_version.is_some() {
                        "version from the source URL tag".to_string()
                    } else if let Some(d) = declared {
                        format!("declared version of output '{}'", d.key)
                    } else {
                        String::new()
                    };
                    AuditTarget {
                        package,
                        kind: "source",
                        name,
                        version: Some(version),
                        ecosystem: None,
                        revision: None,
                        confidence: Confidence::Extracted,
                        provenance,
                    }
                }
                None => AuditTarget {
                    package,
                    kind: "source",
                    name,
                    version: None,
                    ecosystem: None,
                    revision: None,
                    confidence: Confidence::Unmapped,
                    provenance: "versionless source URL — no upstream version derivable"
                        .to_string(),
                },
            }
        }
        _ => AuditTarget {
            package,
            kind: "source",
            name: String::new(),
            version: None,
            ecosystem: None,
            revision: None,
            confidence: Confidence::Unmapped,
            provenance: "no upstream name/version derivable from the URL".to_string(),
        },
    }
}

/// Every auditable entry in the lockfile, in deterministic order:
/// `sources` (URL pins), `packages` (pod packages with resolved
/// versions), `snaps` (store pins). `raw` — the evaluated definition's
/// outputs, when a definition was given — enriches source pins with
/// declared versions and output-key labels.
pub fn collect_targets(
    lock: &LockFile,
    raw: Option<&BTreeMap<String, serde_json::Value>>,
) -> Vec<AuditTarget> {
    let declared = raw.map(declared_sources);
    let mut out = Vec::new();
    for url in sorted_keys(&lock.sources) {
        out.push(source_target(
            url,
            declared.as_ref().and_then(|d| d.get(url)),
        ));
    }
    for name in sorted_keys(&lock.packages) {
        let entry = &lock.packages[name.as_str()];
        out.push(package_target(name, entry.version.as_str()));
    }
    for name in sorted_keys(&lock.snaps) {
        let entry = &lock.snaps[name.as_str()];
        out.push(AuditTarget {
            package: name.clone(),
            kind: "snap",
            name: name.clone(),
            version: None,
            ecosystem: None,
            revision: Some(entry.revision),
            confidence: Confidence::NameOnly,
            provenance: format!(
                "store revision {} — no upstream version recorded in the lockfile",
                entry.revision
            ),
        });
    }
    out
}

/// One `packages` entry: the resolved version makes it an Extracted
/// upstream identity; a versionless entry is unmapped.
fn package_target(name: &str, version: &str) -> AuditTarget {
    if version.is_empty() {
        return AuditTarget {
            package: name.to_string(),
            kind: "package",
            name: name.to_string(),
            version: None,
            ecosystem: None,
            revision: None,
            confidence: Confidence::Unmapped,
            provenance: "the lockfile records no resolved version".to_string(),
        };
    }
    AuditTarget {
        package: name.to_string(),
        kind: "package",
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: None,
        revision: None,
        confidence: Confidence::Extracted,
        provenance: "resolved version pinned in the lockfile".to_string(),
    }
}

// ── Queries ──

/// Ecosystems an Extracted target (version known, ecosystem unknown) is
/// fanned out over. REGISTRY ecosystems only: their name+version
/// identity is canonical ("requests 2.28.0" in PyPI is the same
/// artifact the lockfile pins). Distro ecosystems (Debian/Ubuntu) are
/// deliberately excluded — distro source-package names and patched
/// versions double-translate upstream identity, and a GitHub tag fanned
/// into Debian's kernel package produced thousands of false
/// version-matches in live testing. The matched ecosystem is named on
/// every finding because the lockfile does not PROVE the package
/// belongs to it. First cut set — extensible.
pub const EXTRACTED_ECOSYSTEMS: &[&str] = &["PyPI", "npm", "crates.io", "Go"];

/// Ecosystems a store snap is name-matched against: snaps ship
/// Ubuntu-family software, and the Debian/Ubuntu OSV databases track the
/// same upstream projects. Name-only queries return every advisory for
/// the name in that ecosystem, so per-snap results are summarized into
/// one bounded warning rather than sprayed per advisory.
pub const SNAP_ECOSYSTEMS: &[&str] = &["Debian", "Ubuntu"];

/// The candidate ecosystems for one target, in query order.
fn candidate_ecosystems(t: &AuditTarget) -> Vec<&'static str> {
    match t.confidence {
        Confidence::Exact => t.ecosystem.into_iter().collect(),
        Confidence::Extracted => EXTRACTED_ECOSYSTEMS.to_vec(),
        Confidence::NameOnly => SNAP_ECOSYSTEMS.to_vec(),
        Confidence::Unmapped => Vec::new(),
    }
}

/// The OSV query for one target within one ecosystem — `None` when the
/// target has nothing queryable. The OSV API requires `ecosystem` on
/// every package query (ecosystem-less queries are rejected with 400),
/// which is why non-exact targets fan out over candidates instead.
fn osv_query(t: &AuditTarget, eco: &str) -> Option<serde_json::Value> {
    if t.name.is_empty() {
        return None;
    }
    match t.confidence {
        Confidence::Unmapped => None,
        Confidence::NameOnly => Some(json!({ "package": { "name": t.name, "ecosystem": eco } })),
        Confidence::Extracted | Confidence::Exact => {
            let v = t.version.as_deref()?;
            Some(json!({ "package": { "name": t.name, "ecosystem": eco, "version": v } }))
        }
    }
}

// ── Cache + client ──

/// Where the audit talks to OSV and keeps its responses. Constructed
/// from env at the CLI layer; tests build it explicitly.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// The querybatch endpoint (`SHUTTLE_OSV_URL` overrides).
    pub url: String,
    /// Response cache directory (`SHUTTLE_AUDIT_CACHE` overrides; default
    /// `~/.cache/shuttle/audit/`).
    pub cache_dir: PathBuf,
    /// Bypass cache reads and refetch everything (`--update`).
    pub update: bool,
}

impl AuditConfig {
    pub fn from_env(update: bool) -> Self {
        let url = std::env::var("SHUTTLE_OSV_URL").unwrap_or_else(|_| OSV_BATCH_URL.to_string());
        let cache_dir = std::env::var("SHUTTLE_AUDIT_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                Path::new(&home)
                    .join(".cache")
                    .join("shuttle")
                    .join("audit")
            });
        AuditConfig {
            url,
            cache_dir,
            update,
        }
    }
}

/// One query's resolved OSV data: the `results[i]` object (which carries
/// `vulns` when anything matched) plus the date it was fetched — the
/// staleness tag surfaced on cache-served findings.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub result: serde_json::Value,
    pub queried_at: String,
}

/// The outcome of resolving a set of queries against cache + network.
#[derive(Debug, Default)]
pub struct FetchOutcome {
    /// Aligned with the requested unique queries; `None` = unavailable.
    pub entries: Vec<Option<Fetched>>,
    /// True when the network was needed but failed (offline/timeout).
    pub degraded: bool,
}

/// `YYYY-MM-DD` (UTC) for cache staleness tags — the same days-from-epoch
/// civil conversion dep_fetch uses.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_date(secs)
}

/// Days-from-epoch → civil date (Howard Hinnant's algorithm, verbatim
/// from dep_fetch's tested implementation).
fn iso_date(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    // Hinnant's year shift: in this day-numbering March is month 0 of
    // the internal year, so Jan/Feb belong to the NEXT internal year —
    // the civil year is one lower than `yoe + era*400` for m ≤ 2.
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Canonical cache key for one query: sha256 over the serialized query
/// (serde_json maps serialize in sorted key order, so the key is stable).
fn cache_key(query: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(query.to_string().as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn cache_path(cache_dir: &Path, query: &serde_json::Value) -> PathBuf {
    cache_dir.join(format!("osv-{}.json", cache_key(query)))
}

/// Read one cached response. Corrupt or unreadable files are treated as
/// absent — a tampered cache degrades to a refetch, never a crash.
fn cache_read(cache_dir: &Path, query: &serde_json::Value) -> Option<Fetched> {
    let text = std::fs::read_to_string(cache_path(cache_dir, query)).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(Fetched {
        result: value.get("response")?.clone(),
        queried_at: value
            .get("queried_at")
            .and_then(|d| d.as_str())
            .unwrap_or("unknown")
            .to_string(),
    })
}

fn cache_write(cache_dir: &Path, query: &serde_json::Value, fetched: &Fetched) {
    if std::fs::create_dir_all(cache_dir).is_err() {
        return; // cache is best-effort
    }
    let entry = json!({ "queried_at": fetched.queried_at, "response": fetched.result });
    let _ = std::fs::write(cache_path(cache_dir, query), entry.to_string());
}

/// The curl binary path through the tools module (issue #101): curl
/// resolves PATH-first with the provisioned fallback, and `ensure` is its
/// mid-build entry (for curl it is the resolve path).
fn curl_tool() -> miette::Result<PathBuf> {
    let resolved = crate::tools::ensure(crate::tools::ToolName::Curl)
        .map_err(|e| miette::miette!("resolve curl: {e}"))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path,
    })
}

/// POST one querybatch chunk to the OSV endpoint via curl (the repo's
/// HTTP client — no new dependencies). Bounded: 5s connect, 60s total.
fn curl_querybatch(
    url: &str,
    queries: &[&serde_json::Value],
) -> miette::Result<Vec<serde_json::Value>> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let inp = work.path().join("query.json");
    let outp = work.path().join("response.json");
    let body = json!({ "queries": queries });
    std::fs::write(&inp, body.to_string())
        .map_err(|e| miette::miette!("writing OSV request: {e}"))?;
    let curl = curl_tool()?;
    let out = std::process::Command::new(&curl)
        .args([
            "-fsSL",
            "--connect-timeout",
            "5",
            "--max-time",
            "60",
            "-H",
            "Content-Type: application/json",
            "-A",
            concat!("shuttle/", env!("CARGO_PKG_VERSION"), " (osv audit)"),
            "--data-binary",
        ])
        .arg(format!("@{}", inp.display()))
        .arg(url)
        .arg("-o")
        .arg(&outp)
        .output()
        .map_err(|e| miette::miette!("curl not found: {e}"))?;
    if !out.status.success() {
        let tail = String::from_utf8_lossy(&out.stderr);
        let tail = tail.lines().last().unwrap_or("").trim();
        miette::bail!(
            "OSV query failed (curl exit {:?}): {tail}",
            out.status.code()
        );
    }
    let text =
        std::fs::read_to_string(&outp).map_err(|e| miette::miette!("reading OSV response: {e}"))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| miette::miette!("OSV response is not valid JSON: {e}"))?;
    let results = value
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(|| miette::miette!("OSV response carries no 'results' array"))?;
    Ok(results.clone())
}

/// Resolve every unique query: cache first (unless `update`), then one
/// batched network pass for the misses. A network failure degrades —
/// missing entries stay `None` and the caller warns; cached results keep
/// the audit useful offline.
fn fetch_queries(cfg: &AuditConfig, queries: &[serde_json::Value]) -> FetchOutcome {
    let mut entries: Vec<Option<Fetched>> = Vec::with_capacity(queries.len());
    let mut missing: Vec<usize> = Vec::new();
    for query in queries {
        let hit = if cfg.update {
            None
        } else {
            cache_read(&cfg.cache_dir, query)
        };
        if hit.is_none() {
            missing.push(entries.len());
        }
        entries.push(hit);
    }
    let mut degraded = false;
    if !missing.is_empty() {
        let unique_queries: Vec<&serde_json::Value> =
            missing.iter().map(|&i| &queries[i]).collect();
        match batch_all(&cfg.url, &unique_queries) {
            Ok(results) => {
                for (slot, result) in missing.iter().zip(&results) {
                    let fetched = Fetched {
                        result: result.clone().unwrap_or(json!({})),
                        queried_at: today(),
                    };
                    cache_write(&cfg.cache_dir, &queries[*slot], &fetched);
                    entries[*slot] = Some(fetched);
                }
            }
            Err(reason) => {
                degraded = true;
                crate::output::warn(format!(
                    "OSV querybatch failed — serving what the local cache has: {reason}"
                ));
            }
        }
    }
    FetchOutcome { entries, degraded }
}

/// Batch queries in API-sized chunks; each query gets its results-array
/// entry (missing/short results → `None`).
fn batch_all(
    url: &str,
    queries: &[&serde_json::Value],
) -> miette::Result<Vec<Option<serde_json::Value>>> {
    let mut out = Vec::with_capacity(queries.len());
    for chunk in queries.chunks(BATCH_CHUNK) {
        let results = curl_querybatch(url, chunk)?;
        for i in 0..chunk.len() {
            out.push(results.get(i).cloned());
        }
    }
    Ok(out)
}

// ── Findings ──

fn finding(package: &str, severity: Severity, message: String, hint: String) -> Finding {
    Finding {
        check: CHECK,
        package: package.to_string(),
        severity,
        message,
        hint,
    }
}

/// One advisory's CVE aliases ("CVE-…" only).
fn vuln_cves(v: &serde_json::Value) -> String {
    let cves: Vec<&str> = v
        .get("aliases")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter(|s| s.starts_with("CVE-"))
                .collect()
        })
        .unwrap_or_default();
    if cves.is_empty() {
        String::new()
    } else {
        format!(" ({})", cves.join(", "))
    }
}

/// One advisory's one-line summary (details' first line, truncated; falls
/// back to the id when neither carries prose).
fn vuln_summary(v: &serde_json::Value, id: &str) -> String {
    let raw = v
        .get("summary")
        .and_then(|s| s.as_str())
        .or_else(|| v.get("details").and_then(|s| s.as_str()))
        .unwrap_or("");
    let mut summary: String = raw.lines().next().unwrap_or("").to_string();
    if summary.is_empty() {
        summary = id.to_string();
    }
    if summary.chars().count() > 160 {
        summary = summary.chars().take(157).collect::<String>() + "...";
    }
    summary
}

/// One advisory's display pieces: id, CVE aliases, one-line summary.
fn vuln_pieces(v: &serde_json::Value) -> (String, String, String) {
    let id = v
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("unknown-vuln")
        .to_string();
    let cves = vuln_cves(v);
    let summary = vuln_summary(v, &id);
    (id, cves, summary)
}

/// Confirmed (version-matched) advisory → error finding. The message
/// states the matched identity, the provenance of the version, and the
/// data's fetch date — a confirmed label is only as fresh as its
/// database. When the ecosystem was matched by name (Extracted
/// fan-out), the message says so: the lockfile proves the version, not
/// the ecosystem.
fn confirmed_finding(
    t: &AuditTarget,
    eco: &str,
    id: &str,
    cves: &str,
    summary: &str,
    queried_at: &str,
) -> Finding {
    let version = t.version.as_deref().unwrap_or("(none)");
    let eco_label = if t.ecosystem == Some(eco) {
        eco.to_string()
    } else {
        format!("{eco} (ecosystem matched by name)")
    };
    // Debian-style records carry no prose — don't render "GHSA-x: GHSA-x".
    let summary_part = if summary == id {
        String::new()
    } else {
        format!(": {summary}")
    };
    finding(
        &t.package,
        Severity::Error,
        format!(
            "{id}{cves}{summary_part} — affects {name} {version} [{eco_label}]; {provenance}; \
             OSV data {queried_at}",
            name = t.name,
            provenance = t.provenance,
        ),
        format!(
            "upgrade {name} to a version fixed per {id} and re-lock \
             (`shuttle lock`, or `shuttle deps fetch --latest` for closures)",
            name = t.name
        ),
    )
}

/// Name-only advisory (store snaps) → ONE bounded summary warning per
/// snap, however many advisories name-match: a raw spray (curl carries
/// 100+ Debian advisories) would drown the report. Never claims
/// confirmation — a store revision is not an upstream version.
fn name_only_summary_finding(
    t: &AuditTarget,
    hits: &[(&'static str, String)],
    queried_at: &str,
) -> Finding {
    let revision = t.revision.map(|r| r.to_string()).unwrap_or("?".into());
    let mut per_eco: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut examples: Vec<&str> = Vec::new();
    for (eco, id) in hits {
        *per_eco.entry(eco).or_default() += 1;
        if examples.len() < 3 {
            examples.push(id.as_str());
        }
    }
    let eco_counts: Vec<String> = per_eco
        .into_iter()
        .map(|(eco, n)| format!("{eco} {n}"))
        .collect();
    let (noun, verb) = if hits.len() == 1 {
        ("advisory", "name-matches")
    } else {
        ("advisories", "name-match")
    };
    finding(
        &t.package,
        Severity::Warn,
        format!(
            "{n} {noun} {verb} snap '{name}' ({ecos}) — a store revision \
             ({revision}) is not an upstream version, so NONE can be confirmed against \
             a pinned version; for example: {examples}; OSV data {queried_at}",
            n = hits.len(),
            name = t.name,
            ecos = eco_counts.join(", "),
            examples = examples.join(", "),
        ),
        "resolve the snap's upstream version and re-audit; treat as unconfirmed until then"
            .to_string(),
    )
}

/// All findings for one target given its per-ecosystem fetched results.
/// Exact and Extracted targets get one error per unique advisory
/// (deduplicated across the fan-out); name-only targets get one summary
/// warning.
fn target_findings(t: &AuditTarget, results: &[(String, Option<Fetched>)]) -> Vec<Finding> {
    let mut hits: Vec<(&'static str, String)> = Vec::new();
    let mut queried_at = String::new();
    let mut seen = BTreeSet::new();
    let mut confirmed = Vec::new();
    for (eco, fetched) in results {
        let Some(eco) = static_eco(eco) else {
            continue;
        };
        let Some(fetched) = fetched else {
            continue;
        };
        if queried_at.is_empty() {
            queried_at = fetched.queried_at.clone();
        }
        for v in fetched
            .result
            .get("vulns")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let (id, cves, summary) = vuln_pieces(v);
            match t.confidence {
                Confidence::NameOnly => {
                    if seen.insert(id.clone()) {
                        hits.push((eco, id));
                    }
                }
                _ => {
                    if seen.insert(id.clone()) {
                        confirmed.push(confirmed_finding(
                            t,
                            eco,
                            &id,
                            &cves,
                            &summary,
                            &fetched.queried_at,
                        ));
                    }
                }
            }
        }
    }
    match t.confidence {
        Confidence::NameOnly if !hits.is_empty() => {
            vec![name_only_summary_finding(t, &hits, &queried_at)]
        }
        _ => confirmed,
    }
}

/// Recover the 'static ecosystem tag for a candidate name (the
/// candidates all come from 'static tables).
fn static_eco(eco: &str) -> Option<&'static str> {
    EXTRACTED_ECOSYSTEMS
        .iter()
        .chain(SNAP_ECOSYSTEMS)
        .copied()
        .find(|c| *c == eco)
}

/// Unmapped pin → explicit unauditable warning (no silent skips).
fn unmapped_finding(t: &AuditTarget) -> Finding {
    finding(
        &t.package,
        Severity::Warn,
        format!(
            "cannot audit {} pin '{}': {}",
            t.kind, t.package, t.provenance
        ),
        "record an explicit upstream version for this pin (a declared version or a \
         versioned source URL) so it can be matched against OSV"
            .to_string(),
    )
}

/// Query with no data (offline, no cache) → warning with the update hint.
fn unaudited_finding(t: &AuditTarget, cfg: &AuditConfig) -> Finding {
    let identity = match &t.version {
        Some(v) => format!("{} {v}", t.name),
        None => t.name.clone(),
    };
    finding(
        &t.package,
        Severity::Warn,
        format!(
            "unaudited: no OSV data for {identity} — the vulnerability database is \
             unreachable (offline?) and the local cache has no entry"
        ),
        format!(
            "run `shuttle audit --update` when online (cache: {})",
            cfg.cache_dir.display()
        ),
    )
}

/// Dependency closures are pinned by content hash only (ADR-0017): the
/// lockfile does not enumerate their transitive packages, so each
/// deps-bearing package carries one explicit under-report warning.
fn closure_findings(lock: &LockFile) -> Vec<Finding> {
    let mut out = Vec::new();
    for name in sorted_keys(&lock.packages) {
        let Some(deps) = &lock.packages[name.as_str()].deps else {
            continue;
        };
        out.push(finding(
            name,
            Severity::Warn,
            format!(
                "dependency closure {:.12}… is pinned by content hash only — the lockfile \
                 does not enumerate its transitive packages, so they are NOT audited by \
                 this pass (deliberate under-report, issue #52)",
                deps.deps_hash
            ),
            "re-fetch the closure (`shuttle deps fetch --latest`) to move the pin, then \
             re-audit; auditing vendored trees per package is future work"
                .to_string(),
        ));
    }
    out
}

// ── Orchestration ──

/// The audit result: findings plus the counters the CLI reports.
pub struct AuditReport {
    pub findings: Vec<Finding>,
    pub targets: usize,
    pub unaudited: usize,
    pub degraded: bool,
}

/// Run the audit: collect targets, resolve queries (cache → network →
/// degrade), and emit findings sorted deterministically by (package,
/// message).
pub fn run_audit(
    lock: &LockFile,
    raw: Option<&BTreeMap<String, serde_json::Value>>,
    cfg: &AuditConfig,
) -> miette::Result<AuditReport> {
    let targets = collect_targets(lock, raw);
    let mut findings = closure_findings(lock);

    // One canonical query per (identity, ecosystem); targets sharing an
    // identity share one fetch (and one cache entry).
    let mut unique: Vec<serde_json::Value> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    // Per target: the query indices of its candidate-ecosystem fan-out,
    // in candidate order.
    let mut target_slots: Vec<Vec<usize>> = Vec::with_capacity(targets.len());
    for t in &targets {
        let mut slots = Vec::new();
        for eco in candidate_ecosystems(t) {
            if let Some(q) = osv_query(t, eco) {
                let key = q.to_string();
                let i = if let Some(&i) = index.get(&key) {
                    i
                } else {
                    unique.push(q);
                    let i = unique.len() - 1;
                    index.insert(key, i);
                    i
                };
                slots.push(i);
            }
        }
        target_slots.push(slots);
    }

    let outcome = fetch_queries(cfg, &unique);

    let mut unaudited = 0usize;
    for (t, slots) in targets.iter().zip(&target_slots) {
        if slots.is_empty() {
            findings.push(unmapped_finding(t));
            continue;
        }
        let ecos = candidate_ecosystems(t);
        let results: Vec<(String, Option<Fetched>)> = ecos
            .iter()
            .zip(slots)
            .map(|(eco, slot)| ((*eco).to_string(), outcome.entries[*slot].clone()))
            .collect();
        let missing = results.iter().any(|(_, f)| f.is_none());
        if missing {
            unaudited += 1;
            findings.push(unaudited_finding(t, cfg));
        }
        findings.extend(target_findings(t, &results));
    }
    findings.sort_by(|a, b| (&a.package, &a.message).cmp(&(&b.package, &b.message)));
    Ok(AuditReport {
        findings,
        targets: targets.len(),
        unaudited,
        degraded: outcome.degraded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{PackageDepsLock, PodPackageLockEntry, SnapLockEntry, SourceLockEntry};

    fn lock_with(
        sources: Vec<(&str, &str)>,
        packages: Vec<(&str, &str, Option<&str>)>,
        snaps: Vec<(&str, u32)>,
    ) -> LockFile {
        let mut lock = LockFile::empty();
        for (url, sha) in sources {
            lock.sources.insert(
                url.to_string(),
                SourceLockEntry {
                    sha256: sha.to_string(),
                },
            );
        }
        for (name, version, deps_hash) in packages {
            lock.packages.insert(
                name.to_string(),
                PodPackageLockEntry {
                    version: version.to_string(),
                    constraint: None,
                    deps: deps_hash.map(|h| PackageDepsLock {
                        deps_hash: h.to_string(),
                        fetched_at: Some("2026-01-01".into()),
                        lock_sha256: None,
                    }),
                    recipe_sha256: None,
                    recipe_digest_scheme: None,
                },
            );
        }
        for (name, revision) in snaps {
            lock.snaps.insert(
                name.to_string(),
                SnapLockEntry {
                    revision,
                    sha3_384: "a".repeat(96),
                },
            );
        }
        lock
    }

    fn parts(url: &str) -> (Option<String>, Option<String>, Option<&'static str>) {
        classify_source_url(url)
    }

    // ── URL classification ──

    #[test]
    fn npm_urls_classify_unscoped_and_scoped() {
        let (n, v, e) = parts("https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("lodash"), Some("4.17.20"), Some("npm"))
        );
        let (n, v, e) = parts("https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("@babel/core"), Some("7.23.0"), Some("npm"))
        );
        // Half-parseable → nothing (never query garbage).
        let (n, v, e) = parts("https://registry.npmjs.org/weird/");
        assert_eq!((n, v, e), (None, None, None));
    }

    #[test]
    fn pypi_urls_classify_normalize_wheel_and_sdist() {
        let (n, v, e) =
            parts("https://files.pythonhosted.org/packages/x/zipp-3.8.0-py3-none-any.whl");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("zipp"), Some("3.8.0"), Some("PyPI"))
        );
        let (n, v, e) =
            parts("https://files.pythonhosted.org/packages/x/requests_toolbelt-1.0.0.tar.gz");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("requests-toolbelt"), Some("1.0.0"), Some("PyPI"))
        );
    }

    #[test]
    fn crates_urls_classify_both_shapes() {
        let (n, v, e) = parts("https://crates.io/api/v1/crates/libc/0.2.100/download");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("libc"), Some("0.2.100"), Some("crates.io"))
        );
        let (n, v, e) = parts("https://static.crates.io/crates/libc/libc-0.2.100.crate");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("libc"), Some("0.2.100"), Some("crates.io"))
        );
    }

    #[test]
    fn golang_urls_classify_module_and_version() {
        let (n, v, e) = parts("https://proxy.golang.org/golang.org/x/net/@v/v0.17.0.zip");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("golang.org/x/net"), Some("v0.17.0"), Some("Go"))
        );
    }

    #[test]
    fn github_urls_classify_tag_and_release_and_passthrough_versionless() {
        let (n, v, e) = parts("https://github.com/torvalds/linux/archive/refs/tags/v6.1.tar.gz");
        assert_eq!(
            (n.as_deref(), v.as_deref(), e),
            (Some("linux"), Some("6.1"), None)
        );
        let (n, v, _) = parts("https://github.com/foo/bar/releases/download/2.3.4/bar-2.3.4.zip");
        assert_eq!((n.as_deref(), v.as_deref()), (Some("bar"), Some("2.3.4")));
        let (n, v, e) = parts("https://github.com/foo/bar/commit/abc.tar.gz");
        assert_eq!((n.as_deref(), v.as_deref(), e), (Some("bar"), None, None));
    }

    #[test]
    fn unknown_urls_are_unmapped() {
        let (n, v, e) = parts("https://example.com/downloads/blob.tar.gz");
        assert_eq!((n, v, e), (None, None, None));
    }

    // ── Target collection ──

    #[test]
    fn collect_targets_covers_all_three_maps() {
        let lock = lock_with(
            vec![(
                "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                "aa",
            )],
            vec![("my-tool", "2.1.0", Some("abc123def456"))],
            vec![("core22", 1847)],
        );
        let targets = collect_targets(&lock, None);
        assert_eq!(targets.len(), 3);
        let src = &targets[0];
        assert_eq!(src.kind, "source");
        assert_eq!(src.confidence, Confidence::Exact);
        assert_eq!(src.ecosystem, Some("npm"));
        assert_eq!(src.version.as_deref(), Some("4.17.20"));
        let pkg = &targets[1];
        assert_eq!(pkg.kind, "package");
        assert_eq!(pkg.confidence, Confidence::Extracted);
        assert_eq!(pkg.version.as_deref(), Some("2.1.0"));
        let snap = &targets[2];
        assert_eq!(snap.kind, "snap");
        assert_eq!(snap.confidence, Confidence::NameOnly);
        assert_eq!(snap.revision, Some(1847));
    }

    #[test]
    fn enrichment_supplies_declared_version_and_label() {
        // A versionless source URL (no archive/release marker, no tag) —
        // the declared version from the eval output fills the gap.
        let lock = lock_with(
            vec![("https://github.com/foo/bar/commit/abc.tar.gz", "aa")],
            vec![],
            vec![],
        );
        let mut raw = BTreeMap::new();
        raw.insert(
            "my-snap".to_string(),
            serde_json::json!({
                "name": "my-snap",
                "version": "9.9.9",
                "source": "https://github.com/foo/bar/commit/abc.tar.gz",
            }),
        );
        let targets = collect_targets(&lock, Some(&raw));
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert_eq!(t.package, "my-snap");
        assert_eq!(t.version.as_deref(), Some("9.9.9"));
        assert_eq!(t.confidence, Confidence::Extracted);
        assert!(t
            .provenance
            .contains("declared version of output 'my-snap'"));
    }

    #[test]
    fn versionless_package_is_unmapped() {
        let lock = lock_with(vec![], vec![("ghost", "", None)], vec![]);
        let targets = collect_targets(&lock, None);
        assert_eq!(targets[0].confidence, Confidence::Unmapped);
    }

    // ── Queries ──

    #[test]
    fn queries_match_confidence_shapes() {
        let exact = AuditTarget {
            package: "p".into(),
            kind: "source",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
            ecosystem: Some("npm"),
            revision: None,
            confidence: Confidence::Exact,
            provenance: String::new(),
        };
        let extracted = AuditTarget {
            confidence: Confidence::Extracted,
            ecosystem: None,
            ..exact.clone()
        };
        let name_only = AuditTarget {
            confidence: Confidence::NameOnly,
            version: None,
            ..extracted.clone()
        };
        let unmapped = AuditTarget {
            confidence: Confidence::Unmapped,
            name: String::new(),
            ..name_only.clone()
        };
        // Exact: one query, the proven ecosystem, version-filtered.
        assert_eq!(
            osv_query(&exact, "npm").unwrap(),
            json!({"package": {"name": "lodash", "ecosystem": "npm", "version": "4.17.20"}})
        );
        // Extracted: fanned out over the candidate ecosystems.
        assert_eq!(
            candidate_ecosystems(&extracted),
            EXTRACTED_ECOSYSTEMS.to_vec()
        );
        assert_eq!(
            osv_query(&extracted, "PyPI").unwrap(),
            json!({"package": {"name": "lodash", "ecosystem": "PyPI", "version": "4.17.20"}})
        );
        // Name-only snaps: name+ecosystem only (the API rejects
        // ecosystem-less queries), Debian/Ubuntu candidates.
        assert_eq!(candidate_ecosystems(&name_only), SNAP_ECOSYSTEMS.to_vec());
        assert_eq!(
            osv_query(&name_only, "Debian").unwrap(),
            json!({"package": {"name": "lodash", "ecosystem": "Debian"}})
        );
        // Unmapped: nothing.
        assert!(candidate_ecosystems(&unmapped).is_empty());
        assert!(osv_query(&unmapped, "npm").is_none());
    }

    // ── Findings ──

    fn vuln_response(id: &str, cve: &str, summary: &str) -> Fetched {
        Fetched {
            result: json!({"vulns": [{"id": id, "aliases": [cve], "summary": summary}]}),
            queried_at: "2026-09-14".into(),
        }
    }

    fn results_of(fetched: &[(&'static str, Option<Fetched>)]) -> Vec<(String, Option<Fetched>)> {
        fetched
            .iter()
            .map(|(eco, f)| ((*eco).to_string(), f.clone()))
            .collect()
    }

    fn extracted_target() -> AuditTarget {
        AuditTarget {
            package: "my-tool".into(),
            kind: "package",
            name: "my-tool".into(),
            version: Some("2.1.0".into()),
            ecosystem: None,
            revision: None,
            confidence: Confidence::Extracted,
            provenance: "resolved version pinned in the lockfile".into(),
        }
    }

    #[test]
    fn confirmed_hit_is_an_error_naming_provenance() {
        let t = extracted_target();
        let results = results_of(&[(
            "PyPI",
            Some(vuln_response("GHSA-x", "CVE-2026-0001", "bad things")),
        )]);
        let findings = target_findings(&t, &results);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].check, CHECK);
        let m = &findings[0].message;
        assert!(
            m.contains("GHSA-x")
                && m.contains("CVE-2026-0001")
                && m.contains("my-tool 2.1.0")
                && m.contains("resolved version pinned in the lockfile")
                && m.contains("OSV data 2026-09-14"),
            "{m}"
        );
    }

    #[test]
    fn extracted_hit_names_the_ecosystem_it_matched_by() {
        let t = extracted_target();
        let results = results_of(&[(
            "PyPI",
            Some(vuln_response("GHSA-x", "CVE-2026-0001", "bad things")),
        )]);
        let findings = target_findings(&t, &results);
        let m = &findings[0].message;
        assert!(
            m.contains("[PyPI (ecosystem matched by name)]"),
            "Extracted hits must not imply the lockfile proved the ecosystem: {m}"
        );
    }

    #[test]
    fn exact_ecosystem_hit_does_not_carry_the_matched_by_name_caveat() {
        let mut t = extracted_target();
        t.ecosystem = Some("PyPI");
        t.confidence = Confidence::Exact;
        t.provenance = "version from the PyPI registry URL".into();
        let results = results_of(&[(
            "PyPI",
            Some(vuln_response("GHSA-x", "CVE-2026-0001", "bad things")),
        )]);
        let findings = target_findings(&t, &results);
        let m = &findings[0].message;
        assert!(
            m.contains("[PyPI];") && !m.contains("matched by name"),
            "{m}"
        );
    }

    #[test]
    fn fanout_dupes_collapse_to_one_confirmed_finding() {
        let t = extracted_target();
        let results = results_of(&[
            (
                "PyPI",
                Some(vuln_response("GHSA-x", "CVE-2026-0001", "bad things")),
            ),
            (
                "Ubuntu",
                Some(vuln_response("GHSA-x", "CVE-2026-0001", "bad things")),
            ),
        ]);
        assert_eq!(target_findings(&t, &results).len(), 1);
    }

    #[test]
    fn name_only_hit_is_a_bounded_summary_that_never_claims_confirmation() {
        let t = AuditTarget {
            package: "core22".into(),
            kind: "snap",
            name: "core22".into(),
            version: None,
            ecosystem: None,
            revision: Some(1847),
            confidence: Confidence::NameOnly,
            provenance: "store revision 1847".into(),
        };
        let many = Fetched {
            result: json!({"vulns": [
                {"id": "GHSA-y1", "aliases": ["CVE-2026-0002"], "summary": "worse things"},
                {"id": "GHSA-y2", "aliases": ["CVE-2026-0003"], "summary": "even worse"},
                {"id": "GHSA-y3", "summary": "third"},
                {"id": "GHSA-y4", "summary": "fourth"},
            ]}),
            queried_at: "2026-09-14".into(),
        };
        let results = results_of(&[("Debian", Some(many.clone())), ("Ubuntu", Some(many))]);
        let findings = target_findings(&t, &results);
        // ONE summary warning, not four findings; the same advisory in
        // both ecosystems counts once.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        let m = &findings[0].message;
        assert!(
            m.contains("4 advisories name-match snap 'core22'")
                && m.contains("Debian 4")
                && !m.contains("Ubuntu")
                && m.contains("1847")
                && m.contains("NONE can be confirmed")
                && m.contains("GHSA-y1")
                && !m.contains("GHSA-y4"),
            "summary must count, dedupe across ecosystems, cap examples: {m}"
        );
    }

    #[test]
    fn duplicate_advisories_dedup_per_target() {
        let t = extracted_target();
        let fetched = Fetched {
            result: json!({"vulns": [
                {"id": "GHSA-x", "summary": "a"},
                {"id": "GHSA-x", "aliases": ["CVE-2026-0003"], "summary": "dup"},
            ]}),
            queried_at: "2026-09-14".into(),
        };
        let results = results_of(&[("PyPI", Some(fetched))]);
        assert_eq!(target_findings(&t, &results).len(), 1);
    }

    #[test]
    fn empty_result_yields_no_findings() {
        let t = extracted_target();
        let fetched = Fetched {
            result: json!({}),
            queried_at: "2026-09-14".into(),
        };
        let results = results_of(&[("PyPI", Some(fetched))]);
        assert!(target_findings(&t, &results).is_empty());
    }

    #[test]
    fn closure_pin_warns_about_the_under_report() {
        let lock = lock_with(
            vec![],
            vec![("my-tool", "2.1.0", Some("abc123def456aa"))],
            vec![],
        );
        let findings = closure_findings(&lock);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("abc123def456")
                && findings[0].message.contains("NOT audited")
                && findings[0].message.contains("#52"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn unmapped_pin_warns_explicitly() {
        let lock = lock_with(
            vec![("https://example.com/blob.tar.gz", "aa")],
            vec![],
            vec![],
        );
        let targets = collect_targets(&lock, None);
        let f = unmapped_finding(&targets[0]);
        assert_eq!(f.severity, Severity::Warn);
        assert!(
            f.message.contains("cannot audit") && f.message.contains("blob.tar.gz"),
            "{}",
            f.message
        );
    }

    // ── Cache ──

    #[test]
    fn cache_roundtrip_is_stable_and_corruption_degrades_to_absent() {
        let dir = tempfile::tempdir().unwrap();
        let query = json!({"package": {"name": "lodash", "version": "4.17.20"}});
        assert!(cache_read(dir.path(), &query).is_none());
        let fetched = vuln_response("GHSA-x", "CVE-2026-0001", "s");
        cache_write(dir.path(), &query, &fetched);
        let hit = cache_read(dir.path(), &query).unwrap();
        assert_eq!(hit.queried_at, "2026-09-14");
        assert_eq!(hit.result["vulns"][0]["id"], "GHSA-x");
        // Same query → same file; different query → different file.
        assert!(cache_path(dir.path(), &query).exists());
        assert!(!cache_path(dir.path(), &json!({"package": {"name": "x"}})).exists());
        // A tampered cache entry is absent, never a crash.
        let corrupt_path = cache_path(dir.path(), &json!({"package": {"name": "evil"}}));
        std::fs::write(&corrupt_path, "{not json").unwrap();
        assert!(cache_read(dir.path(), &json!({"package": {"name": "evil"}})).is_none());
    }

    // ── Offline end-to-end (dead endpoint, no network) ──

    #[test]
    fn offline_audit_degrades_to_unaudited_warnings_and_exits_clean() {
        let lock = lock_with(
            vec![("https://example.com/blob.tar.gz", "aa")],
            vec![("my-tool", "2.1.0", None)],
            vec![("core22", 1847)],
        );
        // Port 1 on loopback refuses instantly — a deterministic "offline".
        let cfg = AuditConfig {
            url: "http://127.0.0.1:1/v1/querybatch".into(),
            cache_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            update: false,
        };
        let report = run_audit(&lock, None, &cfg).unwrap();
        assert!(report.degraded, "dead endpoint must mark degraded");
        // my-tool (version query) and core22 (name-only query) are both
        // queryable → unaudited offline; the unmapped source gets its own
        // warning; NO errors — offline never fabricates.
        let errors = report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        assert_eq!(errors, 0);
        let unaudited: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.message.contains("unaudited"))
            .collect();
        assert_eq!(unaudited.len(), 2, "{:?}", report.findings);
        assert!(
            unaudited[0].hint.contains("--update") && unaudited[0].hint.contains("cache"),
            "{}",
            unaudited[0].hint
        );
        assert_eq!(report.unaudited, 2);
    }

    #[test]
    fn iso_date_matches_the_known_epoch_anchor() {
        assert_eq!(iso_date(0), "1970-01-01");
        // 2026-09-14 00:00:00 UTC = day 20710 since the epoch.
        assert_eq!(iso_date(1_789_344_000), "2026-09-14");
    }
}
