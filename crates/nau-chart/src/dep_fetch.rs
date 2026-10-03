//! Dependency-closure fetch for interpreted and registry-built packages
//! (ADR-0017, issues #13/#36).
//!
//! Packages declare a `deps` closure — an ecosystem resolver plus its
//! lockfile. This module implements the **fetch phase**: a pure downloader
//! that runs OUTSIDE the build sandbox with network, resolves the
//! dependency closure from the lockfile, and materializes it into a
//! deterministic tree. The tree is digested NAR-style (sorted paths +
//! contents) into a `deps_hash`, recorded in the pod's `nau.lock`, and
//! stored as ONE content-addressed pod-store blob. The sandbox build later
//! verifies that hash and mounts the entry read-only
//! (`$NAU_DEPS_DIR`).
//!
//! Safety property (council-reviewed): **the fetch never executes
//! lifecycle/install scripts on the host.** npm closures come from tarball
//! GETs driven by the resolved lock (never `npm install`); pip closures
//! are wheels fetched from a PEP 503 simple index (never `pip install`);
//! cargo closures are `.crate` downloads verified against the Cargo.lock
//! checksums and extracted data-only into a `cargo vendor`-equivalent
//! tree (never `cargo fetch`/`cargo build`); go closures are `.zip`
//! downloads from a GOPROXY, verified against the go.sum `h1:` dirhash,
//! and materialized into the Go module cache layout (never `go mod
//! download`). Extraction is data-only — any build scripts ship inert
//! inside the tree and only ever run, if at all, inside the offline
//! sandbox.
//!
//! The canonical archive format ("SHDEP") is a minimal, deterministic
//! serialization: entries sorted by path, normalized modes (0755/0644 by
//! exec bit), no timestamps, no uid/gid. `deps_hash` = SHA-256 of the
//! archive bytes = the pod-store blob name, so content addressing and the
//! lock pin are the same number.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

use crate::lock::{PackageDepsLock, SourceValidators};
use nau_core::blob_store::BlobStore;
use nau_core::snap_types::{DepsLockSpec, SnapMeta, SourceSpec};

/// Default PyPI simple index for pip resolvers (overridable per resolver
/// via `deps.pip.index` — tests point it at a loopback server).
pub const DEFAULT_PIP_INDEX: &str = "https://pypi.org/simple";

/// Default crates.io API base for cargo resolvers: `.crate` downloads are
/// `GET {api}/{name}/{version}/download`, verified against the Cargo.lock
/// checksum. Overridable per resolver via `deps.cargo.index` — tests point
/// it at a loopback server (same seam as `deps.pip.index`).
pub const DEFAULT_CRATES_API: &str = "https://crates.io/api/v1/crates";

/// Default GOPROXY base for go resolvers: module zips/mods/info are
/// `GET {proxy}/{module}/@v/{version}.zip|.mod|.info`. The proxy zip
/// layout IS the Go module cache layout — no repacking on the consumer
/// side. Overridable per resolver via `deps.go.index` — tests point it
/// at a loopback server (same seam as `deps.pip.index`).
pub const DEFAULT_GO_PROXY: &str = "https://proxy.golang.org";

// ── Orchestration ──

/// The OBSERVED sha256 of a fetched source tarball plus the validator
/// state the observation carries. `etag` is the entity tag the server
/// returned for THESE bytes (verbatim; `None` when it sent none or the
/// observation was a 304, which re-certifies the recorded etag instead
/// of producing a new one). `unchanged` is true for a 304 short-circuit:
/// `sha256` is then the RECORDED pin — no bytes were downloaded, no
/// extraction happened, and per the co-write invariant nothing may be
/// written from this observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceObserved {
    pub sha256: String,
    pub etag: Option<String>,
    pub unchanged: bool,
}

/// What one dependency-closure fetch produced (the pin to record plus
/// the source observation the float hold reuses — ADR-0017 Decision 4a).
#[derive(Debug, Clone)]
pub struct DepsFetch {
    /// SHA-256 (hex) of the canonical closure archive = the store blob.
    pub hash: String,
    /// The recipe-shipped lockfile's sha256 when the lock resolved from
    /// the recipe directory; `None` for source-tree locks.
    pub lock_sha256: Option<String>,
    /// The observed source tarball when this call downloaded (or 304-
    /// certified) one; `None` when every lock was recipe-local.
    pub source: Option<SourceObserved>,
}

/// The outcome of [`fetch_deps_closure`]: either the closure was
/// re-resolved and stored, or the conditional probe returned 304 — the
/// source tree is byte-identical to the recorded pin, so the lock-driven
/// re-resolve is skipped and the recorded pin stands (bounded by the
/// validators' TTL: expired stamps never reach this path).
#[derive(Debug, Clone)]
pub enum DepsFetchOutcome {
    Resolved(DepsFetch),
    Unchanged(SourceObserved),
}

/// Ensure the package's dependency closure is fetched and cached in the
/// pod store, returning the pin to record in `nau.lock` plus the
/// OBSERVED sha256 of the source tarball when this call downloaded (or
/// 304-certified) one (`None` when a cached pin was honored or every
/// lock was recipe-local — ADR-0017 Decision 4a: the float hold compares
/// this observation against the lockfile's restamped source pin instead
/// of rebuilding).
///
/// Locked packages (`floating == false`) with a cached store entry never
/// re-fetch — bit-reproducible. A locked package whose store entry went
/// missing (pod GC) re-fetches and requires the closure to reproduce the
/// pinned hash: a moved upstream is a pin violation, not a silent update.
/// Floating packages (`floating == true`, explicit opt-in) re-resolve on
/// every call, record the new hash and a fresh `fetched_at` date tag, and
/// keep the last-known pin intact until the caller commits the new one —
/// rollback stays hash-pinned either way (ADR-0017 Decision 5).
///
/// `validators` (the lock's recorded etag + stamp for the source URL,
/// only ever passed for floating packages) turn the source observation
/// into a conditional GET: a 304 short-circuits the whole re-resolve and
/// returns the recorded pin untouched.
pub fn ensure_pod_deps(
    store: &BlobStore,
    meta: &SnapMeta,
    prev: Option<&PackageDepsLock>,
    floating: bool,
    recipe_dir: Option<&Path>,
    validators: Option<SourceValidators>,
) -> miette::Result<(PackageDepsLock, Option<SourceObserved>)> {
    let Some(deps) = &meta.deps else {
        miette::bail!(
            "internal: ensure_pod_deps called for '{}' which declares no deps",
            meta.name
        );
    };
    let pinned = prev.map(|p| p.deps_hash.as_str());

    // Locked + cached: fetch nothing — the pin is verified where the
    // closure is consumed: on the held sync (pod.rs verify_held_deps_blob,
    // issue #125) and at build time (materialize_deps_entry).
    if !floating {
        if let Some(hash) = pinned {
            if store.blob_path(hash).exists() {
                return Ok((prev.expect("pinned implies prev").clone(), None));
            }
        }
    }

    // A 304 short-circuit needs a pin to stand: without a recorded
    // closure pin there is nothing to return, so a pinless caller
    // probes with a full GET.
    let validators = if pinned.is_some() { validators } else { None };

    match fetch_deps_closure(store, meta, deps, recipe_dir, validators.as_ref())? {
        DepsFetchOutcome::Unchanged(observed) => {
            // The 304 IS the observation: the source tree — and with it
            // the lock-driven closure — is byte-identical to the pin's.
            // The recorded pin stands wholesale (fetched_at untouched,
            // nothing written anywhere).
            Ok((
                prev.expect("guarded above: validators imply pinned")
                    .clone(),
                Some(observed),
            ))
        }
        DepsFetchOutcome::Resolved(fetched) => {
            let observed_source = fetched.source;
            Ok((
                match pinned {
                    // The re-fetch reproduced the pin (locked entry rebuilt after GC,
                    // or a float whose upstream closure did not move): keep the pin —
                    // and its original fetched_at — untouched.
                    Some(old) if old == fetched.hash => prev.expect("pinned implies prev").clone(),
                    Some(old) => {
                        if !floating {
                            miette::bail!(
                                "dependency closure for '{}' changed upstream ({:.12} → {:.12}) \
                                 but the package is locked and its cached store entry was missing — \
                                 refusing to move the pin; run `nau deps fetch --latest` to move it deliberately",
                                meta.name,
                                old,
                                fetched.hash
                            );
                        }
                        nau_infra::output::warn(format!(
                            "floating package '{}': dependency closure changed ({:.12} → {:.12})",
                            meta.name, old, fetched.hash
                        ));
                        PackageDepsLock {
                            deps_hash: fetched.hash,
                            fetched_at: Some(today()),
                            lock_sha256: fetched.lock_sha256,
                        }
                    }
                    None => {
                        // TOFU (ADR-0017 Decision 3): print the hash; the lockfile IS
                        // the pin record.
                        nau_infra::output::ok(format!(
                            "pinned dependency closure for '{}': {:.12}… (recorded in nau.lock)",
                            meta.name, fetched.hash
                        ));
                        PackageDepsLock {
                            deps_hash: fetched.hash,
                            fetched_at: Some(today()),
                            lock_sha256: fetched.lock_sha256,
                        }
                    }
                },
                observed_source,
            ))
        }
    }
}

/// Fetch + materialize the closure and store it as one content-addressed
/// blob. Returns the blob's sha256 (the `deps_hash`), the sha256 of
/// the lockfile bytes when the lock resolved from the package recipe
/// directory (`recipe/` lock path — the audit field beside the pin;
/// `None` for source-tree locks), and the OBSERVED sha256 of the source
/// tarball when this call downloaded one (ADR-0017 Decision 4a — the
/// float-hold's drift observation, reused so the sync never downloads
/// the source twice). `None` when every lock was recipe-local and no
/// source was read. `validators` (lock-recorded etag + stamp) turn the
/// source fetch conditional: a 304 short-circuits the whole re-resolve.
fn fetch_deps_closure(
    store: &BlobStore,
    meta: &SnapMeta,
    deps: &nau_core::snap_types::PackageDeps,
    recipe_dir: Option<&Path>,
    validators: Option<&SourceValidators>,
) -> miette::Result<DepsFetchOutcome> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    // All-recipe-local closures never read a source tree: every lock
    // resolves against the recipe directory, so there is nothing to
    // download — skip the fetch entirely (and with it the `source`
    // requirement, mirroring the parse-boundary relaxation in
    // `snap`). Any other lock shape still needs the tree.
    let (src_root, observed_source) = if deps.all_locks_recipe_local() {
        (work.path().to_path_buf(), None)
    } else {
        match fetch_source_tree(meta, work.path(), validators)? {
            SourceTree::Unchanged { recorded_sha256 } => {
                return Ok(DepsFetchOutcome::Unchanged(SourceObserved {
                    sha256: recorded_sha256,
                    etag: None,
                    unchanged: true,
                }));
            }
            SourceTree::Fetched { root, observed } => (root, Some(observed)),
        }
    };
    // Resolve the declared locks once up front: fails fast on a missing
    // recipe lock (before any download), and records the recipe-shipped
    // lockfile's sha for the pin. The per-resolver fetches re-read the
    // same tiny files.
    let lock_sha256 = recipe_lock_sha256(deps, &src_root, recipe_dir)?;
    let tree = fetch_tree_dir(work.path())?;
    fetch_all_resolvers(deps, &src_root, recipe_dir, &tree, work.path())?;
    let bytes = pack_canonical(&tree)?;
    let hash = store.write_blob(&bytes)?;
    Ok(DepsFetchOutcome::Resolved(DepsFetch {
        hash,
        lock_sha256,
        source: observed_source,
    }))
}

/// The scratch dir the materialized closure tree is packed from.
fn fetch_tree_dir(work: &Path) -> miette::Result<PathBuf> {
    let tree = work.join("tree");
    std::fs::create_dir_all(&tree).map_err(|e| miette::miette!("creating tree dir: {e}"))?;
    Ok(tree)
}

/// Run every declared ecosystem resolver against the fetched source tree.
fn fetch_all_resolvers(
    deps: &nau_core::snap_types::PackageDeps,
    src_root: &Path,
    recipe_dir: Option<&Path>,
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    if let Some(npm) = &deps.npm {
        fetch_npm_closure(npm, src_root, recipe_dir, tree, work)?;
    }
    if let Some(pip) = &deps.pip {
        fetch_pip_closure(pip, src_root, recipe_dir, tree, work)?;
    }
    if let Some(cargo) = &deps.cargo {
        fetch_cargo_closure(cargo, src_root, recipe_dir, tree, work)?;
    }
    if let Some(go) = &deps.go {
        fetch_go_closure(go, src_root, recipe_dir, tree)?;
    }
    Ok(())
}

/// Verify the store's closure blob against its pin and unpack it into a
/// fresh temp dir for the build sandbox to mount read-only (ADR-0017
/// Decision 3: "the sandbox build verifies the hash before use"). The
/// verify rides the process-lifetime blob memo (sync-speed plan item
/// 6a: write_blob / held-sync verify / this mount hash the same blob in
/// one sync — the memo keeps it at one hash), and the unpack STREAMS
/// from the blob (6c: a 4 GB closure never lands in memory whole).
pub fn materialize_deps_entry(
    store: &BlobStore,
    deps_hash: &str,
) -> miette::Result<tempfile::TempDir> {
    let blob = store.blob_path(deps_hash);
    if !blob.exists() {
        miette::bail!(
            "cached dependency closure {deps_hash:.12}… is missing from the pod store — \
             run `nau deps fetch` to fetch it"
        );
    }
    let actual = nau_core::blob_memo::memoized_sha256_file(&blob)?;
    if actual != deps_hash {
        miette::bail!(
            "dependency closure hash mismatch: expected {deps_hash}, found {actual} — \
             the store entry is corrupted or tampered with; refusing to build against it"
        );
    }
    let file = std::fs::File::open(&blob)
        .map_err(|e| miette::miette!("reading {}: {e}", blob.display()))?;
    let dir = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    unpack_canonical(std::io::BufReader::new(file), dir.path())?;
    Ok(dir)
}

// ── Source tree ──

/// What [`fetch_source_tree`] produced for the declared source.
#[derive(Debug)]
enum SourceTree {
    /// 304: the source is byte-identical to the recorded pin — no
    /// tarball landed, nothing was extracted, nothing may be written.
    Unchanged { recorded_sha256: String },
    /// Fresh bytes: the extracted tree plus the observation.
    Fetched {
        root: PathBuf,
        observed: SourceObserved,
    },
}

/// Download + extract the package's source tarball and return its source
/// root plus the OBSERVED tarball sha256 (ADR-0017 Decision 4a: the
/// float-hold's drift observation rides this fetch so the closure
/// re-resolve never downloads the source twice). Lockfiles resolve from
/// this tree first (plain `lock` values), or from the package recipe
/// directory (`recipe/` values — see [`lock_candidates`]).
///
/// `validators` (the lock's recorded etag + validation stamp, passed
/// only for floating sources) turn the observation into a conditional
/// GET: a strong etag + fresh stamp send `If-None-Match`, and a 304
/// returns the RECORDED sha as the observation without downloading,
/// hashing, or extracting anything — the 304 IS the observation. Every
/// other path still rides the same curl seam with no condition, so the
/// server's etag is captured for free and a later probe can use it.
fn fetch_source_tree(
    meta: &SnapMeta,
    work: &Path,
    validators: Option<&SourceValidators>,
) -> miette::Result<SourceTree> {
    let spec = meta.source.as_ref().ok_or_else(|| {
        miette::miette!(
            "package '{}': deps requires source — the lockfile resolves from the source tree",
            meta.name
        )
    })?;
    fetch_tree_for_spec(&meta.name, spec, meta.floating, work, validators)
}

/// The fetchable core of [`fetch_source_tree`], split so tests can drive
/// it with a bare [`SourceSpec`] (a full [`SnapMeta`] carries ~30
/// build-time fields no fetch path reads).
fn fetch_tree_for_spec(
    name: &str,
    spec: &SourceSpec,
    floating: bool,
    work: &Path,
    validators: Option<&SourceValidators>,
) -> miette::Result<SourceTree> {
    let url = spec.url();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        miette::bail!("package '{name}': deps requires an http(s) source URL, got {url}");
    }
    let filename = url.rsplit('/').next().unwrap_or("source.tar.gz");
    let tarball = work.join(filename);
    let spinner = nau_infra::output::spinner(&format!(
        "fetching dependency closure for {name} (downloading source)..."
    ));
    // Conditional probe (float-304 plan): a weak etag (`W/` prefix) is
    // rejected → treated as absent — never sent as a condition.
    let if_none_match = validators
        .filter(|v| !v.etag.starts_with("W/"))
        .map(|v| v.etag.as_str());
    let fetch = http_get_conditional(url, &tarball, if_none_match)?;
    if let Some(recorded) = probe_unchanged(&fetch, if_none_match, validators, &tarball, url)? {
        nau_infra::output::info(format!("drift probe '{name}': 304 (unchanged, 0 bytes)"));
        nau_infra::output::finish_ok(&spinner, &format!("source of {name} unchanged (304)"));
        return Ok(SourceTree::Unchanged {
            recorded_sha256: recorded,
        });
    }
    if fetch.code != 200 {
        let _ = std::fs::remove_file(&tarball);
        nau_infra::output::finish_err(&spinner, &format!("source of {name} failed"));
        miette::bail!("failed to download {url} (HTTP {})", fetch.code);
    }
    let sha = sha256_file(&tarball)?;
    verify_observed_source(name, spec, floating, url, &sha)?;
    let src_dir = work.join("src");
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| miette::miette!("creating {}: {e}", src_dir.display()))?;
    // Issue #170: extraction is in-process (nau_infra::archive::extract_tarball) —
    // never at the mercy of the caller PATH's `tar` binary.
    nau_infra::archive::extract_tarball(&tarball, &src_dir)
        .map_err(|e| e.wrap_err(format!("failed to extract {filename}")))?;
    nau_infra::output::finish_ok(&spinner, &format!("fetched source of {name}"));
    Ok(SourceTree::Fetched {
        root: find_source_root(&src_dir),
        observed: SourceObserved {
            sha256: sha,
            etag: fetch.etag,
            unchanged: false,
        },
    })
}

/// The 304 arm of the probe: when the server answered `304 Not Modified`
/// to our conditional GET, delete the zero-byte tmp curl left behind
/// (the recorded bytes stand untouched) and return the RECORDED sha as
/// the observation. A 304 to anything but our own recorded-validator
/// condition is a server bug — named refusal.
fn probe_unchanged(
    fetch: &CdnFetch,
    if_none_match: Option<&str>,
    validators: Option<&SourceValidators>,
    tarball: &Path,
    url: &str,
) -> miette::Result<Option<String>> {
    if fetch.code != 304 {
        return Ok(None);
    }
    let _ = std::fs::remove_file(tarball);
    let recorded = match (if_none_match, validators) {
        (Some(condition), Some(v)) if v.etag == condition => v.recorded_sha256.clone(),
        _ => miette::bail!("server answered 304 to an unconditional GET of {url}"),
    };
    Ok(Some(recorded))
}

/// The declared-pin check of an observed source (issue #175): a locked
/// source refuses moved bytes; a FLOATING source re-resolves — its pin
/// is a moving target by design, so the new hash is TOFU-recorded (the
/// caller restamps the lock once the rebuild lands) and only warned
/// about.
fn verify_observed_source(
    name: &str,
    spec: &SourceSpec,
    floating: bool,
    url: &str,
    sha: &str,
) -> miette::Result<()> {
    let Some(expected) = spec.expected_sha256() else {
        return Ok(());
    };
    if sha == expected {
        return Ok(());
    }
    if !floating {
        return Err(miette::miette!(
            "SHA-256 mismatch for {url}:\n  expected: {expected}\n  got:      {sha}"
        ));
    }
    nau_infra::output::warn(format!(
        "floating source of {name} re-resolved: {:.12}… → {:.12}… (restamping the pin)",
        expected, sha
    ));
    Ok(())
}

/// The single top-level directory after extraction, if there is exactly
/// one (mirrors `snap::find_source_root`); otherwise the extraction dir.
fn find_source_root(dir: &Path) -> PathBuf {
    let mut dirs = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for entry in read.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && !entry.file_name().to_string_lossy().starts_with('.')
            {
                dirs.push(entry.path());
            }
        }
    }
    if dirs.len() == 1 {
        dirs.remove(0)
    } else {
        dir.to_path_buf()
    }
}

// ── npm ──

/// One artifact the npm lockfile pins: its `node_modules/...` location,
/// the registry tarball URL, and the SRI integrity hash (when present).
struct NpmArtifact {
    key: String,
    url: String,
    integrity: Option<String>,
}

/// Parse `package-lock.json` (lockfileVersion 2/3, the `packages` map):
/// every `node_modules/...` entry with an http(s) `resolved` URL is one
/// artifact to fetch. The lockfile drives the fetch — no npm on the host.
fn parse_npm_lock(bytes: &[u8]) -> miette::Result<Vec<NpmArtifact>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| miette::miette!("package-lock.json is not valid JSON: {e}"))?;
    let packages = value
        .get("packages")
        .and_then(|p| p.as_object())
        .ok_or_else(|| {
            miette::miette!(
                "package-lock.json has no 'packages' map (lockfileVersion 1 is unsupported — \
                 regenerate the lock with npm 7 or newer)"
            )
        })?;
    let mut out = Vec::new();
    for (key, entry) in packages {
        if key.is_empty() || !key.starts_with("node_modules/") {
            // "" is the root package; non-node_modules keys are workspace
            // members — no separate artifact either way.
            continue;
        }
        let url = entry
            .get("resolved")
            .and_then(|r| r.as_str())
            .ok_or_else(|| {
                miette::miette!(
                    "package-lock.json: entry '{key}' has no 'resolved' URL \
                     (link:/file:/workspace deps are unsupported)"
                )
            })?;
        if !url.starts_with("http://") && !url.starts_with("https://") {
            miette::bail!("package-lock.json: entry '{key}' resolved to non-http URL {url}");
        }
        out.push(NpmArtifact {
            key: key.to_string(),
            url: url.to_string(),
            integrity: entry
                .get("integrity")
                .and_then(|i| i.as_str())
                .map(str::to_string),
        });
    }
    // Deterministic fetch order.
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Glob match with `*` (any run of chars, including `/`) and `?`
/// (exactly one char). Patterns match the FULL lock key. Iterative
/// two-pointer scan with single-star backtracking: after a mismatch, the
/// last seen `*` absorbs one more character and the suffix match retries.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Apply the fetch-side exclusion globs (issue #14): artifacts whose key
/// matches any pattern are dropped BEFORE any download — never fetched,
/// never extracted, and therefore never archived, so the `deps_hash`
/// inherently pins the post-filter closure. One warn per dropped key,
/// then an info summary count, then a warn for any pattern that matched
/// nothing (a typo would otherwise silently fetch what it meant to
/// exclude).
fn apply_npm_exclude(mut artifacts: Vec<NpmArtifact>, exclude: &[String]) -> Vec<NpmArtifact> {
    let total = artifacts.len();
    let mut matched = vec![false; exclude.len()];
    artifacts.retain(|artifact| {
        match exclude
            .iter()
            .position(|pattern| glob_match(pattern, &artifact.key))
        {
            Some(i) => {
                matched[i] = true;
                nau_infra::output::warn(format!(
                    "npm closure: excluding '{}' (matched deps.npm.exclude '{}')",
                    artifact.key, exclude[i]
                ));
                false
            }
            None => true,
        }
    });
    nau_infra::output::info(format!(
        "npm exclude: {} of {total} package(s) dropped by deps.npm.exclude",
        total - artifacts.len()
    ));
    for (pattern, hit) in exclude.iter().zip(&matched) {
        if !hit {
            nau_infra::output::warn(format!(
                "npm closure: exclude pattern '{pattern}' matched nothing (typo?)"
            ));
        }
    }
    artifacts
}

/// Fetch every npm artifact into the materialized tree: entry
/// `node_modules/<path>` unpacks (tarball root stripped) at
/// `tree/node_modules/<path>` — the npm ci layout.
///
/// `spec.exclude` (issue #14) filters the parsed lock BEFORE any
/// download: an excluded key is never downloaded, never extracted, and
/// never enters the canonical archive — the `deps_hash` inherently pins
/// the post-filter closure.
fn fetch_npm_closure(
    spec: &DepsLockSpec,
    src_root: &Path,
    recipe_dir: Option<&Path>,
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    let lock_bytes = read_lock_file(src_root, recipe_dir, &spec.lock)?;
    let mut artifacts = parse_npm_lock(&lock_bytes)?;
    if !spec.exclude.is_empty() {
        artifacts = apply_npm_exclude(artifacts, &spec.exclude);
    }
    nau_infra::output::info(format!(
        "npm closure: {} package(s) from {}",
        artifacts.len(),
        spec.lock
    ));
    let dl = work.join("npm-dl");
    std::fs::create_dir_all(&dl).map_err(|e| miette::miette!("creating {}: {e}", dl.display()))?;
    for (i, artifact) in artifacts.iter().enumerate() {
        let tgz = dl.join(format!("pkg-{i}.tgz"));
        http_get_to_file(&artifact.url, &tgz)?;
        if let Some(integrity) = &artifact.integrity {
            verify_sri(&tgz, integrity)
                .map_err(|e| miette::miette!("npm '{}': {e}", artifact.key))?;
        }
        let dest = tree.join(&artifact.key);
        extract_npm_tarball(&tgz, &dest)
            .map_err(|e| miette::miette!("npm '{}': {e}", artifact.key))?;
    }
    Ok(())
}

/// Extract an npm registry tarball (gzip tar rooted at `package/`) into
/// `dest`, stripping the archive root. Data-only: file contents, modes,
/// and symlinks — nothing executes (ADR-0017 Decision 2).
fn extract_npm_tarball(tgz: &Path, dest: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dest)
        .map_err(|e| miette::miette!("creating {}: {e}", dest.display()))?;
    let gz = flate2::read::GzDecoder::new(
        File::open(tgz).map_err(|e| miette::miette!("opening {}: {e}", tgz.display()))?,
    );
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(true);
    for entry in archive
        .entries()
        .map_err(|e| miette::miette!("reading {}: {e}", tgz.display()))?
    {
        let mut entry = entry.map_err(|e| miette::miette!("tar entry: {e}"))?;
        extract_tar_entry(&mut entry, dest)?;
    }
    Ok(())
}

/// Extract one tar entry at its root-stripped location under `dest`.
fn extract_tar_entry<R: Read>(entry: &mut tar::Entry<'_, R>, dest: &Path) -> miette::Result<()> {
    let path = entry
        .path()
        .map_err(|e| miette::miette!("tar entry path: {e}"))?
        .to_path_buf();
    let rel: PathBuf = path.components().skip(1).collect();
    if rel.as_os_str().is_empty() {
        // The archive root directory itself ("package").
        return Ok(());
    }
    check_rel_path(&rel)?;
    let out = dest.join(&rel);
    let ty = entry.header().entry_type();
    if ty.is_dir() {
        std::fs::create_dir_all(&out)
            .map_err(|e| miette::miette!("creating {}: {e}", out.display()))?;
    } else if ty.is_symlink() {
        extract_tar_symlink(entry, &out, &rel)?;
    } else {
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
        }
        entry
            .unpack(&out)
            .map_err(|e| miette::miette!("unpacking {}: {e}", out.display()))?;
    }
    Ok(())
}

/// Materialize one tar symlink entry.
fn extract_tar_symlink<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    out: &Path,
    rel: &Path,
) -> miette::Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
    }
    let target = entry
        .link_name()
        .map_err(|e| miette::miette!("tar link name: {e}"))?
        .ok_or_else(|| miette::miette!("symlink entry without target"))?;
    let _ = std::fs::remove_file(out);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, out)
        .map_err(|e| miette::miette!("symlinking {}: {e}", rel.display()))?;
    Ok(())
}

/// Reject path-escape components (".." , absolute roots) in an extracted
/// entry's relative path (zip-slip guard).
fn check_rel_path(rel: &Path) -> miette::Result<()> {
    use std::path::Component;
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => miette::bail!("tar entry escapes its root: {rel:?}"),
        }
    }
    Ok(())
}

/// Verify a downloaded artifact against an npm SRI integrity string
/// (`"sha512-<base64>"`, possibly multiple space-separated entries).
/// Hashes we cannot compute (e.g. legacy sha1-only) are an error, never a
/// silent skip — the closure hash pins the tree, the SRI pins each input.
fn verify_sri(path: &Path, integrity: &str) -> miette::Result<()> {
    let bytes =
        std::fs::read(path).map_err(|e| miette::miette!("reading {}: {e}", path.display()))?;
    let mut supported = false;
    let mut matched = false;
    for part in integrity.split_whitespace() {
        let Some((algo, expected_b64)) = part.split_once('-') else {
            miette::bail!("malformed SRI integrity '{part}'");
        };
        let computed: Option<String> = match algo {
            "sha512" => {
                Some(base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes)))
            }
            "sha256" => {
                Some(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes)))
            }
            _ => None,
        };
        let Some(computed) = computed else {
            continue;
        };
        supported = true;
        if constant_eq(computed.as_bytes(), expected_b64.as_bytes()) {
            matched = true;
        }
    }
    if !supported {
        miette::bail!(
            "integrity '{integrity}' names no supported algorithm (sha512/sha256) — \
             refusing an unverifiable artifact"
        );
    }
    if !matched {
        miette::bail!("integrity mismatch: artifact does not match '{integrity}'");
    }
    Ok(())
}

// ── pip ──

/// One pinned requirement from a pip lock.
///
/// Two lock formats resolve to this shape (sniffed by content, see
/// [`parse_pip_pins`]): pip-compile `requirements.lock` lines
/// (`name==version --hash=sha256:…`, resolved against a PEP 503 index)
/// and `uv.lock` entries (wheel URLs carried directly in the lock).
struct PipPin {
    name: String,
    version: String,
    /// sha256 hex hashes from the lock. Empty = TOFU (verify against the
    /// index anchor hash; warn when neither exists).
    hashes: Vec<String>,
    /// Direct wheel URL (uv.lock). `None` = resolve on the index page.
    url: Option<String>,
}

/// Parse a pinned requirements lock (pip-compile output: continuation
/// lines, `--hash=sha256:...`, comments). Only exact `name==version`
/// pins are supported — range specifiers have no place in a lock.
fn parse_pip_requirements(bytes: &[u8]) -> miette::Result<Vec<PipPin>> {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut logical_lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.ends_with('\\') {
            cur.push_str(line.trim_end_matches('\\'));
            cur.push(' ');
            continue;
        }
        cur.push_str(line);
        logical_lines.push(std::mem::take(&mut cur));
    }
    if !cur.trim().is_empty() {
        logical_lines.push(cur);
    }
    let mut out = Vec::new();
    for line in logical_lines {
        if let Some(pin) = parse_requirement_line(&line)? {
            out.push(pin);
        }
    }
    Ok(out)
}

/// Parse a pip lock in either supported format. The format is sniffed by
/// content: a `uv.lock` is TOML with `[[package]]` tables; a
/// `requirements.lock` is the pip-compile line format. Both resolve to
/// the same pin list.
fn parse_pip_pins(bytes: &[u8], target_minor: Option<u8>) -> miette::Result<Vec<PipPin>> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("[[package]]") {
        parse_uv_lock(bytes, target_minor)
    } else {
        parse_pip_requirements(bytes)
    }
}

// ── uv.lock format (uv's cross-platform Python lockfile) ──

#[derive(serde::Deserialize)]
struct UvLock {
    package: Vec<UvPackage>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct UvPackage {
    name: String,
    version: String,
    /// Registry packages carry `{ registry = "https://…" }`; editable,
    /// virtual, directory, and git sources are skipped (they have no
    /// immutable artifact to fetch).
    source: Option<UvSource>,
    wheels: Option<Vec<UvWheel>>,
    /// Regular dependency edges (`dependencies = [{ name = "…" }]`).
    dependencies: Option<Vec<UvDep>>,
    /// Dev-only dependency edges (TOML `dev-dependencies`) — the input
    /// to the dev/prod split (issue #14). Two shapes exist in the wild:
    /// the grouped table (`[package.dev-dependencies]` with one key per
    /// group, uv's current format) and a plain array (older locks).
    dev_dependencies: Option<UvDevDeps>,
}

/// The two `dev-dependencies` shapes, flattened to the same name list
/// (see [`UvDevDeps::names`]).
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum UvDevDeps {
    /// uv's current format: a table keyed by group name, each group an
    /// array of entries (`dev = [{ name = "pytest" }, …]`).
    Groups(BTreeMap<String, Vec<UvDep>>),
    /// Older locks: one flat array of entries.
    Flat(Vec<UvDep>),
}

impl UvDevDeps {
    /// Every dependency name across all groups (order: group key, then
    /// array order — BTreeMap keeps it deterministic).
    fn names(&self) -> impl Iterator<Item = &str> {
        match self {
            UvDevDeps::Groups(groups) => {
                Box::new(groups.values().flatten().map(|d| d.name.as_str()))
                    as Box<dyn Iterator<Item = &str>>
            }
            UvDevDeps::Flat(deps) => Box::new(deps.iter().map(|d| d.name.as_str())),
        }
    }
}

/// One entry of a uv.lock dependency array. Only the name matters for
/// the dev/prod split; version/marker specs are ignored (serde drops
/// unknown fields by default).
#[derive(serde::Deserialize)]
struct UvDep {
    name: String,
}

#[derive(serde::Deserialize)]
struct UvSource {
    registry: Option<String>,
}

#[derive(serde::Deserialize)]
struct UvWheel {
    url: String,
    /// `"sha256:<hex>"`.
    hash: Option<String>,
}

/// Extract pip pins from a uv.lock: every registry-sourced package whose
/// lock carries a wheel this platform can run (see [`wheel_tags_match`]).
/// Packages without a matching wheel are skipped with a warning — sdist-only
/// packages (which would need a build, ADR-0017 Decision 2) and
/// other-platform binary wheels both land here, so the warning names them.
///
/// Dev-only packages (see [`dev_only_names`], issue #14) are skipped
/// before any wheel check, with ONE aggregated warning naming what was
/// dropped — the dev-dependency split keeps devtool-class closures
/// (pytest, ruff, pyarrow) out of the fetch.
fn parse_uv_lock(bytes: &[u8], target_minor: Option<u8>) -> miette::Result<Vec<PipPin>> {
    let text = String::from_utf8_lossy(bytes);
    let lock: UvLock =
        toml::from_str(&text).map_err(|e| miette::miette!("uv.lock is not valid TOML: {e}"))?;
    let dev_only = dev_only_names(&lock.package);
    let mut out = Vec::new();
    let mut dev_skipped: Vec<String> = Vec::new();
    for pkg in &lock.package {
        if dev_only.contains(&normalize_name(&pkg.name)) {
            dev_skipped.push(pkg.name.clone());
            continue;
        }
        if let Some(pin) = pin_for_package(pkg, target_minor) {
            out.push(pin);
        }
    }
    if !dev_skipped.is_empty() {
        nau_infra::output::warn(format!(
            "uv.lock: skipping {} dev-only package(s): {}",
            dev_skipped.len(),
            truncated_name_list(&dev_skipped)
        ));
    }
    Ok(out)
}

/// One non-dev package's pip pin: its best platform wheel (see
/// [`wheel_tags_match`]). Skips with a warning and returns `None` for
/// packages with no wheels (sdist-only), non-registry sources, and no
/// wheel for this platform. `target_minor` (the declared pod python)
/// reorders the pick: an exact `cp<target>` wheel wins over `abi3`,
/// which wins over interpreter-agnostic tags — uv.lock records the
/// locking machine's choice, and first-match otherwise ships a wheel
/// the pod interpreter cannot import.
fn pin_for_package(pkg: &UvPackage, target_minor: Option<u8>) -> Option<PipPin> {
    let Some(wheels) = &pkg.wheels else {
        nau_infra::output::warn(format!(
            "uv.lock: {} {} has no wheels (sdist-only or non-registry source) — skipped",
            pkg.name, pkg.version
        ));
        return None;
    };
    if pkg
        .source
        .as_ref()
        .and_then(|s| s.registry.as_deref())
        .is_none()
    {
        nau_infra::output::warn(format!(
            "uv.lock: {} {} is not from a registry — skipped",
            pkg.name, pkg.version
        ));
        return None;
    }
    let norm = normalize_name(&pkg.name);
    let Some(wheel) = wheels
        .iter()
        .filter(|w| {
            let filename = w.url.rsplit('/').next().unwrap_or("");
            // Wheel filenames keep the distribution's original spelling
            // (pydantic_core-…, typing_extensions-…) — normalize the
            // filename's name segment before the prefix match, which
            // compares PEP 503-normalized names.
            let normed = match filename.split_once('-') {
                Some((name_seg, rest)) => format!("{}-{}", normalize_name(name_seg), rest),
                None => filename.to_string(),
            };
            is_matching_wheel(&normed, &norm, &pkg.version) && wheel_tags_match(filename)
        })
        .min_by_key(|w| wheel_python_rank(w, target_minor))
    else {
        nau_infra::output::warn(format!(
            "uv.lock: {} {} has no wheel for this platform — skipped",
            pkg.name, pkg.version
        ));
        return None;
    };
    Some(PipPin {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        hashes: wheel
            .hash
            .as_deref()
            .and_then(|h| h.strip_prefix("sha256:"))
            .map(|h| vec![h.to_string()])
            .unwrap_or_default(),
        url: Some(wheel.url.clone()),
    })
}

/// Preference rank for a lock-recorded wheel given the declared pod
/// python: exact CPython minor match first, then `abi3`, then
/// interpreter-agnostic, then anything else (lock order).
fn wheel_python_rank(w: &UvWheel, target_minor: Option<u8>) -> u8 {
    let filename = w.url.rsplit('/').next().unwrap_or("");
    let Some(without_ext) = filename.strip_suffix(".whl") else {
        return 3;
    };
    let Some((rest, _platform)) = without_ext.rsplit_once('-') else {
        return 3;
    };
    let Some((rest, abi)) = rest.rsplit_once('-') else {
        return 3;
    };
    let Some((_, python)) = rest.rsplit_once('-') else {
        return 3;
    };
    match (python, abi, target_minor) {
        ("py3", _, _) | ("py2.py3", _, _) => 2,
        (p, "abi3", Some(target)) => {
            if p.strip_prefix("cp3")
                .and_then(|m| m.parse::<u8>().ok())
                .is_some_and(|m| m <= target)
            {
                1
            } else {
                3
            }
        }
        (p, _, Some(target)) => {
            if p == format!("cp3{target}") {
                0
            } else {
                3
            }
        }
        (_, _, None) => 3,
    }
}

/// The PEP 503-normalized names of packages that exist ONLY for
/// development (issue #14): the transitive closure of every package's
/// `dev-dependencies`, minus the closure reachable from the packages
/// nau installs from source. Those prod roots are every NON-registry
/// source (editable/virtual/directory/git — their regular dependency
/// closure IS the wanted closure). Fail-safe: a lock with no
/// source-installed package has no reliable dev/prod split, so an empty
/// prod root set yields an empty set (fetch everything).
fn dev_only_names(pkgs: &[UvPackage]) -> BTreeSet<String> {
    let dev_roots: BTreeSet<String> = pkgs
        .iter()
        .flat_map(|p| p.dev_dependencies.iter().flat_map(UvDevDeps::names))
        .map(normalize_name)
        .collect();
    let prod_roots: BTreeSet<String> = pkgs
        .iter()
        .filter(|p| {
            p.source
                .as_ref()
                .and_then(|s| s.registry.as_deref())
                .is_none()
        })
        .flat_map(|p| p.dependencies.iter().flatten())
        .map(|d| normalize_name(&d.name))
        .collect();
    if prod_roots.is_empty() {
        return BTreeSet::new();
    }
    let dev = reachable_from(pkgs, &dev_roots);
    let prod = reachable_from(pkgs, &prod_roots);
    dev.difference(&prod).cloned().collect()
}

/// Transitive closure of `roots` over every package's regular
/// (`dependencies`) edges — normalized names, roots included.
fn reachable_from(pkgs: &[UvPackage], roots: &BTreeSet<String>) -> BTreeSet<String> {
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in pkgs {
        let from = normalize_name(&pkg.name);
        let deps = pkg
            .dependencies
            .iter()
            .flatten()
            .map(|d| normalize_name(&d.name));
        edges.entry(from).or_default().extend(deps);
    }
    let mut seen = BTreeSet::new();
    let mut queue: Vec<&String> = roots.iter().collect();
    while let Some(name) = queue.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(deps) = edges.get(name) {
            queue.extend(deps.iter());
        }
    }
    seen
}

/// The dev-skip warning's name list: at most 8 names, then ", …".
fn truncated_name_list(names: &[String]) -> String {
    const MAX_NAMES: usize = 8;
    if names.len() <= MAX_NAMES {
        names.join(", ")
    } else {
        format!("{}, …", names[..MAX_NAMES].join(", "))
    }
}

/// Can this host run the wheel? Checks the `{python}-{abi}-{platform}`
/// tag triple of a wheel filename against linux x86_64 and the CPython 3
/// ABI line: universal wheels (`py3-none-any`, `abi3`) and `cp3x` wheels
/// for the 3.9+ line on linux x86_64. Tag-gated foreign-platform wheels
/// (macOS, Windows, aarch64) never match.
fn wheel_tags_match(filename: &str) -> bool {
    let Some(without_ext) = filename.strip_suffix(".whl") else {
        return false;
    };
    // Tag triple: `{name}-{version}-{python}-{abi}-{platform}` — peel
    // platform, then abi, then python from the right (name+version,
    // already matched by is_matching_wheel, is discarded).
    let Some((rest, platform)) = without_ext.rsplit_once('-') else {
        return false;
    };
    let Some((rest, abi)) = rest.rsplit_once('-') else {
        return false;
    };
    let Some((_, python)) = rest.rsplit_once('-') else {
        return false;
    };
    let platform_ok = platform == "any"
        || (platform.contains("linux")
            && !platform.contains("musl")
            && platform.contains("x86_64"));
    // `abi3` wheels run on any CPython 3 newer than the python tag, so a
    // cp36-abi3 wheel is fine on 3.9+; plain cp3x wheels must be 3.9+.
    let python_ok = python == "py3"
        || python == "py2.py3"
        || (python.starts_with("cp3") && python[3..].parse::<u8>().is_ok_and(|n| n >= 9))
        || (abi == "abi3" && python.starts_with("cp3") && python[3..].parse::<u8>().is_ok());
    let abi_ok = abi == "none"
        || abi == "abi3"
        || (abi.starts_with("cp3") && abi[3..].parse::<u8>().is_ok_and(|n| n >= 9));
    platform_ok && python_ok && abi_ok
}

/// Parse one logical requirement line; `None` for non-requirement lines
/// (comments, bare options).
fn parse_requirement_line(line: &str) -> miette::Result<Option<PipPin>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // Strip a trailing comment (whitespace-preceded '#').
    let body = match trimmed.find(" #") {
        Some(pos) => &trimmed[..pos],
        None => trimmed,
    };
    let mut name = None;
    let mut version = None;
    let mut hashes = Vec::new();
    for token in body.split_whitespace() {
        if let Some(hash) = token.strip_prefix("--hash=sha256:") {
            hashes.push(hash.to_string());
        } else if let Some((n, v)) = token.split_once("==") {
            if token.starts_with('-') {
                continue; // an option like --foo==bar
            }
            // Strip environment-marker extras: `requests[socks]==2.31.0`.
            let n = n.split('[').next().unwrap_or(n);
            name = Some(n.to_string());
            version = Some(v.to_string());
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok(Some(PipPin {
            name,
            version,
            hashes,
            url: None,
        })),
        _ => Ok(None),
    }
}

/// Fetch every pinned wheel from the simple index into the tree root.
fn fetch_pip_closure(
    spec: &DepsLockSpec,
    src_root: &Path,
    recipe_dir: Option<&Path>,
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    let index = spec.index.as_deref().unwrap_or(DEFAULT_PIP_INDEX);
    let lock_bytes = read_lock_file(src_root, recipe_dir, &spec.lock)?;
    let target_python = spec.python.as_deref().map(parse_python_minor).transpose()?;
    let pins = parse_pip_pins(&lock_bytes, target_python)?;
    nau_infra::output::info(format!(
        "pip closure: {} package(s) from {} via {index}",
        pins.len(),
        spec.lock
    ));
    let excludes: Vec<String> = spec.exclude.iter().map(|n| normalize_name(n)).collect();
    for pin in &pins {
        if excludes.contains(&normalize_name(&pin.name)) {
            nau_infra::output::info(format!(
                "pip closure: skipping {} (deps.pip exclude)",
                pin.name
            ));
            continue;
        }
        fetch_pip_wheel(pin, index, tree, work, target_python)?;
    }
    Ok(())
}

/// Parse a declared pod-interpreter version ("3.14") into its minor
/// number. The wheel tag check compares CPython minor tags against it.
fn parse_python_minor(v: &str) -> miette::Result<u8> {
    let rest = v
        .strip_prefix("3.")
        .ok_or_else(|| miette::miette!("deps.pip: 'python' must be \"3.<minor>\", got '{v}'"))?;
    rest.parse::<u8>()
        .ok()
        .filter(|_| !rest.is_empty())
        .ok_or_else(|| miette::miette!("deps.pip: 'python' must be \"3.<minor>\", got '{v}'"))
}

/// Validate one fetched wheel against the declared pod interpreter.
/// A plain `cp3x` wheel only runs on CPython x — anything else than the
/// exact minor is a silent runtime breakage (imports of the compiled
/// module fail), so the mismatch fails the fetch closed. `abi3` wheels
/// run on any CPython newer than their python tag; pure-python tags run
/// anywhere.
fn validate_wheel_python(filename: &str, target_minor: u8) -> miette::Result<()> {
    let Some(without_ext) = filename.strip_suffix(".whl") else {
        return Ok(()); // sdists and non-wheel artifacts carry no tags
    };
    let Some((rest, _platform)) = without_ext.rsplit_once('-') else {
        return Ok(());
    };
    let Some((rest, abi)) = rest.rsplit_once('-') else {
        return Ok(());
    };
    let Some((_, python)) = rest.rsplit_once('-') else {
        return Ok(());
    };
    let tag_minor = |tag: &str| tag.strip_prefix("cp3").and_then(|m| m.parse::<u8>().ok());
    let ok = match (python, abi) {
        ("py3", _) | ("py2.py3", _) => true,
        (p, "abi3") => tag_minor(p).is_some_and(|m| m <= target_minor),
        (p, _) => tag_minor(p).is_some_and(|m| m == target_minor),
    };
    if ok {
        return Ok(());
    }
    miette::bail!(
        "pip: wheel {filename} does not serve the declared pod python \
         3.{target_minor} (relock against the pod interpreter, or exclude \
         the package via deps.pip exclude if the app tolerates its absence)"
    )
}

/// Resolve one pin to a wheel and download it, verifying integrity.
/// A pin with a direct URL (uv.lock) is fetched straight from the lock;
/// otherwise the pin resolves on the index's project page. Either way
/// the wheel is verified against the pin's hash (authoritative) or the
/// page's anchor hash (TOFU when the lock carries no hash).
fn fetch_pip_wheel(
    pin: &PipPin,
    index: &str,
    tree: &Path,
    work: &Path,
    target_minor: Option<u8>,
) -> miette::Result<()> {
    match &pin.url {
        Some(url) => fetch_pip_wheel_direct(pin, url, tree, target_minor),
        None => fetch_pip_wheel_index(pin, index, tree, work, target_minor),
    }
}

/// Fetch a uv.lock direct-URL wheel: validate its tags against the
/// declared pod interpreter, download, verify the lock's hash.
fn fetch_pip_wheel_direct(
    pin: &PipPin,
    url: &str,
    tree: &Path,
    target_minor: Option<u8>,
) -> miette::Result<()> {
    let filename = url.rsplit('/').next().unwrap_or("wheel.whl");
    if let Some(minor) = target_minor {
        validate_wheel_python(filename, minor)?;
    }
    let dest = tree.join(filename);
    http_get_to_file(url, &dest)?;
    match pin.hashes.first() {
        Some(hash) => {
            let actual = sha256_file(&dest)?;
            if !constant_eq(actual.as_bytes(), hash.as_bytes()) {
                let _ = std::fs::remove_file(&dest);
                miette::bail!("pip: wheel {filename} hash mismatch: expected {hash}, got {actual}");
            }
            Ok(())
        }
        None => {
            let actual = sha256_file(&dest)?;
            nau_infra::output::warn(format!(
                "pip: wheel {filename} fetched unpinned (hash {actual:.16}… — pin it in the lock)"
            ));
            Ok(())
        }
    }
}

/// Resolve one pin on the index's PEP 503 project page: pick the first
/// anchor matching name+version+tags, validate it against the declared
/// pod interpreter, download, verify against the lock's hash or the
/// anchor hash (TOFU when the lock carries none).
fn fetch_pip_wheel_index(
    pin: &PipPin,
    index: &str,
    tree: &Path,
    work: &Path,
    target_minor: Option<u8>,
) -> miette::Result<()> {
    let page_url = format!(
        "{}/{}/",
        index.trim_end_matches('/'),
        normalize_name(&pin.name)
    );
    let page = http_get_to_string(&page_url, work)?;
    let anchors = parse_simple_index(&page);
    let match_name = normalize_name(&pin.name);
    let found = anchors.iter().find_map(|(href, text)| {
        let candidate = if !text.is_empty() { text } else { href };
        let candidate = candidate.rsplit('/').next().unwrap_or(candidate);
        (is_matching_wheel(candidate, &match_name, &pin.version) && wheel_tags_match(candidate))
            .then(|| (href.clone(), candidate.to_string()))
    });
    let Some((href, filename)) = found else {
        miette::bail!(
            "pip: no wheel for {pin}=={v} at {index} (only wheels are fetched; \
             sdists would need a build — ADR-0017 Decision 2)",
            pin = pin.name,
            v = pin.version
        );
    };
    if let Some(minor) = target_minor {
        validate_wheel_python(&filename, minor)?;
    }
    let url = resolve_url(&page_url, href.split('#').next().unwrap_or(&href));
    let dest = tree.join(&filename);
    http_get_to_file(&url, &dest)?;
    let anchor_hash = href.split_once("#sha256=").map(|(_, h)| h.to_string());
    let expected = pin.hashes.first().or(anchor_hash.as_ref());
    match expected {
        Some(hash) => {
            let actual = sha256_file(&dest)?;
            if !constant_eq(actual.as_bytes(), hash.as_bytes()) {
                let _ = std::fs::remove_file(&dest);
                miette::bail!("pip: wheel {filename} hash mismatch: expected {hash}, got {actual}");
            }
        }
        None => {
            let actual = sha256_file(&dest)?;
            nau_infra::output::warn(format!(
                "pip: wheel {filename} fetched unpinned (hash {actual:.16}… — add --hash=sha256 to the lock to pin)"
            ));
        }
    }
    Ok(())
}

/// PEP 503 name normalization: runs of `-`, `_`, `.` collapse to `-`,
/// lowercased.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !prev_dash {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    out
}

/// Does a wheel filename match `{name}-{version}-*.whl`? (Names already
/// PEP 503-normalized on both sides.)
fn is_matching_wheel(filename: &str, name: &str, version: &str) -> bool {
    let Some(without_ext) = filename.strip_suffix(".whl") else {
        return false;
    };
    let prefix = format!("{name}-{version}-");
    without_ext.starts_with(&prefix)
}

/// Parse the anchors of a PEP 503 simple-index page into (href, text).
fn parse_simple_index(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<a ") {
        rest = &rest[start..];
        let Some(tag_end_rel) = rest.find('>') else {
            break;
        };
        let tag = &rest[..=tag_end_rel];
        let Some(href) = extract_href(tag) else {
            rest = &rest[tag_end_rel + 1..];
            continue;
        };
        let after_tag = &rest[tag_end_rel + 1..];
        let Some(text_end) = after_tag.find("</a>") else {
            break;
        };
        out.push((href, after_tag[..text_end].trim().to_string()));
        rest = &after_tag[text_end + 4..];
    }
    out
}

/// Pull the `href="…"` attribute out of one anchor tag.
fn extract_href(tag: &str) -> Option<String> {
    let pos = tag.find("href=")?;
    let rest = &tag[pos + 5..];
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let end = rest[1..].find(quote)? + 1;
        Some(rest[1..end].to_string())
    } else {
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

/// Resolve a possibly-relative href against its page URL (enough for
/// PEP 503 pages: absolute, root-relative, and ../ segments).
fn resolve_url(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    if let Some(scheme_end) = base.find("://") {
        let host_start = scheme_end + 3;
        if let Some(slash) = base[host_start..].find('/') {
            let root = &base[..host_start + slash];
            if href.starts_with('/') {
                return format!("{root}{href}");
            }
        }
    }
    let mut segments: Vec<&str> = base
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or(base)
        .split('/')
        .collect();
    for seg in href.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(seg),
        }
    }
    segments.join("/")
}

// ── cargo ──

/// One crate pinned by Cargo.lock: its exact name/version and the
/// registry checksum the fetch verifies the downloaded `.crate` against.
#[derive(Debug)]
struct CargoCrate {
    name: String,
    version: String,
    checksum: String,
}

/// The `[[package]]` shape Cargo.lock actually carries for this resolver.
/// `source`/`checksum` are absent for path/workspace members (they ship
/// inside the package source tree and are never fetched).
#[derive(serde::Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

#[derive(serde::Deserialize)]
struct CargoLockFile {
    #[serde(default)]
    package: Vec<CargoLockPackage>,
}

/// Parse Cargo.lock (lockfileVersion 3 and 4 share the registry entry
/// shape): every `registry+https://...crates.io...` package is one
/// artifact to fetch. Path/workspace members are skipped (they ship in
/// the source tree); git dependencies and third-party registries are
/// rejected — there is no crates.io download URL to verify them against.
/// The lockfile drives the fetch — no cargo on the host.
fn parse_cargo_lock(bytes: &[u8]) -> miette::Result<Vec<CargoCrate>> {
    let lock: CargoLockFile = toml::from_str(
        std::str::from_utf8(bytes)
            .map_err(|e| miette::miette!("Cargo.lock is not valid UTF-8: {e}"))?,
    )
    .map_err(|e| miette::miette!("Cargo.lock is not valid TOML: {e}"))?;
    let mut out = Vec::new();
    for pkg in lock.package {
        let Some(source) = &pkg.source else {
            // Path/workspace member — resolved from the package source tree.
            continue;
        };
        if source.starts_with("git+") {
            miette::bail!(
                "Cargo.lock: crate '{} {}' comes from a git dependency ({source}) — \
                 git dependencies cannot be vendored from a registry; \
                 vendor them into the source tree instead",
                pkg.name,
                pkg.version
            );
        }
        if !(source.contains("crates.io")) {
            miette::bail!(
                "Cargo.lock: crate '{} {}' resolves against a non-crates.io registry \
                 ({source}) — only crates.io registry crates can be fetched",
                pkg.name,
                pkg.version
            );
        }
        let Some(checksum) = pkg.checksum else {
            miette::bail!(
                "Cargo.lock: crates.io crate '{} {}' has no checksum — \
                 refusing an unverifiable artifact",
                pkg.name,
                pkg.version
            );
        };
        out.push(CargoCrate {
            name: pkg.name,
            version: pkg.version,
            checksum,
        });
    }
    // Deterministic fetch order.
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    Ok(out)
}

/// Fetch every Cargo.lock crate into a `cargo vendor`-equivalent tree:
/// `tree/vendor/<name>-<version>/` holding the extracted `.crate` source
/// (tarball root stripped) plus a `.cargo-checksum.json` declaring every
/// file's sha256 and the original `.crate` checksum in `package` — the
/// exact contract cargo's directory source enforces. The lockfile's
/// checksum verifies each download BEFORE extraction, so the closure hash
/// pins lockfile-verified content.
fn fetch_cargo_closure(
    spec: &DepsLockSpec,
    src_root: &Path,
    recipe_dir: Option<&Path>,
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    let api = spec.index.as_deref().unwrap_or(DEFAULT_CRATES_API);
    let lock_bytes = read_lock_file(src_root, recipe_dir, &spec.lock)?;
    let crates = parse_cargo_lock(&lock_bytes)?;
    nau_infra::output::info(format!(
        "cargo closure: {} crate(s) from {}",
        crates.len(),
        spec.lock
    ));
    let vendor = tree.join("vendor");
    std::fs::create_dir_all(&vendor)
        .map_err(|e| miette::miette!("creating {}: {e}", vendor.display()))?;
    let dl = work.join("cargo-dl");
    std::fs::create_dir_all(&dl).map_err(|e| miette::miette!("creating {}: {e}", dl.display()))?;
    for c in &crates {
        fetch_cargo_crate(c, api, &dl, &vendor)?;
    }
    Ok(())
}

/// Download one crate, verify its lockfile checksum, extract it into the
/// vendor tree, and write its `.cargo-checksum.json`.
fn fetch_cargo_crate(c: &CargoCrate, api: &str, dl: &Path, vendor: &Path) -> miette::Result<()> {
    let url = format!("{api}/{}/{}/download", c.name, c.version);
    let crate_file = dl.join(format!("{}-{}.crate", c.name, c.version));
    http_get_to_file(&url, &crate_file)?;
    let actual = sha256_file(&crate_file)?;
    if !constant_eq(actual.as_bytes(), c.checksum.as_bytes()) {
        let _ = std::fs::remove_file(&crate_file);
        miette::bail!(
            "cargo: crate {}-{} hash mismatch: expected {}, got {actual}",
            c.name,
            c.version,
            c.checksum
        );
    }
    let dest = vendor.join(format!("{}-{}", c.name, c.version));
    extract_npm_tarball(&crate_file, &dest)
        .map_err(|e| miette::miette!("cargo '{}-{}': {e}", c.name, c.version))?;
    write_cargo_checksums(&dest, &c.checksum)
}

/// Write a vendored crate's `.cargo-checksum.json`: every regular file's
/// sha256 (relative path, sorted) plus the `.crate`'s registry checksum
/// under `package`. Without this file cargo's directory source refuses
/// the crate; with it, cargo re-verifies the tree at build time.
fn write_cargo_checksums(crate_dir: &Path, package_checksum: &str) -> miette::Result<()> {
    let mut files = BTreeMap::new();
    let mut stack = vec![crate_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = std::fs::read_dir(&dir)
            .map_err(|e| miette::miette!("reading {}: {e}", dir.display()))?;
        for entry in read.flatten() {
            let path = entry.path();
            let meta = entry
                .metadata()
                .map_err(|e| miette::miette!("stat {}: {e}", path.display()))?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.file_type().is_symlink() {
                miette::bail!(
                    "vendored crate {}: symlink entries are not supported ({})",
                    crate_dir.display(),
                    path.display()
                );
            } else {
                let rel = path
                    .strip_prefix(crate_dir)
                    .expect("entry under the crate dir")
                    .to_string_lossy()
                    .into_owned();
                // The checksum file is cargo's own metadata — never listed
                // inside itself (mirrors `cargo vendor`, and keeps the
                // function idempotent).
                if rel == ".cargo-checksum.json" {
                    continue;
                }
                let digest = sha256_file(&path)?;
                files.insert(rel, digest);
            }
        }
    }
    let json = serde_json::json!({ "files": files, "package": package_checksum });
    let out = crate_dir.join(".cargo-checksum.json");
    std::fs::write(&out, json.to_string())
        .map_err(|e| miette::miette!("writing {}: {e}", out.display()))
}

// ── go ──

/// One module pinned by go.mod + go.sum: its module path and the version
/// string `go.sum` records (already `vX.Y.Z` with a possible `+incompatible`
/// or `+upgrade` build tag — the literal proxy path segment). The path +
/// version is both the proxy fetch key and the cache directory element.
#[derive(Debug)]
struct GoModule {
    path: String,
    version: String,
}

/// Parse a `go.mod`'s `require` blocks: every `module@version` line —
/// direct and indirect, with or without a `// indirect` comment — is one
/// artifact to fetch. `go 1.17+` pruned module graphs carry the full
/// closure in the main module's go.mod, so this is complete; the standard
/// library is never listed (it ships with the toolchain and is skipped
/// implicitly).
///
/// The go.mod drives the require list (the fetch key set); go.sum carries
/// the hashes that verify each artifact. Local `replace` directives are
/// NOT followed here — they are a source-tree concern (the replaced
/// module ships in the source tree or is fetched at its own proxy path)
/// and are resolved at build time by the Go toolchain against the same
/// offline cache.
fn parse_go_requires(bytes: &[u8]) -> miette::Result<Vec<GoModule>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| miette::miette!("go.mod is not valid UTF-8: {e}"))?;
    let mut out = Vec::new();
    let mut in_require_block = false;
    for raw in text.lines() {
        let line = raw.trim();
        // A `require (` block closes on `)`. Block form and single-line
        // form are both accepted.
        if line.starts_with(')') {
            in_require_block = false;
            continue;
        }
        if !in_require_block {
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            }
            // Single-line: `require module version`.
            if !line.starts_with("require ") {
                continue;
            }
            let spec = line.trim_start_matches("require ").trim();
            let Some((path, version)) = split_require_spec(spec) else {
                miette::bail!("go.mod: malformed require line: '{line}'");
            };
            out.push(GoModule {
                path: path.to_string(),
                version: version.to_string(),
            });
            continue;
        }
        let Some((path, version)) = split_require_spec(line) else {
            miette::bail!("go.mod: malformed require entry: '{line}'");
        };
        out.push(GoModule {
            path: path.to_string(),
            version: version.to_string(),
        });
    }
    if in_require_block {
        miette::bail!("go.mod: unterminated require block");
    }
    // Stable fetch order.
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.version.cmp(&b.version)));
    Ok(out)
}

/// Split a `require` spec line into (path, version). A trailing `//`
/// comment and any `// indirect` marker are stripped. Globs and `v0.0.0`
/// pseudo-versions pass through verbatim (they are exact index keys).
fn split_require_spec(spec: &str) -> Option<(&str, &str)> {
    let spec = spec.split("//").next()?.trim();
    if spec.is_empty() {
        return None;
    }
    let mut parts = spec.split_whitespace();
    let path = parts.next()?;
    let version = parts.next()?;
    // A third non-comment token is malformed; `//` comments already split.
    if parts.next().is_some() {
        return None;
    }
    if path.is_empty() || version.is_empty() {
        return None;
    }
    Some((path, version))
}

/// Fetch every go.mod module from the proxy into the Go module cache
/// layout: `tree/cache/download/<encoded module path>/@v/<version>.info`,
/// `.mod`, `.zip`, and `.ziphash`. The `<version>` is the module cache
/// path's sumdb-safe element — for a module with a normal `vX.Y.Z`
/// version this is the version itself; `+incompatible` is written with
/// its literal `+` in the escaped path (escaping only affects the module
/// path, never the version element).
///
/// `tree/cache/download` is the `$GOPATH/pkg/mod/cache/download` layout,
/// so a build wired with `GOMODCACHE`/`GOPATH` onto the extracted closure
/// (or a `file://` GOPROXY onto the download dir) resolves every module
/// OFFLINE — the proxy zip layout IS the cache layout.
fn fetch_go_closure(
    spec: &DepsLockSpec,
    src_root: &Path,
    recipe_dir: Option<&Path>,
    tree: &Path,
) -> miette::Result<()> {
    let proxy = spec.index.as_deref().unwrap_or(DEFAULT_GO_PROXY);
    let mod_bytes = read_lock_file(src_root, recipe_dir, &spec.lock)?;
    let sum_path = spec.sum.as_deref().unwrap_or("go.sum");
    let sum_bytes = read_lock_file(src_root, recipe_dir, sum_path)?;
    let modules = parse_go_requires(&mod_bytes)?;
    let sums = parse_go_sum(&sum_bytes)?;
    nau_infra::output::info(format!(
        "go closure: {} module(s) from {} (go.sum)",
        modules.len(),
        spec.lock
    ));
    let dl_base = tree.join("cache").join("download");
    std::fs::create_dir_all(&dl_base)
        .map_err(|e| miette::miette!("creating {}: {e}", dl_base.display()))?;
    for m in &modules {
        let (zip_line, mod_line) =
            sums.get(&(m.path.clone(), m.version.clone()))
                .ok_or_else(|| {
                    miette::miette!(
                        "go.sum: module '{} {}' is required by go.mod but has no hash — \
                     run `go mod tidy` upstream to generate a complete go.sum",
                        m.path,
                        m.version
                    )
                })?;
        fetch_go_module(proxy, &dl_base, m, zip_line, mod_line)?;
    }
    Ok(())
}

/// Fetch one module's `.info`, `.mod`, `.zip`, and `.ziphash` into the
/// cache download dir, verifying the `.mod` and `.zip` against their
/// go.sum dirhashes. Writes directly into the closure tree: a fetch
/// failure bails before `pack_canonical` runs, so no partial module ever
/// enters the archival blob.
fn fetch_go_module(
    proxy: &str,
    dl_base: &Path,
    module: &GoModule,
    zip_line: &str,
    mod_line: &str,
) -> miette::Result<()> {
    let escaped = escape_module_path(&module.path);
    let atv = dl_base.join(&escaped).join("@v");
    std::fs::create_dir_all(&atv)
        .map_err(|e| miette::miette!("creating {}: {e}", atv.display()))?;
    go_fetch_verify(&atv, proxy, &escaped, module, zip_line, mod_line)
}

/// One module's four cache entries: fetch each artifact, verify the
/// content-addressed pair (`zip` + `mod`) against go.sum, write the
/// cache's own `.ziphash` marker.
fn go_fetch_verify(
    atv: &Path,
    proxy: &str,
    escaped: &str,
    module: &GoModule,
    zip_line: &str,
    mod_line: &str,
) -> miette::Result<()> {
    let v = &module.version;
    let url = |name: &str| format!("{proxy}/{escaped}/@v/{v}.{name}");
    // .info — the proxy's version metadata. Not covered by dirhash (the
    // hash is over the module's files, not the .info), but the cache
    // entry's presence is what `go` requires to consider a version
    // resolved. Fetched once; content is not content-addressed.
    let info = atv.join(format!("{v}.info"));
    go_fetch_once(&url("info"), &info)?;
    // .mod — covered by the go.sum `<version>/go.mod` hash (the
    // single-file dirhash `h1:`). Verified before the zip so the cache
    // never settles a .mod whose bytes disagree with the pin.
    let mod_path = atv.join(format!("{v}.mod"));
    go_fetch_once(&url("mod"), &mod_path)?;
    verify_go_dirhash(&mod_path, mod_line, &module.path, v)?;
    // .zip — the source archive, verified against the go.sum `<version>`
    // dirhash over the zip's file list.
    let zip_path = atv.join(format!("{v}.zip"));
    go_fetch_once(&url("zip"), &zip_path)?;
    verify_go_dirhash(&zip_path, zip_line, &module.path, v)?;
    // .ziphash — the line `go` itself writes into the cache, the cache's
    // own integrity marker. Mirrors cmd/go's exact bytes so an
    // already-populated cache and our closure are interchangeable.
    let ziphash_path = atv.join(format!("{v}.ziphash"));
    std::fs::write(
        &ziphash_path,
        format!("{} {} {}\n", module.path, v, zip_line),
    )
    .map_err(|e| miette::miette!("writing {}: {e}", ziphash_path.display()))?;
    Ok(())
}

/// GET a proxy artifact at `url` once (skip when the cache entry already
/// exists). Used for the `.info`/`.mod`/`.zip` fetches.
fn go_fetch_once(url: &str, dest: &Path) -> miette::Result<()> {
    if dest.exists() {
        return Ok(());
    }
    http_get_to_file(url, dest)
}

/// Parse a go.sum into `(module path, version) → (zip dirhash, mod
/// dirhash)`. Two record shapes coexist:
///   `<path> <version> <dirhash>` — the module zip hash
///   `<path> <version>/go.mod <dirhash>` — the go.mod file hash
/// `go.sum` is append-only; the LAST occurrence of a key wins (a later
/// `go mod tidy` may add a second hash for the same version).
fn parse_go_sum(bytes: &[u8]) -> miette::Result<BTreeMap<(String, String), (String, String)>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| miette::miette!("go.sum is not valid UTF-8: {e}"))?;
    let mut map: BTreeMap<(String, String), (String, String)> = BTreeMap::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let path = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("");
        let hash = parts.next().unwrap_or("");
        if parts.next().is_some() {
            miette::bail!("go.sum:{lineno}: malformed line: '{line}'");
        }
        if path.is_empty() || version.is_empty() || hash.is_empty() {
            miette::bail!("go.sum:{lineno}: malformed line: '{line}'");
        }
        if !hash.starts_with("h1:") {
            miette::bail!(
                "go.sum:{lineno}: unsupported hash '{hash}' (only h1: dirhashes are verifiable) \
                 — regenerate go.sum with `go mod tidy`"
            );
        }
        let (key, is_mod) = match version.strip_suffix("/go.mod") {
            Some(mod_ver) => ((path.to_string(), mod_ver.to_string()), true),
            None => ((path.to_string(), version.to_string()), false),
        };
        let entry = map.entry(key).or_default();
        if is_mod {
            entry.1 = hash.to_string();
        } else {
            entry.0 = hash.to_string();
        }
    }
    Ok(map)
}

/// The Go module dirhash (`h1:`) over a file: either a ZIP archive's file
/// list (module zip) or a single `go.mod` text file. The zip form hashes
/// each member's SHA-256 (base64, standard alphabet, no padding) plus the
/// member's full archive-path name; the single-file form is
/// `sha256(bytes)  go.mod`. Both are the exact formulas cmd/go's
/// `golang.org/x/mod/sumdb/dirhash` implements.
fn go_dirhash(path: &Path) -> miette::Result<String> {
    if path.extension().is_some_and(|e| e == "zip") {
        go_zip_dirhash(path)
    } else {
        let bytes =
            std::fs::read(path).map_err(|e| miette::miette!("reading {}: {e}", path.display()))?;
        Ok(go_dirhash_bytes(&bytes, "go.mod"))
    }
}

/// The dirhash over a module zip: `<zip sha256>  <full member path>` for
/// every member, sorted by path, then SHA-256 over that list, base64 std.
fn go_zip_dirhash(path: &Path) -> miette::Result<String> {
    let file = File::open(path).map_err(|e| miette::miette!("opening {}: {e}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| miette::miette!("reading zip {}: {e}", path.display()))?;
    let mut hashes: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let mut member = archive
            .by_index(i)
            .map_err(|e| miette::miette!("zip entry {}: {e}", i))?;
        if member.is_dir() {
            continue;
        }
        let name = member.name().to_string();
        let mut digest = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = member
                .read(&mut buf)
                .map_err(|e| miette::miette!("zip member {name}: {e}"))?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
        }
        // The inner member hash is the file's sha256 in HEX (dirhash
        // Hash1 over each member), not base64 — only the final aggregate
        // is base64-encoded under the `h1:` prefix.
        hashes.push((name, hex(&digest.finalize())));
    }
    hashes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, sha) in &hashes {
        h.update(format!("{sha}  {name}\n").as_bytes());
    }
    Ok(format!("h1:{}", go_base64(&h.finalize())))
}

/// The single-file dirhash: `sha256(bytes)  go.mod`.
fn go_dirhash_bytes(bytes: &[u8], name: &str) -> String {
    let inner = hex(&Sha256::digest(bytes));
    let mut h = Sha256::new();
    h.update(format!("{inner}  {name}\n").as_bytes());
    format!("h1:{}", go_base64(&h.finalize()))
}

fn go_base64(digest: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Verify a fetched artifact against its pinned go.sum dirhash. A
/// mismatch is an error (never a silent skip) — the closure hash pins the
/// tree, the dirhash pins each input.
fn verify_go_dirhash(
    path: &Path,
    expected: &str,
    module: &str,
    version: &str,
) -> miette::Result<()> {
    let actual = go_dirhash(path)?;
    if !constant_eq(actual.as_bytes(), expected.as_bytes()) {
        let _ = std::fs::remove_file(path);
        miette::bail!(
            "go: module {}@{} hash mismatch: expected {expected}, got {actual}",
            module,
            version
        );
    }
    Ok(())
}

/// Escaping for a module path as a proxy/cache path element: uppercase
/// letters are emitted as `!<lowercase>` (Go module path escaping, the
/// `module.EscapePath` rule). Lowercase and punctuation pass through.
fn escape_module_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            out.push('!');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

// ── Canonical archive (SHDEP) ──

/// Deterministically serialize a materialized tree: entries sorted by
/// relative path, modes normalized to 0755 (any exec bit) or 0644, no
/// timestamps/uid/gid. The SHA-256 of these bytes is the `deps_hash`.
///
/// ```text
/// F <mode:o> <size> <path>\n<size bytes>
/// L <target_len> <target> <path>\n
/// D <path>\n
/// END\n
/// ```
fn pack_canonical(tree: &Path) -> miette::Result<Vec<u8>> {
    let mut entries = BTreeMap::new();
    collect_tree(tree, tree, &mut entries)?;
    let mut buf = Vec::new();
    for (rel, kind) in &entries {
        check_rel_path(Path::new(rel))?;
        match kind {
            TreeKind::Dir => {
                buf.extend_from_slice(format!("D {rel}\n").as_bytes());
            }
            TreeKind::Link(target) => {
                buf.extend_from_slice(format!("L {} ", target.len()).as_bytes());
                buf.extend_from_slice(target.as_bytes());
                buf.extend_from_slice(format!(" {rel}\n").as_bytes());
            }
            TreeKind::File(mode) => {
                let path = tree.join(rel);
                let bytes =
                    std::fs::read(&path).map_err(|e| miette::miette!("reading {rel}: {e}"))?;
                buf.extend_from_slice(format!("F {mode:o} {} {rel}\n", bytes.len()).as_bytes());
                buf.extend_from_slice(&bytes);
            }
        }
    }
    buf.extend_from_slice(b"END\n");
    Ok(buf)
}

/// One collected tree entry.
enum TreeKind {
    Dir,
    File(u32),
    Link(String),
}

/// Depth-first collection of relative paths → kinds (symlink-follow free:
/// symlinks are recorded as links, never descended into).
fn collect_tree(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, TreeKind>,
) -> miette::Result<()> {
    let read =
        std::fs::read_dir(dir).map_err(|e| miette::miette!("reading {}: {e}", dir.display()))?;
    for entry in read.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .expect("entry under root")
            .to_string_lossy()
            .into_owned();
        if rel.contains('\n') || rel.contains('\r') {
            miette::bail!("path with newline cannot be archived: {rel:?}");
        }
        let meta = entry
            .metadata()
            .map_err(|e| miette::miette!("stat {rel}: {e}"))?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| miette::miette!("readlink {rel}: {e}"))?
                .to_string_lossy()
                .into_owned();
            out.insert(rel, TreeKind::Link(target));
        } else if meta.is_dir() {
            out.insert(rel.clone(), TreeKind::Dir);
            collect_tree(root, &path, out)?;
        } else {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                let m = meta.permissions().mode() & 0o777;
                if m & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                }
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            out.insert(rel, TreeKind::File(mode));
        }
    }
    Ok(())
}

/// Unpack a canonical archive under `dest` (the build-sandbox mount is
/// produced from this — pure data, no scripts). STREAMING (sync-speed
/// plan item 6c): the reader is consumed entry by entry, so a
/// multi-gigabyte closure blob never lands in memory whole — the caller
/// hands in a `BufReader` over the store blob (or a cursor in tests).
fn unpack_canonical<R: std::io::Read>(mut reader: R, dest: &Path) -> miette::Result<()> {
    loop {
        let line = read_archive_line(&mut reader)?;
        let Some(line) = line else {
            miette::bail!("corrupt closure archive: missing END marker");
        };
        if line == "END" {
            return Ok(());
        }
        unpack_streamed_entry(&line, &mut reader, dest)?;
    }
}

/// One header line from the archive reader: bytes up to (not including)
/// the newline, UTF-8 validated. `Ok(None)` at clean EOF.
fn read_archive_line<R: std::io::Read>(reader: &mut R) -> miette::Result<Option<String>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if line.is_empty() {
                    return Ok(None);
                }
                miette::bail!("corrupt closure archive: unterminated entry");
            }
            Ok(_) if byte[0] == b'\n' => {
                let entry = std::str::from_utf8(&line)
                    .map_err(|_| miette::miette!("corrupt closure archive: bad header"))?
                    .to_string();
                return Ok(Some(entry));
            }
            Ok(_) => line.push(byte[0]),
            Err(e) => return Err(miette::miette!("reading closure archive: {e}")),
        }
    }
}

/// Unpack one streamed archive entry: the header line is parsed, then a
/// file entry's payload is copied straight from the reader to disk.
fn unpack_streamed_entry<R: std::io::Read>(
    line: &str,
    reader: &mut R,
    dest: &Path,
) -> miette::Result<()> {
    let mut parts = line.splitn(4, ' ');
    match parts.next() {
        Some("D") => {
            let rel = parts.next().unwrap_or("");
            std::fs::create_dir_all(dest.join(rel))
                .map_err(|e| miette::miette!("mkdir {rel}: {e}"))?;
            Ok(())
        }
        Some("L") => unpack_link_entry(line, dest).map(|_| ()),
        Some("F") => unpack_streamed_file_entry(line, reader, dest),
        _ => miette::bail!("corrupt closure archive: unknown entry '{line}'"),
    }
}

/// Stream one file entry's payload: `F <mode:o> <size> <path>` followed
/// by exactly `<size>` payload bytes copied reader → file (never buffered
/// whole — the deepsec-sized closures stay O(1) in RSS). Short payload is
/// the corrupt-archive error, same as the byte-buffered form.
fn unpack_streamed_file_entry<R: std::io::Read>(
    line: &str,
    reader: &mut R,
    dest: &Path,
) -> miette::Result<()> {
    let mut parts = line.splitn(4, ' ');
    parts.next(); // "F"
    let mode: u32 = parts
        .next()
        .and_then(|s| u32::from_str_radix(s, 8).ok())
        .ok_or_else(|| miette::miette!("corrupt file entry"))?;
    let size: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| miette::miette!("corrupt file entry"))?;
    let rel = parts.next().unwrap_or("");
    let out = dest.join(rel);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| miette::miette!("mkdir {rel}: {e}"))?;
    }
    let mut file = std::fs::File::create(&out).map_err(|e| miette::miette!("write {rel}: {e}"))?;
    let copied = std::io::copy(&mut reader.take(size as u64), &mut file)
        .map_err(|e| miette::miette!("write {rel}: {e}"))?;
    if copied != size as u64 {
        miette::bail!("corrupt file entry: short body ({rel})");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))
            .map_err(|e| miette::miette!("chmod {rel}: {e}"))?;
    }
    Ok(())
}

/// Unpack a symlink entry: `L <target_len> <target> <path>` — target and
/// path both live inside the header line.
fn unpack_link_entry(line: &str, dest: &Path) -> miette::Result<usize> {
    let rest = line
        .strip_prefix("L ")
        .ok_or_else(|| miette::miette!("corrupt link"))?;
    let (tlen_str, rest) = rest
        .split_once(' ')
        .ok_or_else(|| miette::miette!("corrupt link entry"))?;
    let tlen: usize = tlen_str
        .parse()
        .map_err(|_| miette::miette!("corrupt link entry"))?;
    let target = rest
        .get(..tlen)
        .ok_or_else(|| miette::miette!("corrupt link entry"))?;
    let rel = rest
        .get(tlen + 1..)
        .ok_or_else(|| miette::miette!("corrupt link entry"))?;
    let out = dest.join(rel);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("mkdir {}: {e}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&out);
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &out).map_err(|e| miette::miette!("symlink {rel}: {e}"))?;
    Ok(0)
}

// ── Store blob plumbing ──

// ── Store blob plumbing: writes go through nau_core::blob_store::BlobStore ──

// ── Small shared helpers ──

/// The curl binary path through the tools module (issue #101): curl
/// resolves PATH-first with the provisioned fallback, and `ensure` is its
/// mid-build entry (for curl it is the resolve path).
fn curl_tool() -> miette::Result<PathBuf> {
    let resolved = nau_infra::tools::ensure(nau_infra::tools::ToolName::Curl)
        .map_err(|e| miette::miette!("resolve curl: {e}"))?;
    Ok(match resolved {
        nau_infra::tools::ResolvedTool::Provisioned { path, .. }
        | nau_infra::tools::ResolvedTool::Path { path, .. } => path,
    })
}

/// The User-Agent every registry-facing GET sends (crates.io 403s
/// requests without one). The URL is contact info: GitHub throttles by
/// identity and grants exceptions to identified agents (council lever 4
/// rider on the rate-limit retry).
const FETCH_USER_AGENT: &str = concat!(
    "nau/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/rbelem/shuttle)"
);

// ── Rate-limit resilience (council lever 1): retry with backoff at
// the one curl seam ──

/// Default per-sync shared sleep budget, in milliseconds: retries may
/// spend at most this much wall-clock sleep across ALL fetches of one
/// sync (`NAU_NET_RETRY_BUDGET` overrides, in seconds).
const NET_RETRY_BUDGET_DEFAULT_MS: u64 = 150_000;
/// Default cap on any single honored delay, in milliseconds: a
/// `Retry-After` over this fails loud instead of clamping
/// (`NAU_NET_RETRY_CAP_SECS` overrides, in seconds).
const NET_RETRY_CAP_DEFAULT_MS: u64 = 120_000;
/// First exponential-backoff delay; doubles per retry (2s → 4s → 8s,
/// ±50% jitter). No env override — tests inject 0 directly.
const NET_RETRY_BACKOFF_BASE_MS: u64 = 2_000;
/// Attempts per request: one initial call plus two retries.
const NET_RETRY_MAX_ATTEMPTS: u32 = 3;

/// The per-sync shared retry sleep budget (module state): every retry
/// delay through the seam is reserved here first, so N fetches cannot
/// multiply per-fetch budgets into an unbounded sync hang. Reset at
/// sync entry ([`reset_net_retry_budget`]); serial syncs make the
/// single counter sound (already GitHub's "avoid concurrent requests"
/// guidance).
static NET_RETRY_BUDGET_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(NET_RETRY_BUDGET_DEFAULT_MS);

/// Retry knobs for one request through the seam. [`RetryKnobs::from_env`]
/// is the production shape (kill switch + cap override, env-only per the
/// provider-cred precedent); tests build them directly with a zero
/// backoff base and a no-op sleep.
struct RetryKnobs {
    /// Master kill switch: false = today's single-attempt behavior
    /// exactly (`NAU_NET_RETRY=0`).
    enabled: bool,
    /// Largest honored `Retry-After`, in milliseconds.
    cap_ms: u64,
    /// First exponential-backoff delay, in milliseconds.
    backoff_base_ms: u64,
}

impl RetryKnobs {
    /// Production knobs, read at the seam: `NAU_NET_RETRY=0` disables
    /// retrying entirely; `NAU_NET_RETRY_CAP_SECS` overrides the 120s
    /// per-delay cap. An unparsable override fails loud naming the
    /// variable — never a silently ignored misconfiguration.
    fn from_env() -> miette::Result<Self> {
        let enabled = std::env::var("NAU_NET_RETRY")
            .map(|v| v != "0")
            .unwrap_or(true);
        let cap_ms = env_secs_ms("NAU_NET_RETRY_CAP_SECS")?.unwrap_or(NET_RETRY_CAP_DEFAULT_MS);
        Ok(Self {
            enabled,
            cap_ms,
            backoff_base_ms: NET_RETRY_BACKOFF_BASE_MS,
        })
    }
}

/// One `*_SECS` env override, in milliseconds: absent → `None`;
/// unparsable → fail loud naming the variable and value.
fn env_secs_ms(var: &str) -> miette::Result<Option<u64>> {
    match std::env::var(var) {
        Err(_) => Ok(None),
        Ok(raw) => {
            let secs: u64 = raw
                .trim()
                .parse()
                .map_err(|e| miette::miette!("{var}={raw}: not a seconds value: {e}"))?;
            Ok(Some(secs.saturating_mul(1_000)))
        }
    }
}

/// Reset the shared per-sync retry sleep budget — the sync entry's one
/// move (one reconcile = one budget across every fetch through the
/// seam). `NAU_NET_RETRY_BUDGET` overrides the default seconds;
/// unparsable fails loud naming the variable.
pub fn reset_net_retry_budget() -> miette::Result<()> {
    let ms = env_secs_ms("NAU_NET_RETRY_BUDGET")?.unwrap_or(NET_RETRY_BUDGET_DEFAULT_MS);
    NET_RETRY_BUDGET_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// The retry gate: ONLY a 429, plus a 403 that carries `Retry-After`
/// (GitHub surfaces secondary limits as 403). A bare 403 is a hard
/// error — permission failures are never retried. 304/200/5xx and
/// transport deaths keep today's single-shot behavior; `enabled=false`
/// (the `NAU_NET_RETRY=0` kill switch) is today's behavior exactly.
fn should_retry(enabled: bool, code: u16, has_retry_after: bool) -> bool {
    enabled && (code == 429 || (code == 403 && has_retry_after))
}

/// ±50% jitter without a rand dependency: the clock's sub-second
/// nanos are plenty random for spacing retries (never crypto).
fn jittered(ms: u64) -> u64 {
    let half = ms / 2;
    let noise = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    ms - half + (noise % (half + 1))
}

/// The delay before the next attempt: a present `Retry-After` (seconds
/// form) wins verbatim — over the cap it fails loud NAMING the value,
/// per the hang-risk ruling (never clamp-and-retry-early: early retries
/// are the ban-magnet); absent, a jittered exponential backoff.
fn plan_delay_ms(
    knobs: &RetryKnobs,
    url: &str,
    retry_after_secs: Option<u64>,
    attempt: u32,
) -> miette::Result<u64> {
    if let Some(secs) = retry_after_secs {
        let ms = secs.saturating_mul(1_000);
        if ms > knobs.cap_ms {
            miette::bail!(
                "failed to download {url}: Retry-After: {secs} exceeds the {}s retry cap \
                 (refusing to retry early)",
                knobs.cap_ms / 1_000
            );
        }
        return Ok(ms);
    }
    Ok(jittered(knobs.backoff_base_ms << (attempt - 1)))
}

/// Reserve `delay_ms` from the shared per-sync sleep budget
/// (compare-exchange so no two fetches can oversubscribe it), then
/// sleep the reserved amount. An insufficient budget fails loud — the
/// sync ends instead of hammering through the throttle.
fn reserve_sleep_ms(
    url: &str,
    sleep: &dyn Fn(std::time::Duration),
    delay_ms: u64,
) -> miette::Result<()> {
    use std::sync::atomic::Ordering;
    let mut current = NET_RETRY_BUDGET_MS.load(Ordering::Relaxed);
    loop {
        if current < delay_ms {
            miette::bail!(
                "failed to download {url}: shared retry sleep budget exhausted \
                 ({current} ms left, need {delay_ms} ms this sync)"
            );
        }
        match NET_RETRY_BUDGET_MS.compare_exchange_weak(
            current,
            current - delay_ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                sleep(std::time::Duration::from_millis(delay_ms));
                return Ok(());
            }
            Err(actual) => current = actual,
        }
    }
}

/// The result of one GET through the curl seam: the final HTTP status
/// code (after redirects) plus the entity tag the final hop returned,
/// when any. The etag is captured verbatim — never normalized.
#[derive(Debug)]
pub struct CdnFetch {
    pub code: u16,
    pub etag: Option<String>,
}

/// One curl GET writing the body to `dest_tmp`, optionally conditional
/// on `if_none_match` (the raw `If-None-Match` header value, quoted form
/// included). NO `-f`: the caller branches explicitly on the returned
/// code — 304 means curl left a zero-byte `dest_tmp` that the caller
/// must delete, 200 means the caller renames `dest_tmp` over its
/// destination, anything else is an error naming the code. With `-L` the
/// redirect hops concatenate their headers, so the ETag is parsed from
/// the LAST HTTP block (github.com 302s to codeload.github.com, which
/// serves the real ETag). Curl exit nonzero or a `000` code (no HTTP
/// response at all) bails loud.
///
/// Rate-limit contract (council lever 1): a 429 — or a 403 carrying
/// `Retry-After` — is retried here with an honored-header-seconds-first,
/// jittered-exponential-else delay, at most 2 retries (3 attempts) per
/// request; every sleep draws from the shared per-sync budget and any
/// delay over the cap fails loud. Exhaustion fails loud as
/// `failed to download {url} (HTTP <code>, after <n> attempts)` — a 429
/// NEVER becomes a hold or a drift verdict: the sync fails, no pin
/// moves, and the next sync re-probes. 200/304/5xx and transport deaths
/// are single-shot exactly as before; `NAU_NET_RETRY=0` restores
/// today's behavior.
fn http_get_conditional(
    url: &str,
    dest_tmp: &Path,
    if_none_match: Option<&str>,
) -> miette::Result<CdnFetch> {
    let knobs = RetryKnobs::from_env()?;
    http_get_conditional_with(&knobs, &real_sleep, url, dest_tmp, if_none_match)
}

/// Wall-clock sleep — the production sleeper, injected into
/// [`http_get_conditional_with`] so tests run with a no-op.
fn real_sleep(d: std::time::Duration) {
    std::thread::sleep(d);
}

/// [`http_get_conditional`] with the retry policy injected: `knobs`
/// carry the kill switch and the per-delay cap, `sleep` stands in for
/// wall-clock (tests pass a no-op plus a zero backoff base).
fn http_get_conditional_with(
    knobs: &RetryKnobs,
    sleep: &dyn Fn(std::time::Duration),
    url: &str,
    dest_tmp: &Path,
    if_none_match: Option<&str>,
) -> miette::Result<CdnFetch> {
    let curl = curl_tool()?;
    let header_file = dest_tmp.with_file_name(format!(
        ".{}.headers-{}",
        dest_tmp
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("body"),
        std::process::id()
    ));
    let result = retry_curl_get(
        knobs,
        sleep,
        &curl,
        url,
        dest_tmp,
        &header_file,
        if_none_match,
    );
    let _ = std::fs::remove_file(&header_file);
    result
}

/// The retry loop behind [`http_get_conditional_with`]: drive
/// [`run_curl_get`] through the rate-limit policy ([`should_retry`],
/// [`plan_delay_ms`], [`reserve_sleep_ms`]); retries exhaust into a
/// loud terminal failure naming the attempts.
fn retry_curl_get(
    knobs: &RetryKnobs,
    sleep: &dyn Fn(std::time::Duration),
    curl: &Path,
    url: &str,
    dest_tmp: &Path,
    header_file: &Path,
    if_none_match: Option<&str>,
) -> miette::Result<CdnFetch> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let fetch = run_curl_get(curl, url, dest_tmp, header_file, if_none_match)?;
        // The seconds form only: an HTTP-date (or garbage) parses as
        // None and falls back to the exponential path.
        let retry_after = parse_last_header(header_file, "retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok());
        if !should_retry(knobs.enabled, fetch.code, retry_after.is_some()) {
            return Ok(fetch);
        }
        if attempt >= NET_RETRY_MAX_ATTEMPTS {
            miette::bail!(
                "failed to download {url} (HTTP {}, after {attempt} attempts)",
                fetch.code
            );
        }
        let delay_ms = plan_delay_ms(knobs, url, retry_after, attempt)?;
        reserve_sleep_ms(url, sleep, delay_ms)?;
    }
}

/// The curl invocation of [`http_get_conditional`], split so the
/// header-dump cleanup above always runs.
fn run_curl_get(
    curl: &Path,
    url: &str,
    dest_tmp: &Path,
    header_file: &Path,
    if_none_match: Option<&str>,
) -> miette::Result<CdnFetch> {
    let mut cmd = std::process::Command::new(curl);
    cmd.args(["-sSL", "-D"]).arg(header_file);
    if let Some(etag) = if_none_match {
        cmd.arg("-H").arg(format!("If-None-Match: {etag}"));
    }
    let out = cmd
        .arg("-o")
        .arg(dest_tmp)
        .arg("-w")
        .arg("%{http_code}")
        .args(["-A", FETCH_USER_AGENT])
        .arg(url)
        .output()
        .map_err(|e| miette::miette!("curl not found: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr = stderr.trim();
        miette::bail!(
            "failed to download {url}: curl exit {}{}",
            out.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    let code = parse_http_code(&out.stdout, url)?;
    Ok(CdnFetch {
        code,
        etag: parse_last_etag(header_file),
    })
}

/// Parse curl's `-w %{http_code}` output. `000` (no HTTP response —
/// connection refused, TLS failure, …) bails loud like a nonzero exit.
fn parse_http_code(stdout: &[u8], url: &str) -> miette::Result<u16> {
    let text = String::from_utf8_lossy(stdout);
    let code = text
        .trim()
        .parse::<u16>()
        .map_err(|e| miette::miette!("failed to download {url}: unreadable curl status: {e}"))?;
    if code == 0 {
        miette::bail!("failed to download {url}: no HTTP response (curl code 000)");
    }
    Ok(code)
}

/// The ETag header of the LAST HTTP block in a curl `-D` header dump
/// (with `-L` the hops concatenate; the final hop serves the body). Each
/// new status line resets the capture; a missing or unreadable dump
/// yields `None` — the fetch succeeds, only the free etag capture is
/// lost.
fn parse_last_etag(path: &Path) -> Option<String> {
    parse_last_header(path, "etag")
}

/// The LAST value of header `name` (case-insensitive, colon appended)
/// in a curl `-D` header dump: each new status line resets the capture
/// so the final hop wins after `-L` hops. A missing or unreadable dump
/// yields `None`. Core of [`parse_last_etag`] and the retry policy's
/// `Retry-After` read.
fn parse_last_header(path: &Path, name: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let prefix = format!("{name}:");
    let mut value = None;
    for line in text.lines() {
        if line.starts_with("HTTP/") {
            value = None;
        } else if line.len() > prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(&prefix) {
            value = Some(line[prefix.len()..].trim().to_string());
        }
    }
    value
}

/// curl download (the codebase's one network mechanism): an unconditional
/// GET routed through [`http_get_conditional`] so the etag is captured
/// for free on every full fetch. The body lands via a sibling temp file
/// renamed over `dest` only on a 200 — a failure never leaves a partial
/// or empty file at the destination.
fn http_get_to_file(url: &str, dest: &Path) -> miette::Result<()> {
    let tmp = dest.with_file_name(format!(
        ".{}.tmp-{}",
        dest.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download"),
        std::process::id()
    ));
    let result = http_get_conditional(url, &tmp, None).and_then(|fetch| match fetch.code {
        200 => std::fs::rename(&tmp, dest)
            .map_err(|e| miette::miette!("finalizing {}: {e}", dest.display())),
        code => {
            let _ = std::fs::remove_file(&tmp);
            miette::bail!("failed to download {url} (HTTP {code})");
        }
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// GET a small text resource (index pages) via a temp file.
fn http_get_to_string(url: &str, work: &Path) -> miette::Result<String> {
    let tmp = work.join(format!("page-{}", hex_sha256(url.as_bytes())));
    http_get_to_file(url, &tmp)?;
    let text = std::fs::read_to_string(&tmp)
        .map_err(|e| miette::miette!("reading response of {url}: {e}"))?;
    let _ = std::fs::remove_file(&tmp);
    Ok(text)
}

// ── Lockfile resolution (source tree + recipe dir) ──

/// One lockfile read to its bytes, plus where the bytes came from.
struct ResolvedLock {
    bytes: Vec<u8>,
    /// True when the winning candidate was the recipe-directory copy.
    from_recipe: bool,
}

/// The candidate locations of a declared lock path, in priority order,
/// paired with whether each is the recipe-directory copy.
///
/// Contract: a plain path resolves from the fetched source tree first —
/// exactly the legacy behavior — with the recipe directory as a fallback
/// for upstreams that ship no lockfile. A `recipe/`-prefixed path is
/// fail-closed: it resolves against the package recipe directory ONLY
/// (the directory beside the package's `init.lua` or single `<name>.lua`)
/// and never falls back to the source tree — the prefix declares "my
/// recipe ships the authoritative lock", so silently consuming an
/// upstream copy would defeat it.
fn lock_candidates(
    src_root: &Path,
    recipe_dir: Option<&Path>,
    declared: &str,
) -> miette::Result<Vec<(PathBuf, bool)>> {
    if let Some(rest) = declared.strip_prefix("recipe/") {
        check_recipe_rel_path(rest)?;
        let Some(dir) = recipe_dir else {
            miette::bail!(
                "declared lockfile '{declared}' resolves from the package recipe directory, \
                 but no recipe directory is known for this package"
            );
        };
        return Ok(vec![(dir.join(rest), true)]);
    }
    let mut out = vec![(src_root.join(declared), false)];
    if let Some(dir) = recipe_dir {
        out.push((dir.join(declared), true));
    }
    Ok(out)
}

/// The path under `recipe/` must stay inside the recipe directory: no
/// `..` components, no absolute remnant, never empty.
fn check_recipe_rel_path(rest: &str) -> miette::Result<()> {
    use std::path::Component;
    let rel = Path::new(rest);
    let escapes =
        rel.is_absolute() || rest.is_empty() || rel.components().any(|c| c == Component::ParentDir);
    if escapes {
        miette::bail!(
            "'recipe/' lock path must name a file inside the recipe directory, got '{rest}'"
        );
    }
    Ok(())
}

/// Read a declared lockfile (or go.sum sibling) from its candidate
/// locations (see [`lock_candidates`]). Found in NONE of them → the
/// named-diagnostic failure listing every path tried.
fn read_lock_file(
    src_root: &Path,
    recipe_dir: Option<&Path>,
    declared: &str,
) -> miette::Result<Vec<u8>> {
    resolve_lock(src_root, recipe_dir, declared).map(|r| r.bytes)
}

fn resolve_lock(
    src_root: &Path,
    recipe_dir: Option<&Path>,
    declared: &str,
) -> miette::Result<ResolvedLock> {
    let mut tried = Vec::new();
    for (path, from_recipe) in lock_candidates(src_root, recipe_dir, declared)? {
        match std::fs::read(&path) {
            Ok(bytes) => return Ok(ResolvedLock { bytes, from_recipe }),
            Err(_) => tried.push(path.display().to_string()),
        }
    }
    miette::bail!(
        "declared lockfile '{declared}' not found (looked at {})",
        tried.join(" and ")
    )
}

/// The sha256 of the first declared lock that resolves from the recipe
/// directory (resolver order npm → pip → cargo → go; single-resolver
/// packages are the norm) — the audit value recorded beside `deps_hash`
/// in nau.lock. Every declared lock is resolved here first, so a
/// missing recipe lock fails BEFORE any source download; the per-resolver
/// fetches re-read the same files.
fn recipe_lock_sha256(
    deps: &nau_core::snap_types::PackageDeps,
    src_root: &Path,
    recipe_dir: Option<&Path>,
) -> miette::Result<Option<String>> {
    let declared = [
        deps.npm.as_ref().map(|s| s.lock.as_str()),
        deps.pip.as_ref().map(|s| s.lock.as_str()),
        deps.cargo.as_ref().map(|s| s.lock.as_str()),
        deps.go.as_ref().map(|s| s.lock.as_str()),
    ];
    for lock in declared.into_iter().flatten() {
        let resolved = resolve_lock(src_root, recipe_dir, lock)?;
        if resolved.from_recipe {
            return Ok(Some(hex_sha256(&resolved.bytes)));
        }
    }
    Ok(None)
}

/// Streaming SHA-256 of a file, hex-encoded.
pub fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file = File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {}", path.display(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| miette::miette!("reading {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// SHA-256 of in-memory bytes, hex-encoded.
fn hex_sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time-ish equality (no early return on mismatch) for hashes.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// `YYYY-MM-DD` for the current UTC day (no chrono dependency: the
/// well-known days-from-epoch → civil calendar conversion).
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso_date(secs)
}

fn iso_date(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn wheel_python_validation_matches_declared_interpreter() {
        // Plain cp3x wheels: exact minor match required.
        assert!(
            validate_wheel_python("pydantic_core-2.46.5-cp314-cp314-manylinux.whl", 14).is_ok()
        );
        assert!(
            validate_wheel_python("pydantic_core-2.46.5-cp312-cp312-manylinux.whl", 14).is_err()
        );
        // abi3 wheels run on any newer CPython.
        assert!(validate_wheel_python("cffi-2.1.1-cp39-abi3-manylinux.whl", 14).is_ok());
        assert!(validate_wheel_python("cffi-2.1.1-cp314-abi3-manylinux.whl", 12).is_err());
        // Pure-python tags run anywhere.
        assert!(validate_wheel_python("requests-2.34.2-py3-none-any.whl", 14).is_ok());
        assert!(validate_wheel_python("requests-2.34.2-py2.py3-none-any.whl", 14).is_ok());
        // Non-wheel artifacts are not tag-checked.
        assert!(validate_wheel_python("skillspector-2.11.2.tar.gz", 14).is_ok());
    }

    #[test]
    fn parse_python_minor_requires_three_dot_minor() {
        assert_eq!(parse_python_minor("3.14").unwrap(), 14);
        assert!(parse_python_minor("3").is_err());
        assert!(parse_python_minor("3.x").is_err());
        assert!(parse_python_minor("4.0").is_err());
    }

    #[test]
    fn parse_npm_lock_v3() {
        let lock = r#"{
            "name": "app", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "dependencies": { "dep": "^1.0.0" } },
                "node_modules/dep": {
                    "version": "1.2.3",
                    "resolved": "https://registry.npmjs.org/dep/-/dep-1.2.3.tgz",
                    "integrity": "sha512-abc="
                },
                "node_modules/@scope/lib": {
                    "version": "0.1.0",
                    "resolved": "https://registry.npmjs.org/@scope/lib/-/lib-0.1.0.tgz"
                },
                "packages/inner": { "name": "inner", "version": "1.0.0" }
            }
        }"#;
        let artifacts = parse_npm_lock(lock.as_bytes()).unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].key, "node_modules/@scope/lib");
        assert_eq!(artifacts[0].integrity, None);
        assert_eq!(artifacts[1].key, "node_modules/dep");
        assert_eq!(
            artifacts[1].url,
            "https://registry.npmjs.org/dep/-/dep-1.2.3.tgz"
        );
    }

    #[test]
    fn parse_npm_lock_v1_rejected() {
        let lock = r#"{
            "name": "app", "version": "1.0.0", "lockfileVersion": 1,
            "dependencies": { "dep": { "version": "1.0.0", "resolved": "https://x/dep.tgz" } }
        }"#;
        assert!(parse_npm_lock(lock.as_bytes()).is_err());
    }

    #[test]
    fn glob_match_semantics() {
        // Literal.
        assert!(glob_match("node_modules/a", "node_modules/a"));
        assert!(!glob_match("node_modules/a", "node_modules/b"));
        // `*` mid-pattern.
        assert!(glob_match("node_modules/*-core", "node_modules/@x/py-core"));
        // `*` crosses `/`.
        assert!(glob_match(
            "node_modules/@node-llama-cpp/*",
            "node_modules/@node-llama-cpp/llama-cpp-sys/bindings"
        ));
        // `?` is exactly one char (not zero, not two).
        assert!(glob_match("node_modules/a?", "node_modules/ab"));
        assert!(!glob_match("node_modules/a?", "node_modules/a"));
        assert!(!glob_match("node_modules/a?", "node_modules/abc"));
        // No match: no star to backtrack through.
        assert!(!glob_match("node_modules/a*", "other/b"));
        // Pattern longer than text.
        assert!(!glob_match("node_modules/abcdef", "node_modules/abc"));
        // Trailing star: any suffix, empty included.
        assert!(glob_match(
            "node_modules/b*",
            "node_modules/beta/lib/index.js"
        ));
        assert!(glob_match("node_modules/b*", "node_modules/b"));
        assert!(glob_match("*", "anything/else"));
    }

    #[test]
    fn npm_exclude_filters_artifacts_before_fetch() {
        let lock = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "dependencies": { "a": "1.0.0", "beta": "2.0.0" } },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
                },
                "node_modules/beta": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/beta/-/beta-2.0.0.tgz"
                }
            }
        }"#;
        let artifacts = parse_npm_lock(lock.as_bytes()).unwrap();
        assert_eq!(artifacts.len(), 2);
        let kept = apply_npm_exclude(artifacts, &["node_modules/b*".to_string()]);
        assert_eq!(kept.len(), 1, "only 'a' survives the b* glob");
        assert_eq!(kept[0].key, "node_modules/a");
        assert_eq!(kept[0].url, "https://registry.npmjs.org/a/-/a-1.0.0.tgz");
    }

    #[test]
    fn parse_pip_lock_continuations_and_hashes() {
        let req = "\
# pip-compile output
certifi==2024.2.2 \
    --hash=sha256:0569859f95fc761b18b451478c1c207a \
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
click==8.1.7
flask[async]==3.0.0 # pinned with extras
--some-option==ignored
";
        let pins = parse_pip_requirements(req.as_bytes()).unwrap();
        assert_eq!(pins.len(), 3);
        assert_eq!(pins[0].name, "certifi");
        assert_eq!(pins[0].version, "2024.2.2");
        assert_eq!(pins[0].hashes.len(), 2);
        assert_eq!(pins[1].name, "click");
        assert!(pins[1].hashes.is_empty());
        // Extras stripped, trailing comment stripped.
        assert_eq!(pins[2].name, "flask");
        assert_eq!(pins[2].version, "3.0.0");
    }

    #[test]
    fn parse_uv_lock_selects_platform_wheel_and_skips_the_rest() {
        let lock = r#"
version = 1
requires-python = ">=3.12"

[[package]]
name = "whichllm"
version = "0.5.16"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.example/whichllm-0.5.16-py3-none-any.whl", hash = "sha256:aaaa" },
]

[[package]]
name = "psutil"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.example/psutil-7.0.0-cp36-abi3-macosx_11_0_arm64.whl", hash = "sha256:bbbb" },
    { url = "https://files.example/psutil-7.0.0-cp36-abi3-manylinux_2_12_x86_64.manylinux2010_x86_64.whl", hash = "sha256:cccc" },
    { url = "https://files.example/psutil-7.0.0-cp36-abi3-win_amd64.whl", hash = "sha256:dddd" },
]

[[package]]
name = "pydantic-core"
version = "2.41.5"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.example/pydantic_core-2.41.5-cp312-cp312-manylinux_2_17_x86_64.whl", hash = "sha256:ffff" },
    { url = "https://files.example/pydantic_core-2.41.5-cp312-cp312-macosx_11_0_arm64.whl", hash = "sha256:abab" },
]

[[package]]
name = "dbgpu"
version = "2025.12"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/dbgpu-2025.12.tar.gz", hash = "sha256:eeee" }

[[package]]
name = "local-tool"
version = "1.0.0"
source = { editable = "." }
"#;
        let pins = parse_pip_pins(lock.as_bytes(), None).unwrap();
        // dbgpu (sdist-only) and local-tool (editable) are skipped with a
        // warning; the whichllm, psutil, and pydantic-core closures
        // survive.
        assert_eq!(pins.len(), 3);
        assert_eq!(pins[0].name, "whichllm");
        assert!(pins[0]
            .url
            .as_deref()
            .unwrap()
            .ends_with("py3-none-any.whl"));
        assert_eq!(pins[0].hashes, vec!["aaaa"]);
        // The linux manylinux wheel, not the first (macOS) entry.
        assert_eq!(pins[1].name, "psutil");
        assert!(pins[1].url.as_deref().unwrap().contains("manylinux"));
        assert_eq!(pins[1].hashes, vec!["cccc"]);
        // Underscore distributions match their normalized lock name, and
        // the linux wheel wins over the macOS one.
        assert_eq!(pins[2].name, "pydantic-core");
        assert!(pins[2]
            .url
            .as_deref()
            .unwrap()
            .contains("manylinux_2_17_x86_64"));
        assert_eq!(pins[2].hashes, vec!["ffff"]);
    }

    #[test]
    fn parse_uv_lock_prefers_the_declared_python_minor() {
        let lock = r#"
version = 1
requires-python = ">=3.12"

[[package]]
name = "pydantic-core"
version = "2.46.5"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.example/pydantic_core-2.46.5-cp312-cp312-manylinux_2_17_x86_64.whl", hash = "sha256:3123" },
    { url = "https://files.example/pydantic_core-2.46.5-cp314-cp314-manylinux_2_17_x86_64.whl", hash = "sha256:3144" },
]
"#;
        // Without a declared interpreter, first match wins (lock order).
        let pins = parse_pip_pins(lock.as_bytes(), None).unwrap();
        assert!(pins[0].url.as_deref().unwrap().contains("cp312"));
        // With python = "3.14", the cp314 wheel outranks the cp312 one.
        let pins = parse_pip_pins(lock.as_bytes(), Some(14)).unwrap();
        assert!(pins[0].url.as_deref().unwrap().contains("cp314"));
    }

    #[test]
    fn uv_dev_split_skips_dev_only_subgraph() {
        let text = r#"
version = 1
requires-python = ">=3.9"

[[package]]
name = "app"
version = "1.0"
source = { editable = "." }
dependencies = [{ name = "prod" }]
dev-dependencies = [{ name = "devtool" }]

[[package]]
name = "prod"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://f/prod-2.0-py3-none-any.whl", hash = "sha256:pppp" },
]

[[package]]
name = "devtool"
version = "3.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "devtrans" }]
wheels = [
    { url = "https://f/devtool-3.0-py3-none-any.whl", hash = "sha256:dddd" },
]

[[package]]
name = "devtrans"
version = "4.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://f/devtrans-4.0-py3-none-any.whl", hash = "sha256:tttt" },
]
"#;
        // The dev-only set, computed directly: devtool plus its transitive
        // devtrans — prod is reachable from the editable root and stays.
        let lock: UvLock = toml::from_str(text).unwrap();
        let dev_only = dev_only_names(&lock.package);
        assert_eq!(
            dev_only,
            BTreeSet::from(["devtool".to_string(), "devtrans".to_string()])
        );

        // parse_uv_lock skips the dev-only set BEFORE the wheel checks:
        // both dev wheels exist and match this platform, yet only prod pins.
        let pins = parse_uv_lock(text.as_bytes(), None).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "prod");
        assert_eq!(pins[0].hashes, vec!["pppp"]);
    }

    #[test]
    fn uv_dev_split_handles_both_dev_dependencies_shapes() {
        // uv's current format: [package.dev-dependencies] is a TABLE
        // keyed by group name (the shape of the real whichllm lock).
        let grouped = r#"
version = 1

[[package]]
name = "app"
version = "1.0"
source = { editable = "." }
dependencies = [{ name = "prod" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }, { name = "pyarrow" }]
lint = [{ name = "ruff" }]

[[package]]
name = "prod"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://f/prod-2.0-py3-none-any.whl" }]

[[package]]
name = "pytest"
version = "3.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://f/pytest-3.0-py3-none-any.whl" }]
"#;
        let lock: UvLock = toml::from_str(grouped).unwrap();
        let dev_only = dev_only_names(&lock.package);
        assert!(
            dev_only.contains("pytest")
                && dev_only.contains("pyarrow")
                && dev_only.contains("ruff")
        );
        assert!(!dev_only.contains("prod"));
        // The flat array shape (older locks) flattens to the same roots.
        let flat = grouped.replace(
            "[package.dev-dependencies]\ndev = [{ name = \"pytest\" }, { name = \"pyarrow\" }]\nlint = [{ name = \"ruff\" }]",
            "dev-dependencies = [{ name = \"pytest\" }, { name = \"pyarrow\" }, { name = \"ruff\" }]",
        );
        let lock: UvLock = toml::from_str(&flat).unwrap();
        assert_eq!(dev_only_names(&lock.package), dev_only);
    }

    #[test]
    fn uv_dev_split_fail_safe_without_source_installed_root() {
        // No editable/virtual/git package → no reliable prod roots →
        // nothing is dev-only (fetch everything), even though the lock
        // carries dev-dependencies.
        let text = r#"
version = 1

[[package]]
name = "app"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dev-dependencies = [{ name = "devtool" }]
wheels = [
    { url = "https://f/app-1.0-py3-none-any.whl", hash = "sha256:aaaa" },
]

[[package]]
name = "devtool"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://f/devtool-2.0-py3-none-any.whl", hash = "sha256:bbbb" },
]
"#;
        let lock: UvLock = toml::from_str(text).unwrap();
        assert!(dev_only_names(&lock.package).is_empty());
        let pins = parse_uv_lock(text.as_bytes(), None).unwrap();
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn uv_lock_sniffed_over_requirements_format() {
        // A uv.lock routes to the TOML parser even via the shared entry.
        let lock = "[[package]]\nname = \"x\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://f/x-1.0-py3-none-any.whl\" }]\n";
        let pins = parse_pip_pins(lock.as_bytes(), None).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "x");
        // A requirements file never sniffs as uv.lock (no [[package]]).
        let req = "certifi==2024.2.2\n";
        let pins = parse_pip_pins(req.as_bytes(), None).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "certifi");
        assert!(pins[0].url.is_none());
    }

    #[test]
    fn wheel_tags_gate_foreign_platforms() {
        assert!(wheel_tags_match("x-1.0-py3-none-any.whl"));
        assert!(wheel_tags_match("x-1.0-py2.py3-none-any.whl"));
        // abi3 with an old python tag: stable ABI, fine on 3.9+.
        assert!(wheel_tags_match(
            "p-1.0-cp36-abi3-manylinux_2_12_x86_64.manylinux2010_x86_64.whl"
        ));
        assert!(wheel_tags_match(
            "p-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
        ));
        // aarch64 platform: linux but not x86_64.
        assert!(!wheel_tags_match(
            "p-1.0-cp39-cp39-manylinux2014_aarch64.whl"
        ));
        assert!(!wheel_tags_match("p-1.0-cp39-cp39-macosx_11_0_arm64.whl"));
        assert!(!wheel_tags_match("p-1.0-cp39-cp39-win_amd64.whl"));
        // musl is not the glibc runtime.
        assert!(!wheel_tags_match(
            "p-1.0-cp312-cp312-musllinux_1_1_x86_64.whl"
        ));
        // Pre-3.9 ABI line is out of support.
        assert!(!wheel_tags_match(
            "p-1.0-cp38-cp38-manylinux_2_17_x86_64.whl"
        ));
    }

    #[test]
    fn canonical_roundtrip_and_determinism() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        let a = tree.join("node_modules/dep");
        std::fs::create_dir_all(a.join("lib")).unwrap();
        std::fs::write(a.join("lib/index.js"), b"module.exports = 1;\n").unwrap();
        std::fs::write(a.join("bin.sh"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(a.join("bin.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        std::fs::create_dir_all(tree.join("wheels")).unwrap();

        let bytes1 = pack_canonical(&tree).unwrap();
        // Touch a file (changes mtime) — the digest must not move.
        std::fs::write(a.join("lib/index.js"), b"module.exports = 1;\n").unwrap();
        let bytes2 = pack_canonical(&tree).unwrap();
        assert_eq!(bytes1, bytes2, "archive must be mtime-independent");

        let out = dir.path().join("out");
        unpack_canonical(&bytes1[..], &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("node_modules/dep/lib/index.js")).unwrap(),
            b"module.exports = 1;\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(out.join("node_modules/dep/bin.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "exec bit preserved");
            let mode = std::fs::metadata(out.join("node_modules/dep/lib/index.js"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o644, "non-exec normalized to 0644");
        }

        // Content change moves the digest.
        std::fs::write(a.join("lib/index.js"), b"module.exports = 2;\n").unwrap();
        let bytes3 = pack_canonical(&tree).unwrap();
        assert_ne!(bytes1, bytes3);
    }

    #[test]
    fn canonical_archive_symlink_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("tree");
        let pkg = tree.join("node_modules/a");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("real.js"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("real.js", pkg.join("link.js")).unwrap();

        let bytes = pack_canonical(&tree).unwrap();
        let out = dir.path().join("out");
        unpack_canonical(&bytes[..], &out).unwrap();
        #[cfg(unix)]
        {
            let target = std::fs::read_link(out.join("node_modules/a/link.js")).unwrap();
            assert_eq!(target.to_string_lossy(), "real.js");
        }
    }

    #[test]
    fn normalize_name_pep503() {
        assert_eq!(normalize_name("Flask_Environ"), "flask-environ");
        assert_eq!(normalize_name("typing.Extensions"), "typing-extensions");
        assert_eq!(normalize_name("click"), "click");
    }

    #[test]
    fn wheel_matching() {
        assert!(is_matching_wheel(
            "click-8.1.7-py3-none-any.whl",
            "click",
            "8.1.7"
        ));
        assert!(!is_matching_wheel(
            "click-8.1.6-py3-none-any.whl",
            "click",
            "8.1.7"
        ));
        assert!(!is_matching_wheel("click-8.1.7.tar.gz", "click", "8.1.7"));
    }

    #[test]
    fn simple_index_parsing() {
        let html = r#"<html><body><a href="../../wheels/click-8.1.7-py3-none-any.whl#sha256=abc">click-8.1.7-py3-none-any.whl</a>
        <a href="https://files.example/x-1.0-py3-none-any.whl#sha256=def">x-1.0-py3-none-any.whl</a>
        <a href="../other/">other</a></body></html>"#;
        let anchors = parse_simple_index(html);
        assert_eq!(anchors.len(), 3);
        assert_eq!(
            anchors[0].0,
            "../../wheels/click-8.1.7-py3-none-any.whl#sha256=abc"
        );
        assert_eq!(anchors[0].1, "click-8.1.7-py3-none-any.whl");
        assert_eq!(
            anchors[1].0,
            "https://files.example/x-1.0-py3-none-any.whl#sha256=def"
        );
    }

    #[test]
    fn url_resolution() {
        let base = "http://127.0.0.1:8000/simple/click/";
        assert_eq!(
            resolve_url(base, "../../files/click-8.1.7-py3-none-any.whl"),
            "http://127.0.0.1:8000/files/click-8.1.7-py3-none-any.whl"
        );
        assert_eq!(
            resolve_url(base, "https://files.example/x.whl"),
            "https://files.example/x.whl"
        );
        assert_eq!(
            resolve_url(base, "/files/x.whl"),
            "http://127.0.0.1:8000/files/x.whl"
        );
    }

    #[test]
    fn iso_date_known_values() {
        assert_eq!(iso_date(0), "1970-01-01");
        // 2026-09-05 00:00:00 UTC = 1788624000? Verify with a stable value:
        // 2024-01-01 UTC = 1704067200.
        assert_eq!(iso_date(1_704_067_200), "2024-01-01");
        assert_eq!(iso_date(946_684_800), "2000-01-01");
    }

    #[test]
    fn sri_verification() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("artifact");
        std::fs::write(&f, b"hello closure\n").unwrap();
        use base64::Engine;
        let sha256_b64 =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"hello closure\n"));
        let sha512_b64 =
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b"hello closure\n"));
        verify_sri(&f, &format!("sha256-{sha256_b64}")).unwrap();
        verify_sri(&f, &format!("sha512-{sha512_b64}")).unwrap();
        verify_sri(&f, &format!("sha512-{sha512_b64} sha512-wrong=")).unwrap();
        // Wrong digest must fail.
        assert!(verify_sri(&f, "sha512-AAAA").is_err());
        // Unsupported-only algorithm must fail, not silently pass.
        assert!(verify_sri(&f, "sha1-AAAA").is_err());
    }

    const CRATE_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    #[test]
    fn parse_cargo_lock_skips_members_sorts_registry_crates() {
        // v3 shape; the v4 locks keep the same registry entry fields.
        let lock = format!(
            r#"
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "statix"
version = "0.5.8"
dependencies = ["libc"]

[[package]]
name = "libc"
version = "0.2.169"
source = "{CRATE_IO}"
checksum = "a60553f9a9e039a333b4e9b20573b9e9b9c0bb3a11e201ccc48ef4283456d673"

[[package]]
name = "aho-corasick"
version = "0.7.18"
source = "{CRATE_IO}"
checksum = "1e37cfd5e7657ada45f742d6e99ca5788580b5c529dc78faf11ece6dc702656f"

[[package]]
name = "lib-member"
version = "0.1.0"
"#
        );
        let crates = parse_cargo_lock(lock.as_bytes()).unwrap();
        // Workspace/path members (statix, lib-member) are skipped; the
        // registry closure is sorted by name.
        assert_eq!(crates.len(), 2);
        assert_eq!(crates[0].name, "aho-corasick");
        assert_eq!(crates[1].name, "libc");
        assert_eq!(
            crates[1].checksum,
            "a60553f9a9e039a333b4e9b20573b9e9b9c0bb3a11e201ccc48ef4283456d673"
        );
    }

    #[test]
    fn parse_cargo_lock_rejects_git_dependency() {
        let lock = r#"
version = 3

[[package]]
name = "upstream"
version = "0.1.0"
source = "git+https://github.com/example/upstream#abc123"
checksum = "1e37cfd5e7657ada45f742d6e99ca5788580b5c529dc78faf11ece6dc702656f"
"#;
        let err = parse_cargo_lock(lock.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("git dependency"), "{err}");
    }

    #[test]
    fn parse_cargo_lock_rejects_registry_crate_without_checksum() {
        let lock = format!(
            r#"
version = 3

[[package]]
name = "libc"
version = "0.2.169"
source = "{CRATE_IO}"
"#
        );
        let err = parse_cargo_lock(lock.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("no checksum"), "{err}");
    }

    #[test]
    fn parse_cargo_lock_rejects_non_crates_io_registry() {
        let lock = r#"
version = 3

[[package]]
name = "internal"
version = "1.0.0"
source = "registry+https://registry.example.com/index/"
checksum = "1e37cfd5e7657ada45f742d6e99ca5788580b5c529dc78faf11ece6dc702656f"
"#;
        let err = parse_cargo_lock(lock.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("non-crates.io registry"), "{err}");
    }

    /// A `.crate` is a gzipped tarball rooted at `<name>-<version>/` — the
    /// same shape the extraction path strips. Built in-process so the test
    /// stays hermetic.
    fn build_crate_tgz(dir: &Path, name: &str, version: &str, say: &str) -> Vec<u8> {
        let root = dir.join(format!("{name}-{version}"));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            format!("pub fn say() -> &'static str {{ \"{say}\" }}\n"),
        )
        .unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_dir_all(format!("{name}-{version}"), &root)
            .unwrap();
        builder.finish().unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn cargo_crate_extracts_to_vendor_layout_with_checksum_file() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_crate_tgz(dir.path(), "pcrate", "0.1.0", "vendored");
        let crate_file = dir.path().join("pcrate-0.1.0.crate");
        std::fs::write(&crate_file, &bytes).unwrap();

        let tree = dir.path().join("tree");
        let vendor = tree.join("vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        let dest = vendor.join("pcrate-0.1.0");
        extract_npm_tarball(&crate_file, &dest).unwrap();
        let checksum = sha256_file(&crate_file).unwrap();
        write_cargo_checksums(&dest, &checksum).unwrap();

        // The extracted crate source, tarball root stripped.
        assert_eq!(
            std::fs::read_to_string(dest.join("src/lib.rs")).unwrap(),
            "pub fn say() -> &'static str { \"vendored\" }\n"
        );
        // The checksum file lists every file's sha256 plus the .crate
        // checksum in `package` — the contract cargo's directory source
        // enforces.
        let text = std::fs::read_to_string(dest.join(".cargo-checksum.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let files = value["files"].as_object().unwrap();
        assert!(files.contains_key("Cargo.toml"));
        assert!(files.contains_key("src/lib.rs"));
        assert_eq!(files.len(), 2);
        let lib_sha = files["src/lib.rs"].as_str().unwrap();
        let expected: String = Sha256::digest(b"pub fn say() -> &'static str { \"vendored\" }\n")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(lib_sha, expected);
        assert_eq!(value["package"].as_str().unwrap(), checksum);
    }

    #[test]
    fn cargo_checksum_file_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let crate_dir = dir.path().join("c-1.0.0");
        std::fs::create_dir_all(crate_dir.join("src")).unwrap();
        std::fs::write(crate_dir.join("src/a.rs"), "a").unwrap();
        std::fs::write(crate_dir.join("src/b.rs"), "b").unwrap();
        write_cargo_checksums(&crate_dir, "deadbeef").unwrap();
        let first = std::fs::read_to_string(crate_dir.join(".cargo-checksum.json")).unwrap();
        write_cargo_checksums(&crate_dir, "deadbeef").unwrap();
        let second = std::fs::read_to_string(crate_dir.join(".cargo-checksum.json")).unwrap();
        assert_eq!(first, second, "checksum file must be byte-deterministic");
        assert!(first.contains("\"package\":\"deadbeef\""), "{first}");
    }

    // ── go (issue #40) ──

    #[test]
    fn parse_go_requires_reads_block_and_single_line() {
        let gomod = r#"module nau.test/app

go 1.21

require (
    github.com/foo/bar v1.2.3
    golang.org/x/text v0.39.0 // indirect
)

require github.com/only/one v0.1.0
"#;
        let mods = parse_go_requires(gomod.as_bytes()).unwrap();
        // Stably sorted by path.
        assert_eq!(mods.len(), 3);
        assert_eq!(mods[0].path, "github.com/foo/bar");
        assert_eq!(mods[0].version, "v1.2.3");
        assert_eq!(mods[1].path, "github.com/only/one");
        assert_eq!(mods[2].path, "golang.org/x/text");
        assert_eq!(mods[2].version, "v0.39.0");
    }

    #[test]
    fn parse_go_requires_rejects_malformed_entry() {
        let gomod = "module nau.test/app\n\nrequire (\n    github.com/foo/bar\n)\n";
        let err = parse_go_requires(gomod.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("malformed require"), "{err}");
    }

    #[test]
    fn parse_go_requires_rejects_unterminated_block() {
        let gomod = "module nau.test/app\n\nrequire (\n    github.com/foo/bar v1.2.3\n";
        let err = parse_go_requires(gomod.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("unterminated"), "{err}");
    }

    #[test]
    fn parse_go_sum_merges_zip_and_mod_hashes() {
        // go.sum records both the module zip hash and its /go.mod hash.
        let gosum = "nau.test/godep v1.0.0 h1:AAAA=\nnau.test/godep v1.0.0/go.mod h1:BBBB=\n";
        let map = parse_go_sum(gosum.as_bytes()).unwrap();
        let (zip, gm) = map
            .get(&("nau.test/godep".to_string(), "v1.0.0".to_string()))
            .unwrap();
        assert_eq!(zip, "h1:AAAA=");
        assert_eq!(gm, "h1:BBBB=");
    }

    #[test]
    fn parse_go_sum_rejects_non_dirhash() {
        let gosum = "nau.test/godep v1.0.0 sha256:abcd=\n";
        let err = parse_go_sum(gosum.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("only h1:"), "{err}");
    }

    #[test]
    fn go_dirhash_matches_hermetic_known_vector() {
        // A hand-computed dirhash over two files — the exact formula cmd/go
        // applies. This pins the algorithm so a refactor of the hashing
        // cannot silently drift from what go.sum records. The fixture module
        // path stays `shuttle.test` (fake .test domain, pre-rename): the
        // expected vectors below were hand-computed over it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("shuttle.test:godep@v1.0.0");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("godep.go"),
            "package godep\n\nfunc Say() string { return \"go-dep-ran\" }\n",
        )
        .unwrap();
        std::fs::write(
            root.join("go.mod"),
            "module shuttle.test/godep\n\ngo 1.21\n",
        )
        .unwrap();
        let zip_path = dir.path().join("m.zip");
        write_module_zip(&root, &zip_path, "shuttle.test/godep", "v1.0.0");
        let h = go_dirhash(&zip_path).unwrap();
        assert_eq!(
            h, "h1:yMDzDvc+Re9CZLHq89VV1qk0bouZyBD8jp0rMUe+Okc=",
            "zip dirhash"
        );
        // The single-file .mod form over the same go.mod.
        let mod_path = dir.path().join("go.mod");
        std::fs::copy(root.join("go.mod"), &mod_path).unwrap();
        let mh = go_dirhash(&mod_path).unwrap();
        assert_eq!(
            mh, "h1:svH/m3yrhSlYgOqmdsXQf46ptt9MS3zJ/plYAGCJHwo=",
            ".mod dirhash"
        );
    }

    #[test]
    fn escape_module_path_escapes_uppercase() {
        assert_eq!(
            escape_module_path("github.com/Google/foo"),
            "github.com/!google/foo"
        );
        assert_eq!(
            escape_module_path("github.com/maximhq/bifrost/core"),
            "github.com/maximhq/bifrost/core"
        );
    }

    #[test]
    fn go_module_zip_dirhash_is_deterministic_and_order_independent() {
        let dir = tempfile::tempdir().unwrap();
        // Build two zips with identical content in different member
        // insertion order.
        let a = zip::ZipWriter::new(std::fs::File::create(dir.path().join("a.zip")).unwrap());
        let b = zip::ZipWriter::new(std::fs::File::create(dir.path().join("b.zip")).unwrap());
        let afile = b"package a\n";
        let bfile = b"package b\n";
        // a.zip: b then a; b.zip: a then b.
        for (writer, order) in [
            (a, vec![("b.go", bfile), ("a.go", afile)]),
            (b, vec![("a.go", afile), ("b.go", bfile)]),
        ] {
            let mut writer = writer;
            for (name, bytes) in order {
                let opts = zip::write::FileOptions::<()>::default()
                    .compression_method(zip::CompressionMethod::Stored);
                writer.start_file(name, opts).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        let ha = go_dirhash(&dir.path().join("a.zip")).unwrap();
        let hb = go_dirhash(&dir.path().join("b.zip")).unwrap();
        assert_eq!(ha, hb, "dirhash must sort members, not trust archive order");
    }

    /// Write a module zip with a single top-level directory member
    /// `<module>@<version>/`, the proxy's archive shape (files only; the
    /// top-level dir member is implied by the path prefix).
    fn write_module_zip(root: &Path, dest: &Path, module: &str, version: &str) {
        let prefix = format!("{module}@{version}/");
        let opts = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut zipw = zip::ZipWriter::new(std::fs::File::create(dest).unwrap());
        for path in walk(root) {
            let rel = path.strip_prefix(root).unwrap();
            let name = format!("{prefix}{}", rel.to_string_lossy());
            zipw.start_file(name, opts).unwrap();
            zipw.write_all(&std::fs::read(&path).unwrap()).unwrap();
        }
        zipw.finish().unwrap();
    }

    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    // ── Conditional drift probe (float-304 plan) ──

    /// A minimal tar.gz with one member `pkg/data.txt`, so a 200 source
    /// fetch extracts cleanly and `find_source_root` sees one top dir.
    fn tiny_tarball(body: &str) -> Vec<u8> {
        let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "pkg/data.txt", body.as_bytes())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    /// A throwaway loopback HTTP/1.1 server: `respond` builds one raw
    /// response per request from the raw request bytes (headers
    /// included, so tests branch on `If-None-Match`). Every response
    /// closes the connection, so each curl hop is one fresh accept. The
    /// accept loop exits when the returned flag is set; leftover threads
    /// die with the test process.
    fn spawn_http_server(
        respond: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = shutdown.clone();
        std::thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            loop {
                if sd.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut req = Vec::new();
                        let mut buf = [0u8; 4096];
                        loop {
                            match std::io::Read::read(&mut stream, &mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    req.extend_from_slice(&buf[..n]);
                                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                            }
                        }
                        let head_end = req
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|p| p + 4)
                            .unwrap_or(req.len());
                        let response = respond(&req[..head_end]);
                        let _ = std::io::Write::write_all(&mut stream, &response);
                        let _ = std::io::Write::flush(&mut stream);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        (format!("http://{addr}/src.tar.gz"), shutdown)
    }

    /// The loopback test server responses are raw bytes like curl's -w
    /// contract expects; keep one builder so the Content-Length math is
    /// written once.
    fn http_response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut head = format!("{status_line}\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        head.push_str("Connection: close\r\n\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn curl_available() -> bool {
        match nau_infra::tools::ensure(nau_infra::tools::ToolName::Curl) {
            Ok(_) => true,
            Err(e) => {
                // Loopback curl tests are the gate's contract; a machine
                // without curl skips rather than fails.
                eprintln!("skipping curl-backed probe test: {e}");
                false
            }
        }
    }

    fn validators(etag: &str, recorded_sha256: &str) -> Option<SourceValidators> {
        Some(SourceValidators {
            etag: etag.to_string(),
            recorded_sha256: recorded_sha256.to_string(),
        })
    }

    fn unverified_spec(url: &str) -> SourceSpec {
        SourceSpec::Unverified(url.to_string())
    }

    #[test]
    fn http_get_conditional_captures_etag_and_body_on_200() {
        if !curl_available() {
            return;
        }
        let body = b"payload-bytes".to_vec();
        let (url, shutdown) = spawn_http_server(move |_req| {
            http_response("HTTP/1.1 200 OK", &[("ETag", "\"v2\"")], &body)
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch = http_get_conditional(&url, &tmp, None).unwrap();
        assert_eq!(fetch.code, 200);
        // The etag is stored verbatim — quoted form included.
        assert_eq!(fetch.etag.as_deref(), Some("\"v2\""));
        assert_eq!(std::fs::read(&tmp).unwrap(), b"payload-bytes");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// A server dying mid-body (Content-Length promises more than it
    /// sends, connection drops) must fail the fetch loud AND leave a
    /// pre-existing dest byte-identical — the sibling-tmp + rename-on-200
    /// contract means a partial transfer can never replace real bytes
    /// (council test plan: mid-transfer kill leaves dest intact).
    #[test]
    fn http_get_conditional_mid_transfer_kill_leaves_dest_intact() {
        if !curl_available() {
            return;
        }
        let (url, shutdown) = spawn_http_server(move |_req| {
            // Promises 100 bytes, sends 5, closes: curl exits 18/23.
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec()
        });
        let work = tempfile::tempdir().unwrap();
        let dest = work.path().join("out.bin");
        std::fs::write(&dest, b"original-bytes").unwrap();
        let err = http_get_to_file(&url, &dest).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download"),
            "mid-transfer kill must bail loud: {msg}"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"original-bytes",
            "a partial transfer must never replace dest bytes"
        );
        let tmp = dest.with_file_name(format!(
            ".{}.tmp-{}",
            dest.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download"),
            std::process::id()
        ));
        assert!(!tmp.exists(), "a failed transfer must not leave its tmp");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn http_get_conditional_304_leaves_tmp_deletion_to_the_caller() {
        if !curl_available() {
            return;
        }
        let (url, shutdown) = spawn_http_server(move |req| {
            if req.windows(14).any(|w| w == b"If-None-Match:") {
                http_response("HTTP/1.1 304 Not Modified", &[("ETag", "\"v1\"")], b"")
            } else {
                http_response("HTTP/1.1 500 Internal Server Error", &[], b"")
            }
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        std::fs::write(&tmp, b"stale").unwrap();
        let fetch = http_get_conditional(&url, &tmp, Some("\"v1\"")).unwrap();
        assert_eq!(fetch.code, 304);
        // The seam's raw contract: a 304 has no body, so curl leaves the
        // tmp's existing bytes untouched (and creates nothing when absent)
        // — deleting it and keeping the recorded bytes standing is the
        // CALLER's move.
        assert!(tmp.exists(), "curl must leave the tmp for the caller");
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            b"stale",
            "a 304 never touches existing bytes"
        );
        let recorded = probe_unchanged(
            &fetch,
            Some("\"v1\""),
            validators("\"v1\"", "recorded-sha").as_ref(),
            &tmp,
            &url,
        )
        .unwrap();
        assert_eq!(recorded.as_deref(), Some("recorded-sha"));
        assert!(!tmp.exists(), "the caller deletes the tmp");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn http_get_conditional_bails_loud_without_an_http_response() {
        if !curl_available() {
            return;
        }
        // A port nothing listens on: curl exits nonzero (connection
        // refused) — bail loud.
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let err = http_get_conditional("http://127.0.0.1:9/src.tar.gz", &tmp, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download"),
            "bail must keep the download-failure wording: {msg}"
        );
    }

    #[test]
    fn http_get_to_file_surfaces_the_status_code_and_never_writes_dest() {
        if !curl_available() {
            return;
        }
        let (url, shutdown) =
            spawn_http_server(move |_req| http_response("HTTP/1.1 404 Not Found", &[], b""));
        let work = tempfile::tempdir().unwrap();
        let dest = work.path().join("src.tar.gz");
        let err = http_get_to_file(&url, &dest).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download") && msg.contains("404"),
            "bail must keep today's wording plus the status: {msg}"
        );
        assert!(!dest.exists(), "a failed GET never leaves a file at dest");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn parse_last_etag_reads_the_final_redirect_hop() {
        if !curl_available() {
            return;
        }
        // github.com 302s to codeload.github.com; both hops carry an
        // ETag and the LAST block's is the real one.
        let (url, shutdown) = spawn_http_server(move |req| {
            let path = std::str::from_utf8(req).unwrap_or("");
            if path.contains("GET /src.tar.gz ") {
                let body = b"redirected".to_vec();
                http_response(
                    "HTTP/1.1 302 Found",
                    &[("Location", "/real"), ("ETag", "\"hop-etag\"")],
                    &body,
                )
            } else {
                let body = b"real-bytes".to_vec();
                http_response("HTTP/1.1 200 OK", &[("ETag", "\"real-etag\"")], &body)
            }
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch = http_get_conditional(&url, &tmp, None).unwrap();
        assert_eq!(fetch.code, 200);
        assert_eq!(
            fetch.etag.as_deref(),
            Some("\"real-etag\""),
            "with -L the redirect hops concatenate; the LAST block's etag wins"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn fetch_tree_304_short_circuits_without_extraction() {
        if !curl_available() {
            return;
        }
        let (url, shutdown) = spawn_http_server(move |req| {
            if req.windows(14).any(|w| w == b"If-None-Match:") {
                http_response("HTTP/1.1 304 Not Modified", &[("ETag", "\"v1\"")], b"")
            } else {
                http_response("HTTP/1.1 500 Internal Server Error", &[], b"")
            }
        });
        let work = tempfile::tempdir().unwrap();
        let validators = validators("\"v1\"", "recorded-sha");
        let out = fetch_tree_for_spec(
            "tool",
            &unverified_spec(&url),
            true,
            work.path(),
            validators.as_ref(),
        )
        .unwrap();
        match out {
            SourceTree::Unchanged { recorded_sha256 } => {
                assert_eq!(recorded_sha256, "recorded-sha");
            }
            SourceTree::Fetched { .. } => panic!("a 304 must short-circuit, not fetch"),
        }
        assert!(
            !work.path().join("src.tar.gz").exists(),
            "the zero-byte tmp is deleted; no tarball remains"
        );
        assert!(!work.path().join("src").exists(), "a 304 never extracts");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn fetch_tree_condition_ignored_full_get_has_no_false_drift() {
        if !curl_available() {
            return;
        }
        let archive = tiny_tarball("same-bytes");
        let recorded_sha = hex_sha256(&archive);
        let (url, shutdown) = spawn_http_server(move |_req| {
            // The server IGNORES If-None-Match and re-serves identical
            // bytes under a refreshed etag.
            http_response("HTTP/1.1 200 OK", &[("ETag", "\"v2\"")], &archive)
        });
        let work = tempfile::tempdir().unwrap();
        let validators = validators("\"v1\"", &recorded_sha);
        let out = fetch_tree_for_spec(
            "tool",
            &unverified_spec(&url),
            true,
            work.path(),
            validators.as_ref(),
        )
        .unwrap();
        let SourceTree::Fetched { root, observed } = out else {
            panic!("a 200 must fetch and extract");
        };
        assert_eq!(observed.sha256, recorded_sha, "no false drift");
        assert!(!observed.unchanged);
        assert_eq!(observed.etag.as_deref(), Some("\"v2\""), "etag refreshed");
        let data = root.join("data.txt");
        assert_eq!(std::fs::read_to_string(&data).unwrap(), "same-bytes");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn fetch_tree_weak_etag_is_never_sent_as_a_condition() {
        if !curl_available() {
            return;
        }
        let archive = tiny_tarball("fresh-bytes");
        let sha = hex_sha256(&archive);
        let (url, shutdown) = spawn_http_server(move |req| {
            if req.windows(14).any(|w| w == b"If-None-Match:") {
                // Would 304 if the weak etag leaked into the request.
                http_response("HTTP/1.1 304 Not Modified", &[], b"")
            } else {
                http_response("HTTP/1.1 200 OK", &[("ETag", "\"v2\"")], &archive)
            }
        });
        let work = tempfile::tempdir().unwrap();
        // Weak validators are rejected → treated as absent: the fetch is
        // unconditional and the recorded sha plays no part.
        let validators = validators("W/\"weak-1\"", "not-the-sha");
        let out = fetch_tree_for_spec(
            "tool",
            &unverified_spec(&url),
            true,
            work.path(),
            validators.as_ref(),
        )
        .unwrap();
        let SourceTree::Fetched { observed, .. } = out else {
            panic!("a weak etag must full-GET, not 304");
        };
        assert_eq!(observed.sha256, sha);
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn fetch_tree_non_200_bails_naming_the_code() {
        if !curl_available() {
            return;
        }
        let (url, shutdown) = spawn_http_server(move |_req| {
            http_response("HTTP/1.1 500 Internal Server Error", &[], b"")
        });
        let work = tempfile::tempdir().unwrap();
        let err = fetch_tree_for_spec("tool", &unverified_spec(&url), true, work.path(), None)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download") && msg.contains("500"),
            "bail must keep today's wording plus the status: {msg}"
        );
        assert!(!work.path().join("src").exists());
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // ── Retry on 429 (council lever 1: rate-limit resilience) ──

    /// Serializes mutations of the module-global retry budget and the
    /// `NAU_NET_RETRY` env pin — both process globals, the same window
    /// pattern as the env lock in src/sign.rs.
    static RETRY_GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Knobs for retry tests: retrying on, generous cap, zero backoff
    /// base so the no-op sleep never stalls the suite.
    fn retry_test_knobs(cap_ms: u64) -> RetryKnobs {
        RetryKnobs {
            enabled: true,
            cap_ms,
            backoff_base_ms: 0,
        }
    }

    /// The test sleeper: policy timing runs, wall-clock does not.
    fn noop_sleep(_: std::time::Duration) {}

    /// Council scenario (a): 429 + `Retry-After: 0` then 200 — one
    /// retry, and the etag capture of the final hop stays intact.
    #[test]
    fn http_get_conditional_retries_429_with_retry_after_zero_then_succeeds() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let body = b"payload-bytes".to_vec();
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            let n = hits_server.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                http_response(
                    "HTTP/1.1 429 Too Many Requests",
                    &[("Retry-After", "0")],
                    b"",
                )
            } else {
                http_response("HTTP/1.1 200 OK", &[("ETag", "\"v2\"")], &body)
            }
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap();
        assert_eq!(fetch.code, 200);
        assert_eq!(
            fetch.etag.as_deref(),
            Some("\"v2\""),
            "etag capture must survive the retry"
        );
        assert_eq!(std::fs::read(&tmp).unwrap(), b"payload-bytes");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "429 + Retry-After: 0 must retry exactly once before the 200"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council scenario (b): bare 429s ride the jittered-backoff path
    /// (base 0ms injected) and succeed on the third attempt.
    #[test]
    fn http_get_conditional_retries_bare_429_through_the_backoff_path() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            let n = hits_server.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                http_response("HTTP/1.1 429 Too Many Requests", &[], b"")
            } else {
                http_response("HTTP/1.1 200 OK", &[("ETag", "\"v3\"")], b"third-try")
            }
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap();
        assert_eq!(fetch.code, 200);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "two bare 429s must exhaust both retries before the 200"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council scenario (c): `Retry-After: 9999` over the 120s cap
    /// fails loud naming the value, and never fires a second request —
    /// clamp-and-retry-early is the ban-magnet.
    #[test]
    fn http_get_conditional_fails_loud_when_retry_after_exceeds_the_cap() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            hits_server.fetch_add(1, Ordering::SeqCst);
            http_response(
                "HTTP/1.1 429 Too Many Requests",
                &[("Retry-After", "9999")],
                b"",
            )
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let err =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download") && msg.contains("9999"),
            "over-cap Retry-After must fail loud naming the value: {msg}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "an over-cap Retry-After must never fire a second request"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council scenario (d): the shared per-sync sleep budget (amended
    /// over the doc's count cap — N fetches must not multiply budgets)
    /// fails loud immediately when the next honored delay cannot fit.
    #[test]
    fn http_get_conditional_fails_loud_when_the_shared_sleep_budget_is_spent() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _window = RETRY_GLOBAL_LOCK.lock().unwrap();
        NET_RETRY_BUDGET_MS.store(100, std::sync::atomic::Ordering::Relaxed);
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            hits_server.fetch_add(1, Ordering::SeqCst);
            http_response(
                "HTTP/1.1 429 Too Many Requests",
                &[("Retry-After", "60")],
                b"",
            )
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let err =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download") && msg.contains("budget"),
            "a spent shared budget must fail loud: {msg}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "an unservable delay must fail on first sight of the 429"
        );
        NET_RETRY_BUDGET_MS.store(
            NET_RETRY_BUDGET_DEFAULT_MS,
            std::sync::atomic::Ordering::Relaxed,
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council scenario (e): after the last attempt the message keeps
    /// today's shape and names the attempts — a 429 stays a loud sync
    /// failure, never a hold or a drift verdict.
    #[test]
    fn http_get_conditional_names_attempts_when_retries_are_exhausted() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            hits_server.fetch_add(1, Ordering::SeqCst);
            http_response("HTTP/1.1 429 Too Many Requests", &[], b"")
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let err =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to download")
                && msg.contains("(HTTP 429")
                && msg.contains("after 3 attempts"),
            "exhaustion must keep the download-failure shape plus attempts: {msg}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "exactly the 3 attempts, no more"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council scenario (f): a bare 403 is a hard error — permission
    /// failures are never retried, today's single-shot behavior.
    #[test]
    fn http_get_conditional_never_retries_a_bare_403() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            hits_server.fetch_add(1, Ordering::SeqCst);
            http_response("HTTP/1.1 403 Forbidden", &[], b"")
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch =
            http_get_conditional_with(&retry_test_knobs(120_000), &noop_sleep, &url, &tmp, None)
                .unwrap();
        assert_eq!(fetch.code, 403);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a bare 403 must never retry"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// The `NAU_NET_RETRY=0` kill switch is today's behavior exactly:
    /// one request, the caller's `(HTTP 429)` shape, no `after` clause.
    #[test]
    fn http_get_conditional_kill_switch_keeps_todays_single_attempt_behavior() {
        if !curl_available() {
            return;
        }
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let _window = RETRY_GLOBAL_LOCK.lock().unwrap();
        std::env::set_var("NAU_NET_RETRY", "0");
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_server = hits.clone();
        let (url, shutdown) = spawn_http_server(move |_req| {
            hits_server.fetch_add(1, Ordering::SeqCst);
            http_response("HTTP/1.1 429 Too Many Requests", &[], b"")
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch = http_get_conditional(&url, &tmp, None).unwrap();
        assert_eq!(fetch.code, 429);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the kill switch means one request"
        );
        let dest = work.path().join("via-to-file.bin");
        let err = http_get_to_file(&url, &dest).unwrap_err();
        let msg = format!("{err}");
        std::env::remove_var("NAU_NET_RETRY");
        assert!(
            msg.contains("(HTTP 429)") && !msg.contains("after"),
            "the kill switch keeps today's caller-facing shape: {msg}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "one request per fetch, still"
        );
        shutdown.store(true, Ordering::Relaxed);
    }

    /// Council lever 4 rider: the UA carries contact info so GitHub can
    /// identify (and except) the agent.
    #[test]
    fn http_get_conditional_sends_the_contact_user_agent() {
        if !curl_available() {
            return;
        }
        use std::sync::{Arc, Mutex};
        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let seen_server = seen.clone();
        let (url, shutdown) = spawn_http_server(move |req| {
            *seen_server.lock().unwrap() = Some(String::from_utf8_lossy(req).into_owned());
            http_response("HTTP/1.1 200 OK", &[], b"")
        });
        let work = tempfile::tempdir().unwrap();
        let tmp = work.path().join("out.bin");
        let fetch = http_get_conditional(&url, &tmp, None).unwrap();
        assert_eq!(fetch.code, 200);
        let head = seen.lock().unwrap().clone().unwrap();
        let ua = head
            .lines()
            .find(|l| l.len() > 12 && l[..11].eq_ignore_ascii_case("user-agent:"))
            .unwrap_or_else(|| panic!("request must carry a User-Agent: {head}"));
        assert!(
            ua.contains("nau/") && ua.contains("(+https://github.com/rbelem/shuttle)"),
            "the UA must carry the contact info: {ua}"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
