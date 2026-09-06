//! Dependency-closure fetch for interpreted packages (ADR-0017, issue #13).
//!
//! Interpreter-based packages (Node/Python CLIs) declare a `deps` closure —
//! an ecosystem resolver plus its lockfile. This module implements the
//! **fetch phase**: a pure downloader that runs OUTSIDE the build sandbox
//! with network, resolves the dependency closure from the lockfile, and
//! materializes it into a deterministic tree. The tree is digested
//! NAR-style (sorted paths + contents) into a `deps_hash`, recorded in the
//! pod's `shuttle.lock`, and stored as ONE content-addressed pod-store
//! blob. The sandbox build later verifies that hash and mounts the entry
//! read-only (`$SHUTTLE_DEPS_DIR`).
//!
//! Safety property (council-reviewed): **the fetch never executes
//! lifecycle/install scripts on the host.** npm closures come from tarball
//! GETs driven by the resolved lock (never `npm install`); pip closures
//! are wheels fetched from a PEP 503 simple index (never `pip install`).
//! Extraction is data-only — any install scripts ship inert inside the
//! tree and only ever run, if at all, inside the offline sandbox.
//!
//! The canonical archive format ("SHDEP") is a minimal, deterministic
//! serialization: entries sorted by path, normalized modes (0755/0644 by
//! exec bit), no timestamps, no uid/gid. `deps_hash` = SHA-256 of the
//! archive bytes = the pod-store blob name, so content addressing and the
//! lock pin are the same number.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

use crate::lock::PackageDepsLock;
use crate::runtime::RuntimeStore;
use crate::snap::{DepsLockSpec, SnapMeta};

/// Default PyPI simple index for pip resolvers (overridable per resolver
/// via `deps.pip.index` — tests point it at a loopback server).
pub const DEFAULT_PIP_INDEX: &str = "https://pypi.org/simple";

// ── Orchestration ──

/// Ensure the package's dependency closure is fetched and cached in the
/// pod store, returning the pin to record in `shuttle.lock`.
///
/// Locked packages (`floating == false`) with a cached store entry never
/// re-fetch — bit-reproducible. A locked package whose store entry went
/// missing (pod GC) re-fetches and requires the closure to reproduce the
/// pinned hash: a moved upstream is a pin violation, not a silent update.
/// Floating packages (`floating == true`, explicit opt-in) re-resolve on
/// every call, record the new hash and a fresh `fetched_at` date tag, and
/// keep the last-known pin intact until the caller commits the new one —
/// rollback stays hash-pinned either way (ADR-0017 Decision 5).
pub fn ensure_pod_deps(
    store: &RuntimeStore,
    meta: &SnapMeta,
    prev: Option<&PackageDepsLock>,
    floating: bool,
) -> miette::Result<PackageDepsLock> {
    let Some(deps) = &meta.deps else {
        miette::bail!(
            "internal: ensure_pod_deps called for '{}' which declares no deps",
            meta.name
        );
    };
    let pinned = prev.map(|p| p.deps_hash.as_str());

    // Locked + cached: verify nothing, fetch nothing — the entry is
    // content-addressed and re-verified against the pin at build time.
    if !floating {
        if let Some(hash) = pinned {
            if store.blob_path(hash).exists() {
                return Ok(prev.expect("pinned implies prev").clone());
            }
        }
    }

    let hash = fetch_deps_closure(store, meta, deps)?;

    match pinned {
        // The re-fetch reproduced the pin (locked entry rebuilt after GC,
        // or a float whose upstream closure did not move): keep the pin —
        // and its original fetched_at — untouched.
        Some(old) if old == hash => Ok(prev.expect("pinned implies prev").clone()),
        Some(old) => {
            if !floating {
                miette::bail!(
                    "dependency closure for '{}' changed upstream ({:.12} → {:.12}) \
                     but the package is locked and its cached store entry was missing — \
                     refusing to move the pin; run `shuttle deps fetch --latest` to move it deliberately",
                    meta.name,
                    old,
                    hash
                );
            }
            crate::output::warn(format!(
                "floating package '{}': dependency closure changed ({:.12} → {:.12})",
                meta.name, old, hash
            ));
            Ok(PackageDepsLock {
                deps_hash: hash,
                fetched_at: Some(today()),
            })
        }
        None => {
            // TOFU (ADR-0017 Decision 3): print the hash; the lockfile IS
            // the pin record.
            crate::output::ok(format!(
                "pinned dependency closure for '{}': {:.12}… (recorded in shuttle.lock)",
                meta.name, hash
            ));
            Ok(PackageDepsLock {
                deps_hash: hash,
                fetched_at: Some(today()),
            })
        }
    }
}

/// Fetch + materialize the closure and store it as one content-addressed
/// blob. Returns the blob's sha256 (the `deps_hash`).
fn fetch_deps_closure(
    store: &RuntimeStore,
    meta: &SnapMeta,
    deps: &crate::snap::PackageDeps,
) -> miette::Result<String> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let src_root = fetch_source_tree(meta, work.path())?;
    let tree = work.path().join("tree");
    std::fs::create_dir_all(&tree).map_err(|e| miette::miette!("creating tree dir: {e}"))?;
    if let Some(npm) = &deps.npm {
        fetch_npm_closure(npm, &src_root, &tree, work.path())?;
    }
    if let Some(pip) = &deps.pip {
        fetch_pip_closure(pip, &src_root, &tree, work.path())?;
    }
    let bytes = pack_canonical(&tree)?;
    write_store_blob(store, &bytes)
}

/// Verify the store's closure blob against its pin and unpack it into a
/// fresh temp dir for the build sandbox to mount read-only (ADR-0017
/// Decision 3: "the sandbox build verifies the hash before use").
pub fn materialize_deps_entry(
    store: &RuntimeStore,
    deps_hash: &str,
) -> miette::Result<tempfile::TempDir> {
    let blob = store.blob_path(deps_hash);
    if !blob.exists() {
        miette::bail!(
            "cached dependency closure {deps_hash:.12}… is missing from the pod store — \
             run `shuttle deps fetch` to fetch it"
        );
    }
    let actual = sha256_file(&blob)?;
    if actual != deps_hash {
        miette::bail!(
            "dependency closure hash mismatch: expected {deps_hash}, found {actual} — \
             the store entry is corrupted or tampered with; refusing to build against it"
        );
    }
    let bytes =
        std::fs::read(&blob).map_err(|e| miette::miette!("reading {}: {e}", blob.display()))?;
    let dir = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    unpack_canonical(&bytes, dir.path())?;
    Ok(dir)
}

// ── Source tree (the lockfile ships in the package source) ──

/// Download + extract the package's source tarball and return its source
/// root — the same download/TOFU semantics `run_build` applies.
fn fetch_source_tree(meta: &SnapMeta, work: &Path) -> miette::Result<PathBuf> {
    let spec = meta.source.as_ref().ok_or_else(|| {
        miette::miette!(
            "package '{}': deps requires source — the lockfile resolves from the source tree",
            meta.name
        )
    })?;
    let url = spec.url();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        miette::bail!(
            "package '{}': deps requires an http(s) source URL, got {url}",
            meta.name
        );
    }
    let filename = url.rsplit('/').next().unwrap_or("source.tar.gz");
    let tarball = work.join(filename);
    let spinner = crate::output::spinner(&format!(
        "fetching dependency closure for {} (downloading source)...",
        meta.name
    ));
    http_get_to_file(url, &tarball)?;
    let sha = sha256_file(&tarball)?;
    if let Some(expected) = spec.expected_sha256() {
        if sha != expected {
            return Err(miette::miette!(
                "SHA-256 mismatch for {url}:\n  expected: {expected}\n  got:      {sha}"
            ));
        }
    }
    let src_dir = work.join("src");
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| miette::miette!("creating {}: {e}", src_dir.display()))?;
    let status = std::process::Command::new("tar")
        .arg("xf")
        .arg(&tarball)
        .arg("-C")
        .arg(&src_dir)
        .status()
        .map_err(|e| miette::miette!("tar not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("failed to extract {filename}"));
    }
    crate::output::finish_ok(&spinner, &format!("fetched source of {}", meta.name));
    Ok(find_source_root(&src_dir))
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
                crate::output::warn(format!(
                    "npm closure: excluding '{}' (matched deps.npm.exclude '{}')",
                    artifact.key, exclude[i]
                ));
                false
            }
            None => true,
        }
    });
    crate::output::info(format!(
        "npm exclude: {} of {total} package(s) dropped by deps.npm.exclude",
        total - artifacts.len()
    ));
    for (pattern, hit) in exclude.iter().zip(&matched) {
        if !hit {
            crate::output::warn(format!(
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
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    let lock_bytes = read_source_file(src_root, &spec.lock)?;
    let mut artifacts = parse_npm_lock(&lock_bytes)?;
    if !spec.exclude.is_empty() {
        artifacts = apply_npm_exclude(artifacts, &spec.exclude);
    }
    crate::output::info(format!(
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
fn parse_pip_pins(bytes: &[u8]) -> miette::Result<Vec<PipPin>> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("[[package]]") {
        parse_uv_lock(bytes)
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
    /// to the dev/prod split (issue #14).
    dev_dependencies: Option<Vec<UvDep>>,
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
fn parse_uv_lock(bytes: &[u8]) -> miette::Result<Vec<PipPin>> {
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
        if let Some(pin) = pin_for_package(pkg) {
            out.push(pin);
        }
    }
    if !dev_skipped.is_empty() {
        crate::output::warn(format!(
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
/// wheel for this platform.
fn pin_for_package(pkg: &UvPackage) -> Option<PipPin> {
    let Some(wheels) = &pkg.wheels else {
        crate::output::warn(format!(
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
        crate::output::warn(format!(
            "uv.lock: {} {} is not from a registry — skipped",
            pkg.name, pkg.version
        ));
        return None;
    }
    let norm = normalize_name(&pkg.name);
    let Some(wheel) = wheels.iter().find(|w| {
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
    }) else {
        crate::output::warn(format!(
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

/// The PEP 503-normalized names of packages that exist ONLY for
/// development (issue #14): the transitive closure of every package's
/// `dev-dependencies`, minus the closure reachable from the packages
/// shuttle installs from source. Those prod roots are every NON-registry
/// source (editable/virtual/directory/git — their regular dependency
/// closure IS the wanted closure). Fail-safe: a lock with no
/// source-installed package has no reliable dev/prod split, so an empty
/// prod root set yields an empty set (fetch everything).
fn dev_only_names(pkgs: &[UvPackage]) -> BTreeSet<String> {
    let dev_roots: BTreeSet<String> = pkgs
        .iter()
        .flat_map(|p| p.dev_dependencies.iter().flatten())
        .map(|d| normalize_name(&d.name))
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
    tree: &Path,
    work: &Path,
) -> miette::Result<()> {
    let index = spec.index.as_deref().unwrap_or(DEFAULT_PIP_INDEX);
    let lock_bytes = read_source_file(src_root, &spec.lock)?;
    let pins = parse_pip_pins(&lock_bytes)?;
    crate::output::info(format!(
        "pip closure: {} package(s) from {} via {index}",
        pins.len(),
        spec.lock
    ));
    for pin in &pins {
        fetch_pip_wheel(pin, index, tree, work)?;
    }
    Ok(())
}

/// Resolve one pin to a wheel and download it, verifying integrity.
/// A pin with a direct URL (uv.lock) is fetched straight from the lock;
/// otherwise the pin resolves on the index's project page. Either way
/// the wheel is verified against the pin's hash (authoritative) or the
/// page's anchor hash (TOFU when the lock carries no hash).
fn fetch_pip_wheel(pin: &PipPin, index: &str, tree: &Path, work: &Path) -> miette::Result<()> {
    if let Some(url) = &pin.url {
        let filename = url.rsplit('/').next().unwrap_or("wheel.whl");
        let dest = tree.join(filename);
        http_get_to_file(url, &dest)?;
        return match pin.hashes.first() {
            Some(hash) => {
                let actual = sha256_file(&dest)?;
                if !constant_eq(actual.as_bytes(), hash.as_bytes()) {
                    let _ = std::fs::remove_file(&dest);
                    miette::bail!(
                        "pip: wheel {filename} hash mismatch: expected {hash}, got {actual}"
                    );
                }
                Ok(())
            }
            None => {
                let actual = sha256_file(&dest)?;
                crate::output::warn(format!(
                    "pip: wheel {filename} fetched unpinned (hash {actual:.16}… — pin it in the lock)"
                ));
                Ok(())
            }
        };
    }
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
            crate::output::warn(format!(
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
/// produced from this — pure data, no scripts).
fn unpack_canonical(bytes: &[u8], dest: &Path) -> miette::Result<()> {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some(line_end) = bytes[pos..].iter().position(|&b| b == b'\n') else {
            miette::bail!("corrupt closure archive: unterminated entry");
        };
        let line = std::str::from_utf8(&bytes[pos..pos + line_end])
            .map_err(|_| miette::miette!("corrupt closure archive: bad header"))?;
        pos += line_end + 1;
        if line == "END" {
            return Ok(());
        }
        pos += unpack_entry(line, &bytes[pos..], dest)?;
    }
    miette::bail!("corrupt closure archive: missing END marker")
}

/// Unpack one archive entry given its header line and the payload bytes
/// that follow it; returns how many payload bytes were consumed.
fn unpack_entry(line: &str, body: &[u8], dest: &Path) -> miette::Result<usize> {
    let mut parts = line.splitn(4, ' ');
    match parts.next() {
        Some("D") => {
            let rel = parts.next().unwrap_or("");
            std::fs::create_dir_all(dest.join(rel))
                .map_err(|e| miette::miette!("mkdir {rel}: {e}"))?;
            Ok(0)
        }
        Some("L") => unpack_link_entry(line, dest),
        Some("F") => unpack_file_entry(line, body, dest),
        _ => miette::bail!("corrupt closure archive: unknown entry '{line}'"),
    }
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

/// Unpack a file entry: `F <mode:o> <size> <path>` + `<size> payload
/// bytes`; returns the consumed payload size.
fn unpack_file_entry(line: &str, body: &[u8], dest: &Path) -> miette::Result<usize> {
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
    let payload = body
        .get(..size)
        .ok_or_else(|| miette::miette!("corrupt file entry: short body"))?;
    let out = dest.join(rel);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(&out, payload).map_err(|e| miette::miette!("write {rel}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))
            .map_err(|e| miette::miette!("chmod {rel}: {e}"))?;
    }
    Ok(size)
}

// ── Store blob plumbing ──

/// Write `bytes` into the pod store content-addressed by its sha256
/// (atomic: temp file + rename). Returns the hash (= the `deps_hash`).
fn write_store_blob(store: &RuntimeStore, bytes: &[u8]) -> miette::Result<String> {
    let hash = hex_sha256(bytes);
    let path = store.blob_path(&hash);
    if path.exists() {
        return Ok(hash);
    }
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("blob path has no parent"))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        ".blob-tmp-{}-{}",
        std::process::id(),
        &hash[..12.min(hash.len())]
    ));
    {
        let mut f =
            File::create(&tmp).map_err(|e| miette::miette!("creating {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| miette::miette!("writing {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| miette::miette!("finalizing {}: {e}", path.display()))?;
    Ok(hash)
}

// ── Small shared helpers ──

/// curl download (the codebase's one network mechanism).
fn http_get_to_file(url: &str, dest: &Path) -> miette::Result<()> {
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| miette::miette!("curl not found: {e}"))?;
    if !status.success() {
        miette::bail!("failed to download {url}");
    }
    Ok(())
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

/// Read a lockfile out of the fetched source tree with a clear error when
/// the declared path is missing.
fn read_source_file(src_root: &Path, rel: &str) -> miette::Result<Vec<u8>> {
    let path = src_root.join(rel);
    std::fs::read(&path).map_err(|_| {
        miette::miette!(
            "declared lockfile '{rel}' not found in the package source tree (looked at {})",
            path.display()
        )
    })
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
    use super::*;

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
        let pins = parse_pip_pins(lock.as_bytes()).unwrap();
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
        let pins = parse_uv_lock(text.as_bytes()).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "prod");
        assert_eq!(pins[0].hashes, vec!["pppp"]);
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
        let pins = parse_uv_lock(text.as_bytes()).unwrap();
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn uv_lock_sniffed_over_requirements_format() {
        // A uv.lock routes to the TOML parser even via the shared entry.
        let lock = "[[package]]\nname = \"x\"\nversion = \"1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://f/x-1.0-py3-none-any.whl\" }]\n";
        let pins = parse_pip_pins(lock.as_bytes()).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "x");
        // A requirements file never sniffs as uv.lock (no [[package]]).
        let req = "certifi==2024.2.2\n";
        let pins = parse_pip_pins(req.as_bytes()).unwrap();
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
        unpack_canonical(&bytes1, &out).unwrap();
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
        unpack_canonical(&bytes, &out).unwrap();
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
}
