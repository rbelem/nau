//! Package source resolution — fetch package definitions from declared inputs.
//!
//! Inspired by Nix flake inputs, shuttle supports:
//! - `github:user/repo[/branch]` — shallow clone from GitHub
//! - `path:/local/directory`     — local filesystem path
//!
//! Global inputs (declared at the top of `shuttle.lua` before the return statement)
//! power the package index. Per-snap inputs declare additional sources.
//!
//! GitHub URLs are cached in `~/.cache/shuttle/inputs/<hash>/` after a shallow
//! clone. Local paths are used directly. If no inputs are configured, a default
//! input (`github:rbelem/shuttle/main`) is used as fallback so `shuttle build <pkg>`
//! works out of the box.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::lock::{InputLockEntry, LockFile};
use crate::snap::PackageInput;

// ── Cache paths ──

/// SHA-256 hex digest of a string.
fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Default input URL used when no inputs are configured.
pub const DEFAULT_INPUT_URL: &str = "github:rbelem/shuttle/main";

/// Default input name for the fallback.
pub const DEFAULT_INPUT_NAME: &str = "packages";

/// Home-directory cache root for fetched inputs.
fn cache_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".cache/shuttle/inputs")
}

/// Cache directory for a given github: URL.
fn github_cache_dir(owner: &str, repo: &str, branch: &str) -> PathBuf {
    github_cache_dir_in(&cache_root(), owner, repo, branch)
}

/// [`github_cache_dir`] under an explicit cache root (test injection).
fn github_cache_dir_in(root: &Path, owner: &str, repo: &str, branch: &str) -> PathBuf {
    let key = format!("github:{owner}/{repo}/{branch}");
    let hash = sha256_hex(&key);
    root.join(&hash[..16])
}

// ── Input resolution ──

/// Split a `github:owner/repo[/branch]` URL into `(owner, repo, branch)`.
/// Branch defaults to `"HEAD"`. Returns `None` for non-github or malformed URLs.
pub fn parse_github_url(url: &str) -> Option<(&str, &str, &str)> {
    let rest = url.strip_prefix("github:")?;
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    let branch = parts.next().unwrap_or("HEAD");
    Some((owner, repo, branch))
}

/// Resolve a single input URL to a local filesystem path containing `pkgs/`.
///
/// For `github:` URLs, this fetches (or uses cached) the repo.
/// For `path:` URLs, this strips the prefix and verifies the path.
pub fn resolve_input(input: &PackageInput) -> miette::Result<PathBuf> {
    resolve_input_with(input, None, false)
}

/// Resolve an input honoring a lockfile pin and offline mode.
///
/// - `path:` inputs always resolve to the local directory (pins are markers).
/// - Pinned `github:` inputs resolve to the pinned revision's cache directory,
///   fetching it on first use (never when `offline`) and verifying the
///   recorded content hash.
/// - Unpinned `github:` inputs use the branch-head cache; offline fails
///   instead of fetching.
pub fn resolve_input_with(
    input: &PackageInput,
    pin: Option<&InputLockEntry>,
    offline: bool,
) -> miette::Result<PathBuf> {
    resolve_input_in(&cache_root(), input, pin, offline)
}

/// [`resolve_input_with`] under an explicit cache root (test injection).
fn resolve_input_in(
    root: &Path,
    input: &PackageInput,
    pin: Option<&InputLockEntry>,
    offline: bool,
) -> miette::Result<PathBuf> {
    let url = &input.url;

    if let Some(local) = url.strip_prefix("path:") {
        let p = PathBuf::from(local);
        if !p.exists() {
            return Err(miette::miette!(
                "local input path '{}' does not exist",
                p.display()
            ));
        }
        return Ok(p);
    }

    let Some((owner, repo, branch)) = parse_github_url(url) else {
        return Err(miette::miette!(
            "unsupported input URL scheme in '{url}' (expected 'github:...' or 'path:...')"
        ));
    };

    if let Some(sha) = pin.and_then(|p| p.revision.as_deref()) {
        let dir = pinned_cache_dir_in(root, owner, repo, sha);
        if !dir.exists() {
            if offline {
                return Err(miette::miette!(
                    "input '{url}' is pinned to {sha} but not cached; --offline prevents fetching"
                ));
            }
            fetch_github_rev(owner, repo, sha, &dir)?;
        }
        if let Some(expected) = pin.and_then(|p| p.sha256.as_ref()) {
            let actual = content_hash(&dir)?;
            if &actual != expected {
                return Err(miette::miette!(
                    "input '{url}' content changed since lock (lockfile: {expected}, cache: {actual}); \
                     run 'shuttle lock' or 'shuttle build --update' to refresh the pin"
                ));
            }
        }
        return Ok(dir);
    }

    let cache_dir = github_cache_dir_in(root, owner, repo, branch);
    if !cache_dir.exists() {
        if offline {
            return Err(miette::miette!(
                "input '{url}' is not cached and --offline prevents fetching"
            ));
        }
        fetch_github(owner, repo, branch, &cache_dir)?;
    }
    Ok(cache_dir)
}

/// Shallow-clone a GitHub repo into a cache directory.
fn fetch_github(owner: &str, repo: &str, branch: &str, dest: &Path) -> miette::Result<()> {
    let url = format!("https://github.com/{owner}/{repo}.git");

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("failed to create cache dir {}: {e}", parent.display()))?;
    }

    let output = std::process::Command::new("git")
        .args([
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            "--single-branch",
            &url,
            &dest.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| miette::miette!("failed to run git: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up partial clone
        let _ = std::fs::remove_dir_all(dest);
        return Err(miette::miette!(
            "failed to clone {url} (branch: {branch}): {stderr}"
        ));
    }

    Ok(())
}

/// Re-fetch a cached GitHub input (for `shuttle index update`).
pub fn refresh_input(input: &PackageInput) -> miette::Result<()> {
    let url = &input.url;
    if let Some((owner, repo, branch)) = parse_github_url(url) {
        let cache_dir = github_cache_dir(owner, repo, branch);

        if cache_dir.exists() {
            std::fs::remove_dir_all(&cache_dir)
                .map_err(|e| miette::miette!("failed to remove old cache: {e}"))?;
        }
        fetch_github(owner, repo, branch, &cache_dir)
    } else {
        // Local paths don't need refreshing
        Ok(())
    }
}

// ── Input locking (Phase 16) ──

/// Cache directory for a github input pinned to a specific commit SHA.
/// Separate from the branch-head cache so pins never move.
fn pinned_cache_dir(owner: &str, repo: &str, sha: &str) -> PathBuf {
    pinned_cache_dir_in(&cache_root(), owner, repo, sha)
}

/// [`pinned_cache_dir`] under an explicit cache root (test injection).
fn pinned_cache_dir_in(root: &Path, owner: &str, repo: &str, sha: &str) -> PathBuf {
    let key = format!("github:{owner}/{repo}@{sha}");
    let hash = sha256_hex(&key);
    root.join(&hash[..16])
}

/// Run a git command, failing with its stderr on error.
fn git(cwd: Option<&Path>, args: &[&str]) -> miette::Result<()> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| miette::miette!("failed to run git: {e}"))?;
    if !output.status.success() {
        return Err(miette::miette!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Run a git command and return its stdout.
fn git_out(args: &[&str]) -> miette::Result<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| miette::miette!("failed to run git: {e}"))?;
    if !output.status.success() {
        return Err(miette::miette!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Resolve the current head commit SHA of a GitHub branch (network).
fn head_sha(owner: &str, repo: &str, branch: &str) -> miette::Result<String> {
    let url = format!("https://github.com/{owner}/{repo}.git");
    let out = git_out(&["ls-remote", &url, branch])?;
    let sha = out
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("");
    if sha.is_empty() {
        return Err(miette::miette!(
            "could not resolve head of {url} (branch: {branch})"
        ));
    }
    Ok(sha.to_string())
}

/// Fetch a github repo at an exact commit SHA into `dest`.
///
/// Tries a shallow fetch of the bare SHA first (works on GitHub); falls back
/// to a full clone + checkout for hosts that don't allow SHA fetches.
fn fetch_github_rev(owner: &str, repo: &str, sha: &str, dest: &Path) -> miette::Result<()> {
    let url = format!("https://github.com/{owner}/{repo}.git");

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("failed to create cache dir {}: {e}", parent.display()))?;
    }

    let shallow = (|| -> miette::Result<()> {
        git(None, &["init", "--quiet", &dest.to_string_lossy()])?;
        git(Some(dest), &["remote", "add", "origin", &url])?;
        git(
            Some(dest),
            &["fetch", "--depth", "1", "--quiet", "origin", sha],
        )?;
        git(
            Some(dest),
            &["checkout", "--quiet", "--detach", "FETCH_HEAD"],
        )?;
        Ok(())
    })();
    if shallow.is_ok() {
        return Ok(());
    }

    let _ = std::fs::remove_dir_all(dest);
    if let Err(e) = git(None, &["clone", "--quiet", &url, &dest.to_string_lossy()])
        .and_then(|_| git(Some(dest), &["checkout", "--quiet", "--detach", sha]))
    {
        let _ = std::fs::remove_dir_all(dest);
        return Err(e);
    }
    Ok(())
}

/// Collect every file under `dir`, excluding `.git`.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> miette::Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| miette::miette!("failed to read {}: {e}", dir.display()))?;
    for entry in entries {
        let p = entry.map_err(|e| miette::miette!("{e}"))?.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == ".git" {
            continue;
        }
        if p.is_dir() {
            collect_files(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}

/// SHA-256 over every file under `dir` (paths sorted, `.git` excluded).
/// Each file's relative path and content feed one running hash, so renames
/// and content changes both change the digest.
pub fn content_hash(dir: &Path) -> miette::Result<String> {
    use sha2::Digest;
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    let mut hasher = sha2::Sha256::new();
    for f in &files {
        let rel = f.strip_prefix(dir).unwrap_or(f);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0]);
        let data =
            std::fs::read(f).map_err(|e| miette::miette!("failed to read {}: {e}", f.display()))?;
        hasher.update(&data);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Resolve an input to its current lock entry: branch-head SHA + content
/// hash for github inputs; a local marker for `path:` inputs.
pub fn lock_input_entry(input: &PackageInput) -> miette::Result<InputLockEntry> {
    let url = &input.url;

    if let Some(local) = url.strip_prefix("path:") {
        if !Path::new(local).exists() {
            return Err(miette::miette!("local input path '{local}' does not exist"));
        }
        return Ok(InputLockEntry {
            revision: None,
            sha256: None,
            local: true,
        });
    }

    let Some((owner, repo, branch)) = parse_github_url(url) else {
        return Err(miette::miette!(
            "unsupported input URL scheme in '{url}' (expected 'github:...' or 'path:...')"
        ));
    };

    let sha = head_sha(owner, repo, branch)?;
    let dir = pinned_cache_dir(owner, repo, &sha);
    if !dir.exists() {
        fetch_github_rev(owner, repo, &sha, &dir)?;
    }
    let hash = content_hash(&dir)?;
    Ok(InputLockEntry {
        revision: Some(sha),
        sha256: Some(hash),
        local: false,
    })
}

/// Record lock entries for declared inputs missing from the lockfile
/// (first-build behavior — same record-once rule as source hashes).
/// All entries are resolved before any is recorded: a failure on one input
/// leaves the lockfile untouched. Returns the number of pins recorded.
pub fn ensure_input_pins(
    inputs: &HashMap<String, PackageInput>,
    lock: &mut LockFile,
) -> miette::Result<usize> {
    let mut resolved = Vec::new();
    for (name, input) in inputs {
        if lock.inputs.contains_key(name) {
            continue;
        }
        resolved.push((name.clone(), lock_input_entry(input)?));
    }
    let n = resolved.len();
    for (name, entry) in resolved {
        lock.inputs.insert(name, entry);
    }
    Ok(n)
}

/// One applied input-pin refresh, for old→new reporting.
#[derive(Debug, Clone)]
pub struct InputPinUpdate {
    pub name: String,
    /// Revision before the refresh (`None` when newly pinned).
    pub old: Option<String>,
    /// Revision after the refresh (`None` for local, unlocked inputs).
    pub new: Option<String>,
    /// True for `path:` inputs (marker entry, no revision).
    pub local: bool,
}

/// Re-resolve inputs to their latest revision and update their pins.
/// Empty `names` updates all declared inputs. Every pin is resolved before
/// any is written: a failure on one input (e.g. network down mid-loop)
/// leaves the lockfile exactly as it was — never a half-updated lock.
/// Returns one [`InputPinUpdate`] per refreshed input.
pub fn update_input_pins(
    inputs: &HashMap<String, PackageInput>,
    names: &[&str],
    lock: &mut LockFile,
) -> miette::Result<Vec<InputPinUpdate>> {
    for name in names {
        if !inputs.contains_key(*name) {
            let declared: Vec<&str> = inputs.keys().map(|s| s.as_str()).collect();
            return Err(miette::miette!(
                "input '{name}' is not declared (declared: {})",
                declared.join(", ")
            ));
        }
    }
    let mut resolved = Vec::new();
    for (name, input) in inputs {
        if !names.is_empty() && !names.contains(&name.as_str()) {
            continue;
        }
        resolved.push((name.clone(), lock_input_entry(input)?));
    }
    let mut updates = Vec::new();
    for (name, entry) in resolved {
        let old = lock.inputs.get(&name).and_then(|e| e.revision.clone());
        let new = entry.revision.clone();
        let local = entry.local;
        lock.inputs.insert(name.clone(), entry);
        updates.push(InputPinUpdate {
            name,
            old,
            new,
            local,
        });
    }
    Ok(updates)
}

// ── Global input state (re-initializable) ──

static GLOBAL_PATHS: Mutex<Option<HashMap<String, PathBuf>>> = Mutex::new(None);

/// Initialize global package source paths from a set of inputs.
///
/// Called during `shuttle build` / `shuttle deps` / etc. before any package
/// resolution. If `inputs` is empty, the default input
/// (`github:rbelem/shuttle/main`) is used. This can be called multiple times —
/// later calls override earlier ones (e.g. when a config file specifies inputs).
pub fn init_global_inputs(inputs: &HashMap<String, PackageInput>) -> miette::Result<()> {
    init_global_inputs_with(inputs, &HashMap::new(), false)
}

/// Like [`init_global_inputs`], but resolves each github input through its
/// lockfile pin and refuses to fetch when `offline` is set.
pub fn init_global_inputs_with(
    inputs: &HashMap<String, PackageInput>,
    lock_inputs: &HashMap<String, InputLockEntry>,
    offline: bool,
) -> miette::Result<()> {
    let paths = if inputs.is_empty() {
        let default = PackageInput {
            url: DEFAULT_INPUT_URL.to_string(),
        };
        let mut m = HashMap::new();
        m.insert(
            DEFAULT_INPUT_NAME.to_string(),
            resolve_input_with(&default, lock_inputs.get(DEFAULT_INPUT_NAME), offline)?,
        );
        m
    } else {
        let mut result = HashMap::new();
        for (name, input) in inputs {
            let path = resolve_input_with(input, lock_inputs.get(name), offline)?;
            result.insert(name.clone(), path);
        }
        result
    };

    let mut guard = GLOBAL_PATHS
        .lock()
        .map_err(|e| miette::miette!("global paths lock poisoned: {e}"))?;
    *guard = Some(paths);
    Ok(())
}

/// Resolve a HashMap of inputs to their local paths.
pub fn resolve_global_inputs(
    inputs: &HashMap<String, PackageInput>,
) -> miette::Result<HashMap<String, PathBuf>> {
    let mut result = HashMap::new();
    for (name, input) in inputs {
        let path = resolve_input(input)?;
        result.insert(name.clone(), path);
    }
    Ok(result)
}

/// Get the resolved global input paths (returns empty map if not initialized).
fn global_pkgs_paths() -> HashMap<String, PathBuf> {
    GLOBAL_PATHS
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_default()
}

/// Directories of the initialized global input sources.
///
/// These are the allowlisted roots the eval subprocess resolver may serve
/// `require()` requests from (see `crate::isolate::SourceResolver`).
pub fn resolver_roots() -> Vec<PathBuf> {
    global_pkgs_paths().into_values().collect()
}

// ── Package resolution ──

/// Result of resolving a package.
#[derive(Debug)]
pub enum PkgResult {
    /// File exists on disk at this path.
    File(String),
    /// Package found in an input source.
    Found {
        /// Path to the .lua file (for display).
        path: String,
        /// The Lua source content.
        content: String,
    },
    /// Not found anywhere.
    NotFound,
}

/// Try to find a package's Lua source by name.
///
/// Resolution order:
/// 1. If `name` is a direct filesystem path, return it.
/// 2. Check local `pkgs/<letter>/<name>.lua` (and `/init.lua`).
/// 3. Check each initialized global input source's `pkgs/` directory.
pub fn resolve_pkg(name: &str) -> PkgResult {
    // 1. Direct path
    if Path::new(name).exists() {
        return PkgResult::File(name.to_string());
    }

    let first = name.chars().next().unwrap_or('x').to_ascii_lowercase();
    let pkg_base = format!("pkgs/{first}");

    // 2. Local working directory pkgs/
    let single = format!("{pkg_base}/{name}.lua");
    if Path::new(&single).exists() {
        return PkgResult::File(single);
    }
    let dir_pkg = format!("{pkg_base}/{name}/init.lua");
    if Path::new(&dir_pkg).exists() {
        return PkgResult::File(dir_pkg);
    }

    // 3. Global input sources
    for path in global_pkgs_paths().values() {
        let input_single = path.join(&single);
        if input_single.exists() {
            let content = std::fs::read_to_string(&input_single).unwrap_or_default();
            return PkgResult::Found {
                path: input_single.to_string_lossy().to_string(),
                content,
            };
        }
        let input_dir = path.join(&dir_pkg);
        if input_dir.exists() {
            let content = std::fs::read_to_string(&input_dir).unwrap_or_default();
            return PkgResult::Found {
                path: input_dir.to_string_lossy().to_string(),
                content,
            };
        }
    }

    PkgResult::NotFound
}

/// Materialize an embedded package's source into a fresh, unpredictable,
/// private temp dir and return the definition path inside it.
///
/// Security (resolver-root containment): the returned definition path
/// doubles as the eval/check stages' resolver entry, and
/// `SourceResolver::for_build` allowlists the entry file's parent — so the
/// write target determines the whole require() attack surface. The old
/// predictable, world-writable `$TMPDIR/shuttle-<name>.lua` made that root
/// `/tmp` itself, letting `require("anything")` read any `/tmp/*.lua` into
/// eval. Here the tempdir is fresh and mode 0700 (created by `tempfile`),
/// and the definition is created with `create_new` so a pre-planted symlink
/// can never be followed — the resolver root becomes this invocation's
/// private directory ONLY, never `/tmp`.
///
/// The tempdir handle is kept alive for the process lifetime: dropping it
/// would unlink the definition out from under the eval/check stages.
pub fn materialize_embedded(content: &str) -> miette::Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create embedded-package temp dir: {e}"))?;
    let path = dir.path().join("shuttle.lua");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| miette::miette!("failed to create {}: {e}", path.display()))?;
    f.write_all(content.as_bytes())
        .map_err(|e| miette::miette!("failed to write {}: {e}", path.display()))?;

    EMBEDDED_TEMPDIRS
        .lock()
        .map_err(|e| miette::miette!("embedded temp dir registry poisoned: {e}"))?
        .push(dir);
    Ok(path)
}

/// Embedded-package materializations kept alive for the process lifetime
/// (see [`materialize_embedded`]).
static EMBEDDED_TEMPDIRS: Mutex<Vec<tempfile::TempDir>> = Mutex::new(Vec::new());

/// Resolve a package name to a filesystem path (for non-Lua resolution).
/// Follows the same lookup order as `resolve_pkg` but returns a path only,
/// without loading content.
pub fn resolve_path(name_or_path: &str) -> PathBuf {
    if name_or_path.contains('/') || name_or_path.ends_with(".lua") {
        return PathBuf::from(name_or_path);
    }

    let first = name_or_path
        .chars()
        .next()
        .unwrap_or('x')
        .to_ascii_lowercase();
    let pkg_base = PathBuf::from("pkgs").join(first.to_string());

    let single = pkg_base.join(format!("{name_or_path}.lua"));
    if single.exists() {
        return single;
    }

    let dir_pkg = pkg_base.join(name_or_path).join("init.lua");
    if dir_pkg.exists() {
        return dir_pkg;
    }

    // Check input sources too
    for path in global_pkgs_paths().values() {
        let input_single = path.join(&single);
        if input_single.exists() {
            return input_single;
        }
        let input_dir = path.join(&dir_pkg);
        if input_dir.exists() {
            return input_dir;
        }
    }

    PathBuf::from(name_or_path)
}

/// Iterate over all available package names from all sources.
/// Used by `shuttle search`.
pub fn iter_packages() -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut names = Vec::new();

    // Local pkgs/ directory
    let fs_base = Path::new("pkgs");
    if fs_base.exists() {
        if let Ok(entries) = std::fs::read_dir(fs_base) {
            for entry in entries.flatten() {
                let letter = entry.path();
                if !letter.is_dir() {
                    continue;
                }
                if let Ok(files) = std::fs::read_dir(&letter) {
                    for file in files.flatten() {
                        let path = file.path();
                        let name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        if seen.insert(name.clone()) {
                            names.push(name);
                        }
                    }
                }
            }
        }
    }

    // Input sources pkgs/ directories
    for path in global_pkgs_paths().values() {
        let input_pkgs = path.join("pkgs");
        if !input_pkgs.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&input_pkgs) {
            for entry in entries.flatten() {
                let letter = entry.path();
                if !letter.is_dir() {
                    continue;
                }
                if let Ok(files) = std::fs::read_dir(&letter) {
                    for file in files.flatten() {
                        let path = file.path();
                        let name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_string();
                        if seen.insert(name.clone()) {
                            names.push(name);
                        }
                    }
                }
            }
        }
    }

    names
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex_known() {
        let hash = sha256_hex("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_resolve_path_local_pkgs() {
        // This test only works if a pkgs/ directory exists
        let gcc = resolve_path("gcc");
        assert!(
            gcc.to_string_lossy().ends_with("pkgs/g/gcc.lua")
                || gcc.to_string_lossy().ends_with("pkgs/g/gcc/init.lua")
                || gcc.to_string_lossy().ends_with("gcc"), // fallback
            "expected pkgs/g/gcc.lua or init.lua, got {gcc:?}"
        );
    }

    #[test]
    fn test_resolve_path_contains_slash() {
        let p = resolve_path("examples/full-system/system-base/shuttle.lua");
        assert!(p
            .to_string_lossy()
            .ends_with("examples/full-system/system-base/shuttle.lua"));
    }

    #[test]
    fn test_cache_root_contains_shuttle() {
        let root = cache_root();
        let s = root.to_string_lossy();
        assert!(s.contains(".cache/shuttle/inputs"));
    }

    #[test]
    fn test_resolve_input_invalid_url() {
        let input = PackageInput {
            url: "ftp://bad".into(),
        };
        let result = resolve_input(&input);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unsupported input URL scheme"),
            "expected unsupported scheme error, got: {err}"
        );
    }

    #[test]
    fn test_parse_github_url() {
        assert_eq!(parse_github_url("github:o/r"), Some(("o", "r", "HEAD")));
        assert_eq!(
            parse_github_url("github:o/r/main"),
            Some(("o", "r", "main"))
        );
        assert_eq!(parse_github_url("github:o"), None);
        assert_eq!(parse_github_url("path:/tmp"), None);
    }

    #[test]
    fn test_content_hash_stable_and_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();

        let h1 = content_hash(dir.path()).unwrap();
        assert_eq!(h1, content_hash(dir.path()).unwrap(), "hash must be stable");

        std::fs::write(dir.path().join("a.txt"), b"world").unwrap();
        let h2 = content_hash(dir.path()).unwrap();
        assert_ne!(h1, h2, "content change must change the hash");

        // .git is excluded from the hash
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), b"anything").unwrap();
        assert_eq!(h2, content_hash(dir.path()).unwrap());

        // path changes change the hash
        std::fs::write(dir.path().join("b.txt"), b"hello").unwrap();
        assert_ne!(h2, content_hash(dir.path()).unwrap());
    }

    #[test]
    fn test_pinned_cache_dir_differs_from_branch_dir() {
        let branch = github_cache_dir("o", "r", "main");
        let pinned = pinned_cache_dir("o", "r", "abc123");
        let pinned2 = pinned_cache_dir("o", "r", "def456");
        assert_ne!(branch, pinned);
        assert_ne!(pinned, pinned2);
        // Same key → same dir
        assert_eq!(pinned, pinned_cache_dir("o", "r", "abc123"));
    }

    #[test]
    fn test_offline_uncached_input_errors() {
        let input = PackageInput {
            url: "github:shuttle-test-nonexistent-xyz/nope".into(),
        };
        let err = resolve_input_with(&input, None, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline"), "got: {err}");
    }

    #[test]
    fn test_resolve_input_local_with_pin() {
        let dir = tempfile::tempdir().unwrap();
        let input = PackageInput {
            url: format!("path:{}", dir.path().display()),
        };
        let pin = InputLockEntry {
            revision: None,
            sha256: None,
            local: true,
        };
        // Even offline, local inputs resolve; pins are markers only.
        let p = resolve_input_with(&input, Some(&pin), true).unwrap();
        assert_eq!(p, dir.path());
    }

    #[test]
    fn test_update_input_pins_unknown_name() {
        let mut inputs = HashMap::new();
        inputs.insert(
            "packages".to_string(),
            PackageInput {
                url: "path:/tmp".into(),
            },
        );
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };
        let err = update_input_pins(&inputs, &["nope"], &mut lock)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not declared"), "got: {err}");
    }

    #[test]
    fn test_update_and_ensure_input_pins_local() {
        let dir = tempfile::tempdir().unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            "local".to_string(),
            PackageInput {
                url: format!("path:{}", dir.path().display()),
            },
        );
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };

        // ensure records the local marker once
        let n = ensure_input_pins(&inputs, &mut lock).unwrap();
        assert_eq!(n, 1);
        assert!(lock.inputs["local"].local);

        // second ensure is a no-op (record-once)
        let n = ensure_input_pins(&inputs, &mut lock).unwrap();
        assert_eq!(n, 0);

        // update forces a refresh of the entry
        let updates = update_input_pins(&inputs, &[], &mut lock).unwrap();
        assert_eq!(updates.len(), 1);
        assert!(updates[0].local);
        assert!(updates[0].old.is_none() && updates[0].new.is_none());
        assert!(lock.inputs["local"].local);
    }

    /// Seed a fake pinned input tree under a test cache root and pin it.
    fn seed_pinned(
        root: &Path,
        owner: &str,
        repo: &str,
        sha: &str,
        body: &[u8],
    ) -> (PackageInput, InputLockEntry) {
        let dir = pinned_cache_dir_in(root, owner, repo, sha);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pkgs.lua"), body).unwrap();
        let entry = InputLockEntry {
            revision: Some(sha.to_string()),
            sha256: Some(content_hash(&dir).unwrap()),
            local: false,
        };
        (
            PackageInput {
                url: format!("github:{owner}/{repo}/main"),
            },
            entry,
        )
    }

    #[test]
    fn test_pinned_input_roundtrip_and_hash_verified() {
        let root = tempfile::tempdir().unwrap();
        let (input, pin) = seed_pinned(
            root.path(),
            "shuttle-test-fixture",
            "roundtrip",
            "1111111111111111111111111111111111111111",
            b"contents",
        );

        // Pinned + cache present + hash matches → resolves to the pinned dir.
        let resolved = resolve_input_in(root.path(), &input, Some(&pin), false).unwrap();
        assert_eq!(
            resolved,
            pinned_cache_dir_in(
                root.path(),
                "shuttle-test-fixture",
                "roundtrip",
                "1111111111111111111111111111111111111111"
            )
        );
    }

    #[test]
    fn test_pinned_input_mismatch_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let (input, pin) = seed_pinned(
            root.path(),
            "shuttle-test-fixture",
            "tampered",
            "2222222222222222222222222222222222222222",
            b"original",
        );

        // Tamper with the cached tree after locking.
        let dir = pinned_cache_dir_in(
            root.path(),
            "shuttle-test-fixture",
            "tampered",
            "2222222222222222222222222222222222222222",
        );
        std::fs::write(dir.join("pkgs.lua"), b"tampered").unwrap();

        let err = resolve_input_in(root.path(), &input, Some(&pin), false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("content changed since lock"),
            "named mismatch error required, got: {err}"
        );
        assert!(
            err.contains("shuttle build --update"),
            "error must point at the refresh path, got: {err}"
        );
    }

    #[test]
    fn test_offline_pinned_input_absent_no_fetch_no_dirs() {
        let root = tempfile::tempdir().unwrap();
        // Pin exists in the lockfile, but the pinned cache dir is absent —
        // exactly the "inputs absent from cache" offline scenario.
        let input = PackageInput {
            url: "github:shuttle-test-fixture/absent/main".into(),
        };
        let pin = InputLockEntry {
            revision: Some("3333333333333333333333333333333333333333".to_string()),
            sha256: Some("deadbeef".to_string()),
            local: false,
        };

        let err = resolve_input_in(root.path(), &input, Some(&pin), true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("pinned to 3333333333333333333333333333333333333333")
                && err.contains("--offline prevents fetching"),
            "named offline error required, got: {err}"
        );

        // No fetch may have been attempted: the cache root must still be empty.
        let created: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            created.is_empty(),
            "offline mode must not create cache dirs (no fetch), found: {created:?}"
        );
    }

    #[test]
    fn test_update_input_pins_all_or_nothing_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            "good".to_string(),
            PackageInput {
                url: format!("path:{}", dir.path().display()),
            },
        );
        inputs.insert(
            "bad".to_string(),
            PackageInput {
                url: "ftp://not-supported".into(),
            },
        );

        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };
        // Pre-pin "good" with a revision that a path: refresh would change
        // (path entries carry no revision), so partial application is observable.
        lock.inputs.insert(
            "good".to_string(),
            InputLockEntry {
                revision: Some("oldrev".to_string()),
                sha256: None,
                local: false,
            },
        );

        assert!(update_input_pins(&inputs, &[], &mut lock).is_err());
        // The lockfile map is exactly as before: "good" not re-resolved,
        // "bad" never inserted. All-or-nothing.
        assert_eq!(lock.inputs.len(), 1);
        assert_eq!(lock.inputs["good"].revision.as_deref(), Some("oldrev"));
        assert!(!lock.inputs.contains_key("bad"));
    }

    #[test]
    fn test_update_input_pins_reports_old_to_new() {
        let dir = tempfile::tempdir().unwrap();
        let mut inputs = HashMap::new();
        inputs.insert(
            "pkg".to_string(),
            PackageInput {
                url: format!("path:{}", dir.path().display()),
            },
        );
        let mut lock = LockFile {
            version: 1,
            sources: HashMap::new(),
            snaps: HashMap::new(),
            inputs: HashMap::new(),
        };

        // First update: new pin (old = None).
        let updates = update_input_pins(&inputs, &["pkg"], &mut lock).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "pkg");
        assert!(updates[0].old.is_none(), "fresh pin has no old revision");
    }
}
