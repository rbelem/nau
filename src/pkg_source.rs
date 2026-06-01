//! Package source resolution — fetch package definitions from declared inputs.
//!
//! Inspired by Nix flake inputs, shoot supports:
//! - `github:user/repo[/branch]` — shallow clone from GitHub
//! - `path:/local/directory`     — local filesystem path
//!
//! Global inputs (declared at the top of `shoot.lua` before the return statement)
//! power the package index. Per-snap inputs declare additional sources.
//!
//! GitHub URLs are cached in `~/.cache/shoot/inputs/<hash>/` after a shallow
//! clone. Local paths are used directly. If no inputs are configured, a default
//! input (`github:rbelem/shoot/main`) is used as fallback so `shoot build <pkg>`
//! works out of the box.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
const DEFAULT_INPUT_URL: &str = "github:rbelem/shoot/main";

/// Default input name for the fallback.
pub const DEFAULT_INPUT_NAME: &str = "packages";

/// Home-directory cache root for fetched inputs.
fn cache_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".cache/shoot/inputs")
}

/// Cache directory for a given github: URL.
fn github_cache_dir(owner: &str, repo: &str, branch: &str) -> PathBuf {
    let key = format!("github:{owner}/{repo}/{branch}");
    let hash = sha256_hex(&key);
    cache_root().join(&hash[..16])
}

// ── Input resolution ──

/// Resolve a single input URL to a local filesystem path containing `pkgs/`.
///
/// For `github:` URLs, this fetches (or uses cached) the repo.
/// For `path:` URLs, this strips the prefix and verifies the path.
pub fn resolve_input(input: &PackageInput) -> miette::Result<PathBuf> {
    let url = &input.url;

    if let Some(local) = url.strip_prefix("path:") {
        let p = PathBuf::from(local);
        if !p.exists() {
            return Err(miette::miette!(
                "local input path '{}' does not exist",
                p.display()
            ));
        }
        Ok(p)
    } else if let Some(github) = url.strip_prefix("github:") {
        let parts: Vec<&str> = github.split('/').collect();
        if parts.len() < 2 {
            return Err(miette::miette!(
                "invalid github input URL '{url}': expected 'github:owner/repo[/branch]'"
            ));
        }
        let owner = parts[0];
        let repo = parts[1];
        let branch = if parts.len() > 2 { parts[2] } else { "HEAD" };

        let cache_dir = github_cache_dir(owner, repo, branch);

        if !cache_dir.exists() {
            fetch_github(owner, repo, branch, &cache_dir)?;
        }

        Ok(cache_dir)
    } else {
        Err(miette::miette!(
            "unsupported input URL scheme in '{url}' (expected 'github:...' or 'path:...')"
        ))
    }
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

/// Re-fetch a cached GitHub input (for `shoot index update`).
pub fn refresh_input(input: &PackageInput) -> miette::Result<()> {
    let url = &input.url;
    if let Some(github) = url.strip_prefix("github:") {
        let parts: Vec<&str> = github.split('/').collect();
        if parts.len() < 2 {
            return Err(miette::miette!("invalid github URL '{url}'"));
        }
        let owner = parts[0];
        let repo = parts[1];
        let branch = if parts.len() > 2 { parts[2] } else { "HEAD" };
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

// ── Global input state (re-initializable) ──

static GLOBAL_PATHS: Mutex<Option<HashMap<String, PathBuf>>> = Mutex::new(None);

/// Initialize global package source paths from a set of inputs.
///
/// Called during `shoot build` / `shoot deps` / etc. before any package
/// resolution. If `inputs` is empty, the default input
/// (`github:rbelem/shoot/main`) is used. This can be called multiple times —
/// later calls override earlier ones (e.g. when a config file specifies inputs).
pub fn init_global_inputs(inputs: &HashMap<String, PackageInput>) -> miette::Result<()> {
    let paths = if inputs.is_empty() {
        let default = PackageInput {
            url: DEFAULT_INPUT_URL.to_string(),
        };
        let mut m = HashMap::new();
        m.insert(DEFAULT_INPUT_NAME.to_string(), resolve_input(&default)?);
        m
    } else {
        resolve_global_inputs(inputs)?
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
/// Used by `shoot search`.
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
        let p = resolve_path("examples/full-system/system-base/shoot.lua");
        assert!(p
            .to_string_lossy()
            .ends_with("examples/full-system/system-base/shoot.lua"));
    }

    #[test]
    fn test_cache_root_contains_shoot() {
        let root = cache_root();
        let s = root.to_string_lossy();
        assert!(s.contains(".cache/shoot/inputs"));
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
}
