//! Embedded package definitions and default index.
//!
//! The entire `pkgs/` directory tree and the default `package-index.json` are
//! compiled into the binary via `rust-embed`. This lets `shoot` resolve and
//! build packages without a local clone of the repo.
//!
//! Filesystem wins over embedded — if `pkgs/<letter>/<name>.lua` exists on
//! disk, it's used instead of the embedded copy. This allows users to override
//! individual packages or add custom ones.
//!
//! Usage:
//! ```rust,ignore
//! // Check if a package is embedded
//! if let Some(content) = Pkgs::get("g/gcc.lua") {
//!     let src = std::str::from_utf8(content.data.as_ref()).unwrap();
//! }
//! ```

use std::path::Path;

use rust_embed::RustEmbed;

/// Embedded `pkgs/` directory — all package `.lua` files at compile time.
#[derive(RustEmbed)]
#[folder = "pkgs/"]
pub struct Pkgs;

// Default index entries are in `index.rs::default_entries()` — no separate
// file needed since they're already compiled into the binary.

/// Result of resolving a package: either found on the filesystem or embedded.
pub enum PkgResult {
    /// File exists on disk at this path.
    File(String),
    /// Package is embedded — use the content directly.
    Embedded {
        /// Relative path within pkgs/ (e.g. "g/gcc.lua").
        path: String,
        /// Raw Lua source.
        content: String,
    },
    /// Not found anywhere.
    NotFound,
}

/// Try to find a package's Lua source by name.
///
/// Resolution order:
/// 1. If `name` is a filesystem path that exists, return `File(path)`.
/// 2. Resolve through pkgs/<letter>/<name>.lua (and /init.lua), check filesystem.
/// 3. Fall back to embedded pkgs/ store.
/// 4. Return NotFound.
pub fn resolve_pkg(name: &str) -> PkgResult {
    // 1. Check if the raw name is an existing file path
    if Path::new(name).exists() {
        return PkgResult::File(name.to_string());
    }

    // 2. Check if it's a name like "bash" → try pkgs/b/bash.lua on disk
    let first = name.chars().next().unwrap_or('x').to_ascii_lowercase();
    let pkg_base = format!("pkgs/{}", first);

    let single = format!("{}/{}.lua", pkg_base, name);
    if Path::new(&single).exists() {
        return PkgResult::File(single);
    }

    let dir_pkg = format!("{}/{}/init.lua", pkg_base, name);
    if Path::new(&dir_pkg).exists() {
        return PkgResult::File(dir_pkg);
    }

    // 3. Check embedded pkgs/ store
    // rust-embed paths are relative to the pkgs/ folder
    let embedded_path = format!("{}/{}.lua", first, name);
    if let Some(file) = Pkgs::get(&embedded_path) {
        let content = std::str::from_utf8(file.data.as_ref())
            .unwrap_or("")
            .to_string();
        return PkgResult::Embedded {
            path: embedded_path,
            content,
        };
    }

    // Try embedded directory package (pkgs/<letter>/<name>/init.lua)
    let embedded_dir = format!("{}/{}/init.lua", first, name);
    if let Some(file) = Pkgs::get(&embedded_dir) {
        let content = std::str::from_utf8(file.data.as_ref())
            .unwrap_or("")
            .to_string();
        return PkgResult::Embedded {
            path: embedded_dir,
            content,
        };
    }

    PkgResult::NotFound
}
