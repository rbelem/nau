//! Content-addressed source cache — pinned sources only (ADR-0048
//! Phase 2).
//!
//! Layout: `~/.cache/nau/src/<sha256[0:2]>/<sha256>`. The key is the
//! recipe's expected content sha256, known before download for every
//! pinned source, so a hit replaces the network fetch outright.
//!
//! Write path: copy to a `<final>.tmp` sibling, re-verify the tmp's
//! digest against the key, then an atomic rename into place (the
//! `pkg_source.rs` clone-cache precedent). Read path: digest-on-read —
//! an entry is re-hashed before it is served, and a mismatched entry is
//! evicted and reported as a miss, never served (ADR-0024 posture:
//! content claims are re-hashed before trust is acquired).
//!
//! Eligibility is the caller's decision (`crate::snap`): only pinned,
//! non-floating sources consult the cache, in either direction. From
//! the build's point of view everything here is best-effort: a cache
//! I/O error is a miss, never a build failure.

use std::path::{Path, PathBuf};

use sha2::Digest;

/// Default cache root: `~/.cache/nau/src`, HOME resolved the same way
/// `PackageCache::new` resolves it.
pub fn default_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".cache").join("nau").join("src")
}

/// Whether `key` is a 64-char lowercase hex digest — the only entry
/// name this cache accepts. The key rides straight into path
/// components, so anything else (a crafted pin included) must never
/// address the filesystem: it is a miss on read and a refusal on write.
fn is_sha256_hex(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

/// Entry path and its `<final>.tmp` staging sibling for a digest, under
/// an explicit root.
fn entry_paths(root: &Path, sha256: &str) -> Option<(PathBuf, PathBuf)> {
    if !is_sha256_hex(sha256) {
        return None;
    }
    let shard = root.join(&sha256[..2]);
    Some((shard.join(sha256), shard.join(format!("{sha256}.tmp"))))
}

/// SHA-256 hex of a file's bytes, streamed; `None` when the file cannot
/// be read (a miss, by rule — the cache never becomes a failure mode).
fn sha256_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Some(hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// Serve a pinned source by its expected sha256, if a verified entry
/// exists.
///
/// Digest-on-read: the entry is re-hashed before it is trusted; a
/// mismatch evicts it (best-effort) and reports a miss. Any I/O failure
/// is also a miss — the caller falls through to the download.
pub fn lookup(root: &Path, expected_sha256: &str) -> Option<PathBuf> {
    let (entry, _) = entry_paths(root, expected_sha256)?;
    match sha256_file(&entry) {
        Some(h) if h == expected_sha256 => Some(entry),
        _ => {
            // Corrupted (e.g. torn by a killed writer) or unreadable:
            // never serve. Best-effort eviction; a racing remover's
            // ENOENT is fine.
            let _ = std::fs::remove_file(&entry);
            None
        }
    }
}

/// Store a verified source under its expected sha256.
///
/// Copies `source` to a `<final>.tmp` sibling, verifies the tmp's
/// digest against the key, then renames it into place. The rename is
/// atomic and last-writer-wins: a concurrent storer racing for the same
/// key is not an error (both wrote verified bytes). On any failure the
/// tmp is removed (no litter) and the error returned — callers treat
/// store as best-effort; it must never fail a build.
pub fn store(root: &Path, source: &Path, expected_sha256: &str) -> std::io::Result<PathBuf> {
    let (entry, tmp) = entry_paths(root, expected_sha256).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source cache key is not a sha256 hex digest",
        )
    })?;
    std::fs::create_dir_all(entry.parent().expect("shard parent always exists"))?;

    // Copy aside, then digest the tmp: a torn copy (the field-proven
    // partial-write corruption class) must never become a cache entry.
    let publish = std::fs::copy(source, &tmp).and_then(|_| match sha256_file(&tmp) {
        Some(h) if h == expected_sha256 => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "copied source digest does not match the pin",
        )),
    });
    match publish {
        Ok(()) => match std::fs::rename(&tmp, &entry) {
            Ok(()) => Ok(entry),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}
