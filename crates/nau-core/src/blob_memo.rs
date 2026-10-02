//! Process-lifetime memo of computed blob hashes — the "same bytes,
//! same process, same hash: hash once" seam (sync-speed plan item 6a).
//!
//! The CLI is one process per verb, so a process-lifetime map IS the
//! per-sync lifetime: entries record digests this process either
//! computed by hashing a file's CURRENT bytes or established by writing
//! those exact bytes itself ([`crate::blob_store::BlobStore::write_blob`]
//! records after the rename). Nothing else may insert, and any writer
//! that overwrites a recorded path must invalidate or re-record first —
//! the entries are provable only while the file is untouched.
//!
//! NOT a persistent cache: nothing crosses processes, nothing survives
//! the verb. Re-verification across syncs stays the #125/#116 contract.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::Digest;

static MEMO: std::sync::OnceLock<Mutex<HashMap<PathBuf, String>>> = std::sync::OnceLock::new();

fn memo() -> &'static Mutex<HashMap<PathBuf, String>> {
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The recorded computed digest for `path`, when this process already
/// established it. `None` never means "verified" — callers must hash.
pub fn lookup(path: &Path) -> Option<String> {
    memo()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(path)
        .cloned()
}

/// Record `hash` as this process's computed digest for `path`. Only for
/// callers that just hashed the file's current bytes or wrote the exact
/// digest preimage to `path` — a recorded entry is a proof, not a guess.
pub fn record(path: &Path, hash: &str) {
    memo()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(path.to_path_buf(), hash.to_string());
}

/// Drop the recorded entry for `path`: a writer about to (re)create the
/// file must call this BEFORE writing, so a later lookup can never
/// return the pre-overwrite digest.
pub fn invalidate(path: &Path) {
    memo()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(path);
}

/// Streaming SHA-256 of a file, hex-encoded, memoized: a path this
/// process already hashed (or wrote) returns the recorded digest without
/// a second read. Buffer and message shape match the other streaming
/// sha256 helpers (65_536-byte buffer).
pub fn memoized_sha256_file(path: &Path) -> miette::Result<String> {
    if let Some(hash) = lookup(path) {
        return Ok(hash);
    }
    let hash = sha256_file(path)?;
    record(path, &hash);
    Ok(hash)
}

/// Streaming SHA-256 of a file, hex-encoded (65_536-byte buffer).
fn sha256_file(path: &Path) -> miette::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open {}: {e}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
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
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Test seam: drop every entry. Tests stage disjoint tempdirs, so this
/// only ever clears a test's own records — never another test's state.
#[doc(hidden)]
pub fn clear_for_tests() {
    memo().lock().unwrap_or_else(|p| p.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The memo is a process-global; cargo runs this module's tests on
    /// parallel threads, and a concurrent `clear_for_tests()` wipes any
    /// in-flight assertion's records. Serialize the tests over the map.
    static MEMO_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn memoized_sha256_hashes_once_then_serves_the_record() {
        let _guard = MEMO_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"closure bytes").unwrap();
        let first = memoized_sha256_file(&path).unwrap();
        let second = memoized_sha256_file(&path).unwrap();
        assert_eq!(first, second);
        // The record IS the content hash: independent digest matches.
        let digest: String = sha2::Sha256::digest(b"closure bytes")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(first, digest);
        assert_eq!(lookup(&path).as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn invalidate_forces_a_fresh_hash_of_the_new_bytes() {
        let _guard = MEMO_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"v1").unwrap();
        let v1 = memoized_sha256_file(&path).unwrap();
        // Overwrite WITHOUT invalidating: the memo serves the stale
        // record — the documented writer obligation is invalidate-first.
        std::fs::write(&path, b"v2").unwrap();
        assert_eq!(memoized_sha256_file(&path).unwrap(), v1);
        // The writer-side contract: invalidate before the rewrite, then
        // the memo reflects the new bytes.
        invalidate(&path);
        let v2 = memoized_sha256_file(&path).unwrap();
        let digest: String = sha2::Sha256::digest(b"v2")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(v2, digest);
        assert_ne!(v1, v2);
    }

    #[test]
    fn missing_file_is_an_error_and_records_nothing() {
        let _guard = MEMO_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_for_tests();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent");
        assert!(memoized_sha256_file(&path).is_err());
        assert!(lookup(&path).is_none());
    }
}
