//! Content-addressed source cache (ADR-0048 Phase 2) — store/lookup
//! contract: the `<root>/<sha256[0:2]>/<sha256>` layout, digest-on-read
//! serving with eviction of corrupted entries, tmp-then-rename staging
//! with no litter on failure, and idempotent concurrent stores.

use std::path::Path;

use nau::source_cache;

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(bytes);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// A source file plus its pin (the digest its bytes hash to).
fn pinned_source(dir: &Path, name: &str, bytes: &[u8]) -> (std::path::PathBuf, String) {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    (path, sha256_hex(bytes))
}

#[test]
fn store_then_lookup_serves_byte_identical_bytes() {
    let root = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let bytes = b"pinned tarball bytes\nsecond line\n";
    let (source, pin) = pinned_source(work.path(), "src.tar.gz", bytes);

    let entry = source_cache::store(root.path(), &source, &pin).unwrap();

    // The entry lands at the documented layout: <root>/<sha[0:2]>/<sha>.
    assert_eq!(
        entry,
        root.path().join(&pin[..2]).join(&pin),
        "entry must be sharded by the pin's first two hex digits"
    );
    assert_eq!(std::fs::read(&entry).unwrap(), bytes);

    // Lookup serves the same path, and the served bytes re-hash to the
    // pin (digest-on-read is the module's own contract — re-checked
    // here so a regression to existence-only serving is caught).
    let served = source_cache::lookup(root.path(), &pin).unwrap();
    assert_eq!(served, entry);
    assert_eq!(sha256_hex(&std::fs::read(&served).unwrap()), pin);
}

#[test]
fn lookup_misses_on_an_empty_root() {
    let root = tempfile::tempdir().unwrap();
    let pin = sha256_hex(b"never stored");
    assert!(source_cache::lookup(root.path(), &pin).is_none());
}

#[test]
fn lookup_evicts_a_corrupted_entry_and_returns_none() {
    let root = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let bytes = b"good bytes, later corrupted in place";
    let (source, pin) = pinned_source(work.path(), "src.tar.gz", bytes);
    let entry = source_cache::store(root.path(), &source, &pin).unwrap();

    // Corrupt the entry the way a torn write would: truncate, then a
    // full overwrite with different bytes.
    let corrupted: Vec<u8> = bytes[..bytes.len() / 2].to_vec();
    std::fs::write(&entry, &corrupted).unwrap();
    assert!(source_cache::lookup(root.path(), &pin).is_none());
    assert!(!entry.exists(), "a mismatched entry must be evicted");

    std::fs::write(&entry, b"totally different bytes").unwrap();
    assert!(source_cache::lookup(root.path(), &pin).is_none());
    assert!(!entry.exists(), "overwritten entry evicted too");
}

#[test]
fn failed_store_leaves_no_tmp_litter() {
    let root = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();

    // The tmp's digest is re-verified against the key before the
    // rename, so storing bytes that do NOT hash to the pin must fail
    // and leave no <sha>.tmp sibling behind.
    let (source, _real_pin) = pinned_source(work.path(), "src.tar.gz", b"bytes of a different pin");
    let pin = sha256_hex(b"expected bytes that were never stored");

    assert!(source_cache::store(root.path(), &source, &pin).is_err());
    let shard = root.path().join(&pin[..2]);
    assert!(
        shard.read_dir().map(|mut d| d.next().is_none()).unwrap(),
        "a failed store must leave the shard empty: no tmp, no entry"
    );
    assert!(!shard.join(format!("{pin}.tmp")).exists());
}

#[test]
fn store_over_an_existing_entry_does_not_error() {
    let root = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let bytes = b"same pin, stored twice (concurrent-ish race)";
    let (source, pin) = pinned_source(work.path(), "src.tar.gz", bytes);

    let first = source_cache::store(root.path(), &source, &pin).unwrap();
    // Last-writer-wins: the rename over an existing entry is a normal
    // overwrite, not a failure.
    let second = source_cache::store(root.path(), &source, &pin).unwrap();
    assert_eq!(first, second);
    assert_eq!(std::fs::read(&second).unwrap(), bytes);
    assert!(source_cache::lookup(root.path(), &pin).is_some());
}

#[test]
fn non_digest_keys_never_address_the_filesystem() {
    let root = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let (source, _pin) = pinned_source(work.path(), "src.tar.gz", b"payload");

    // A crafted "pin" must not escape the cache root (the key rides
    // into path components): short, traversal, and wrong-alphabet keys
    // are a miss on read and a refusal on write.
    for bad in ["", "a", "../../escape", "ABCDEFGH", &"x".repeat(64)] {
        assert!(source_cache::lookup(root.path(), bad).is_none(), "{bad:?}");
        assert!(
            source_cache::store(root.path(), &source, bad).is_err(),
            "{bad:?}"
        );
    }
    // Nothing was written outside or inside the root.
    assert!(root.path().read_dir().unwrap().next().is_none());
}
