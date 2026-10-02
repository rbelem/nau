//! Content-addressed blob store (`store/<aa>/<sha256>`) — the on-disk
//! layout knowledge for pod-store content blobs, shared by the runtime
//! store and the chart dependency fetcher (ADR-0051 Decision 3).
//!
//! `RuntimeStore` delegates its `blob_path` here (no duplicated layout),
//! and `dep_fetch` writes closure blobs through [`BlobStore::write_blob`]
//! — the one seam that lets the chart crate materialize deps without
//! importing the runtime domain.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A content-addressed blob store rooted at `root` (the `store/` directory
/// itself, not the runtime root): blobs live at `<root>/<aa>/<sha256>`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Create a handle over the store directory `root`.
    pub fn new(root: PathBuf) -> Self {
        BlobStore { root }
    }

    /// Path of the content blob with hash `sha256` (`<root>/<aa>/<sha>`).
    pub fn blob_path(&self, sha256: &str) -> PathBuf {
        let (aa, _) = sha256.split_at(2.min(sha256.len()));
        self.root.join(aa).join(sha256)
    }

    /// The store root this handle was built over (the parent of the
    /// `<aa>` shard dirs) — the pull lane derives sibling layout paths
    /// (the manifest inbox) from it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `bytes` into the store content-addressed by their sha256
    /// (atomic: temp file + rename). Returns the hash. Idempotent: an
    /// already-present blob short-circuits.
    ///
    /// A completed write RECORDS the digest in the process-lifetime blob
    /// memo (`crate::blob_memo`): the bytes this call hashed are the
    /// exact bytes the rename installed at `path`, so a same-process
    /// verifier can trust the record and skip the re-read. The
    /// short-circuit arm records nothing — an existing file's bytes were
    /// never observed here.
    pub fn write_blob(&self, bytes: &[u8]) -> miette::Result<String> {
        use std::io::Write;

        let hash: String = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(bytes);
            digest.iter().map(|b| format!("{b:02x}")).collect()
        };
        let path = self.blob_path(&hash);
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
            let mut f = FileGuard::create(&tmp)?;
            f.write_all(bytes)
                .map_err(|e| miette::miette!("writing {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| miette::miette!("finalizing {}: {e}", path.display()))?;
        crate::blob_memo::record(&path, &hash);
        Ok(hash)
    }
}

/// Tiny create helper so the error context stays with the store vocabulary.
struct FileGuard(std::fs::File);

impl FileGuard {
    fn create(path: &Path) -> miette::Result<Self> {
        std::fs::File::create(path)
            .map(FileGuard)
            .map_err(|e| miette::miette!("creating {}: {e}", path.display()))
    }
}

impl Write for FileGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_path_pairs_the_prefix_dir() {
        let store = BlobStore::new(PathBuf::from("/p/store"));
        assert_eq!(
            store.blob_path("abcdef1234567890"),
            PathBuf::from("/p/store/ab/abcdef1234567890")
        );
    }

    #[test]
    fn write_blob_is_content_addressed_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path().to_path_buf());
        let h1 = store.write_blob(b"hello").unwrap();
        let h2 = store.write_blob(b"hello").unwrap();
        assert_eq!(h1, h2);
        assert!(store.blob_path(&h1).exists());
        let written = std::fs::read(store.blob_path(&h1)).unwrap();
        assert_eq!(written, b"hello");
        // A different payload lands at a different address.
        let h3 = store.write_blob(b"world").unwrap();
        assert_ne!(h1, h3);
    }
}
