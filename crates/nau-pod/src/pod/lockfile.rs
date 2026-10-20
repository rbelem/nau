//! Pod lockfile discovery (issue #3): which name a pod's lockfile
//! carries, and where a read finds it.
//!
//! `nau.lock` is the canonical name every write produces
//! ([`LockFile::FILENAME`]). Pods created before the shuttle to nau
//! rename (ADR-0031) still carry `shuttle.lock` on disk, and no write
//! has touched most of them since, so their pins live only under the
//! old name. Reads therefore honour either name; writes stay canonical.
//!
//! Why not migrate on read. A read verb must not mutate pod state
//! (`pod list` on an unknown pod is an error, not a bootstrap), and a
//! rename during a read races every concurrent reader into a spurious
//! "failed to read" between `exists` and `read`. Accepting the old
//! name is pure. Migration still happens, safely, on the next write: a
//! write loads through [`load_pod_lock`] (so no legacy pin is dropped),
//! and saves to [`pod_lock_path`], after which the canonical file
//! exists and wins. The stale legacy file is left in place — deleting
//! pod state is not this module's call.

use std::path::{Path, PathBuf};

use nau_core::lock::LockFile;

/// The pre-rename lockfile name (ADR-0031). Read-only: no write path
/// produces it.
const LEGACY_LOCK_FILE: &str = "shuttle.lock";

/// Path to a pod's canonical lockfile. This is the WRITE target; reads
/// go through [`load_pod_lock`] so a pre-rename pod's pins are seen.
pub fn pod_lock_path(root: &Path, pod_name: &str) -> PathBuf {
    nau_core::paths::pod_dir(root, pod_name).join(LockFile::FILENAME)
}

/// Path a read takes for a pod's lockfile: the canonical name when it
/// exists, else the pre-rename `shuttle.lock` when that exists, else
/// the canonical path (which [`LockFile::load`] reports as absent).
///
/// Canonical wins when both are present. A pod carrying both was
/// written after the rename, and that write serialized the whole lock
/// from the legacy one, so the canonical file is the complete, newer
/// record; the legacy file is a leftover.
pub fn pod_lock_read_path(root: &Path, pod_name: &str) -> PathBuf {
    let canonical = pod_lock_path(root, pod_name);
    if canonical.exists() {
        return canonical;
    }
    let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
    if legacy.exists() {
        return legacy;
    }
    canonical
}

/// Load a pod's lockfile, honouring a pre-rename `shuttle.lock`.
/// `Ok(None)` means the pod has no lockfile under either name.
pub fn load_pod_lock(root: &Path, pod_name: &str) -> miette::Result<Option<LockFile>> {
    LockFile::load(&pod_lock_read_path(root, pod_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pod directory plus its canonical lockfile path (unwritten).
    fn seed(root: &Path, pod: &str) -> PathBuf {
        let dir = nau_core::paths::pod_dir(root, pod);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(LockFile::FILENAME)
    }

    fn lock_with(version: &str) -> LockFile {
        let mut lock = LockFile::empty();
        lock.packages.insert(
            "gcc".into(),
            nau_core::lock::PodPackageLockEntry {
                version: version.into(),
                constraint: None,
                deps: None,
                recipe_sha256: None,
                recipe_digest_scheme: None,
            },
        );
        lock
    }

    #[test]
    fn legacy_shuttle_lock_is_read_when_canonical_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
        lock_with("14.2.0").save(&legacy).unwrap();

        assert_eq!(pod_lock_read_path(tmp.path(), "gate"), legacy);
        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "14.2.0");
    }

    #[test]
    fn canonical_wins_when_both_names_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        lock_with("16.2.0").save(&canonical).unwrap();
        lock_with("14.2.0")
            .save(&canonical.with_file_name(LEGACY_LOCK_FILE))
            .unwrap();

        assert_eq!(pod_lock_read_path(tmp.path(), "gate"), canonical);
        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "16.2.0");
    }

    #[test]
    fn no_lockfile_under_either_name_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        assert!(!canonical.exists());
        assert_eq!(pod_lock_read_path(tmp.path(), "gate"), canonical);
        assert!(load_pod_lock(tmp.path(), "gate").unwrap().is_none());
    }

    #[test]
    fn legacy_pin_survives_a_canonical_write() {
        // The migration is the next write: load through the resolver,
        // save to the canonical path, and the pin set is preserved.
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        lock_with("14.2.0")
            .save(&canonical.with_file_name(LEGACY_LOCK_FILE))
            .unwrap();

        let mut lock = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        lock.packages.insert(
            "rust".into(),
            nau_core::lock::PodPackageLockEntry {
                version: "1.97.1".into(),
                constraint: None,
                deps: None,
                recipe_sha256: None,
                recipe_digest_scheme: None,
            },
        );
        lock.save(&pod_lock_path(tmp.path(), "gate")).unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "14.2.0");
        assert_eq!(loaded.packages["rust"].version, "1.97.1");
    }
}
