//! Pod lockfile discovery (issue #3): which name a pod's lockfile
//! carries, and where a read finds it.
//!
//! `nau.lock` is the canonical name every write produces
//! ([`LockFile::FILENAME`]). Pods created before the shuttle to nau
//! rename (ADR-0031) still carry `shuttle.lock` on disk, so their pins
//! live only under the old name.
//!
//! A pod can carry BOTH, and the canonical file is not necessarily the
//! complete record. A writer that had already learned the new name but
//! still read the old one started from an empty lock and saved only the
//! packages it had touched. Measured on this host (issue #20): the
//! `default` pod's canonical file holds 3 packages and its pre-rename
//! file holds 51.
//!
//! So a read takes both and merges them: the canonical file wins per
//! entry and the pre-rename file fills the gaps. Taking either file
//! whole drops the pins the other one holds.
//!
//! Why not migrate on read. A read verb must not mutate pod state
//! (`pod list` on an unknown pod is an error, not a bootstrap), and a
//! rename during a read races every concurrent reader into a spurious
//! "failed to read" between `exists` and `read`. Accepting the old
//! name is pure. Migration still happens, safely, on the next write: a
//! write loads through [`load_pod_lock`] (so no legacy pin is dropped)
//! and saves to [`pod_lock_path`], after which the canonical file holds
//! the whole set.
//!
//! The stale pre-rename file is left in place, and a removal retires it
//! (see [`remove_pod_pins`]): a merge-on-read resolver would otherwise
//! hand the removed package's pin back.

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

/// Load a pod's lockfile, honouring a pre-rename `shuttle.lock`.
///
/// Both names are read when both exist, and merged: the canonical file
/// wins per entry and the pre-rename file fills the gaps. `Ok(None)`
/// means the pod has no lockfile under either name.
pub fn load_pod_lock(root: &Path, pod_name: &str) -> miette::Result<Option<LockFile>> {
    let canonical = pod_lock_path(root, pod_name);
    let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
    match (LockFile::load(&canonical)?, LockFile::load(&legacy)?) {
        (Some(mut canonical), Some(legacy)) => {
            canonical.merge_missing_from(&legacy);
            Ok(Some(canonical))
        }
        (Some(canonical), None) => Ok(Some(canonical)),
        (None, Some(legacy)) => Ok(Some(legacy)),
        (None, None) => Ok(None),
    }
}

/// Drop a package's pins from a pod's lockfiles: the canonical file and
/// the pre-rename one, when it is there.
///
/// A removal has to reach both. The resolver merges the two names
/// (issue #20), so a package left in the pre-rename file would have its
/// pin handed back by the next read.
pub fn remove_pod_pins(root: &Path, pod_name: &str, package: &str) -> miette::Result<()> {
    let canonical_path = pod_lock_path(root, pod_name);
    if let Some(mut lock) = load_pod_lock(root, pod_name)? {
        lock.packages.remove(package);
        // A sideloaded package's blob pin goes with it (issue #116): a
        // stale `snaps` entry would hold a future re-add of the same
        // name from the collection at phantom content.
        lock.snaps.remove(package);
        lock.save(&canonical_path)?;
    }
    let legacy_path = canonical_path.with_file_name(LEGACY_LOCK_FILE);
    if let Some(mut legacy) = LockFile::load(&legacy_path)? {
        let had_package = legacy.packages.remove(package).is_some();
        let had_snap = legacy.snaps.remove(package).is_some();
        if had_package || had_snap {
            legacy.save(&legacy_path)?;
        }
    }
    Ok(())
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

    fn package(version: &str) -> nau_core::lock::PodPackageLockEntry {
        nau_core::lock::PodPackageLockEntry {
            version: version.to_string(),
            constraint: None,
            deps: None,
            recipe_sha256: None,
            recipe_digest_scheme: None,
        }
    }

    fn lock_with(version: &str) -> LockFile {
        let mut lock = LockFile::empty();
        lock.packages.insert("gcc".into(), package(version));
        lock
    }

    #[test]
    fn legacy_shuttle_lock_is_read_when_canonical_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
        lock_with("14.2.0").save(&legacy).unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "14.2.0");
    }

    #[test]
    fn canonical_lock_is_read_when_the_legacy_name_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        lock_with("16.2.0").save(&canonical).unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "16.2.0");
    }

    #[test]
    fn both_names_merge_with_the_canonical_winning_per_entry() {
        // The measured shape (issue #20): the canonical file is a strict
        // subset, so taking it whole drops the pins the legacy file holds.
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);

        let mut canonical_lock = lock_with("16.2.0");
        canonical_lock
            .packages
            .insert("rust".into(), package("1.97.1"));
        canonical_lock.save(&canonical).unwrap();

        let mut legacy_lock = lock_with("14.2.0");
        legacy_lock
            .packages
            .insert("ripgrep".into(), package("15.2.0"));
        legacy_lock.snaps.insert(
            "toolchain".into(),
            nau_core::lock::SnapLockEntry {
                revision: 0,
                sha3_384: "abc".into(),
            },
        );
        legacy_lock.build_deps.insert(
            "bison".into(),
            nau_core::lock::BuildDepsLockEntry {
                pin: Some("3.8.2".into()),
                hash: None,
            },
        );
        legacy_lock.save(&legacy).unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        // The canonical entry wins where both files have one.
        assert_eq!(loaded.packages["gcc"].version, "16.2.0");
        // The legacy file fills the gaps.
        assert_eq!(loaded.packages["rust"].version, "1.97.1");
        assert_eq!(loaded.packages["ripgrep"].version, "15.2.0");
        assert_eq!(loaded.snaps["toolchain"].sha3_384, "abc");
        assert_eq!(loaded.build_deps["bison"].pin.as_deref(), Some("3.8.2"));
    }

    #[test]
    fn no_lockfile_under_either_name_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), "gate");

        assert!(load_pod_lock(tmp.path(), "gate").unwrap().is_none());
    }

    #[test]
    fn legacy_pin_survives_a_canonical_write() {
        // The migration is the next write: load through the resolver,
        // save to the canonical path, and the pin set is preserved.
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
        lock_with("14.2.0").save(&legacy).unwrap();

        let mut lock = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        lock.packages.insert("rust".into(), package("1.97.1"));
        lock.save(&pod_lock_path(tmp.path(), "gate")).unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert_eq!(loaded.packages["gcc"].version, "14.2.0");
        assert_eq!(loaded.packages["rust"].version, "1.97.1");
    }

    #[test]
    fn a_removed_package_does_not_come_back_from_the_legacy_file() {
        let tmp = tempfile::tempdir().unwrap();
        let canonical = seed(tmp.path(), "gate");
        let legacy = canonical.with_file_name(LEGACY_LOCK_FILE);
        lock_with("14.2.0").save(&legacy).unwrap();

        remove_pod_pins(tmp.path(), "gate", "gcc").unwrap();

        let loaded = load_pod_lock(tmp.path(), "gate").unwrap().unwrap();
        assert!(
            !loaded.packages.contains_key("gcc"),
            "the removed package's pin does not come back"
        );
        // The pre-rename file keeps the rest of the pod's pins.
        let legacy_lock = LockFile::load(&legacy).unwrap().unwrap();
        assert!(legacy_lock.packages.is_empty());
    }
}
