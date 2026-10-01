//! The root `oci` shim (issue #326 PR 4): the OCI registry client moved
//! to `nau-ship` (`nau_ship::oci`); every pre-existing `crate::oci::`
//! path keeps resolving through the re-export. `pending_from_blob` —
//! the `pull --install` revision resolution — stays HERE: it reads the
//! root runtime's lockfile records and hands
//! [`crate::runtime::PendingSnap`]s to
//! [`crate::runtime::RuntimeStore::install_batch`] (the install
//! contract is the command layer's, not the ship crate's).

pub use nau_ship::oci::*;

use miette::miette;
pub use nau_core::lock::LockFile;
pub use nau_ship::oci::parse_artifact_filename;

use crate::runtime::PendingSnap;

use std::path::Path;

// ── pull --install wiring ──

/// Resolve one pulled `.snap` blob into a [`PendingSnap`].
///
/// # Revision-resolution rule (the Phase 25 documented follow-up)
///
/// The artifact filename carries `{name}_{version}_{arch}` — the store
/// revision is NOT in the filename. It is resolved from the local
/// lockfile ([`LockFile`]) by matching the blob's sha3-384 against the
/// pinned entry for the parsed name:
///
/// - name pinned and sha3-384 matches → that pin's revision;
/// - name pinned but sha3-384 differs → named refusal (the pulled
///   content diverged from the lock — installing it would put a
///   foreign payload behind a trusted dedup key);
/// - name absent from the lockfile → named refusal to install an
///   unpinned blob; plain `pull` (without `--install`) still writes
///   the files.
///
/// [`install_batch`][crate::runtime::RuntimeStore::install_batch]'s
/// dedup key (name+revision+sha3-384) therefore only ever sees
/// lockfile-backed revisions. The filename parser is the SAME one push
/// uses ([`parse_artifact_filename`], ambiguous-underscore rejection
/// included); the payload path is passed through untouched and install
/// re-verifies sha3-384 fail-closed on its own.
pub fn pending_from_blob(payload: &Path, lockfile: &LockFile) -> miette::Result<PendingSnap> {
    let (name, _version, _arch) = parse_artifact_filename(payload)?;
    let sha3_384 = nau_infra::store::sha3_384_file(payload)?;
    let entry = lockfile.snaps.get(&name).ok_or_else(|| {
        miette!(
            "'{name}' has no {pin} entry — refusing to install a blob whose \
             store revision cannot be established; use plain `pull` (without \
             --install) or `nau lock` the snap first",
            pin = LockFile::FILENAME
        )
    })?;
    if entry.sha3_384 != sha3_384 {
        miette::bail!(
            "'{name}' pulled blob sha3-384 {sha3_384} does not match the \
             lockfile pin ({}) — refusing to install (fail-closed)",
            entry.sha3_384
        );
    }
    Ok(PendingSnap {
        name,
        revision: entry.revision,
        sha3_384,
        payload_path: payload.to_path_buf(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_artifact(dir: &Path, file: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(file);
        std::fs::write(&p, content).unwrap();
        p
    }

    fn lock_with(name: &str, revision: u32, sha3_384: &str) -> LockFile {
        let mut lock = LockFile {
            version: 1,
            sources: Default::default(),
            snaps: Default::default(),
            inputs: Default::default(),
            packages: Default::default(),
            build_deps: Default::default(),
        };
        lock.snaps.insert(
            name.to_string(),
            crate::lock::SnapLockEntry {
                revision,
                sha3_384: sha3_384.to_string(),
            },
        );
        lock
    }

    #[test]
    fn pending_from_blob_resolves_revision_from_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let payload = write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let sha3 = crate::store::sha3_384_file(&payload).unwrap();
        let lock = lock_with("app", 7, &sha3);

        let pending = pending_from_blob(&payload, &lock).unwrap();
        assert_eq!(pending.name, "app");
        assert_eq!(pending.revision, 7);
        assert_eq!(pending.sha3_384, sha3);
        assert_eq!(pending.payload_path, payload);
    }

    #[test]
    fn pending_from_blob_refuses_unpinned_divergent_and_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let payload = write_artifact(dir.path(), "app_1.0.0_amd64.snap", b"payload");
        let sha3 = crate::store::sha3_384_file(&payload).unwrap();

        // name absent from the lockfile → unpinned refusal
        let lock = lock_with("other", 7, &sha3);
        let err = pending_from_blob(&payload, &lock).unwrap_err().to_string();
        assert!(err.contains("no nau.lock entry"), "{err}");
        assert!(err.contains("plain `pull`"), "{err}");

        // pinned but content diverged → fail-closed
        let lock = lock_with("app", 7, &"f".repeat(96));
        let err = pending_from_blob(&payload, &lock).unwrap_err().to_string();
        assert!(err.contains("does not match the lockfile pin"), "{err}");

        // ambiguous filename rejected by the SHARED push parser
        let amb = write_artifact(dir.path(), "a_b_c_d.snap", b"payload");
        let lock = lock_with("a", 1, "x");
        let err = pending_from_blob(&amb, &lock).unwrap_err().to_string();
        assert!(err.contains("ambiguous"), "{err}");
    }
}
