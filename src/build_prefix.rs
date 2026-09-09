//! Merged build prefix — payload visibility for source builds (ADR-0018,
//! issue #17).
//!
//! A source package's `requires` + `build_deps` entries name pool packages
//! whose built `.snap` payloads carry the headers, link libraries, and
//! pkg-config metadata a build needs (`./configure`, `pkg-config`, the
//! compiler). The build sandbox is hermetic (ADR-0004): none of that is
//! visible today, which is why `htop` cannot find pool ncurses.
//!
//! The fix (ADR-0018 Decision 2) materializes the payloads of every entry
//! into ONE `/usr`-like prefix tree and binds it read-only into the build
//! sandbox ([`crate::snap::SANDBOX_BUILD_PREFIX`]). Per-package directories
//! with hand-rolled `-I`/`-L` flags are rejected by the ADR — a single
//! consumable prefix is the whole mechanism.
//!
//! Merge semantics: the same relative path with identical content merges
//! fine (deduplicated); the same path with differing content is a hard
//! build error naming both source packages. Payloads never overlap → no
//! conflicts → the merge is a no-op beyond copying.
//!
//! The payloads come from the existing build machinery: a dependency's
//! `.snap` (built by `shuttle build` into the output dir or fetched from
//! the binary cache) is data-only unpacked with `unsquashfs` — never
//! executed, never mounted.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One dependency payload to merge: the source package name (for conflict
/// messages) and its built `.snap` file.
pub struct Payload {
    pub pkg: String,
    pub snap: PathBuf,
}

/// The materialized merged prefix: owns the tempdir backing the tree and
/// exposes the `/usr`-like prefix path the build sandbox binds (the tempdir
/// also holds the per-payload unpack dirs, which live BESIDE the prefix, not
/// inside it).
#[derive(Debug)]
pub struct MergedPrefix {
    /// Held for its `Drop` (removes the tree when the build finishes) —
    /// never read directly.
    #[allow(dead_code)]
    work: tempfile::TempDir,
    path: PathBuf,
}

impl MergedPrefix {
    /// The `/usr`-like prefix tree to bind into the build sandbox.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The snapd packaging subtree every payload carries (`snap.yaml`, hooks,
/// gui icons) — per-package by definition and never consumed by a build
/// (`./configure`, `pkg-config`, compilers read the `usr/` prefix). Always
/// excluded from the merge: including it would hard-error every pair of
/// packages on their differing `meta/snap.yaml`.
const META_SUBTREE: &str = "meta";

/// Materialize the merged `/usr`-like build prefix from `payloads`.
///
/// Returns the [`MergedPrefix`] — the caller must keep it alive for as long
/// as the build runs and bind [`MergedPrefix::path`] into the sandbox;
/// dropping it removes the tree. An empty `payloads` list yields an empty
/// prefix (callers usually skip materializing instead).
pub fn materialize_merged_prefix(payloads: &[Payload]) -> miette::Result<MergedPrefix> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let path = work.path().join("prefix");
    std::fs::create_dir_all(&path).map_err(|e| miette::miette!("create prefix dir: {e}"))?;

    // rel path → the package that contributed it, so a conflict can name
    // both source packages.
    let mut owners: HashMap<String, String> = HashMap::new();
    for payload in payloads {
        let unpack_dir = work.path().join("payloads").join(&payload.pkg);
        // unsquashfs requires the destination's parent to exist.
        std::fs::create_dir_all(&unpack_dir)
            .map_err(|e| miette::miette!("creating unpack dir for '{}': {e}", payload.pkg))?;
        unpack_snap(&payload.snap, &unpack_dir)?;
        merge_tree(&unpack_dir, &payload.pkg, &path, &mut owners)?;
    }
    Ok(MergedPrefix { work, path })
}

/// Data-only unpack of a `.snap` (squashfs) into `dest` with `unsquashfs`.
/// The payload is never executed — files are just extracted.
fn unpack_snap(snap: &Path, dest: &Path) -> miette::Result<()> {
    let output = std::process::Command::new("unsquashfs")
        .arg("-no-progress")
        .arg("-d")
        .arg(dest)
        .arg(snap)
        .output()
        .map_err(|e| {
            miette::miette!(
                "unsquashfs not found (needed to unpack dependency payloads \
                 for the merged build prefix): {e}"
            )
        })?;
    if !output.status.success() {
        return Err(miette::miette!(
            "failed to unpack {} for the merged build prefix: {}",
            snap.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Merge `src` (the unpacked payload of `pkg`) into `prefix`, tracking who
/// contributed each relative path in `owners`.
fn merge_tree(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    merge_dir(src, pkg, prefix, "", owners)
}

fn merge_dir(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    rel: &str,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let entries =
        std::fs::read_dir(src).map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Per-package packaging metadata never enters the prefix.
        if rel.is_empty() && name == META_SUBTREE {
            continue;
        }
        // No symlink following: the payload tree is what the package staged.
        let ft = entry
            .file_type()
            .map_err(|e| miette::miette!("reading payload of '{pkg}': {e}"))?;
        let child_rel = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{}", entry.file_name().to_string_lossy())
        };
        merge_entry(&entry.path(), ft, pkg, prefix, &child_rel, owners)?;
        owners.entry(child_rel).or_insert_with(|| pkg.to_string());
    }
    Ok(())
}

/// Merge one payload entry into the prefix at `child_rel`.
fn merge_entry(
    src: &Path,
    ft: std::fs::FileType,
    pkg: &str,
    prefix: &Path,
    child_rel: &str,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let dst = prefix.join(child_rel);
    if ft.is_dir() {
        merge_dir_entry(src, pkg, prefix, child_rel, &dst, owners)
    } else if ft.is_symlink() {
        merge_symlink(src, pkg, child_rel, &dst, owners)
    } else {
        merge_file(src, pkg, child_rel, &dst, owners)
    }
}

/// Directory entry: recurse, merging subtree into the existing dir.
fn merge_dir_entry(
    src: &Path,
    pkg: &str,
    prefix: &Path,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    if !dst.is_dir() && dst.symlink_metadata().is_ok() {
        return Err(conflict(child_rel, owners, pkg));
    }
    std::fs::create_dir_all(dst)
        .map_err(|e| miette::miette!("merging payload dir '{child_rel}': {e}"))?;
    merge_dir(src, pkg, prefix, child_rel, owners)
}

/// Symlink entry: identical target dedupes, differing target conflicts.
fn merge_symlink(
    src: &Path,
    pkg: &str,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    let target = std::fs::read_link(src)
        .map_err(|e| miette::miette!("reading payload link '{child_rel}': {e}"))?;
    if dst.symlink_metadata().is_ok() {
        let same = std::fs::read_link(dst)
            .map(|t| t == target)
            .unwrap_or(false);
        if !same {
            return Err(conflict(child_rel, owners, pkg));
        }
        return Ok(());
    }
    std::os::unix::fs::symlink(&target, dst)
        .map_err(|e| miette::miette!("merging payload link '{child_rel}': {e}"))
}

/// Regular-file entry: identical content dedupes, differing content is a
/// hard error naming both packages.
fn merge_file(
    src: &Path,
    pkg: &str,
    child_rel: &str,
    dst: &Path,
    owners: &mut HashMap<String, String>,
) -> miette::Result<()> {
    if dst.symlink_metadata().is_ok() {
        // A regular file never merges with a symlink at the same path.
        if dst.is_file() && is_same_file_content(src, dst) {
            return Ok(());
        }
        return Err(conflict(child_rel, owners, pkg));
    }
    std::fs::copy(src, dst)
        .map_err(|e| miette::miette!("merging payload file '{child_rel}': {e}"))?;
    Ok(())
}

/// The hard build error for a same-path/different-content collision,
/// naming both source packages (ADR-0018 merge semantics).
fn conflict(rel: &str, owners: &HashMap<String, String>, incoming: &str) -> miette::Error {
    let existing = owners
        .get(rel)
        .cloned()
        .unwrap_or_else(|| "an earlier payload".to_string());
    miette::miette!(
        "build prefix conflict: '{rel}' differs between '{existing}' and '{incoming}' — \
         the merged build prefix requires identical content at shared paths"
    )
}

/// Byte-identical regular files (size short-circuit, then stream compare).
fn is_same_file_content(a: &Path, b: &Path) -> bool {
    let (ma, mb) = match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    if !ma.is_file() || !mb.is_file() || ma.len() != mb.len() {
        return false;
    }
    use std::io::Read;
    let (mut fa, mut fb) = match (std::fs::File::open(a), std::fs::File::open(b)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    let (mut ba, mut bb) = ([0u8; 65536], [0u8; 65536]);
    loop {
        let (na, nb) = match (fa.read(&mut ba), fb.read(&mut bb)) {
            (Ok(na), Ok(nb)) => (na, nb),
            _ => return false,
        };
        if na != nb {
            return false;
        }
        if na == 0 {
            return true;
        }
        if ba[..na] != bb[..nb] {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Skip gate for tests that shell out to squashfs tools (repo convention:
    /// integration-ish tests skip when the tools are unavailable).
    fn squashfs_tools_available() -> bool {
        std::process::Command::new("mksquashfs")
            .arg("-version")
            .output()
            .is_ok()
            && std::process::Command::new("unsquashfs")
                .arg("-version")
                .output()
                .is_ok()
    }

    /// Build a `.snap` whose payload contains the given rel-path → content
    /// files (plus a symlink: rel → target).
    fn make_snap(dir: &Path, files: &[(&str, &str)], links: &[(&str, &str)]) -> PathBuf {
        let payload = dir.join("payload");
        for (rel, content) in files {
            let p = payload.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
        }
        for (rel, target) in links {
            let p = payload.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, &p).unwrap();
        }
        let snap = dir.join("test.snap");
        let _ = std::fs::remove_file(&snap);
        let status = std::process::Command::new("mksquashfs")
            .arg(&payload)
            .arg(&snap)
            .arg("-no-progress")
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        snap
    }

    #[test]
    fn merge_disjoint_payloads_and_dedupes_identical() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(
            &tmp.path().join("a"),
            &[
                ("usr/include/ah.h", "a-header\n"),
                ("usr/share/common", "shared\n"),
            ],
            &[("usr/lib/liba.so", "liba.so.1")],
        );
        let snap_b = make_snap(
            &tmp.path().join("b"),
            &[
                ("usr/include/bh.h", "b-header\n"),
                ("usr/share/common", "shared\n"),
            ],
            &[],
        );

        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .unwrap();
        let prefix = merged.path().to_path_buf();
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/include/ah.h")).unwrap(),
            "a-header\n"
        );
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/include/bh.h")).unwrap(),
            "b-header\n"
        );
        // Identical content at the same path: merged fine.
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/common")).unwrap(),
            "shared\n"
        );
        // Symlinks survive the merge.
        assert_eq!(
            std::fs::read_link(prefix.join("usr/lib/liba.so")).unwrap(),
            Path::new("liba.so.1")
        );
    }

    #[test]
    fn merge_conflicting_content_is_a_hard_error_naming_both() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(&tmp.path().join("a"), &[("usr/share/x", "from-a\n")], &[]);
        let snap_b = make_snap(&tmp.path().join("b"), &[("usr/share/x", "from-b\n")], &[]);

        let err = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("usr/share/x"), "names the path: {msg}");
        assert!(
            msg.contains("pkg-a") && msg.contains("pkg-b"),
            "names both packages: {msg}"
        );
    }

    #[test]
    fn meta_packaging_subtree_is_excluded_from_the_merge() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs unavailable");
            return;
        }
        // Every payload ships its own meta/snap.yaml — differing content is
        // normal packaging metadata, never a build-prefix conflict.
        let tmp = tempfile::tempdir().unwrap();
        let snap_a = make_snap(
            &tmp.path().join("a"),
            &[
                ("meta/snap.yaml", "name: a\n"),
                ("usr/share/data", "shared\n"),
            ],
            &[],
        );
        let snap_b = make_snap(
            &tmp.path().join("b"),
            &[
                ("meta/snap.yaml", "name: b\n"),
                ("usr/share/data", "shared\n"),
            ],
            &[],
        );

        let merged = materialize_merged_prefix(&[
            Payload {
                pkg: "pkg-a".into(),
                snap: snap_a,
            },
            Payload {
                pkg: "pkg-b".into(),
                snap: snap_b,
            },
        ])
        .expect("differing meta/ subtrees must not conflict");
        let prefix = merged.path().to_path_buf();
        assert!(!prefix.join("meta").exists(), "meta/ must be excluded");
        assert_eq!(
            std::fs::read_to_string(prefix.join("usr/share/data")).unwrap(),
            "shared\n"
        );
    }
    #[test]
    fn empty_payload_list_yields_empty_prefix() {
        let merged = materialize_merged_prefix(&[]).unwrap();
        assert!(merged.path().is_dir());
    }
}
