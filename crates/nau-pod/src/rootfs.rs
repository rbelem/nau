//! The pod's FHS rootfs for the farm's mount namespace: a symlink farm
//! that puts the generation's library dirs at their FHS positions, plus
//! the loader the kernel resolves as `PT_INTERP`.
//!
//! Why a namespace: glibc 2.44's `libc.so.6` references
//! `__pointer_chk_guard` as `UND@GLIBC_PRIVATE`, so only a loader from
//! the same build can satisfy it. The kernel resolves `PT_INTERP`
//! (`/lib64/ld-linux-x86-64.so.2`) inside the process's mount
//! namespace, which is the one mechanism that also reaches every CHILD
//! process — a child cannot inherit the loader its parent was started
//! with. The farm wrapper therefore execs the app with the pod's loader
//! bound at the FHS interpreter slot, and the pod's `libc.so.6` comes
//! from the loader path (`crate::loader_libs`), so the pair is matched.
//!
//! Why the gather: decision four gives the pod its own `/usr/lib`. A
//! program carrying a hardcoded absolute library path must resolve the
//! pod's copy, and the host's `/usr/lib` must be invisible to every
//! process in the namespace. The gather mirrors the generation's
//! library dirs into `generations/<n>/rootfs/<fhs position>` as
//! relative symlinks into the generation's own extension trees, so it
//! costs no space and a rollback re-emit re-scopes it with the
//! generation.
//!
//! Merge semantics are the build prefix's (`crates/nau-build/src/
//! build_prefix.rs`, ADR-0018): identical content dedupes, a
//! same-path/different-content collision is a hard error naming both
//! packages. The walk starts at the library positions, so payload-root
//! packaging metadata (`meta/`, `usr/share/info/dir`) never enters —
//! the same exclusion the prefix merge applies.

use std::collections::BTreeMap;
use std::path::Path;

use nau_core::generation_view::StoreView;
use nau_core::pkg_manifest::Generation;

use crate::loader_libs::{loader_lib_entries, LoaderLibDir};

/// The gather directory inside a generation: `generations/<n>/rootfs`.
pub const ROOTFS_DIR: &str = "rootfs";

/// The interpreter slot the kernel reads from `PT_INTERP` for an
/// x86_64 payload. It is a host-wide constant, not a payload choice.
pub const LOADER_NAME: &str = "ld-linux-x86-64.so.2";

/// The C library's soname; a dir carrying both this and
/// [`LOADER_NAME`] is the matched loader/libc pair.
pub const LIBC_NAME: &str = "libc.so.6";

/// The FHS position for one payload-relative library dir: the extension
/// prefix `usr/` is the payload root, so stripping it yields the path
/// the payload would occupy on a normal root (`usr/usr/lib` → `usr/lib`,
/// `usr/lib64` → `lib64`).
fn fhs_position(sub: &str) -> &str {
    sub.strip_prefix("usr/").unwrap_or(sub)
}

/// The namespace plan for one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRootfs {
    /// FHS positions the gather carries, sorted and deduped
    /// (`lib64`, `usr/lib`, `usr/lib/x86_64-linux-gnu`, ...).
    pub positions: Vec<String>,
    /// Generation-relative path of the pod's loader, e.g.
    /// `extensions/glibc/usr/lib64/ld-linux-x86-64.so.2`.
    pub loader_rel: String,
}

/// How a path entered the gather, kept so a later package's same-path
/// entry can be compared with the build prefix's rules.
enum Placed {
    Dir(String),
    File(String, std::path::PathBuf),
    Symlink(String, std::path::PathBuf),
}

impl Placed {
    fn package(&self) -> &str {
        match self {
            Placed::Dir(pkg) | Placed::File(pkg, _) | Placed::Symlink(pkg, _) => pkg,
        }
    }
}

/// Build (or clear) the generation's rootfs gather.
///
/// Returns `None` when no loader/libc pair is on the loader path: such
/// a pod needs no namespace, and the farm keeps its plain LD wrapper.
/// On a loader-carrying generation the gather is rebuilt from scratch on
/// every emit, so a generation that loses its loader also loses a stale
/// tree.
pub fn prepare(store: &StoreView, gen: &Generation) -> miette::Result<Option<PodRootfs>> {
    // Absolute source paths: the gather is bound at /usr/lib and /lib64
    // inside the namespace, where a relative `../../../extensions/...`
    // would resolve against the mounted position, not the generation.
    let gen_dir = std::fs::canonicalize(store.generation_dir(gen.n))
        .unwrap_or_else(|_| store.generation_dir(gen.n));
    let rootfs = gen_dir.join(ROOTFS_DIR);
    let libs = loader_lib_entries(store, gen);
    let Some(loader) = libs
        .iter()
        .find(|lib| has_loader_pair(&gen_dir.join(&lib.rel)))
    else {
        withdraw(&rootfs)?;
        return Ok(None);
    };
    if rootfs.exists() {
        std::fs::remove_dir_all(&rootfs)
            .map_err(|e| miette::miette!("clearing stale rootfs {}: {e}", rootfs.display()))?;
    }
    std::fs::create_dir_all(&rootfs)
        .map_err(|e| miette::miette!("creating rootfs {}: {e}", rootfs.display()))?;

    let mut owners: BTreeMap<String, Placed> = BTreeMap::new();
    let mut positions: Vec<String> = Vec::new();
    for lib in &libs {
        let position = fhs_position(&lib.sub).to_string();
        if !positions.contains(&position) {
            positions.push(position.clone());
        }
        let dst = rootfs.join(&position);
        std::fs::create_dir_all(&dst)
            .map_err(|e| miette::miette!("creating rootfs position {}: {e}", dst.display()))?;
        gather_dir(&gen_dir, &rootfs, lib, &position, "", &mut owners)?;
    }
    positions.sort();

    Ok(Some(PodRootfs {
        positions,
        loader_rel: format!("{}/{}", loader.rel, LOADER_NAME),
    }))
}

/// Withdraw a gather an earlier emit left behind, so a re-emit without
/// the glibc payload never keeps a stale tree.
fn withdraw(rootfs: &Path) -> miette::Result<()> {
    if rootfs.exists() {
        std::fs::remove_dir_all(rootfs)
            .map_err(|e| miette::miette!("clearing stale rootfs {}: {e}", rootfs.display()))?;
    }
    Ok(())
}

/// True when `dir` carries a loader and a C library, the pair rule the
/// gcc payload's `cc` shim already uses.
fn has_loader_pair(dir: &Path) -> bool {
    dir.join(LOADER_NAME).exists() && dir.join(LIBC_NAME).exists()
}

/// Mirror one library dir (recursively) into the gather at `position`,
/// under the relative subtree `sub`.
fn gather_dir(
    gen_dir: &Path,
    rootfs: &Path,
    lib: &LoaderLibDir,
    position: &str,
    sub: &str,
    owners: &mut BTreeMap<String, Placed>,
) -> miette::Result<()> {
    let src_dir = gen_dir.join(&lib.rel).join(sub);
    let mut entries: Vec<_> = std::fs::read_dir(&src_dir)
        .map_err(|e| miette::miette!("reading rootfs source {}: {e}", src_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| miette::miette!("reading rootfs source {}: {e}", src_dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_sub = if sub.is_empty() {
            name
        } else {
            format!("{sub}/{name}")
        };
        let src = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| miette::miette!("reading rootfs source {}: {e}", src.display()))?;
        if ft.is_dir() {
            place_dir(gen_dir, rootfs, lib, position, &child_sub, owners)?;
        } else if ft.is_symlink() || ft.is_file() {
            place_leaf(
                rootfs,
                lib,
                position,
                &child_sub,
                &src,
                ft.is_symlink(),
                owners,
            )?;
        }
    }
    Ok(())
}

/// Merge a subdirectory into the gather and recurse.
fn place_dir(
    gen_dir: &Path,
    rootfs: &Path,
    lib: &LoaderLibDir,
    position: &str,
    child_sub: &str,
    owners: &mut BTreeMap<String, Placed>,
) -> miette::Result<()> {
    let fhs_rel = format!("{position}/{child_sub}");
    match owners.get(&fhs_rel) {
        Some(Placed::Dir(_)) => {}
        Some(existing) => return Err(conflict(&fhs_rel, existing, &lib.pkg)),
        None => {
            owners.insert(fhs_rel.clone(), Placed::Dir(lib.pkg.clone()));
        }
    }
    let dst = rootfs.join(&fhs_rel);
    std::fs::create_dir_all(&dst)
        .map_err(|e| miette::miette!("creating rootfs dir {}: {e}", dst.display()))?;
    gather_dir(gen_dir, rootfs, lib, position, child_sub, owners)
}

/// Place one leaf as a relative symlink into its extension tree,
/// deduping identical content and failing closed on a real collision.
fn place_leaf(
    rootfs: &Path,
    lib: &LoaderLibDir,
    position: &str,
    child_sub: &str,
    src: &Path,
    symlink: bool,
    owners: &mut BTreeMap<String, Placed>,
) -> miette::Result<()> {
    let fhs_rel = format!("{position}/{child_sub}");
    if let Some(existing) = owners.get(&fhs_rel) {
        return if same_entry(existing, src, symlink) {
            Ok(())
        } else {
            Err(conflict(&fhs_rel, existing, &lib.pkg))
        };
    }
    let dst = rootfs.join(&fhs_rel);
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating rootfs dir {}: {e}", parent.display()))?;
    }
    if is_interpreter(child_sub) {
        // The interpreter slot is a mount DESTINATION for the wrapper's
        // loader bind, and bwrap refuses a symlink destination. A
        // hardlink keeps the gather cheap while giving bwrap a regular
        // file to mount on.
        let real = std::fs::canonicalize(src).unwrap_or_else(|_| src.to_path_buf());
        std::fs::hard_link(&real, &dst).map_err(|e| {
            miette::miette!(
                "hardlinking rootfs interpreter {} -> {}: {e}",
                real.display(),
                dst.display()
            )
        })?;
    } else {
        // Absolute, because the gather is mounted at the FHS position
        // inside the namespace: a relative target's depth would have to
        // change with the mount. The host root stays bound at `/`, so
        // the absolute path resolves in both views.
        let target = src.to_string_lossy().into_owned();
        std::os::unix::fs::symlink(&target, &dst)
            .map_err(|e| miette::miette!("linking rootfs {} -> {target}: {e}", dst.display()))?;
    }
    let placed = if symlink {
        Placed::Symlink(lib.pkg.clone(), src.to_path_buf())
    } else {
        Placed::File(lib.pkg.clone(), src.to_path_buf())
    };
    owners.insert(fhs_rel, placed);
    Ok(())
}

/// Whether a gather leaf is the dynamic loader, the one path bwrap
/// mounts over and therefore the one that cannot be a symlink.
fn is_interpreter(child_sub: &str) -> bool {
    child_sub.rsplit('/').next() == Some(LOADER_NAME)
}

/// Whether an incumbent and an incoming leaf carry the same content, by
/// the build prefix's rule: symlinks compare targets, regular files
/// compare bytes.
fn same_entry(existing: &Placed, src: &Path, symlink: bool) -> bool {
    match (existing, symlink) {
        (Placed::Symlink(_, incumbent), true) => {
            std::fs::read_link(incumbent).ok() == std::fs::read_link(src).ok()
        }
        (Placed::File(_, incumbent), false) => is_same_file_content(incumbent, src),
        _ => false,
    }
}

/// The hard gather error for a same-path/different-content collision,
/// naming both packages — the build prefix's merge rule (ADR-0018).
fn conflict(rel: &str, existing: &Placed, incoming: &str) -> miette::Error {
    miette::miette!(
        "pod rootfs conflict: '{rel}' differs between '{}' and '{incoming}' — \
         the pod's gathered library set requires identical content at shared paths",
        existing.package()
    )
}

/// Byte-identical regular files (size short-circuit, then stream
/// compare) — the build prefix's `is_same_file_content`, kept beside
/// its one pod-side caller.
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
    use nau_core::blob_store::BlobStore;
    use nau_core::pkg_manifest::{ClaimLayer, InstalledPackage};

    fn store_fixture(dir: &Path) -> StoreView {
        let root = dir.join("nau/pods/default");
        let blobs = BlobStore::new(root.join("store"));
        StoreView::new(root, blobs)
    }

    fn gen_with(n: u64, pkgs: &[(&str, ClaimLayer)]) -> Generation {
        let mut packages = BTreeMap::new();
        for (name, layer) in pkgs {
            packages.insert(
                name.to_string(),
                InstalledPackage {
                    name: name.to_string(),
                    version: "1.0".into(),
                    revision: 1,
                    sha3_384: "abc".into(),
                    files: vec![],
                    units: vec![],
                    layer: *layer,
                    apps: BTreeMap::new(),
                    requires: Vec::new(),
                    launchers: BTreeMap::new(),
                    assembly: BTreeMap::new(),
                    confined: None,
                    app_confined: BTreeMap::new(),
                    desktops: BTreeMap::new(),
                    fonts: BTreeMap::new(),
                    services: BTreeMap::new(),
                    service_bins: BTreeMap::new(),
                    meta_digest: None,
                },
            );
        }
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    fn write(path: &Path, body: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn glibc_pair(gen_dir: &Path) {
        write(
            &gen_dir.join("extensions/glibc/usr/lib64/ld-linux-x86-64.so.2"),
            b"loader",
        );
        write(
            &gen_dir.join("extensions/glibc/usr/lib64/libc.so.6"),
            b"libc",
        );
    }

    #[test]
    fn gather_maps_payload_dirs_to_fhs_positions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen_dir = store.generation_dir(1);
        glibc_pair(&gen_dir);
        write(
            &gen_dir.join("extensions/gcc/usr/usr/lib/x86_64-linux-gnu/libisl.so.23"),
            b"isl",
        );
        let gen = gen_with(1, &[("glibc", ClaimLayer::Own), ("gcc", ClaimLayer::Own)]);

        let rootfs = prepare(&store, &gen).unwrap().expect("loader pair");
        assert_eq!(
            rootfs.loader_rel,
            "extensions/glibc/usr/lib64/ld-linux-x86-64.so.2"
        );
        assert!(rootfs.positions.contains(&"lib64".to_string()));
        assert!(
            rootfs
                .positions
                .contains(&"usr/lib/x86_64-linux-gnu".to_string()),
            "{:?}",
            rootfs.positions
        );
        let gather = gen_dir.join(ROOTFS_DIR);
        let link = std::fs::read_link(gather.join("lib64/libc.so.6")).unwrap();
        assert!(
            link.is_absolute() && link.ends_with("extensions/glibc/usr/lib64/libc.so.6"),
            "gather links are absolute so they resolve inside the namespace: {}",
            link.display()
        );
        let loader = std::fs::symlink_metadata(gather.join("lib64/ld-linux-x86-64.so.2")).unwrap();
        assert!(
            loader.file_type().is_file(),
            "the interpreter slot must be a regular file: bwrap refuses a symlink mount destination"
        );
        assert!(gather
            .join("usr/lib/x86_64-linux-gnu/libisl.so.23")
            .exists());
    }

    #[test]
    fn identical_content_dedupes_and_different_content_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen_dir = store.generation_dir(1);
        glibc_pair(&gen_dir);
        write(
            &gen_dir.join("extensions/one/usr/usr/lib/libdup.so"),
            b"same",
        );
        write(
            &gen_dir.join("extensions/two/usr/usr/lib/libdup.so"),
            b"same",
        );
        let gen = gen_with(
            1,
            &[
                ("glibc", ClaimLayer::Own),
                ("one", ClaimLayer::Own),
                ("two", ClaimLayer::Own),
            ],
        );
        prepare(&store, &gen).unwrap();

        write(
            &gen_dir.join("extensions/two/usr/usr/lib/libdup.so"),
            b"diff",
        );
        let err = prepare(&store, &gen).unwrap_err().to_string();
        assert!(err.contains("'one'") && err.contains("'two'"), "{err}");
    }

    #[test]
    fn no_loader_pair_means_no_rootfs_and_a_stale_one_is_withdrawn() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen_dir = store.generation_dir(1);
        glibc_pair(&gen_dir);
        let with = gen_with(1, &[("glibc", ClaimLayer::Own)]);
        assert!(prepare(&store, &with).unwrap().is_some());

        let without = gen_with(1, &[]);
        assert!(prepare(&store, &without).unwrap().is_none());
        assert!(!gen_dir.join(ROOTFS_DIR).exists());
    }

    #[test]
    fn payload_root_metadata_never_enters_the_gather() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let gen_dir = store.generation_dir(1);
        glibc_pair(&gen_dir);
        write(&gen_dir.join("extensions/glibc/usr/meta/manifest"), b"meta");
        let gen = gen_with(1, &[("glibc", ClaimLayer::Own)]);
        prepare(&store, &gen).unwrap();
        assert!(!gen_dir.join(ROOTFS_DIR).join("meta").exists());
    }
}
