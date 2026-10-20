//! The generation's loader-lib dirs: the directories the farm's LD
//! wrapper puts on `LD_LIBRARY_PATH` so a pod's apps resolve the pod's
//! own runtime libraries.
//!
//! Split out of `farm` (the file is unreadable in one pass) because the
//! list is the pod's runtime library surface: the same dirs feed the
//! farm wrapper's `LD_LIBRARY_PATH` and the namespace gather
//! (`crate::rootfs`), so the pair of loader and C library is matched by
//! construction.

use nau_core::generation_view::StoreView;
use nau_core::pkg_manifest::{ClaimLayer, Generation};

use crate::farm::layered_packages;

/// The subdirectories of an extension tree that may hold runtime
/// libraries, in the order the loader searches them.
///
/// `usr/lib` is NOT a key: the emit writes `usr/lib/extension-release`
/// into every extension (runtime.rs), so the dir always exists and would
/// wrap every app in every pod. A subdirectory of a recorded dir is NOT
/// itself recorded — the loader searches only the listed dirs. Every
/// entry is stat-gated at emit, so layouts a payload does not ship are
/// never recorded.
pub const LOADER_LIB_SUBDIRS: [&str; 4] = [
    "usr/usr/lib",
    "usr/usr/lib64",
    "usr/usr/lib/x86_64-linux-gnu",
    "usr/lib64",
];

/// One loader-lib dir of the generation, in loader search order, with
/// the package that ships it. The package name is what the namespace
/// gather's fail-closed conflict error names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderLibDir {
    pub rel: String,
    pub pkg: String,
}

/// Collect the generation's loader-lib dirs with their owning package,
/// higher composition layer first ([`layered_packages`] reversed — the
/// loader's first-match search must resolve a shared soname to the
/// highest layer, the same precedence the farm's shared-name overwrite
/// encodes), package name ascending within a layer. Only dirs that exist
/// in the freshly staged tree are recorded — the emit runs right after
/// materialization, so the stat is authoritative and no manifest schema
/// changes.
pub fn loader_lib_entries(store: &StoreView, gen: &Generation) -> Vec<LoaderLibDir> {
    let extensions = store.generation_dir(gen.n).join("extensions");
    let mut dirs: Vec<(ClaimLayer, String, String)> = Vec::new();
    for pkg in layered_packages(gen) {
        for sub in LOADER_LIB_SUBDIRS {
            let rel = format!("extensions/{}/{}", pkg.name, sub);
            let dir = extensions.join(&pkg.name).join(sub);
            if !dir.is_dir() {
                continue;
            }
            // The C library's RUNTIME half stays ON the loader path
            // (reversal, 2026-10-19). glibc 2.44's libc.so.6 references
            // __pointer_chk_guard as UND@GLIBC_PRIVATE: the symbol moved
            // into the dynamic loader, so only a MATCHING 2.44 loader can
            // satisfy it. Keeping the pod's libc off this list made the
            // pod run the HOST's libc, which hid the mismatch instead of
            // fixing it. The farm now runs every loader-carrying
            // generation inside a mount namespace where the pod's loader
            // answers /lib64/ld-linux-x86-64.so.2 (crate::rootfs), and
            // this list supplies the pod's libc from the loader path —
            // the matched pair decision one encodes.
            dirs.push((pkg.layer, pkg.name.clone(), rel));
        }
    }
    dirs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    dirs.into_iter()
        .map(|(_, pkg, rel)| LoaderLibDir { rel, pkg })
        .collect()
}

/// Collect the generation's loader-lib dirs in loader search order.
pub fn loader_lib_dirs(store: &StoreView, gen: &Generation) -> Vec<String> {
    loader_lib_entries(store, gen)
        .into_iter()
        .map(|dir| dir.rel)
        .collect()
}
