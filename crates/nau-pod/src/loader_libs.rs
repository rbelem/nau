//! The generation's loader-lib dirs: the directories the farm's LD
//! wrapper puts on `LD_LIBRARY_PATH` so a pod's apps resolve the pod's
//! own runtime libraries.
//!
//! Split out of `farm` (the file is unreadable in one pass) because the
//! list and the rule that filters it belong together: the C library's
//! runtime half is deliberately excluded, and the reason is not obvious
//! from the list alone.

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

/// Collect the generation's loader-lib dirs, higher composition layer
/// first ([`layered_packages`] reversed — the loader's first-match
/// search must resolve a shared soname to the highest layer, the same
/// precedence the farm's shared-name overwrite encodes), package name
/// ascending within a layer. Only dirs that exist in the freshly
/// staged tree are recorded — the emit runs right after materialization,
/// so the stat is authoritative and no manifest schema changes.
pub fn loader_lib_dirs(store: &StoreView, gen: &Generation) -> Vec<String> {
    let extensions = store.generation_dir(gen.n).join("extensions");
    let mut dirs: Vec<(ClaimLayer, String, String)> = Vec::new();
    for pkg in layered_packages(gen) {
        for sub in LOADER_LIB_SUBDIRS {
            let rel = format!("extensions/{}/{}", pkg.name, sub);
            let dir = extensions.join(&pkg.name).join(sub);
            if !dir.is_dir() {
                continue;
            }
            // A C library's RUNTIME half stays OFF the farm's loader path.
            // glibc 2.44's libc.so.6 references __pointer_chk_guard as
            // UND@GLIBC_PRIVATE: the symbol moved into the dynamic
            // loader, so only a MATCHING 2.44 loader can satisfy it. The
            // farm runs the pod's binaries under the HOST's loader, and
            // a child process cannot inherit the loader its parent was
            // started with — so every fortify-compiled binary in the pod
            // dies with "symbol lookup error: .../libc.so.6: undefined
            // symbol: __pointer_chk_guard, version GLIBC_PRIVATE"
            // (measured 2026-10-19 on the 16.2.0 toolchain: the gcc
            // driver, cc1, cc1plus, and the binutils shims).
            //
            // The farm has no per-pod rootfs to pair a C library with its
            // loader, so the pod's binaries run against the HOST's libc
            // and the payload's C library is used for what it can be
            // used for: headers, crt objects, and the linker's libc.so
            // script. This matches the two other faces: the build
            // sandbox's LD_LIBRARY_PATH omits the prefix's runtime
            // slibdir (crates/nau-build/src/prefix_paths.rs), and the
            // toolchain meta's own launcher never puts its staged
            // runtime half on the loader path.
            if dir.join("libc.so.6").exists() {
                continue;
            }
            dirs.push((pkg.layer, pkg.name.clone(), rel));
        }
    }
    dirs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    dirs.into_iter().map(|(_, _, rel)| rel).collect()
}
