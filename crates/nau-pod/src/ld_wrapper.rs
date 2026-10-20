//! The farm's LD wrapper: the `/bin/sh` script a farm entry points at
//! when the generation ships runtime libraries.
//!
//! Two responsibilities, one script:
//!
//! 1. Issue #110 (ADR-0034): SET `LD_LIBRARY_PATH` (and the compiler's
//!    `LIBRARY_PATH`/`CPATH`/`COMPILER_PATH`) to the generation's
//!    recorded loader-lib dirs, never compose-prepend, so the pod's
//!    libraries ride only the process the pod launches and the ambient
//!    shell stays clean.
//! 2. The pod rootfs: when the generation carries a loader/libc pair,
//!    exec the app inside a mount namespace where the pod's loader
//!    answers `/lib64/ld-linux-x86-64.so.2` and the gather
//!    ([`crate::rootfs`]) supplies `/usr/lib`, `/usr/lib64` and
//!    `/lib64`. The kernel resolves `PT_INTERP` inside the process's
//!    mount namespace, so the app AND every child start on the pod's
//!    loader — the matched pair glibc 2.44 requires.
//!
//! The bwrap path is resolved at emit time and baked in. The emit runs
//! on the host that owns the pod's state, while the farm runs under the
//! caller's PATH, which may not carry bwrap. A missing bwrap at emit
//! writes a wrapper that fails loudly at run time: silently falling back
//! to the host loader is the exact bug this file exists to fix.

use std::path::{Path, PathBuf};

use nau_core::generation_view::StoreView;

use crate::rootfs::{PodRootfs, ROOTFS_DIR};

/// The per-generation LD-wrapper area (issue #110, ADR-0034):
/// `generations/<n>/ld-wrappers/<app>`.
pub const LD_WRAPPERS_DIR: &str = "ld-wrappers";

/// Host `/usr` entries the namespace never binds back: the pod's gather
/// owns every library position, so the host's must stay invisible
/// (decision four). A subdirectory of one of these is hidden with it.
const HIDDEN_USR_ROOTS: [&str; 4] = ["lib", "lib64", "lib32", "libx32"];

/// Path of generation `n`'s LD-wrapper area.
pub(crate) fn dir(store: &StoreView, n: u64) -> PathBuf {
    store.generation_dir(n).join(LD_WRAPPERS_DIR)
}

/// Clear and recreate the LD-wrapper area. Runs on every emit — a full
/// rebuild, so a generation that lost its lib payloads (or an older
/// emit's wrappers for renamed apps) never leaves stale wrappers.
pub(crate) fn reset(store: &StoreView, n: u64) -> miette::Result<()> {
    let dir = dir(store, n);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| miette::miette!("clearing stale ld-wrappers {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| miette::miette!("creating ld-wrappers {}: {e}", dir.display()))
}

/// The namespace a wrapper enters. Built once per emit and shared by
/// every wrapper of the generation.
pub(crate) struct Namespace<'a> {
    /// The resolved bubblewrap path; `None` when the host carries none
    /// at emit time (the wrapper then fails loudly).
    pub bwrap: Option<&'a Path>,
    /// The generation's gather and loader.
    pub rootfs: &'a PodRootfs,
    /// Host `/usr` children to bind back into the namespace, sorted.
    pub host_usr_children: &'a [String],
}

/// The bubblewrap path to bake into a wrapper, resolved on the host that
/// emits. The farm runs under the caller's PATH, which may not carry
/// bwrap, so the wrapper cannot resolve it later.
pub(crate) fn resolve_bwrap() -> Option<PathBuf> {
    use nau_infra::tools::{self, ResolvedTool, ToolName};
    match tools::resolve(ToolName::Bwrap) {
        Ok(ResolvedTool::Provisioned { path, .. } | ResolvedTool::Path { path, .. }) => Some(path),
        Err(_) => None,
    }
}

/// Host `/usr` children the namespace binds back, sorted: everything
/// except the library positions the gather replaces.
pub(crate) fn host_usr_children() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/usr") else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !HIDDEN_USR_ROOTS.contains(&name.as_str()))
        .collect();
    names.sort();
    names
}

/// The mount roots the gather exposes under `/usr` (`usr/lib`,
/// `usr/lib64`, ...), collapsed to the first component so a nested
/// position rides its parent's bind.
fn usr_mount_roots(rootfs: &PodRootfs) -> Vec<String> {
    let mut roots: Vec<String> = rootfs
        .positions
        .iter()
        .filter_map(|position| {
            let rest = position.strip_prefix("usr/")?;
            let top = rest.split('/').next()?;
            Some(format!("usr/{top}"))
        })
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// Top-level FHS positions outside `/usr` (`lib64`): each gets a tmpfs
/// at its root, then the gather bound over it.
fn top_level_roots(rootfs: &PodRootfs) -> Vec<String> {
    let mut roots: Vec<String> = rootfs
        .positions
        .iter()
        .filter(|position| !position.starts_with("usr/"))
        .map(|position| position.split('/').next().unwrap_or(position).to_string())
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// Write one app's LD wrapper and return the farm-relative symlink
/// target for it. The script resolves its own location (the wrapper file
/// under `generations/<n>/ld-wrappers/`), so every path stays
/// generation-relative and the `current` flip re-scopes it atomically on
/// rollback.
///
/// Self-location uses shell builtins only: farm entries are links into
/// `ld-wrappers`, so no `readlink` or `dirname` binary is needed. That
/// keeps wrappers working on hosts without system coreutils, and unique
/// PATH names are unnecessary.
pub(crate) fn write(
    store: &StoreView,
    n: u64,
    app: &str,
    real_target: &str,
    lib_list: &str,
    namespace: Option<&Namespace<'_>>,
) -> miette::Result<String> {
    let path = dir(store, n).join(app);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("creating ld-wrappers {}: {e}", parent.display()))?;
    }
    let body = match namespace {
        Some(ns) => match ns.bwrap {
            Some(bwrap) => namespace_body(app, real_target, lib_list, ns, bwrap),
            None => missing_bwrap_body(app),
        },
        None => plain_body(real_target, lib_list),
    };
    std::fs::write(&path, &body)
        .map_err(|e| miette::miette!("writing ld-wrapper {}: {e}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| miette::miette!("chmod {}: {e}", path.display()))?;
    Ok(format!("../{LD_WRAPPERS_DIR}/{app}"))
}

/// The compiler-facing search paths every wrapper computes (issue #164):
/// `LIBRARY_PATH` (the gcc/clang drivers map it onto `-L` AND startfile
/// search), `CPATH` (every extension's `usr/usr/include`), and
/// `COMPILER_PATH` (where the driver and collect2 find `as`/`ld`).
/// Values stay in `libs`/`cpath`/`compath`: the plain wrapper exports
/// them, while the namespace wrapper hands them to bwrap so bwrap's OWN
/// process never loads the pod's libc.
fn search_paths(lib_list: &str) -> String {
    format!(
        "libs=\"{lib_list}\"\n\
         cpath=\n\
         compath=\n\
         for i in \"$d\"/../extensions/*/usr/usr/include; do\n\
         \x20 [ -d \"$i\" ] && cpath=\"$cpath$i:\"\n\
         done\n\
         cpath=\"${{cpath%:}}\"\n\
         for i in \"$d\"/../extensions/*/usr/usr/bin; do\n\
         \x20 [ -d \"$i\" ] && compath=\"$compath$i:\"\n\
         done\n\
         compath=\"${{compath%:}}\"\n"
    )
}

/// Locate `$d` (the generation directory, from the wrapper's own path)
/// with shell builtins only, and make it absolute for bwrap's bind
/// sources (bwrap resolves them against its working directory).
const LOCATE: &str = "case $0 in\n\
                     \x20 */*) d=${0%/*} ;;\n\
                     \x20 *) d=. ;;\n\
                     esac\n\
                     [ -L \"$0\" ] && d=$d/../ld-wrappers\n\
                     case $d in\n\
                     \x20 /*) ;;\n\
                     \x20 *) d=$PWD/$d ;;\n\
                     esac\n";

/// Set-only environment, no namespace: the pre-rootfs wrapper shape for
/// generations with no loader/libc pair.
fn plain_body(real_target: &str, lib_list: &str) -> String {
    format!(
        "#!/bin/sh\n{LOCATE}{}\
         LD_LIBRARY_PATH=\"$libs\"\n\
         LIBRARY_PATH=\"$libs\"\n\
         CPATH=\"$cpath\"\n\
         COMPILER_PATH=\"$compath\"\n\
         export LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n\
         exec \"$d/../farm/{real_target}\" \"$@\"\n",
        search_paths(lib_list)
    )
}

/// The mount namespace: bind the host root, replace `/usr`'s library
/// positions with the gather, hide the host loader, put the pod's
/// loader at the FHS interpreter slot, then exec the app.
fn namespace_body(
    app: &str,
    real_target: &str,
    lib_list: &str,
    ns: &Namespace<'_>,
    bwrap: &Path,
) -> String {
    let mut body = format!("#!/bin/sh\n{LOCATE}{}", search_paths(lib_list));
    body.push_str(&format!(
        "# Pod rootfs namespace (crate::rootfs): '{}'.\n",
        app
    ));
    // bwrap's own process must start WITHOUT the pod's libc on its
    // loader path: the loader that starts bwrap is the host's, and it
    // may predate the pod's glibc (the __pointer_chk_guard class). The
    // app gets the pod's paths through --setenv, applied inside the
    // namespace.
    body.push_str("unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH\n");
    body.push_str(&format!(
        "exec {} --bind / / --tmpfs /usr",
        shell_quote(bwrap)
    ));
    for child in ns.host_usr_children {
        body.push_str(&format!(
            " \\\n  --ro-bind {} {}",
            shell_quote_str(&format!("/usr/{child}")),
            shell_quote_str(&format!("/usr/{child}"))
        ));
    }
    for root in usr_mount_roots(ns.rootfs) {
        body.push_str(&format!(
            " \\\n  --ro-bind \"$d/../{ROOTFS_DIR}/{root}\" {}",
            shell_quote_str(&format!("/{root}"))
        ));
    }
    for root in top_level_roots(ns.rootfs) {
        body.push_str(&format!(
            " \\\n  --tmpfs {} \\\n  --ro-bind \"$d/../{ROOTFS_DIR}/{root}\" {}",
            shell_quote_str(&format!("/{root}")),
            shell_quote_str(&format!("/{root}"))
        ));
    }
    if top_level_roots(ns.rootfs)
        .iter()
        .all(|root| root != "lib64")
    {
        body.push_str(" \\\n  --tmpfs /lib64");
    }
    body.push_str(&format!(
        " \\\n  --ro-bind \"$d/../{}\" {} \\\n",
        ns.rootfs.loader_rel,
        shell_quote_str(&format!("/lib64/{}", crate::rootfs::LOADER_NAME))
    ));
    body.push_str(
        "  --setenv LD_LIBRARY_PATH \"$libs\" \
         --setenv LIBRARY_PATH \"$libs\" \
         --setenv CPATH \"$cpath\" \
         --setenv COMPILER_PATH \"$compath\" \\\n",
    );
    body.push_str(&format!("  -- \"$d/../farm/{real_target}\" \"$@\"\n"));
    body
}

/// A loader-carrying generation emitted on a host with no bwrap: the
/// namespace cannot be entered, and running on the host loader would
/// reintroduce `__pointer_chk_guard`. Fail loudly.
fn missing_bwrap_body(app: &str) -> String {
    format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"pod '{app}': this generation ships its own dynamic loader, \
         but bubblewrap was not available when the farm was emitted, so the mount \
         namespace that pairs the loader with its libc cannot be entered. Run \
         'nau doctor --fix' to provision bubblewrap, then re-emit the pod.\" >&2\n\
         exit 127\n"
    )
}

/// POSIX single-quote a path for the baked bwrap command.
fn shell_quote(path: &Path) -> String {
    shell_quote_str(&path.to_string_lossy())
}

fn shell_quote_str(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rootfs::PodRootfs;

    fn rootfs() -> PodRootfs {
        PodRootfs {
            positions: vec![
                "lib64".into(),
                "usr/lib".into(),
                "usr/lib/x86_64-linux-gnu".into(),
            ],
            loader_rel: "extensions/glibc/usr/lib64/ld-linux-x86-64.so.2".into(),
        }
    }

    fn store_fixture(root: &Path) -> StoreView {
        let root = root.join("nau/pods/default");
        let blobs = nau_core::blob_store::BlobStore::new(root.join("store"));
        StoreView::new(root, blobs)
    }

    #[test]
    fn plain_wrapper_sets_the_env_and_execs_the_target() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let target = write(
            &store,
            1,
            "git",
            "../../../store/ha/hash-git",
            "$d/../extensions/git/usr/usr/lib",
            None,
        )
        .unwrap();
        assert_eq!(target, "../ld-wrappers/git");
        let body = std::fs::read_to_string(dir(&store, 1).join("git")).unwrap();
        assert!(body.contains("$d/../extensions/git/usr/usr/lib"));
        assert!(body.contains("exec \"$d/../farm/../../../store/ha/hash-git\""));
        assert!(!body.contains("bwrap"));
        assert!(!body.contains("readlink") && !body.contains("dirname"));
    }

    #[test]
    fn namespace_wrapper_binds_the_gather_and_the_pod_loader() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let fake = tmp.path().join("bwrap");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        let children = vec!["bin".to_string(), "local".to_string()];
        let ns = Namespace {
            bwrap: Some(&fake),
            rootfs: &rootfs(),
            host_usr_children: &children,
        };
        write(
            &store,
            1,
            "gcc",
            "../../../store/ab/blob",
            "$d/../extensions/glibc/usr/lib64",
            Some(&ns),
        )
        .unwrap();
        let body = std::fs::read_to_string(dir(&store, 1).join("gcc")).unwrap();
        assert!(body.contains("--bind / /"), "{body}");
        assert!(body.contains("--tmpfs /usr"), "{body}");
        assert!(body.contains("--ro-bind '/usr/bin' '/usr/bin'"), "{body}");
        assert!(
            body.contains("--ro-bind \"$d/../rootfs/usr/lib\" '/usr/lib'"),
            "{body}"
        );
        assert!(
            !body.contains("--ro-bind /usr/lib /usr/lib"),
            "the host's /usr/lib must stay hidden: {body}"
        );
        assert!(
            body.contains(
                "--ro-bind \"$d/../extensions/glibc/usr/lib64/ld-linux-x86-64.so.2\" \
                 '/lib64/ld-linux-x86-64.so.2'"
            ),
            "{body}"
        );
        assert!(body.contains("--tmpfs '/lib64'"), "{body}");
        assert!(
            body.contains("--setenv LD_LIBRARY_PATH \"$libs\""),
            "the app gets the loader path inside the namespace: {body}"
        );
        assert!(
            body.contains("unset LD_LIBRARY_PATH LIBRARY_PATH CPATH COMPILER_PATH"),
            "bwrap's own process must start without the pod's libc: {body}"
        );
        assert!(!body.contains("readlink") && !body.contains("dirname"));
    }

    #[test]
    fn missing_bwrap_fails_loudly_instead_of_using_the_host_loader() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let ns = Namespace {
            bwrap: None,
            rootfs: &rootfs(),
            host_usr_children: &[],
        };
        write(&store, 1, "cc1", "../../../store/ab/blob", "", Some(&ns)).unwrap();
        let body = std::fs::read_to_string(dir(&store, 1).join("cc1")).unwrap();
        assert!(body.contains("bubblewrap"), "{body}");
        assert!(body.contains("exit 127"), "{body}");
        assert!(!body.contains("exec \"$d/../farm"), "{body}");
    }

    #[test]
    fn namespace_wrapper_runs_and_passes_the_mount_plan_to_bwrap() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        // A fake bwrap prints its argv, which proves the wrapper's shell
        // syntax and the order of the bind arguments without a real
        // namespace.
        let fake = tmp.path().join("bwrap");
        std::fs::write(
            &fake,
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let children = vec!["bin".to_string()];
        let ns = Namespace {
            bwrap: Some(&fake),
            rootfs: &rootfs(),
            host_usr_children: &children,
        };
        write(&store, 1, "gcc", "../../../store/ab/blob", "", Some(&ns)).unwrap();
        let out = std::process::Command::new(dir(&store, 1).join("gcc"))
            .arg("--version")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--bind\n/\n/"), "{text}");
        assert!(text.contains("/lib64/ld-linux-x86-64.so.2"), "{text}");
        assert!(text.lines().any(|l| l.ends_with("--version")), "{text}");
    }
}
