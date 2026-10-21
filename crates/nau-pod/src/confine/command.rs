//! The arbitrary-command form of `nau run` (issue #102) and the
//! path-addressed form (issue #9).
//!
//! Issue #102: `nau run -- <cmd…>` execs any command with the pod's env
//! overlaid (the farm-first PATH and the declared env/secrets) and no
//! sandbox — fail-open by design.
//!
//! Issue #9: a command addressed by a PATH is resolved against the
//! pod's own rootfs FIRST. A path the pod owns runs inside the pod's
//! namespace (the pod's loader, the pod's libraries); a path the pod
//! does NOT own is a host command, and the reason the pod's namespace
//! was not entered is named.

use std::path::{Path, PathBuf};

use nau_core::generation_view::StoreView;
use nau_core::pkg_manifest::Generation;

use crate::pod::PodShellenv;

/// Run an arbitrary command with the pod's environment overlaid (issue
/// #102): the farm-first PATH and loader-lib LD_LIBRARY_PATH of
/// [`crate::pod::shellenv`] — the SAME env contract the shell export
/// uses, never a second one. No confinement, no sandbox (fail-open by
/// design). Transparent exec: the command replaces this process, so its
/// exit status is `nau run`'s.
///
/// Trust: the command runs with the caller's full privileges, and a
/// farm name resolves BEFORE the caller's PATH — the pod's active
/// generation is trusted like the caller's own bin directory.
///
/// Issue #9: a command addressed by a PATH is resolved against the
/// pod's own rootfs FIRST. A path the pod owns runs inside the pod's
/// namespace (the pod's loader, the pod's libraries); a path the pod
/// does NOT own is a host command, and the reason the pod's namespace
/// was not entered is named.
pub fn run_command(pod_dir: &Path, pod_name: &str, command: &[String]) -> miette::Result<()> {
    // `pod_dir` is `<root>/<pod>` (the store lives under the pod), while
    // the shellenv contract is rooted at the pod state root one level up.
    let root = pod_dir.parent().unwrap_or(pod_dir);
    let env = crate::pod::shellenv(root, pod_name)?;
    let farm = PathBuf::from(&env.farm);
    let Some(prog) = command.first() else {
        miette::bail!("nau run: empty command — nothing to exec");
    };
    if prog.contains('/') {
        let store = {
            let blobs = nau_core::blob_store::BlobStore::new(pod_dir.join("store"));
            StoreView::new(pod_dir.to_path_buf(), blobs)
        };
        let Some(gen) = store.active_generation()? else {
            miette::bail!(
                "pod '{pod_name}' has no active generation — nothing to run for '{prog}'"
            );
        };
        let gen_dir = std::fs::canonicalize(store.generation_dir(gen.n))
            .unwrap_or_else(|_| store.generation_dir(gen.n));
        let rootfs_dir = gen_dir.join(crate::rootfs::ROOTFS_DIR);
        match resolve_path_target(&rootfs_dir, prog, pod_name) {
            PathTarget::Pod { target } => {
                return run_in_pod_namespace(pod_name, &store, &gen, &target, command, &env);
            }
            PathTarget::Host { note } => nau_infra::output::warn(note),
        }
    }
    let program = resolve_command(prog, &farm)?;
    let mut cmd = std::process::Command::new(program);
    for a in &command[1..] {
        cmd.arg(a);
    }
    overlay_pod_env(&mut cmd, &env);
    crate::confine::exec_cmd(cmd)
}

/// What a path-addressed command resolves to (issue #9).
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathTarget {
    /// The pod owns the path: it runs inside the pod's namespace — the
    /// pod's loader, the pod's libraries.
    Pod {
        /// The pod's own copy of the path, inside the pod's rootfs.
        target: PathBuf,
    },
    /// The pod does NOT own the path: it runs on the host, at the path
    /// as written, and `note` names the reason the pod's namespace was
    /// not entered.
    Host { note: String },
}

/// Resolve a path-addressed command against the pod's own rootfs (issue
/// #9).
///
/// The pod's rootfs (`generations/<n>/rootfs`) is the gather of the
/// pod's FHS positions — its library dirs and its loader. A path the
/// pod owns is the pod's own copy of that position, and it runs inside
/// the pod's namespace. A path the pod does NOT own is a host file: the
/// namespace overlays `/usr` and would break a host binary's library
/// lookup, so it stays on the host — legibly, with the reason the
/// namespace was not entered named.
fn resolve_path_target(rootfs_dir: &Path, path: &str, pod_name: &str) -> PathTarget {
    match pod_owned_path(rootfs_dir, path) {
        Some(target) => PathTarget::Pod { target },
        None => PathTarget::Host {
            note: host_note(pod_name, path, rootfs_dir),
        },
    }
}

/// The pod's own copy of `path`, when the pod owns it: the gather's
/// entry at that FHS position. `None` when the pod carries no such
/// path — the command is a host file.
fn pod_owned_path(rootfs_dir: &Path, path: &str) -> Option<PathBuf> {
    let rel = path.strip_prefix('/').unwrap_or(path);
    if rel.is_empty() {
        return None;
    }
    // The gather mirrors the payload's own tree, so a path that walks
    // out of it (`..`) is never the pod's own.
    if rel.split('/').any(|part| part == "..") {
        return None;
    }
    let candidate = rootfs_dir.join(rel);
    candidate.exists().then_some(candidate)
}

/// Why a path-addressed command runs on the host (issue #9): the pod
/// does not own the path, so the pod's namespace was not entered and
/// the command runs with the HOST's loader and libraries.
fn host_note(pod_name: &str, path: &str, rootfs_dir: &Path) -> String {
    format!(
        "pod '{pod_name}': '{path}' is not a path the pod owns — the pod's rootfs \
         ({rootfs}) carries no such path, so the pod's namespace was not entered: the \
         command runs on the HOST, with the host's dynamic loader and libraries \
         instead of the pod's",
        rootfs = rootfs_dir.display()
    )
}

/// Run a pod-owned path inside the pod's namespace (issue #9): the
/// SAME mount the farm's LD wrapper enters, with the pod's loader and
/// the pod's libraries, and the pod's own copy of the path as the
/// command.
///
/// FAIL CLOSED: a loader-carrying generation whose host has no bwrap
/// refuses to run — the host's loader is the mismatch the namespace
/// exists to prevent (the farm's wrapper fails closed the same way).
fn run_in_pod_namespace(
    pod_name: &str,
    store: &StoreView,
    gen: &Generation,
    target: &Path,
    command: &[String],
    env: &PodShellenv,
) -> miette::Result<()> {
    let gen_dir = std::fs::canonicalize(store.generation_dir(gen.n))
        .unwrap_or_else(|_| store.generation_dir(gen.n));
    // The namespace needs the pod's loader paired with its libc — the
    // plan the emit computed. A generation with no loader pair has no
    // namespace to enter, and the pod cannot own a path it cannot
    // namespace: refuse rather than run the pod's own file on the
    // host's loader.
    let Some(plan) = crate::rootfs::plan(store, gen) else {
        miette::bail!(
            "pod '{pod_name}': '{target}' is a path the pod owns, but generation {n} \
             carries no loader/libc pair, so the pod's namespace cannot be entered — \
             refusing to run it with the host's dynamic loader",
            target = target.display(),
            n = gen.n
        );
    };
    let bwrap = namespace_backend(pod_name, target, crate::ld_wrapper::resolve_bwrap())?;
    let libs = crate::loader_libs::loader_lib_dirs(store, gen);
    let cmd = namespace_command(&bwrap, &plan, &gen_dir, target, &command[1..], &libs, env);
    crate::confine::exec_cmd(cmd)
}

/// The bwrap backend for the pod's namespace, or the refusal to run
/// without it (issue #9): a loader-carrying generation must not fall
/// back to the host's loader — the mismatch the namespace exists to
/// prevent. The farm's wrapper fails closed the same way.
fn namespace_backend(
    pod_name: &str,
    target: &Path,
    available: Option<PathBuf>,
) -> miette::Result<PathBuf> {
    available.ok_or_else(|| {
        miette::miette!(
            "pod '{pod_name}': '{target}' is a path the pod owns, but bubblewrap is not \
             available on this host (no provisioned set and none on PATH), so the mount \
             namespace that pairs the pod's own dynamic loader with its libc cannot be \
             entered — refusing to run it with the host's loader. Run `nau doctor --fix` \
             to provision bubblewrap, or install it (e.g. `apt install bubblewrap`).",
            target = target.display()
        )
    })
}

/// The namespace command for a pod-owned path (issue #9): the mounts
/// the farm's LD wrapper enters (the shared mount list — one source of
/// truth), the pod's loader and libraries inside the namespace, and the
/// pod's own copy of the path as the command.
fn namespace_command(
    bwrap: &Path,
    plan: &crate::rootfs::PodRootfs,
    gen_dir: &Path,
    target: &Path,
    args: &[String],
    libs: &[String],
    env: &PodShellenv,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(bwrap);
    for arg in crate::namespace::args(plan, gen_dir, &crate::ld_wrapper::host_usr_children()) {
        cmd.arg(arg);
    }
    for (name, value) in crate::namespace::env(gen_dir, libs) {
        cmd.arg("--setenv").arg(name).arg(value);
    }
    cmd.arg("--").arg(target);
    for a in args {
        cmd.arg(a);
    }
    // The pod's env overlay still applies (ADR-0030, ADR-0042 D3).
    overlay_pod_env(&mut cmd, env);
    // bwrap's own process must start WITHOUT the pod's libc on its
    // loader path: the loader that starts bwrap is the host's, and it
    // may predate the pod's glibc. The pod's paths ride the
    // namespace's --setenv instead — and the overlay's declared value,
    // if any, is shadowed there exactly as the farm's wrapper shadows
    // it.
    cmd.env_remove("LD_LIBRARY_PATH");
    cmd.env_remove("LIBRARY_PATH");
    cmd.env_remove("CPATH");
    cmd.env_remove("COMPILER_PATH");
    cmd
}

/// Resolve the command's program: a name containing `/` is an explicit
/// path taken verbatim (like sh, no resolution); otherwise the pod's
/// farm is searched before the caller's PATH, because the pod's active
/// generation is the provider seam this command form is about.
fn resolve_command(name: &str, farm: &Path) -> miette::Result<PathBuf> {
    let mut entries = vec![farm.to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&path));
    }
    resolve_command_in(name, &entries)
}

/// The resolution proper, over explicit entries — split out so tests can
/// pin lookup order without mutating the process PATH (the suite runs
/// tests in parallel).
fn resolve_command_in(name: &str, entries: &[PathBuf]) -> miette::Result<PathBuf> {
    if name.contains('/') {
        return Ok(PathBuf::from(name));
    }
    nau_infra::pathsearch::resolve_in_path(name, entries).ok_or_else(|| {
        miette::miette!(
            "command '{name}' not found in the pod's farm ({}), or PATH — \
             add the package that provides it to the pod \
             (`nau pod add <package>`) or install it on the host PATH",
            entries
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        )
    })
}

/// Overlay the pod env onto `cmd`, mirroring
/// [`crate::pod::render_shellenv`]'s semantics: PATH is the farm
/// prepended to the caller's existing PATH (the farm alone when the
/// caller has none), plus the declared env vars (ADR-0030). No
/// `LD_LIBRARY_PATH` is ever set here (issue #110, ADR-0034): farm
/// apps carry their own emit-time LD wrappers, and an arbitrary
/// command is not a pod process.
pub(crate) fn overlay_pod_env(cmd: &mut std::process::Command, env: &PodShellenv) {
    overlay_pod_env_with(cmd, env, std::env::var_os("PATH").as_deref())
}

/// The overlay proper, over explicit existing values — split out so
/// tests can pin the semantics (including unset/empty) without mutating
/// the process environment.
pub(crate) fn overlay_pod_env_with(
    cmd: &mut std::process::Command,
    env: &PodShellenv,
    existing_path: Option<&std::ffi::OsStr>,
) {
    // split_paths of an unset PATH yields nothing, and an EMPTY string
    // would yield one empty entry (a trailing empty element the loader
    // reads as the current directory) — so empty is filtered explicitly:
    // the farm alone is exported either way.
    let mut entries = vec![PathBuf::from(&env.farm)];
    if let Some(existing) = existing_path {
        if !existing.is_empty() {
            entries.extend(std::env::split_paths(existing));
        }
    }
    // join_paths only fails when an entry contains the separator; fall
    // back to the bare farm rather than silently dropping the seam.
    let path = std::env::join_paths(&entries).unwrap_or_else(|_| env.farm.as_str().into());
    cmd.env("PATH", path);

    // No LD_LIBRARY_PATH here (issue #110, ADR-0034): farm apps carry
    // their own emit-time LD wrappers, and an arbitrary command is not a
    // pod process — it runs with the caller's environment, minus this
    // overlay's PATH prepend. Exporting the pod's lib dirs here was the
    // leak this issue closed.

    // ADR-0030: the generation's declared env replaces inherited values
    // (the devbox `env:` semantics) — declared beats ambient by design.
    for (key, value) in &env.vars {
        cmd.env(key, value);
    }
    // ADR-0042 D3 (issue #184): the resolved secrets ride the SAME
    // overlay with the SAME rule — declared replaces inherited. The
    // values were resolved (all-or-nothing, D7) inside `shellenv`'s
    // serve step before this overlay ever ran.
    for (key, value) in &env.secret_vars {
        cmd.env(key, value);
    }
}

#[cfg(test)]
mod tests;
