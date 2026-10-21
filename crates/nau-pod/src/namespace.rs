//! The pod's mount namespace: the shape the farm's LD wrapper and the
//! direct `nau pod run` path both enter.
//!
//! One list, two renderings. The mount list lives here
//! ([`MountPlan`]); the farm's LD wrapper renders it into a shell
//! command line, and the direct path (issue #9) renders the SAME list
//! into an argv. The namespace's shape is therefore written once, and
//! the two entry points cannot drift apart.
//!
//! What the namespace holds is the pod's own rootfs
//! ([`crate::rootfs`]): the gather of the pod's FHS positions (its
//! library dirs and its loader) mounted over the host's, so the pod's
//! loader answers `/lib64/ld-linux-x86-64.so.2` and the pod's
//! libraries answer the loader's search.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::rootfs::{PodRootfs, ROOTFS_DIR};

/// One mount in the pod's namespace.
enum Mount {
    /// The host root, bound read-write at `/` — the namespace's base.
    Root,
    /// A tmpfs over `/usr`: the host's library positions stay hidden.
    UsrTmpfs,
    /// A host `/usr` child bound back read-only at its own path.
    UsrChild(String),
    /// A gather position, bound read-only at its FHS path.
    Gather(String),
    /// A tmpfs over a top-level FHS position (`/lib64`).
    TopTmpfs(String),
    /// The pod's loader, bound read-only at the interpreter slot.
    Loader(String),
}

/// The pod's namespace shape: the mounts bwrap applies, in order.
struct MountPlan {
    mounts: Vec<Mount>,
}

impl MountPlan {
    /// The plan for a generation's namespace: the host root, the tmpfs
    /// over `/usr`, the host's `/usr` children bound back, the gather's
    /// positions, and the pod's loader at the interpreter slot.
    fn new(rootfs: &PodRootfs, host_usr_children: &[String]) -> Self {
        let mut mounts = vec![Mount::Root, Mount::UsrTmpfs];
        for child in host_usr_children {
            mounts.push(Mount::UsrChild(child.clone()));
        }
        for root in usr_mount_roots(rootfs) {
            mounts.push(Mount::Gather(root));
        }
        let top = top_level_roots(rootfs);
        for root in &top {
            mounts.push(Mount::TopTmpfs(root.clone()));
            mounts.push(Mount::Gather(root.clone()));
        }
        if !top.iter().any(|root| root == "lib64") {
            // The interpreter slot needs a tmpfs of its own: the host's
            // /lib64 stays hidden behind the pod's loader.
            mounts.push(Mount::TopTmpfs("lib64".to_string()));
        }
        mounts.push(Mount::Loader(rootfs.loader_rel.clone()));
        Self { mounts }
    }

    /// The mounts, in bwrap order.
    fn mounts(&self) -> &[Mount] {
        &self.mounts
    }
}

impl Mount {
    /// The mount as the farm wrapper's shell fragment.
    fn shell(&self) -> String {
        match self {
            Mount::Root => "--bind / /".to_string(),
            Mount::UsrTmpfs => "--tmpfs /usr".to_string(),
            Mount::UsrChild(child) => {
                let path = format!("/usr/{child}");
                format!(
                    "--ro-bind {} {}",
                    shell_quote_str(&path),
                    shell_quote_str(&path)
                )
            }
            Mount::Gather(position) => format!(
                "--ro-bind \"$d/../{ROOTFS_DIR}/{position}\" {}",
                shell_quote_str(&format!("/{position}"))
            ),
            Mount::TopTmpfs(position) => {
                format!("--tmpfs {}", shell_quote_str(&format!("/{position}")))
            }
            Mount::Loader(rel) => format!(
                "--ro-bind \"$d/../{rel}\" {}",
                shell_quote_str(&format!("/lib64/{}", crate::rootfs::LOADER_NAME))
            ),
        }
    }

    /// The mount as bwrap arguments, over real paths: the gather
    /// resolved under the generation dir, the pod's loader at its
    /// generation-relative path.
    fn args(&self, gen_dir: &Path) -> Vec<OsString> {
        match self {
            Mount::Root => vec!["--bind".into(), "/".into(), "/".into()],
            Mount::UsrTmpfs => vec!["--tmpfs".into(), "/usr".into()],
            Mount::UsrChild(child) => {
                let path = format!("/usr/{child}");
                vec!["--ro-bind".into(), path.clone().into(), path.into()]
            }
            Mount::Gather(position) => vec![
                "--ro-bind".into(),
                gen_dir.join(ROOTFS_DIR).join(position).into(),
                format!("/{position}").into(),
            ],
            Mount::TopTmpfs(position) => vec!["--tmpfs".into(), format!("/{position}").into()],
            Mount::Loader(rel) => vec![
                "--ro-bind".into(),
                gen_dir.join(rel).into(),
                format!("/lib64/{}", crate::rootfs::LOADER_NAME).into(),
            ],
        }
    }
}

/// The mount list as the farm wrapper's shell command line: one
/// continuation line per mount, the way the wrapper's `exec` line
/// carries them.
pub(crate) fn shell_plan(rootfs: &PodRootfs, host_usr_children: &[String]) -> String {
    let mut out = String::new();
    for mount in MountPlan::new(rootfs, host_usr_children).mounts() {
        out.push_str(&format!(" \\\n  {}", mount.shell()));
    }
    out
}

/// The bwrap arguments for the pod's namespace, over real paths — the
/// direct `nau pod run` path's half of the shared mount list (issue
/// #9). The farm's wrapper renders the same list into a shell command
/// line.
pub(crate) fn args(
    rootfs: &PodRootfs,
    gen_dir: &Path,
    host_usr_children: &[String],
) -> Vec<OsString> {
    MountPlan::new(rootfs, host_usr_children)
        .mounts()
        .iter()
        .flat_map(|mount| mount.args(gen_dir))
        .collect()
}

/// The environment the pod's processes see INSIDE the namespace: the
/// loader paths, applied inside the namespace so bwrap's own process
/// never starts with the pod's libc on its loader path.
///
/// The values are the ones the farm's wrapper computes in its shell
/// (the same dirs, the same order) — this is the Rust half, for the
/// direct `nau pod run` path (issue #9).
pub(crate) fn env(gen_dir: &Path, lib_rels: &[String]) -> Vec<(&'static str, String)> {
    let libs = lib_rels
        .iter()
        .map(|rel| gen_dir.join(rel).display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let (cpath, compath) = extension_search_paths(gen_dir);
    vec![
        ("LD_LIBRARY_PATH", libs.clone()),
        ("LIBRARY_PATH", libs),
        ("CPATH", cpath),
        ("COMPILER_PATH", compath),
    ]
}

/// The compiler-facing search paths (issue #164): every extension
/// tree's include dir and bin dir, in the same order the wrapper's
/// shell glob yields them.
fn extension_search_paths(gen_dir: &Path) -> (String, String) {
    let mut cpath: Vec<String> = Vec::new();
    let mut compath: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(gen_dir.join("extensions")) else {
        return (String::new(), String::new());
    };
    let mut trees: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    trees.sort();
    for tree in trees {
        let include = tree.join("usr/usr/include");
        if include.is_dir() {
            cpath.push(include.display().to_string());
        }
        let bin = tree.join("usr/usr/bin");
        if bin.is_dir() {
            compath.push(bin.display().to_string());
        }
    }
    (cpath.join(":"), compath.join(":"))
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

/// POSIX single-quote a path for the baked bwrap command.
pub(crate) fn shell_quote(path: &Path) -> String {
    shell_quote_str(&path.to_string_lossy())
}

pub(crate) fn shell_quote_str(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}
