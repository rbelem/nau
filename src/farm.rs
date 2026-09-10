//! The pod bin farm (issue #3): a per-generation directory of direct
//! symlinks into the content store, plus the pod's `current` link.
//!
//! Farm entries are symlinks to STORE paths (`store/<aa>/<sha256>`),
//! never shims, wrappers, or links into generation trees — the ticket's
//! hard rule. The pod-level `current` link is the documented activation
//! seam (CONTEXT.md: Pod generation — "rollback switches that pod's
//! `current` link only"): it points at the latest generation's farm, so
//! a shell with `<pod>/current` on PATH runs that pod's current tools.
//!
//! The emitter is deliberately dumb: it reads the generation manifest's
//! app table (recorded at install time, `runtime.rs`) and links. Any
//! crash mid-emit is healed by re-running the emit (fully idempotent —
//! the farm is rebuilt from scratch each time).
//!
//! Issue #7: the emit also (re)builds the generation's Freedesktop
//! launcher set (`crate::desktop`) beside the farm — the launchers are
//! part of the generation, so rollback and removal surface the target
//! generation's set by re-emitting.
//!
//! Issue #37: multi-file packages. Some payloads ship content beside a
//! command binary (`pi`'s package.json/theme/assets,
//! git-credential-manager's libSkiaSharp.so) that the binary resolves
//! relative to its own path; a bare link to the lone content blob
//! strands those siblings in the store. For an app recorded with an
//! [`AppAssembly`] the emitter assembles a per-package subtree under
//! the generation — `generations/<n>/apps/<pkg>/...` — with the binary
//! and its siblings HARDLINKED from the store at their payload paths.
//! Hardlinks, not symlinks: the executed leaf must be a real file, or
//! `/proc/self/exe` collapses through a symlink chain back to the lone
//! blob and the siblings are lost again (the same load-bearing
//! hardlink the extension trees use). The farm entry itself stays a
//! DIRECT symlink (`farm/<app> → ../apps/<pkg>/<binary>`), so `which`
//! resolves under the farm and no shim, wrapper, or re-exec is
//! introduced. The subtree lives in the generation directory, so the
//! `current` flip swaps it atomically on rollback and GC drops it with
//! the generation. Single-binary packages record no assembly and keep
//! the unchanged direct store link.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runtime::{Generation, InstalledPackage, RuntimeStore};

/// The farm directory inside a generation: `<root>/generations/<n>/farm`.
pub const FARM_DIR: &str = "farm";

/// The pod's activation link: `<pod>/current` → `generations/<n>/farm`
/// (relative, mirroring the store's own `active` link convention).
pub const CURRENT_LINK: &str = "current";

/// The per-generation assembly area for multi-file packages (issue
/// #37): `generations/<n>/apps/<pkg>/...`. Lives BESIDE the farm (the
/// farm itself stays a flat directory of direct tool links) and inside
/// the generation dir, so `current` swaps it atomically on rollback.
pub const ASSEMBLY_DIR: &str = "apps";

/// One app's multi-file payload assembly (issue #37): the app binary's
/// in-payload path plus the content that ships beside it (same payload
/// directory, recursively), recorded at install time from the walked
/// payload tree. Paths under `files`/`links` are relative to the
/// binary's directory and reproduce the payload layout the binary
/// resolves against. Empty maps mean the payload ships the binary
/// alone — nothing recorded, the farm keeps the bare direct link.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AppAssembly {
    /// In-payload path of the app's command binary (e.g.
    /// `usr/bin/git-credential-manager`).
    pub binary: String,
    /// Files beside the binary: path relative to the binary's payload
    /// directory → sha256 of the content blob in the store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, String>,
    /// Symlinks beside the binary, recreated verbatim: relative path →
    /// link target (never followed — payload links stay payload-scoped).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
}

impl AppAssembly {
    /// Whether the payload ships this app's binary alone.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.links.is_empty()
    }
}

/// The generation's assembly area: `<root>/generations/<n>/apps`.
pub fn assembly_dir(store: &RuntimeStore, n: u64) -> PathBuf {
    store.generation_dir(n).join(ASSEMBLY_DIR)
}

/// One package's assembly subtree root: `<root>/generations/<n>/apps/<pkg>`.
pub fn package_assembly_dir(store: &RuntimeStore, n: u64, pkg: &str) -> PathBuf {
    assembly_dir(store, n).join(pkg)
}

/// The assembled path of one app's binary: the hardlinked leaf inside
/// the generation's assembly subtree, whose directory holds the
/// recorded siblings. `shuttle run` execs this path for multi-file
/// apps so relative-to-executable resolution finds the siblings.
pub fn assembly_bin_path(store: &RuntimeStore, n: u64, pkg: &str, asm: &AppAssembly) -> PathBuf {
    package_assembly_dir(store, n, pkg).join(&asm.binary)
}

// ── ID-collision classifier (shared, not desktop-specific) ──

/// The precedence layer a claim on a shared ID (a desktop application ID
/// or a binary name) comes from. Derived from the pod composition chain
/// (CONTEXT.md: Pod, Overlay — issue #8): a package provided by a loaded
/// pod is `Loaded` (lowest); the loading pod's own declaration is `Own`;
/// a package patched by this pod's inline overlay is `Overlay`, which
/// strictly dominates. A pod never sits below what it loads: the loading
/// pod wins cross-layer binary conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimLayer {
    /// Provided by a loaded pod (issue #8) — the composition floor.
    Loaded,
    /// This pod's own declared packages.
    #[default]
    Own,
    /// This pod's inline overlay — the top layer.
    Overlay,
}

/// The verdict for two claims on the same ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionVerdict {
    /// The incoming claim sits on a strictly higher layer than the
    /// incumbent: it overrides (warn, incoming wins).
    Override,
    /// The incoming claim sits on a strictly lower layer than the
    /// incumbent: it is shadowed (warn, incumbent stays).
    Shadowed,
    /// Both claims sit on the same layer: a same-precedence collision
    /// (hard error).
    Error,
}

/// Classify two claims on the same application ID. Same-precedence
/// duplicates error; a higher layer overrides with a warning; a lower
/// layer is shadowed with a warning. Pure and desktop-agnostic so the
/// loads generalization (#8) can reuse it for binary names unchanged.
pub fn classify_collision(incumbent: ClaimLayer, incoming: ClaimLayer) -> CollisionVerdict {
    match incumbent.cmp(&incoming) {
        Ordering::Equal => CollisionVerdict::Error,
        Ordering::Less => CollisionVerdict::Override,
        Ordering::Greater => CollisionVerdict::Shadowed,
    }
}

/// Packages of a generation in deterministic LAYER order (issue #8):
/// lower precedence first (`Loaded` < `Own` < `Overlay`), package name
/// breaking ties. Consumers that emit a shared name (farm links,
/// desktop entries) iterate in this order so a later entry overwrites
/// an earlier one and the HIGHER layer wins the shared name — the
/// loading pod's own content beats what it loaded.
pub fn layered_packages(gen: &Generation) -> Vec<&InstalledPackage> {
    let mut pkgs: Vec<&InstalledPackage> = gen.packages.values().collect();
    pkgs.sort_by_key(|p| (p.layer, p.name.clone()));
    pkgs
}

/// Warn about one name collision resolved at emit time (activation).
/// Generations this code produces are collision-checked at mutation
/// time (`pod.rs` claim resolution), so emit only ever sees cross-layer
/// overrides (warn: higher layer wins) or same-precedence duplicates
/// from pre-#8 manifests (warn: deterministic replacement). Never
/// silent, never fatal — a rollback must always be able to re-emit.
pub fn warn_emit_collision(kind: &str, id: &str, winner: &str, loser: &str, same_layer: bool) {
    if same_layer {
        crate::output::warn(format!(
            "{kind} '{id}' is shipped by both '{winner}' and '{loser}' at the same \
             precedence (pre-composition manifest) — '{winner}' wins deterministically"
        ));
    } else {
        crate::output::warn(format!(
            "{kind} '{id}' from '{winner}' overrides '{loser}' (higher layer wins)"
        ));
    }
}

/// Farm directory of generation `n`.
pub fn farm_dir(store: &RuntimeStore, n: u64) -> PathBuf {
    store.generation_dir(n).join(FARM_DIR)
}

/// Emit (rebuild) the farm for generation `n` from its manifest and
/// return the farm path.
///
/// Packages iterate in LAYER order ([`layered_packages`], issue #8), so
/// a binary name shared across the composition resolves to the highest
/// layer: the loading pod's own package overrides a loaded pod's with a
/// warning; a same-precedence duplicate (only possible in pre-#8
/// manifests) warns and resolves deterministically by package name.
/// Cross-layer shadowing is never silent.
pub fn emit(store: &RuntimeStore, gen: &Generation) -> miette::Result<PathBuf> {
    let farm = farm_dir(store, gen.n);
    if farm.exists() {
        std::fs::remove_dir_all(&farm)
            .map_err(|e| miette::miette!("clearing stale farm {}: {e}", farm.display()))?;
    }
    std::fs::create_dir_all(&farm)
        .map_err(|e| miette::miette!("creating farm {}: {e}", farm.display()))?;
    reset_assembly(store, gen.n)?;
    let mut seen: std::collections::BTreeMap<&str, (&str, ClaimLayer)> = Default::default();
    for pkg in layered_packages(gen) {
        for (app, hash) in &pkg.apps {
            if let Some((incumbent_pkg, incumbent_layer)) = seen.get(app.as_str()) {
                warn_emit_collision(
                    "binary",
                    app,
                    &pkg.name,
                    incumbent_pkg,
                    *incumbent_layer == pkg.layer,
                );
            }
            seen.insert(app, (&pkg.name, pkg.layer));
            let link = farm.join(app);
            // Same-content collisions leave identical links; differing
            // content must not accumulate — replace, never merge.
            let _ = std::fs::remove_file(&link);
            let target = entry_target_rel(store, gen.n, pkg, app, hash)?;
            std::os::unix::fs::symlink(&target, &link)
                .map_err(|e| miette::miette!("linking {} -> {}: {e}", link.display(), target))?;
        }
    }
    // The Freedesktop launcher set is part of the generation (issue #7):
    // emit it beside the bin farm so removal and rollback surface the
    // target generation's entries by re-emitting.
    crate::desktop::emit(store, gen)?;
    Ok(farm)
}

/// Reset the generation's assembly area wholesale (issue #37): the emit
/// is a full rebuild, so stale packages' subtrees never accumulate.
fn reset_assembly(store: &RuntimeStore, n: u64) -> miette::Result<()> {
    let dir = assembly_dir(store, n);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| miette::miette!("clearing stale assembly {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// The relative symlink target for one farm entry, building the
/// assembly subtree when the app needs one (issue #37).
///
/// A multi-file app gets its per-package assembly subtree built
/// regardless of confinement — `shuttle run` execs the assembled leaf
/// — but only an UNCONFINED app's farm entry links into the subtree. A
/// confined app (ticket #11) keeps the unchanged direct store link to
/// its launcher-wrapper blob (its real binary is exec'd later by
/// `shuttle run`, which performs its own assembly resolution). A
/// single-binary app keeps the unchanged direct store link.
fn entry_target_rel(
    store: &RuntimeStore,
    n: u64,
    pkg: &InstalledPackage,
    app: &str,
    hash: &str,
) -> miette::Result<String> {
    if let Some(asm) = pkg.assembly.get(app) {
        build_assembly(store, n, &pkg.name, hash, asm)?;
        if !effective_confined(pkg, app) {
            return Ok(format!("../{ASSEMBLY_DIR}/{}/{}", pkg.name, asm.binary));
        }
    }
    // Ticket #11: a confined app's farm entry points at its
    // confined-launcher wrapper (which invokes `shuttle run`), not the
    // raw command binary. This keeps `which`/PATH truthful while the
    // sandbox is set up transparently. The wrapper blob is recorded in
    // `launchers`; effective confinement is the per-app override or the
    // package default.
    let target_hash = if effective_confined(pkg, app) {
        pkg.launchers.get(app).map_or(hash, String::as_str)
    } else {
        hash
    };
    Ok(store_blob_rel(target_hash))
}

/// Whether an app runs confined: the per-app override or the package
/// default (ticket #11).
fn effective_confined(pkg: &InstalledPackage, app: &str) -> bool {
    pkg.app_confined
        .get(app)
        .or(pkg.confined.as_ref())
        .is_some()
}

/// Relative store target for a farm entry, from the farm directory
/// (`<root>/generations/<n>/farm` → `<root>/store/<aa>/<sha256>`).
fn store_blob_rel(hash: &str) -> String {
    let (aa, _) = hash.split_at(2.min(hash.len()));
    format!("../../../store/{aa}/{hash}")
}

/// Assemble one app's multi-file payload under
/// `generations/<n>/apps/<pkg>/` (issue #37): the command binary at its
/// payload path plus every recorded sibling (files hardlinked from the
/// store, symlinks recreated verbatim) under the binary's directory —
/// the layout the binary resolves against is reproduced exactly.
/// Hardlink leaves are load-bearing — a symlinked leaf would collapse
/// `/proc/self/exe` back onto the lone store blob and the siblings
/// would be lost again.
fn build_assembly(
    store: &RuntimeStore,
    n: u64,
    pkg: &str,
    binary_hash: &str,
    asm: &AppAssembly,
) -> miette::Result<()> {
    let base = package_assembly_dir(store, n, pkg);
    // `binary` is payload-root-relative; sibling paths are relative to
    // the binary's directory.
    let bin_dir = asm.binary.rsplit_once('/').map(|(d, _)| d);
    let sibling = |rel: &str| -> PathBuf {
        match bin_dir {
            Some(d) => base.join(d).join(rel),
            None => base.join(rel),
        }
    };
    hardlink_assembly_blob(store, &base.join(&asm.binary), binary_hash)?;
    for (rel, sha256) in &asm.files {
        hardlink_assembly_blob(store, &sibling(rel), sha256)?;
    }
    for (rel, target) in &asm.links {
        let dest = sibling(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("creating assembly dir {}: {e}", parent.display()))?;
        }
        std::os::unix::fs::symlink(target, &dest)
            .map_err(|e| miette::miette!("linking {} -> {}: {e}", dest.display(), target))?;
    }
    Ok(())
}

/// Hardlink one store blob into the assembly subtree at `dest`.
/// Cross-device (EXDEV) is a loud fail-closed error, mirroring the
/// extension-tree rule: the state root lives on ONE filesystem.
fn hardlink_assembly_blob(store: &RuntimeStore, dest: &Path, sha256: &str) -> miette::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| miette::miette!("assembly path {} has no parent", dest.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| miette::miette!("creating assembly dir {}: {e}", parent.display()))?;
    let blob = store.blob_path(sha256);
    // Idempotent: a payload may record the command binary AND the same
    // path as a sibling (e.g. bun ships `usr/bin/bunx`, and the binary's
    // own entry can collide with a sibling entry). A prior emit of this
    // generation can also leave the leaf in place. If `dest` already
    // points at the same blob, nothing to do; otherwise drop the stale
    // leaf and relink (replace, never fail).
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_file() {
            use std::os::unix::fs::MetadataExt;
            let same = std::fs::metadata(dest)
                .and_then(|d| {
                    std::fs::metadata(&blob).map(|b| (d.dev(), d.ino()) == (b.dev(), b.ino()))
                })
                .unwrap_or(false);
            if same {
                return Ok(());
            }
        }
        std::fs::remove_file(dest).map_err(|e| {
            miette::miette!("replacing stale assembly entry {}: {e}", dest.display())
        })?;
    }
    std::fs::hard_link(&blob, dest).map_err(|e| {
        if e.raw_os_error() == Some(libc::EXDEV) {
            miette::miette!(
                "cannot hardlink blob into the assembly subtree: {} and {} are \
                 on different filesystems (EXDEV). The state root must live on \
                 ONE filesystem — move --state-dir onto the store's filesystem.",
                blob.display(),
                dest.display()
            )
        } else {
            miette::miette!("hardlinking {} -> {}: {e}", blob.display(), dest.display())
        }
    })
}

/// Flip the pod's `current` link at generation `n`'s farm, atomically
/// (temp symlink + rename(2), the store's `active` flip pattern).
pub fn flip_current(pod_dir: &Path, n: u64) -> miette::Result<()> {
    let link = pod_dir.join(CURRENT_LINK);
    let tmp = pod_dir.join(format!(".{}.tmp-{}", CURRENT_LINK, std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(format!("generations/{n}/{FARM_DIR}"), &tmp)
        .map_err(|e| miette::miette!("staging current -> generation {n}: {e}"))?;
    std::fs::rename(&tmp, &link)
        .map_err(|e| miette::miette!("activating current -> generation {n}: {e}"))?;
    Ok(())
}

/// Drop the pod's `current` link (a pod with no active generation
/// exposes nothing). Removing a missing link is a no-op.
pub fn clear_current(pod_dir: &Path) -> miette::Result<()> {
    let _ = std::fs::remove_file(pod_dir.join(CURRENT_LINK));
    Ok(())
}

/// The generation the pod's `current` link points at, if any.
pub fn current_generation(pod_dir: &Path) -> miette::Result<Option<u64>> {
    let target = match std::fs::read_link(pod_dir.join(CURRENT_LINK)) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    // generations/<n>/farm
    let n = target
        .components()
        .rev()
        .nth(1)
        .and_then(|c| c.as_os_str().to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| {
            miette::miette!(
                "pod current link points at an unexpected target {:?}",
                target
            )
        })?;
    Ok(Some(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn store_fixture(dir: &Path) -> RuntimeStore {
        // The documented pod layout `<data-home>/shuttle/pods/<pod>`:
        // the launcher emitter derives its user-level surface from this
        // shape, so a nested fixture root keeps every write inside the
        // test's tempdir without touching the environment.
        RuntimeStore::new(dir.join("shuttle/pods/default"))
    }

    fn gen_with_apps(n: u64, pkg: &str, apps: &[(&str, &str)]) -> Generation {
        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            crate::runtime::InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![],
                units: vec![],
                layer: ClaimLayer::Own,
                apps: apps
                    .iter()
                    .map(|(a, h)| (a.to_string(), h.to_string()))
                    .collect(),
                assembly: BTreeMap::new(),
                desktops: BTreeMap::new(),
                launchers: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
            },
        );
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    /// A generation fixture with confined apps: `confined` grants plus a
    /// launcher-wrapper hash per app (ticket #11).
    fn gen_with_confined_apps(
        n: u64,
        pkg: &str,
        apps: &[(&str, &str)],
        launchers: &[(&str, &str)],
    ) -> Generation {
        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            crate::runtime::InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![],
                units: vec![],
                layer: ClaimLayer::Own,
                apps: apps
                    .iter()
                    .map(|(a, h)| (a.to_string(), h.to_string()))
                    .collect(),
                launchers: launchers
                    .iter()
                    .map(|(a, h)| (a.to_string(), h.to_string()))
                    .collect(),
                assembly: BTreeMap::new(),
                confined: Some(crate::snap::Confinement {
                    backend: crate::snap::BackendKind::Bwrap,
                    filesystem: vec!["write".into()],
                    network: false,
                    sockets: vec![],
                    devices: vec![],
                    backend_options: BTreeMap::new(),
                }),
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
            },
        );
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    #[test]
    fn confined_farm_links_point_at_the_launcher_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        for hash in ["aa11", "bb22"] {
            let blob = store.blob_path(hash);
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(&blob, b"content").unwrap();
        }
        let gen = gen_with_confined_apps(1, "guiapp", &[("myapp", "aa11")], &[("myapp", "bb22")]);
        let farm = emit(&store, &gen).unwrap();
        let link = farm.join("myapp");
        let target = std::fs::read_link(&link).unwrap();
        assert!(
            target.ends_with("store/bb/bb22"),
            "confined farm entry must point at the launcher wrapper, got {target:?}"
        );
        // The wrapper blob is the executed content, not the raw binary.
        assert_eq!(std::fs::read(link).unwrap(), b"content");
    }

    #[test]
    fn farm_links_are_direct_symlinks_into_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let hash = "abcdef1234";
        // The blob must exist for the link to resolve.
        let blob = store.blob_path(hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"content").unwrap();

        let gen = gen_with_apps(1, "hello", &[("hello", hash)]);
        let farm = emit(&store, &gen).unwrap();
        let link = farm.join("hello");
        let target = std::fs::read_link(&link).unwrap();
        assert!(
            target.ends_with("store/ab/abcdef1234"),
            "farm entry must link into the store, got {target:?}"
        );
        // Resolves to executable store content, not a wrapper.
        assert_eq!(std::fs::read(link).unwrap(), b"content");
    }

    #[test]
    fn emit_is_idempotent_and_prunes_stale_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        for hash in ["aa11", "bb22"] {
            let blob = store.blob_path(hash);
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(&blob, b"x").unwrap();
        }
        let old = gen_with_apps(1, "p", &[("old", "aa11")]);
        emit(&store, &old).unwrap();
        let new = gen_with_apps(1, "p", &[("new", "bb22")]);
        let farm = emit(&store, &new).unwrap();
        assert!(!farm.join("old").exists(), "stale entry pruned");
        assert!(farm.join("new").is_file(), "fresh entry present");
    }

    #[test]
    fn current_link_flips_atomically_and_tracks_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let pod_dir = tmp.path();
        flip_current(pod_dir, 3).unwrap();
        let link = pod_dir.join(CURRENT_LINK);
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("generations/3/farm")
        );
        assert_eq!(current_generation(pod_dir).unwrap(), Some(3));
        flip_current(pod_dir, 7).unwrap();
        assert_eq!(current_generation(pod_dir).unwrap(), Some(7));
        clear_current(pod_dir).unwrap();
        assert!(!link.exists(), "cleared");
        assert_eq!(current_generation(pod_dir).unwrap(), None);
        // Clearing a missing link is a no-op.
        clear_current(pod_dir).unwrap();
    }

    // ── Issue #7: desktop launchers beside the farm ──

    use crate::runtime::{DesktopIcon, DesktopLauncher};

    fn launcher(name: &str, categories: &[&str], icon: Option<DesktopIcon>) -> DesktopLauncher {
        DesktopLauncher {
            name: Some(name.to_string()),
            generic_name: None,
            comment: None,
            categories: categories.iter().map(|s| s.to_string()).collect(),
            icon_ref: None,
            icon,
        }
    }

    fn gen_with_desktops(
        n: u64,
        pkg: &str,
        apps: &[(&str, &str)],
        desktops: &[(&str, DesktopLauncher)],
    ) -> Generation {
        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            crate::runtime::InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![],
                units: vec![],
                layer: ClaimLayer::Own,
                apps: apps
                    .iter()
                    .map(|(a, h)| (a.to_string(), h.to_string()))
                    .collect(),
                launchers: BTreeMap::new(),
                confined: None,
                app_confined: BTreeMap::new(),
                assembly: BTreeMap::new(),
                desktops: desktops
                    .iter()
                    .map(|(a, l)| (a.to_string(), l.clone()))
                    .collect(),
            },
        );
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    #[test]
    fn launchers_are_emitted_beside_the_farm_with_pod_namespaced_links() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let hash = "ab11iconhash";
        let blob = store.blob_path(hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"png-bytes").unwrap();

        let gen = gen_with_desktops(
            1,
            "guiapp",
            &[("myapp", "aa11binhash")],
            &[(
                "myapp",
                launcher(
                    "My App",
                    &["Utility"],
                    Some(DesktopIcon {
                        sha256: hash.into(),
                        ext: "png".into(),
                    }),
                ),
            )],
        );
        let farm = emit(&store, &gen).unwrap();

        // The launcher file lives in the generation, beside the farm.
        let launchers = farm.parent().unwrap().join(crate::desktop::LAUNCHERS_DIR);
        let entry = launchers.join("myapp.desktop");
        let text = std::fs::read_to_string(&entry).unwrap();
        crate::desktop::validate(&text, Some("shuttle-pod-default-myapp"), None).unwrap();
        assert!(text.contains("Name=My App\n"), "got: {text}");
        assert!(text.contains("Categories=Utility;\n"));
        // Exec points at the pod's farm activation seam, never the store.
        let expected_exec = store.root().join(crate::farm::CURRENT_LINK).join("myapp");
        assert!(
            text.contains(&format!("Exec=\"{}\"", expected_exec.display())),
            "Exec must be the farm path, got: {text}"
        );

        // The user-level link is pod-namespaced and resolves into the
        // generation (the documented-layout data home is the tmpdir).
        let data_home = tmp.path();
        let user_link = data_home
            .join("applications")
            .join("shuttle-pod-default-myapp.desktop");
        assert_eq!(
            std::fs::read_link(&user_link).unwrap(),
            entry,
            "user entry must link into the generation"
        );

        // The icon link is pod-namespaced, under the theme apps dir, and
        // resolves into the store blob.
        let icon_link = data_home
            .join("icons/hicolor/256x256/apps")
            .join("shuttle-pod-default-myapp.png");
        assert_eq!(std::fs::read_link(&icon_link).unwrap(), blob);
        assert_eq!(std::fs::read(&icon_link).unwrap(), b"png-bytes");
    }

    #[test]
    fn reemit_withdraws_stale_user_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let old = gen_with_desktops(
            1,
            "p",
            &[],
            &[("gone", launcher("Gone", &["Utility"], None))],
        );
        emit(&store, &old).unwrap();
        let user_link = tmp
            .path()
            .join("applications")
            .join("shuttle-pod-default-gone.desktop");
        assert!(user_link.exists());

        let new = gen_with_desktops(
            2,
            "p",
            &[],
            &[("kept", launcher("Kept", &["Utility"], None))],
        );
        emit(&store, &new).unwrap();
        assert!(!user_link.exists(), "stale entry withdrawn");
        assert!(
            tmp.path()
                .join("applications/shuttle-pod-default-kept.desktop")
                .exists(),
            "fresh entry present"
        );
        // Foreign entries are never touched.
        let foreign = tmp.path().join("applications/firefox.desktop");
        std::fs::write(&foreign, b"[Desktop Entry]\n").unwrap();
        emit(&store, &new).unwrap();
        assert!(foreign.exists());
    }

    #[test]
    fn classifier_same_precedence_errors_layer_overrides() {
        use ClaimLayer::{Loaded, Overlay, Own};
        use CollisionVerdict::*;
        assert_eq!(classify_collision(Own, Own), Error);
        assert_eq!(classify_collision(Overlay, Overlay), Error);
        assert_eq!(classify_collision(Loaded, Loaded), Error);
        assert_eq!(classify_collision(Loaded, Own), Override);
        assert_eq!(classify_collision(Own, Overlay), Override);
        assert_eq!(classify_collision(Overlay, Own), Shadowed);
        assert_eq!(classify_collision(Own, Loaded), Shadowed);
    }

    // ── Issue #37: multi-file packages — the assembly subtree ──

    /// A generation fixture with one app carrying a sibling assembly.
    fn gen_with_assembly(
        n: u64,
        pkg: &str,
        app: &str,
        bin_hash: &str,
        asm: AppAssembly,
    ) -> Generation {
        let mut packages = BTreeMap::new();
        packages.insert(
            pkg.to_string(),
            crate::runtime::InstalledPackage {
                name: pkg.to_string(),
                version: "1.0".into(),
                revision: 1,
                sha3_384: "abc".into(),
                files: vec![],
                units: vec![],
                layer: ClaimLayer::Own,
                apps: [(app.to_string(), bin_hash.to_string())]
                    .into_iter()
                    .collect(),
                launchers: BTreeMap::new(),
                assembly: [(app.to_string(), asm)].into_iter().collect(),
                confined: None,
                app_confined: BTreeMap::new(),
                desktops: BTreeMap::new(),
            },
        );
        Generation {
            n,
            base_version: "24.04".into(),
            packages,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    /// Store a blob with explicit mode (the exec test needs an
    /// executable binary blob).
    fn write_blob(store: &RuntimeStore, hash: &str, content: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let blob = store.blob_path(hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, content).unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn multifile_app_gets_an_assembly_subtree_with_hardlink_leaves() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        write_blob(&store, "aa11", b"pi-binary", 0o755);
        write_blob(&store, "bb22", b"{\"version\": \"0.85.1\"}", 0o644);
        write_blob(&store, "cc33", b"theme bytes", 0o644);
        let asm = AppAssembly {
            binary: "usr/bin/pi".into(),
            files: [
                ("package.json".to_string(), "bb22".to_string()),
                ("theme/now.txt".to_string(), "cc33".to_string()),
            ]
            .into_iter()
            .collect(),
            links: BTreeMap::new(),
        };
        let gen = gen_with_assembly(1, "pi", "pi", "aa11", asm);
        let farm = emit(&store, &gen).unwrap();

        // The farm entry is a DIRECT symlink into the assembly subtree.
        let link = farm.join("pi");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../apps/pi/usr/bin/pi"),
            "farm entry must link into the per-package assembly subtree"
        );
        // The assembled leaf is a REAL FILE hardlinked to the store blob
        // (same inode) — a symlink leaf would collapse /proc/self/exe
        // back onto the lone blob and strand the siblings.
        let leaf = assembly_bin_path(&store, 1, "pi", &gen.packages["pi"].assembly["pi"]);
        assert!(!std::fs::symlink_metadata(&leaf)
            .unwrap()
            .file_type()
            .is_symlink());
        use std::os::unix::fs::MetadataExt;
        let blob_meta = std::fs::metadata(store.blob_path("aa11")).unwrap();
        let leaf_meta = std::fs::metadata(&leaf).unwrap();
        assert_eq!(
            (blob_meta.dev(), blob_meta.ino()),
            (leaf_meta.dev(), leaf_meta.ino())
        );
        // The siblings sit beside the leaf, content readable through
        // the payload layout, from the FARM path too.
        let bin_dir = leaf.parent().unwrap();
        assert_eq!(
            std::fs::read(bin_dir.join("package.json")).unwrap(),
            b"{\"version\": \"0.85.1\"}"
        );
        assert_eq!(
            std::fs::read(bin_dir.join("theme/now.txt")).unwrap(),
            b"theme bytes"
        );
        assert_eq!(std::fs::read(&link).unwrap(), b"pi-binary");
    }

    #[test]
    fn multifile_binary_executed_from_the_farm_reads_its_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        // The synthetic payload: a "binary" that reads the data file
        // beside it (relative-to-executable resolution), plus that data
        // file — exactly the pi/gcm shape.
        let script = b"#!/bin/sh\nexec cat \"$(dirname \"$(readlink -f \"$0\")\")/data.txt\"\n";
        write_blob(&store, "aa11", script, 0o755);
        write_blob(&store, "bb22", b"sibling-data-bytes", 0o644);
        let asm = AppAssembly {
            binary: "usr/bin/tool".into(),
            files: [("data.txt".to_string(), "bb22".to_string())]
                .into_iter()
                .collect(),
            links: BTreeMap::new(),
        };
        let gen = gen_with_assembly(1, "toolkit", "tool", "aa11", asm);
        let farm = emit(&store, &gen).unwrap();

        // Execute through the farm entry (what PATH resolution runs)
        // and assert the sibling read succeeds.
        let out = std::process::Command::new(farm.join("tool"))
            .output()
            .expect("farm entry must execute");
        assert!(
            out.status.success(),
            "stderr: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"sibling-data-bytes");
    }

    #[test]
    fn single_binary_package_keeps_the_bare_direct_link_and_no_assembly() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        write_blob(&store, "abcdef1234", b"content", 0o755);
        let gen = gen_with_apps(1, "hello", &[("hello", "abcdef1234")]);
        let farm = emit(&store, &gen).unwrap();
        // Unchanged layout: direct store link, no assembly area built.
        let target = std::fs::read_link(farm.join("hello")).unwrap();
        assert!(
            target.ends_with("store/ab/abcdef1234"),
            "single-binary entries must keep the direct store link, got {target:?}"
        );
        assert!(
            !assembly_dir(&store, 1).exists(),
            "no assembly subtree for a single-binary package"
        );
    }

    #[test]
    fn confined_multifile_app_keeps_the_wrapper_link_but_assembles_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        write_blob(&store, "aa11", b"raw-binary", 0o755);
        write_blob(&store, "bb22", b"wrapper", 0o755);
        write_blob(&store, "cc33", b"libSkiaSharp.so", 0o755);
        let asm = AppAssembly {
            binary: "usr/bin/gcm".into(),
            files: [("libSkiaSharp.so".to_string(), "cc33".to_string())]
                .into_iter()
                .collect(),
            links: BTreeMap::new(),
        };
        let mut gen = gen_with_confined_apps(1, "gcmpkg", &[("gcm", "aa11")], &[("gcm", "bb22")]);
        gen.packages
            .get_mut("gcmpkg")
            .unwrap()
            .assembly
            .insert("gcm".into(), asm);
        let farm = emit(&store, &gen).unwrap();
        // The farm entry still points at the launcher wrapper blob
        // (ticket #11 behavior unchanged for confined apps).
        let target = std::fs::read_link(farm.join("gcm")).unwrap();
        assert!(
            target.ends_with("store/bb/bb22"),
            "confined entries keep the wrapper link, got {target:?}"
        );
        // But the assembly exists for `shuttle run`, which execs the
        // assembled binary beside its siblings inside the sandbox.
        let bin = assembly_bin_path(&store, 1, "gcmpkg", &gen.packages["gcmpkg"].assembly["gcm"]);
        assert!(bin.is_file());
        assert_eq!(
            std::fs::read(bin.parent().unwrap().join("libSkiaSharp.so")).unwrap(),
            b"libSkiaSharp.so"
        );
    }

    #[test]
    fn reemit_prunes_stale_assembly_subtrees() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        write_blob(&store, "aa11", b"bin", 0o755);
        write_blob(&store, "bb22", b"data", 0o644);
        let asm = AppAssembly {
            binary: "usr/bin/old".into(),
            files: [("data.txt".to_string(), "bb22".to_string())]
                .into_iter()
                .collect(),
            links: BTreeMap::new(),
        };
        let old = gen_with_assembly(1, "p", "old", "aa11", asm);
        emit(&store, &old).unwrap();
        assert!(package_assembly_dir(&store, 1, "p").is_dir());

        // A re-emit without the assembly (package downgraded to a bare
        // binary) prunes the stale subtree and restores the direct link.
        let new = gen_with_apps(1, "p", &[("new", "aa11")]);
        let farm = emit(&store, &new).unwrap();
        assert!(
            !package_assembly_dir(&store, 1, "p").exists(),
            "stale assembly pruned"
        );
        let target = std::fs::read_link(farm.join("new")).unwrap();
        assert!(target.ends_with("store/aa/aa11"));
    }
}
