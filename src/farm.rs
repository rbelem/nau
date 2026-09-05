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

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runtime::{Generation, InstalledPackage, RuntimeStore};

/// The farm directory inside a generation: `<root>/generations/<n>/farm`.
pub const FARM_DIR: &str = "farm";

/// The pod's activation link: `<pod>/current` → `generations/<n>/farm`
/// (relative, mirroring the store's own `active` link convention).
pub const CURRENT_LINK: &str = "current";

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
            // Ticket #11: a confined app's farm entry points at its
            // confined-launcher wrapper (which invokes `shuttle run`),
            // not the raw command binary. This keeps `which`/PATH truthful
            // while the sandbox is set up transparently. The wrapper blob
            // is recorded in `launchers`; effective confinement is the
            // per-app override or the package default.
            let effective_confined = pkg
                .app_confined
                .get(app)
                .or(pkg.confined.as_ref())
                .is_some();
            let target_hash = if effective_confined {
                pkg.launchers.get(app).unwrap_or(hash)
            } else {
                hash
            };
            let (aa, _) = target_hash.split_at(2.min(target_hash.len()));
            let target = format!("../../../store/{aa}/{target_hash}");
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
}
