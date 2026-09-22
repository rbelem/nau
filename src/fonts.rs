//! User-level font activation for pod packages (issue #29 cutover).
//!
//! Font payload packages (the `nerd-fonts-*` pool set) stage their
//! typefaces into the payload's `/usr/share/fonts` tree and declare no
//! `apps` — so the bin farm exposes nothing for them. On the devbox
//! stack their fonts were visible only because the devbox profile's
//! `share/` directory rode `XDG_DATA_DIRS`; retiring devbox-global would
//! silently drop every pod-installed font. This module is the
//! activation surface that closes that gap.
//!
//! The mechanism mirrors the desktop launchers (issue #7,
//! `desktop.rs`): the generation manifest records each package's font
//! files at install time (path under `usr/share/fonts` → sha256), and
//! the emit surfaces them as user-level symlinks into the content
//! store under `$XDG_DATA_HOME/fonts/shuttle-pod-<pod>/<pkg>/…` — the
//! fontconfig-scanned user font directory (the default `fonts.conf`
//! ships `<dir prefix="xdg">fonts</dir>`; subdirectories are scanned
//! recursively). The generation is the versioned source of truth:
//! install/remove/rollback re-emit the target generation's font set,
//! so fonts follow generations exactly like launchers and farm
//! binaries. Nothing is ever written outside user directories.
//!
//! Per-package namespacing (`shuttle-pod-<pod>/<pkg>/`) means two
//! packages shipping the same font file name never collide at the
//! user level — both ship, and fontconfig resolves family conflicts
//! by its own ordering (the same behavior a merged profile prefix has
//! on the devbox/nix side). Withdrawal only ever touches entries
//! under the pod's own namespaced directory.

use std::collections::BTreeMap;

use crate::runtime::{Generation, RuntimeStore};

/// The user-level fonts directory (redirectable for tests), inside the
/// data home the desktop launchers use.
pub fn user_fonts_dir(data_home: &std::path::Path) -> std::path::PathBuf {
    data_home.join("fonts")
}

/// The pod-namespaced directory this emitter owns under the user's
/// fonts directory: `shuttle-pod-<pod>`. The same ownership rule as
/// the desktop entry prefix — withdrawal recognizes only its own
/// subtree, never the user's own fonts or other pods'.
pub fn surface_dir(pod: &str) -> String {
    format!("shuttle-pod-{pod}")
}

/// Emit a generation's font set to the user level. The surface is
/// redirected through [`crate::desktop::user_data_home`]; use
/// [`emit_in`] for an explicit data home (tests).
pub fn emit(store: &RuntimeStore, gen: &Generation) -> miette::Result<()> {
    let data_home = crate::desktop::user_data_home(store.root());
    let pod = crate::desktop::pod_name(store)?;
    emit_in(store, gen, &data_home, &pod)
}

/// [`emit`] with an explicit pod name and data home.
///
/// Rebuilds the pod's namespaced font subtree from scratch on every
/// call (fully idempotent): the subtree is owned by this pod alone, so
/// a full wipe cannot touch other pods' fonts or the user's own.
pub fn emit_in(
    store: &RuntimeStore,
    gen: &Generation,
    data_home: &std::path::Path,
    pod: &str,
) -> miette::Result<()> {
    let surface = user_fonts_dir(data_home).join(surface_dir(pod));

    // Collect first, mutate second: the keep set decides whether the
    // surface exists at all after this emit.
    let mut keep: BTreeMap<&str, Vec<(&str, &str)>> = Default::default();
    for pkg in crate::farm::layered_packages(gen) {
        if pkg.fonts.is_empty() {
            continue;
        }
        keep.insert(pkg.name.as_str(), {
            let mut v: Vec<(&str, &str)> = pkg
                .fonts
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            v.sort();
            v
        });
    }

    if surface.exists() {
        std::fs::remove_dir_all(&surface)
            .map_err(|e| miette::miette!("clearing stale fonts {}: {e}", surface.display()))?;
    }
    if keep.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(&surface)
        .map_err(|e| miette::miette!("creating fonts {}: {e}", surface.display()))?;

    for (pkg_name, files) in &keep {
        link_package_fonts(store, &surface, pkg_name, files)?;
    }
    Ok(())
}

/// Link one package's font files into its surface subtree: recreate the
/// package directory, then symlink every recorded file into the store.
fn link_package_fonts(
    store: &RuntimeStore,
    surface: &std::path::Path,
    pkg_name: &str,
    files: &[(&str, &str)],
) -> miette::Result<()> {
    let pkg_dir = surface.join(pkg_name);
    std::fs::create_dir_all(&pkg_dir)
        .map_err(|e| miette::miette!("creating {}: {e}", pkg_dir.display()))?;
    for (rel, hash) in files {
        let dest_rel = font_rel(rel)?;
        let dest = pkg_dir.join(&dest_rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("creating {}: {e}", parent.display()))?;
        }
        crate::desktop::link_or_replace(&store.blob_path(hash), &dest)?;
    }
    Ok(())
}

/// Validate one recorded font path (relative to the payload's
/// `usr/share/fonts`): a single relative subpath, no `..` escape, no
/// absolute rewrite. A manifest is trusted data, but a corrupted one
/// must fail the emit — never write outside the pod's surface.
fn font_rel(rel: &str) -> miette::Result<String> {
    if rel.is_empty() {
        miette::bail!("font path must not be empty");
    }
    if rel.starts_with('/') {
        miette::bail!("font path must be relative: {rel:?}");
    }
    if rel.split('/').any(|c| c == "..") {
        miette::bail!("font path must not contain '..': {rel:?}");
    }
    Ok(rel.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::farm::ClaimLayer;

    fn store_fixture(dir: &std::path::Path) -> RuntimeStore {
        // The documented pod layout `<data-home>/shuttle/pods/<pod>`:
        // the emitter derives its user-level surface from this shape,
        // so a nested fixture root keeps every write inside the test's
        // tempdir without touching the environment.
        RuntimeStore::new(dir.join("shuttle/pods/pilot"))
    }

    fn gen_with_fonts(n: u64, packages: &[(&str, &[(&str, &str)])]) -> Generation {
        let mut pkgs = std::collections::BTreeMap::new();
        for (name, fonts) in packages {
            pkgs.insert(
                name.to_string(),
                crate::runtime::InstalledPackage {
                    name: name.to_string(),
                    version: "1.0".into(),
                    revision: 1,
                    sha3_384: "abc".into(),
                    files: vec![],
                    units: vec![],
                    layer: ClaimLayer::Own,
                    apps: std::collections::BTreeMap::new(),
                    requires: Vec::new(),
                    launchers: std::collections::BTreeMap::new(),
                    assembly: std::collections::BTreeMap::new(),
                    confined: None,
                    app_confined: std::collections::BTreeMap::new(),
                    desktops: std::collections::BTreeMap::new(),
                    fonts: fonts
                        .iter()
                        .map(|(p, h)| (p.to_string(), h.to_string()))
                        .collect(),
                    services: std::collections::BTreeMap::new(),
                    service_bins: std::collections::BTreeMap::new(),
                    meta_digest: None,
                },
            );
        }
        Generation {
            n,
            base_version: "24.04".into(),
            packages: pkgs,
            created_epoch: 0,
            boot_entry: None,
        }
    }

    fn seed_blob(store: &RuntimeStore, hash: &str, content: &[u8]) -> std::path::PathBuf {
        let blob = store.blob_path(hash);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, content).unwrap();
        blob
    }

    #[test]
    fn emit_links_font_payloads_into_the_user_fonts_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        let blob = seed_blob(&store, "ab12", b"ttf-bytes");
        let gen = gen_with_fonts(
            1,
            &[(
                "nerd-fonts-hack",
                &[("truetype/HackNerdFont-Regular.ttf", "ab12")],
            )],
        );
        emit(&store, &gen).unwrap();
        let link = tmp
            .path()
            .join("fonts/shuttle-pod-pilot/nerd-fonts-hack/truetype/HackNerdFont-Regular.ttf");
        assert!(link.is_file(), "font surface link missing");
        assert_eq!(std::fs::read_link(&link).unwrap(), blob);
        assert_eq!(std::fs::read(&link).unwrap(), b"ttf-bytes");
    }

    #[test]
    fn emit_is_idempotent_and_prunes_stale_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        for hash in ["aa11", "bb22"] {
            seed_blob(&store, hash, b"x");
        }
        let old = gen_with_fonts(1, &[("fonts-a", &[("t/A.ttf", "aa11")])]);
        emit(&store, &old).unwrap();
        let new = gen_with_fonts(2, &[("fonts-b", &[("t/B.ttf", "bb22")]), ("fonts-c", &[])]);
        emit(&store, &new).unwrap();
        let surface = tmp.path().join("fonts/shuttle-pod-pilot");
        assert!(!surface.join("fonts-a").exists(), "stale package pruned");
        assert!(
            surface.join("fonts-b/t/B.ttf").is_file(),
            "fresh package present"
        );
        // A fontless package contributes no directory.
        assert!(!surface.join("fonts-c").exists(), "fontless package absent");
    }

    #[test]
    fn removal_withdraws_the_whole_namespaced_surface() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store_fixture(tmp.path());
        seed_blob(&store, "aa11", b"x");
        let with = gen_with_fonts(1, &[("fonts-a", &[("t/A.ttf", "aa11")])]);
        emit(&store, &with).unwrap();
        let without = gen_with_fonts(2, &[]);
        emit(&store, &without).unwrap();
        assert!(
            !tmp.path().join("fonts/shuttle-pod-pilot").exists(),
            "pod font surface withdrawn"
        );
        // The user's own fonts dir survives.
        assert!(tmp.path().join("fonts").is_dir());
    }

    #[test]
    fn two_pods_surfaces_coexist() {
        let tmp = tempfile::tempdir().unwrap();
        let pilot = RuntimeStore::new(tmp.path().join("shuttle/pods/pilot"));
        let work = RuntimeStore::new(tmp.path().join("shuttle/pods/work"));
        for store in [&pilot, &work] {
            seed_blob(store, "aa11", b"font");
        }
        let gen = gen_with_fonts(1, &[("fonts-a", &[("t/A.ttf", "aa11")])]);
        emit(&pilot, &gen).unwrap();
        emit(&work, &gen).unwrap();
        assert!(tmp.path().join("fonts/shuttle-pod-pilot/fonts-a").is_dir());
        assert!(tmp.path().join("fonts/shuttle-pod-work/fonts-a").is_dir());
    }

    #[test]
    fn font_rel_rejects_escapes() {
        assert!(font_rel("").is_err());
        assert!(font_rel("/etc/passwd").is_err());
        assert!(font_rel("../../escape").is_err());
        assert!(font_rel("truetype/../ok-but-no.ttf").is_err());
        font_rel("truetype/sub/Font.ttf").unwrap();
    }
}
