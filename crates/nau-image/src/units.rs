//! App execution emission — hardened systemd units for nau-built snaps
//! (ADR-0011 step (f), Phase 24a; issue #326 PR 3: the image-build
//! emission half of the former root `units` module — the pure planner
//! and the payload vocabulary live in `nau_core::units`).
//!
//! For every shoot-built app snap staged into an image this module
//! unsquashfses `meta/snap.yaml`, extracts each app's command binary to
//! `/usr/bin/<snap>-<app>`, and — for daemon-bearing apps — emits a
//! hardened unit plus its `multi-user.target.wants` enablement symlink.
//! Emission happens after payload staging and BEFORE root populate +
//! dm-verity: binaries and units must be inside the hashed tree.

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

use nau_core::store::ResolvedSnap;
use nau_infra::command::CommandRunner;

pub use nau_core::units::{
    classify, plan_app, spec_from_payload_app, AppPlan, PayloadSnap, PlugRef, RuntimeClass,
};
// ── Emission (image-build path) ──

/// Emit app runtime for every staged snap into the rootfs at `root`.
///
/// For each payload in `cache_dir` (named `<name>_<rev>_<sha3>.snap`,
/// the sha3-384-verified download): read `meta/snap.yaml`, classify,
/// extract app binaries to `usr/bin/<snap>-<app>`, and write hardened
/// units + enablement symlinks for daemon-bearing apps. Returns every
/// per-app warning for the build log.
///
/// Per-payload problems (missing metadata, unparseable yaml, missing
/// binary) are warn-and-continue — one inert snap never fails an image
/// build. Staged-rootfs write failures are hard errors.
pub fn emit_app_runtime(
    runner: &dyn CommandRunner,
    snaps: &[(String, ResolvedSnap)],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
) -> miette::Result<Vec<String>> {
    if !has_unsquashfs {
        eprintln!(
            "  ⚠ unsquashfs not found — app execution skipped (no binaries, no units emitted)"
        );
        return Ok(Vec::new());
    }

    let mut all_warnings = Vec::new();
    for (name, snap) in snaps {
        let payload = cache_dir.join(format!("{}_{}_{}.snap", name, snap.revision, snap.sha3_384));
        if !payload.exists() {
            eprintln!("  ⚠ {name}: payload missing from cache — app execution skipped");
            continue;
        }
        match emit_one_snap(runner, name, &payload, root) {
            Ok(warnings) => {
                for w in &warnings {
                    eprintln!("  ⚠ {w}");
                }
                all_warnings.extend(warnings);
            }
            Err(e) => {
                eprintln!("  ⚠ {name}: app execution skipped: {e:#}");
            }
        }
    }
    Ok(all_warnings)
}

/// The unsquashfs argv[0] (issue #101 seam): resolved through the tools
/// module (provisioned-first, PATH fallback). A resolution failure means
/// the emit cannot extract — the per-payload skip path reports it.
fn unsquashfs_argv0() -> miette::Result<String> {
    let resolved = nau_infra::tools::resolve(nau_infra::tools::ToolName::Unsquashfs)
        .map_err(|e| miette::miette!("resolve unsquashfs: {e}"))?;
    Ok(match resolved {
        nau_infra::tools::ResolvedTool::Provisioned { path, .. }
        | nau_infra::tools::ResolvedTool::Path { path, .. } => path.to_string_lossy().into_owned(),
    })
}

/// Emit runtime for one payload: classify, extract binaries, write
/// units. Warnings are returned; hard failures mean the rootfs cannot
/// be written and abort the build.
fn emit_one_snap(
    runner: &dyn CommandRunner,
    name: &str,
    payload: &Path,
    root: &Path,
) -> miette::Result<Vec<String>> {
    let work = tempfile::tempdir().map_err(|e| miette::miette!("tempdir: {e}"))?;
    let extract_dir = work.path().join("extract");

    // 1. Read meta/snap.yaml out of the payload (single-file
    //    extraction, same tool + flags as the base-rootfs flow).
    let argv = vec![
        unsquashfs_argv0()?,
        "-no-xattrs".to_string(),
        "-d".to_string(),
        extract_dir.to_string_lossy().into_owned(),
        payload.to_string_lossy().into_owned(),
        "meta/snap.yaml".to_string(),
    ];
    let status = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    let yaml_path = extract_dir.join("meta").join("snap.yaml");
    if status.code != 0 || !yaml_path.exists() {
        return Err(miette::miette!("meta/snap.yaml not extractable"));
    }
    let yaml_text = std::fs::read_to_string(&yaml_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", yaml_path.display()))?;
    let meta: PayloadSnap = serde_yaml::from_str(&yaml_text)
        .map_err(|e| miette::miette!("meta/snap.yaml parse: {e}"))?;

    // 2. Classify — store payloads are skipped with an explicit note.
    let snap_name = meta.name.as_deref().unwrap_or(name);
    match classify(meta.snap_type.as_deref()) {
        RuntimeClass::Infrastructure => return Ok(Vec::new()),
        RuntimeClass::Store => {
            eprintln!(
                "  ℹ {snap_name}: type=store — app execution skipped (store snaps keep \
                 their own runtime)"
            );
            return Ok(Vec::new());
        }
        RuntimeClass::ShootBuilt => {}
    }
    if meta.apps.is_empty() {
        return Ok(Vec::new());
    }

    // 3. Plan every app.
    let snap_plugs: Vec<PlugRef> = meta
        .plugs
        .iter()
        .map(|(plug_name, plug)| plug.to_plug_ref(plug_name))
        .collect();
    let plans: Vec<AppPlan> = meta
        .apps
        .iter()
        .map(|(app_name, app)| {
            let spec = spec_from_payload_app(snap_name, app_name, app, snap_plugs.clone());
            plan_app(&spec)
        })
        .collect();

    // 4. Extract every app binary in one unsquashfs call.
    let mut file_args: Vec<String> = Vec::new();
    for plan in &plans {
        file_args.push(plan.in_snap_binary.clone());
    }
    let mut argv = vec![
        unsquashfs_argv0()?,
        "-no-xattrs".to_string(),
        "-d".to_string(),
        extract_dir.join("files").to_string_lossy().into_owned(),
        payload.to_string_lossy().into_owned(),
    ];
    argv.extend(file_args.iter().cloned());
    let status = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if status.code != 0 {
        return Err(miette::miette!(
            "app binaries not extractable ({} …)",
            file_args.first().map(String::as_str).unwrap_or("?")
        ));
    }
    let files_dir = extract_dir.join("files");
    let bin_dir = root.join("usr").join("bin");
    std::fs::create_dir_all(&bin_dir)
        .into_diagnostic()
        .wrap_err("creating /usr/bin")?;
    for plan in &plans {
        let src = files_dir.join(&plan.in_snap_binary);
        if !src.exists() {
            return Err(miette::miette!(
                "command binary '{}' not found in payload",
                plan.in_snap_binary
            ));
        }
        let dest = bin_dir.join(format!("{}-{}", plan.snap, plan.app));
        std::fs::copy(&src, &dest)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging {}", dest.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
                .into_diagnostic()
                .wrap_err_with(|| format!("chmod 0755 {}", dest.display()))?;
        }
    }

    // 5. Units + enablement for daemon-bearing apps.
    for plan in &plans {
        let Some(unit) = &plan.daemon else {
            // Plain app: binary only, no unit.
            continue;
        };
        let unit_rel = Path::new("usr/lib/systemd/system").join(&unit.unit_name);
        crate::emit::write_unit(root, &unit_rel, &unit.text)?;
        // Build-time enablement: multi-user.target.wants symlink.
        crate::emit::enable_unit(root, "multi-user.target", &unit.unit_name)?;
    }

    Ok(plans.into_iter().flat_map(|p| p.warnings).collect())
}

#[cfg(test)]
mod tests;
