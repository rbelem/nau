//! Rootfs staging + ADR-0019 base-aware resolution (issue #57).

use std::path::Path;

use miette::IntoDiagnostic;
use serde::Deserialize;

use super::*;
use crate::store::{ResolvedSnap, StoreClient};

// ── ADR-0019: base-aware kernel/gadget resolution ──

/// The role an image snap plays; kernel and gadget snaps ride the image
/// base's store track (ADR-0019), base and extra snaps never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapRole {
    Base,
    Kernel,
    Gadget,
    Extra,
}

/// Derive the store channel track from an image base name:
/// "core22" → Some("22"), "core26" → Some("26"); bases without a numeric
/// series ("core", custom bases) derive nothing.
pub(crate) fn base_track(base_name: &str) -> Option<&str> {
    let series = base_name.strip_prefix("core")?;
    if !series.is_empty() && series.bytes().all(|b| b.is_ascii_digit()) {
        Some(series)
    } else {
        None
    }
}

/// Replace the track of a "track/risk" (or bare risk) channel, keeping the
/// risk: "latest/stable" + track "22" → "22/stable"; "stable" → "22/stable".
pub(crate) fn channel_on_track(channel: &str, track: &str) -> String {
    // Mirrors the StoreClient channel parse: one part is a risk, two parts
    // are track/risk.
    let risk = channel.split('/').nth(1).unwrap_or(channel);
    format!("{track}/{risk}")
}

/// The effective store channel for a kernel/gadget image snap (ADR-0019).
///
/// An author-pinned channel (`channel` opt on the pin entry) wins verbatim
/// and marks the override; otherwise the image base's track replaces the
/// default track ("core22" + "latest/stable" → "22/stable" — the
/// `latest` kernel line carries the legacy 4.4 ESM payloads); a base with
/// no numeric series leaves the channel untouched.
///
/// Returns `(channel, override_used)`.
pub(crate) fn image_snap_channel(
    default_channel: &str,
    base_name: &str,
    explicit: Option<&str>,
) -> (String, bool) {
    if let Some(explicit) = explicit {
        return (explicit.to_string(), true);
    }
    match base_track(base_name) {
        Some(track) => (channel_on_track(default_channel, track), false),
        None => (default_channel.to_string(), false),
    }
}

/// The declared `base:` of a downloaded snap's `meta/snap.yaml`, if the
/// metadata carries one.
#[derive(Debug, Deserialize)]
pub(crate) struct PayloadBase {
    #[serde(rename = "base")]
    base: Option<String>,
}

pub(crate) fn snap_yaml_base(yaml_text: &str) -> Option<String> {
    serde_yaml::from_str::<PayloadBase>(yaml_text)
        .ok()
        .and_then(|meta| meta.base)
        .filter(|b| !b.is_empty())
}

/// ADR-0019 backstop: a resolved kernel/gadget snap whose declared base
/// mismatches the image base fails the build, naming both. A snap with no
/// declared base skips the check (and says so) — store metadata quality is
/// outside shuttle's control.
pub(crate) fn check_declared_base(
    role: &str,
    snap_name: &str,
    declared_base: Option<&str>,
    image_base: &str,
) -> miette::Result<()> {
    match declared_base {
        None => {
            eprintln!(
                "  ℹ {role} {snap_name}: declares no base (or meta/snap.yaml unreadable) \
                 — ADR-0019 base check skipped"
            );
            Ok(())
        }
        Some(declared) if declared == image_base => Ok(()),
        Some(declared) => Err(miette::miette!(
            "{role} snap '{snap_name}' declares base '{declared}' but the image base is \
             '{image_base}' — refusing to pair them (ADR-0019): the mismatch is silent at \
             build time and bricks at first boot. To accept it deliberately, pin an \
             explicit channel on the {role} entry, e.g. \
             {role} = pin(\"{snap_name}\", {{ channel = \"latest/stable\" }})"
        )),
    }
}

/// Read the declared `base:` out of a downloaded snap payload by
/// single-file extracting `meta/snap.yaml` (same tool + flags as the
/// runtime emitter). `Ok(None)` means the metadata could not be read or
/// carries no base — the caller logs the skip.
pub(crate) fn payload_declared_base(runner: &dyn CommandRunner, payload: &Path) -> Option<String> {
    let work = tempfile::tempdir().ok()?;
    let extract_dir = work.path().join("extract");
    let argv = vec![
        "unsquashfs".to_string(),
        "-no-xattrs".to_string(),
        "-d".to_string(),
        extract_dir.to_string_lossy().into_owned(),
        payload.to_string_lossy().into_owned(),
        "meta/snap.yaml".to_string(),
    ];
    let out = runner.run(&argv).ok()?;
    if out.code != 0 {
        return None;
    }
    let yaml_text = std::fs::read_to_string(extract_dir.join("meta").join("snap.yaml")).ok()?;
    snap_yaml_base(&yaml_text)
}

/// ADR-0019 enforcement point: after the kernel/gadget payloads are
/// downloaded and hash-verified, their declared `base:` must match the
/// image base (mismatch = build error) or be absent (logged skip). An
/// author-pinned channel is the recorded override for both the track
/// derivation and this check.
pub(crate) fn enforce_base_contract(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    has_unsquashfs: bool,
) -> miette::Result<()> {
    let checks = [
        (
            image.kernel.as_ref().map(|k| k.snap.name.as_str()),
            "kernel",
            image.kernel.as_ref().and_then(|k| k.channel.as_ref()),
        ),
        (
            image.gadget.as_ref().map(|g| g.name.as_str()),
            "gadget",
            image.gadget_channel.as_ref(),
        ),
    ];
    for (entry, role, explicit) in checks {
        let Some(name) = entry else {
            continue;
        };
        if let Some(channel) = explicit {
            eprintln!(
                "  ⚠ {role} {name}: author-pinned channel '{channel}' — ADR-0019 base \
                 check skipped (recorded override)"
            );
            continue;
        }
        if !has_unsquashfs {
            eprintln!(
                "  ⚠ {role} {name}: unsquashfs unavailable — ADR-0019 declared-base \
                 check skipped"
            );
            continue;
        }
        let Some(snap) = resolved.iter().find(|s| s.name == name) else {
            continue;
        };
        let payload = cache_dir.join(format!(
            "{}_{}_{}.snap",
            snap.name, snap.revision, snap.sha3_384
        ));
        let declared_base = payload_declared_base(runner, &payload);
        check_declared_base(role, name, declared_base.as_deref(), &image.base.name)?;
    }
    Ok(())
}

/// Resolve all snaps in an image declaration, using the lockfile for defaults.
///
/// Kernel and gadget snaps resolve from the image base's store track
/// (ADR-0019) unless the author pinned an explicit channel on the entry.
fn resolve_image_snaps(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    lockfile: &LockFile,
    channel: &str,
    arch: &str,
) -> miette::Result<Vec<ResolvedSnap>> {
    let mut resolved = Vec::new();

    let mut entries: Vec<(&SnapRef, SnapRole)> = vec![(&image.base, SnapRole::Base)];
    if let Some(ref k) = image.kernel {
        entries.push((&k.snap, SnapRole::Kernel));
    }
    if let Some(ref g) = image.gadget {
        entries.push((g, SnapRole::Gadget));
    }
    for s in &image.extra_snaps {
        entries.push((s, SnapRole::Extra));
    }

    for (snap_ref, role) in entries {
        let pin = if snap_ref.revision.is_none() || snap_ref.sha3_384.is_none() {
            if let Some(locked) = lockfile.lookup_snap(&snap_ref.name) {
                eprintln!("  ℹ {}: using lockfile pin", snap_ref.name);
                locked
            } else {
                snap_ref.clone()
            }
        } else {
            snap_ref.clone()
        };

        // ADR-0019: kernel/gadget snaps ride the image base's track unless
        // the author pinned an explicit channel on the entry.
        let (effective_channel, override_used) = match role {
            SnapRole::Kernel => image_snap_channel(
                channel,
                &image.base.name,
                image.kernel.as_ref().and_then(|k| k.channel.as_deref()),
            ),
            SnapRole::Gadget => {
                image_snap_channel(channel, &image.base.name, image.gadget_channel.as_deref())
            }
            SnapRole::Base | SnapRole::Extra => (channel.to_string(), false),
        };
        if override_used {
            eprintln!(
                "  ⚠ {}: author-pinned channel '{effective_channel}' — ADR-0019 track \
                 derivation + base check skipped (recorded override)",
                snap_ref.name
            );
        } else if matches!(role, SnapRole::Kernel | SnapRole::Gadget)
            && effective_channel != channel
        {
            eprintln!(
                "  ℹ {}: image base {} → channel {effective_channel} (ADR-0019)",
                snap_ref.name, image.base.name
            );
        }

        // Try Snap Store first, then fall back to package index
        let snap = match StoreClient::resolve_with(runner, &pin, &effective_channel, arch) {
            Ok(s) => s,
            Err(_) => {
                // Try resolving through the package index
                let index_path = std::path::PathBuf::from(crate::index::DEFAULT_INDEX);
                if let Ok(idx) = crate::index::PackageIndex::load_or_default(&index_path) {
                    if let Some(entry) = idx.find_by_name_or_alias(&snap_ref.name) {
                        // Check if the index already has pre-resolved pins for this arch
                        if let Some(ref pins) = entry.pins {
                            if let Some(pin_entry) = pins.get(arch) {
                                eprintln!(
                                    "  ℹ {}: using pre-resolved pin from index (rev {})",
                                    snap_ref.name, pin_entry.revision
                                );
                                resolved.push(ResolvedSnap {
                                    name: snap_ref.name.clone(),
                                    revision: pin_entry.revision,
                                    sha3_384: pin_entry.sha3_384.clone(),
                                    download_url: String::new(),
                                });
                                continue;
                            }
                        }
                        // If index has a store name, try resolving with it.
                        // ADR-0019: the derived track wins over the index's
                        // store channel for kernel/gadget roles too — the
                        // empirical failure came from an index entry
                        // carrying the default `latest` track.
                        if let Some(ref store) = entry.store {
                            let store_name =
                                store.name.as_deref().unwrap_or(&snap_ref.name).to_string();
                            let resolved_pin = SnapRef {
                                name: store_name,
                                revision: pin.revision,
                                sha3_384: pin.sha3_384,
                            };
                            match StoreClient::resolve_with(
                                runner,
                                &resolved_pin,
                                &effective_channel,
                                arch,
                            ) {
                                Ok(s) => {
                                    eprintln!(
                                        "  ℹ {}: resolved via index (store: {})",
                                        snap_ref.name, resolved_pin.name
                                    );
                                    s
                                }
                                Err(e) => {
                                    return Err(miette::miette!(
                                        "cannot resolve '{}': not in Snap Store or package index ({})",
                                        snap_ref.name, e
                                    ));
                                }
                            }
                        } else {
                            return Err(miette::miette!(
                                "cannot resolve '{}': found in index but has no store reference",
                                snap_ref.name
                            ));
                        }
                    } else {
                        return Err(miette::miette!(
                            "cannot resolve '{}': not in Snap Store or package index",
                            snap_ref.name
                        ));
                    }
                } else {
                    return Err(miette::miette!(
                        "cannot resolve '{}': not in Snap Store",
                        snap_ref.name
                    ));
                }
            }
        };

        eprintln!(
            "  ✓ {} revision {} — sha3-384: {}",
            snap.name,
            snap.revision,
            &snap.sha3_384[..16]
        );
        resolved.push(snap);
    }

    Ok(resolved)
}

/// Kernel-payload policy for [`stage_rootfs`] — the ONE behavioral seam
/// between the squashfs-only path (`build_image`) and the disk path
/// (`build_disk_image`), both of which share the staging sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelPayloadPolicy {
    /// `build_image` (squashfs-only output): the kernel merge is
    /// best-effort. A failed kernel unsquashfs (exit >= 128) is skipped
    /// silently, no boot payload is required, and `None` is returned. The
    /// base-extract step also keeps its historical warning-only paths.
    BestEffort,
    /// `build_disk_image`: the kernel merge fails closed on a failed
    /// unsquashfs and requires a locatable boot payload (the UKI needs it).
    Required,
}

/// A fully staged rootfs — the shared result of [`stage_rootfs`]. Owns the
/// build directory (dropping it removes the staged tree) alongside the
/// resolved snaps, the `(name, snap)` pairs the manifest and snap-copy
/// stages consume, and the located kernel boot payload (disk builds only).
pub(crate) struct StagedRootfs {
    /// Keeps the staged rootfs directory alive for the caller; bind it to a
    /// local so the tree is not dropped mid-build.
    pub(crate) build_dir: tempfile::TempDir,
    pub(crate) root: PathBuf,
    pub(crate) resolved: Vec<ResolvedSnap>,
    pub(crate) snap_paths: Vec<(String, ResolvedSnap)>,
    pub(crate) payload: Option<KernelPayload>,
    /// Whether a host `unsquashfs` was found (the disk build threads this
    /// into app-runtime emission).
    pub(crate) has_unsquashfs: bool,
}

/// The ONE shared rootfs-staging sequence (issue #57): resolve every snap
/// (ADR-0019 channels), download + verify each into the content-addressed
/// cache, enforce the ADR-0019 declared-base contract, then extract the base
/// snap as the rootfs foundation and merge the kernel modules/firmware per
/// `policy`. `build_image` and `build_disk_image` both route through here.
pub(crate) fn stage_rootfs(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
    policy: KernelPayloadPolicy,
) -> miette::Result<StagedRootfs> {
    let resolved = resolve_image_snaps(runner, image, lockfile, channel, arch)?;
    let snap_paths = download_and_verify(runner, &resolved, cache_dir)?;

    let has_unsquashfs = runner
        .run(&["which".to_string(), "unsquashfs".to_string()])
        .ok()
        .is_some_and(|o| o.code == 0);

    // ADR-0019: the kernel/gadget payloads must declare the image's base —
    // mismatch fails the build before anything is assembled.
    enforce_base_contract(runner, image, &resolved, cache_dir, has_unsquashfs)?;

    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {e}"))?;
    let root = build_dir.path().to_path_buf();

    let payload = extract_base_and_kernel(
        runner,
        image,
        &resolved,
        cache_dir,
        &root,
        has_unsquashfs,
        policy,
    )?;

    Ok(StagedRootfs {
        build_dir,
        root,
        resolved,
        snap_paths,
        payload,
        has_unsquashfs,
    })
}

/// Download and sha3-384-verify every resolved snap into the cache, returning
/// the `(name, snap)` pairs later stages consume.
pub(crate) fn download_and_verify(
    runner: &dyn CommandRunner,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
) -> miette::Result<Vec<(String, ResolvedSnap)>> {
    let mut snap_paths: Vec<(String, ResolvedSnap)> = Vec::new();
    for snap in resolved {
        let path = StoreClient::download(runner, snap, cache_dir)?;
        StoreClient::verify(&path, &snap.sha3_384)?;
        eprintln!(
            "  ✓ {} revision {} — sha3-384 verified",
            snap.name, snap.revision
        );
        snap_paths.push((snap.name.clone(), snap.clone()));
    }
    Ok(snap_paths)
}

/// Extract the base snap as the rootfs foundation, then merge the kernel
/// snap's modules/firmware. Returns the located kernel boot payload when a
/// kernel is declared AND `policy` requires one; the payload feeds UKI
/// assembly (ADR-0011 step (a)) later in the build.
pub(crate) fn extract_base_and_kernel(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
    policy: KernelPayloadPolicy,
) -> miette::Result<Option<KernelPayload>> {
    extract_base(
        runner,
        image,
        resolved,
        cache_dir,
        root,
        has_unsquashfs,
        policy,
    )?;
    merge_kernel(
        runner,
        image,
        resolved,
        cache_dir,
        root,
        has_unsquashfs,
        policy,
    )
}

/// Base-snap extraction. Message-for-message identical to the historical
/// `build_image` inline code under [`KernelPayloadPolicy::BestEffort`] and to
/// the historical `extract_base_and_kernel` under
/// [`KernelPayloadPolicy::Required`].
fn extract_base(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
    policy: KernelPayloadPolicy,
) -> miette::Result<()> {
    let base_snap = resolved
        .iter()
        .find(|s| s.name == image.base.name)
        .ok_or_else(|| miette::miette!("base snap '{}' not resolved", image.base.name))?;
    let base_filename = format!(
        "{}_{}_{}.snap",
        base_snap.name, base_snap.revision, base_snap.sha3_384
    );
    let base_path = cache_dir.join(&base_filename);

    if has_unsquashfs {
        run_base_unsquashfs(runner, &base_path, root, &image.base.name, policy)?;
    } else if policy == KernelPayloadPolicy::BestEffort {
        eprintln!("  ⚠ unsquashfs not found — base snap not extracted");
    }

    // build_image's historical rootfs sanity echo (disk builds skip it).
    if policy == KernelPayloadPolicy::BestEffort {
        report_rootfs_extracted(root, &image.base.name);
    }
    Ok(())
}

/// Run the base-snap unsquashfs and enforce the policy's failure posture,
/// preserving each path's historical messages exactly.
fn run_base_unsquashfs(
    runner: &dyn CommandRunner,
    base_path: &Path,
    root: &Path,
    base_name: &str,
    policy: KernelPayloadPolicy,
) -> miette::Result<()> {
    eprintln!("  extracting base snap into {:?}", root);
    let argv = vec![
        "unsquashfs".to_string(),
        "-d".to_string(),
        root.to_string_lossy().into_owned(),
        "-no-xattrs".to_string(),
        base_path.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs not found: {e}"))?;
    let exit_code = crate::command::exit_code(&out);
    if exit_code >= 128 {
        return Err(match policy {
            KernelPayloadPolicy::BestEffort => {
                miette::miette!("failed to unsquashfs base snap '{base_name}' (exit {exit_code})")
            }
            KernelPayloadPolicy::Required => {
                miette::miette!("failed to unsquashfs base snap '{base_name}'")
            }
        });
    }
    // build_image's historical warning-only path (disk builds are quiet).
    if policy == KernelPayloadPolicy::BestEffort && exit_code != 0 {
        eprintln!("  ⚠ unsquashfs warnings (exit {exit_code}) — files should be extracted");
    }
    Ok(())
}

/// Echo whether the base snap actually produced a rootfs (best-effort path).
fn report_rootfs_extracted(root: &Path, base_name: &str) {
    if root.join("bin").exists() || root.join("usr").exists() {
        eprintln!("  ✓ rootfs extracted ({base_name})");
    } else {
        eprintln!("  ⚠ no rootfs files found — check unsquashfs");
    }
}

/// Kernel-snap merge. Best-effort under
/// [`KernelPayloadPolicy::BestEffort`] (skip on unsquashfs failure, no
/// payload); fail-closed under [`KernelPayloadPolicy::Required`] (error on
/// unsquashfs failure, require a locatable payload).
fn merge_kernel(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
    policy: KernelPayloadPolicy,
) -> miette::Result<Option<KernelPayload>> {
    // build_image only merged when unsquashfs was available; disk builds
    // attempt unconditionally (and fail closed if it is missing).
    if policy == KernelPayloadPolicy::BestEffort && !has_unsquashfs {
        return Ok(None);
    }
    let Some(kernel_entry) = image.kernel.as_ref() else {
        return Ok(None);
    };
    let Some(ks) = resolved.iter().find(|s| s.name == kernel_entry.snap.name) else {
        return Ok(None);
    };
    let k_filename = format!("{}_{}_{}.snap", ks.name, ks.revision, ks.sha3_384);
    let kpath = cache_dir.join(&k_filename);
    eprintln!("  merging kernel snap: {}", kernel_entry.snap.name);
    // Short-lived extraction scratch; the located payload points into `root`.
    let kernel_work = tempfile::tempdir().map_err(|e| miette::miette!("{e}"))?;
    let kernel_dir = kernel_work.path().join("kernel-snap");
    if !unsquashfs_kernel(runner, &kpath, &kernel_dir, &kernel_entry.snap.name, policy)? {
        return Ok(None);
    }
    copy_kernel_tree(&kernel_dir, root)?;
    // The squashfs-only path never needed a boot payload.
    if policy == KernelPayloadPolicy::BestEffort {
        return Ok(None);
    }
    // Fail closed on a payload that cannot boot the image.
    let payload = locate_kernel_payload(&kernel_dir, root).map_err(|e| {
        miette::miette!(
            "kernel snap '{}': {e}; refusing to build a disk image that cannot boot",
            kernel_entry.snap.name
        )
    })?;
    Ok(Some(payload))
}

/// Run the kernel-snap unsquashfs. Returns `Ok(true)` to continue merging,
/// `Ok(false)` when best-effort policy tolerates the failure, and `Err` when
/// required policy fails closed.
fn unsquashfs_kernel(
    runner: &dyn CommandRunner,
    kpath: &Path,
    kernel_dir: &Path,
    snap_name: &str,
    policy: KernelPayloadPolicy,
) -> miette::Result<bool> {
    let argv = vec![
        "unsquashfs".to_string(),
        "-d".to_string(),
        kernel_dir.to_string_lossy().into_owned(),
        "-no-xattrs".to_string(),
        kpath.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if crate::command::exit_code(&out) < 128 {
        return Ok(true);
    }
    match policy {
        // build_image skipped the merge silently on a failed unsquashfs.
        KernelPayloadPolicy::BestEffort => Ok(false),
        KernelPayloadPolicy::Required => Err(miette::miette!(
            "failed to unsquashfs kernel snap '{snap_name}'"
        )),
    }
}

/// Copy the merged kernel modules/firmware trees into the staged rootfs.
fn copy_kernel_tree(kernel_dir: &Path, root: &Path) -> miette::Result<()> {
    for dir in ["lib/modules", "lib/firmware"] {
        let src = kernel_dir.join(dir);
        let dst = root.join(dir);
        if src.exists() {
            std::fs::create_dir_all(dst.parent().unwrap()).into_diagnostic()?;
            cp_r(&src, &dst)?;
        }
    }
    Ok(())
}
