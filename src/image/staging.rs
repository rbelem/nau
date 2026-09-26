//! Rootfs staging + ADR-0019 base-aware resolution (issue #57).

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
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

/// The unsquashfs argv[0] (issue #101 seam): resolved through the tools
/// module (provisioned-first, PATH fallback).
fn unsquashfs_argv0() -> miette::Result<String> {
    let resolved = crate::tools::resolve(crate::tools::ToolName::Unsquashfs)
        .map_err(|e| miette::miette!("resolve unsquashfs: {e}"))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path.to_string_lossy().into_owned(),
    })
}

/// Read the declared `base:` out of a downloaded snap payload by
/// single-file extracting `meta/snap.yaml` (same tool + flags as the
/// runtime emitter). `Ok(None)` means the metadata could not be read or
/// carries no base — the caller logs the skip.
pub(crate) fn payload_declared_base(runner: &dyn CommandRunner, payload: &Path) -> Option<String> {
    let work = tempfile::tempdir().ok()?;
    let extract_dir = work.path().join("extract");
    let argv = vec![
        unsquashfs_argv0().ok()?,
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
    cache_dir: &Path,
) -> miette::Result<Vec<ResolvedSnap>> {
    let mut resolved = Vec::new();

    // #48/#69: the image path resolves through the index the declaration
    // baked its pins from — SHUTTLE_INDEX_PATH, else package-index.json in
    // the CWD (the same seam the eval worker uses). Loaded once per build.
    let index_path = std::env::var("SHUTTLE_INDEX_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::index::DEFAULT_INDEX));
    let image_index = crate::index::PackageIndex::load_or_default(&index_path).ok();

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

        // #48/#69: a baked, cache-backed index pin wins over a live store
        // query — the build must not silently re-resolve what the
        // declaration pinned (a store-first order races the store's
        // CURRENT revision between builds, so identical pins could produce
        // different images). The store remains the path for anything
        // unpinned or uncached ([`try_index_pin`] returns None on a cache
        // miss while the store is still an option).
        if let Some(idx) = image_index.as_ref() {
            if let Some(entry) = idx.find_by_name_or_alias(&snap_ref.name) {
                if let Some(ref pins) = entry.pins {
                    if let Some(s) = try_index_pin(
                        entry,
                        pins,
                        &snap_ref.name,
                        arch,
                        &effective_channel,
                        cache_dir,
                    ) {
                        resolved.push(s);
                        continue;
                    }
                }
            }
        }

        // Try Snap Store first, then fall back to package index
        let snap = match StoreClient::resolve_with(runner, &pin, &effective_channel, arch) {
            Ok(s) => s,
            Err(_) => {
                // Try resolving through the package index
                if let Some(idx) = image_index.as_ref() {
                    if let Some(entry) = idx.find_by_name_or_alias(&snap_ref.name) {
                        // Issue #69: a pre-resolved index pin is only
                        // trusted on the channel it was resolved FROM —
                        // never on a channel the build derived some other
                        // way. A pin also carries no download URL, so it is
                        // only usable when its payload is already in the
                        // content-addressed cache (the offline path).
                        if let Some(ref pins) = entry.pins {
                            if let Some(s) = try_index_pin(
                                entry,
                                pins,
                                &snap_ref.name,
                                arch,
                                &effective_channel,
                                cache_dir,
                            ) {
                                resolved.push(s);
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

/// Use a pre-resolved index pin for `arch` on `effective_channel`, but only
/// when the pin is trustworthy AND usable (issue #69):
///
/// - the pin must be recorded FOR the channel (keyed `"<arch>@<channel>"`,
///   or a bare pin that itself records a matching channel) — the build
///   never silently uses a pin resolved on some other channel;
/// - the pin carries no download URL, so its payload must already sit in
///   the content-addressed cache, under the local entry name or the store
///   name (a store-named blob is hard-linked to the local name the
///   downstream download/verify step expects). A cache miss falls back to
///   store resolution — it must not fail the build while the store is
///   still reachable.
///
/// Returns `Some(resolved)` when the pin was used; the caller then skips
/// store resolution for this snap.
fn try_index_pin(
    entry: &crate::index::IndexEntry,
    pins: &HashMap<String, crate::index::PinEntry>,
    local_name: &str,
    arch: &str,
    effective_channel: &str,
    cache_dir: &Path,
) -> Option<ResolvedSnap> {
    let Some(pin_entry) = crate::index::PackageIndex::channel_pin(pins, arch, effective_channel)
    else {
        if crate::index::PackageIndex::has_arch_pins(pins, arch) {
            eprintln!(
                "  ⚠ {local_name}: index pins exist but none for channel \
                 '{effective_channel}' — not trusting them (issue #69)"
            );
        }
        return None;
    };

    let local_path = cache_dir.join(format!(
        "{local_name}_{}_{}.snap",
        pin_entry.revision, pin_entry.sha3_384
    ));
    if !local_path.exists() {
        let store_name = entry
            .store
            .as_ref()
            .and_then(|s| s.name.as_deref())
            .unwrap_or(local_name);
        let store_path = cache_dir.join(format!(
            "{store_name}_{}_{}.snap",
            pin_entry.revision, pin_entry.sha3_384
        ));
        if store_path.exists() {
            if let Err(e) = std::fs::hard_link(&store_path, &local_path) {
                eprintln!("  ⚠ could not hard-link {store_path:?} → {local_path:?}: {e}");
                if std::fs::copy(&store_path, &local_path).is_err() {
                    return None;
                }
            }
        } else {
            eprintln!(
                "  ⚠ {local_name}: index pin (rev {}, channel {effective_channel}) is \
                 not in the snap cache — resolving from the store",
                pin_entry.revision
            );
            return None;
        }
    }

    eprintln!(
        "  ℹ {local_name}: using pre-resolved pin from index (rev {}, channel \
         {effective_channel}, cached payload)",
        pin_entry.revision
    );
    Some(ResolvedSnap {
        name: local_name.to_string(),
        revision: pin_entry.revision,
        sha3_384: pin_entry.sha3_384.clone(),
        download_url: String::new(),
    })
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

// ── The host binary ships inside the image (#81) ──

/// Staged-rootfs-relative path the running shuttle binary is embedded at.
///
/// `/usr/bin` is deliberate (#81): the default boot units exec the binary,
/// so it must live inside the hashed (dm-verity) base tree at a pinned,
/// deterministic location — not on a writable partition an A/B flip or a
/// corrupted state disk could take away, and not resolved through PATH.
/// `usr/bin` already hosts the app-command binaries the build materializes
/// ([`crate::units::emit_app_runtime`]), and systemd's own search-path
/// convention puts package binaries there.
///
/// The emitted units exec the ABSOLUTE spelling `/{SHUTTLE_BIN_PATH}`
/// (systemd requires an absolute `ExecStart=`); [`SHUTTLE_BIN_PATH`] is the
/// single source of truth and the `unit_exec_targets_match_the_staged_binary_path`
/// test asserts the two cannot drift.
pub(crate) const SHUTTLE_BIN_PATH: &str = "usr/bin/shuttle";

/// Copy the running shuttle binary into the staged rootfs at
/// [`SHUTTLE_BIN_PATH`] (#81).
///
/// The image build runs inside the shuttle process, so
/// [`std::env::current_exe`] is the exact binary this build was made with —
/// the local build ships itself, no network fetch, no host-path leakage into
/// the image content (the staged file is a copy; the host source path is
/// never written into any image file). Any failure fails the build closed:
/// the emitted boot units exec `/usr/bin/shuttle` by absolute path, so an
/// image whose health path cannot work must never be packed.
///
/// Reproducibility: the staged file carries only the copied bytes and
/// `0755` permissions — the same treatment as every other build-emitted
/// file; `mksquashfs`/`mkfs.ext4` timestamp clamping (SOURCE_DATE_EPOCH)
/// applies to it like to the rest of the tree.
///
/// The source is [`embed_source`]: under `cfg(test)` that is a tiny fixture
/// (the test executable is a 200 MB+ artifact, and copying it into every
/// staged rootfs slows the suite and starves the load-sensitive autotools
/// e2e tests of I/O headroom); in production it is always the running
/// binary — the KVM boot proof pins the real end-to-end behavior.
pub(crate) fn embed_shuttle_binary(
    runner: &dyn CommandRunner,
    root: &Path,
    arch: &str,
) -> miette::Result<()> {
    embed_binary_at(root, &embed_source()?)?;
    anchor_binary_to_guest(runner, &root.join(SHUTTLE_BIN_PATH), arch)
}

/// The dynamic-loader path the guest provides for `arch`.
///
/// The embedded binary must exec inside the IMAGE, whose loader lives at
/// the FHS path — never at a build-host path (the devbox/nix toolchain
/// bakes its own store interpreter into the ELF it produces).
fn guest_interpreter(arch: &str) -> miette::Result<&'static str> {
    match arch {
        "amd64" | "x86_64" => Ok("/lib64/ld-linux-x86-64.so.2"),
        "arm64" | "aarch64" => Ok("/lib/ld-linux-aarch64.so.1"),
        other => Err(miette::miette!(
            "no guest interpreter mapping for arch '{other}' — cannot stage the \
             shuttle binary for the image (issue #81)"
        )),
    }
}

/// Re-anchor the staged shuttle binary to the guest (#81): the generic
/// [`anchor_elf_to_guest`] with the shuttle path as the error label and the
/// host RUNPATH dropped (the guest resolves libc through its own default
/// search path).
fn anchor_binary_to_guest(
    runner: &dyn CommandRunner,
    staged: &Path,
    arch: &str,
) -> miette::Result<()> {
    anchor_elf_to_guest(runner, staged, arch, &format!("/{SHUTTLE_BIN_PATH}"), None)
}

/// Re-anchor a staged ELF to the guest (#81; generalized for the #85
/// bless-boot tooling by the `label` and `rpath` parameters).
///
/// A devbox/nix-built ELF requests its interpreter from the build host's
/// store (`/nix/store/…/ld-linux-…`) and carries that store in RUNPATH —
/// paths that do not exist inside the image, where the exec would fail with
/// the exact "No such file or directory" #81 closes. When the staged file's
/// interpreter is not already the guest's standard path, `patchelf`
/// (already part of this repo's toolchain, `snap.rs` ELF repair) rewrites it
/// to [`guest_interpreter`] — unprivileged, deterministic, and strictly
/// REMOVING host paths from the image. `rpath` decides the RUNPATH rewrite:
/// `None` drops it (the guest's own libraries resolve through the default
/// search path), `Some(dir)` points it at a guest directory the file's
/// dependencies were staged into. A file patchelf cannot parse (static
/// binary, test fixture) needs no anchoring and is skipped with a note.
fn anchor_elf_to_guest(
    runner: &dyn CommandRunner,
    staged: &Path,
    arch: &str,
    label: &str,
    rpath: Option<&str>,
) -> miette::Result<()> {
    let guest = guest_interpreter(arch)?;
    let staged_str = staged.to_string_lossy().into_owned();
    let has_patchelf = runner
        .run(&["which".to_string(), "patchelf".to_string()])
        .ok()
        .is_some_and(|o| o.code == 0);

    let out = match runner.run(&[
        "patchelf".to_string(),
        "--print-interpreter".to_string(),
        staged_str.clone(),
    ]) {
        Ok(out) => out,
        Err(e) if !has_patchelf => {
            return Err(miette::miette!(
                "patchelf is required to stage {label} into the image (#81): \
                 the build-host ELF must be re-anchored to the guest loader \
                 before it can exec on-device. Install patchelf (devbox ships \
                 it) and rebuild: {e}"
            ));
        }
        Err(e) => {
            return Err(miette::miette!("cannot inspect {label} with patchelf: {e}"));
        }
    };
    if crate::command::exit_code(&out) != 0 {
        eprintln!("  ℹ {label}: not a dynamically linked ELF — no guest anchoring needed");
        return Ok(());
    }
    let current = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if current == guest {
        // The loader is already the guest's, but the RUNPATH rewrite is the
        // caller's contract too (rpath: #85). Reaching here with a requested
        // rpath still applies it.
        apply_rpath_only(runner, &staged_str, label, rpath, has_patchelf)?;
        return Ok(());
    }
    rewrite_interpreter(
        runner,
        &staged_str,
        label,
        arch,
        &current,
        rpath,
        has_patchelf,
    )?;
    eprintln!("  ✓ {label} anchored to the guest loader '{guest}' (was '{current}')");
    Ok(())
}

/// Apply only the RUNPATH contract: `Some(dir)` is set, `None` is a no-op.
fn apply_rpath_only(
    runner: &dyn CommandRunner,
    staged_str: &str,
    label: &str,
    rpath: Option<&str>,
    has_patchelf: bool,
) -> miette::Result<()> {
    let Some(dir) = rpath else {
        return Ok(());
    };
    if !has_patchelf {
        return Err(miette::miette!(
            "{label} needs its RUNPATH set to '{dir}' for the guest to resolve \
             its dependencies, and patchelf is unavailable — refusing to ship \
             an image whose boot tooling cannot load (#85). Install patchelf \
             (devbox ships it) and rebuild."
        ));
    }
    let out = runner
        .run(&[
            "patchelf".to_string(),
            "--set-rpath".to_string(),
            dir.to_string(),
            staged_str.to_string(),
        ])
        .map_err(|e| miette::miette!("patchelf failed: {e}"))?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "patchelf could not set the RUNPATH of {label} to '{dir}' — \
             refusing to ship a binary whose dependencies cannot resolve in \
             the guest (#85)"
        ));
    }
    eprintln!("  ✓ {label} RUNPATH set to '{dir}' (#85)");
    Ok(())
}

/// The interpreter differs from the guest's: rewrite it, applying the
/// caller's RUNPATH decision in the same patchelf pass.
fn rewrite_interpreter(
    runner: &dyn CommandRunner,
    staged_str: &str,
    label: &str,
    arch: &str,
    current: &str,
    rpath: Option<&str>,
    has_patchelf: bool,
) -> miette::Result<()> {
    let guest = guest_interpreter(arch)?;
    if !has_patchelf {
        return Err(miette::miette!(
            "{label} requests interpreter '{current}', which does not exist in \
             the image, and patchelf is unavailable to re-anchor it to \
             '{guest}' — the staged binary would be inert on-device (#81). \
             Install patchelf (devbox ships it) and rebuild."
        ));
    }
    let mut argv = vec![
        "patchelf".to_string(),
        "--set-interpreter".to_string(),
        guest.to_string(),
    ];
    match rpath {
        Some(dir) => {
            argv.push("--set-rpath".to_string());
            argv.push(dir.to_string());
        }
        None => argv.push("--remove-rpath".to_string()),
    }
    argv.push(staged_str.to_string());
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("patchelf failed: {e}"))?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "patchelf could not re-anchor {label} to '{guest}' — refusing to \
             ship a binary the guest cannot exec (#81)"
        ));
    }
    Ok(())
}

/// The bytes staged at [`SHUTTLE_BIN_PATH`]: the running shuttle binary
/// (production), a small fixture under test.
#[cfg(test)]
fn embed_source() -> miette::Result<PathBuf> {
    static FIXTURE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    let path = FIXTURE.get_or_init(|| {
        let dir =
            std::env::temp_dir().join(format!("shuttle-embed-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create embed fixture dir");
        let file = dir.join("shuttle");
        std::fs::write(&file, b"\x7fELF-shuttle-embed-fixture").expect("write embed fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
                .expect("set embed fixture mode");
        }
        file
    });
    Ok(path.clone())
}

/// The production [`embed_source`]: the running shuttle binary itself.
#[cfg(not(test))]
fn embed_source() -> miette::Result<PathBuf> {
    std::env::current_exe().map_err(|e| {
        miette::miette!(
            "cannot locate the running shuttle binary to embed at /{SHUTTLE_BIN_PATH} \
             (issue #81): {e}"
        )
    })
}

// ── The bless-boot tooling the base may lack (#85) ──

/// Guest-relative install path of the `systemd-bless-boot` helper (#85).
///
/// This is the path [`super::boot::BLESS_BOOT_EXEC`] execs (a drift-pin test
/// asserts the two cannot diverge). `usr/lib/systemd/` is the FHS install
/// directory upstream's own unit uses.
pub(crate) const BLESS_BOOT_TOOLING_BIN_PATH: &str = "usr/lib/systemd/systemd-bless-boot";

/// Guest-relative install path of the `systemd-bless-boot-generator` (#85).
///
/// `usr/lib/systemd/system-generators/` is where systemd runs boot
/// generators from; this is the generator that pulls
/// `systemd-bless-boot.service` into the transaction of a COUNTED boot (the
/// stock mechanism, `systemd-bless-boot-generator(8)`).
pub(crate) const BLESS_BOOT_TOOLING_GENERATOR_PATH: &str =
    "usr/lib/systemd/system-generators/systemd-bless-boot-generator";

/// The guest directory the staged tooling's RUNPATH points at when its
/// `libsystemd-shared-<major>.so` had to be shipped from the build host (#85).
pub(crate) const BLESS_BOOT_TOOLING_LIB_DIR: &str = "/usr/lib/systemd";

/// The multiarch triplet an image arch's libraries live under (#85 glibc
/// gate: the tooling must be checked against the libc of its OWN arch).
fn multiarch_triplet(arch: &str) -> Option<&'static str> {
    match arch {
        "amd64" | "x86_64" => Some("x86_64-linux-gnu"),
        "arm64" | "aarch64" => Some("aarch64-linux-gnu"),
        _ => None,
    }
}

/// Build-host override naming a directory that carries the host's own
/// `systemd-bless-boot` (and, alongside it, `system-generators/
/// systemd-bless-boot-generator` and `libsystemd-shared-<major>.so`). For
/// hosts whose tooling is installed outside the probed defaults.
pub(crate) const BLESS_BOOT_TOOLING_DIR_ENV: &str = "SHUTTLE_BLESS_BOOT_DIR";

/// Ship the `systemd-bless-boot` helper and its boot generator into the
/// staged rootfs when the base does not provide them (#85).
///
/// The core26 base (measured: `core26_462`, systemd 259) ships
/// `boot-complete.target` and the counted-boot protocol but **neither**
/// binary — so on UC26 a counted boot (the normal state after the first
/// sysupdate install) could never be blessed: the generator that pulls the
/// bless service is absent, and even a hand-pulled service would exec a
/// missing `/usr/lib/systemd/systemd-bless-boot`. Every UC22-era base
/// (measured: core22 2437/2955) ships both, so the fast path is
/// "already there — touch nothing".
///
/// When staging is needed, the source is the BUILD HOST's own systemd
/// tooling, and every step fails closed:
///
/// 1. **arch-aware**: the ELF `e_machine` of each host binary must match
///    the image's target arch — a cross-arch build cannot ship host-arch
///    tooling and fails with a named error.
/// 2. **version-gated** against the #79 floor: the host binary reports its
///    own version (`--version`; a host binary may be executed by the host)
///    and must be ≥ [`super::boot::BOOT_ASSESSMENT_MIN_MAJOR`].
/// 3. **runnable in the guest**: the `libsystemd-shared-<major>.so` the
///    binaries link is resolved IN THE GUEST when the base carries the same
///    major (RUNPATH → that directory); otherwise the host's copy is staged
///    into [`BLESS_BOOT_TOOLING_LIB_DIR`] — a self-consistent pair, since
///    `libsystemd-shared` is not a stable ABI across majors. The guest's
///    glibc must define every `GLIBC_*` symbol version the staged host ELFs
///    request (the #80 lesson: a nix toolchain needs glibc ≥ 2.36's
///    `GLIBC_ABI_GNU2_TLS`, which the core22 guest's 2.35 lacks — an
///    inert-at-boot binary must fail the BUILD, not the first bless).
///
/// Runs BEFORE the rootfs is hashed (same write-before-verity contract as
/// every other staged file). Called from the same step-5c gate that emits
/// the boot assessment.
pub(crate) fn stage_bless_boot_binaries(
    runner: &dyn CommandRunner,
    root: &Path,
    arch: &str,
) -> miette::Result<()> {
    // Fast path: the base ships its own tooling — touch nothing.
    if root.join(BLESS_BOOT_TOOLING_BIN_PATH).is_file()
        && root.join(BLESS_BOOT_TOOLING_GENERATOR_PATH).is_file()
    {
        eprintln!("  ✓ base ships its own systemd-bless-boot tooling — nothing staged (#85)");
        return Ok(());
    }

    let (bless, generator) = locate_host_bless_tooling(runner).wrap_err_with(|| {
        "boot assessment is emitted but the bless-boot tooling cannot be \
         provided (#85, gate #79): the base rootfs ships neither \
         systemd-bless-boot nor its generator, and the build host has no \
         usable systemd tooling to ship — install the host's systemd tooling \
         or point SHUTTLE_BLESS_BOOT_DIR at it"
    })?;
    bless_tooling_arch_gate(&bless, &generator, arch)?;
    let major = bless_tooling_version(runner, &bless)?;

    let (rpath, host_lib) = resolve_tooling_lib(runner, root, &bless, major)?;
    let gated_elfs = gated_tooling_elfs(&bless, &generator, host_lib.as_ref());
    assert_guest_libc_covers(root, arch, &gated_elfs)?;
    stage_bless_binaries(runner, root, arch, &bless, &generator, &rpath)?;
    eprintln!(
        "  ✓ shipped systemd-bless-boot + its generator from the build host's \
         systemd tooling (major {major}) (#85)"
    );
    Ok(())
}

/// The #85 arch gate: both host binaries must be ELFs for the image's
/// target arch — cross-arch tooling cannot be staged.
fn bless_tooling_arch_gate(bless: &Path, generator: &Path, arch: &str) -> miette::Result<()> {
    let want = machine_for_arch(arch)?;
    for path in [bless, generator] {
        let got = elf_machine(path).wrap_err_with(|| {
            format!("inspecting the host bless-boot tooling {}", path.display())
        })?;
        if got != want {
            return Err(miette::miette!(
                "the host's bless-boot tooling ({}, {}) is ELF machine {got} \
                 but the image targets arch '{arch}' (machine {want}) — \
                 cross-arch tooling cannot be staged (#85). Point \
                 {BLESS_BOOT_TOOLING_DIR_ENV} at tooling built for '{arch}'.",
                bless.display(),
                generator.display(),
            ));
        }
    }
    Ok(())
}

/// The #85 version gate: read the host tooling's own version
/// (`--version`; a host binary may be executed by the host) and require
/// the #79 floor.
fn bless_tooling_version(runner: &dyn CommandRunner, bless: &Path) -> miette::Result<u32> {
    let out = runner
        .run(&[
            bless.to_string_lossy().into_owned(),
            "--version".to_string(),
        ])
        .map_err(|e| {
            miette::miette!(
                "cannot run the host's systemd-bless-boot ({}) to read its \
                 version — the tooling must be executable on the build host \
                 to be gated (#85): {e}",
                bless.display()
            )
        })?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "the host's systemd-bless-boot ({}) exited {} on --version — \
             refusing to stage tooling whose version cannot be proven (#85, \
             gate #79)",
            bless.display(),
            crate::command::exit_code(&out),
        ));
    }
    let major = systemd_major_from_version_output(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| {
            miette::miette!(
                "cannot parse a systemd major from the host's bless-boot \
                 --version output ({:?}) — refusing to stage ungated tooling \
                 (#85, gate #79)",
                String::from_utf8_lossy(&out.stdout).trim()
            )
        })?;
    if major < super::boot::BOOT_ASSESSMENT_MIN_MAJOR {
        return Err(miette::miette!(
            "the host's bless-boot tooling is systemd major {major}, below the \
             boot-assessment floor {} — refusing to stage tooling the #79 gate \
             cannot vouch for (#85)",
            super::boot::BOOT_ASSESSMENT_MIN_MAJOR,
        ));
    }
    if let Some(warning) = super::boot::bless_boot_busy_warning(major) {
        eprintln!("  ⚠ {warning}");
    }
    Ok(major)
}

/// Resolve the libsystemd-shared the staged binaries link, returning the
/// guest directory their RUNPATH must point at plus the staged host lib
/// (when one was copied — it joins the glibc coverage gate) (#85).
///
/// When the guest's own shared lib carries the SAME major, the tooling is
/// pointed at it (no duplication). Otherwise the host's copy is staged into
/// [`BLESS_BOOT_TOOLING_LIB_DIR`] — a self-consistent pair, since
/// `libsystemd-shared` is not a stable ABI across majors.
fn resolve_tooling_lib(
    runner: &dyn CommandRunner,
    root: &Path,
    bless: &Path,
    major: u32,
) -> miette::Result<(String, Option<PathBuf>)> {
    if let Some((_, path)) = super::boot::base_systemd_shared_lib(root).filter(|(m, _)| *m == major)
    {
        let dir = match path.strip_prefix(root) {
            Ok(rel) => match rel.parent() {
                Some(parent_dir) => format!("/{}", parent_dir.to_string_lossy()),
                None => BLESS_BOOT_TOOLING_LIB_DIR.to_string(),
            },
            Err(_) => BLESS_BOOT_TOOLING_LIB_DIR.to_string(),
        };
        eprintln!(
            "  ✓ guest's own libsystemd-shared-{major}.so resolves the staged \
             tooling (RUNPATH → {dir}) (#85)"
        );
        return Ok((dir, None));
    }
    let host_lib = find_host_shared_lib(bless, major).ok_or_else(|| {
        miette::miette!(
            "no libsystemd-shared-{major}.so found next to the host's bless-boot \
             tooling ({}) — the staged binaries would be inert on-device (#85)",
            bless.display()
        )
    })?;
    copy_into_root(root, &host_lib, "usr/lib/systemd", 0o644)?;
    let lib_name = host_lib.file_name().expect("shared lib has a file name");
    let staged_lib = root
        .join(BLESS_BOOT_TOOLING_LIB_DIR.trim_start_matches('/'))
        .join(lib_name);
    // Drop the host RUNPATH (nix store paths): the staged lib's own NEEDED
    // (libc/libm) resolve through the guest's default search path. A shared
    // library carries no PT_INTERP, so this is a direct RUNPATH rewrite —
    // not the interpreter anchoring the executables get.
    let out = runner
        .run(&[
            "patchelf".to_string(),
            "--remove-rpath".to_string(),
            staged_lib.to_string_lossy().into_owned(),
        ])
        .map_err(|e| miette::miette!("patchelf failed: {e}"))?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "patchelf could not strip the host RUNPATH from the staged \
             libsystemd-shared-{major}.so — refusing to ship host store paths \
             inside the image (#85)"
        ));
    }
    eprintln!(
        "  ✓ staged host libsystemd-shared-{major}.so next to the tooling, host \
         RUNPATH stripped (self-consistent pair, #85)"
    );
    Ok((BLESS_BOOT_TOOLING_LIB_DIR.to_string(), Some(staged_lib)))
}

/// The host-sourced ELFs the glibc coverage gate must vouch for: the two
/// binaries plus, when staged, the host shared lib (#85).
fn gated_tooling_elfs(bless: &Path, generator: &Path, host_lib: Option<&PathBuf>) -> Vec<PathBuf> {
    let mut elfs = vec![bless.to_path_buf(), generator.to_path_buf()];
    if let Some(lib) = host_lib {
        elfs.push(lib.clone());
    }
    elfs
}

/// Stage the two binaries at their pinned paths (0755) and anchor them to
/// the guest loader with the resolved RUNPATH.
fn stage_bless_binaries(
    runner: &dyn CommandRunner,
    root: &Path,
    arch: &str,
    bless: &Path,
    generator: &Path,
    rpath: &str,
) -> miette::Result<()> {
    for (source, rel) in [
        (bless, BLESS_BOOT_TOOLING_BIN_PATH),
        (generator, BLESS_BOOT_TOOLING_GENERATOR_PATH),
    ] {
        copy_into_root(root, source, rel, 0o755)?;
        anchor_elf_to_guest(
            runner,
            &root.join(rel),
            arch,
            &format!("/{rel}"),
            Some(rpath),
        )?;
    }
    Ok(())
}

/// Locate the build host's `systemd-bless-boot` and its generator.
///
/// Priority: the [`BLESS_BOOT_TOOLING_DIR_ENV`] override, `which` (through
/// the command seam), then the FHS install paths (`/usr/lib/systemd`,
/// `/lib/systemd` and their `system-generators/` subdirs). Not finding both
/// is the #85/#79 fail-closed case — the error names every probed location.
fn locate_host_bless_tooling(runner: &dyn CommandRunner) -> miette::Result<(PathBuf, PathBuf)> {
    let env_dir = std::env::var_os(BLESS_BOOT_TOOLING_DIR_ENV).map(PathBuf::from);

    let mut bin_dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = &env_dir {
        bin_dirs.push(dir.clone());
    }
    if let Some(hit) = which(runner, "systemd-bless-boot") {
        bin_dirs.push(
            hit.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/usr/lib/systemd")),
        );
    }
    bin_dirs.push(PathBuf::from("/usr/lib/systemd"));
    bin_dirs.push(PathBuf::from("/lib/systemd"));

    let bless = bin_dirs
        .iter()
        .map(|dir| dir.join("systemd-bless-boot"))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            miette::miette!(
                "no systemd-bless-boot on the build host: probed {} (from \
                 {BLESS_BOOT_TOOLING_DIR_ENV}), `which systemd-bless-boot`, and \
                 the FHS paths /usr/lib/systemd/ and /lib/systemd/. A base that \
                 lacks the tooling cannot emit boot assessment without it — \
                 install the host's systemd tooling or set \
                 {BLESS_BOOT_TOOLING_DIR_ENV} (#85).",
                env_dir
                    .as_ref()
                    .map(|d| d.display().to_string())
                    .unwrap_or_else(|| "no override dir".to_string()),
            )
        })?;
    let generator = locate_generator(runner, env_dir.as_ref(), &bless)?;
    Ok((bless, generator))
}

/// Locate the generator sibling of a found `systemd-bless-boot` binary:
/// the env dir, the binary dir (and its `system-generators/` subdir),
/// `which`, then the FHS generator paths.
fn locate_generator(
    runner: &dyn CommandRunner,
    env_dir: Option<&PathBuf>,
    bless: &Path,
) -> miette::Result<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = env_dir {
        dirs.push(dir.clone());
        dirs.push(dir.join("system-generators"));
    }
    if let Some(bin_dir) = bless.parent() {
        dirs.push(bin_dir.to_path_buf());
        dirs.push(bin_dir.join("system-generators"));
    }
    dirs.push(PathBuf::from("/usr/lib/systemd/system-generators"));
    dirs.push(PathBuf::from("/lib/systemd/system-generators"));
    dirs.iter()
        .map(|dir| dir.join("systemd-bless-boot-generator"))
        .find(|candidate| candidate.is_file())
        .or_else(|| which(runner, "systemd-bless-boot-generator"))
        .ok_or_else(|| {
            miette::miette!(
                "no systemd-bless-boot-generator on the build host: probed the \
                 tooling dir and its system-generators/, `which`, \
                 /usr/lib/systemd/system-generators/ and \
                 /lib/systemd/system-generators/ — a counted boot has nothing \
                 to pull the bless service into the transaction (#85)."
            )
        })
}

/// `which <name>` through the command seam; `None` when not found (the
/// resolved path is read from stdout — an empty one is not a hit).
fn which(runner: &dyn CommandRunner, name: &str) -> Option<PathBuf> {
    let out = runner.run(&["which".to_string(), name.to_string()]).ok()?;
    if crate::command::exit_code(&out) != 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(PathBuf::from(path))
}

/// The ELF `e_machine` of a host binary (u16 at offset 0x12, file
/// endianness), for the #85 arch gate.
fn elf_machine(path: &Path) -> miette::Result<u16> {
    let bytes = std::fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    if bytes.len() < 0x14 || &bytes[0..4] != b"\x7fELF" {
        return Err(miette::miette!(
            "{} is not an ELF binary — it cannot be staged as guest tooling (#85)",
            path.display()
        ));
    }
    let (lo, hi) = (bytes[0x12], bytes[0x13]);
    Ok(match bytes[5] {
        1 => u16::from_le_bytes([lo, hi]),
        2 => u16::from_be_bytes([lo, hi]),
        other => {
            return Err(miette::miette!(
                "{} carries an unknown ELF data encoding ({other}) (#85)",
                path.display()
            ))
        }
    })
}

/// The ELF `e_machine` value an image arch must match (#85 arch gate).
fn machine_for_arch(arch: &str) -> miette::Result<u16> {
    match arch {
        "amd64" | "x86_64" => Ok(62),   // EM_X86_64
        "arm64" | "aarch64" => Ok(183), // EM_AARCH64
        other => Err(miette::miette!(
            "no ELF machine mapping for arch '{other}' — cannot gate the \
             bless-boot tooling for it (#85)"
        )),
    }
}

/// Parse the systemd major from a `systemd-bless-boot --version` first line
/// ("systemd 261 (261.2)").
fn systemd_major_from_version_output(output: &str) -> Option<u32> {
    let mut tokens = output.lines().next()?.split_whitespace();
    if tokens.next()? != "systemd" {
        return None;
    }
    tokens.next()?.parse::<u32>().ok()
}

/// The host `libsystemd-shared-<major>.so` for `major`, searched next to the
/// bless binary and in the sibling multiarch/systemd dirs a distro layout
/// may use. `None` fails the build at the caller.
fn find_host_shared_lib(bless: &Path, major: u32) -> Option<PathBuf> {
    let name = format!("{}{major}.so", super::boot::SYSTEMD_SHARED_LIB_PREFIX);
    let bin_dir = bless.parent()?;
    let mut dirs: Vec<PathBuf> = vec![bin_dir.to_path_buf()];
    if let Some(parent) = bin_dir.parent() {
        dirs.push(parent.join("systemd"));
        if let Ok(read) = std::fs::read_dir(parent) {
            let mut multiarch: Vec<PathBuf> = read
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains("-linux-"))
                })
                .map(|p| p.join("systemd"))
                .collect();
            dirs.append(&mut multiarch);
        }
    }
    dirs.iter()
        .map(|dir| dir.join(&name))
        .find(|candidate| candidate.is_file())
}

/// Copy `source` into `root/<rel>` (when `rel` is a directory, under its
/// file name) with an explicit mode — the fixed-permission shape
/// [`embed_binary_at`] uses, for the #85 tooling staging.
fn copy_into_root(root: &Path, source: &Path, rel: &str, mode: u32) -> miette::Result<()> {
    let target = root.join(rel);
    let dest = if target.is_dir() {
        target.join(source.file_name().expect("source has a file name"))
    } else {
        target
    };
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(source, &dest)
        .into_diagnostic()
        .wrap_err_with(|| format!("staging {} → {}", source.display(), dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
            .into_diagnostic()
            .wrap_err_with(|| format!("setting mode {mode:o} on {}", dest.display()))?;
    }
    Ok(())
}

/// Every `GLIBC_2.x` / `GLIBC_ABI_*` symbol-version name the ELF requests
/// (byte scan of `.gnu.version_r` content — static, no foreign exec).
fn needed_glibc_versions(bytes: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"GLIBC_2.") {
            if bytes.len() > i + 8 && bytes[i + 8].is_ascii_digit() {
                let start = i;
                i += 8;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                found.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
            } else {
                i += 1;
            }
        } else if bytes[i..].starts_with(b"GLIBC_ABI_") {
            let start = i;
            i += 10;
            while i < bytes.len()
                && (bytes[i].is_ascii_uppercase() || bytes[i].is_ascii_digit() || bytes[i] == b'_')
            {
                i += 1;
            }
            found.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
        } else {
            i += 1;
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The staged rootfs's own `libc.so.6` for the image's arch (the multiarch
/// dir spelled by [`multiarch_triplet`] first — a core26 base also ships an
/// i386 libc, which must NOT answer for an amd64 tooling check — then the
/// legacy spellings).
fn guest_libc_path(root: &Path, arch: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(triplet) = multiarch_triplet(arch) {
        candidates.push(root.join("usr/lib").join(triplet));
        candidates.push(root.join("lib").join(triplet));
    }
    for base in ["usr/lib", "lib"] {
        let dir = root.join(base);
        if let Ok(read) = std::fs::read_dir(&dir) {
            let mut multiarch: Vec<PathBuf> = read
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains("-linux-"))
                })
                .collect();
            candidates.append(&mut multiarch);
        }
        candidates.push(dir);
    }
    candidates.push(root.join("lib64"));
    candidates.push(root.join("usr/lib64"));
    candidates
        .iter()
        .map(|dir| dir.join("libc.so.6"))
        .find(|candidate| candidate.is_file())
}

/// Fail closed when any staged host ELF requests a `GLIBC_*` version the
/// guest's own libc does not define — the static, build-time form of the
/// #80 lesson (a tooling binary the guest cannot load must never be
/// shipped). An undeterminable guest libc fails closed too (#79 posture).
fn assert_guest_libc_covers(root: &Path, arch: &str, host_elfs: &[PathBuf]) -> miette::Result<()> {
    let libc = guest_libc_path(root, arch).ok_or_else(|| {
        miette::miette!(
            "no libc.so.6 for arch '{arch}' found in the staged rootfs — the \
             guest's glibc version cannot be proven statically, so the staged \
             bless-boot tooling cannot be gated (#85). Failing closed."
        )
    })?;
    let libc_bytes = std::fs::read(&libc)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", libc.display()))?;
    for elf in host_elfs {
        let bytes = std::fs::read(elf)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", elf.display()))?;
        for version in needed_glibc_versions(&bytes) {
            if !libc_bytes
                .windows(version.len())
                .any(|window| window == version.as_bytes())
            {
                return Err(miette::miette!(
                    "the staged bless-boot tooling ({}) requests GLIBC symbol \
                     version {version}, which the guest's libc ({}) does not \
                     define — the tooling would be inert on-device (#85, the \
                     #80 GLIBC_ABI_GNU2_TLS lesson). Ship tooling built for a \
                     glibc the guest provides.",
                    elf.display(),
                    libc.display(),
                ));
            }
        }
    }
    Ok(())
}

/// [`embed_shuttle_binary`] with an explicit source file — the seam the
/// unit tests drive. Copies `source` to `root/usr/bin/shuttle`, mode `0755`.
/// Stage the image declaration's `files =` entries verbatim into the
/// staged rootfs (#80). Runs before the rootfs is hashed, so dm-verity
/// covers every declared file. Fails closed: a missing source, an
/// unreadable file, or a dest that escapes the staged root aborts the
/// build — an image that silently dropped a declared file would boot
/// without the tooling it declared.
pub(crate) fn stage_extra_files(root: &Path, files: &[StagedFile]) -> miette::Result<()> {
    for file in files {
        stage_one_file(root, file)?;
    }
    Ok(())
}

/// Stage one `files =` entry: copy `source` into the staged root at the
/// absolute guest path `dest`, mirroring the source's permission mode
/// (the exec bit must survive for staged executables).
fn stage_one_file(root: &Path, file: &StagedFile) -> miette::Result<()> {
    let rel = file
        .dest
        .strip_prefix('/')
        .expect("dest validated absolute at parse time");
    let dest = root.join(rel);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    ensure_inside_root(root, &dest, &file.dest)?;
    let bytes = std::fs::read(&file.source)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading files[].source {}", file.source.display()))?;
    std::fs::write(&dest, &bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("staging {} → /{rel}", file.source.display()))?;
    mirror_source_mode(&file.source, &dest, rel)?;
    eprintln!("  ✓ staged file: /{rel} ← {}", file.source.display());
    Ok(())
}

/// Defense in depth beyond the parse-time `..` check: resolve the
/// destination through any existing symlinks and refuse anything that
/// lands outside the staged root (e.g. a base-shipped `/lib → usr/lib`
/// symlink under a declared `/lib/...` dest).
fn ensure_inside_root(root: &Path, dest: &Path, declared: &str) -> miette::Result<()> {
    let canonical_root = root
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("canonicalizing staged root {}", root.display()))?;
    let canonical_parent = dest
        .parent()
        .expect("dest has a parent after create_dir_all")
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("resolving {}", dest.display()))?;
    let resolved = canonical_parent.join(dest.file_name().expect("dest has a file name"));
    if !resolved.starts_with(&canonical_root) {
        return Err(miette::miette!(
            "files[].dest {declared:?} escapes the staged root — refusing to stage"
        ));
    }
    Ok(())
}

/// Copy the source file's permission bits onto the staged copy.
fn mirror_source_mode(source: &Path, dest: &Path, rel: &str) -> miette::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(source)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o644);
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode))
            .into_diagnostic()
            .wrap_err_with(|| format!("setting mode on /{rel}"))?;
    }
    let _ = (source, dest, rel);
    Ok(())
}

pub(crate) fn embed_binary_at(root: &Path, source: &Path) -> miette::Result<()> {
    let dest = root.join(SHUTTLE_BIN_PATH);
    std::fs::create_dir_all(dest.parent().expect("usr/bin has a parent"))
        .into_diagnostic()
        .wrap_err_with(|| format!("creating /{}", SHUTTLE_BIN_PATH))?;
    std::fs::copy(source, &dest)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "embedding the shuttle binary {} → /{SHUTTLE_BIN_PATH}",
                source.display()
            )
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .into_diagnostic()
            .wrap_err_with(|| format!("setting exec mode on /{SHUTTLE_BIN_PATH}"))?;
    }
    let kib = std::fs::metadata(&dest)
        .map(|m| m.len() / 1024)
        .unwrap_or(0);
    eprintln!("  ✓ embedded shuttle binary ({kib} KiB) → /{SHUTTLE_BIN_PATH} (#81)");
    Ok(())
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
    /// The extracted kernel-snap tree the boot payload was located in,
    /// alive for the whole build so the ADR-0024 §1 initrd-module gate can
    /// re-read the kernel config (`boot/config-<ver>`) from it. `None` for
    /// kernel-free builds and best-effort builds that merged no kernel.
    pub(crate) kernel_snap_dir: Option<tempfile::TempDir>,
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
    let resolved = resolve_image_snaps(runner, image, lockfile, channel, arch, cache_dir)?;
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

    let (payload, kernel_snap_dir) = extract_base_and_kernel(
        runner,
        image,
        &resolved,
        cache_dir,
        &root,
        has_unsquashfs,
        policy,
    )?;

    // #81: the image ships the shuttle binary the boot units exec. Shared
    // by both build paths so every staged rootfs carries /usr/bin/shuttle;
    // a failure here fails the build closed (the units name it absolutely).
    embed_shuttle_binary(runner, &root, arch)?;

    Ok(StagedRootfs {
        build_dir,
        root,
        resolved,
        snap_paths,
        payload,
        kernel_snap_dir,
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
/// kernel is declared AND `policy` requires one, plus the extracted
/// kernel-snap tree (kept alive so the ADR-0024 §1 initrd-module gate can
/// re-read the kernel config).
pub(crate) fn extract_base_and_kernel(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    root: &Path,
    has_unsquashfs: bool,
    policy: KernelPayloadPolicy,
) -> miette::Result<(Option<KernelPayload>, Option<tempfile::TempDir>)> {
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
        unsquashfs_argv0()?,
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
) -> miette::Result<(Option<KernelPayload>, Option<tempfile::TempDir>)> {
    // build_image only merged when unsquashfs was available; disk builds
    // attempt unconditionally (and fail closed if it is missing).
    if policy == KernelPayloadPolicy::BestEffort && !has_unsquashfs {
        return Ok((None, None));
    }
    let Some(kernel_entry) = image.kernel.as_ref() else {
        return Ok((None, None));
    };
    let Some(ks) = resolved.iter().find(|s| s.name == kernel_entry.snap.name) else {
        return Ok((None, None));
    };
    let k_filename = format!("{}_{}_{}.snap", ks.name, ks.revision, ks.sha3_384);
    let kpath = cache_dir.join(&k_filename);
    eprintln!("  merging kernel snap: {}", kernel_entry.snap.name);
    // Extraction scratch — the located payload points into `root`, but the
    // tree is returned alongside it so the ADR-0024 §1 initrd-module gate
    // can re-read `boot/config-<ver>` after staging returns.
    let kernel_work = tempfile::tempdir().map_err(|e| miette::miette!("{e}"))?;
    let kernel_dir = kernel_work.path().join("kernel-snap");
    if !unsquashfs_kernel(runner, &kpath, &kernel_dir, &kernel_entry.snap.name, policy)? {
        return Ok((None, None));
    }
    copy_kernel_tree(&kernel_dir, root)?;
    // The squashfs-only path never needed a boot payload.
    if policy == KernelPayloadPolicy::BestEffort {
        return Ok((None, None));
    }
    // Fail closed on a payload that cannot boot the image. The raw
    // vmlinuz/initrd convention is first choice; the real Ubuntu Core
    // `pc-kernel` snap's prebuilt `kernel.efi` is the #70 fallback, split
    // with objcopy into a scratch dir kept alive by the returned payload;
    // the Raspberry Pi shape (#74) is located as a `pi_raw` payload and
    // paired against the declared bootloader (#87).
    let payload =
        locate_payload_for_snap(runner, image, &kernel_dir, root, &kernel_entry.snap.name)?;
    Ok((Some(payload), Some(kernel_work)))
}

/// Locate the kernel snap's boot payload and, for a prebuilt-UKI payload,
/// replace its Canonical snap-bootstrap initramfs with shuttle's native one
/// (issue #75). Fails closed with the snap name in every message, including
/// the payload↔bootloader pairing gate (#87): the Pi payload is only
/// consumable by the piboot backend, and the piboot backend only consumes
/// the Pi payload.
fn locate_payload_for_snap(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    kernel_dir: &Path,
    root: &Path,
    snap_name: &str,
) -> miette::Result<KernelPayload> {
    let payload = locate_kernel_payload(
        runner,
        find_objcopy().as_deref(),
        kernel_dir,
        kernel_dir,
        root,
    )
    .map_err(|e| {
        miette::miette!(
            "kernel snap '{snap_name}': {e}; refusing to build a disk image that cannot boot"
        )
    })?;
    piboot::assert_payload_bootloader_pairing(image, payload.pi_raw, snap_name)?;
    // Issue #75: a prebuilt `kernel.efi` carries Canonical's snap-bootstrap
    // initramfs, which cannot honor shuttle's cmdline. Replace it with
    // shuttle's native initramfs (busybox + veritysetup + the snap's own
    // module closure) so the built UKI mounts and verifies the shuttle root.
    // The raw-convention path keeps its own initrd untouched.
    if !payload.prebuilt_uki {
        return Ok(payload);
    }
    let native = build_native_initramfs_for_snap(kernel_dir, &payload)
        .map_err(|e| miette::miette!("kernel snap '{snap_name}': {e}"))?;
    Ok(KernelPayload {
        initrd: native,
        ..payload
    })
}

/// Build shuttle's native initramfs for a prebuilt-UKI payload (issue #75).
/// The module tree is `kernel_dir/modules/<version>`; the archive lands in a
/// subdir of `kernel_dir`, whose `kernel_work` TempDir keeps it alive until
/// the UKI is assembled. Every input failure names the exact missing file.
fn build_native_initramfs_for_snap(
    kernel_dir: &Path,
    payload: &KernelPayload,
) -> miette::Result<PathBuf> {
    let version = payload.version.as_str();
    let modules_root = kernel_dir.join("modules").join(version);
    let config = crate::doctor::find_kernel_config(kernel_dir, version).ok_or_else(|| {
        miette::miette!(
            "no kernel config found under {} for {version} — cannot derive the \
             initramfs boot-chain modules, so refusing to build an initramfs \
             that cannot load its boot chain",
            kernel_dir.display()
        )
    })?;
    let tools = discover_initramfs_tools()?;
    build_native_initramfs(&tools, &modules_root, &config, version, kernel_dir)
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
        unsquashfs_argv0()?,
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
///
/// Two source shapes are mapped: the conventional `lib/modules` +
/// `lib/firmware` of a source-built kernel snap, and the real Ubuntu Core
/// `pc-kernel` layout (#70) which carries `modules/` + `firmware/` at the
/// snap ROOT. The booted runtime needs `/lib/modules/<ver>` either way —
/// shuttle's native runtime has no snapd to mount the kernel snap, so the
/// modules must be in the rootfs. `discover_kernel_version` stays
/// single-source on `lib/modules/`, so this mapping is what makes the UC
/// layout discoverable.
fn copy_kernel_tree(kernel_dir: &Path, root: &Path) -> miette::Result<()> {
    // Issue #74: the real pi-kernel carries BOTH spellings at once —
    // conventional `lib/modules` + `lib/firmware` as SYMLINKS to the real
    // snap-root `modules/` + `firmware/`. `cp_r` follows the symlink for
    // the first spelling and copies the real tree for the second; the
    // merge-overwrite walk lands the same content either way, so the
    // double spelling is idempotent, not corrupting (proven by
    // `copy_kernel_tree_maps_the_pi_kernel_double_spelling`).
    for (src_rel, dst_rel) in [
        ("lib/modules", "lib/modules"),
        ("lib/firmware", "lib/firmware"),
        ("modules", "lib/modules"),
        ("firmware", "lib/firmware"),
    ] {
        let src = kernel_dir.join(src_rel);
        let dst = root.join(dst_rel);
        if src.exists() {
            std::fs::create_dir_all(dst.parent().unwrap()).into_diagnostic()?;
            cp_r(&src, &dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real pi-kernel snap layout (#74): BOTH spellings at once —
    /// `lib/modules` and `lib/firmware` as SYMLINKS to the snap-root
    /// `modules/`/`firmware/` trees. The merge must land exactly one
    /// correct `lib/modules/<ver>` tree in the rootfs: the symlink walk
    /// and the real-tree walk overlap, and a corrupting interaction
    /// (dangling link, truncated dir, duplicated version dir) would break
    /// `discover_kernel_version` and the booted runtime alike.
    #[test]
    fn copy_kernel_tree_maps_the_pi_kernel_double_spelling() {
        let kdir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let version = "5.15.0-1103-raspi";

        // The real tree: modules/<ver>/kernel/... with a module file.
        let ko = kdir
            .path()
            .join(format!("modules/{version}/kernel/dm-verity.ko"));
        std::fs::create_dir_all(ko.parent().unwrap()).unwrap();
        std::fs::write(&ko, b"ko-bytes").unwrap();
        std::fs::create_dir_all(kdir.path().join("firmware")).unwrap();
        std::fs::write(kdir.path().join("firmware/fw.bin"), b"fw").unwrap();
        // The Pi spellings: lib/modules -> ../modules, lib/firmware -> ../firmware.
        std::fs::create_dir_all(kdir.path().join("lib")).unwrap();
        std::os::unix::fs::symlink(kdir.path().join("modules"), kdir.path().join("lib/modules"))
            .unwrap();
        std::os::unix::fs::symlink(
            kdir.path().join("firmware"),
            kdir.path().join("lib/firmware"),
        )
        .unwrap();

        copy_kernel_tree(kdir.path(), root.path()).unwrap();

        let staged_modules = root.path().join("lib/modules");
        let staged_ver = staged_modules.join(&version);
        // A REAL directory — never the symlink spelling copied verbatim.
        let meta = std::fs::symlink_metadata(&staged_modules).unwrap();
        assert!(
            meta.is_dir(),
            "staged lib/modules must be a real directory, got {:?}",
            meta.file_type()
        );
        assert!(
            staged_ver.join("kernel/dm-verity.ko").is_file(),
            "module tree staged under lib/modules/{version}"
        );
        assert_eq!(
            std::fs::read(staged_ver.join("kernel/dm-verity.ko")).unwrap(),
            b"ko-bytes",
            "staged module bytes are the snap's bytes"
        );
        assert!(
            root.path().join("lib/firmware/fw.bin").is_file(),
            "firmware staged under lib/firmware"
        );
        // Exactly one version dir — the overlapping walks must not fork.
        let versions: Vec<String> = std::fs::read_dir(&staged_modules)
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        assert_eq!(
            versions,
            vec![version.to_string()],
            "the double spelling must merge into one module tree, got {versions:?}"
        );
    }

    #[test]
    fn embed_binary_stages_the_executable_at_the_pinned_path() {
        let root = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let src_file = source.path().join("shuttle-under-test");
        std::fs::write(&src_file, b"\x7fELF-fake-binary").unwrap();

        embed_binary_at(root.path(), &src_file).unwrap();

        let staged = root.path().join(SHUTTLE_BIN_PATH);
        assert!(staged.is_file(), "binary staged at /{SHUTTLE_BIN_PATH}");
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            b"\x7fELF-fake-binary",
            "staged bytes are the copied binary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
            assert_eq!(mode & 0o755, 0o755, "staged binary is executable: {mode:o}");
        }
    }

    #[test]
    fn embed_binary_fails_closed_on_an_unreadable_source() {
        let root = tempfile::tempdir().unwrap();
        let err = embed_binary_at(root.path(), Path::new("/nonexistent/shuttle")).unwrap_err();
        assert!(
            format!("{err:?}").contains(SHUTTLE_BIN_PATH),
            "failure names the pinned install path: {err:?}"
        );
        assert!(
            !root.path().join(SHUTTLE_BIN_PATH).exists(),
            "nothing staged on failure"
        );
    }

    #[test]
    fn unit_exec_targets_match_the_staged_binary_path() {
        // Issue #81: the units exec the binary the build embeds. The
        // absolute spelling and the staged-rootfs-relative path must agree,
        // or the emitted units are inert (203/EXEC) by construction.
        let absolute = format!("/{SHUTTLE_BIN_PATH}");
        assert_eq!(BOOT_HEALTH_EXEC, format!("{absolute} runtime activate"));
        assert_eq!(ACTIVATE_EXEC, format!("{absolute} runtime activate"));
    }

    #[test]
    fn guest_interpreter_maps_the_supported_arches() {
        assert_eq!(
            guest_interpreter("amd64").unwrap(),
            "/lib64/ld-linux-x86-64.so.2"
        );
        assert_eq!(
            guest_interpreter("x86_64").unwrap(),
            "/lib64/ld-linux-x86-64.so.2"
        );
        assert_eq!(
            guest_interpreter("arm64").unwrap(),
            "/lib/ld-linux-aarch64.so.1"
        );
        assert!(
            guest_interpreter("riscv64").is_err(),
            "unknown arch fails closed"
        );
    }

    #[test]
    fn anchor_repoints_a_foreign_interpreter_to_the_guest() {
        // Real patchelf against a REAL dynamic ELF (a copy of this test
        // binary, whose nix toolchain interpreter is a host-store path) —
        // proving the anchoring the guest needs, not just the seam shape.
        if !crate::command::RealRunner
            .run(&["which".to_string(), "patchelf".to_string()])
            .ok()
            .is_some_and(|o| o.code == 0)
        {
            eprintln!("skipping: patchelf not on PATH");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = std::env::current_exe().unwrap();
        let staged = root.path().join("shuttle");
        std::fs::copy(&source, &staged).unwrap();

        anchor_binary_to_guest(&crate::command::RealRunner, &staged, "amd64").unwrap();

        let out = crate::command::RealRunner
            .run(&[
                "patchelf".to_string(),
                "--print-interpreter".to_string(),
                staged.to_string_lossy().into_owned(),
            ])
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "/lib64/ld-linux-x86-64.so.2",
            "interpreter re-anchored to the guest loader"
        );
        let out = crate::command::RealRunner
            .run(&[
                "patchelf".to_string(),
                "--print-rpath".to_string(),
                staged.to_string_lossy().into_owned(),
            ])
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).trim().is_empty(),
            "host store RUNPATH removed: {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn anchor_skips_a_non_elf_fixture_instead_of_failing() {
        // The test embed fixture is not a real ELF; anchoring must skip it
        // (a static/foreign binary needs no loader) rather than fail.
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join("shuttle");
        std::fs::write(&staged, b"not-an-elf").unwrap();
        anchor_binary_to_guest(&crate::command::RealRunner, &staged, "amd64").unwrap();
        assert!(staged.is_file(), "file untouched");
    }

    #[test]
    fn anchor_is_a_noop_when_the_interpreter_already_matches_the_guest() {
        if !crate::command::RealRunner
            .run(&["which".to_string(), "patchelf".to_string()])
            .ok()
            .is_some_and(|o| o.code == 0)
        {
            eprintln!("skipping: patchelf not on PATH");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let source = std::env::current_exe().unwrap();
        let staged = root.path().join("shuttle");
        std::fs::copy(&source, &staged).unwrap();
        // First anchor, then anchor again: the second pass must observe the
        // guest interpreter and change nothing (no second set call).
        anchor_binary_to_guest(&crate::command::RealRunner, &staged, "amd64").unwrap();
        let before = std::fs::read(&staged).unwrap();
        anchor_binary_to_guest(&crate::command::RealRunner, &staged, "amd64").unwrap();
        let after = std::fs::read(&staged).unwrap();
        assert_eq!(before, after, "second anchor is a byte-identical no-op");
    }

    // ── #85: the bless-boot tooling the base may lack ──

    /// A 64-byte 64-bit little-endian ELF header fixture with the given
    /// `e_machine`, plus `extra` appended (GLIBC version markers).
    fn elf_fixture(machine: u16, extra: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little-endian
        bytes[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(extra);
        bytes
    }

    const EM_X86_64: u16 = 62;
    const MARKER_GLIBC: &[u8] = b"GLIBC_2.34";

    /// A scripted runner for the staging seams: `which` answers from
    /// `which_hits`, `patchelf --print-interpreter` reports the fake nix
    /// loader, everything else succeeds; `<bless> --version` answers
    /// `version`.
    struct BlessRunner {
        which_bless: Option<String>,
        version: &'static str,
    }

    const FAKE_HOST_LOADER: &str = "/nix/store/fake/ld-linux-x86-64.so.2\n";
    const SELF_VERSION_OUTPUT: &str = "systemd 249 (249.11-0ubuntu3.22)\n";

    impl BlessRunner {
        fn locating(bless: &Path) -> BlessRunner {
            BlessRunner {
                which_bless: Some(bless.to_string_lossy().into_owned()),
                version: SELF_VERSION_OUTPUT,
            }
        }

        fn locating_with_version(bless: &Path, version: &'static str) -> BlessRunner {
            BlessRunner {
                which_bless: Some(bless.to_string_lossy().into_owned()),
                version,
            }
        }
    }

    impl crate::command::CommandRunner for BlessRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            let program = argv.first().map(String::as_str).unwrap_or("");
            let (code, stdout) = match program {
                "which" => match argv.get(1).map(String::as_str) {
                    Some("systemd-bless-boot") => match &self.which_bless {
                        Some(path) => (0, path.clone() + "\n"),
                        None => (1, String::new()),
                    },
                    Some("patchelf") => (0, "/usr/bin/patchelf\n".to_string()),
                    _ => (1, String::new()),
                },
                "patchelf" => match argv.iter().any(|a| a == "--print-interpreter") {
                    true => (0, FAKE_HOST_LOADER.to_string()),
                    false => (0, String::new()),
                },
                _ if argv.iter().any(|a| a == "--version") => (0, self.version.to_string()),
                _ => (0, String::new()),
            };
            Ok(crate::command::RunnerOutput {
                code,
                stdout: stdout.into_bytes(),
                stderr: String::new(),
            })
        }
    }

    /// A never-answer runner: any call panics, proving a path needs no host
    /// tooling at all.
    struct NoRunner;

    impl crate::command::CommandRunner for NoRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            panic!("no host command expected, saw {argv:?}");
        }
    }

    /// The tooling fast path: a base that ships both binaries (every
    /// UC22-era base — measured core22 2437/2955) stages nothing and runs
    /// no host tooling.
    #[test]
    fn bless_tooling_fast_path_when_the_base_ships_both() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/systemd/system-generators")).unwrap();
        std::fs::write(root.path().join("usr/lib/systemd/systemd-bless-boot"), b"x").unwrap();
        std::fs::write(
            root.path()
                .join("usr/lib/systemd/system-generators/systemd-bless-boot-generator"),
            b"x",
        )
        .unwrap();

        stage_bless_boot_binaries(&NoRunner, root.path(), "amd64")
            .expect("a tooling-bearing base must pass through untouched");
    }

    /// The shipped-from-host happy path with the guest's own shared lib
    /// resolving the tooling: both binaries staged, no lib duplicated, the
    /// RUNPATH pointed at the guest systemd dir.
    #[test]
    fn bless_tooling_stages_from_the_host_and_reuses_the_guest_shared_lib() {
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::create_dir_all(host.path().join("system-generators")).unwrap();
        std::fs::write(
            host.path()
                .join("system-generators/systemd-bless-boot-generator"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        // Guest: same-major shared lib + a libc that defines the marker.
        let guest_systemd = root.path().join("usr/lib/x86_64-linux-gnu/systemd");
        std::fs::create_dir_all(&guest_systemd).unwrap();
        std::fs::write(
            guest_systemd.join("libsystemd-shared-249.so"),
            elf_fixture(EM_X86_64, b""),
        )
        .unwrap();
        std::fs::write(
            root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6"),
            b"GLIBC C Library fixture GLIBC_2.34",
        )
        .unwrap();

        let runner = BlessRunner::locating(&host.path().join("systemd-bless-boot"));
        stage_bless_boot_binaries(&runner, root.path(), "amd64")
            .expect("a well-formed host tooling must stage");

        let bin = root.path().join(BLESS_BOOT_TOOLING_BIN_PATH);
        let gen = root.path().join(BLESS_BOOT_TOOLING_GENERATOR_PATH);
        assert!(bin.is_file(), "bless binary staged at /usr/lib/systemd/");
        assert!(gen.is_file(), "generator staged under system-generators/");
        assert!(
            !root
                .path()
                .join("usr/lib/systemd/libsystemd-shared-249.so")
                .exists(),
            "the guest's own shared lib must not be duplicated"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bin).unwrap().permissions().mode();
            assert_eq!(mode & 0o755, 0o755, "bless binary is executable: {mode:o}");
        }
    }

    /// When the guest's shared lib carries a different major, the host's
    /// copy is staged next to the tooling (self-consistent pair) and the
    /// RUNPATH points at the staging dir.
    #[test]
    fn bless_tooling_stages_the_host_shared_lib_when_the_guest_lacks_it() {
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::create_dir_all(host.path().join("system-generators")).unwrap();
        std::fs::write(
            host.path()
                .join("system-generators/systemd-bless-boot-generator"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::write(
            host.path().join("libsystemd-shared-249.so"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        // Guest: a DIFFERENT major (269 vs 249) — the reuse path must not
        // fire — plus a libc that defines the marker.
        let guest_systemd = root.path().join("usr/lib/systemd");
        std::fs::create_dir_all(&guest_systemd).unwrap();
        std::fs::write(
            guest_systemd.join("libsystemd-shared-269.so"),
            elf_fixture(EM_X86_64, b""),
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        std::fs::write(
            root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6"),
            b"fixture GLIBC_2.34",
        )
        .unwrap();

        let runner = BlessRunner::locating(&host.path().join("systemd-bless-boot"));
        stage_bless_boot_binaries(&runner, root.path(), "amd64")
            .expect("the host shared lib completes the pair");

        let staged_lib = root.path().join("usr/lib/systemd/libsystemd-shared-249.so");
        assert!(
            staged_lib.is_file(),
            "the host shared lib is staged next to the tooling"
        );
    }

    /// Cross-arch tooling fails closed: an x86-64 host binary cannot be
    /// shipped into an arm64 image (#85 arch gate).
    #[test]
    fn bless_tooling_fails_closed_on_an_arch_mismatch() {
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot-generator"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        let runner = BlessRunner::locating(&host.path().join("systemd-bless-boot"));
        let err = stage_bless_boot_binaries(&runner, root.path(), "arm64")
            .expect_err("cross-arch tooling must not stage");
        let message = err.to_string();
        assert!(
            message.contains("arm64") && message.contains("62"),
            "names both the target arch and the tooling machine: {message}"
        );
        assert!(
            !root.path().join(BLESS_BOOT_TOOLING_BIN_PATH).exists(),
            "nothing staged on failure"
        );
    }

    /// Tooling below the #79 floor fails closed: the gate vouches for the
    /// same floor the emitted machinery needs.
    #[test]
    fn bless_tooling_fails_closed_below_the_boot_assessment_floor() {
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot-generator"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        let runner = BlessRunner::locating_with_version(
            &host.path().join("systemd-bless-boot"),
            "systemd 239 (239)\n",
        );
        let err = stage_bless_boot_binaries(&runner, root.path(), "amd64")
            .expect_err("tooling below the floor must not stage");
        assert!(
            err.to_string().contains("240"),
            "names the #79 floor: {err}"
        );
    }

    /// The missing-tooling case is the #85/#79 fail-closed gate: every probe
    /// misses ⇒ the build refuses to emit unbacked assessment.
    #[test]
    fn bless_tooling_fails_closed_when_the_host_has_none() {
        if host_ships_fhs_bless_tooling() {
            eprintln!("skipping: the test host ships FHS bless tooling");
            return;
        }
        struct NothingRunner;
        impl crate::command::CommandRunner for NothingRunner {
            fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
                let program = argv.first().map(String::as_str).unwrap_or("");
                if program == "which" {
                    return Ok(crate::command::RunnerOutput {
                        code: 1,
                        stdout: Vec::new(),
                        stderr: String::new(),
                    });
                }
                panic!("no further host command expected, saw {argv:?}");
            }
        }
        let root = tempfile::tempdir().unwrap();
        let err = stage_bless_boot_binaries(&NothingRunner, root.path(), "amd64")
            .expect_err("missing tooling must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("cannot be provided"),
            "names the #85/#79 gate: {message}"
        );
        assert!(
            message.contains("SHUTTLE_BLESS_BOOT_DIR"),
            "names the override: {message}"
        );
    }

    /// The #80 lesson, enforced: a staged host ELF whose GLIBC version
    /// requirements the guest libc does not define fails the BUILD.
    #[test]
    fn bless_tooling_fails_closed_when_the_guest_libc_cannot_satisfy_it() {
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot"),
            elf_fixture(EM_X86_64, b"GLIBC_2.99"),
        )
        .unwrap();
        std::fs::write(
            host.path().join("systemd-bless-boot-generator"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();
        std::fs::write(
            host.path().join("libsystemd-shared-249.so"),
            elf_fixture(EM_X86_64, MARKER_GLIBC),
        )
        .unwrap();

        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        std::fs::write(
            root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6"),
            b"fixture GLIBC_2.34 only",
        )
        .unwrap();

        let runner = BlessRunner::locating(&host.path().join("systemd-bless-boot"));
        let err = stage_bless_boot_binaries(&runner, root.path(), "amd64")
            .expect_err("an unsatisfiable GLIBC requirement must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("GLIBC_2.99"),
            "names the missing symbol version: {message}"
        );
        assert!(
            message.contains("libc.so.6"),
            "names the guest libc it was checked against: {message}"
        );
    }

    /// The GLIBC gate must check the libc of the IMAGE's arch: a core26
    /// base also ships an i386 libc, and its directory sort order must not
    /// answer for an amd64 tooling check (found by the first real build).
    #[test]
    fn guest_libc_path_matches_the_image_arch_triplet() {
        let root = tempfile::tempdir().unwrap();
        // The i386 libc lacks the marker; the amd64 one carries it.
        std::fs::create_dir_all(root.path().join("usr/lib/i386-linux-gnu")).unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        std::fs::write(
            root.path().join("usr/lib/i386-linux-gnu/libc.so.6"),
            b"32-bit fixture, no marker",
        )
        .unwrap();
        std::fs::write(
            root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6"),
            b"fixture GLIBC_2.34",
        )
        .unwrap();

        let libc = guest_libc_path(root.path(), "amd64").expect("amd64 libc found");
        assert!(
            libc.to_string_lossy().contains("x86_64-linux-gnu"),
            "the image arch's own libc must be checked: {}",
            libc.display()
        );
        // The staged tooling passes against it.
        let host = tempfile::tempdir().unwrap();
        let bless = host.path().join("systemd-bless-boot");
        std::fs::write(&bless, elf_fixture(EM_X86_64, MARKER_GLIBC)).unwrap();
        assert_guest_libc_covers(root.path(), "amd64", &[bless])
            .expect("the arch-matched libc defines the requested version");
    }

    fn host_ships_fhs_bless_tooling() -> bool {
        Path::new("/usr/lib/systemd/systemd-bless-boot").is_file()
            || Path::new("/lib/systemd/systemd-bless-boot").is_file()
    }

    /// The version parser: the standardized `--version` first line, and the
    /// junk shapes it must reject.
    #[test]
    fn systemd_major_parses_from_the_version_output() {
        assert_eq!(
            systemd_major_from_version_output("systemd 261 (261.2)\n"),
            Some(261)
        );
        assert_eq!(
            systemd_major_from_version_output("systemd 249\n"),
            Some(249)
        );
        assert_eq!(
            systemd_major_from_version_output("v249 junk"),
            None,
            "not the systemd spelling"
        );
        assert_eq!(systemd_major_from_version_output(""), None);
        assert_eq!(
            systemd_major_from_version_output("systemd nan"),
            None,
            "a non-numeric major is undeterminable"
        );
    }

    /// Drift pin (#85): the shipped tooling path and the unit's ExecStart
    /// must spell the same location, or the shipped helper is inert.
    #[test]
    fn bless_exec_targets_the_staged_tooling_path() {
        assert_eq!(
            super::boot::BLESS_BOOT_EXEC,
            format!("/{} good", BLESS_BOOT_TOOLING_BIN_PATH)
        );
    }

    /// The GLIBC scanner sees version markers the way the runtime's
    /// `.gnu.version_r` spells them.
    #[test]
    fn needed_glibc_versions_scans_both_spellings() {
        let bytes = b"\0GLIBC_2.34\0xGLIBC_ABI_GNU2_TLS\0GLIBC_2.2.5\0GLIBC_2.";
        assert_eq!(
            needed_glibc_versions(bytes),
            vec!["GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_ABI_GNU2_TLS"]
        );
        assert!(needed_glibc_versions(b"nothing here").is_empty());
    }

    /// Real patchelf against the real host tooling (when present): the
    /// interpreter lands on the guest loader and the RUNPATH on the staging
    /// dir — the exact anchoring the shipped binaries need on-device.
    #[test]
    fn anchor_repoints_real_bless_tooling_with_an_rpath() {
        if !crate::command::RealRunner
            .run(&["which".to_string(), "patchelf".to_string()])
            .ok()
            .is_some_and(|o| o.code == 0)
        {
            eprintln!("skipping: patchelf not on PATH");
            return;
        }
        let real = find_host_shared_lib_probe();
        let Some(source) = real else {
            eprintln!("skipping: no host systemd-bless-boot to probe");
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let staged = root.path().join("systemd-bless-boot");
        std::fs::copy(&source, &staged).unwrap();

        anchor_elf_to_guest(
            &crate::command::RealRunner,
            &staged,
            "amd64",
            "/usr/lib/systemd/systemd-bless-boot",
            Some("/usr/lib/systemd"),
        )
        .unwrap();

        let print = |flag: &str| {
            let out = crate::command::RealRunner
                .run(&[
                    "patchelf".to_string(),
                    flag.to_string(),
                    staged.to_string_lossy().into_owned(),
                ])
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(
            print("--print-interpreter"),
            "/lib64/ld-linux-x86-64.so.2",
            "interpreter re-anchored to the guest loader"
        );
        assert_eq!(
            print("--print-rpath"),
            "/usr/lib/systemd",
            "RUNPATH set to the tooling lib dir"
        );
    }

    /// Best-effort probe of a real host `systemd-bless-boot` for the
    /// anchoring test: FHS paths, then a nix-store glob.
    fn find_host_shared_lib_probe() -> Option<PathBuf> {
        for candidate in [
            PathBuf::from("/usr/lib/systemd/systemd-bless-boot"),
            PathBuf::from("/lib/systemd/systemd-bless-boot"),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let mut hits = std::fs::read_dir("/nix/store")
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("systemd-") && !n.contains("minimal"))
            })
            .map(|p| p.join("lib/systemd/systemd-bless-boot"))
            .filter(|p| p.is_file())
            .collect::<Vec<_>>();
        hits.sort();
        hits.into_iter().next()
    }

    // ── Pin-first resolution (#48/#69) ──

    /// A runner that answers NOTHING: any store query (curl) is a test
    /// failure by construction — the pin-first path must never reach it.
    struct NoStoreRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl NoStoreRunner {
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::command::CommandRunner for NoStoreRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            Err(std::io::Error::other("store must not be queried"))
        }
    }

    /// An index with one channel-keyed core26 pin, plus its cached payload
    /// under the exact content-addressed name the pin carries. Returns the
    /// index FILE path (the seam takes a file, not a directory).
    fn pin_fixture(dir: &Path) -> (PathBuf, String) {
        let sha3 = "7d1230c3236bd8840000000000000000000000000000000000000000000000000000000000000000000000000000000000aa";
        let index = serde_json::json!({
            "version": 1,
            "snaps": [{
                "name": "core26",
                "pins": {
                    "amd64@26/stable": {
                        "revision": 462,
                        "sha3-384": sha3,
                        "channel": "26/stable"
                    }
                }
            }]
        });
        let index_path = dir.join("package-index.json");
        std::fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();
        std::fs::write(dir.join(format!("core26_462_{sha3}.snap")), b"payload").unwrap();
        (index_path, sha3.to_string())
    }

    /// Lock the SHUTTLE_INDEX_PATH seam for the duration of one test — the
    /// resolve loop reads it, and parallel tests must not race it.
    struct IndexPathGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn set_index_path(path: &Path) -> IndexPathGuard {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SHUTTLE_INDEX_PATH", path);
        IndexPathGuard { _lock: lock }
    }

    impl Drop for IndexPathGuard {
        fn drop(&mut self) {
            std::env::remove_var("SHUTTLE_INDEX_PATH");
        }
    }

    fn unpinned_core26_image() -> ImageDeclaration {
        ImageDeclaration {
            name: "pinfirst".into(),
            version: "1.0.0".into(),
            base: SnapRef {
                name: "core26".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
            files: vec![],
            boot_health_exec: None,
        }
    }

    /// A baked index pin with a cached payload resolves WITHOUT any store
    /// query — two builds hours apart cannot race the store's current
    /// revision (#48). This is the pin-honoring contract the rebuild
    /// compare asserts on the log line.
    #[test]
    fn cached_index_pin_resolves_without_touching_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (index_home, sha3) = pin_fixture(dir.path());
        let _guard = set_index_path(&index_home);

        let runner = NoStoreRunner {
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let resolved = resolve_image_snaps(
            &runner,
            &unpinned_core26_image(),
            &LockFile::empty(),
            "26/stable",
            "amd64",
            dir.path(),
        )
        .expect("the cached pin resolves offline");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "core26");
        assert_eq!(resolved[0].revision, 462);
        assert_eq!(resolved[0].sha3_384, sha3);
        assert!(
            runner.calls().is_empty(),
            "the store was never queried: {:?}",
            runner.calls()
        );
    }

    /// A cache miss falls through to the store — the pin path must not
    /// brick a build while the store is reachable (#69 contract).
    #[test]
    fn index_pin_cache_miss_falls_through_to_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (index_home, _sha3) = pin_fixture(dir.path());
        let _guard = set_index_path(&index_home);

        let cache = tempfile::tempdir().unwrap();
        let resolved = resolve_image_snaps(
            &NoStoreRunner {
                calls: std::sync::Mutex::new(Vec::new()),
            },
            &unpinned_core26_image(),
            &LockFile::empty(),
            "26/stable",
            "amd64",
            cache.path(),
        )
        .expect_err("no store reachable and no cached payload is a hard failure");
        let msg = format!("{resolved:#}");
        assert!(
            msg.contains("cannot resolve"),
            "names the unresolvable snap: {msg}"
        );
    }
}
