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
    cache_dir: &Path,
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

/// Re-anchor the staged binary to the guest (#81).
///
/// A devbox/nix-built ELF requests its interpreter from the build host's
/// store (`/nix/store/…/ld-linux-…`) and carries that store in RUNPATH —
/// paths that do not exist inside the image, where the exec would fail with
/// the exact "No such file or directory" #81 closes. When the staged file's
/// interpreter is not already the guest's standard path, `patchelf`
/// (already part of this repo's toolchain, `snap.rs` ELF repair) rewrites it
/// to [`guest_interpreter`] and drops the host RUNPATH — unprivileged,
/// deterministic, and strictly REMOVING host paths from the image. A file
/// patchelf cannot parse (static binary, test fixture) needs no anchoring
/// and is skipped with a note.
fn anchor_binary_to_guest(
    runner: &dyn CommandRunner,
    staged: &Path,
    arch: &str,
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
                "patchelf is required to stage the shuttle binary into the image \
                 (#81): the build-host ELF must be re-anchored to the guest loader \
                 before it can exec on-device. Install patchelf (devbox ships it) \
                 and rebuild: {e}"
            ));
        }
        Err(e) => {
            return Err(miette::miette!(
                "cannot inspect /{SHUTTLE_BIN_PATH} with patchelf: {e}"
            ));
        }
    };
    if crate::command::exit_code(&out) != 0 {
        eprintln!(
            "  ℹ /{SHUTTLE_BIN_PATH}: not a dynamically linked ELF — no guest \
             anchoring needed"
        );
        return Ok(());
    }
    let current = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if current == guest {
        return Ok(());
    }
    if !has_patchelf {
        return Err(miette::miette!(
            "/{SHUTTLE_BIN_PATH} requests interpreter '{current}', which does not \
             exist in the image, and patchelf is unavailable to re-anchor it to \
             '{guest}' — the embedded binary would be inert on-device (#81). \
             Install patchelf (devbox ships it) and rebuild."
        ));
    }
    let out = runner
        .run(&[
            "patchelf".to_string(),
            "--set-interpreter".to_string(),
            guest.to_string(),
            "--remove-rpath".to_string(),
            staged_str.clone(),
        ])
        .map_err(|e| miette::miette!("patchelf failed: {e}"))?;
    if crate::command::exit_code(&out) != 0 {
        return Err(miette::miette!(
            "patchelf could not re-anchor /{SHUTTLE_BIN_PATH} to '{guest}' — \
             refusing to ship a binary the guest cannot exec (#81)"
        ));
    }
    eprintln!(
        "  ✓ /{SHUTTLE_BIN_PATH} anchored to the guest loader '{guest}' \
         (was '{current}')"
    );
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

/// [`embed_shuttle_binary`] with an explicit source file — the seam the
/// unit tests drive. Copies `source` to `root/usr/bin/shuttle`, mode `0755`.
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
    // with objcopy into a scratch dir kept alive by the returned payload.
    let payload = locate_payload_for_snap(runner, &kernel_dir, root, &kernel_entry.snap.name)?;
    Ok((Some(payload), Some(kernel_work)))
}

/// Locate the kernel snap's boot payload and, for a prebuilt-UKI payload,
/// replace its Canonical snap-bootstrap initramfs with shuttle's native one
/// (issue #75). Fails closed with the snap name in every message.
fn locate_payload_for_snap(
    runner: &dyn CommandRunner,
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
}
