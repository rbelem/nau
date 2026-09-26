//! The Raspberry Pi boot chain — the `piboot` backend (issue #87, ADR-0025
//! amendment).
//!
//! Raspberry Pi hardware does not run systemd-boot or any UEFI loader by
//! default: the GPU firmware (`start.elf` family, loaded by `bootcode.bin`)
//! reads a FAT partition, honors `config.txt`, loads the board device tree,
//! decompresses a gzip-wrapped kernel image, and jumps to it — the
//! `piboot` scheme the pi gadget declares (`bootloader: piboot`). The
//! measured pi gadget rev 132 (22/stable) makes the chain explicit in its
//! own `config.txt`:
//!
//! ```text
//! [all]
//! kernel=kernel.img
//! cmdline=cmdline.txt
//! initramfs initrd.img followkernel
//! os_prefix=
//! ```
//!
//! so the shuttle Pi backend is a staging contract, not a loader:
//!
//! 1. the firmware partition carries the gadget's `boot-assets/` verbatim
//!    (firmware blobs, `config.txt`, per-board DTBs, `overlays/`), plus the
//!    kernel snap's board DTBs (the gadget's own content spec stages
//!    `$kernel:dtbs` board trees);
//! 2. the kernel snap's Pi-spelled payload — `kernel.img` (gzip ARM64
//!    Image, decompressed by the firmware itself) and `initrd.img` — is
//!    staged verbatim under the names `config.txt` references;
//! 3. `cmdline.txt` is REWRITTEN to carry the image's declared kernel
//!    params plus `root=PARTUUID=<root>` — the Pi equivalent of the
//!    UKI-embedded cmdline (the integrity binding, ADR-0011 step (a));
//! 4. `config.txt` keeps every stock line EXCEPT `initramfs`: the payload's
//!    `initrd.img` is Canonical's snap-bootstrap initramfs, which mounts a
//!    writable `ubuntu-data` and cannot honor this image's cmdline.
//!
//! # Named scope limits (ADR-0025 amendment, #87)
//!
//! - **No dm-verity.** The measured raspi kernel builds `CONFIG_DM_VERITY=m`
//!   — the mapping needs an initramfs to load the module and run
//!   `veritysetup`, and shuttle's native initramfs binaries (issue #75) are
//!   host-static, not arm64. The Pi root is a plain ext4 partition.
//! - **No boot assessment.** try-boot/revert is a systemd-boot protocol
//!   (boot counters, `LoaderBootCountPath`); the Pi's native analog
//!   (`tryboot`/`autoboot.txt`, Pi 4 EEPROM bootloader) would need per-slot
//!   boot partitions and its own bless path. A/B slots and `update_source`
//!   are REFUSED for this backend rather than shipped inert.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use super::*;

/// The `bootloader.type` value selecting this backend — the gadget.yaml
/// bootloader name the pi gadget itself declares (`bootloader: piboot`).
pub(crate) const BOOTLOADER_PIBOOT: &str = "piboot";

/// `true` when the image declared `bootloader.type = "piboot"`.
pub(crate) fn is_piboot_boot(image: &ImageDeclaration) -> bool {
    image
        .bootloader
        .as_ref()
        .is_some_and(|b| b.type_ == BOOTLOADER_PIBOOT)
}

// ── Payload ↔ bootloader pairing (staging gate) ──

/// Fail closed when the located kernel payload and the declared bootloader
/// cannot form a boot chain. The Pi payload is only consumable by this
/// backend, and this backend only consumes the Pi payload — every other
/// pairing would produce an artifact nothing can boot.
pub(crate) fn assert_payload_bootloader_pairing(
    image: &ImageDeclaration,
    pi_raw: bool,
    snap_name: &str,
) -> miette::Result<()> {
    if pi_raw && !is_piboot_boot(image) {
        return Err(miette::miette!(
            "kernel snap '{snap_name}': this payload is the Raspberry Pi kernel shape \
             (kernel.img + initrd.img at the snap root) — the Pi firmware boots it directly \
             through the gadget's boot-assets, a chain only the \"piboot\" backend implements \
             (issue #87); systemd-boot cannot boot Raspberry Pi hardware. Set \
             bootloader = {{ type = \"piboot\" }} in the image declaration (ADR-0025 amendment)"
        ));
    }
    if !pi_raw && is_piboot_boot(image) {
        return Err(miette::miette!(
            "kernel snap '{snap_name}': bootloader.type = \"piboot\" consumes the Raspberry \
             Pi raw payload (kernel.img + initrd.img at the snap root), which this snap does \
             not carry — restaging a vmlinuz/UKI payload under Pi spellings would invent a \
             firmware contract shuttle cannot verify. Use the pi-kernel snap for piboot \
             images; UEFI targets use the systemd-boot backend (issue #87, ADR-0025 amendment)"
        ));
    }
    Ok(())
}

// ── Build-time preconditions (fail closed BEFORE any destructive step) ──

/// Each precondition returns the named refusal when violated, `None` when it
/// holds. Array order in [`assert_piboot_preconditions`] is the report
/// order: the most actionable refusal wins.
fn refusal_missing_gadget(image: &ImageDeclaration) -> Option<String> {
    image.gadget.is_none().then(|| {
        "bootloader.type = \"piboot\" needs a gadget snap (gadget = pin(…)) — the Pi \
         firmware boots the gadget's boot-assets (start4.elf, fixup*.dat, bootcode.bin, \
         config.txt, DTBs); a boot partition staged without them has no firmware to run \
         (issue #87)"
            .to_string()
    })
}

fn refusal_disk_label(layout: &DiskLayout) -> Option<String> {
    (layout.label != "gpt").then(|| {
        "bootloader.type = \"piboot\" requires label = \"gpt\" — the root= kernel \
         argument references the GPT PARTUUID the build reads back from the partition \
         table, and MBR partitions carry no PARTUUID; the Pi firmware reads GPT fine \
         (the pi gadget's own gadget.yaml notes firmware GPT support), so declare \
         label = \"gpt\" (issue #87)"
            .to_string()
    })
}

fn refusal_ab_slots(layout: &DiskLayout) -> Option<String> {
    layout.ab.then(|| {
        "disk.ab = true is not implemented for bootloader.type = \"piboot\" — the Pi's \
         native try-boot (config.txt tryboot + autoboot.txt, Pi 4 EEPROM bootloader) \
         would need per-slot boot partitions each carrying their slot's \
         kernel.img/cmdline.txt, and a health-gated autoboot.txt bless shuttle has not \
         built; without it slot B is an unreachable byte-twin, which is exactly the \
         inert-configuration class ADR-0024 refuses. Declare a single root (issue #87, \
         ADR-0025 amendment scope)"
            .to_string()
    })
}

fn refusal_update_source(image: &ImageDeclaration) -> Option<String> {
    image.update_source.is_some().then(|| {
        "update_source is not implemented for bootloader.type = \"piboot\" — the \
         systemd-sysupdate transfers shuttle emits are the systemd-boot UKI protocol \
         (EFI/Linux UKIs, x86-64 partition type GUIDs, boot-counter filenames); a Pi \
         update path needs its own transfer shape and slot selection (issue #87, \
         ADR-0025 amendment scope)"
            .to_string()
    })
}

fn vfat_partition_count(layout: &DiskLayout) -> usize {
    layout.partitions.iter().filter(|p| p.fs == "vfat").count()
}

fn refusal_vfat_partition(layout: &DiskLayout) -> Option<String> {
    match vfat_partition_count(layout) {
        1 => None,
        0 => Some(
            "bootloader.type = \"piboot\" needs exactly one vfat partition — the firmware \
             partition the Pi reads boot-assets from; the firmware can only read FAT, so \
             a Pi image without one cannot boot (issue #87)"
                .to_string(),
        ),
        n => Some(format!(
            "bootloader.type = \"piboot\" needs exactly one vfat partition — the firmware \
             partition the Pi reads boot-assets from; found {n}, and shuttle would have to \
             guess which one the firmware scans first. Declare one (issue #87)"
        )),
    }
}

fn refusal_ext4_root(layout: &DiskLayout) -> Option<String> {
    let roots = root_partition_indices(layout);
    match roots.as_slice() {
        [] => Some(
            "bootloader.type = \"piboot\" needs a root partition (mount = \"/\") — the \
             kernel argument root= must reference a declared, read-back PARTUUID \
             (issue #87)"
                .to_string(),
        ),
        [i] => {
            let fs = layout.partitions[*i].fs.as_str();
            (fs != "ext4").then(|| {
                format!(
                    "bootloader.type = \"piboot\" requires an ext4 root partition — the Pi \
                     chain boots WITHOUT an initramfs, so the root filesystem must be built \
                     into the kernel (audited: CONFIG_EXT4_FS=y); partition '{}' declares \
                     '{fs}' (issue #87)",
                    layout.partitions[*i].name
                )
            })
        }
        _ => Some(
            "bootloader.type = \"piboot\" supports exactly one root partition — multiple \
             mount = \"/\" partitions have no slot semantics on Pi (issue #87)"
                .to_string(),
        ),
    }
}

/// The fail-closed preconditions for a `piboot` image, checked before any
/// destructive step (dd/parted/mkfs). Every refusal names the fix; passing
/// preconditions print the backend's scope notes so the build log states
/// what this backend does NOT do.
pub(crate) fn assert_piboot_preconditions(
    image: &ImageDeclaration,
    layout: &DiskLayout,
) -> miette::Result<()> {
    let refusals = [
        refusal_missing_gadget(image),
        refusal_disk_label(layout),
        refusal_ab_slots(layout),
        refusal_update_source(image),
        refusal_vfat_partition(layout),
        refusal_ext4_root(layout),
    ];
    if let Some(first) = refusals.into_iter().flatten().next() {
        return Err(miette::miette!("{first}"));
    }
    eprintln!("  ℹ piboot: kernel.img (gzip ARM64 Image) + initrd.img staged verbatim — the Pi firmware decompresses and boots them directly (issue #87)");
    eprintln!("  ℹ piboot: dm-verity NOT applied — DM_VERITY=m + no arm64 native initramfs (#75 binaries are host-static); the root is a plain ext4 partition (ADR-0025 amendment scope)");
    eprintln!("  ℹ piboot: no boot assessment — try-boot/revert is a systemd-boot protocol; the Pi tryboot mapping is future work (ADR-0025 amendment scope)");
    Ok(())
}

// ── ADR-0024 §1 Pi analog: the no-initramfs boot-chain audit ──

/// The kernel configs the no-initramfs Pi boot REQUIRES built in. Without an
/// initramfs nothing loads modules or runs userspace helpers before the root
/// mount: the kernel must see the SD host controller, the block layer, and
/// the root filesystem itself (`=y`, not `=m`). Measured on the real
/// pi-kernel 22/stable rev 1137 (`config-5.15.0-1103-raspi`): all three are
/// `=y`.
const PIBOOT_REQUIRED_BUILTIN: [&str; 3] = ["CONFIG_EXT4_FS", "CONFIG_MMC", "CONFIG_MMC_BLOCK"];

/// `true` when the config text carries the exact `CONFIG_X=y` line (same
/// match rule as [`doctor::audit_kernel_verity_config`]).
fn has_builtin_line(config_text: &str, config: &str) -> bool {
    let wanted = format!("{config}=y");
    config_text.lines().any(|l| l.trim() == wanted)
}

/// The build-time audit for the no-initramfs Pi boot chain (ADR-0024 §1's Pi
/// analog): a kernel that cannot mount its own root before any userspace
/// runs is a brick, so a missing built-in FAILS CLOSED naming the config
/// symbols and the reason. Also prints the dm-verity scope note derived from
/// the config (the measured raspi kernel builds `CONFIG_DM_VERITY=m`).
pub(crate) fn audit_builtin_boot_chain(
    config_text: &str,
    kernel_version: &str,
) -> miette::Result<()> {
    let missing: Vec<&str> = PIBOOT_REQUIRED_BUILTIN
        .iter()
        .copied()
        .filter(|cfg| !has_builtin_line(config_text, cfg))
        .collect();
    if !missing.is_empty() {
        return Err(miette::miette!(
            "kernel {kernel_version} config lacks built-in boot-chain support: {} are not \
             '=y' — the piboot chain boots WITHOUT an initramfs, so the kernel must see its \
             own SD host controller, MMC block layer, and ext4 root filesystem before any \
             userspace runs; a kernel that cannot mount its root is a brick — refusing to \
             build (ADR-0024 §1 Pi analog, issue #87)",
            missing.join(", ")
        ));
    }
    if has_builtin_line(config_text, "CONFIG_DM_VERITY") {
        eprintln!(
            "  ℹ kernel {kernel_version}: CONFIG_DM_VERITY present but unused by the piboot \
             chain — no initramfs exists to construct the mapping (issue #87)"
        );
    } else {
        eprintln!(
            "  ℹ kernel {kernel_version}: dm-verity not part of the piboot chain (no \
             initramfs to load the module; the root is a plain ext4 partition, ADR-0025 \
             amendment scope)"
        );
    }
    eprintln!(
        "  ✓ kernel {kernel_version}: built-in boot chain confirmed (ext4 + MMC + \
         MMC_BLOCK '=y', no-initramfs boot, issue #87)"
    );
    Ok(())
}

/// Resolve the kernel config from the extracted kernel-snap tree and run the
/// built-in boot-chain audit. `None`/missing config fails closed — unlike
/// the warn-only UKI-side verity audit, the no-initramfs contract cannot be
/// verified any other way.
pub(crate) fn audit_piboot_kernel(
    kernel_snap_dir: Option<&Path>,
    version: &str,
) -> miette::Result<()> {
    let dir = kernel_snap_dir.ok_or_else(|| {
        miette::miette!(
            "the kernel snap tree was not extracted, so the piboot boot-chain audit \
             cannot read the kernel config — refusing to build a disk image whose \
             no-initramfs boot contract is unverified (issue #87)"
        )
    })?;
    let path = doctor::find_kernel_config(dir, version).ok_or_else(|| {
        miette::miette!(
            "no kernel config found under {} for {version} — the piboot chain boots \
             without an initramfs, so built-in ext4/MMC support must be auditable from \
             the config; refusing to build an unverifiable boot chain (issue #87)",
            dir.display()
        )
    })?;
    let text = std::fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading kernel config {}", path.display()))?;
    audit_builtin_boot_chain(&text, version)
}

// ── Boot-asset staging ──

/// Inputs to [`stage_pi_boot_assets`] — everything the firmware-visible
/// partition tree is derived from.
pub(crate) struct PiBootStage<'a> {
    pub(crate) runner: &'a dyn CommandRunner,
    /// Build scratch dir; the gadget snap is extracted and the staged tree
    /// is built under here.
    pub(crate) scratch: &'a Path,
    /// The verified gadget snap in the content-addressed cache.
    pub(crate) gadget_snap: &'a Path,
    /// The located Pi payload (kernel.img / initrd.img paths inside the
    /// extracted kernel-snap tree).
    pub(crate) payload: &'a KernelPayload,
    pub(crate) params: &'a [String],
    /// The read-back GPT PARTUUID of the root slot — `root=PARTUUID=` in
    /// cmdline.txt. A missing PARTUUID fails closed: a nil-GUID cmdline
    /// would boot nothing.
    pub(crate) root_partuuid: &'a str,
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

/// Run the gadget-snap unsquashfs, failing closed — the boot partition has
/// no content without it (Required policy, mirroring
/// [`crate::image::staging`]'s kernel extraction).
fn unsquashfs_gadget(runner: &dyn CommandRunner, snap: &Path, dir: &Path) -> miette::Result<()> {
    let argv = vec![
        unsquashfs_argv0()?,
        "-d".to_string(),
        dir.to_string_lossy().into_owned(),
        "-no-xattrs".to_string(),
        snap.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if crate::command::exit_code(&out) < 128 {
        Ok(())
    } else {
        Err(miette::miette!(
            "failed to unsquashfs gadget snap {} — the Pi boot-assets cannot be staged \
             from an unreadable gadget; refusing to build (issue #87)",
            snap.display()
        ))
    }
}

/// The board-DTB source directory inside the extracted kernel snap. The
/// measured pi-kernel layout is `dtbs/broadcom/` (rev 1137); the gadget's
/// content spec spells the same tree `dtbs/dtbs/broadcom/` (the snapd
/// kernel-assets indirection). Both spellings are accepted, measured first.
fn dtb_source(kernel_snap: &Path) -> Option<PathBuf> {
    [
        kernel_snap.join("dtbs/broadcom"),
        kernel_snap.join("dtbs/dtbs/broadcom"),
    ]
    .into_iter()
    .find(|p| p.is_dir())
}

/// Stage the kernel snap's board DTBs: `broadcom/` → the partition root
/// (the firmware loads the board tree from there), `overlays/` →
/// `overlays/`. Staged BEFORE the gadget's boot-assets, which are
/// authoritative where names collide (mirroring the gadget's own content
/// ordering, boot-assets last).
fn stage_kernel_dtbs(kernel_snap: &Path, stage: &Path) -> miette::Result<()> {
    let broadcom = dtb_source(kernel_snap).ok_or_else(|| {
        miette::miette!(
            "kernel snap carries no board DTBs (searched dtbs/broadcom/, dtbs/dtbs/broadcom/ \
             under {}) — the Pi firmware boots the board device tree, and a boot partition \
             with no DTBs cannot start any board; refusing to build (issue #87)",
            kernel_snap.display()
        )
    })?;
    cp_r(&broadcom, stage)?;
    let overlays = kernel_snap.join("dtbs").join("overlays");
    if overlays.is_dir() {
        cp_r(&overlays, &stage.join("overlays"))?;
    }
    Ok(())
}

/// Stage the gadget's `boot-assets/` verbatim onto the partition tree.
fn stage_boot_assets(gadget_dir: &Path, stage: &Path) -> miette::Result<()> {
    let assets = gadget_dir.join("boot-assets");
    if !assets.is_dir() {
        return Err(miette::miette!(
            "gadget snap ships no boot-assets/ directory (searched {}) — not a piboot \
             (UC20-style) gadget: the Pi firmware blobs (start4.elf, fixup*.dat, \
             bootcode.bin) and config.txt live there, and without them the partition has \
             no firmware to run; refusing to build (issue #87)",
            assets.display()
        ));
    }
    cp_r(&assets, stage)
}

/// Stage the kernel payload verbatim under the names the gadget's
/// `config.txt` references (`kernel=kernel.img`): the gzip wrapper stays —
/// the Pi firmware decompresses gzipped kernel images itself.
fn stage_payload_files(payload: &KernelPayload, stage: &Path) -> miette::Result<()> {
    for (src, dst_name) in [
        (&payload.kernel, "kernel.img"),
        (&payload.initrd, "initrd.img"),
    ] {
        let dst = stage.join(dst_name);
        std::fs::copy(src, &dst)
            .into_diagnostic()
            .wrap_err_with(|| format!("staging {dst_name} onto the Pi boot partition"))?;
    }
    Ok(())
}

/// Rewrite `cmdline.txt`: the image's declared kernel params (the
/// authoritative cmdline — stock UC params are replaced, not merged) plus
/// the root binding. This is the Pi equivalent of the UKI-embedded cmdline.
pub(crate) fn cmdline_txt(params: &[String], root_partuuid: &str) -> String {
    let mut args: Vec<String> = params.to_vec();
    args.push(format!("root=PARTUUID={root_partuuid}"));
    args.join(" ")
}

/// The header written above the transformed `config.txt` — documents the
/// one deviation from verbatim boot-assets.
pub(crate) const CONFIG_TXT_HEADER: &str =
    "# Generated by shuttle (issue #87): staged from the gadget's boot-assets with\n\
     # the `initramfs` line removed — the payload's initrd.img is Canonical's\n\
     # snap-bootstrap initramfs, which mounts a writable ubuntu-data and cannot\n\
     # honor this image's cmdline. The Pi backend boots kernel.img directly\n\
     # against the declared root (ADR-0025 amendment).\n";

/// Transform the gadget's stock `config.txt`: every line kept EXCEPT
/// `initramfs` lines (the stock snap-bootstrap initramfs cannot boot a
/// shuttle root — see [`CONFIG_TXT_HEADER`]). Everything else, including
/// `kernel=kernel.img`, `cmdline=cmdline.txt`, `os_prefix=`, board sections,
/// and dtparam/dtoverlay lines, passes through byte-identical.
pub(crate) fn config_txt_transform(stock: &str) -> String {
    let kept: Vec<&str> = stock
        .lines()
        .filter(|l| !l.trim_start().starts_with("initramfs "))
        .collect();
    format!("{CONFIG_TXT_HEADER}{}\n", kept.join("\n"))
}

/// Rewrite the two generated files on the staged tree: `cmdline.txt` from
/// the image's declared params + root PARTUUID, and `config.txt` from the
/// staged stock file with the `initramfs` line dropped.
fn write_pi_boot_configs(
    stage: &Path,
    params: &[String],
    root_partuuid: &str,
) -> miette::Result<()> {
    let cmdline = stage.join("cmdline.txt");
    std::fs::write(
        &cmdline,
        format!("{}\n", cmdline_txt(params, root_partuuid)),
    )
    .into_diagnostic()
    .wrap_err_with(|| format!("writing {}", cmdline.display()))?;
    let stock_path = stage.join("config.txt");
    let stock = std::fs::read_to_string(&stock_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading the gadget's staged {}", stock_path.display()))?;
    std::fs::write(&stock_path, config_txt_transform(&stock))
        .into_diagnostic()
        .wrap_err_with(|| format!("writing {}", stock_path.display()))?;
    Ok(())
}

/// Build the firmware-visible Pi boot tree and return its staging path:
///
/// ```text
/// piboot-staging/
///   bcm2710-rpi-3-b.dtb …        ← kernel snap dtbs/broadcom (board DTBs)
///   overlays/                     ← kernel dtbs/overlays + gadget overlays
///   bootcode.bin start*.elf …     ← gadget boot-assets/ (verbatim)
///   config.txt                    ← gadget's, `initramfs` line dropped
///   cmdline.txt                   ← declared params + root=PARTUUID
///   kernel.img initrd.img         ← kernel snap payload (verbatim)
/// ```
///
/// Every input is fail-closed: an unreadable gadget, a boot-assets-less
/// gadget, a DTB-less kernel, a missing payload file, or an unresolvable
/// root PARTUUID is a named build error, never a hopeful artifact.
pub(crate) fn stage_pi_boot_assets(inp: PiBootStage) -> miette::Result<PathBuf> {
    let gadget_dir = inp.scratch.join("gadget-snap");
    unsquashfs_gadget(inp.runner, inp.gadget_snap, &gadget_dir)?;
    let stage = inp.scratch.join("piboot-staging");
    std::fs::create_dir_all(&stage)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", stage.display()))?;
    // Kernel-snap tree: the payload lives inside the extracted kernel snap
    // (paths point into it); its dtbs/ sit beside them.
    let kernel_snap = inp
        .payload
        .kernel
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    stage_kernel_dtbs(&kernel_snap, &stage)?;
    stage_boot_assets(&gadget_dir, &stage)?;
    stage_payload_files(inp.payload, &stage)?;
    write_pi_boot_configs(&stage, inp.params, inp.root_partuuid)?;
    eprintln!(
        "  ✓ Pi boot-assets staged: gadget boot-assets + kernel payload (kernel.img, \
         initrd.img) + board DTBs; cmdline.txt carries the declared params + \
         root=PARTUUID={}",
        inp.root_partuuid
    );
    Ok(stage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;

    /// The stock pi-gadget rev 132 `config.txt` head (measured, 2026-09-13):
    /// the lines the backend depends on, plus a board section that must
    /// pass through untouched.
    const STOCK_CONFIG: &str = "[all]\n\
         kernel=kernel.img\n\
         cmdline=cmdline.txt\n\
         initramfs initrd.img followkernel\n\
         os_prefix=\n\
         \n\
         [pi4]\n\
         max_framebuffers=2\n\
         arm_boost=1\n";

    /// The measured pi-kernel 22/stable rev 1137 config lines the audit
    /// reads (`config-5.15.0-1103-raspi`, cropped to the boot-chain set).
    const RASPI_CONFIG: &str = "CONFIG_MD=y\n\
         CONFIG_BLK_DEV_DM=y\n\
         CONFIG_DM_VERITY=m\n\
         CONFIG_MMC=y\n\
         CONFIG_MMC_BLOCK=y\n\
         CONFIG_MMC_SDHCI=y\n\
         CONFIG_EXT4_FS=y\n\
         CONFIG_CRYPTO_SHA256=y\n";

    fn piboot_image() -> ImageDeclaration {
        let mut image = crate::image::test_support::sample_image();
        image.bootloader = Some(BootloaderConfig {
            type_: BOOTLOADER_PIBOOT.into(),
            timeout: 3,
        });
        image
    }

    fn pi_layout() -> DiskLayout {
        DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("fw", "vfat"), part("root", "ext4")],
            swap: None,
            ab: false,
        }
    }

    fn part(name: &str, fs: &str) -> Partition {
        Partition {
            name: name.into(),
            size: "512M".into(),
            fs: fs.into(),
            mount: if fs == "ext4" {
                "/".into()
            } else {
                "/boot".into()
            },
            options: vec![],
            role: String::new(),
        }
    }

    fn root_partuuid() -> String {
        "11111111-2222-3333-4444-555555555555".to_string()
    }

    #[test]
    fn config_txt_transform_drops_the_initramfs_line_and_keeps_the_rest() {
        let out = config_txt_transform(STOCK_CONFIG);
        assert!(
            out.contains(CONFIG_TXT_HEADER),
            "the transformation must document itself: {out}"
        );
        assert!(
            !out.lines()
                .any(|l| !l.starts_with('#') && l.trim_start().starts_with("initramfs ")),
            "the snap-bootstrap initramfs line must be dropped: {out}"
        );
        for kept in [
            "kernel=kernel.img",
            "cmdline=cmdline.txt",
            "os_prefix=",
            "[pi4]",
            "arm_boost=1",
        ] {
            assert!(
                out.contains(kept),
                "stock line '{kept}' must survive: {out}"
            );
        }
    }

    #[test]
    fn config_txt_transform_without_initramfs_keeps_the_body_byte_identical() {
        let stock = "[all]\nkernel=kernel.img\n";
        let out = config_txt_transform(stock);
        assert!(
            out.starts_with(CONFIG_TXT_HEADER) && out.ends_with("[all]\nkernel=kernel.img\n"),
            "body unchanged apart from the header: {out:?}"
        );
    }

    #[test]
    fn cmdline_txt_carries_declared_params_then_the_root_binding() {
        let params = vec!["console=serial0,115200".to_string(), "rootwait".to_string()];
        assert_eq!(
            cmdline_txt(&params, &root_partuuid()),
            format!(
                "console=serial0,115200 rootwait root=PARTUUID={}",
                root_partuuid()
            )
        );
        assert_eq!(
            cmdline_txt(&[], &root_partuuid()),
            format!("root=PARTUUID={}", root_partuuid()),
            "no declared params leaves just the root binding"
        );
    }

    #[test]
    fn audit_accepts_the_measured_raspi_config() {
        audit_builtin_boot_chain(RASPI_CONFIG, "5.15.0-1103-raspi")
            .expect("the real raspi config carries the no-initramfs boot chain built in");
    }

    #[test]
    fn audit_refuses_a_module_only_root_filesystem() {
        let config = "CONFIG_EXT4_FS=m\nCONFIG_MMC=y\nCONFIG_MMC_BLOCK=y\n";
        let err = audit_builtin_boot_chain(config, "5.15.0-1103-raspi").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("CONFIG_EXT4_FS") && msg.contains("WITHOUT an initramfs"),
            "refusal must name the symbol and the no-initramfs reason: {msg}"
        );
    }

    #[test]
    fn audit_refuses_missing_mmc_block_layer() {
        let config = "CONFIG_EXT4_FS=y\nCONFIG_MMC=y\n";
        let err = audit_builtin_boot_chain(config, "5.15.0-1103-raspi").unwrap_err();
        assert!(
            format!("{err:#}").contains("CONFIG_MMC_BLOCK"),
            "the SD block layer must be named: {err:#}"
        );
    }

    #[test]
    fn pairing_refuses_a_pi_payload_on_a_systemd_boot_image() {
        let mut image = crate::image::test_support::sample_image();
        image.bootloader = Some(BootloaderConfig {
            type_: "systemd-boot".into(),
            timeout: 3,
        });
        let err = assert_payload_bootloader_pairing(&image, true, "pi-kernel").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Raspberry Pi kernel shape") && msg.contains("piboot"),
            "the refusal must name the shape and the backend: {msg}"
        );
    }

    #[test]
    fn pairing_refuses_a_non_pi_payload_on_a_piboot_image() {
        let image = piboot_image();
        let err = assert_payload_bootloader_pairing(&image, false, "pc-kernel").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("kernel.img") && msg.contains("pi-kernel"),
            "the refusal must name the missing Pi spellings: {msg}"
        );
    }

    #[test]
    fn pairing_accepts_the_pi_payload_on_a_piboot_image() {
        let image = piboot_image();
        assert_payload_bootloader_pairing(&image, true, "pi-kernel")
            .expect("pi payload + piboot backend is the implemented chain");
    }

    #[test]
    fn preconditions_accept_the_measured_pi_shape() {
        let image = piboot_image();
        assert_piboot_preconditions(&image, &pi_layout())
            .expect("gadget + gpt + single slot + one vfat + ext4 root must pass");
    }

    #[test]
    fn preconditions_refuse_ab_with_the_tryboot_scope_statement() {
        let image = piboot_image();
        let mut layout = pi_layout();
        layout.ab = true;
        let err = assert_piboot_preconditions(&image, &layout).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tryboot") && msg.contains("not implemented"),
            "the A/B refusal must name the Pi tryboot mapping: {msg}"
        );
    }

    #[test]
    fn preconditions_refuse_an_update_source() {
        let mut image = piboot_image();
        image.update_source = Some("https://updates.example".into());
        let err = assert_piboot_preconditions(&image, &pi_layout()).unwrap_err();
        assert!(
            format!("{err:#}").contains("systemd-boot UKI protocol"),
            "the update_source refusal must name the sysupdate protocol: {err:#}"
        );
    }

    #[test]
    fn preconditions_refuse_mbr_disks() {
        let image = piboot_image();
        let mut layout = pi_layout();
        layout.label = "mbr".into();
        let err = assert_piboot_preconditions(&image, &layout).unwrap_err();
        assert!(
            format!("{err:#}").contains("PARTUUID"),
            "the mbr refusal must name the PARTUUID dependency: {err:#}"
        );
    }

    #[test]
    fn preconditions_refuse_a_missing_gadget() {
        let mut image = piboot_image();
        image.gadget = None;
        let err = assert_piboot_preconditions(&image, &pi_layout()).unwrap_err();
        assert!(
            format!("{err:#}").contains("boot-assets"),
            "the gadget refusal must name the boot-assets: {err:#}"
        );
    }

    #[test]
    fn preconditions_refuse_vfat_partition_counts_other_than_one() {
        let image = piboot_image();
        let mut none = pi_layout();
        none.partitions = vec![part("root", "ext4")];
        let err = assert_piboot_preconditions(&image, &none).unwrap_err();
        assert!(format!("{err:#}").contains("exactly one vfat"), "{err:#}");

        let mut two = pi_layout();
        two.partitions = vec![
            part("fw", "vfat"),
            part("fw2", "vfat"),
            part("root", "ext4"),
        ];
        let err = assert_piboot_preconditions(&image, &two).unwrap_err();
        assert!(
            format!("{err:#}").contains("found 2"),
            "two vfat partitions must be ambiguous: {err:#}"
        );
    }

    #[test]
    fn preconditions_refuse_a_non_ext4_root() {
        let image = piboot_image();
        let mut layout = pi_layout();
        layout.partitions[1].fs = "btrfs".into();
        let err = assert_piboot_preconditions(&image, &layout).unwrap_err();
        assert!(
            format!("{err:#}").contains("ext4 root partition")
                && format!("{err:#}").contains("btrfs"),
            "the root-fs refusal must name the audited contract: {err:#}"
        );
    }

    /// Fake runner whose `unsquashfs -d <dir>` extracts a miniature pi
    /// gadget: `boot-assets/` with the stock config.txt/cmdline.txt head, a
    /// firmware blob, and one overlay — the firmware-visible minimum.
    struct GadgetRunner {
        with_boot_assets: bool,
    }

    impl CommandRunner for GadgetRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            // argv[0] is a bare tool name or an absolute path resolved
            // through the tools module (issue #101) — dispatch on the
            // basename either way.
            let program = argv
                .first()
                .map(|p| {
                    Path::new(p)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.clone())
                })
                .unwrap_or_default();
            match program.as_str() {
                "unsquashfs" => {
                    let dir = argv
                        .iter()
                        .position(|a| a == "-d")
                        .and_then(|i| argv.get(i + 1))
                        .expect("unsquashfs argv carries -d");
                    if self.with_boot_assets {
                        let assets = Path::new(dir).join("boot-assets");
                        std::fs::create_dir_all(assets.join("overlays")).unwrap();
                        std::fs::write(assets.join("start4.elf"), b"firmware-blob").unwrap();
                        std::fs::write(assets.join("config.txt"), STOCK_CONFIG).unwrap();
                        std::fs::write(assets.join("cmdline.txt"), "stock params\n").unwrap();
                        std::fs::write(assets.join("overlays/vc4-fkms-v3d.dtbo"), b"dtbo").unwrap();
                    } else {
                        std::fs::create_dir_all(Path::new(dir).join("meta")).unwrap();
                    }
                    Ok(RunnerOutput {
                        code: 0,
                        stdout: Vec::new(),
                        stderr: String::new(),
                    })
                }
                other => panic!("unexpected tool invocation: {other}"),
            }
        }
    }

    /// A miniature extracted pi-kernel tree mirroring the real snap layout
    /// (issue #74): payload files at the snap root, `dtbs/broadcom/` +
    /// `dtbs/overlays/`.
    fn pi_kernel_fixture(dir: &Path) -> KernelPayload {
        std::fs::create_dir_all(dir.join("dtbs/broadcom")).unwrap();
        std::fs::create_dir_all(dir.join("dtbs/overlays")).unwrap();
        std::fs::write(dir.join("dtbs/broadcom/bcm2710-rpi-3-b.dtb"), b"dtb").unwrap();
        std::fs::write(dir.join("dtbs/overlays/disable-bt.dtbo"), b"dtbo").unwrap();
        std::fs::write(dir.join("kernel.img"), [0x1f, 0x8b, 0x08, 0x00]).unwrap();
        std::fs::write(dir.join("initrd.img"), [0x28, 0xb5, 0x2f, 0xfd, 0x00]).unwrap();
        KernelPayload::pi_raw(
            dir.join("kernel.img"),
            dir.join("initrd.img"),
            "5.15.0-1103-raspi".into(),
        )
    }

    #[test]
    fn stage_pi_boot_assets_builds_the_firmware_visible_tree() {
        let scratch = tempfile::tempdir().unwrap();
        let kernel = tempfile::tempdir().unwrap();
        let payload = pi_kernel_fixture(kernel.path());
        let gadget_snap = scratch.path().join("pi_132_x.snap");
        std::fs::write(&gadget_snap, b"squashfs").unwrap();
        let params = vec!["rootwait".to_string(), "quiet".to_string()];

        let stage = stage_pi_boot_assets(PiBootStage {
            runner: &GadgetRunner {
                with_boot_assets: true,
            },
            scratch: scratch.path(),
            gadget_snap: &gadget_snap,
            payload: &payload,
            params: &params,
            root_partuuid: &root_partuuid(),
        })
        .expect("the miniature measured layout must stage");

        // Payload verbatim under the names config.txt references.
        assert_eq!(
            std::fs::read(stage.join("kernel.img")).unwrap(),
            vec![0x1f, 0x8b, 0x08, 0x00],
            "kernel.img must be byte-identical (gzip wrapper stays)"
        );
        assert_eq!(
            std::fs::read(stage.join("initrd.img")).unwrap(),
            vec![0x28, 0xb5, 0x2f, 0xfd, 0x00],
            "initrd.img must be byte-identical"
        );
        // Gadget boot-assets verbatim.
        assert_eq!(
            std::fs::read(stage.join("start4.elf")).unwrap(),
            b"firmware-blob".to_vec(),
            "firmware blobs pass through"
        );
        // Kernel DTBs + both overlay sources merged.
        assert!(
            stage.join("bcm2710-rpi-3-b.dtb").is_file(),
            "board DTB at the root"
        );
        assert!(
            stage.join("overlays/disable-bt.dtbo").is_file(),
            "kernel overlay"
        );
        assert!(
            stage.join("overlays/vc4-fkms-v3d.dtbo").is_file(),
            "gadget overlay"
        );
        // Generated configs.
        let cmdline = std::fs::read_to_string(stage.join("cmdline.txt")).unwrap();
        assert_eq!(
            cmdline,
            format!("rootwait quiet root=PARTUUID={}\n", root_partuuid()),
            "declared params + root binding, one line"
        );
        let config = std::fs::read_to_string(stage.join("config.txt")).unwrap();
        assert!(config.contains("kernel=kernel.img"));
        assert!(
            !config
                .lines()
                .any(|l| !l.starts_with('#') && l.trim_start().starts_with("initramfs ")),
            "the staged config must not carry the snap-bootstrap initramfs line: {config}"
        );
        assert!(
            !config.contains("stock params"),
            "cmdline.txt is generated, not the stock one"
        );
    }

    #[test]
    fn stage_pi_boot_assets_fails_closed_without_boot_assets() {
        let scratch = tempfile::tempdir().unwrap();
        let kernel = tempfile::tempdir().unwrap();
        let payload = pi_kernel_fixture(kernel.path());
        let gadget_snap = scratch.path().join("pc_9_x.snap");
        std::fs::write(&gadget_snap, b"squashfs").unwrap();

        let err = stage_pi_boot_assets(PiBootStage {
            runner: &GadgetRunner {
                with_boot_assets: false,
            },
            scratch: scratch.path(),
            gadget_snap: &gadget_snap,
            payload: &payload,
            params: &[],
            root_partuuid: &root_partuuid(),
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("boot-assets"),
            "a non-piboot gadget must be named: {err:#}"
        );
    }

    #[test]
    fn stage_pi_boot_assets_fails_closed_without_board_dtbs() {
        let scratch = tempfile::tempdir().unwrap();
        let kernel = tempfile::tempdir().unwrap();
        let mut payload = pi_kernel_fixture(kernel.path());
        // The firmware-visible minimum needs the board trees.
        std::fs::remove_dir_all(kernel.path().join("dtbs")).unwrap();
        payload.kernel = kernel.path().join("kernel.img");
        let gadget_snap = scratch.path().join("pi_132_x.snap");
        std::fs::write(&gadget_snap, b"squashfs").unwrap();

        let err = stage_pi_boot_assets(PiBootStage {
            runner: &GadgetRunner {
                with_boot_assets: true,
            },
            scratch: scratch.path(),
            gadget_snap: &gadget_snap,
            payload: &payload,
            params: &[],
            root_partuuid: &root_partuuid(),
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no board DTBs") && msg.contains("dtbs/broadcom"),
            "the DTB refusal must name the searched spellings: {msg}"
        );
    }
}
