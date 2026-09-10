//! Partition lifecycle — extents, mkfs, populate, splice,
//! geometry, and Ubuntu Core routing (issue #57).

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use super::*;

/// GPT partition name passed to `parted mkpart` — the partition's declared
/// `name` becomes BOTH the GPT PARTLABEL (matched by the UC initrd's
/// `90-ubuntu-core-partitions.rules` as `ID_PART_ENTRY_NAME`) and the mkfs
/// filesystem label, so the two never diverge. For GPT labels the first
/// positional arg after `mkpart` IS the partition name; for MBR (msdos)
/// labels it is the partition TYPE, which the code always hardcodes to
/// `"primary"`. A partition with no declared name defaults to `"primary"`
/// so existing non-UC images are byte-identical.
pub(crate) fn mkpart_name(label: &str, part: &Partition) -> String {
    if label == "gpt" {
        if part.name.is_empty() {
            "primary".to_string()
        } else {
            part.name.clone()
        }
    } else {
        "primary".to_string()
    }
}

/// Build the `parted mkpart` argv for one partition (name, fs-type, start,
/// end) so the GPT PARTLABEL source is unit-testable without running
/// parted. `mkpart_name` supplies the partition name / MBR type.
pub(crate) fn parted_mkpart_args(
    img_path: &Path,
    label: &str,
    part: &Partition,
    start_mb: u64,
    end_mb: u64,
) -> Vec<String> {
    let fs_type = if part.fs == "vfat" {
        "fat32".to_string()
    } else {
        part.fs.clone()
    };
    vec![
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "mkpart".to_string(),
        mkpart_name(label, part),
        fs_type,
        format!("{start_mb}MB"),
        format!("{end_mb}MB"),
    ]
}

/// Create the raw disk image with dd, lay out partitions with parted, and
/// set the ESP flag on the first partition.
pub(crate) fn create_partitions(
    runner: &dyn CommandRunner,
    img_path: &Path,
    layout: &DiskLayout,
    total_mb: u64,
) -> miette::Result<()> {
    let argv: Vec<String> = vec![
        "dd".to_string(),
        "if=/dev/zero".to_string(),
        format!("of={}", img_path.display()),
        "bs=1M".to_string(),
        format!("count={total_mb}"),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("dd not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!("dd failed to create disk image"));
    }

    let argv: Vec<String> = [
        "parted".to_string(),
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "mklabel".to_string(),
        layout.label.clone(),
    ]
    .to_vec();
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("parted not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!("parted failed to create partition table"));
    }

    let mut part_start_mb = 4u64; // after GPT
    for (part_num, part) in layout.partitions.iter().enumerate() {
        let size_mb = parse_size_mb(&part.size, total_mb - part_start_mb);
        let end_mb = part_start_mb + size_mb;

        let argv = std::iter::once("parted".to_string())
            .chain(parted_mkpart_args(
                img_path,
                &layout.label,
                part,
                part_start_mb,
                end_mb,
            ))
            .collect::<Vec<String>>();
        let out = runner
            .run(&argv)
            .map_err(|e| miette::miette!("parted: {e}"))?;
        if out.code != 0 {
            return Err(miette::miette!(
                "parted failed to create partition '{}'",
                part.name
            ));
        }

        if part_num == 0 {
            set_esp_flag(runner, img_path);
        }

        part_start_mb = end_mb;
    }

    if let Some(ref swap) = layout.swap {
        create_swap_partition(runner, img_path, swap, part_start_mb)?;
    }
    Ok(())
}

/// Set the GPT esp flag on partition 1; a failure is reported but not
/// fatal (matching the historical behavior — the vfat fs still works).
pub(crate) fn set_esp_flag(runner: &dyn CommandRunner, img_path: &Path) {
    let argv = vec![
        "parted".to_string(),
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "set".to_string(),
        "1".to_string(),
        "esp".to_string(),
        "on".to_string(),
    ];
    if !runner.run(&argv).is_ok_and(|o| o.code == 0) {
        eprintln!("  ⚠ failed to set ESP flag");
    }
}

/// Add the declared swap partition (if any) after the data partitions.
pub(crate) fn create_swap_partition(
    runner: &dyn CommandRunner,
    img_path: &Path,
    swap: &SwapConfig,
    part_start_mb: u64,
) -> miette::Result<()> {
    let swap_size = parse_size_mb(&swap.size, 0);
    if swap_size == 0 {
        return Ok(());
    }
    let end_mb = part_start_mb + swap_size;
    let argv: Vec<String> = vec![
        "parted".to_string(),
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "mkpart".to_string(),
        "primary".to_string(),
        "linux-swap".to_string(),
        format!("{}MB", part_start_mb),
        format!("{}MB", end_mb),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("parted: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!("parted failed to create swap partition"));
    }
    Ok(())
}

/// One partition's authoritative geometry + GPT PARTUUID, read back from
/// the finished partition table. `start_bytes`/`size_bytes` are derived
/// from sfdisk's 512-byte-sector `start`/`size` fields (scaled by the
/// table's reported sector-size when present); the vec index equals the
/// parted partition number - 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartitionExtent {
    pub(crate) start_bytes: u64,
    pub(crate) size_bytes: u64,
    pub(crate) partuuid: Option<String>,
}

/// Parse `sfdisk -J` JSON into partition extents. Fail closed: a missing
/// partitiontable, a missing/invalid start or size, or unparseable JSON is
/// an error — a guessed offset would splice a filesystem over the wrong
/// partition.
pub(crate) fn parse_partition_extents(json: &str) -> miette::Result<Vec<PartitionExtent>> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        miette::miette!(
            "sfdisk -J printed unparseable JSON ({e}) — refusing to guess partition offsets"
        )
    })?;
    let table = value.get("partitiontable").ok_or_else(|| {
        miette::miette!(
            "sfdisk -J output carries no 'partitiontable' — refusing to guess \
             partition offsets"
        )
    })?;
    let sector_size = table
        .get("sector-size")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(512);
    let partitions = table
        .get("partitions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            miette::miette!(
                "sfdisk -J output carries no 'partitiontable.partitions' array — \
                 refusing to guess partition offsets"
            )
        })?;
    partitions
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let sector = |key: &str| -> miette::Result<u64> {
                part.get(key)
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        miette::miette!(
                            "sfdisk -J partition {} carries no valid '{key}' sector \
                             field — refusing to guess partition offsets",
                            i + 1
                        )
                    })
            };
            Ok(PartitionExtent {
                start_bytes: sector("start")? * sector_size,
                size_bytes: sector("size")? * sector_size,
                partuuid: part
                    .get("uuid")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect()
}

/// Read the authoritative partition geometry back from the finished image
/// with one `sfdisk -J` call. `expected` is the partition count
/// [`create_partitions`] laid out (declared partitions + swap); a mismatch
/// fails closed — populating from misaligned extents would corrupt
/// neighboring partitions.
pub(crate) fn read_partition_extents(
    runner: &dyn CommandRunner,
    img_path: &Path,
    expected: usize,
) -> miette::Result<Vec<PartitionExtent>> {
    let argv = vec![
        "sfdisk".to_string(),
        "-J".to_string(),
        img_path.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("sfdisk not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "sfdisk -J failed reading back the partition table ({}): {}",
            crate::command::exit_code(&out),
            out.stderr.trim()
        ));
    }
    let extents = parse_partition_extents(&String::from_utf8_lossy(&out.stdout))?;
    if extents.len() != expected {
        return Err(miette::miette!(
            "partition table read-back found {} partitions but the layout created \
             {expected} — refusing to populate from misaligned extents",
            extents.len()
        ));
    }
    Ok(extents)
}

/// Shared context for the populate stage — everything the per-partition
/// workers need besides the partition itself. Partition geometry comes
/// from the read-back [`PartitionExtent`]s; every partition is built as a
/// standalone file and spliced, so nothing here is a device path.
pub(crate) struct PopulateCtx<'a> {
    pub(crate) image: &'a ImageDeclaration,
    pub(crate) extents: &'a [PartitionExtent],
    pub(crate) scratch_dir: &'a Path,
    pub(crate) root: &'a Path,
    pub(crate) uki: Option<&'a UkiFacts>,
    pub(crate) uki_stage: &'a Path,
    /// Ubuntu Core seed/role-model staging (issue #32). `None` for the
    /// non-UC/unsimplified path — content routing falls back to the
    /// historical behavior.
    pub(crate) uc: Option<&'a UcCtx>,
}

/// Ubuntu Core seed/role-model context threaded into the populate stage.
/// Carries the staged seed tree (`ubuntu-seed`) and boot tree
/// (`ubuntu-boot` with `device/modeenv`) built by [`setup_uc_context`].
pub(crate) struct UcCtx {
    pub(crate) seed_stage: PathBuf,
    pub(crate) boot_stage: PathBuf,
}

impl PopulateCtx<'_> {
    /// The staged tree a UC role-marked partition should be populated from,
    /// or `None` when the partition carries no UC role (falls through to the
    /// ESP/data behavior).
    pub(crate) fn uc_route_stage(&self, part: &Partition) -> Option<&Path> {
        let uc = self.uc?;
        match partition_uc_role(part)? {
            crate::uc::ROLE_SEED => Some(&uc.seed_stage),
            crate::uc::ROLE_BOOT => Some(&uc.boot_stage),
            _ => None,
        }
    }
}

/// Create (or truncate) a standalone partition file at the EXACT extent
/// size — a larger file would make [`splice_into`] overrun the next
/// partition; a smaller one would splice short. Sparse, zero-filled.
pub(crate) fn extent_file(
    build_dir: &Path,
    name: &str,
    extent: &PartitionExtent,
) -> miette::Result<PathBuf> {
    let path = build_dir.join(name);
    let f = std::fs::File::create(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", path.display()))?;
    f.set_len(extent.size_bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("sizing {} to {} bytes", path.display(), extent.size_bytes))?;
    Ok(path)
}

/// Splice a fully-built standalone partition file into the image at its
/// extent offset — in-process `io::copy` bounded by `.take()`, so neither
/// a mis-sized source nor a future regression can overrun the next
/// partition.
pub(crate) fn splice_into(
    img: &Path,
    part_file: &Path,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    use std::io::{Read, Seek, Write};
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .open(img)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {}", img.display()))?;
    dst.seek(std::io::SeekFrom::Start(extent.start_bytes))
        .into_diagnostic()
        .wrap_err("seeking into the disk image")?;
    let src = std::fs::File::open(part_file)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {}", part_file.display()))?;
    let copied = std::io::copy(&mut src.take(extent.size_bytes), &mut dst)
        .into_diagnostic()
        .wrap_err("splicing a partition into the disk image")?;
    if copied != extent.size_bytes {
        return Err(miette::miette!(
            "partition file {} is {} bytes short of its extent — refusing to splice \
             a short partition (the tail would carry stale image bytes)",
            part_file.display(),
            extent.size_bytes - copied
        ));
    }
    dst.flush().into_diagnostic()?;
    Ok(())
}

/// Fail closed on filesystems the file-based (unprivileged) build cannot
/// populate: `mkfs.btrfs` cannot fill a filesystem from a directory tree,
/// so btrfs needs a loop-device backend.
pub(crate) fn refuse_non_ext4_vfat(part: &Partition) -> miette::Result<()> {
    match part.fs.as_str() {
        "ext4" | "vfat" => Ok(()),
        other => Err(miette::miette!(
            "partition '{}' declares filesystem '{other}' — the unprivileged image \
             build supports ext4 and vfat; btrfs needs a loop-device backend",
            part.name
        )),
    }
}

/// mkfs + populate a standalone ext4 partition file from a staged tree in
/// one `mkfs.ext4 -d` pass — no mount, no root. The file must already be
/// truncated to the exact extent ([`extent_file`]); the block count pins
/// the filesystem inside it (mkfs may leave an unused tail — fine, it can
/// never overrun). The verity variant pins [`VERITY_BLOCK_SIZE`] fs blocks
/// via [`mkfs_flags_for`] so the root mounts over its dm-verity mapping.
pub(crate) fn build_ext4_partition(
    runner: &dyn CommandRunner,
    part_file: &Path,
    staged_root: &Path,
    part: &Partition,
    extent: &PartitionExtent,
    verity: bool,
) -> miette::Result<()> {
    let (tool, flags) = mkfs_flags_for(&part.fs, verity)?;
    let block_count = (extent.size_bytes / u64::from(VERITY_BLOCK_SIZE)).to_string();
    let mut args: Vec<String> = flags;
    args.push(part.name.clone()); // label — mkfs_flags_for ends its flags with the label option
    args.push("-d".into());
    args.push(staged_root.to_string_lossy().into_owned());
    args.push(part_file.to_string_lossy().into_owned());
    args.push(block_count);
    let argv: Vec<String> = std::iter::once(tool.to_string()).chain(args).collect();
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "{tool} -d failed to build the {} partition '{}' (exit {})",
            part.fs,
            part.name,
            crate::command::exit_code(&out)
        ));
    }
    Ok(())
}

/// Sorted-walk helper for [`mtools_populate_vfat`]: relative paths of
/// every file and directory under `staged`, parents before children.
pub(crate) fn collect_staged_entries(
    staged: &Path,
    rel: &Path,
    out: &mut Vec<(String, bool)>,
) -> miette::Result<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(staged)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", staged.display()))?
        .collect::<Result<Vec<_>, _>>()
        .into_diagnostic()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let child_rel = rel.join(entry.file_name());
        if entry.path().is_dir() {
            out.push((child_rel.to_string_lossy().into_owned(), true));
            collect_staged_entries(&entry.path(), &child_rel, out)?;
        } else {
            out.push((child_rel.to_string_lossy().into_owned(), false));
        }
    }
    Ok(())
}

/// Populate a standalone vfat file (the ESP) with mtools — no mount, no
/// root. The staged tree is walked in sorted order (directories before
/// their contents fall out of a lexicographic sort: a parent path is a
/// strict prefix of its children) so the FAT layout is deterministic;
/// each directory is created with `mmd`, each file copied with `mcopy`.
/// Only the exit status decides — mkfs/mtools may print benign warnings
/// (e.g. "less than suggested minimum clusters" on small extents).
pub(crate) fn mtools_populate_vfat(
    runner: &dyn CommandRunner,
    vfat_file: &Path,
    staged: &Path,
) -> miette::Result<()> {
    let mut entries: Vec<(String, bool)> = Vec::new();
    collect_staged_entries(staged, Path::new(""), &mut entries)?;
    entries.sort();
    for (rel, is_dir) in entries {
        let target = format!("::/{rel}");
        if is_dir {
            let argv = vec![
                "mmd".to_string(),
                "-i".to_string(),
                vfat_file.to_string_lossy().into_owned(),
                target.clone(),
            ];
            let out = runner
                .run(&argv)
                .map_err(|e| miette::miette!("mmd not found: {e}"))?;
            if out.code != 0 {
                return Err(miette::miette!("mmd failed creating {target} on the ESP"));
            }
        } else {
            let argv = vec![
                "mcopy".to_string(),
                "-i".to_string(),
                vfat_file.to_string_lossy().into_owned(),
                staged.join(&rel).to_string_lossy().into_owned(),
                target.clone(),
            ];
            let out = runner
                .run(&argv)
                .map_err(|e| miette::miette!("mcopy not found: {e}"))?;
            if out.code != 0 {
                return Err(miette::miette!("mcopy failed copying /{rel} onto the ESP"));
            }
        }
    }
    Ok(())
}

/// Build and splice every partition EXCEPT the root slots (already
/// populated + verity-formatted in [`build_disk_image`] step 9) and the
/// auto-appended verity-hash partitions (raw `veritysetup` output — never
/// mkfs'd, never mounted) — both carried in `skip`. Partition 1 when vfat
/// is the ESP (systemd-boot fallback binary, UKI, loader.conf — staged
/// into a tree and copied on with mtools); every other partition receives
/// the staged rootfs through `mkfs.ext4 -d`.
pub(crate) fn populate_remaining_partitions(
    runner: &dyn CommandRunner,
    ctx: &PopulateCtx,
    layout: &DiskLayout,
    skip: &[usize],
) -> miette::Result<()> {
    for (i, part) in layout.partitions.iter().enumerate() {
        if skip.contains(&i) || part.name == VERITY_HASH_PART_NAME {
            continue;
        }
        populate_side_partition(runner, ctx, i, part)?;
    }
    Ok(())
}

/// Build one non-root partition as a standalone file and splice it in:
/// the ESP (partition 1, vfat) is mkfs.vfat'd and populated with mtools
/// from the staged EFI tree; other data partitions receive the staged
/// rootfs via `mkfs.ext4 -d`. Failures here leave the partition
/// unpopulated (historical warn-not-fatal side-partition behavior); a
/// btrfs (or other unpopulatable) filesystem fails closed
/// ([`refuse_non_ext4_vfat`]).
pub(crate) fn populate_side_partition(
    runner: &dyn CommandRunner,
    ctx: &PopulateCtx,
    index: usize,
    part: &Partition,
) -> miette::Result<()> {
    refuse_non_ext4_vfat(part)?;
    let extent = &ctx.extents[index];
    let part_file = extent_file(ctx.scratch_dir, &format!("part-{}.img", index + 1), extent)?;
    // Ubuntu Core routing (issue #32): a role-marked seed/boot partition is
    // populated from its dedicated staged tree (seed / modeenv), never the
    // rootfs — the UC role model replaces the simplified "everything is the
    // rootfs" routing for those partitions.
    if let Some(stage) = ctx.uc_route_stage(part) {
        build_staged_partition(runner, &part_file, part, stage, extent)?;
    } else if index == 0 && part.fs == "vfat" {
        build_esp_partition(runner, ctx, &part_file, part)?;
    } else {
        build_data_partition(runner, ctx, &part_file, part, extent)?;
    }
    splice_into(&ctx.scratch_dir.join("disk.img"), &part_file, extent)
}

/// mkfs.vfat the standalone ESP file and copy the staged boot tree on with
/// mtools (no offset syntax needed — the file IS the partition).
/// Warn-not-fatal: a failure leaves the ESP unpopulated (historical
/// side-partition behavior — the mount attempt used to decide).
pub(crate) fn build_esp_partition(
    runner: &dyn CommandRunner,
    ctx: &PopulateCtx,
    part_file: &Path,
    part: &Partition,
) -> miette::Result<()> {
    let esp_stage = ctx.scratch_dir.join("esp-staging");
    populate_esp(runner, &esp_stage.join("EFI").join("BOOT"))?;
    install_uki(ctx.image, &esp_stage, ctx.uki, ctx.uki_stage)?;
    let (tool, flags) = mkfs_flags_for("vfat", false)?;
    let mut args: Vec<String> = flags;
    args.push(part.name.clone()); // -n label
    args.push(part_file.to_string_lossy().into_owned());
    let argv: Vec<String> = std::iter::once(tool.to_string()).chain(args).collect();
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if out.code != 0 {
        eprintln!("  ⚠ {tool} failed for {} — ESP left unpopulated", part.name);
        return Ok(());
    }
    if let Err(e) = mtools_populate_vfat(runner, part_file, &esp_stage) {
        eprintln!(
            "  ⚠ mtools failed populating the ESP ({}): {e:#}",
            part.name
        );
        return Ok(());
    }
    eprintln!("  ✓ ESP: {} (vfat)", part.name);
    Ok(())
}

/// mkfs + populate one partition from a dedicated staged tree (the UC seed
/// or boot tree) through `mkfs.ext4 -d`. Unlike the historical
/// warn-not-fatal side-partition behavior, a UC seed/boot populate failure
/// is FATAL: an `ubuntu-seed`/`ubuntu-boot` that cannot be read would leave
/// snap-bootstrap without a model/seed/modeenv and stop at `cannot detect
/// mode` — a silently-broken UC image is worse than a loud build failure.
pub(crate) fn build_staged_partition(
    runner: &dyn CommandRunner,
    part_file: &Path,
    part: &Partition,
    stage: &Path,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    build_ext4_partition(runner, part_file, stage, part, extent, false)
        .wrap_err_with(|| format!("UC {} partition '{}' populate failed", part.fs, part.name))?;
    eprintln!("  ✓ {}: {} populated (UC staged tree)", part.name, part.fs);
    Ok(())
}

/// mkfs + populate one data partition from the staged rootfs (authoritative
/// manifest included) through `mkfs.ext4 -d`, then splice it in.
/// Warn-not-fatal: a failure leaves the partition unpopulated (historical
/// side-partition behavior — the mount attempt used to decide).
pub(crate) fn build_data_partition(
    runner: &dyn CommandRunner,
    ctx: &PopulateCtx,
    part_file: &Path,
    part: &Partition,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    if let Err(e) = build_ext4_partition(runner, part_file, ctx.root, part, extent, false) {
        eprintln!(
            "  ⚠ {}: {} populate failed ({e:#}) — partition left unpopulated",
            part.name, part.fs
        );
        return Ok(());
    }
    eprintln!("  ✓ {}: {} populated", part.name, part.fs);
    Ok(())
}

/// mkfs tool + leading flags for one partition filesystem (the label and
/// remaining args are appended by the caller). `verity` marks the partition as
/// a dm-verity data device (a root slot in the verity branch): the
/// filesystem is then pinned to [`VERITY_BLOCK_SIZE`] blocks so it mounts
/// over the verity mapping — ext4 via `-b`, btrfs via nodesize +
/// sectorsize. vfat + verity fails closed: FAT has no block-size knob and
/// cannot serve as a verity data device.
pub(crate) fn mkfs_flags_for(
    fs: &str,
    verity: bool,
) -> miette::Result<(&'static str, Vec<String>)> {
    let bs = VERITY_BLOCK_SIZE.to_string();
    let (tool, flags): (&'static str, Vec<String>) = match (fs, verity) {
        ("vfat", true) => {
            return Err(miette::miette!(
                "root filesystem 'vfat' is incompatible with dm-verity — FAT has no \
                 {VERITY_BLOCK_SIZE}-byte block-size knob and cannot be a verity data \
                 device; declare an ext4 (or btrfs) root"
            ));
        }
        ("vfat", false) => ("mkfs.vfat", vec!["-F".into(), "32".into(), "-n".into()]),
        ("btrfs", true) => (
            "mkfs.btrfs",
            vec![
                "-f".into(),
                "--nodesize".into(),
                bs.clone(),
                "--sectorsize".into(),
                bs,
                "-L".into(),
            ],
        ),
        ("btrfs", false) => ("mkfs.btrfs", vec!["-f".into(), "-L".into()]),
        (_, true) => ("mkfs.ext4", vec!["-F".into(), "-b".into(), bs, "-L".into()]),
        (_, false) => ("mkfs.ext4", vec!["-F".into(), "-L".into()]),
    };
    Ok((tool, flags))
}

// ── Ubuntu Core seed / role-model wiring (issue #32) ──

/// UC gadget role of a partition, inferred from its explicit `role` opt or
/// its `ubuntu-*` PARTLABEL name. Returns the gadget role (`system-seed`,
/// `system-boot`, `system-data`) when the partition participates in the UC
/// role model; `None` for ordinary partitions (the simplified path).
pub(crate) fn partition_uc_role(part: &Partition) -> Option<&'static str> {
    // Explicit role opt wins; a recognized role maps to a UC PARTLABEL.
    if crate::uc::role_partlabel(&part.role).is_some() {
        return crate::uc::role_partlabel(&part.role).and_then(uc_role_for_partlabel);
    }
    // Infer from the PARTLABEL name.
    uc_role_for_partlabel(&part.name)
}

/// Map a UC PARTLABEL name back to its gadget role.
pub(crate) fn uc_role_for_partlabel(label: &str) -> Option<&'static str> {
    match label {
        crate::uc::UC_SEED_PART => Some(crate::uc::ROLE_SEED),
        crate::uc::UC_BOOT_PART => Some(crate::uc::ROLE_BOOT),
        crate::uc::UC_DATA_PART => Some(crate::uc::ROLE_DATA),
        _ => None,
    }
}

/// Activate the Ubuntu Core seed/role-model path (issue #32).
///
/// Active only when BOTH conditions hold:
/// - the image base is a UC coreN base (`core22`/`core24`/`core26` …), and
/// - the layout declares at least one partition with a UC gadget role
///   (`role = "system-seed"` … or a `ubuntu-*` name).
///
/// When active, role-marked partitions are remapped to their UC PARTLABEL
/// (`ubuntu-seed`/`ubuntu-boot`/`ubuntu-data`) — the remap runs BEFORE
/// partitioning so the parted-created GPT PARTLABELs come out correct — and
/// the seed tree (`seed.yaml` + signed model assertion) and boot tree
/// (`device/modeenv`) are staged into scratch dirs for the populate stage.
///
/// Non-UC bases, and coreN bases that mark no partition for a UC role, are
/// returned as `Ok(None)` unchanged — the simplified path is bit-identical.
pub(crate) fn setup_uc_context(
    image: &ImageDeclaration,
    layout: &mut DiskLayout,
    scratch: &Path,
    arch: &str,
    resolved: &[ResolvedSnap],
) -> miette::Result<Option<UcCtx>> {
    if !crate::uc::is_uc_base(&image.base.name) {
        return Ok(None);
    }
    let any_role = layout
        .partitions
        .iter()
        .any(|p| partition_uc_role(p).is_some());
    if !any_role {
        eprintln!(
            "  ℹ image base {} is Ubuntu Core but no partition declares a UC gadget role \
             (role = \"system-seed\"/\"system-boot\"/\"system-data\") — simplified path kept",
            image.base.name
        );
        return Ok(None);
    }

    // Remap role-marked partitions to their UC PARTLABEL. This mutates the
    // effective layout BEFORE `create_partitions` so parted's mkpart emits
    // the right GPT names (and `mkfs` labels).
    for part in &mut layout.partitions {
        if let Some(role) = partition_uc_role(part) {
            if let Some(label) = crate::uc::role_partlabel(role) {
                if part.name != label {
                    eprintln!(
                        "  ✓ UC role {role}: partition '{}' → PARTLABEL '{label}'",
                        part.name
                    );
                    part.name = label.to_string();
                }
            }
        }
    }

    // Build the signed model assertion and stage the seed + modeenv trees.
    let model = crate::uc::ModelAssertion::from_image(image, arch)?;
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let kp = match crate::sign::load_secret_key(&home)? {
        Some(kp) => kp,
        None => crate::sign::create_secret_key(&home)?,
    };
    let seed_stage = scratch.join("uc-seed-staging");
    crate::uc::emit_seed(&seed_stage, image, resolved, &model, &kp)?;
    let label = crate::uc::recovery_label(image);
    let boot_stage = scratch.join("uc-boot-staging");
    let kernel_name = image.kernel.as_ref().map(|k| k.snap.name.as_str());
    let gadget_name = image.gadget.as_ref().map(|g| g.name.as_str());
    crate::uc::emit_modeenv(
        &boot_stage,
        &label,
        kernel_name,
        &image.base.name,
        gadget_name,
    )?;
    eprintln!(
        "  ✓ UC seed + modeenv staged (recovery system label {label}, key id {})",
        kp.key_id()
    );
    Ok(Some(UcCtx {
        seed_stage,
        boot_stage,
    }))
}
