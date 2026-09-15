//! Partition lifecycle — extents, mkfs, populate, splice,
//! geometry, and Ubuntu Core routing (issue #57).
//!
//! Reproducible identity (#48): every random-per-build byte the unprivileged
//! pipeline would otherwise mint — parted's GPT disk GUID and partition
//! GUIDs, mke2fs's filesystem UUID and directory-hash seed, verity's salt —
//! is replaced by a derivation over the image identity (`name|version` +
//! partition name/index). Same declaration + same inputs ⇒ same bytes, so a
//! rebuild diff (`examples/rebuild-compare.sh`) can prove it.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use super::*;

/// Derivation namespaces for the deterministic identity GUIDs (#48).
/// Distinct constants keep a partition's PARTUUID, its filesystem UUID, and
/// its directory-hash seed from ever colliding by accident.
pub(crate) const GUID_NS_DISK: &str = "shuttle.gpt.disk.v1";
pub(crate) const GUID_NS_PARTITION: &str = "shuttle.gpt.part.v1";
pub(crate) const GUID_NS_FSUUID: &str = "shuttle.ext4.uuid.v1";
pub(crate) const GUID_NS_HASH_SEED: &str = "shuttle.ext4.hashseed.v1";

/// A deterministic GUID derived from `namespace` + `parts` (SHA-256, first
/// 16 bytes, dashed) — the reproducible replacement for the random GUIDs
/// parted/mke2fs would mint per run (#48). Mirrors the roothash-derived
/// generation GUID convention (`generation_guids_from_roothash`): raw
/// dashed hex, no RFC-4122 version bits.
pub(crate) fn identity_guid(namespace: &str, parts: &[&str]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(namespace.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32],
    )
}

/// CRC-32 (IEEE 802.3, the polynomial GPT headers use), table-free.
fn gpt_crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Parse a dashed GUID string into the 16-byte little-endian-mixed form the
/// GPT on-disk format uses (first three fields little-endian, last two
/// big-endian). The same encoding `sfdisk --part-uuid` writes for the same
/// string, so derived PARTUUIDs and the patched disk GUID share one
/// representation.
fn guid_bytes(guid: &str) -> miette::Result<[u8; 16]> {
    let hex: String = guid.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(miette::miette!(
            "GUID {guid:?} is not a dashed 32-hex string — cannot encode it into the GPT"
        ));
    }
    fn field(hex: &str, le: bool) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hexdigit checked above"))
            .collect();
        if le {
            bytes.reverse();
        }
        bytes
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&field(&hex[0..8], true));
    out[4..6].copy_from_slice(&field(&hex[8..12], true));
    out[6..8].copy_from_slice(&field(&hex[12..16], true));
    out[8..10].copy_from_slice(&field(&hex[16..20], false));
    out[10..16].copy_from_slice(&field(&hex[20..32], false));
    Ok(out)
}

/// Overwrite the GPT disk GUID (primary + backup header) with `guid` and
/// refresh both header CRC32s, in place — parted mints a fresh random disk
/// GUID at `mklabel` time, which would make every image irreproducible (#48).
/// Pure file surgery on the raw image (the same unprivileged style as
/// [`splice_into`]); fails closed when either header does not carry the
/// `EFI PART` signature — a table that did not land is not silently shipped.
pub(crate) fn set_disk_guid(img_path: &Path, guid: &str) -> miette::Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    const SIG: &[u8; 8] = b"EFI PART";
    let bytes = guid_bytes(guid)?;
    let sector: u64 = 512;
    let mut img = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(img_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {} for the disk GUID patch", img_path.display()))?;
    // Primary header at LBA1; the backup's LBA is read out of the primary
    // (header offset 32, little-endian u64).
    let mut raw = [0u8; 8];
    img.seek(SeekFrom::Start(sector + 32)).into_diagnostic()?;
    img.read_exact(&mut raw).into_diagnostic()?;
    let backup_offset = u64::from_le_bytes(raw) * sector;
    for (label, offset) in [("GPT header", sector), ("backup GPT header", backup_offset)] {
        let mut header = [0u8; 92];
        img.seek(SeekFrom::Start(offset)).into_diagnostic()?;
        img.read_exact(&mut header).into_diagnostic()?;
        if &header[0..8] != SIG {
            return Err(miette::miette!(
                "no {label} at offset {offset} of {} — parted did not lay the table it \
                 reported; refusing to patch a disk GUID onto a non-GPT image",
                img_path.display()
            ));
        }
        header[56..72].copy_from_slice(&bytes); // disk GUID (header offset 56)
        header[16..20].copy_from_slice(&0u32.to_le_bytes()); // the header CRC covers itself as zero
        let crc = gpt_crc32(&header);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
        img.seek(SeekFrom::Start(offset)).into_diagnostic()?;
        img.write_all(&header).into_diagnostic()?;
    }
    Ok(())
}

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

/// Create the raw disk image with dd and lay out partitions with parted.
/// The GPT esp flag (the EFI System PARTITION TYPE GUID — what firmware
/// scans for when it looks for `\EFI\boot\bootx64.efi`) lands on
/// `esp_partition` when given (the UC path marks `ubuntu-seed`, which is
/// the pc gadget's ESP), else on the first partition (the historical
/// simplified-path ESP).
pub(crate) fn create_partitions(
    runner: &dyn CommandRunner,
    img_path: &Path,
    layout: &DiskLayout,
    total_mb: u64,
    esp_partition: Option<usize>,
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
        let size_mb = partition_size_mb(layout, part_num, total_mb, part_start_mb)?;
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

        if part_num == esp_partition.unwrap_or(0) {
            set_esp_flag(runner, img_path, part_num + 1);
        }

        part_start_mb = end_mb;
    }

    if let Some(ref swap) = layout.swap {
        create_swap_partition(runner, img_path, swap, part_start_mb)?;
    }
    Ok(())
}

/// Size in MB for the partition at `index`, starting at `start_mb`.
///
/// A declared size of `"0"` means "remaining": it claims what is left after
/// `start_mb` AND after every partition declared later plus swap. Reserving
/// the later partitions is load-bearing — `calculate_disk_size_mb` counts
/// swap into the total, so a grow-to-fill partition that ignored it would
/// consume the whole device and the following `create_swap_partition`
/// `mkpart` would run past the end (parted: "failed to create swap
/// partition"). The verity hash partition appended by
/// [`super::expand_ab_slots`] is reserved the same way.
pub(crate) fn partition_size_mb(
    layout: &DiskLayout,
    index: usize,
    total_mb: u64,
    start_mb: u64,
) -> miette::Result<u64> {
    let reserved = reserved_after_mb(layout, index);
    let available = total_mb.saturating_sub(start_mb).saturating_sub(reserved);
    if layout.partitions[index].size.trim() == "0" {
        if available == 0 {
            return Err(miette::miette!(
                "partition '{}' requests the remaining space but none is left: \
                 {reserved} MB is reserved for later partitions and swap on a \
                 {total_mb} MB disk after a {start_mb} MB start",
                layout.partitions[index].name
            ));
        }
        return Ok(available);
    }
    Ok(parse_size_mb(&layout.partitions[index].size, available))
}

/// Space (MB) that must remain for every partition declared after `index`
/// plus swap, using the same placeholder [`calculate_disk_size_mb`] uses for
/// a "0"-sized partition.
fn reserved_after_mb(layout: &DiskLayout, index: usize) -> u64 {
    let later: u64 = layout.partitions[index + 1..]
        .iter()
        .map(|p| parse_size_mb(&p.size, 1024))
        .sum();
    let swap = layout
        .swap
        .as_ref()
        .map(|s| parse_size_mb(&s.size, 0))
        .unwrap_or(0);
    later + swap
}

/// Set the GPT esp flag on `partition` (1-based); a failure is reported
/// but not fatal (matching the historical behavior — the vfat fs still
/// works).
pub(crate) fn set_esp_flag(runner: &dyn CommandRunner, img_path: &Path, partition: usize) {
    let argv = vec![
        "parted".to_string(),
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "set".to_string(),
        partition.to_string(),
        "esp".to_string(),
        "on".to_string(),
    ];
    if !runner.run(&argv).is_ok_and(|o| o.code == 0) {
        eprintln!("  ⚠ failed to set ESP flag on partition {partition}");
    }
}

/// Pin the GPT's random-per-build identities to deterministic derivations
/// (#48): the disk GUID and every partition's PARTUUID (including the
/// auto-appended verity-hash partitions and swap). The verity slots are
/// re-pinned to the roothash-derived generation GUIDs after the format
/// (`build_disk_image_with`); everything else keeps this derivation. Runs
/// right after the parted layout + slot metadata, BEFORE the first extents
/// read-back, so every downstream consumer (cmdline, manifest, fstab) sees
/// final identities. Fail-closed through [`set_disk_guid`] /
/// [`set_partition_uuid`]: an identity that did not land aborts the build.
pub(crate) fn pin_gpt_identities(
    runner: &dyn CommandRunner,
    img_path: &Path,
    image_identity: &str,
    layout: &DiskLayout,
) -> miette::Result<()> {
    set_disk_guid(img_path, &identity_guid(GUID_NS_DISK, &[image_identity]))?;
    for (i, part) in layout.partitions.iter().enumerate() {
        let guid = identity_guid(
            GUID_NS_PARTITION,
            &[image_identity, &part.name, &i.to_string()],
        );
        set_partition_uuid(runner, img_path, i + 1, &guid)?;
    }
    let swap_size = layout
        .swap
        .as_ref()
        .map_or(0, |s| parse_size_mb(&s.size, 0));
    if swap_size > 0 {
        let i = layout.partitions.len();
        let guid = identity_guid(GUID_NS_PARTITION, &[image_identity, "swap", &i.to_string()]);
        set_partition_uuid(runner, img_path, i + 1, &guid)?;
    }
    Ok(())
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
                // sfdisk -J reports GUIDs upper-case; normalize to lowercase
                // at the read-back source (#92). GPT GUIDs are
                // case-insensitive, but every string consumer downstream —
                // the UKI cmdline's root=PARTUUID= and the verity
                // by-partuuid device paths, the signed manifest — must be
                // byte-identical to udev's LOWERCASE /dev/disk/by-partuuid/
                // symlinks, or userspace device-unit matching misses.
                partuuid: part
                    .get("uuid")
                    .and_then(serde_json::Value::as_str)
                    .map(|u| u.to_ascii_lowercase()),
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
    /// `"<name>|<version>"` — the derivation seed the deterministic ext4
    /// fs UUID / hash seed pin from (#48); same derivation the GPT
    /// identity pinning uses.
    pub(crate) identity: &'a str,
    /// Ubuntu Core seed/role-model staging (issue #32). `None` for the
    /// non-UC/unsimplified path — content routing falls back to the
    /// historical behavior.
    pub(crate) uc: Option<&'a UcCtx>,
    /// The staged Pi firmware-visible boot tree (#87) — `Some` for piboot
    /// images, where the single vfat partition is populated from it
    /// (gadget boot-assets + Pi-spelled kernel payload + generated
    /// cmdline.txt/config.txt) instead of the systemd-boot ESP.
    pub(crate) pi_boot_stage: Option<&'a Path>,
}

/// Ubuntu Core seed/role-model context threaded into the populate stage.
/// Carries the staged seed tree (`ubuntu-seed`) and boot tree
/// (`ubuntu-boot` with `device/modeenv`) built by [`setup_uc_context`].
#[derive(Debug)]
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
///
/// `image_identity` (Some for every disk-build call, #48) pins the two
/// random-per-format ext4 properties — the filesystem UUID and the
/// directory-index hash seed — to derivations over the image identity +
/// partition name + extent offset. Without them two formats of the SAME
/// tree differ byte-for-byte, and a rebuild compare would flag every ext4
/// partition as a nondeterminism.
pub(crate) fn build_ext4_partition(
    runner: &dyn CommandRunner,
    part_file: &Path,
    staged_root: &Path,
    part: &Partition,
    extent: &PartitionExtent,
    verity: bool,
    image_identity: Option<&str>,
) -> miette::Result<()> {
    let (tool, flags) = mkfs_flags_for(&part.fs, verity)?;
    let block_count = (extent.size_bytes / u64::from(VERITY_BLOCK_SIZE)).to_string();
    let mut args: Vec<String> = flags;
    args.push(part.name.clone()); // label — mkfs_flags_for ends its flags with the label option
    if tool == "mkfs.ext4" {
        if let Some(identity) = image_identity {
            let offset = extent.start_bytes.to_string();
            args.push("-U".into());
            args.push(identity_guid(
                GUID_NS_FSUUID,
                &[identity, &part.name, &offset],
            ));
            args.push("-E".into());
            args.push(format!(
                "hash_seed={}",
                identity_guid(GUID_NS_HASH_SEED, &[identity, &part.name, &offset])
            ));
        }
    }
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
            "{tool} -d failed to build the {} partition '{}' (exit {}): {}",
            part.fs,
            part.name,
            crate::command::exit_code(&out),
            out.stderr.trim()
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

/// Normalize ONE staged-tree entry: permissions to 0644 (0755 for dirs —
/// mcopy maps a missing owner-write onto the FAT read-only attribute) and
/// mtime to `time`. Returns whether `path` is a directory to descend into.
fn normalize_tree_entry(path: &Path, time: std::time::SystemTime) -> miette::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    let is_dir = path.is_dir();
    let mode = if is_dir { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .into_diagnostic()
        .wrap_err_with(|| format!("normalizing mode of {}", path.display()))?;
    let file = if is_dir {
        std::fs::File::open(path)
    } else {
        std::fs::OpenOptions::new().write(true).open(path)
    }
    .into_diagnostic()
    .wrap_err_with(|| format!("opening {} for mtime normalization", path.display()))?;
    file.set_times(std::fs::FileTimes::new().set_modified(time))
        .into_diagnostic()
        .wrap_err_with(|| format!("normalizing mtime of {}", path.display()))?;
    Ok(is_dir)
}

/// Set the mtime of every file and directory under `dir` to `epoch` — the
/// staged-tree normalization an mtools populate needs (#48). Upstream
/// mtools copies the SOURCE file's mtime into the FAT directory entry, so
/// whatever clock the build wrote the UKI/loader.conf with would ride
/// onto the ESP and break byte-reproducibility; a fixed pre-1980-or-pinned
/// epoch collapses every entry to one stable FAT date. Files are also
/// pinned to 0644 (dirs 0755): mcopy maps a missing owner-write bit onto
/// the FAT read-only attribute, so host store permissions (0555 nix
/// binaries, e.g. the copied systemd-boot fallback) would otherwise leak
/// into the image — and a read-only file cannot have its mtime set.
pub(crate) fn normalize_tree_times(dir: &Path, epoch: u64) -> miette::Result<()> {
    let time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(epoch);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let read = std::fs::read_dir(&current)
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", current.display()))?;
        for entry in read.flatten() {
            if normalize_tree_entry(&entry.path(), time)? {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

/// The build epoch the image-side timestamp normalization pins to
/// (#48): SOURCE_DATE_EPOCH when the environment carries one, else 0.
pub(crate) fn image_epoch_secs() -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Populate a standalone vfat file (the ESP) with mtools — no mount, no
/// root. The staged tree is walked in sorted order (directories before
/// their contents fall out of a lexicographic sort: a parent path is a
/// strict prefix of its children) so the FAT layout is deterministic;
/// each directory is created with `mmd`, each file copied with `mcopy`.
/// The staged tree's mtimes are normalized to the build epoch first (#48):
/// upstream mtools copies source mtimes into the FAT entries, and the UKI +
/// loader.conf were written by THIS build's clock. Only the exit status
/// decides — mkfs/mtools may print benign warnings (e.g. "less than
/// suggested minimum clusters" on small extents).
pub(crate) fn mtools_populate_vfat(
    runner: &dyn CommandRunner,
    vfat_file: &Path,
    staged: &Path,
) -> miette::Result<()> {
    normalize_tree_times(staged, image_epoch_secs())?;
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
/// from the staged EFI tree; a `role = "state"` partition is mkfs.ext4'd
/// EMPTY (a boot-populated persistence surface, never a rootfs copy);
/// other data partitions receive the staged rootfs via `mkfs.ext4 -d`.
/// Failures on the data/ESP paths leave the partition unpopulated
/// (historical warn-not-fatal side-partition behavior), while a state
/// populate failure fails closed; a btrfs (or other unpopulatable)
/// filesystem always fails closed ([`refuse_non_ext4_vfat`]).
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
    match route_side_partition(ctx, index, part) {
        SideRoute::Uc(stage) => {
            build_staged_partition(runner, &part_file, part, stage, extent, ctx.identity)?
        }
        SideRoute::State => build_state_partition(runner, ctx, &part_file, part, extent)?,
        // #87: on a piboot image the single vfat partition is the Pi
        // firmware partition — populated from the staged boot tree, and
        // FATAL on failure (it IS the boot chain).
        SideRoute::Piboot(stage) => build_piboot_partition(runner, &part_file, part, stage)?,
        SideRoute::Esp => build_esp_partition(runner, ctx, &part_file, part)?,
        SideRoute::Data => build_data_partition(runner, ctx, &part_file, part, extent)?,
        SideRoute::Skip => {
            eprintln!(
                "  ✓ {}: left unformatted (UC gap partition — snapd's gadget \
                 validation wants it present, not populated)",
                part.name
            );
            return Ok(());
        }
    }
    splice_into(&ctx.scratch_dir.join("disk.img"), &part_file, extent)
}

/// The routing decision for one non-root partition: UC role trees, the
/// state partition, the piboot firmware partition (#87), the systemd-boot
/// ESP, a plain data partition, or untouched (UC partitions outside the
/// role model — e.g. a BIOS Boot gap — get no filesystem from the build,
/// exactly like ubuntu-image leaves them).
enum SideRoute<'a> {
    Uc(&'a Path),
    State,
    Piboot(&'a Path),
    Esp,
    Data,
    Skip,
}

fn route_side_partition<'a>(
    ctx: &'a PopulateCtx<'a>,
    index: usize,
    part: &Partition,
) -> SideRoute<'a> {
    if let Some(stage) = ctx.uc_route_stage(part) {
        return SideRoute::Uc(stage);
    }
    if super::is_state_partition(part) {
        return SideRoute::State;
    }
    if let Some(stage) = ctx.pi_boot_stage.filter(|_| part.fs == "vfat") {
        return SideRoute::Piboot(stage);
    }
    // On a UC image the first vfat partition is NOT a systemd-boot ESP —
    // the gadget chain owns every boot asset. Only the simplified path
    // installs one. (The remaining UC gap partitions — a BIOS Boot, say —
    // are skipped: snapd's gadget validation wants them PRESENT, not
    // formatted.)
    if index == 0 && part.fs == "vfat" && ctx.uc.is_none() {
        return SideRoute::Esp;
    }
    if ctx.uc.is_some() {
        return SideRoute::Skip;
    }
    SideRoute::Data
}

/// mkfs an EMPTY ext4 filesystem for a `role = "state"` partition
/// (ADR-0023). The state surface is populated at BOOT by tmpfiles
/// (`/var/lib/shuttle`, `/var/lib/extensions`) — its correct build-time
/// content is nothing at all. Populating it from `ctx.root` (the data
/// path) filled the whole partition with the ~3 GiB rootfs and overflowed
/// a modest state extent, leaving a zeroed partition where fstab mounts
/// `PARTLABEL=state`. Failure is FATAL, unlike the historical
/// warn-not-fatal data behavior: an unformatted state partition is a
/// mount target on the boot path, so a silently-zeroed one wedges boot.
pub(crate) fn build_state_partition(
    runner: &dyn CommandRunner,
    ctx: &PopulateCtx,
    part_file: &Path,
    part: &Partition,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    let empty = ctx.scratch_dir.join("state-staging");
    std::fs::create_dir_all(&empty)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating the empty state staging dir {}", empty.display()))?;
    build_ext4_partition(
        runner,
        part_file,
        &empty,
        part,
        extent,
        false,
        Some(ctx.identity),
    )
    .wrap_err_with(|| format!("state partition '{}' populate failed", part.name))?;
    eprintln!(
        "  ✓ {}: {} formatted empty (state, boot-populated)",
        part.name, part.fs
    );
    Ok(())
}

/// Resolve the ESP/vfat formatter: dosfstools' `mkfs.fat` when present, its
/// `mkfs.vfat` alias as fallback. A resolved `mkfs.vfat` may still be the
/// BusyBox applet (first on some devbox PATHs) — that one lacks
/// `--invariant` and time-seeds the volume id, so the `mkfs.fat
/// --invariant` invocation fails with the named error in
/// [`mkfs_vfat_partition`] instead of silently emitting an irreproducible
/// ESP (#48). `None` = neither binary on PATH.
pub(crate) fn find_mkfs_vfat() -> Option<PathBuf> {
    find_host_tool("mkfs.fat").or_else(|| find_host_tool("mkfs.vfat"))
}

/// mkfs.vfat a standalone partition file (`-F 32`, labelled with the
/// partition name). Shared by the systemd-boot ESP and the piboot firmware
/// partition (#87); the caller decides whether a failure warns or fails.
///
/// The tool is resolved through [`find_mkfs_vfat`] and carries
/// `--invariant` (mkfs_flags_for): dosfstools ≥ 4.2 formats the SAME bytes
/// every run — the volume id and creation timestamps are what BusyBox's
/// mkfs.vfat (and dosfstools without the flag) reseed per run, which a
/// rebuild compare would flag on every ESP (#48).
fn mkfs_vfat_partition(
    runner: &dyn CommandRunner,
    part_file: &Path,
    part: &Partition,
) -> miette::Result<()> {
    let (_, mut flags) = mkfs_flags_for("vfat", false)?;
    flags.push(part.name.clone()); // -n label
    flags.push(part_file.to_string_lossy().into_owned());
    // Resolve the NAME through the runner's own PATH (the `which` probe is
    // the seam apply_gpt_slot_metadata already uses) — a fake runner can
    // then script the resolution, and the real build resolves the same PATH
    // `Command` will search.
    let which = |name: &str| {
        runner
            .run(&["which".to_string(), name.to_string()])
            .ok()
            .filter(|o| o.code == 0)
            .is_some()
    };
    let tool = if which("mkfs.fat") {
        "mkfs.fat".to_string()
    } else if which("mkfs.vfat") {
        "mkfs.vfat".to_string()
    } else {
        return Err(miette::miette!(
            "mkfs.fat not found on PATH — the disk build formats the ESP (and any \
             vfat partition) with dosfstools ≥ 4.2 ('mkfs.fat --invariant') so the \
             volume identity is reproducible; refusing to emit an irreproducible \
             ESP. Run 'shuttle doctor' and install it (e.g. apt install dosfstools \
             or add dosfstools to devbox.json packages)"
        ));
    };
    let argv: Vec<String> = std::iter::once(tool.clone()).chain(flags).collect();
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "{tool} failed for the {} partition '{}' (exit {}): {} — a reproducible \
             ESP needs dosfstools >= 4.2 with --invariant support; BusyBox's \
             mkfs.vfat cannot produce one",
            part.fs,
            part.name,
            crate::command::exit_code(&out),
            out.stderr.trim()
        ));
    }
    Ok(())
}

/// mkfs.vfat the Pi firmware partition and copy the staged boot tree on
/// with mtools (#87) — gadget boot-assets, the Pi-spelled kernel payload,
/// board DTBs, and the generated cmdline.txt/config.txt. FATAL on failure,
/// unlike the warn-not-fatal ESP path: this partition IS the Pi boot chain
/// (start.elf, DTBs, kernel.img), and one the firmware cannot even
/// describe — a blank one is a silent brick.
pub(crate) fn build_piboot_partition(
    runner: &dyn CommandRunner,
    part_file: &Path,
    part: &Partition,
    stage: &Path,
) -> miette::Result<()> {
    mkfs_vfat_partition(runner, part_file, part)
        .wrap_err_with(|| format!("Pi firmware partition '{}' mkfs failed", part.name))?;
    mtools_populate_vfat(runner, part_file, stage)
        .wrap_err_with(|| format!("Pi firmware partition '{}' populate failed", part.name))?;
    eprintln!(
        "  ✓ {}: {} populated (Pi firmware partition — boot-assets + kernel payload, #87)",
        part.name, part.fs
    );
    Ok(())
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
    if let Err(e) = mkfs_vfat_partition(runner, part_file, part) {
        eprintln!("  ⚠ {e:#} — ESP left unpopulated");
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
/// or boot tree). The seed partition is VFAT (for the pc gadget
/// `ubuntu-seed` IS the ESP) and formats + populates through mtools; the
/// ext4 `ubuntu-boot` goes through `mkfs.ext4 -d`. Unlike the historical
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
    identity: &str,
) -> miette::Result<()> {
    match part.fs.as_str() {
        "vfat" => {
            mkfs_vfat_partition(runner, part_file, part).wrap_err_with(|| {
                format!("UC {} partition '{}' mkfs failed", part.fs, part.name)
            })?;
            mtools_populate_vfat(runner, part_file, stage).wrap_err_with(|| {
                format!("UC {} partition '{}' populate failed", part.fs, part.name)
            })?;
        }
        _ => {
            build_ext4_partition(
                runner,
                part_file,
                stage,
                part,
                extent,
                false,
                Some(identity),
            )
            .wrap_err_with(|| {
                format!("UC {} partition '{}' populate failed", part.fs, part.name)
            })?;
        }
    }
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
    if let Err(e) = build_ext4_partition(
        runner,
        part_file,
        ctx.root,
        part,
        extent,
        false,
        Some(ctx.identity),
    ) {
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
///
/// The vfat tool is spelled `mkfs.fat` (dosfstools) because the ESP is
/// formatted with `--invariant` — dosfstools ≥ 4.2 pins the volume id and
/// creation timestamps so two formats of the same tree are byte-identical
/// (#48). `mkfs_vfat_partition` resolves that name (falling back to a
/// dosfstools-provided `mkfs.vfat`); BusyBox's applet of the same name has
/// no `--invariant` and time-seeds the volume id, and is rejected at run
/// time with a named error.
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
        ("vfat", false) => (
            "mkfs.fat",
            vec!["-F".into(), "32".into(), "--invariant".into(), "-n".into()],
        ),
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
/// (`ubuntu-seed`/`ubuntu-boot`/`ubuntu-data`/`ubuntu-save`) — the remap
/// runs BEFORE partitioning so the parted-created GPT PARTLABELs come out
/// correct — and the full seed tree (model assertion + seed.yaml + snap
/// payloads + kernel.efi + grubenv + the gadget's EFI boot assets + snapd's
/// first-boot grub config + the account trust anchor) and the boot tree
/// (`device/modeenv`) are staged into scratch dirs for the populate stage.
///
/// Every snap in the seed must carry its store snap-id (resolved here, or
/// overridden through `SHUTTLE_SNAP_IDS`); a kernel snap without a
/// `kernel.efi`, a gadget snap missing its boot assets, or a seed
/// partition with the wrong filesystem are all named, fail-closed errors.
///
/// Non-UC bases, and coreN bases that mark no partition for a UC role, are
/// returned as `Ok(None)` unchanged — the simplified path is bit-identical.
#[allow(clippy::too_many_arguments)]
pub(crate) fn setup_uc_context(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    layout: &mut DiskLayout,
    scratch: &Path,
    arch: &str,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    kernel_snap_dir: Option<&Path>,
    has_unsquashfs: bool,
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
    assert_uc_partition_shapes(layout)?;

    // UC fail-closed preconditions: the gadget-proper seed needs the full
    // snap chain, an extracted kernel snap (for kernel.efi) and the gadget
    // snap (for the boot assets) — every absence a named error.
    let kernel_entry = image.kernel.as_ref().ok_or_else(|| {
        miette::miette!(
            "the UC seed requires a kernel snap — snapd's first boot cannot seed a \
             model without one"
        )
    })?;
    let gadget_entry = image.gadget.as_ref().ok_or_else(|| {
        miette::miette!(
            "the UC seed requires a gadget snap — the gadget defines the boot chain \
             snap-bootstrap drives (model requires system-seed structure)"
        )
    })?;
    let kernel_dir = kernel_snap_dir.ok_or_else(|| {
        miette::miette!(
            "the UC seed needs the extracted kernel snap (its kernel.efi is the \
             first-boot chainloader) — but the kernel snap tree was not staged"
        )
    })?;
    if !has_unsquashfs {
        return Err(miette::miette!(
            "the UC seed stages the gadget's own boot assets, which needs unsquashfs \
             on PATH to unpack the gadget snap — install squashfs-tools and rebuild"
        ));
    }

    // Store identities: every seed snap is identified by snap-id.
    let snap_ids = resolve_snap_ids(runner, image, resolved)?;
    let cache_path = |name: &str| -> miette::Result<std::path::PathBuf> {
        let snap = resolved.iter().find(|s| s.name == name).ok_or_else(|| {
            miette::miette!(
                "snap '{name}' is required by the UC seed but was not resolved — add \
                 it to the image declaration (snapd is required on UC20+)"
            )
        })?;
        Ok(cache_dir.join(format!(
            "{}_{}_{}.snap",
            snap.name, snap.revision, snap.sha3_384
        )))
    };

    // Seed snap list, in model order: base, snapd, kernel, gadget, extras.
    let mut seeds = Vec::new();
    let track = crate::image::base_track(&image.base.name);
    let derived = |channel: &Option<String>| {
        channel.clone().unwrap_or_else(|| match track {
            Some(t) => format!("{t}/stable"),
            None => "latest/stable".into(),
        })
    };
    let push = |seeds: &mut Vec<crate::uc::SeedSnapFile>,
                name: &str,
                snap_type: &str,
                channel: String|
     -> miette::Result<()> {
        let snap = resolved.iter().find(|s| s.name == name).ok_or_else(|| {
            miette::miette!(
                "snap '{name}' is required by the UC seed but was not resolved — add \
                 it to the image declaration"
            )
        })?;
        seeds.push(crate::uc::SeedSnapFile {
            name: name.to_string(),
            snap_id: snap_ids.get(name).cloned().ok_or_else(|| {
                miette::miette!("snap '{name}' has no store snap-id for the UC seed")
            })?,
            revision: snap.revision,
            channel,
            snap_type: snap_type.to_string(),
            path: cache_path(name)?,
        });
        Ok(())
    };
    let base_name = image.base.name.clone();
    push(&mut seeds, &base_name, "base", derived(&None))?;
    push(&mut seeds, "snapd", "snapd", derived(&None))?;
    push(
        &mut seeds,
        &kernel_entry.snap.name,
        "kernel",
        derived(&kernel_entry.channel),
    )?;
    push(
        &mut seeds,
        &gadget_entry.name,
        "gadget",
        derived(&image.gadget_channel),
    )?;
    for extra in &image.extra_snaps {
        push(&mut seeds, &extra.name, "app", derived(&None))?;
    }

    // The gadget's EFI boot assets — unpack the gadget snap and map them.
    let gadget_file = cache_path(&gadget_entry.name)?;
    let gadget_tree = scratch.join("uc-gadget-tree");
    unpack_snap(runner, &gadget_file, &gadget_tree)?;

    // The kernel snap's kernel.efi (the UKI grub chainloads).
    let kernel_efi = kernel_dir.join("kernel.efi");

    // Build the signed model assertion and stage the seed + modeenv trees.
    let model = crate::uc::ModelAssertion::from_image(image, arch, &snap_ids)?;
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let kp = match crate::sign::load_secret_key(&home)? {
        Some(kp) => kp,
        None => crate::sign::create_secret_key(&home)?,
    };
    let seed_stage = scratch.join("uc-seed-staging");
    let label = crate::uc::recovery_label(image);
    let extra_cmdline = kernel_entry.params.join(" ");
    crate::uc::stage_seed_tree(
        &seed_stage,
        &crate::uc::SeedStageInputs {
            label: &label,
            gadget_tree: &gadget_tree,
            gadget_assets: &crate::uc::pc_gadget_efi_assets(),
            kernel_efi: &kernel_efi,
            extra_cmdline: &extra_cmdline,
            model: &model,
            snaps: &seeds,
            kp: &kp,
        },
    )?;
    let boot_stage = scratch.join("uc-boot-staging");
    let kernel_name = Some(kernel_entry.snap.name.as_str());
    let gadget_name = Some(gadget_entry.name.as_str());
    crate::uc::emit_modeenv(
        &boot_stage,
        &label,
        kernel_name,
        &image.base.name,
        gadget_name,
    )?;
    eprintln!(
        "  ✓ UC seed staged (recovery system {label}, {} snaps, key id {})",
        seeds.len(),
        kp.key_id()
    );
    Ok(Some(UcCtx {
        seed_stage,
        boot_stage,
    }))
}

/// UC partition shape contract (fail-closed): the seed partition is vfat
/// (the pc gadget's `ubuntu-seed` IS the ESP) and every other UC partition
/// is ext4 — snapd's install-time gadget validation compares filesystems
/// against the gadget (`filesystems do not match: declared as X, got Y`).
fn assert_uc_partition_shapes(layout: &DiskLayout) -> miette::Result<()> {
    for part in &layout.partitions {
        let Some(role) = partition_uc_role(part) else {
            continue;
        };
        let want = if role == crate::uc::ROLE_SEED {
            "vfat"
        } else {
            "ext4"
        };
        if part.fs != want {
            return Err(miette::miette!(
                "UC partition '{}' (role {role}) must be {want}, declared as '{}' — \
                 snapd's gadget validation compares partition filesystems against the \
                 gadget and a mismatch is a first-boot install failure",
                part.name,
                part.fs
            ));
        }
    }
    Ok(())
}

/// Resolve the store snap-id for every snap the seed carries: base, kernel,
/// gadget, snapd and the declared extras. Fails closed naming the first
/// snap that cannot be identified.
fn resolve_snap_ids(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
) -> miette::Result<std::collections::BTreeMap<String, String>> {
    let mut ids = std::collections::BTreeMap::new();
    let mut names: Vec<&str> = vec![&image.base.name, "snapd"];
    if let Some(ref k) = image.kernel {
        names.push(&k.snap.name);
    }
    if let Some(ref g) = image.gadget {
        names.push(&g.name);
    }
    for extra in &image.extra_snaps {
        names.push(&extra.name);
    }
    for name in names {
        if ids.contains_key(name) {
            continue;
        }
        if !resolved.iter().any(|s| s.name == *name) {
            return Err(miette::miette!(
                "snap '{name}' is required by the UC seed but was not resolved — add \
                 it to the image declaration"
            ));
        }
        let id = crate::store::StoreClient::snap_id_with(runner, name)?;
        eprintln!("  ✓ snap-id {name} = {id}");
        ids.insert(name.to_string(), id);
    }
    Ok(ids)
}

/// Unpack a snap file into a directory with unsquashfs (the runner resolves
/// it from PATH; presence was checked by the caller).
fn unpack_snap(runner: &dyn CommandRunner, snap: &Path, dest: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dest)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", dest.display()))?;
    let argv = vec![
        "unsquashfs".to_string(),
        "-f".to_string(),
        "-d".to_string(),
        dest.to_string_lossy().into_owned(),
        snap.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("unsquashfs not found: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "unsquashfs failed unpacking {}: {}",
            snap.display(),
            out.stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::SwapConfig;

    fn part(name: &str, size: &str) -> Partition {
        Partition {
            name: name.into(),
            size: size.into(),
            fs: "ext4".into(),
            mount: String::new(),
            options: vec![],
            role: String::new(),
        }
    }

    /// The flagship layout: a grow-to-fill root followed by swap. The root
    /// must leave the swap room instead of consuming the whole device.
    #[test]
    fn grow_to_fill_partition_reserves_a_later_swap_partition() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("root", "0")],
            swap: Some(SwapConfig { size: "8G".into() }),
            ab: false,
        };
        // 4 (GPT) + root + 8192 (swap); root starts at 4.
        let total = 4 + 1024 + 8192;
        let root = partition_size_mb(&layout, 0, total, 4).unwrap();
        assert_eq!(root, 1024, "grow-to-fill root leaves the 8G swap room");
        assert_eq!(4 + root + 8192, total, "the ledger closes exactly");
    }

    /// A grow-to-fill partition with nothing after it still takes the rest.
    #[test]
    fn grow_to_fill_partition_takes_the_remainder_when_unreserved() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("root", "0")],
            swap: None,
            ab: false,
        };
        assert_eq!(partition_size_mb(&layout, 0, 260, 4).unwrap(), 256);
    }

    /// Declared sizes are unaffected by later reservations.
    #[test]
    fn declared_size_is_not_reduced_by_later_partitions() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("root", "512M"), part("hash", "2M")],
            swap: None,
            ab: false,
        };
        assert_eq!(partition_size_mb(&layout, 0, 4096, 4).unwrap(), 512);
    }

    /// Later "0"-sized partitions use the same 1024 MB placeholder the
    /// total-size calculation does, so the reservation matches the ledger.
    #[test]
    fn later_placeholder_partition_is_reserved_at_the_documented_default() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("root", "0"), part("data", "0")],
            swap: None,
            ab: false,
        };
        // total = 4 + 1024 (root placeholder) + 1024 (data placeholder)
        assert_eq!(
            partition_size_mb(&layout, 0, 4 + 1024 + 1024, 4).unwrap(),
            1024
        );
    }

    /// No room left is a precise fail-closed error, never a silent 0-size
    /// partition.
    #[test]
    fn grow_to_fill_with_no_room_left_fails_closed() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("root", "0")],
            swap: Some(SwapConfig { size: "8G".into() }),
            ab: false,
        };
        let err = partition_size_mb(&layout, 0, 4 + 8192, 4).unwrap_err();
        assert!(
            err.to_string().contains("no room") || err.to_string().contains("none is left"),
            "actionable message: {err}"
        );
    }

    // ── State partition populate routing + fail-closed (ADR-0023) ──

    /// A runner that records every argv and answers each tool with a
    /// scripted exit code — enough to drive the ext4 `mkfs -d` seam with
    /// no real filesystem tooling.
    struct RecordingRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        mkfs_code: i32,
    }

    impl RecordingRunner {
        fn new(mkfs_code: i32) -> RecordingRunner {
            RecordingRunner {
                calls: std::sync::Mutex::new(Vec::new()),
                mkfs_code,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::command::CommandRunner for RecordingRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let code = if argv.first().is_some_and(|p| p == "mkfs.ext4") {
                self.mkfs_code
            } else {
                0
            };
            Ok(crate::command::RunnerOutput {
                code,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    fn extent(size_bytes: u64) -> PartitionExtent {
        PartitionExtent {
            start_bytes: 1 << 20,
            size_bytes,
            partuuid: None,
        }
    }

    /// The scratch disk image `splice_into` writes into — a sparse file at
    /// the partition's offset + size.
    fn scratch_disk(scratch: &Path, size_bytes: u64) {
        std::fs::File::create(scratch.join("disk.img"))
            .unwrap()
            .set_len((1 << 20) + size_bytes)
            .unwrap();
    }

    /// The `-d` source of the sole recorded `mkfs.ext4` invocation.
    fn mkfs_d_source(calls: &[Vec<String>]) -> String {
        calls
            .iter()
            .find(|c| c.first().is_some_and(|p| p == "mkfs.ext4"))
            .and_then(|c| c.iter().position(|a| a == "-d").map(|i| c[i + 1].clone()))
            .expect("a mkfs.ext4 -d invocation was recorded")
    }

    /// A state partition is mkfs'd from an EMPTY staged dir — never the
    /// rootfs tree — so the boot-populated surface cannot overflow with a
    /// full rootfs copy.
    #[test]
    fn state_partition_populates_from_an_empty_stage_not_the_rootfs() {
        let scratch = tempfile::tempdir().unwrap();
        scratch_disk(scratch.path(), 4 * 1024 * 1024 * 1024);
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::write(rootfs.path().join("kernel.img"), b"rootfs payload").unwrap();
        let runner = RecordingRunner::new(0);
        let mut state = part("state", "4G");
        state.role = "state".into();
        let image = crate::image::test_support::sample_image();
        let ctx = PopulateCtx {
            image: &image,
            extents: &[extent(4 * 1024 * 1024 * 1024)],
            scratch_dir: scratch.path(),
            root: rootfs.path(),
            uki: None,
            uki_stage: Path::new(""),
            identity: "test-uc|1.0.0",
            uc: None,
            pi_boot_stage: None,
        };

        populate_side_partition(&runner, &ctx, 0, &state).unwrap();

        let source = mkfs_d_source(&runner.calls());
        assert_ne!(
            source,
            rootfs.path().to_string_lossy(),
            "the state partition must not be populated from the rootfs"
        );
        let staged = Path::new(&source);
        assert!(staged.is_dir(), "the -d source is a real dir: {source}");
        assert_eq!(
            std::fs::read_dir(staged).unwrap().count(),
            0,
            "the state staging dir is empty: {source}"
        );
    }

    /// A state-partition populate failure is FATAL (fail-closed): a zeroed
    /// state partition is a mount target on the boot path.
    #[test]
    fn state_partition_populate_failure_fails_closed() {
        let scratch = tempfile::tempdir().unwrap();
        scratch_disk(scratch.path(), 4 * 1024 * 1024 * 1024);
        let rootfs = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new(1);
        let mut state = part("state", "4G");
        state.role = "state".into();
        let image = crate::image::test_support::sample_image();
        let ctx = PopulateCtx {
            image: &image,
            extents: &[extent(4 * 1024 * 1024 * 1024)],
            scratch_dir: scratch.path(),
            root: rootfs.path(),
            uki: None,
            uki_stage: Path::new(""),
            identity: "test-uc|1.0.0",
            uc: None,
            pi_boot_stage: None,
        };

        let err = populate_side_partition(&runner, &ctx, 0, &state).unwrap_err();
        assert!(
            format!("{err:#}").contains("state partition 'state' populate failed"),
            "the failure names the state partition: {err:#}"
        );
    }

    /// An ordinary data-partition populate failure still warns and returns
    /// Ok (the historical side-partition behavior this fix must not change).
    #[test]
    fn data_partition_populate_failure_still_warns_and_succeeds() {
        let scratch = tempfile::tempdir().unwrap();
        scratch_disk(scratch.path(), 4 * 1024 * 1024 * 1024);
        let rootfs = tempfile::tempdir().unwrap();
        let runner = RecordingRunner::new(1);
        let data = part("data", "4G");
        let image = crate::image::test_support::sample_image();
        let ctx = PopulateCtx {
            image: &image,
            extents: &[extent(4 * 1024 * 1024 * 1024)],
            scratch_dir: scratch.path(),
            root: rootfs.path(),
            uki: None,
            uki_stage: Path::new(""),
            identity: "test-uc|1.0.0",
            uc: None,
            pi_boot_stage: None,
        };

        populate_side_partition(&runner, &ctx, 0, &data)
            .expect("data populate warns, does not fail");
        assert_eq!(
            mkfs_d_source(&runner.calls()),
            rootfs.path().to_string_lossy(),
            "an ordinary data partition still populates from the rootfs"
        );
    }

    // ── Deterministic identity (#48) ──

    /// CRC-32 must match the IEEE vector or every GPT header CRC the disk
    /// GUID patch recomputes would be wrong (and parted/sfdisk would reject
    /// the table at read-back).
    #[test]
    fn gpt_crc32_matches_the_ieee_check_vector() {
        assert_eq!(gpt_crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(gpt_crc32(b""), 0x0000_0000);
    }

    /// The identity GUID derivation is stable, well-formed, and sensitive
    /// to every input — two partitions that differ only in name or index
    /// must never share an identity.
    #[test]
    fn identity_guid_is_deterministic_shape_and_input_sensitive() {
        let a = identity_guid("ns", &["img|1.0", "esp", "0"]);
        assert_eq!(a, identity_guid("ns", &["img|1.0", "esp", "0"]));
        assert_eq!(a.len(), 36, "dashed 32-hex: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert_ne!(identity_guid("ns", &["img|1.0", "root", "1"]), a);
        assert_ne!(identity_guid("ns", &["img|1.0", "esp", "1"]), a);
        assert_ne!(identity_guid("other", &["img|1.0", "esp", "0"]), a);
    }

    /// A minimal 4-sector fixture with a primary header (LBA1) pointing at
    /// a backup header (LBA3), the same shape `stamp_fake_gpt` gives the
    /// e2e fake and parted gives a real image.
    fn gpt_fixture(dir: &Path) -> PathBuf {
        let path = dir.join("disk.img");
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(4 * 512).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        let mut header = [0u8; 92];
        header[0..8].copy_from_slice(b"EFI PART");
        header[20..24].copy_from_slice(&92u32.to_le_bytes());
        header[32..40].copy_from_slice(&3u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
        f.seek(SeekFrom::Start(512)).unwrap();
        f.write_all(&header).unwrap();
        f.seek(SeekFrom::Start(3 * 512)).unwrap();
        f.write_all(&header).unwrap();
        path
    }

    /// The disk GUID lands on BOTH headers, encoded little-endian-mixed,
    /// and both header CRCs verify afterwards.
    #[test]
    fn set_disk_guid_patches_both_headers_and_fixes_the_crcs() {
        use std::io::{Read, Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let path = gpt_fixture(dir.path());
        let guid = "11223344-5566-7788-9900-aabbccddeeff";
        set_disk_guid(&path, guid).unwrap();

        let mut f = std::fs::File::open(&path).unwrap();
        for (label, offset) in [("primary", 512u64), ("backup", 3 * 512)] {
            let mut header = [0u8; 92];
            f.seek(SeekFrom::Start(offset)).unwrap();
            f.read_exact(&mut header).unwrap();
            assert_eq!(&header[0..8], b"EFI PART", "{label} signature intact");
            let expected = guid_bytes(guid).unwrap();
            assert_eq!(&header[56..72], &expected[..], "{label} disk GUID bytes");
            // The entries LBA must survive the patch — writing the GUID over
            // it would leave sfdisk reading a bogus entry array.
            let entries_lba = u64::from_le_bytes([
                header[72], header[73], header[74], header[75], header[76], header[77], header[78],
                header[79],
            ]);
            assert_eq!(entries_lba, 2, "{label} entries LBA untouched");
            let mut for_crc = header;
            for_crc[16..20].copy_from_slice(&[0; 4]);
            let stored = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
            assert_eq!(
                gpt_crc32(&for_crc),
                stored,
                "{label} header CRC verifies after the patch"
            );
        }
    }

    /// A non-GPT image (parted never ran, or the table did not land) fails
    /// the patch closed — never a silently-unpatched random GUID.
    #[test]
    fn set_disk_guid_fails_closed_on_a_non_gpt_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blank.img");
        std::fs::File::create(&path).unwrap().set_len(4096).unwrap();
        let err = set_disk_guid(&path, "11223344-5566-7788-9900-aabbccddeeff").unwrap_err();
        assert!(
            format!("{err:#}").contains("EFI PART") || format!("{err:#}").contains("GPT header"),
            "the failure names the missing table: {err:#}"
        );
    }

    /// Every partition the effective layout declares — plus the swap
    /// partition when sized — gets a deterministic PARTUUID pinned through
    /// the sfdisk seam, and the disk GUID is patched.
    #[test]
    fn pin_gpt_identities_pins_every_partition_and_the_disk_guid() {
        use std::io::{Read, Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let path = gpt_fixture(dir.path());
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part("esp", "64M"), part("root", "256M")],
            swap: Some(SwapConfig { size: "64M".into() }),
            ab: false,
        };
        let runner = RecordingRunner::new(0);
        pin_gpt_identities(&runner, &path, "img|1.0", &layout).unwrap();

        let calls = runner.calls();
        let pinned: Vec<(String, String)> = calls
            .iter()
            .filter(|c| c.iter().any(|a| a == "--part-uuid"))
            .filter_map(|c| {
                let i = c.iter().position(|a| a == "--part-uuid")?;
                Some((c[i + 2].clone(), c[i + 3].clone()))
            })
            .collect();
        assert_eq!(pinned.len(), 3, "esp + root + swap pinned: {pinned:?}");
        assert_eq!(pinned[0].0, "1");
        assert_eq!(
            pinned[0].1,
            identity_guid(GUID_NS_PARTITION, &["img|1.0", "esp", "0"])
        );
        assert_eq!(
            pinned[1].1,
            identity_guid(GUID_NS_PARTITION, &["img|1.0", "root", "1"])
        );
        assert_eq!(pinned[2].0, "3", "swap is partition 3 (after 2 declared)");
        assert_eq!(
            pinned[2].1,
            identity_guid(GUID_NS_PARTITION, &["img|1.0", "swap", "2"])
        );

        let mut header = [0u8; 92];
        let mut f = std::fs::File::open(&path).unwrap();
        f.seek(SeekFrom::Start(512)).unwrap();
        f.read_exact(&mut header).unwrap();
        let expected = guid_bytes(&identity_guid(GUID_NS_DISK, &["img|1.0"])).unwrap();
        assert_eq!(&header[56..72], &expected[..], "disk GUID patched");
    }

    /// The staged-tree mtime normalization pins every file AND directory to
    /// the epoch — what upstream mtools would copy into the FAT entries.
    #[test]
    fn normalize_tree_times_pins_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("EFI");
        std::fs::create_dir_all(sub.join("Linux")).unwrap();
        std::fs::write(sub.join("Linux").join("a.efi"), b"uki").unwrap();
        let loader = dir.path().join("loader.conf");
        std::fs::write(&loader, b"timeout 3").unwrap();

        normalize_tree_times(dir.path(), 1_700_000_000).unwrap();

        for path in [
            loader,
            sub.join("Linux").join("a.efi"),
            sub.join("Linux"),
            sub,
        ] {
            let md = std::fs::metadata(&path).unwrap();
            let got = md.modified().unwrap();
            assert_eq!(
                got,
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
                "{} normalized: {got:?}",
                path.display()
            );
        }
    }

    /// The ext4 determinism flags: with an image identity, every ext4 mkfs
    /// carries -U and -E hash_seed derivations (offset-keyed, so two
    /// same-named partitions never share one).
    #[test]
    fn ext4_populate_pins_fs_uuid_and_hash_seed_from_the_identity() {
        let scratch = tempfile::tempdir().unwrap();
        scratch_disk(scratch.path(), 16 * 1024 * 1024);
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::write(rootfs.path().join("f"), b"x").unwrap();
        let runner = RecordingRunner::new(0);
        let e = extent(16 * 1024 * 1024);
        let p = part("state", "16M");
        build_ext4_partition(
            &runner,
            &scratch.path().join("p.img"),
            rootfs.path(),
            &p,
            &e,
            false,
            Some("img|1.0"),
        )
        .unwrap();
        let call = runner
            .calls()
            .into_iter()
            .find(|c| c.first().is_some_and(|t| t == "mkfs.ext4"))
            .unwrap();
        let uuid_at = call.iter().position(|a| a == "-U").unwrap();
        assert_eq!(
            call[uuid_at + 1],
            identity_guid(
                GUID_NS_FSUUID,
                &["img|1.0", "state", &e.start_bytes.to_string()]
            )
        );
        let seed_at = call.iter().position(|a| a == "-E").unwrap();
        assert_eq!(
            call[seed_at + 1],
            format!(
                "hash_seed={}",
                identity_guid(
                    GUID_NS_HASH_SEED,
                    &["img|1.0", "state", &e.start_bytes.to_string()]
                )
            )
        );
    }
}
