//! dm-verity format/roothash/cmdline trailer + A/B slot metadata
//! (issue #57).

use std::path::{Path, PathBuf};

use super::*;
use crate::snap;

// ── dm-verity over the root partition (ADR-0011 step (c)) ──

/// Block size shared by `veritysetup format` (--data-block-size /
/// --hash-block-size) AND the root mkfs invocation (ext4 `-b`, btrfs
/// nodesize/sectorsize). dm-verity hashes the data device in these blocks,
/// so a root filesystem built with smaller blocks cannot mount over the
/// verity mapping: a 1 KiB-block ext4 root fails with "bad block size
/// 1024". Proven in QEMU — the identical verity setup mounts fine
/// (veritysetup status `verified`) once the rootfs is built with 4 KiB
/// blocks. ONE constant so the two argv builders cannot drift.
pub(crate) const VERITY_BLOCK_SIZE: u32 = 4096;

/// Name of the auto-appended dm-verity hash partition. It is formatted only
/// implicitly by `veritysetup format` — never mkfs'd, never mounted — and
/// is identified by this name in the populate stage.
pub(crate) const VERITY_HASH_PART_NAME: &str = "verity-hash";

/// `veritysetup format` stdout marker of the root hash line.
pub(crate) const ROOT_HASH_PREFIX: &str = "Root hash:";

/// dm-verity boot arguments captured during `veritysetup format` and
/// threaded into UKI assembly.
pub(crate) struct VerityBootArgs {
    /// 64-hex sha256 root hash from `veritysetup format`.
    pub(crate) roothash: String,
    /// GPT PARTUUID of the hash partition, when resolvable.
    pub(crate) hash_partuuid: Option<String>,
}

/// Indices of ALL declared root partitions (mount = "/"), in declaration
/// order — the ordered A/B slots (ADR-0011 step (d)). Slot A is the first;
/// slot B (when `disk.ab = true`) is appended by [`expand_ab_slots`].
pub(crate) fn root_partition_indices(layout: &DiskLayout) -> Vec<usize> {
    layout
        .partitions
        .iter()
        .enumerate()
        .filter(|(_, p)| p.mount == "/")
        .map(|(i, _)| i)
        .collect()
}

/// Index of the FIRST declared root partition (mount = "/") — the slot A
/// the factory UKI boots. Fail closed when absent: both the UKI `root=`
/// target and dm-verity formatting need it.
pub(crate) fn root_partition_index(layout: &DiskLayout) -> miette::Result<usize> {
    root_partition_indices(layout)
        .first()
        .copied()
        .ok_or_else(|| {
            miette::miette!(
                "disk layout declares no root partition (mount = \"/\") — the UKI needs \
             a root= target; refusing to build an unbootable image"
            )
        })
}

/// Slot bookkeeping after layout expansion: ordered root-slot indices and
/// the per-slot dm-verity hash partition index (`Some` exactly when the
/// build verity-formats).
#[derive(Debug, Clone)]
pub(crate) struct Slots {
    pub(crate) roots: Vec<usize>,
    pub(crate) hashes: Vec<Option<usize>>,
}

impl Slots {
    /// Indices populate must skip: every slot root and every verity hash
    /// partition (already populated + formatted before this stage).
    pub(crate) fn skip_indices(&self) -> Vec<usize> {
        let mut skip: Vec<usize> = self
            .roots
            .iter()
            .copied()
            .chain(self.hashes.iter().flatten().copied())
            .collect();
        skip.sort_unstable();
        skip
    }
}

/// Expand the effective layout for A/B slots (ADR-0011 step (d)): each
/// declared root gets its dm-verity hash partition appended (kernel images),
/// then `disk.ab = true` clones the (single) declared root + its hash into a
/// same-size, same-fs slot B directly after slot A — the day-one rollback
/// twin. Existing indices never shift. Requires "gpt" (sysupdate slot
/// matching keys off GPT type GUIDs) and exactly one declared root (slot B
/// is derived, not declared).
pub(crate) fn expand_ab_slots(layout: &mut DiskLayout, verity: bool) -> miette::Result<Slots> {
    if layout.ab && layout.label != "gpt" {
        return Err(miette::miette!(
            "disk.ab = true requires label = \"gpt\" — systemd-sysupdate matches A/B \
             slots by GPT partition type GUIDs, which MBR cannot carry"
        ));
    }
    let mut roots = root_partition_indices(layout);
    if verity && roots.is_empty() {
        return Err(miette::miette!(
            "disk layout declares no root partition (mount = \"/\") — dm-verity needs \
             a root data device; refusing to build an unverifiable image"
        ));
    }
    let mut hashes: Vec<Option<usize>> = vec![None; roots.len()];
    if verity {
        for i in 0..roots.len() {
            hashes[i] = Some(append_verity_hash_partition_at(layout, roots[i])?);
        }
    }
    if layout.ab {
        if roots.len() != 1 {
            return Err(miette::miette!(
                "disk.ab = true requires exactly one declared root partition (mount = \
                 \"/\"); found {} — slot B is derived from the root, not declared",
                roots.len()
            ));
        }
        let a = roots[0];
        // Clone AFTER slot A's hash partition so slot B stays contiguous
        // behind slot A. Same size/fs/options; mount stays "/" — the clone
        // is a full root slot, not a data partition.
        let root_a = layout.partitions[a].clone();
        layout.partitions.push(Partition {
            name: format!("{}_b", root_a.name),
            ..root_a
        });
        roots.push(layout.partitions.len() - 1);
        if let Some(h) = hashes[0] {
            let hash_a = layout.partitions[h].clone();
            layout.partitions.push(Partition {
                name: format!("{}_b", hash_a.name),
                ..hash_a
            });
            hashes.push(Some(layout.partitions.len() - 1));
        } else {
            hashes.push(None);
        }
    }
    Ok(Slots { roots, hashes })
}

/// Size in bytes of the dm-verity hash partition for a data device of
/// `data_bytes`: with sha256 over 4K data blocks and 4K hash blocks, one
/// hash block covers 512 KiB of data (128 × 32-byte digests), so the Merkle
/// tree needs ceil(data_bytes / 4096 / 128) 4K blocks; +1 MiB slack covers
/// the veritysetup superblock and alignment; floored at 2 MiB so tiny roots
/// still get a usable partition.
pub(crate) fn verity_hash_partition_bytes(data_bytes: u64) -> u64 {
    (data_bytes.div_ceil(4096 * 128) * 4096 + 1024 * 1024).max(2 * 1024 * 1024)
}

/// Append the dm-verity hash partition for the root device at the END of
/// the layout — existing partition indices never shift. Returns the new
/// partition's index.
///
/// The root size is parsed the same way [`calculate_disk_size_mb`] does
/// ("0"/fill roots use the same 1024 MB default): overshooting the hash
/// area is harmless, undersizing it fails `veritysetup format`.
pub(crate) fn append_verity_hash_partition_at(
    layout: &mut DiskLayout,
    root_idx: usize,
) -> miette::Result<usize> {
    let root_mb = parse_size_mb(&layout.partitions[root_idx].size, 1024);
    let hash_bytes = verity_hash_partition_bytes(root_mb * 1024 * 1024);
    let hash_mb = hash_bytes.div_ceil(1024 * 1024);
    layout.partitions.push(Partition {
        name: VERITY_HASH_PART_NAME.to_string(),
        size: format!("{hash_mb}M"),
        // "ext2" is a valid parted fs-type hint for both GPT and MBR labels;
        // the partition is never mkfs'd (see VERITY_HASH_PART_NAME).
        fs: "ext2".to_string(),
        mount: String::new(),
        options: vec![],
        role: String::new(),
    });
    Ok(layout.partitions.len() - 1)
}

/// Resolve `veritysetup` with the same bind-aware PATH resolution ukify
/// uses ([`find_ukify`]).
pub(crate) fn find_veritysetup() -> Option<PathBuf> {
    snap::resolve_in_path("veritysetup", &snap::path_entries())
}

/// Host tool pre-flight for kernel disk images — fail closed BEFORE any
/// destructive step (dd/parted/mkfs) so an unbootable or unverifiable image
/// is never half-written. Each Option is the host resolution of a required
/// tool; None fires the matching doctor-hinted error without running
/// anything (mirrors [`build_uki_with`]'s injected-tool pattern).
pub(crate) fn preflight_disk_tools_with(
    ukify: Option<&Path>,
    stub: Option<&Path>,
    veritysetup: Option<&Path>,
) -> miette::Result<()> {
    if ukify.is_none() {
        return Err(miette::miette!(
            "ukify not found on PATH — a kernel disk image cannot boot without a UKI, \
             so refusing to produce an unbootable image. Run 'shuttle doctor' and \
             install ukify (systemd >= 254; e.g. apt install systemd-ukify or add \
             systemd to devbox.json packages)"
        ));
    }
    if stub.is_none() {
        return Err(miette::miette!(
            "systemd sd-stub (linuxx64.efi.stub) not found — the UKI cannot be assembled \
             without it. Run 'shuttle doctor'; checked locations: {}",
            EFI_STUB_CANDIDATES.join(", ")
        ));
    }
    if veritysetup.is_none() {
        return Err(miette::miette!(
            "veritysetup not found on PATH — dm-verity over the root partition cannot \
             be formatted, so refusing to emit an unverifiable boot path. Run \
             'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; e.g. \
             apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    }
    Ok(())
}

/// Host tool pre-flight for the unprivileged populate stage: the disk
/// build formats and fills standalone partition files with these tools
/// (extent read-back via sfdisk, ESP via mtools, ext4/vfat via mkfs), so a
/// missing one fails closed BEFORE dd — half-written images are never
/// emitted. `required` pairs each tool name with its host resolution.
pub(crate) fn preflight_populate_tools_with(
    required: &[(&str, Option<PathBuf>)],
) -> miette::Result<()> {
    for (name, resolved) in required {
        if resolved.is_none() {
            let package = populate_tool_package(name);
            return Err(miette::miette!(
                "{name} not found on PATH — the disk build reads back partition \
                 extents and formats + populates standalone partition files with \
                 it, so refusing to start. Run 'shuttle doctor' and install it \
                 (e.g. apt install {package} or add {package} to devbox.json \
                 packages)"
            ));
        }
    }
    Ok(())
}

/// OS package that ships each pre-flighted populate tool (doctor hint).
pub(crate) fn populate_tool_package(name: &str) -> &'static str {
    match name {
        "sfdisk" => "util-linux",
        "mmd" | "mcopy" => "mtools",
        "mkfs.ext4" => "e2fsprogs",
        "mkfs.vfat" => "dosfstools",
        _ => "the matching OS package",
    }
}

/// Resolve a host build tool with the shared bind-aware PATH resolution
/// ([`crate::snap::resolve_in_path`]) — the same search set as
/// [`find_ukify`]/[`find_veritysetup`].
pub(crate) fn find_host_tool(name: &str) -> Option<PathBuf> {
    snap::resolve_in_path(name, &snap::path_entries())
}

/// veritysetup argv for a sha256/4K format-1 invocation, optional pinned
/// salt, devices last.
pub(crate) fn verity_format_args(
    salt: Option<&str>,
    data_dev: &str,
    hash_dev: &str,
) -> Vec<String> {
    let bs = VERITY_BLOCK_SIZE.to_string();
    let mut args = vec![
        "format".to_string(),
        "--hash".to_string(),
        "sha256".to_string(),
        "--data-block-size".to_string(),
        bs.clone(),
        "--hash-block-size".to_string(),
        bs,
        "--format".to_string(),
        "1".to_string(),
    ];
    if let Some(salt) = salt {
        args.push("--salt".to_string());
        args.push(salt.to_string());
    }
    args.push(data_dev.to_string());
    args.push(hash_dev.to_string());
    args
}

/// `veritysetup format` invocation (ADR-0011 step (c)): sha256 over 4K data
/// and hash blocks, on-disk format 1. `veritysetup` is injected so the
/// fail-closed behavior is testable on hosts without cryptsetup;
/// [`verity_format`] resolves it from the host. Returns the root hash
/// printed on stdout. `salt` pins the format salt explicitly — A/B slot
/// twins format with the SAME salt so byte-identical data yields the SAME
/// roothash (the roothash covers data + salt, not the hash superblock).
pub(crate) fn verity_format_with(
    veritysetup: Option<&Path>,
    data_dev: &str,
    hash_dev: &str,
    salt: Option<&str>,
) -> miette::Result<String> {
    let Some(tool) = veritysetup else {
        return Err(miette::miette!(
            "veritysetup not found on PATH — dm-verity over the root partition cannot \
             be formatted, so refusing to emit an unverifiable boot path. Run \
             'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; e.g. \
             apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    };
    let args = verity_format_args(salt, data_dev, hash_dev);
    let out = std::process::Command::new(tool)
        .args(&args)
        .output()
        .map_err(|e| miette::miette!("failed to run veritysetup: {e}"))?;
    if !out.status.success() {
        return Err(miette::miette!(
            "veritysetup format failed ({}): {}",
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_roothash(&String::from_utf8_lossy(&out.stdout))
}

/// Format dm-verity over `data_dev` into `hash_dev` with host-resolved
/// veritysetup (fail-closed when absent). `salt` pins the format salt
/// (A/B slot twins share one salt so identical data → identical roothash).
/// In the unprivileged flow both "devices" are standalone partition files
/// — veritysetup format/verify run userspace and accept plain files.
pub(crate) fn verity_format(
    data_dev: &str,
    hash_dev: &str,
    salt: Option<&str>,
) -> miette::Result<String> {
    verity_format_with(find_veritysetup().as_deref(), data_dev, hash_dev, salt)
}

/// Extract the root hash from `veritysetup format` stdout — the
/// `Root hash: <64-hex>` line. Anything else fails closed: a mangled hash
/// would be baked into a cmdline that is immutable once signed.
pub(crate) fn parse_roothash(stdout: &str) -> miette::Result<String> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with(ROOT_HASH_PREFIX))
        .ok_or_else(|| {
            miette::miette!(
                "veritysetup format printed no '{ROOT_HASH_PREFIX}' line — refusing to \
                 guess the root hash"
            )
        })?;
    let hash = line[ROOT_HASH_PREFIX.len()..].trim();
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hash.to_ascii_lowercase())
    } else {
        Err(miette::miette!(
            "veritysetup printed a malformed root hash ({hash:?}) — expected 64 hex chars"
        ))
    }
}

/// The dm-verity trailing cmdline args (ADR-0011 step (c)): the roothash
/// plus EXPLICIT by-partuuid data/hash devices, so boot needs no dm-verity
/// type GUIDs and the parted flow is untouched. Unresolvable PARTUUIDs fall
/// back to the documented nil-GUID placeholder — loud failure at boot, no
/// silent boot from the wrong volume.
pub(crate) fn verity_trailing(
    roothash: &str,
    root_partuuid: Option<&str>,
    hash_partuuid: Option<&str>,
) -> Vec<String> {
    vec![
        format!("roothash={roothash}"),
        format!(
            "systemd.verity_root_data=/dev/disk/by-partuuid/{}",
            root_partuuid.unwrap_or(NIL_PARTUUID)
        ),
        format!(
            "systemd.verity_root_hash=/dev/disk/by-partuuid/{}",
            hash_partuuid.unwrap_or(NIL_PARTUUID)
        ),
    ]
}

// ── A/B slots + systemd-sysupdate (ADR-0011 step (d)) ──

/// GPT partition type GUIDs systemd-sysupdate matches slots by (x86-64
/// types). Set on the image at build time via sfdisk; the UKI boot path
/// needs none of them (cmdline carries explicit by-partuuid devices), but
/// sysupdate's MatchPartitionType does.
pub const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const ROOT_TYPE_GUID_X86_64: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const VERITY_TYPE_GUID_X86_64: &str = "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5";

/// Slot letter for the n-th root slot (0 → "a", 1 → "b").
pub(crate) fn slot_suffix(slot: usize) -> &'static str {
    const SUFFIXES: [&str; 2] = ["a", "b"];
    SUFFIXES[slot % SUFFIXES.len()]
}

/// GPT PARTLABEL of root slot `slot` — the label scheme sysupdate's
/// MatchPattern keys off: `{image}_{version}_{a|b}` (36-char GPT label
/// budget; longer names degrade to a documented sfdisk warning).
pub(crate) fn slot_partlabel(image_name: &str, image_version: &str, slot: usize) -> String {
    format!("{image_name}_{image_version}_{}", slot_suffix(slot))
}

/// GPT PARTLABEL of the dm-verity hash partition of root slot `slot`:
/// `{image}_{version}_hash_{a|b}`.
pub(crate) fn hash_partlabel(image_name: &str, image_version: &str, slot: usize) -> String {
    format!("{image_name}_{image_version}_hash_{}", slot_suffix(slot))
}

/// MatchPattern for root slot partitions: the two slot labels (version
/// wildcarded) plus the documented `_empty` fallback for factory partitions
/// not yet labeled. First pattern wins for newly created partitions.
pub(crate) fn root_match_pattern(image_name: &str) -> String {
    format!("{image_name}_@v_a {image_name}_@v_b {image_name}_empty")
}

/// MatchPattern for verity-hash slot partitions.
pub(crate) fn hash_match_pattern(image_name: &str) -> String {
    format!("{image_name}_@v_hash_a {image_name}_@v_hash_b {image_name}_hash_empty")
}

/// 64-hex random salt from /dev/urandom — shared across A/B slot formats so
/// byte-identical twins produce the same roothash.
pub(crate) fn random_salt_hex() -> miette::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| miette::miette!("cannot open /dev/urandom: {e}"))?;
    let mut bytes = [0u8; 32];
    f.read_exact(&mut bytes)
        .map_err(|e| miette::miette!("cannot read salt from /dev/urandom: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Apply GPT slot metadata (type GUIDs + PARTLABELs) for A/B layouts via
/// `sfdisk` (util-linux — the same tool the extents read-back uses; the
/// parted `type` command needs 3.5+, sgdisk is not required). Runs on the
/// raw image file BEFORE the extents read-back, so the table carries final
/// metadata. Fail-open, never silent: a missing or failing sfdisk warns
/// loudly — sysupdate partition matching degrades, the image still boots —
/// mirroring the historical ESP-flag posture. (The unprivileged populate
/// pre-flight already fails closed on a missing sfdisk; this guard covers
/// a resolve-vs-which PATH mismatch.)
pub(crate) fn apply_gpt_slot_metadata(
    img_path: &Path,
    image: &ImageDeclaration,
    layout: &DiskLayout,
    slots: &Slots,
) -> miette::Result<()> {
    if !layout.ab {
        return Ok(());
    }
    let sfdisk = match std::process::Command::new("which")
        .arg("sfdisk")
        .output()
        .ok()
        .filter(|o| o.status.success())
    {
        Some(_) => "sfdisk",
        None => {
            eprintln!(
                "  ⚠ sfdisk not found — GPT type GUIDs + PARTLABELs NOT set; \
                 systemd-sysupdate will be unable to match the A/B slots by \
                 MatchPartitionType/MatchPattern (documented fail-open: install \
                 util-linux sfdisk for sysupdate-capable images)"
            );
            return Ok(());
        }
    };
    // (partition number 1-based, type GUID, PARTLABEL)
    let mut ops: Vec<(usize, &str, Option<String>)> = Vec::new();
    if layout.partitions[0].fs == "vfat" {
        ops.push((1, ESP_TYPE_GUID, None));
    }
    for (s, &idx) in slots.roots.iter().enumerate() {
        ops.push((
            idx + 1,
            ROOT_TYPE_GUID_X86_64,
            Some(slot_partlabel(&image.name, &image.version, s)),
        ));
    }
    for (s, hash) in slots.hashes.iter().enumerate() {
        if let Some(idx) = hash {
            ops.push((
                idx + 1,
                VERITY_TYPE_GUID_X86_64,
                Some(hash_partlabel(&image.name, &image.version, s)),
            ));
        }
    }
    for (partno, type_guid, label) in ops {
        let set = |flag: &str, value: &str| -> miette::Result<()> {
            let status = std::process::Command::new(sfdisk)
                .args([
                    flag,
                    &img_path.to_string_lossy(),
                    &partno.to_string(),
                    value,
                ])
                .status()
                .map_err(|e| miette::miette!("sfdisk not runnable: {e}"))?;
            if !status.success() {
                // Raw-file images may warn about partition re-read; treat
                // nonzero as degraded metadata, never a silent skip.
                eprintln!(
                    "  ⚠ sfdisk {flag} failed for partition {partno} ({value}) — \
                     sysupdate slot matching may miss this partition (fail-open)"
                );
            }
            Ok(())
        };
        set("--part-type", type_guid)?;
        if let Some(ref label) = label {
            set("--part-label", label)?;
        }
    }
    eprintln!(
        "  ✓ GPT slot metadata: {} type GUIDs + PARTLABELs (root/verity per slot)",
        slots.roots.len() + slots.hashes.iter().flatten().count()
    );
    Ok(())
}
