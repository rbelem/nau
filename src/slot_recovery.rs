//! sysupdate stranded-slot detection + reclaim (issue #86).
//!
//! # The strand
//!
//! `systemd-sysupdate` writes an A/B slot through the parent's whole-disk
//! fd. When the install is killed mid-transaction (power loss, OOM,
//! deadline kill), the target slot can be left holding a *new* version
//! label (`{name}_{ver}_a` / `{name}_{ver}_hash_a`) while the transaction
//! never completed — the matching UKI was never installed, so no boot
//! entry exists for that version. systemd 249 (UC22) has no `sysupdate
//! vacuum` verb to clear it (upstream grew one much later), and per
//! sysupdate.d(5) the documented recovery is a manual relabel to
//! `_empty`. Left alone, the stranded label poisons every later install:
//! the next `systemd-sysupdate update` sees the newest version already
//! instanced (or no free instance under `InstancesMax`) and either no-ops
//! or fails to find a writable target — one crash mid-install converts
//! the #63 fallback story into a permanently stuck single-generation
//! device.
//!
//! # The invariant
//!
//! > A slot partition carries a version label only while its UKI was
//! > fully written and the update was declared installed. The transfer
//! > ordering guarantees the pairing: the root+verity partitions (50-*)
//! > finalize before the UKI (60-uki) is written, so
//! > label-without-a-bootable-UKI ⇒ the transaction never completed ⇒ the
//! > slot is stranded.
//!
//! "Bootable UKI" is checked structurally, not by trusting timestamps or
//! mere file existence: the file must parse as a PE whose section table
//! fits inside the file ([`pe_looks_complete`]). A truncated UKI (kill
//! mid-file-install) must not be mistaken for a declared install — it is
//! exactly as unbootable as a missing one, and systemd-boot can never
//! have selected it.
//!
//! # The measured strand signature (#86 reproduction, systemd 261 tooling)
//!
//! sysupdate masks a slot it is about to rewrite: early in the transfer it
//! sets the partition type to a placeholder GUID (observed constant in
//! this build, distinct per slot flavor) and a fresh random PARTUUID, so
//! nothing on the system recognizes the partition while data is being
//! streamed into it. The final type, PARTUUID and label are only restored
//! at the end of the transfer (and the re-set only lands for partitions
//! fully acquired before the kill). A transaction killed mid-flight
//! therefore leaves a mix the next `sysupdate update` cannot address at
//! all — measured on the #80 harness after a mid-verity-transfer death:
//!
//! - root slot: FINAL version label + FINAL @u PARTUUID, but a masked
//!   placeholder type GUID — invisible to `MatchPartitionType`;
//! - hash slot: final-version label + a masked placeholder type + a
//!   random PARTUUID (the `@u` pin never ran);
//! - ESP: no UKI for the new version (the 60-uki transfer never started).
//!
//! Neither partition matches its slot type NOR carries `_empty`, so the
//! next install refuses with `Selected update '2.0' is already acquired
//! and partially installed. Vacuum it to try installing again.` — the
//! strand. Hence a partition whose LABEL parses as a slot of this image
//! but whose TYPE is not that slot's flavor type is, by itself, evidence
//! of a transaction that never completed — reclaiming it means restoring
//! the flavor type AND relabeling `_empty`.
//!
//! # The recovery policy (conservative by construction)
//!
//! - Reclaim (retype + relabel `_empty`) ONLY versions whose label is
//!   present and whose UKI is absent or structurally incomplete: such a
//!   slot could never have been booted, so reclaiming cannot destroy
//!   state anyone depended on.
//! - Never touch the running version: it is `%A`, the same
//!   `ProtectVersion=` anchor the transfers use, read from
//!   `/etc/os-release` `IMAGE_VERSION=`.
//! - Refuse to reclaim ANYTHING unless the running version's own UKI is
//!   present and parses: that UKI is the sentinel proving the ESP
//!   listing is real (an unmounted/empty ESP would otherwise make every
//!   installed slot look stranded).
//! - Refuse entirely when the image name cannot be attributed from the
//!   transfer definitions: the `%A` anchor and the label grammar are
//!   what separate running from stranded.
//! - Anything that fits neither the "stranded" nor the "installed" box
//!   (UKI present but partition pair incomplete/masked) surfaces as a
//!   named anomaly and is left untouched.
//!
//! # Where it runs
//!
//! In-guest, at boot: the emitted `shuttle-slot-recovery.service` oneshot
//! ([`super::image::boot`] emits it on the same gate as the sysupdate
//! transfers) runs `shuttle runtime recover-slots`, ordered
//! `Before=systemd-sysupdate.service` — recovery must complete before the
//! next install attempt looks for a writable slot.

use std::collections::BTreeMap;
use std::path::Path;

use miette::WrapErr;

use crate::command::CommandRunner;
use crate::image::ROOT_TYPE_GUID_X86_64;
use crate::image::VERITY_TYPE_GUID_X86_64;

/// The literal DPS marker systemd-sysupdate treats as an unused, writable
/// slot (same spelling the build stamps onto slot B, `super::image::verity`).
pub const EMPTY_SLOT_LABEL: &str = "_empty";

/// Prefix for every message this module prints — the serial-log seam the
/// #86 proof asserts on.
pub const LOG_PREFIX: &str = "slot-recovery:";

/// One partition as observed on the device (in-guest: `lsblk -rno
/// NAME,PARTLABEL,PARTTYPE,PKNAME`, plus the partition number resolved
/// from sysfs naming).
#[derive(Debug, Clone, PartialEq)]
pub struct SlotPartition {
    /// Partition device name, e.g. `vda5` / `nvme0n1p5`.
    pub name: String,
    /// Parent whole-disk device name, e.g. `vda`.
    pub pkname: String,
    /// 1-based partition number on the parent disk, when derivable.
    pub partno: Option<u32>,
    /// GPT PARTLABEL.
    pub partlabel: String,
    /// GPT partition type GUID (lowercase).
    pub parttype: String,
}

/// One UKI candidate on the ESP, with the structural completeness verdict
/// ([`pe_looks_complete`]) precomputed by the driver.
#[derive(Debug, Clone, PartialEq)]
pub struct UkiFile {
    pub name: String,
    pub pe_complete: bool,
}

/// Everything the detection needs. Pure data — tests build it from
/// fixtures, the in-guest driver builds it from `/etc/os-release`, the
/// transfer definitions, `lsblk`, and the ESP directory.
pub struct SlotFacts<'a> {
    pub partitions: &'a [SlotPartition],
    pub uki_files: &'a [UkiFile],
    /// `/etc/os-release` `IMAGE_VERSION=` — the running `%A`.
    pub running_version: Option<&'a str>,
    /// The image name the slot labels key off. NOTE: this is NOT
    /// `/etc/os-release` `NAME=` — a base rootfs keeps its own NAME
    /// (measured: "Ubuntu Core 22") while the slot labels carry the
    /// DSL image name. The driver derives it from the emitted transfer
    /// definitions (see [`image_name_from_root_transfer`]).
    pub image_name: Option<&'a str>,
}

/// One reclaim decision: restore these partitions of a stranded version
/// to writable-slot state — relabel to [`EMPTY_SLOT_LABEL`], and for
/// type-masked partitions also restore the flavor's type GUID.
#[derive(Debug, Clone, PartialEq)]
pub struct Reclaim {
    /// The stranded version (never the running one).
    pub version: String,
    pub partitions: Vec<ReclaimPartition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReclaimPartition {
    pub name: String,
    pub pkname: String,
    pub partno: u32,
    /// The stranded label being cleared (for the log line).
    pub label: String,
    /// When the partition's type GUID was masked mid-install (see the
    /// module docs), recovery must restore this flavor type — `None`
    /// keeps the current type and relabels only.
    pub retype_to: Option<String>,
}

/// Detection outcome. `anomalies` are named conditions that fit neither
/// "stranded" nor "installed" — reported, never acted on.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Assessment {
    pub reclaims: Vec<Reclaim>,
    pub anomalies: Vec<String>,
}

/// A parsed slot label: `{name}_{version}_{a|b}` (root) or
/// `{name}_{version}_hash_{a|b}` (verity hash). Anything else — including
/// the `_empty` marker — is not a version-labeled slot.
#[derive(Debug, Clone, PartialEq)]
struct SlotLabel {
    image: String,
    version: String,
    hash: bool,
}

fn parse_slot_label(label: &str) -> Option<SlotLabel> {
    let (stem, hash) = if let Some(s) = label.strip_suffix("_hash_a") {
        (s, true)
    } else if let Some(s) = label.strip_suffix("_hash_b") {
        (s, true)
    } else if let Some(s) = label.strip_suffix("_a") {
        (s, false)
    } else {
        let s = label.strip_suffix("_b")?;
        (s, false)
    };
    let idx = stem.rfind('_')?;
    let image = &stem[..idx];
    let version = &stem[idx + 1..];
    if image.is_empty() || version.is_empty() {
        return None;
    }
    Some(SlotLabel {
        image: image.to_string(),
        version: version.to_string(),
        hash,
    })
}

/// Does `file` name the UKI of `image_name` at `version`? Both spellings
/// count: the factory/counterless `{name}_{version}.efi` and the
/// try-counted install spelling `{name}_{version}+3-0.efi` (any
/// `+<tries>-<done>` suffix).
pub fn uki_name_matches(file: &str, image_name: &str, version: &str) -> bool {
    if file == format!("{image_name}_{version}.efi") {
        return true;
    }
    file.starts_with(format!("{image_name}_{version}+").as_str()) && file.ends_with(".efi")
}

/// Structural completeness check for a UKI file: a PE whose section table
/// fits inside the file. `true` does not prove bootability — it only
/// proves the file was not truncated mid-write, which is the property the
/// label↔UKI pairing invariant needs ("fully written").
pub fn pe_looks_complete(bytes: &[u8]) -> bool {
    if bytes.get(0..2) != Some(b"MZ") {
        return false;
    }
    let Some(pe_off) = read_u32(bytes, 0x3c) else {
        return false;
    };
    let pe_off = pe_off as usize;
    if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return false;
    }
    let coff = pe_off + 4;
    let Some(sections) = read_u16(bytes, coff + 2) else {
        return false;
    };
    // SizeOfOptionalHeader is a u16 at COFF+16 (PE/COFF spec).
    let Some(opt_size) = read_u16(bytes, coff + 16) else {
        return false;
    };
    if sections == 0 {
        return false;
    }
    let opt_off = coff + 20;
    match read_u16(bytes, opt_off) {
        // PE32 and PE32+ optional headers; a UKI stub is always one of the
        // two. Anything else is not a PE this check can vouch for.
        Some(0x10b) | Some(0x20b) => {}
        _ => return false,
    }
    let table = opt_off + opt_size as usize;
    sections_fit(bytes, table, sections as usize)
}

fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let s = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let s = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Every section's on-disk extent (PointerToRawData + SizeOfRawData) must
/// lie inside the file.
fn sections_fit(bytes: &[u8], table: usize, sections: usize) -> bool {
    for i in 0..sections {
        let s = table + i * 40;
        let (Some(raw_size), Some(raw_ptr)) = (
            read_u32(bytes, s + 16).map(u64::from),
            read_u32(bytes, s + 20).map(u64::from),
        ) else {
            return false;
        };
        if raw_size > 0 && raw_ptr.saturating_add(raw_size) > bytes.len() as u64 {
            return false;
        }
    }
    true
}

fn version_has_bootable_uki(ukis: &[UkiFile], image_name: &str, version: &str) -> bool {
    ukis.iter()
        .any(|f| uki_name_matches(&f.name, image_name, version) && f.pe_complete)
}

/// Partition buckets for one version. The `masked` flag marks partitions
/// whose type GUID was replaced mid-install (placeholder masking GUID) —
/// reclaiming them restores the type.
#[derive(Default)]
struct VersionSlots<'a> {
    root: Vec<(&'a SlotPartition, bool)>,
    hash: Vec<(&'a SlotPartition, bool)>,
}

impl<'a> VersionSlots<'a> {
    fn all_healthy(&self) -> bool {
        self.root.iter().chain(self.hash.iter()).all(|(_, m)| !m)
            && !self.root.is_empty()
            && !self.hash.is_empty()
    }
}

/// The detection core (issue #86 invariant). See the module docs for the
/// policy; this function is pure and driven entirely by [`SlotFacts`].
pub fn assess(facts: &SlotFacts) -> Assessment {
    let mut anomalies = Vec::new();
    let Some(running_version) = facts.running_version else {
        anomalies.push(
            "/etc/os-release has no IMAGE_VERSION — the %A anchor that separates the \
             running slot from stranded ones is missing; refusing to reclaim anything"
                .to_string(),
        );
        return Assessment {
            reclaims: Vec::new(),
            anomalies,
        };
    };
    let Some(image_name) = facts.image_name else {
        anomalies.push(
            "no transfer definitions found to name this image — slot labels cannot \
             be attributed; refusing to reclaim anything"
                .to_string(),
        );
        return Assessment {
            reclaims: Vec::new(),
            anomalies,
        };
    };

    // Bucket this image's version-labeled partitions. `_empty`, foreign
    // images' labels, and non-slot labels (esp, state, swap) never bucket.
    // A label of ours whose type GUID is NOT the flavor's type is the
    // measured masking signature (placeholder GUID set early in the
    // transfer): it buckets as a masked partition instead of being
    // rejected.
    let mut slots: BTreeMap<String, VersionSlots> = BTreeMap::new();
    for p in facts.partitions {
        let Some(label) = parse_slot_label(&p.partlabel) else {
            continue;
        };
        if label.image != image_name {
            continue;
        }
        let want_type = if label.hash {
            VERITY_TYPE_GUID_X86_64
        } else {
            ROOT_TYPE_GUID_X86_64
        };
        let masked = !p.parttype.eq_ignore_ascii_case(want_type);
        if p.partno.is_none() {
            anomalies.push(format!(
                "partition {} carries slot label '{}' but its partition number could \
                 not be resolved — cannot reclaim it",
                p.name, p.partlabel
            ));
            continue;
        }
        let entry = slots.entry(label.version).or_default();
        let pair = (p, masked);
        if label.hash {
            entry.hash.push(pair);
        } else {
            entry.root.push(pair);
        }
    }

    // The sentinel: the running version's own UKI must be present and
    // parse. Without it the ESP listing cannot be trusted (unmounted or
    // wrong ESP would make every installed slot look stranded).
    if !version_has_bootable_uki(facts.uki_files, image_name, running_version) {
        anomalies.push(format!(
            "the running version {running_version} has no structurally complete UKI on \
             the ESP — the listing is untrustworthy (ESP not mounted?); refusing to \
             reclaim anything"
        ));
        return Assessment {
            reclaims: Vec::new(),
            anomalies,
        };
    }

    let mut reclaims = Vec::new();
    for (version, parts) in &slots {
        // The running version is %A: protected, never recycled, even if
        // its UKI looks odd (we booted through it — it cannot be stranded).
        if version == running_version {
            continue;
        }
        if version_has_bootable_uki(facts.uki_files, image_name, version) {
            // Declared installed. Complete only when both halves are
            // present AND healthy; anything else is a state the policy
            // does not understand well enough to touch.
            if !parts.all_healthy() {
                anomalies.push(format!(
                    "version {version} has a bootable UKI but an incomplete or \
                     type-masked partition pair — sysupdate never leaves this \
                     state; not reclaiming"
                ));
            }
            continue;
        }
        // No bootable UKI for a labeled, non-running version: the loader
        // could never have selected it. The transaction never completed —
        // reclaim every labeled half, restoring the flavor type where it
        // was masked. The flavor follows the bucket (root vs hash).
        let partitions = parts
            .root
            .iter()
            .map(|(p, m)| (*p, *m, ROOT_TYPE_GUID_X86_64))
            .chain(
                parts
                    .hash
                    .iter()
                    .map(|(p, m)| (*p, *m, VERITY_TYPE_GUID_X86_64)),
            )
            .map(|(p, masked, flavor)| ReclaimPartition {
                name: p.name.clone(),
                pkname: p.pkname.clone(),
                partno: p.partno.unwrap_or_default(),
                label: p.partlabel.clone(),
                retype_to: masked.then(|| flavor.to_string()),
            })
            .collect();
        reclaims.push(Reclaim {
            version: version.clone(),
            partitions,
        });
    }
    Assessment {
        reclaims,
        anomalies,
    }
}

// ── In-guest driver ──────────────────────────────────────────────────────

/// Tools the driver needs. Resolved from PATH in-guest; `None` anywhere
/// means the driver reports and no-ops (fail-safe — boot must proceed).
pub struct SlotRecoveryTools {
    pub lsblk: Option<std::path::PathBuf>,
    pub sfdisk: Option<std::path::PathBuf>,
}

impl SlotRecoveryTools {
    pub fn resolve() -> SlotRecoveryTools {
        SlotRecoveryTools {
            lsblk: crate::runtime::find_on_path("lsblk"),
            sfdisk: crate::runtime::find_on_path("sfdisk"),
        }
    }
}

/// One `KEY=VALUE` field from an os-release-style file, unquoted.
fn os_release_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some(value) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) else {
            continue;
        };
        return Some(value.trim().trim_matches('"').to_string());
    }
    None
}

/// The image name, read out of the emitted root transfer definition.
///
/// `50-root.transfer`'s `[Target]` carries `MatchPattern={name}_@v_a` —
/// the exact naming contract systemd-sysupdate matches slot labels with,
/// so it is the authoritative in-guest spelling of "this image's name".
/// The `[Source]` MatchPattern (an `@v`/`@u` artifact pattern) and any
/// other sections are not slot-label grammar and are ignored. `None`
/// means the definitions are missing or unparsable — the caller refuses
/// to attribute labels and reclaims nothing.
fn image_name_from_root_transfer(text: &str) -> Option<String> {
    let mut in_target = false;
    for line in text.lines() {
        let line = line.trim();
        match line {
            "[Target]" => in_target = true,
            "[Source]" | "[Transfer]" => in_target = false,
            _ => {}
        }
        if !in_target {
            continue;
        }
        let Some(pattern) = line.strip_prefix("MatchPattern=") else {
            continue;
        };
        // One arm is the norm; if several, any arm of the slot grammar
        // names the image equally.
        for arm in pattern.split_whitespace() {
            if let Some(name) = arm
                .strip_suffix("_@v_a")
                .or_else(|| arm.strip_suffix("_@v_b"))
            {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// `lsblk -rno NAME,PARTLABEL,PARTTYPE,PKNAME` → partition records. Lines
/// that do not carry all four columns (whole disks, unlabelled partitions)
/// are not version-labeled slots and are skipped.
fn gather_partitions(
    runner: &dyn CommandRunner,
    lsblk: &Path,
) -> miette::Result<Vec<SlotPartition>> {
    let argv: Vec<String> = vec![
        lsblk.to_string_lossy().into_owned(),
        "-r".into(),
        "-n".into(),
        "-o".into(),
        "NAME,PARTLABEL,PARTTYPE,PKNAME".into(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("slot-recovery: lsblk failed to run: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "slot-recovery: lsblk exited {}: {}",
            out.code,
            out.stderr.trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut partitions = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            continue;
        }
        let (name, partlabel, parttype, pkname) =
            (fields[0], fields[1], fields[2].to_lowercase(), fields[3]);
        partitions.push(SlotPartition {
            name: name.to_string(),
            pkname: pkname.to_string(),
            partno: parse_partno(name, pkname),
            partlabel: partlabel.to_string(),
            parttype,
        });
    }
    Ok(partitions)
}

/// Partition number from lsblk naming: the parent name plus an optional
/// `p` plus digits (`vda`+`5`, `nvme0n1`+`p5`).
fn parse_partno(name: &str, pkname: &str) -> Option<u32> {
    let rest = name.strip_prefix(pkname)?;
    let rest = rest.strip_prefix('p').unwrap_or(rest);
    rest.parse().ok()
}

/// List the ESP's UKI directory with the PE completeness verdict per file.
/// A missing/unreadable directory yields an empty list — the sentinel
/// check in [`assess`] turns that into a refusal, never a reclaim.
fn gather_ukis(esp: &Path) -> Vec<UkiFile> {
    let dir = esp.join("EFI").join("Linux");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut ukis = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".efi") {
            continue;
        }
        let pe_complete = std::fs::read(entry.path())
            .map(|bytes| pe_looks_complete(&bytes))
            .unwrap_or(false);
        ukis.push(UkiFile { name, pe_complete });
    }
    ukis
}

/// Run the sfdisk operations that restore one stranded partition to a
/// writable slot: type first (undo the mid-install masking), then the
/// `_empty` label. Doing the type before the label means an interrupted
/// recovery leaves a well-typed partition still wearing its stranded
/// label — exactly the state the next boot's assessment detects.
fn reclaim_partition(
    runner: &dyn CommandRunner,
    sfdisk: &Path,
    part: &ReclaimPartition,
) -> miette::Result<()> {
    let disk = format!("/dev/{}", part.pkname);
    let mut ops: Vec<(String, String)> = Vec::new();
    if let Some(guid) = &part.retype_to {
        ops.push(("--part-type".into(), guid.clone()));
    }
    ops.push(("--part-label".into(), EMPTY_SLOT_LABEL.to_string()));
    for (flag, value) in &ops {
        let argv: Vec<String> = vec![
            sfdisk.to_string_lossy().into_owned(),
            flag.clone(),
            disk.clone(),
            part.partno.to_string(),
            value.clone(),
        ];
        let out = runner
            .run(&argv)
            .map_err(|e| miette::miette!("slot-recovery: sfdisk failed to run: {e}"))?;
        if out.code != 0 {
            return Err(miette::miette!(
                "slot-recovery: sfdisk {flag} on {disk} partition {} ('{}') failed: {}",
                part.partno,
                part.label,
                out.stderr.trim()
            ));
        }
    }
    Ok(())
}

/// Apply every reclaim decision, returning the number of partitions
/// restored. The first failed sfdisk op aborts with a named error — a
/// half-applied reclaim is re-detected and re-applied on the next boot.
fn apply_reclaims(
    runner: &dyn CommandRunner,
    sfdisk: &Path,
    reclaims: &[Reclaim],
) -> miette::Result<usize> {
    let mut reclaimed = 0usize;
    for reclaim in reclaims {
        for part in &reclaim.partitions {
            reclaim_partition(runner, sfdisk, part).wrap_err_with(|| {
                format!(
                    "slot-recovery: while reclaiming stranded version {}",
                    reclaim.version
                )
            })?;
            let type_note = match &part.retype_to {
                Some(guid) => format!("; type restored to {guid}"),
                None => String::new(),
            };
            crate::output::ok(format!(
                "{LOG_PREFIX} relabeled '{}' -> '{EMPTY_SLOT_LABEL}' on /dev/{} partition \
                 {} (version {} stranded mid-install: no bootable UKI on the ESP){type_note}",
                part.label, part.pkname, part.partno, reclaim.version
            ));
            reclaimed += 1;
        }
    }
    Ok(reclaimed)
}

/// `shuttle runtime recover-slots` — assess and reclaim, in-guest. Every
/// early exit is a named no-op: a boot must never wedge here, and an
/// assessment error must never relabel half-blind.
pub fn recover_slots(
    esp: &Path,
    runner: &dyn CommandRunner,
    tools: &SlotRecoveryTools,
) -> miette::Result<()> {
    let (lsblk, sfdisk) = match (&tools.lsblk, &tools.sfdisk) {
        (Some(l), Some(s)) => (l, s),
        _ => {
            crate::output::warn(format!(
                "{LOG_PREFIX} lsblk/sfdisk not found — cannot assess slot state; \
                 leaving the disk alone"
            ));
            return Ok(());
        }
    };
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let running_version = os_release_field(&os, "IMAGE_VERSION");
    // The image name comes from the transfer definitions, NOT os-release:
    // a base rootfs keeps its own NAME ("Ubuntu Core 22") while the slot
    // labels and MatchPattern carry the DSL image name (measured, #86).
    let transfer_path = Path::new("/")
        .join(crate::image::SYSUPDATE_DIR)
        .join("50-root.transfer");
    let image_name = std::fs::read_to_string(&transfer_path)
        .ok()
        .as_deref()
        .and_then(image_name_from_root_transfer);

    let partitions = gather_partitions(runner, lsblk)?;
    if !esp.join("EFI").join("Linux").is_dir() {
        crate::output::warn(format!(
            "{LOG_PREFIX} no EFI/Linux directory under {} — ESP not mounted as declared; \
             refusing to assess",
            esp.display()
        ));
        return Ok(());
    }
    let ukis = gather_ukis(esp);

    let facts = SlotFacts {
        partitions: &partitions,
        uki_files: &ukis,
        running_version: running_version.as_deref(),
        image_name: image_name.as_deref(),
    };
    let assessment = assess(&facts);
    for anomaly in &assessment.anomalies {
        crate::output::warn(format!("{LOG_PREFIX} anomaly: {anomaly}"));
    }
    if assessment.reclaims.is_empty() {
        crate::output::info(format!("{LOG_PREFIX} no stranded slots"));
        return Ok(());
    }
    let reclaimed = apply_reclaims(runner, sfdisk, &assessment.reclaims)?;
    crate::output::ok(format!(
        "{LOG_PREFIX} reclaimed {reclaimed} stranded partition(s)"
    ));
    Ok(())
}

// ── Tests — fixture-driven (issue #86) ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = ROOT_TYPE_GUID_X86_64;
    const VERITY: &str = VERITY_TYPE_GUID_X86_64;
    const ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";

    /// The factory #80 device as the guest sees it: 1=esp, 2=rootA
    /// (running), 3=state, 4=hashA, 5=rootB `_empty`, 6=hashB `_empty`,
    /// 7=swap.
    fn factory_partitions() -> Vec<SlotPartition> {
        vec![
            part("vda1", "vda", 1, "esp", ESP),
            part("vda2", "vda", 2, "shuttle-80_1.0_a", ROOT),
            part(
                "vda3",
                "vda",
                3,
                "state",
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
            ),
            part("vda4", "vda", 4, "shuttle-80_1.0_hash_a", VERITY),
            part("vda5", "vda", 5, EMPTY_SLOT_LABEL, ROOT),
            part("vda6", "vda", 6, EMPTY_SLOT_LABEL, VERITY),
            part("vda7", "vda", 7, "", "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"),
        ]
    }

    fn part(name: &str, pkname: &str, partno: u32, label: &str, ptype: &str) -> SlotPartition {
        SlotPartition {
            name: name.to_string(),
            pkname: pkname.to_string(),
            partno: Some(partno),
            partlabel: label.to_string(),
            parttype: ptype.to_string(),
        }
    }

    fn uki(name: &str, complete: bool) -> UkiFile {
        UkiFile {
            name: name.to_string(),
            pe_complete: complete,
        }
    }

    fn facts<'a>(
        partitions: &'a [SlotPartition],
        ukis: &'a [UkiFile],
        running: &'a str,
    ) -> SlotFacts<'a> {
        SlotFacts {
            partitions,
            uki_files: ukis,
            running_version: Some(running),
            image_name: Some("shuttle-80"),
        }
    }

    #[test]
    fn factory_state_is_a_noop() {
        let parts = factory_partitions();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert!(a.reclaims.is_empty(), "factory has nothing stranded");
        assert!(a.anomalies.is_empty(), "{:?}", a.anomalies);
    }

    #[test]
    fn stranded_label_without_uki_is_reclaimed() {
        // The canonical mid-verity kill: root finalized with the new
        // label, hash still `_empty`, no UKI — the transaction never
        // completed, so the labeled half goes back to `_empty`.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert_eq!(a.reclaims.len(), 1, "{:?}", a.reclaims);
        let r = &a.reclaims[0];
        assert_eq!(r.version, "2.0");
        assert_eq!(r.partitions.len(), 1);
        assert_eq!(r.partitions[0].partno, 5);
        assert_eq!(r.partitions[0].label, "shuttle-80_2.0_a");
        assert!(
            r.partitions[0].retype_to.is_none(),
            "healthy type: label-only reclaim"
        );
        assert!(a.anomalies.is_empty(), "{:?}", a.anomalies);
    }

    #[test]
    fn pair_labeled_but_uki_missing_reclaims_both_halves() {
        // Kill between the 50-* transfers and the 60-uki transfer: both
        // halves labeled, no boot entry. Both are reclaimable.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        parts[5].partlabel = "shuttle-80_2.0_hash_a".to_string();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert_eq!(a.reclaims.len(), 1);
        let r = &a.reclaims[0];
        assert_eq!(r.version, "2.0");
        assert_eq!(r.partitions.len(), 2, "root + hash both reclaimed");
    }

    #[test]
    fn complete_install_is_left_alone() {
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        parts[5].partlabel = "shuttle-80_2.0_hash_a".to_string();
        let ukis = vec![
            uki("shuttle-80_1.0.efi", true),
            uki("shuttle-80_2.0+3-0.efi", true),
        ];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert!(a.reclaims.is_empty(), "{:?}", a.reclaims);
        assert!(a.anomalies.is_empty(), "{:?}", a.anomalies);
    }

    #[test]
    fn truncated_uki_counts_as_missing_not_installed() {
        // Kill mid-UKI-write: the file exists but is not a complete PE —
        // systemd-boot can never have loaded it. The slot pair is still
        // stranded.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        parts[5].partlabel = "shuttle-80_2.0_hash_a".to_string();
        let ukis = vec![
            uki("shuttle-80_1.0.efi", true),
            uki("shuttle-80_2.0+3-0.efi", false),
        ];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert_eq!(a.reclaims.len(), 1, "truncated UKI ⇒ stranded");
        assert_eq!(a.reclaims[0].version, "2.0");
    }

    #[test]
    fn running_version_is_never_reclaimed() {
        // Paranoia: even a label for the RUNNING version with no UKI on
        // the ESP must never be relabeled (we booted through it).
        let mut parts = factory_partitions();
        parts[1].partlabel = "shuttle-80_3.0_a".to_string();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "3.0"));
        assert!(a.reclaims.is_empty(), "{:?}", a.reclaims);
        // The untrustworthy-ESP refusal fired instead.
        assert!(
            a.anomalies.iter().any(|m| m.contains("untrustworthy")),
            "{:?}",
            a.anomalies
        );
    }

    #[test]
    fn missing_running_uki_refuses_everything() {
        // An unmounted/wrong ESP makes every slot look stranded — the
        // running system's own UKI is the sentinel proving the listing
        // is real. Without it: refuse everything.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        let a = assess(&facts(&parts, &[], "1.0"));
        assert!(a.reclaims.is_empty(), "refusal must suppress reclaims");
        assert!(a.anomalies.iter().any(|m| m.contains("untrustworthy")));
    }

    #[test]
    fn missing_os_release_anchor_refuses_everything() {
        let parts = factory_partitions();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let f = SlotFacts {
            partitions: &parts,
            uki_files: &ukis,
            running_version: None,
            image_name: Some("shuttle-80"),
        };
        let a = assess(&f);
        assert!(a.reclaims.is_empty());
        assert!(a.anomalies.iter().any(|m| m.contains("IMAGE_VERSION")));
    }

    #[test]
    fn uki_present_but_incomplete_pair_is_a_named_anomaly() {
        // sysupdate finalizes the 50-* partitions BEFORE writing the UKI,
        // so a bootable UKI over an `_empty` half is a state the policy
        // does not understand — surface it, touch nothing.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        let ukis = vec![
            uki("shuttle-80_1.0.efi", true),
            uki("shuttle-80_2.0+3-0.efi", true),
        ];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert!(a.reclaims.is_empty());
        assert!(
            a.anomalies
                .iter()
                .any(|m| m.contains("type-masked partition pair")),
            "{:?}",
            a.anomalies
        );
    }

    #[test]
    fn foreign_image_labels_are_ignored() {
        let mut parts = factory_partitions();
        parts[4].partlabel = "other-os_9.9_a".to_string();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert!(a.reclaims.is_empty());
        assert!(a.anomalies.is_empty());
    }

    #[test]
    fn type_masked_partitions_are_the_strand_and_get_restored() {
        // The MEASURED #86 strand (systemd 261 tooling, mid-transaction
        // kill): both halves wear final-version labels but sysupdate left
        // their type GUIDs masked (placeholder GUIDs), so the next update
        // matches neither by MatchPartitionType nor `_empty`.
        // Recovery restores the flavor type AND relabels.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        parts[4].parttype = "64362e66-0c4f-4d42-a410-0f7f5a71e5a2".to_string(); // masked
        parts[5].partlabel = "shuttle-80_2.0_hash_a".to_string();
        parts[5].parttype = "8c9d831f-e8b7-4285-994a-33623dd5ee68".to_string(); // masked
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert_eq!(a.reclaims.len(), 1, "{:?}", a.reclaims);
        let r = &a.reclaims[0];
        assert_eq!(r.version, "2.0");
        assert_eq!(r.partitions.len(), 2);
        let by_label = |l: &str| {
            r.partitions
                .iter()
                .find(|p| p.label == l)
                .unwrap_or_else(|| panic!("{l} not in {:?}", r.partitions))
        };
        assert_eq!(
            by_label("shuttle-80_2.0_a").retype_to.as_deref(),
            Some(ROOT_TYPE_GUID_X86_64),
            "masked root type restored"
        );
        assert_eq!(
            by_label("shuttle-80_2.0_hash_a").retype_to.as_deref(),
            Some(VERITY_TYPE_GUID_X86_64),
            "masked hash type restored"
        );
        assert!(a.anomalies.is_empty(), "{:?}", a.anomalies);
    }

    #[test]
    fn one_masked_half_of_a_pair_is_reclaimed_too() {
        // Kill between the two 50-* transfers: root finalized (healthy
        // type), hash still `_empty`. The labeled half is reclaimable
        // regardless.
        let mut parts = factory_partitions();
        parts[4].partlabel = "shuttle-80_2.0_a".to_string();
        let ukis = vec![uki("shuttle-80_1.0.efi", true)];
        let a = assess(&facts(&parts, &ukis, "1.0"));
        assert_eq!(a.reclaims.len(), 1);
        let r = &a.reclaims[0];
        assert_eq!(r.partitions.len(), 1);
        assert_eq!(r.partitions[0].partno, 5);
        assert_eq!(r.partitions[0].label, "shuttle-80_2.0_a");
        assert!(
            r.partitions[0].retype_to.is_none(),
            "healthy type: label-only reclaim"
        );
        assert!(a.anomalies.is_empty(), "{:?}", a.anomalies);
    }

    #[test]
    fn slot_label_parsing() {
        let ok = |l: &str| parse_slot_label(l).map(|s| (s.image, s.version, s.hash));
        assert_eq!(
            ok("shuttle-80_2.0_a"),
            Some(("shuttle-80".into(), "2.0".into(), false))
        );
        assert_eq!(
            ok("shuttle-80_2.0_hash_b"),
            Some(("shuttle-80".into(), "2.0".into(), true))
        );
        // Multi-part versions and underscored names split at the LAST `_`.
        assert_eq!(
            ok("my_os_1.2.3_b"),
            Some(("my_os".into(), "1.2.3".into(), false))
        );
        assert_eq!(ok("_empty"), None);
        assert_eq!(ok("esp"), None);
        assert_eq!(ok("state"), None);
        assert_eq!(ok("_a"), None, "empty name");
    }

    #[test]
    fn uki_name_matching_covers_both_spellings() {
        let m = |f| uki_name_matches(f, "shuttle-80", "2.0");
        assert!(m("shuttle-80_2.0.efi"));
        assert!(m("shuttle-80_2.0+3-0.efi"));
        assert!(m("shuttle-80_2.0+2-1.efi"));
        assert!(!m("shuttle-80_1.0.efi"));
        assert!(!m("shuttle-80_2.0.efi.bak"));
        assert!(!m("shuttle-80_20.efi"), "no version prefix collisions");
    }

    #[test]
    fn pe_completeness_accepts_a_well_formed_image_and_rejects_truncation() {
        // Minimal PE32+ with one section whose raw extent is 0x200..0x210.
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.resize(0x3c, 0);
        pe.extend_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        pe.extend_from_slice(b"PE\0\0"); // at 0x40
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // 0x44 machine
        pe.extend_from_slice(&1u16.to_le_bytes()); // 0x46 number of sections
        pe.extend_from_slice(&[0u8; 12]); // 0x48 timestamp, symtab, nsyms
        pe.extend_from_slice(&240u16.to_le_bytes()); // 0x54 optional header size
        pe.extend_from_slice(&[0u8; 2]); // 0x56 characteristics
        pe.extend_from_slice(&0x20bu16.to_le_bytes()); // 0x58 PE32+ magic
        pe.resize(0x58 + 240, 0); // section table at 0x148
                                  // Section table entry: name, vsize, vaddr, raw size, raw ptr, ...
        pe.extend_from_slice(&[0u8; 16]);
        pe.extend_from_slice(&0x10u32.to_le_bytes()); // 0x158 SizeOfRawData
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // 0x15c PointerToRawData
        pe.resize(0x58 + 240 + 40, 0);
        // The file must actually COVER the declared section extent
        // (0x200 + 0x10): that is the completeness property itself.
        pe.resize(0x210, 0);

        assert!(pe_looks_complete(&pe), "well-formed PE must pass");
        let cut = pe.len() - 0x8;
        assert!(!pe_looks_complete(&pe[..cut]), "truncated PE must fail");
        assert!(!pe_looks_complete(&pe[..0x30]), "no e_lfanew target");
        assert!(!pe_looks_complete(b"ELF...."), "not even MZ");
        assert!(!pe_looks_complete(&[]));
    }

    #[test]
    fn os_release_fields_parse_with_quotes_and_comments() {
        let os = "\
# comment
NAME=\"Ubuntu Core 22\"
VERSION_ID=22.04
IMAGE_VERSION=1.0
";
        assert_eq!(
            os_release_field(os, "NAME").as_deref(),
            Some("Ubuntu Core 22")
        );
        assert_eq!(
            os_release_field(os, "IMAGE_VERSION").as_deref(),
            Some("1.0")
        );
        assert_eq!(os_release_field(os, "MISSING"), None);
    }

    #[test]
    fn image_name_comes_from_the_root_transfer_target_pattern() {
        // The real emitted definition: [Target] MatchPattern carries the
        // slot-label grammar the in-guest name must be derived from. The
        // [Source] artifact pattern (`root_@v_@u.img`) must NOT match.
        let t = crate::image::root_transfer("shuttle-80", "http://10.0.2.2:8123/");
        assert_eq!(
            image_name_from_root_transfer(&t).as_deref(),
            Some("shuttle-80")
        );
        assert_eq!(image_name_from_root_transfer("garbage"), None);
        assert_eq!(
            image_name_from_root_transfer("[Target]\nMatchPattern=other_@v_b\n").as_deref(),
            Some("other")
        );
    }

    #[test]
    fn partno_parses_from_lsblk_naming() {
        assert_eq!(parse_partno("vda5", "vda"), Some(5));
        assert_eq!(parse_partno("nvme0n1p5", "nvme0n1"), Some(5));
        assert_eq!(parse_partno("mmcblk0p12", "mmcblk0"), Some(12));
        assert_eq!(parse_partno("sda", ""), None);
    }

    #[test]
    fn lsblk_fixture_dumps_into_partition_records() {
        // Fixture: real `lsblk -rno NAME,PARTLABEL,PARTTYPE,PKNAME` shape
        // for the factory #80 device (disks have no PARTLABEL column data,
        // so their lines carry fewer fields and are skipped).
        struct Fake;
        impl CommandRunner for Fake {
            fn run(&self, _argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
                let out = b"vda\n\
vda1 esp c12a7328-f81f-11d2-ba4b-00a0c93ec93b vda\n\
vda2 shuttle-80_1.0_a 4f68bce3-e8cd-4db1-96e7-fbcaf984b709 vda\n\
vda3 state 0fc63daf-8483-4772-8e79-3d69d8477de4 vda\n\
vda4 shuttle-80_1.0_hash_a 2c7357ed-ebd2-46d9-aec1-23d437ec2bf5 vda\n\
vda5 _empty 4f68bce3-e8cd-4db1-96e7-fbcaf984b709 vda\n\
vda6 _empty 2c7357ed-ebd2-46d9-aec1-23d437ec2bf5 vda\n\
vda7  0657fd6d-a4ab-43c4-84e5-0933c84b4f4f vda\n"
                    .to_vec();
                Ok(crate::command::RunnerOutput {
                    code: 0,
                    stdout: out,
                    stderr: String::new(),
                })
            }
        }
        let parts = gather_partitions(&Fake, Path::new("/usr/bin/lsblk")).unwrap();
        // The whole-disk line ("vda") and the unlabeled swap line (empty
        // PARTLABEL collapses in raw mode → 3 fields) are not slots and
        // are skipped; the 6 labeled partitions are kept.
        assert_eq!(parts.len(), 6, "disk + unlabeled lines skipped");
        let root_a = parts.iter().find(|p| p.name == "vda2").unwrap();
        assert_eq!(root_a.partlabel, "shuttle-80_1.0_a");
        assert_eq!(root_a.partno, Some(2));
        assert_eq!(root_a.pkname, "vda");
        assert!(parts
            .iter()
            .all(|p| p.parttype.chars().all(|c| c.is_ascii())));
    }
}
