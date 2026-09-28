//! `shuttle verify-image` — read-only flash verification against the
//! signed image manifest (ADR-0044 Decision 4, issue #265).
//!
//! A flashed device cannot verify its own medium — trust is established
//! at download; this verb proves the write. It is the entire 1.0
//! installer surface inside shuttle: read-only, unprivileged, no write
//! path, ever.
//!
//! # Pipeline (every refusal names its region)
//!
//! 1. Parse the published signed image manifest and verify its Ed25519
//!    signature under the operator trust anchors (`--key` and/or
//!    `~/.config/shuttle/keys/*.pub`, the ADR-0024 §4 anchor set the
//!    operator held at download; the device-embedded copy is unreachable
//!    unprivileged — it lives inside the dm-verity root). The signature
//!    input is the manifest serialized with the signatures map emptied —
//!    the same canonical-bytes scheme as [`crate::sign`].
//! 2. Read the target's GPT with one read-only `sfdisk -J` call (the
//!    same read-back the build uses) and identify the generation's
//!    regions by their GPT identity: the root/hash PARTUUIDs are DERIVED
//!    from the manifest roothash ([`generation_guids_from_roothash`]),
//!    so the expected identity is not stored anywhere — it is recomputed
//!    from the signed bytes. A device carrying a different image (wrong
//!    mission, wrong version, rewritten table) cannot reproduce them.
//!    The derived pair identifies the GENERATION, not a physical slot —
//!    sysupdate pins the same derived GUIDs onto whichever slot it fills
//!    (`PartitionUUID=@u`) — so selection matches by identity wherever
//!    the generation sits, never first-match on the type GUID, and a
//!    duplicated PARTUUID refuses instead of matching twice.
//! 3. Refuse a truncated medium: any partition extending past the end
//!    of the device is an interrupted flash — a distinct refusal from an
//!    undeterminable medium size, which refuses by its own name.
//! 4. Recompute the verity hash regions: the root and hash partition
//!    bytes are read out to scratch files (plain reads; the device is
//!    never opened for writing) and `veritysetup verify` checks them
//!    against the manifest roothash — the userspace half of what the
//!    UKI's kernel cmdline demands at boot.
//!
//! # Slots (`--slot {a|b|auto}`, default auto)
//!
//! The factory image fills slot A and ships slot B `_empty`; after a
//! sysupdate the NEW generation lives in the other slot and the factory
//! UKI boots it. The manifest signs a generation, not a slot, and the
//! derived PARTUUIDs cannot tell the slots apart — only physical
//! position can. The build writes slot B contiguous behind slot A
//! (root-A, hash-A, root-B, hash-B), so table order IS slot order, and
//! sysupdate overwrites slots in place without re-ordering the GPT.
//! `--slot auto` verifies the manifest's generation wherever it sits
//! (this is what makes a post-sysupdate device verifiable against the
//! new manifest, #286); `--slot a` / `--slot b` additionally demand the
//! generation sit at that physical position and refuse by name when it
//! sits in the other. Verifying a slot the generation never occupied
//! would prove nothing — that is why the identity, not the flag, finds
//! the partitions.
//!
//! # Live axis (deferred)
//!
//! Flash-to-real-medium verification (loop/USB) is the live gate and is
//! exercised in the live phase; everything here runs against device
//! FILES, which is also what makes the unit surface deterministic.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use super::*;

/// Which physical slot's regions one `shuttle verify-image` run
/// verifies (`--slot`, gathered by the CLI in [`crate::cli`]; the
/// library entry takes the struct so tests drive the same path the
/// binary does).
#[derive(Debug, Clone)]
pub struct VerifyImageArgs {
    /// The flashed target: a block device (`/dev/disk/by-id/...`) or an
    /// image file. Only ever opened for reading.
    pub device: PathBuf,
    /// The signed image manifest published with the mission image
    /// (`nau-<mission>-<version>-<arch>.manifest.json`, ADR-0044 D5).
    pub manifest: PathBuf,
    /// Extra trust anchor — a public-key file accepted beside the
    /// operator keychain when verifying the manifest signature.
    pub key: Option<PathBuf>,
    /// Which slot's regions to verify. Auto (the default) locates the
    /// manifest's generation wherever it sits; `A`/`B` demand a physical
    /// slot and refuse by name when the generation sits elsewhere.
    pub slot: SlotSelector,
}

/// The `--slot` choice: a physical slot demand (`a`/`b`) or `auto` —
/// locate the manifest's generation wherever it sits on the device.
///
/// The manifest signs a GENERATION, not a slot: the PARTUUIDs derived
/// from its roothash are pinned by sysupdate onto whichever slot it
/// fills, so the slots are told apart by physical position only — the
/// build writes slot B contiguous behind slot A (root-A, hash-A,
/// root-B, hash-B) and sysupdate overwrites slots in place, so table
/// order among the type-typed partitions IS slot order.
#[derive(clap::ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SlotSelector {
    /// Slot A — the factory slot the build flashes.
    A,
    /// Slot B — the twin the build ships `_empty`, filled by sysupdate.
    B,
    /// Locate the manifest's generation wherever it sits (default);
    /// report which slot held it.
    #[default]
    Auto,
}

impl SlotSelector {
    /// The demanded physical position among the type-typed partitions
    /// (0 → a), or `None` for auto.
    fn position(self) -> Option<usize> {
        match self {
            SlotSelector::A => Some(0),
            SlotSelector::B => Some(1),
            SlotSelector::Auto => None,
        }
    }

    /// The slot letter for reports ("a"/"b") — auto resolves to the
    /// position the generation was actually found at, so this takes the
    /// resolved position.
    fn letter(position: usize) -> &'static str {
        super::slot_suffix(position)
    }
}

/// What one successful verification pinned, for the CLI to report.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub image_name: String,
    pub image_version: String,
    /// Key id the manifest signature verified under.
    pub verified_key_id: String,
    /// dm-verity roothash the medium was recomputed against.
    pub roothash: String,
    /// Which physical slot the generation was verified in ("a"/"b") —
    /// the demanded one under `--slot a|b`, the discovered one under
    /// auto.
    pub slot: String,
    /// GPT identity of the verified root slot.
    pub root_partuuid: String,
    /// GPT identity of the verified hash partition.
    pub hash_partuuid: String,
}

/// Verify a flashed device against its signed image manifest. Read-only
/// over `args.device`; every failure names the region that refused.
/// Resolves `veritysetup` from the host PATH.
pub fn verify_device(
    runner: &dyn crate::command::CommandRunner,
    args: &VerifyImageArgs,
) -> miette::Result<VerifyOutcome> {
    let veritysetup = find_veritysetup();
    verify_device_with(runner, args, veritysetup.as_deref())
}

/// [`verify_device`] with the tool injected — the fail-closed seam the
/// tests drive (mirrors [`verity_format_with`]).
pub(crate) fn verify_device_with(
    runner: &dyn crate::command::CommandRunner,
    args: &VerifyImageArgs,
    veritysetup: Option<&Path>,
) -> miette::Result<VerifyOutcome> {
    let keys_dir = crate::sign::keys_dir(&operator_home()?);
    verify_device_at(runner, args, veritysetup, &keys_dir)
}

/// [`verify_device_with`] against an explicit keychain directory — the
/// seam the release self-check drives (#293 item 4): the release must
/// prove the published set verifies under the SAME keychain it signed
/// with, independent of the process's HOME.
pub(crate) fn verify_device_at(
    runner: &dyn crate::command::CommandRunner,
    args: &VerifyImageArgs,
    veritysetup: Option<&Path>,
    keys_dir: &Path,
) -> miette::Result<VerifyOutcome> {
    let manifest = load_signed_manifest(&args.manifest)?;
    let key_id = verify_manifest_signature_at(&manifest, args.key.as_deref(), keys_dir)?;
    let roothash = required_roothash(&manifest)?;
    let table = read_gpt(runner, &args.device)?;
    let identity = expected_identity(&manifest, &roothash)?;
    let (root, hash, position) = resolve_generation_regions(&table, &identity, args.slot)?;
    check_esp_identity(&table, &identity)?;
    check_truncation(&args.device, &table)?;
    run_verity_verify_with(runner, &args.device, root, hash, &roothash, veritysetup)?;
    Ok(VerifyOutcome {
        image_name: manifest.name,
        image_version: manifest.version,
        verified_key_id: key_id,
        roothash,
        slot: SlotSelector::letter(position).to_string(),
        root_partuuid: root.partuuid.clone(),
        hash_partuuid: hash.partuuid.clone(),
    })
}

// ── 1. Signed manifest ──

/// The top-level fields this shuttle's image-manifest schema defines.
/// A manifest carrying anything else was written by a newer (or foreign)
/// shuttle: serde would silently DROP the unknown fields and the run
/// would die later as a generic "no trusted signature" — naming the skew
/// here instead is what makes the diagnosis a one-liner (#293 item 9).
const KNOWN_MANIFEST_FIELDS: [&str; 10] = [
    "name",
    "version",
    "arch",
    "snaps",
    "kernel_version",
    "cmdline",
    "uki",
    "esp_partuuid",
    "roothash",
    "signatures",
];

/// Load and parse the published signed image manifest. Anything that
/// does not parse is a named refusal — the file is the trust input. A
/// manifest whose top-level field set is not a subset of this shuttle's
/// schema refuses as SCHEMA SKEW before any signature check: newer-schema
/// manifests must not masquerade as signature failures.
fn load_signed_manifest(path: &Path) -> miette::Result<ImageManifest> {
    let text = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading signed image manifest {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        miette::miette!(
            "{} does not parse as a signed image manifest: {e} — pass the \
             .manifest.json published beside the mission image (ADR-0044 D5)",
            path.display()
        )
    })?;
    let unknown: Vec<&str> = value
        .as_object()
        .map(|map| {
            map.keys()
                .map(String::as_str)
                .filter(|k| !KNOWN_MANIFEST_FIELDS.contains(k))
                .collect()
        })
        .unwrap_or_default();
    if !unknown.is_empty() {
        return Err(miette::miette!(
            "manifest schema skew: field(s) {} are not part of this shuttle's \
             image-manifest schema (known fields: {}) — the manifest was written \
             by a newer or foreign shuttle; refusing before signature checks \
             (its fields would be silently dropped here and its canonical bytes \
             would not reproduce the signer's input)",
            unknown.join(", "),
            KNOWN_MANIFEST_FIELDS.join(", ")
        ));
    }
    serde_json::from_value(value).map_err(|e| {
        miette::miette!(
            "{} does not parse as a signed image manifest: {e} — pass the \
             .manifest.json published beside the mission image (ADR-0044 D5)",
            path.display()
        )
    })
}

/// Canonical signature input for the image manifest: serialized with the
/// signatures map emptied — byte-stable, and a signature never covers
/// itself. The exact scheme [`crate::sign::eval_manifest_canonical_bytes`]
/// applies to the eval manifest, applied to the image one. This — NOT the
/// eval scheme — is what `shuttle image --release` signs (#266) and what
/// this module verifies.
pub(crate) fn image_manifest_canonical_bytes(manifest: &ImageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = manifest.clone();
    clean.signatures.clear();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

/// The operator keychain home: `$HOME`, refusing to guess. #285's
/// fail-closed resolution, promoted to the central helper every keychain
/// consumer folds onto (#293 item 8): verify-image's trust anchors, the
/// release signer, the build's pubring/trust embeds, and the UC assertion
/// key. A CWD-relative fallback would silently anchor trust from
/// `./.config/shuttle/*` — exactly the self-bless #285 closed.
pub(crate) fn operator_home() -> miette::Result<PathBuf> {
    std::env::var("HOME").map(PathBuf::from).map_err(|_| {
        miette::miette!(
            "HOME is not set — refusing to guess where the operator keychain \
             lives (a CWD-relative fallback would silently anchor trust from \
             './.config/shuttle/keys'); set HOME or pass --key <public-key-file> \
             explicitly"
        )
    })
}

/// Verify the manifest's signature against an EXPLICIT keychain directory:
/// `extra_key` (when given) merges into the anchors, the ADR-0024 §4
/// device policy (revoked-first, then ANY-anchor) is the trust rule. This
/// is the seam the release self-check drives (#293 item 4: the release
/// proves the published set under the SAME keychain it signed with,
/// independent of process HOME; mirrors
/// [`crate::runtime::verify_signatures_at`]).
pub(crate) fn verify_manifest_signature_at(
    manifest: &ImageManifest,
    extra_key: Option<&Path>,
    keys_dir: &Path,
) -> miette::Result<String> {
    if manifest.signatures.is_empty() {
        return Err(miette::miette!(
            "manifest carries no signatures — refusing to verify an unsigned manifest \
             (a mission image publishes a SIGNED manifest; ADR-0044 D4)"
        ));
    }
    let mut chain = crate::sign::Keychain::load_dir(keys_dir)?;
    if let Some(key) = extra_key {
        chain.merge(
            crate::sign::Keychain::load_pub_file(key)
                .wrap_err_with(|| format!("loading trust anchor {}", key.display()))?,
        );
    }
    if chain.is_empty() {
        return Err(miette::miette!(
            "no trust anchors — pass --key <public-key-file> or install anchors under {} \
             (`shuttle key keygen` installs one); refusing to verify unsigned-by-anyone-\
             trusted input (fail closed)",
            keys_dir.display()
        ));
    }
    // ADR-0024 §4: a signature under a revoked key id is a hard refusal
    // before any anchor check.
    let revoked = crate::sign::read_revoked_keys(keys_dir)?;
    crate::sign::reject_revoked(&manifest.signatures, &revoked)?;
    let canonical = image_manifest_canonical_bytes(manifest)?;
    crate::sign::verify_keychain(&canonical, &manifest.signatures, &chain)
}

/// The dm-verity roothash every later step recomputes against. A
/// manifest without one describes a non-verity image — out of scope:
/// the mission-image chain is verity-protected by construction
/// (ADR-0011 step (c)).
fn required_roothash(manifest: &ImageManifest) -> miette::Result<String> {
    manifest.roothash.clone().ok_or_else(|| {
        miette::miette!(
            "manifest for '{} {}' carries no roothash — verify-image verifies \
             verity-protected mission images; there are no verity hash regions to \
             recompute on this device",
            manifest.name,
            manifest.version
        )
    })
}

// ── 2. The GPT + slot-A identity ──

/// One partition of the target's GPT, as `sfdisk -J` reports it. GUIDs
/// are normalized to lowercase at the source — the same udev-lowercase
/// discipline as [`parse_partition_extents`] (#92).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GptEntry {
    /// 1-based GPT partition number.
    pub(crate) partno: usize,
    /// GPT PARTLABEL (empty when unset).
    pub(crate) name: String,
    /// GPT PARTUUID, lowercase (empty when the table carries none).
    pub(crate) partuuid: String,
    /// GPT partition type GUID, lowercase.
    pub(crate) type_guid: String,
    pub(crate) start_bytes: u64,
    pub(crate) size_bytes: u64,
}

/// The parsed partition table: label plus entries in table order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GptTable {
    pub(crate) label: String,
    pub(crate) entries: Vec<GptEntry>,
}

/// Parse `sfdisk -J` JSON. Fail closed on any missing field — a guessed
/// geometry would verify the wrong bytes. The sector size's JSON key is
/// sfdisk's `sectorsize` (no hyphen); refusing when it is absent or
/// non-numeric is what keeps a 4K-sector device from being read as 512.
fn parse_gpt(json: &str) -> miette::Result<GptTable> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| miette::miette!("sfdisk -J printed unparseable JSON ({e})"))?;
    let table = value
        .get("partitiontable")
        .ok_or_else(|| miette::miette!("sfdisk -J output carries no 'partitiontable'"))?;
    let sector_size = table
        .get("sectorsize")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            miette::miette!(
                "sfdisk -J output carries no valid 'sectorsize' — refusing to guess \
                 the geometry (a guessed sector size would verify the wrong bytes)"
            )
        })?;
    let label = table
        .get("label")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    let partitions = table
        .get("partitions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            miette::miette!("sfdisk -J output carries no 'partitiontable.partitions' array")
        })?;
    let entries = partitions
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let sector = |key: &str| -> miette::Result<u64> {
                part.get(key)
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        miette::miette!(
                            "sfdisk -J partition {} carries no valid '{key}' sector field",
                            i + 1
                        )
                    })
            };
            let guid = |key: &str| -> String {
                part.get(key)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase()
            };
            // The sector→byte mapping multiplies attacker-controlled GPT
            // fields; a wrapped u64 would verify a SHRUNKEN extent as if
            // it were the real one. Checked arithmetic, refused by name —
            // the verity recompute would still refuse the bytes, but the
            // diagnostic must name the impossible table, not a hash
            // mismatch (#293 item 1).
            let bytes = |key: &str, sectors: u64| -> miette::Result<u64> {
                sectors.checked_mul(sector_size).ok_or_else(|| {
                    miette::miette!(
                        "sfdisk -J partition {} sector→byte mapping overflows: '{}' = \
                         {sectors} sectors × sectorsize {sector_size} exceeds u64 — the \
                         partition table maps an impossible extent (attacker-controlled \
                         GPT fields must not wrap into a smaller region); refusing",
                        i + 1,
                        key
                    )
                })
            };
            Ok(GptEntry {
                partno: i + 1,
                name: part
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                partuuid: guid("uuid"),
                type_guid: guid("type"),
                start_bytes: bytes("start", sector("start")?)?,
                size_bytes: bytes("size", sector("size")?)?,
            })
        })
        .collect::<miette::Result<Vec<_>>>()?;
    Ok(GptTable { label, entries })
}

/// Read the target's partition table with one read-only `sfdisk -J` call.
fn read_gpt(runner: &dyn crate::command::CommandRunner, device: &Path) -> miette::Result<GptTable> {
    let argv = vec![
        "sfdisk".to_string(),
        "-J".to_string(),
        device.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("sfdisk not runnable: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "cannot read a partition table from {} ({}): {} — refusing to verify a \
             medium with no readable GPT (wrong device, or the flash never landed?)",
            device.display(),
            crate::command::exit_code(&out),
            out.stderr.trim()
        ));
    }
    let table = parse_gpt(&String::from_utf8_lossy(&out.stdout))?;
    if table.label != "gpt" {
        return Err(miette::miette!(
            "device {} carries a '{}' partition table — mission images are GPT-only \
             (sysupdate slot matching and the UKI's by-partuuid boot both need it). A \
             medium that should carry a flashed image shows exactly this when the flash \
             was interrupted (the GPT is unreadable) or the device is the wrong one \
             entirely; verify the write completed, then re-run",
            device.display(),
            table.label
        ));
    }
    Ok(table)
}

/// The generation identity the device MUST carry, recomputed — never
/// stored — from the signed manifest: PARTUUIDs derived from the roothash
/// ([`generation_guids_from_roothash`]) and the PARTLABELs the build
/// stamps. A different image cannot reproduce any of it. The derived
/// pair identifies the GENERATION, not a physical slot: sysupdate pins
/// the same GUIDs onto whichever slot it fills.
#[derive(Debug, Clone)]
struct GenerationIdentity {
    root_partuuid: String,
    root_partlabel: String,
    hash_partuuid: String,
    hash_partlabel: String,
    /// ESP PARTUUID when the manifest resolved one at build time; the
    /// documented nil placeholder means "unresolvable" and is skipped.
    esp_partuuid: Option<String>,
}

fn expected_identity(
    manifest: &ImageManifest,
    roothash: &str,
) -> miette::Result<GenerationIdentity> {
    let (data_guid, hash_guid) = generation_guids_from_roothash(roothash)?;
    Ok(GenerationIdentity {
        root_partuuid: data_guid,
        root_partlabel: slot_partlabel(&manifest.name, &manifest.version, 0),
        hash_partuuid: hash_guid,
        hash_partlabel: hash_partlabel(&manifest.name, &manifest.version, 0),
        esp_partuuid: manifest
            .esp_partuuid
            .clone()
            .filter(|u| !u.is_empty() && u != NIL_PARTUUID),
    })
}

/// The type-typed partitions in table order — the build writes slot B
/// contiguous behind slot A (root-A, hash-A, root-B, hash-B) and
/// sysupdate overwrites slots in place, so this order IS slot order.
fn typed_partitions<'t>(table: &'t GptTable, type_guid: &str) -> Vec<&'t GptEntry> {
    table
        .entries
        .iter()
        .filter(|e| e.type_guid == type_guid)
        .collect()
}

/// List typed candidates as "#n ('label', uuid)" — the named-refusal
/// body for every mis-selection diagnostic.
fn candidate_list(typed: &[&GptEntry], indices: &[usize]) -> String {
    indices
        .iter()
        .map(|&i| {
            let e = typed[i];
            format!("#{} ('{}', {})", e.partno, e.name, e.partuuid)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Locate the partition carrying the manifest's derived PARTUUID among
/// the typed candidates, honoring the slot demand. The PARTUUID is the
/// fail-closed identity (the UKI boots by it): selection matches by
/// identity, NEVER first-match on the type GUID — a foreign generation
/// sitting earlier in the table must not shadow the manifest's (#286).
/// Returns the entry and its physical slot position (0 → a).
///
/// Refusals, each by name: no typed partition at all; none carrying the
/// derived identity (naming every candidate — the mis-selection
/// diagnostic); a DUPLICATED identity (a copied or rewritten table makes
/// by-partuuid resolution ambiguous — refuse, never pick); an explicit
/// `--slot a|b` demand the identity does not sit at (naming where it
/// actually sits).
fn select_by_identity<'t>(
    typed: &[&'t GptEntry],
    kind: &str,
    type_guid: &str,
    expected_partuuid: &str,
    selector: SlotSelector,
) -> miette::Result<(&'t GptEntry, usize)> {
    if typed.is_empty() {
        return Err(miette::miette!(
            "device carries no {kind} partition (type {type_guid}) — \
             refusing: wrong device, or not a flashed mission image"
        ));
    }
    let all: Vec<usize> = (0..typed.len()).collect();
    let matching: Vec<usize> = typed
        .iter()
        .enumerate()
        .filter(|(_, e)| e.partuuid == expected_partuuid)
        .map(|(i, _)| i)
        .collect();
    if matching.len() > 1 {
        return Err(miette::miette!(
            "duplicate {kind} PARTUUID {expected_partuuid} on partitions {} — \
             refusing (a PARTUUID must be unique: the UKI resolves the root by \
             it, and a duplicated identity makes the mapping ambiguous — the \
             table was copied or rewritten)",
            candidate_list(typed, &matching)
        ));
    }
    match selector.position() {
        None => matching
            .first()
            .copied()
            .map(|i| (typed[i], i))
            .ok_or_else(|| {
                miette::miette!(
                    "no {kind} partition carries the manifest's derived PARTUUID \
                     {expected_partuuid} — {kind} partitions present: {} — refusing \
                     (wrong device, or this manifest's generation was never installed \
                     on this medium; post-sysupdate devices verify against the \
                     manifest of the installed generation)",
                    candidate_list(typed, &all)
                )
            }),
        Some(position) => select_demanded_slot(typed, kind, expected_partuuid, &matching, position),
    }
}

/// The explicit `--slot a|b` arm of [`select_by_identity`]: the typed
/// partition AT the demanded position must carry the derived identity.
fn select_demanded_slot<'t>(
    typed: &[&'t GptEntry],
    kind: &str,
    expected_partuuid: &str,
    matching: &[usize],
    position: usize,
) -> miette::Result<(&'t GptEntry, usize)> {
    let letter = SlotSelector::letter(position);
    let Some(&entry) = typed.get(position) else {
        return Err(miette::miette!(
            "--slot {letter}: the device carries no slot-{letter} {kind} partition \
             ({} typed partition(s) present) — refusing",
            typed.len()
        ));
    };
    if entry.partuuid != expected_partuuid {
        let sits = match matching.first() {
            Some(&i) => format!(
                ", and the generation sits in slot {} (partition #{})",
                SlotSelector::letter(i),
                typed[i].partno
            ),
            None => ", and no typed partition carries the generation at all".to_string(),
        };
        return Err(miette::miette!(
            "--slot {letter}: the manifest's {kind} generation (PARTUUID \
             {expected_partuuid}) is not the slot-{letter} {kind} partition — slot \
             {letter} carries #{} ('{}', {}){sits} — refusing (the demanded slot \
             does not carry this image)",
            entry.partno,
            entry.name,
            entry.partuuid
        ));
    }
    Ok((entry, position))
}

/// Pin the generation's root and hash regions: identity-selected (never
/// first-match), demanded-slot-checked, and cross-checked to sit in the
/// SAME slot — a root in one slot whose hash sits in the other is a
/// frankenstein table no UKI could boot. The PARTLABEL is build-time
/// fail-open metadata (a degraded sfdisk skips the stamp), so a label
/// mismatch warns instead of refusing — mirroring the build's own
/// postures ([`set_partition_uuid`] vs [`apply_gpt_slot_metadata`]).
fn resolve_generation_regions<'t>(
    table: &'t GptTable,
    identity: &GenerationIdentity,
    selector: SlotSelector,
) -> miette::Result<(&'t GptEntry, &'t GptEntry, usize)> {
    let root_type = ROOT_TYPE_GUID_X86_64.to_ascii_lowercase();
    let roots = typed_partitions(table, &root_type);
    let (root, root_position) = select_by_identity(
        &roots,
        "root slot",
        ROOT_TYPE_GUID_X86_64,
        &identity.root_partuuid,
        selector,
    )?;
    if root.name != identity.root_partlabel {
        eprintln!(
            "  ⚠ root slot PARTLABEL is '{}' but the manifest derives '{}' — the build \
             stamps labels fail-open (a degraded sfdisk skips them); identity rests on \
             the PARTUUID, which matched",
            root.name, identity.root_partlabel
        );
    }
    let hash_type = VERITY_TYPE_GUID_X86_64.to_ascii_lowercase();
    let hashes = typed_partitions(table, &hash_type);
    let (hash, hash_position) = select_by_identity(
        &hashes,
        "verity hash",
        VERITY_TYPE_GUID_X86_64,
        &identity.hash_partuuid,
        selector,
    )?;
    if hash_position != root_position {
        return Err(miette::miette!(
            "root and hash generations sit in different slots: root (PARTUUID {}) is \
             slot {} but the hash (PARTUUID {}) is slot {} — refusing (a root whose \
             hash lives in the other slot is a rewritten or corrupted table)",
            identity.root_partuuid,
            SlotSelector::letter(root_position),
            identity.hash_partuuid,
            SlotSelector::letter(hash_position)
        ));
    }
    if hash.name != identity.hash_partlabel {
        eprintln!(
            "  ⚠ hash partition PARTLABEL is '{}' but the manifest derives '{}' — \
             build-time fail-open metadata; identity rests on the PARTUUID, which \
             matched",
            hash.name, identity.hash_partlabel
        );
    }
    Ok((root, hash, root_position))
}

/// Pin the ESP identity when the manifest resolved it at build time: the
/// recorded PARTUUID must still sit on an ESP-typed partition. Skipped
/// for the documented nil placeholder (an unresolvable build-time capture
/// must not demand a partition with the nil GUID).
fn check_esp_identity(table: &GptTable, identity: &GenerationIdentity) -> miette::Result<()> {
    let Some(esp_uuid) = &identity.esp_partuuid else {
        return Ok(());
    };
    let esp_type = ESP_TYPE_GUID.to_ascii_lowercase();
    let matches = table
        .entries
        .iter()
        .any(|e| e.type_guid == esp_type && e.partuuid == *esp_uuid);
    if matches {
        Ok(())
    } else {
        Err(miette::miette!(
            "ESP PARTUUID mismatch: manifest records {esp_uuid} but no ESP-typed \
             partition carries it — refusing (the medium does not match the image the \
             manifest signed)"
        ))
    }
}

// ── 3. Truncation ──

/// The medium's size in bytes: `st_size` for regular files, a read-only
/// lseek to the end for everything else — a block device's inode reports
/// `st_size` 0, so trusting metadata alone would refuse every real
/// `/dev` target as "truncated" (#288). `Ok(None)` is its own outcome:
/// the size source ANSWERED but reported nothing usable (a non-regular
/// file whose seek-to-end lands at 0 — a character device, say) — a
/// distinct diagnostic class from a truncated medium (#293 item 3), so
/// an undeterminable size never masquerades as an interrupted flash.
fn medium_len(device: &Path) -> miette::Result<Option<u64>> {
    let meta = std::fs::metadata(device)
        .into_diagnostic()
        .wrap_err_with(|| format!("stating {}", device.display()))?;
    if meta.is_file() {
        return Ok(Some(meta.len()));
    }
    let mut f = std::fs::File::open(device)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {} read-only", device.display()))?;
    let end = f
        .seek(std::io::SeekFrom::End(0))
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "cannot determine the size of {} (seek to end failed)",
                device.display()
            )
        })?;
    if end == 0 {
        Ok(None)
    } else {
        Ok(Some(end))
    }
}

/// Any partition extending past the end of the medium is an interrupted
/// flash — refuse by name before any recompute. A medium whose size
/// cannot be determined at all refuses under its own name: this is NOT
/// "truncated", it is "unknown", and the two demand different operator
/// responses (re-flash vs check what kind of node the target is).
fn check_truncation(device: &Path, table: &GptTable) -> miette::Result<()> {
    let Some(len) = medium_len(device)? else {
        return Err(miette::miette!(
            "cannot determine the size of {} — the size source answered 0 bytes \
             for a non-regular file, so no extent can be bounds-checked; refusing \
             to verify a medium of unknown size (this is a size-detection \
             refusal, not a truncation: pass the block device or image file, \
             not a special node)",
            device.display()
        ));
    };
    for e in &table.entries {
        let end = e
            .start_bytes
            .checked_add(e.size_bytes)
            .ok_or_else(|| miette::miette!("partition {} extent overflows", e.partno))?;
        if end > len {
            return Err(miette::miette!(
                "truncated medium: {} is {len} bytes but partition '{}' (#{}) extends to \
                 {end} bytes — the flash was interrupted; write the image again",
                device.display(),
                e.name,
                e.partno
            ));
        }
    }
    Ok(())
}

// ── 4. Verity recompute ──

/// Read one partition's bytes out of the medium into a scratch file —
/// plain reads; the device is never opened for writing. The scratch copy
/// is what `veritysetup verify` consumes, the same standalone-file shape
/// the unprivileged build formats ([`verity_format`]).
fn extract_region(device: &Path, entry: &GptEntry, scratch_dir: &Path) -> miette::Result<PathBuf> {
    let mut src = std::fs::File::open(device)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {} read-only", device.display()))?;
    src.seek(std::io::SeekFrom::Start(entry.start_bytes))
        .into_diagnostic()
        .wrap_err_with(|| format!("seeking {} to partition {}", device.display(), entry.partno))?;
    let path = scratch_dir.join(format!("partition-{}", entry.partno));
    let mut dst = std::fs::File::create(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating scratch {}", path.display()))?;
    let copied = std::io::copy(&mut src.take(entry.size_bytes), &mut dst)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "reading partition {} out of {}",
                entry.partno,
                device.display()
            )
        })?;
    if copied != entry.size_bytes {
        return Err(miette::miette!(
            "partition '{}' (#{}): read {} of {} bytes before {} ended — truncated medium",
            entry.name,
            entry.partno,
            copied,
            entry.size_bytes,
            device.display()
        ));
    }
    Ok(path)
}

/// The `veritysetup verify` argv over extracted region files and the
/// manifest roothash. Pure so the argv is unit-testable without a runner.
fn verity_verify_args(data: &Path, hash: &Path, roothash: &str) -> Vec<String> {
    vec![
        "verify".to_string(),
        data.to_string_lossy().into_owned(),
        hash.to_string_lossy().into_owned(),
        roothash.to_string(),
    ]
}

/// Recompute the verity hash regions: extract the root and hash
/// partitions to scratch, then `veritysetup verify` them against the
/// manifest roothash — the userspace half of what the UKI cmdline's
/// dm-verity mapping demands at boot (read-only, unprivileged). The tool
/// is injected; the public entry resolves it from the host PATH.
fn run_verity_verify_with(
    runner: &dyn crate::command::CommandRunner,
    device: &Path,
    root: &GptEntry,
    hash: &GptEntry,
    roothash: &str,
    veritysetup: Option<&Path>,
) -> miette::Result<()> {
    let Some(tool) = veritysetup else {
        return Err(miette::miette!(
            "veritysetup not found on PATH — recomputing the dm-verity hash regions \
             needs it. Run 'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; \
             e.g. apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    };
    let scratch =
        tempfile::tempdir().map_err(|e| miette::miette!("failed to create scratch dir: {e}"))?;
    let data_file = extract_region(device, root, scratch.path())?;
    let hash_file = extract_region(device, hash, scratch.path())?;
    let mut argv = vec![tool.to_string_lossy().into_owned()];
    argv.extend(verity_verify_args(&data_file, &hash_file, roothash));
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("failed to run veritysetup: {e}"))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "dm-verity verification FAILED in slot A: root partition '{}' ({}) over \
             hash partition '{}' ({}) does not recompute to the signed manifest \
             roothash {} — the flashed medium is corrupt or was written from a \
             different image (flip a byte anywhere in either partition and this fires). \
             veritysetup says: {}",
            root.name,
            root.partuuid,
            hash.name,
            hash.partuuid,
            roothash,
            out.stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RunnerOutput;

    const ROOTHASH: &str = "1111111122222222333333334444444455555555666666667777777788888888";

    /// A fake but plausible tool path the hermetic tests inject; the
    /// runner only ever sees it echoed in argv.
    const FAKE_VERITYSETUP: &str = "/usr/bin/veritysetup";

    /// A runner that must never be reached (guards the fail-closed paths).
    struct NoTools;

    impl crate::command::CommandRunner for NoTools {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            panic!("no tool should run on this path: {argv:?}");
        }
    }

    /// The crate-wide test-env lock: every `verify_device_with` test
    /// resolves HOME through [`operator_home`], and the
    /// unset-HOME test below mutates that process-global — hold the lock
    /// for the whole body so parallel tests never read a half-removed
    /// HOME (the `test_env` discipline, issue #149).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The canonical test keypair (deterministic seed).
    fn test_kp(seed_byte: u8) -> crate::sign::KeyPair {
        let seed = [seed_byte; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        crate::sign::KeyPair {
            seed,
            public: sk.verifying_key().to_bytes(),
        }
    }

    fn manifest(roothash: Option<&str>, esp: Option<&str>) -> ImageManifest {
        ImageManifest {
            name: "nau-demo".into(),
            version: "1.0.0".into(),
            arch: "amd64".into(),
            snaps: vec![],
            kernel_version: None,
            cmdline: None,
            uki: None,
            esp_partuuid: esp.map(|s| s.into()),
            roothash: roothash.map(|s| s.into()),
            signatures: Default::default(),
        }
    }

    /// Sign `m` under `kp` and return it with the signature attached.
    fn signed(mut m: ImageManifest, kp: &crate::sign::KeyPair) -> ImageManifest {
        let canonical = image_manifest_canonical_bytes(&m).unwrap();
        m.signatures.insert(
            kp.key_id(),
            serde_json::Value::String(crate::sign::sign_bytes(&canonical, kp)),
        );
        m
    }

    /// GUIDs the manifest's roothash derives, as sfdisk would report the
    /// build's table (upper-case, to exercise the lowercase normalization).
    fn expected_guids() -> (String, String) {
        let (data, hash) = generation_guids_from_roothash(ROOTHASH).unwrap();
        (data.to_uppercase(), hash.to_uppercase())
    }

    /// sfdisk -J body carrying the FULL slot-A identity: ESP + root +
    /// hash, with the root/hash GUIDs derived from the manifest roothash
    /// and the PARTLABELs the build stamps. `esp_uuid` is the ESP PARTUUID
    /// reported by the fixture table.
    fn golden_gpt_json(esp_uuid: &str) -> String {
        let (data_up, hash_up) = expected_guids();
        format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "{esp_uuid}", "name": "ESP"}},
                {{"start": 4096, "size": 4096, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "{}"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "{}"}}
            ]}}}}"#,
            slot_partlabel("nau-demo", "1.0.0", 0),
            hash_partlabel("nau-demo", "1.0.0", 0),
        )
    }

    /// A table with a root partition whose identity is FOREIGN (a
    /// different image): root type present, PARTUUID not derivable.
    fn foreign_gpt_json() -> String {
        let (_, hash_up) = expected_guids();
        format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "AABBCCDD-0011-2233-4455-667788990011", "name": "ESP"}},
                {{"start": 4096, "size": 4096, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "00000000-1111-2222-3333-444444444444", "name": "other_2.0.0_a"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "{}"}}
            ]}}}}"#,
            hash_partlabel("nau-demo", "1.0.0", 0),
        )
    }

    /// A GPT with only a swap partition — no root slot at all.
    fn rootless_gpt_json() -> String {
        r#"{"partitiontable": {"label": "gpt", "sectorsize": 512, "partitions": [
                {"start": 2048, "size": 2048, "type": "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "uuid": "AABB-CCDD", "name": "swap"}
            ]}}"#
            .to_string()
    }

    /// A POST-SYSUPDATE table (#286): slot A still carries the OLD
    /// (foreign) generation; slot B — contiguous behind it, the sysupdate
    /// relabel shape (the `_a` pattern arm, version-substituted) — carries
    /// the manifest's derived identity. Geometry (512-byte sectors):
    /// ESP 1 MiB (1 MiB), root-A 2 MiB (1 MiB), root-B 3 MiB (1 MiB),
    /// hash-A 4 MiB (128 KiB), hash-B 4.25 MiB (128 KiB).
    fn two_slot_gpt_json() -> String {
        let (data_up, hash_up) = expected_guids();
        format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "AABBCCDD-0011-2233-4455-667788990011", "name": "ESP"}},
                {{"start": 4096, "size": 2048, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "00000000-1111-2222-3333-444444444444", "name": "nau-demo_0.9.0_a"}},
                {{"start": 6144, "size": 2048, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "{}"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "99999999-8888-7777-6666-555555555555", "name": "nau-demo_0.9.0_hash_a"}},
                {{"start": 8704, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "{}"}}
            ]}}}}"#,
            slot_partlabel("nau-demo", "1.0.0", 0),
            hash_partlabel("nau-demo", "1.0.0", 0),
        )
    }

    /// A DOS-labeled table — mission images are GPT-only.
    fn dos_gpt_json() -> String {
        r#"{"partitiontable": {"label": "dos", "sectorsize": 512, "partitions": []}}"#.to_string()
    }

    /// A runner answering `sfdisk -J` with `body` and `veritysetup` with
    /// `verity_code` (recording every argv).
    struct FakeTools {
        sfdisk_body: String,
        verity_code: i32,
        calls: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl FakeTools {
        fn new(sfdisk_body: String, verity_code: i32) -> FakeTools {
            FakeTools {
                sfdisk_body,
                verity_code,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::command::CommandRunner for FakeTools {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let (code, stderr) = if argv.first().is_some_and(|t| t.ends_with("veritysetup")) {
                (self.verity_code, "hash mismatch".to_string())
            } else {
                (0, String::new())
            };
            Ok(RunnerOutput {
                code,
                stdout: self.sfdisk_body.clone().into_bytes(),
                stderr,
            })
        }
    }

    /// A sparse device file with `len` bytes — big enough for every
    /// extent the fixtures stamp (512-byte-sector geometry).
    fn device_file_sized(dir: &Path, len: u64) -> PathBuf {
        let path = dir.join("device.img");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(len).unwrap();
        drop(f);
        path
    }

    /// A sparse device file with all three extents: ESP at 1 MiB (1 MiB),
    /// root at 2 MiB (2 MiB), hash at 4 MiB (128 KiB) — matching the
    /// fixture's sfdisk geometry (512-byte sectors).
    fn device_file(dir: &Path) -> PathBuf {
        device_file_sized(dir, 5 * 1024 * 1024)
    }

    fn args(device: &Path, manifest: &Path, key: Option<&Path>) -> VerifyImageArgs {
        args_with_slot(device, manifest, key, SlotSelector::Auto)
    }

    fn args_with_slot(
        device: &Path,
        manifest: &Path,
        key: Option<&Path>,
        slot: SlotSelector,
    ) -> VerifyImageArgs {
        VerifyImageArgs {
            device: device.to_path_buf(),
            manifest: manifest.to_path_buf(),
            key: key.map(|k| k.to_path_buf()),
            slot,
        }
    }

    /// Signed manifest + trust anchor written into `dir` — the shared
    /// setup of the slot-selection family.
    fn signed_manifest_and_anchor(dir: &Path) -> (PathBuf, PathBuf) {
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.join("m.manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&m).unwrap()).unwrap();
        let anchor = dir.join("anchor.pub");
        std::fs::write(&anchor, crate::sign::public_key_file(&kp)).unwrap();
        (manifest_path, anchor)
    }

    // ── Golden manifest passes ──

    #[test]
    fn golden_manifest_verifies_and_records_the_key_id() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(
            manifest(Some(ROOTHASH), Some("aabbccdd-0011-2233-4455-667788990011")),
            &kp,
        );
        let manifest_path = dir.path().join("m.manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&m).unwrap()).unwrap();

        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 0);
        let outcome = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .expect("golden manifest verifies");
        assert_eq!(outcome.verified_key_id, kp.key_id());
        assert_eq!(outcome.roothash, ROOTHASH);
        assert_eq!(
            outcome.root_partuuid,
            generation_guids_from_roothash(ROOTHASH).unwrap().0
        );
        assert_eq!(outcome.image_name, "nau-demo");
        assert_eq!(outcome.slot, "a", "auto reports the slot it found");

        // The verity step consumed the extracted regions and the signed roothash.
        let verity = runner
            .calls()
            .into_iter()
            .find(|c| c.first().is_some_and(|t| t.ends_with("veritysetup")))
            .expect("veritysetup was invoked");
        assert_eq!(&verity[1], "verify");
        assert_eq!(&verity[4], ROOTHASH, "recompute pins the SIGNED roothash");
    }

    // ── Signature refusals ──

    #[test]
    fn unsigned_manifest_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let m = manifest(Some(ROOTHASH), None);
        let manifest_path = dir.path().join("unsigned.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let err = verify_manifest_signature_at(&m, None, &keys)
            .unwrap_err()
            .to_string();
        assert!(err.contains("carries no signatures"), "{err}");
    }

    #[test]
    fn tampered_manifest_body_refuses_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        let kp = test_kp(7);
        let mut m = signed(manifest(Some(ROOTHASH), None), &kp);
        // Tamper AFTER signing: the version in the body no longer matches.
        m.version = "9.9.9".into();
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        crate::sign::install_public_key(&kp, &keys).unwrap();
        let err = verify_manifest_signature_at(&m, None, &keys)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no trusted signature verifies"),
            "tampered body must refuse by name: {err}"
        );
    }

    #[test]
    fn unknown_signer_refuses_under_an_empty_anchor_set() {
        let dir = tempfile::tempdir().unwrap();
        let m = signed(manifest(Some(ROOTHASH), None), &test_kp(7));
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let err = verify_manifest_signature_at(&m, None, &keys)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no trust anchors"), "{err}");
    }

    #[test]
    fn explicit_key_anchor_verifies_without_a_keychain() {
        let dir = tempfile::tempdir().unwrap();
        let kp = test_kp(9);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let keys = dir.path().join("keys"); // exists but empty
        std::fs::create_dir_all(&keys).unwrap();
        let key_file = dir.path().join("downloaded.pub");
        std::fs::write(&key_file, crate::sign::public_key_file(&kp)).unwrap();
        let key_id = verify_manifest_signature_at(&m, Some(&key_file), &keys).unwrap();
        assert_eq!(key_id, kp.key_id(), "--key anchors the downloaded trust");
    }

    #[test]
    fn unset_home_refuses_instead_of_falling_back_to_cwd_anchors() {
        // A CWD-relative `./.config/shuttle/keys` would silently join the
        // anchor set; the central resolution ([`operator_home`], #285,
        // #293 item 8) must refuse by name instead. Mutating the
        // process-global HOME is why every verify test here holds
        // [`env_lock`].
        let _lock = env_lock();
        let old = std::env::var("HOME").ok();
        std::env::remove_var("HOME");
        // Resolve BEFORE restoring so a refusal-shape mismatch can never
        // leak the removal past this test.
        let result = operator_home();
        match old {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
        let err = result.unwrap_err().to_string();
        assert!(err.contains("HOME is not set"), "{err}");
    }

    #[test]
    fn revoked_signer_refuses_before_the_anchor_check() {
        let dir = tempfile::tempdir().unwrap();
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        crate::sign::install_public_key(&kp, &keys).unwrap();
        std::fs::write(keys.join("revoked-keys"), format!("{}\n", kp.key_id())).unwrap();
        let err = verify_manifest_signature_at(&m, None, &keys)
            .unwrap_err()
            .to_string();
        assert!(err.contains("REVOKED"), "{err}");
    }

    #[test]
    fn newer_schema_manifest_refuses_naming_the_skew_before_signature_checks() {
        // L-batch item 9: a newer shuttle's manifest carries a field this
        // schema doesn't know. Without the skew check it would parse with
        // the field dropped and die as a generic "no trusted signature";
        // it must refuse as SCHEMA SKEW instead — and before any tool so
        // the run never touches the device (NoTools enforces that).
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let mut v: serde_json::Value = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("future_field".to_string(), serde_json::json!(1));
        let manifest_path = dir.path().join("newer.manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let err = verify_device_with(
            &NoTools,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("schema skew") && err.contains("future_field"),
            "{err}"
        );
        assert!(
            !err.contains("no trusted signature"),
            "the skew must not masquerade as a signature failure: {err}"
        );
    }

    #[test]
    fn legacy_manifest_shape_still_verifies() {
        // The skew check must keep OLD manifests working: exactly the
        // build's emitted field set (optional fields absent) parses and
        // verifies end to end.
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("legacy.manifest.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 0);
        verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .expect("the legacy field set is a schema subset — no skew refusal");
    }

    // ── GPT identity refusals ──

    #[test]
    fn non_gpt_table_is_refused_by_name() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(dos_gpt_json(), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("'dos' partition table"), "{err}");
    }

    #[test]
    fn wrong_device_refuses_on_the_root_partuuid() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        // A different image's table: root type present, identity foreign —
        // the refusal must name the candidates it saw, not guess.
        let runner = FakeTools::new(foreign_gpt_json(), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no root slot partition carries the manifest's derived PARTUUID")
                && err.contains("00000000-1111-2222-3333-444444444444"),
            "{err}"
        );
    }

    #[test]
    fn medium_without_a_root_slot_refuses_by_name() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(rootless_gpt_json(), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no root slot partition"), "{err}");
    }

    #[test]
    fn esp_partuuid_mismatch_refuses_by_name() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(
            manifest(Some(ROOTHASH), Some("11111111-1111-1111-1111-111111111111")),
            &kp,
        );
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(
            golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), // ≠ the manifest's ESP
            0,
        );
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("ESP PARTUUID mismatch"), "{err}");
    }

    #[test]
    fn nil_esp_partuuid_skips_the_esp_check() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), Some(NIL_PARTUUID)), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 0);
        verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .expect("nil placeholder does not demand a nil-GUID partition");
    }

    #[test]
    fn foreign_partlabels_warn_but_partuuid_identity_holds() {
        let _lock = env_lock();
        // Build-time fail-open metadata: a degraded sfdisk skipped the
        // PARTLABEL stamp — the verify must warn, not refuse.
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let (data_up, hash_up) = expected_guids();
        let body = format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 4096, "size": 4096, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "_empty"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "_empty"}}
            ]}}}}"#
        );
        let runner = FakeTools::new(body, 0);
        assert!(
            verify_device_with(
                &runner,
                &args(&device, &manifest_path, Some(&key_anchor)),
                Some(Path::new(FAKE_VERITYSETUP)),
            )
            .is_ok(),
            "partuuid is the fail-closed identity; the label only warns"
        );
    }

    // ── Slot selection (#286 + L-batch item 2) ──

    #[test]
    fn post_sysupdate_auto_verifies_the_new_generation_in_slot_b() {
        // #286's core acceptance: sysupdate filled slot B (contiguous
        // behind the foreign old slot A). The first-match rule would grab
        // slot A and die on its foreign PARTUUID; identity selection must
        // find the manifest's generation wherever it sits.
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file_sized(dir.path(), 8 * 1024 * 1024);
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        let runner = FakeTools::new(two_slot_gpt_json(), 0);
        let outcome = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .expect("auto locates the sysupdate-filled generation");
        assert_eq!(outcome.slot, "b", "the generation sits in slot B");
        assert_eq!(
            outcome.root_partuuid,
            generation_guids_from_roothash(ROOTHASH).unwrap().0
        );
        // The recompute consumed slot B's regions (partitions #3 and #5).
        let verity = runner
            .calls()
            .into_iter()
            .find(|c| c.first().is_some_and(|t| t.ends_with("veritysetup")))
            .expect("veritysetup was invoked");
        assert!(verity[2].ends_with("partition-3"), "{verity:?}");
        assert!(verity[3].ends_with("partition-5"), "{verity:?}");
    }

    #[test]
    fn explicit_slot_b_pins_the_demand_and_verifies() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file_sized(dir.path(), 8 * 1024 * 1024);
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        let runner = FakeTools::new(two_slot_gpt_json(), 0);
        let outcome = verify_device_with(
            &runner,
            &args_with_slot(&device, &manifest_path, Some(&key_anchor), SlotSelector::B),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .expect("the demanded slot carries the generation");
        assert_eq!(outcome.slot, "b");
    }

    #[test]
    fn explicit_slot_a_refuses_when_the_generation_sits_in_slot_b() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file_sized(dir.path(), 8 * 1024 * 1024);
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        let runner = FakeTools::new(two_slot_gpt_json(), 0);
        let err = verify_device_with(
            &runner,
            &args_with_slot(&device, &manifest_path, Some(&key_anchor), SlotSelector::A),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--slot a") && err.contains("the generation sits in slot b"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_generation_partuuids_refuse_instead_of_first_match() {
        // Both root slots carry the derived PARTUUID — a dd-copied or
        // rewritten table. The UKI resolves the root by PARTUUID, so a
        // duplicate makes the mapping ambiguous: refuse, never pick.
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        let (data_up, hash_up) = expected_guids();
        let body = format!(
            r#"{{"partitiontable": {{"label": "gpt", "sectorsize": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "AABBCCDD-0011-2233-4455-667788990011", "name": "ESP"}},
                {{"start": 4096, "size": 2048, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "{}"}},
                {{"start": 6144, "size": 2048, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "{data_up}", "name": "{}"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "{}"}}
            ]}}}}"#,
            slot_partlabel("nau-demo", "1.0.0", 0),
            slot_partlabel("nau-demo", "1.0.0", 0),
            hash_partlabel("nau-demo", "1.0.0", 0),
        );
        let runner = FakeTools::new(body, 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("duplicate root slot PARTUUID")
                && err.contains("#2")
                && err.contains("#3"),
            "{err}"
        );
    }

    #[test]
    fn explicit_slot_b_without_a_second_slot_refuses_by_name() {
        // The factory disk carries ONE root slot; demanding slot B must
        // refuse naming the shortage, not fall back to slot A.
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let (manifest_path, key_anchor) = signed_manifest_and_anchor(dir.path());
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 0);
        let err = verify_device_with(
            &runner,
            &args_with_slot(&device, &manifest_path, Some(&key_anchor), SlotSelector::B),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("--slot b") && err.contains("no slot-b root slot partition"),
            "{err}"
        );
    }

    // ── Truncation ──

    #[test]
    fn truncated_medium_refuses_by_name() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        // Shrink the medium under the hash partition's extent.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&device)
            .unwrap();
        f.set_len(4 * 1024 * 1024 + 64 * 1024).unwrap();
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("truncated medium"), "{err}");
    }

    #[test]
    fn undetermined_medium_size_refuses_distinctly_from_truncation() {
        // L-batch item 3: a size source that ANSWERS 0 for a non-regular
        // node is "cannot determine", never "truncated" — the two demand
        // different operator responses. /dev/null is the canonical
        // seek-to-end-0 non-regular node on Linux.
        let table = parse_gpt(&golden_gpt_json("aabbccdd-0011-2233-4455-667788990011")).unwrap();
        let err = check_truncation(Path::new("/dev/null"), &table)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot determine the size") && !err.contains("truncated medium"),
            "{err}"
        );
        // A REGULAR 0-byte file is genuinely truncated: its extents
        // extend past the end.
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.img");
        std::fs::write(&empty, b"").unwrap();
        let err = check_truncation(&empty, &table).unwrap_err().to_string();
        assert!(
            err.contains("truncated medium") && !err.contains("cannot determine"),
            "{err}"
        );
    }

    // ── Verity recompute ──

    #[test]
    fn flipped_byte_refuses_naming_the_slot_a_regions() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        // veritysetup reports the mismatch (a flipped byte inside slot A).
        let runner = FakeTools::new(golden_gpt_json("aabbccdd-0011-2233-4455-667788990011"), 1);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("dm-verity verification FAILED in slot A"),
            "{err}"
        );
        assert!(
            err.contains(ROOTHASH),
            "the signed roothash is named: {err}"
        );
    }

    #[test]
    fn missing_veritysetup_fails_closed_with_the_doctor_hint() {
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let root = GptEntry {
            partno: 2,
            name: "nau-demo_1.0.0_a".into(),
            partuuid: expected_guids().0.to_lowercase(),
            type_guid: ROOT_TYPE_GUID_X86_64.into(),
            start_bytes: 2 * 1024 * 1024,
            size_bytes: 2 * 1024 * 1024,
        };
        let hash = GptEntry {
            partno: 3,
            name: "nau-demo_1.0.0_hash_a".into(),
            partuuid: expected_guids().1.to_lowercase(),
            type_guid: VERITY_TYPE_GUID_X86_64.into(),
            start_bytes: 4 * 1024 * 1024,
            size_bytes: 128 * 1024,
        };
        let err = run_verity_verify_with(&NoTools, &device, &root, &hash, ROOTHASH, None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("veritysetup not found on PATH") && err.contains("shuttle doctor"),
            "{err}"
        );
    }

    #[test]
    fn manifest_without_roothash_refuses_by_name() {
        let _lock = env_lock();
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(None, None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        let runner = FakeTools::new(String::new(), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("carries no roothash"), "{err}");
    }

    // ── Pure pieces ──

    #[test]
    fn gpt_parser_normalizes_guids_and_maps_sectors() {
        let table = parse_gpt(&golden_gpt_json("AABBCCDD-0011-2233-4455-667788990011")).unwrap();
        assert_eq!(table.label, "gpt");
        assert_eq!(table.entries.len(), 3);
        let esp = &table.entries[0];
        assert_eq!(esp.partno, 1);
        assert_eq!(
            esp.partuuid, "aabbccdd-0011-2233-4455-667788990011",
            "PARTUUIDs normalize to udev's lowercase (#92)"
        );
        assert_eq!(esp.type_guid, ESP_TYPE_GUID, "type GUIDs normalize too");
        assert_eq!(esp.start_bytes, 2048 * 512);
        assert_eq!(esp.size_bytes, 2048 * 512);
    }

    #[test]
    fn gpt_parser_fails_closed_on_missing_sectors() {
        let err = parse_gpt(
            r#"{"partitiontable": {"label": "gpt", "sectorsize": 512, "partitions": [
                {"size": 100, "type": "x", "uuid": "y"}
            ]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no valid 'start'"), "{err}");
    }

    #[test]
    fn wrapped_sector_mapping_refuses_by_name() {
        // L-batch item 1: start/size are attacker-controlled GPT fields;
        // a wrapped u64 multiply would verify a SHRUNKEN extent as if it
        // were the real one. Both directions refuse by name.
        let start_overflow = parse_gpt(
            r#"{"partitiontable": {"label": "gpt", "sectorsize": 512, "partitions": [
                {"start": 18446744073709551615, "size": 4, "type": "x", "uuid": "y"}
            ]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            start_overflow.contains("sector→byte mapping overflows")
                && start_overflow.contains("'start'"),
            "{start_overflow}"
        );
        let size_overflow = parse_gpt(
            r#"{"partitiontable": {"label": "gpt", "sectorsize": 512, "partitions": [
                {"start": 2048, "size": 18446744073709551615, "type": "x", "uuid": "y"}
            ]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            size_overflow.contains("sector→byte mapping overflows")
                && size_overflow.contains("'size'"),
            "{size_overflow}"
        );
    }

    #[test]
    fn gpt_parser_refuses_a_missing_sector_size() {
        // sfdisk omitting the field must NOT default to 512: on a
        // 4K-sector device that would guess the geometry.
        let err = parse_gpt(
            r#"{"partitiontable": {"label": "gpt", "partitions": [
                {"start": 2048, "size": 2048, "type": "x", "uuid": "y"}
            ]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("no valid 'sectorsize'") && err.contains("guess"),
            "{err}"
        );
    }

    #[test]
    fn verity_argv_carries_the_regions_then_the_roothash() {
        let argv = verity_verify_args(Path::new("/tmp/d"), Path::new("/tmp/h"), "ab");
        assert_eq!(argv, vec!["verify", "/tmp/d", "/tmp/h", "ab"]);
    }

    #[test]
    fn extract_region_copies_exact_bytes_and_refuses_short_devices() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("d.img");
        std::fs::write(&device, vec![0u8; 4096]).unwrap();
        // Stamp a recognizable pattern at offset 1024.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&device)
            .unwrap();
        use std::io::Write as _;
        f.seek(std::io::SeekFrom::Start(1024)).unwrap();
        f.write_all(b"REGION").unwrap();
        drop(f);
        let entry = GptEntry {
            partno: 2,
            name: "root".into(),
            partuuid: "x".into(),
            type_guid: "y".into(),
            start_bytes: 1024,
            size_bytes: 6,
        };
        let out = extract_region(&device, &entry, dir.path()).unwrap();
        assert_eq!(std::fs::read(out).unwrap(), b"REGION");

        let short = GptEntry {
            size_bytes: 4096,
            ..entry
        };
        let err = extract_region(&device, &short, dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("truncated medium"), "{err}");
    }

    #[test]
    fn canonical_bytes_clear_the_signatures_map() {
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let canonical = image_manifest_canonical_bytes(&m).unwrap();
        let text = String::from_utf8(canonical).unwrap();
        assert!(
            !text.contains("signatures"),
            "a signature never covers itself: {text}"
        );
        // And the untouched signed manifest round-trips to the same bytes.
        let reparsed: ImageManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(
            image_manifest_canonical_bytes(&reparsed).unwrap(),
            image_manifest_canonical_bytes(&m).unwrap(),
        );
    }

    #[test]
    fn empty_signatures_field_stays_out_of_the_serialized_manifest() {
        // Byte-comparable doctrine: the build path (which writes the
        // manifest with no signatures) must emit exactly the old bytes.
        let m = manifest(Some(ROOTHASH), None);
        let v = serde_json::to_value(&m).unwrap();
        assert!(v.get("signatures").is_none(), "{v}");
        // A signed one keeps the map, keyed by key id.
        let signer = test_kp(7);
        let m = signed(m, &signer);
        let v = serde_json::to_value(&m).unwrap();
        assert!(v["signatures"].get(signer.key_id()).is_some(), "{v}");
        // And it round-trips through Deserialize (the verify input shape).
        let back: ImageManifest = serde_json::from_value(v).unwrap();
        assert_eq!(back.signatures.len(), 1);
    }
}
