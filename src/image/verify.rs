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
//!    same read-back the build uses) and identify the slot-A regions by
//!    their GPT identity: the root/hash PARTUUIDs are DERIVED from the
//!    manifest roothash ([`generation_guids_from_roothash`]), so the
//!    expected identity is not stored anywhere — it is recomputed from
//!    the signed bytes. A device carrying a different image (wrong
//!    mission, wrong version, rewritten table) cannot reproduce them.
//! 3. Refuse a truncated medium: any partition extending past the end
//!    of the device is an interrupted flash.
//! 4. Recompute the verity hash regions: the root and hash partition
//!    bytes are read out to scratch files (plain reads; the device is
//!    never opened for writing) and `veritysetup verify` checks them
//!    against the manifest roothash — the userspace half of what the
//!    UKI's kernel cmdline demands at boot.
//!
//! Slot A only: the factory UKI boots slot A, the build stamps slot A's
//! GUIDs, and slot B is `_empty` until sysupdate fills it. Verifying a
//! slot the image never wrote would prove nothing.
//!
//! # Live axis (deferred)
//!
//! Flash-to-real-medium verification (loop/USB) is the live gate and is
//! exercised in the live phase; everything here runs against device
//! FILES, which is also what makes the unit surface deterministic.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use super::*;

/// Arguments of one `shuttle verify-image` invocation (gathered by the
/// CLI in [`crate::cli`]; the library entry takes the struct so tests
/// drive the same path the binary does).
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
    let manifest = load_signed_manifest(&args.manifest)?;
    let key_id = verify_manifest_signature(&manifest, args.key.as_deref())?;
    let roothash = required_roothash(&manifest)?;
    let table = read_gpt(runner, &args.device)?;
    let slot = expected_slot_a(&manifest, &roothash)?;
    let (root, hash) = resolve_slot_a_regions(&table, &slot, &manifest.name, &manifest.version)?;
    check_esp_identity(&table, &slot)?;
    check_truncation(&args.device, &table)?;
    run_verity_verify_with(runner, &args.device, root, hash, &roothash, veritysetup)?;
    Ok(VerifyOutcome {
        image_name: manifest.name,
        image_version: manifest.version,
        verified_key_id: key_id,
        roothash,
        root_partuuid: root.partuuid.clone(),
        hash_partuuid: hash.partuuid.clone(),
    })
}

// ── 1. Signed manifest ──

/// Load and parse the published signed image manifest. Anything that
/// does not parse is a named refusal — the file is the trust input.
fn load_signed_manifest(path: &Path) -> miette::Result<ImageManifest> {
    let text = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading signed image manifest {}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| {
        miette::miette!(
            "{} does not parse as a signed image manifest: {e} — pass the \
             .manifest.json published beside the mission image (ADR-0044 D5)",
            path.display()
        )
    })
}

/// Canonical signature input for the image manifest: serialized with the
/// signatures map emptied — byte-stable, and a signature never covers
/// itself. The exact scheme [`crate::sign::canonical_bytes`] applies to
/// the eval manifest, applied to the image one.
pub(crate) fn image_manifest_canonical_bytes(manifest: &ImageManifest) -> miette::Result<Vec<u8>> {
    let mut clean = manifest.clone();
    clean.signatures.clear();
    serde_json::to_vec(&clean).map_err(|e| miette::miette!("canonical serialization: {e}"))
}

/// Verify the manifest's signature under the operator trust anchors:
/// `--key` (when given) plus `~/.config/shuttle/keys/*.pub`. Unsigned
/// manifests refuse outright — verify-image checks the PUBLISHED signed
/// manifest, and the ADR-0024 §4 device policy (revoked-first, then
/// ANY-anchor) is the trust rule, not the rollout-friendly keychain
/// default.
pub fn verify_manifest_signature(
    manifest: &ImageManifest,
    extra_key: Option<&Path>,
) -> miette::Result<String> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    verify_manifest_signature_at(manifest, extra_key, &crate::sign::keys_dir(&home))
}

/// [`verify_manifest_signature`] against an explicit keychain directory —
/// the test seam (mirrors [`crate::runtime::verify_signatures_at`]).
fn verify_manifest_signature_at(
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
/// geometry would verify the wrong bytes.
fn parse_gpt(json: &str) -> miette::Result<GptTable> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| miette::miette!("sfdisk -J printed unparseable JSON ({e})"))?;
    let table = value
        .get("partitiontable")
        .ok_or_else(|| miette::miette!("sfdisk -J output carries no 'partitiontable'"))?;
    let sector_size = table
        .get("sector-size")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(512);
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
            Ok(GptEntry {
                partno: i + 1,
                name: part
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                partuuid: guid("uuid"),
                type_guid: guid("type"),
                start_bytes: sector("start")? * sector_size,
                size_bytes: sector("size")? * sector_size,
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

/// The slot-A identity the device MUST carry, recomputed — never stored —
/// from the signed manifest: PARTUUIDs derived from the roothash
/// ([`generation_guids_from_roothash`]) and the PARTLABELs the build
/// stamps. A different image cannot reproduce any of it.
#[derive(Debug, Clone)]
struct SlotAIdentity {
    root_partuuid: String,
    root_partlabel: String,
    hash_partuuid: String,
    hash_partlabel: String,
    /// ESP PARTUUID when the manifest resolved one at build time; the
    /// documented nil placeholder means "unresolvable" and is skipped.
    esp_partuuid: Option<String>,
}

fn expected_slot_a(manifest: &ImageManifest, roothash: &str) -> miette::Result<SlotAIdentity> {
    let (data_guid, hash_guid) = generation_guids_from_roothash(roothash)?;
    Ok(SlotAIdentity {
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

/// Locate the slot-A root partition in the table and pin its identity.
/// The PARTUUID is the fail-closed identity (the UKI boots by it); the
/// PARTLABEL is build-time fail-open metadata, so a label mismatch warns
/// instead of refusing — mirroring the build's own postures
/// ([`set_partition_uuid`] vs [`apply_gpt_slot_metadata`]).
fn resolve_root_region<'t>(
    table: &'t GptTable,
    slot: &SlotAIdentity,
    image_name: &str,
    image_version: &str,
) -> miette::Result<&'t GptEntry> {
    let root_type = ROOT_TYPE_GUID_X86_64.to_ascii_lowercase();
    let root = table
        .entries
        .iter()
        .find(|e| e.type_guid == root_type)
        .ok_or_else(|| {
            miette::miette!(
                "device carries no root slot partition (type {ROOT_TYPE_GUID_X86_64}) — \
             refusing: wrong device, or not a flashed mission image"
            )
        })?;
    if root.partuuid != slot.root_partuuid {
        return Err(miette::miette!(
            "root slot PARTUUID mismatch: manifest '{image_name} {image_version}' derives \
             {} but the device carries partition #{} ('{}', '{}') — refusing (wrong \
             device, or the partition table was rewritten after the flash)",
            slot.root_partuuid,
            root.partno,
            root.name,
            root.partuuid
        ));
    }
    if root.name != slot.root_partlabel {
        eprintln!(
            "  ⚠ root slot PARTLABEL is '{}' but the manifest derives '{}' — the build \
             stamps labels fail-open (a degraded sfdisk skips them); identity rests on \
             the PARTUUID, which matched",
            root.name, slot.root_partlabel
        );
    }
    Ok(root)
}

/// Locate the slot-A verity hash partition and pin its identity (same
/// rule as the root: PARTUUID fail-closed, PARTLABEL warn-only).
fn resolve_hash_region<'t>(
    table: &'t GptTable,
    slot: &SlotAIdentity,
    image_name: &str,
    image_version: &str,
) -> miette::Result<&'t GptEntry> {
    let hash_type = VERITY_TYPE_GUID_X86_64.to_ascii_lowercase();
    let hash = table
        .entries
        .iter()
        .find(|e| e.type_guid == hash_type)
        .ok_or_else(|| {
            miette::miette!(
                "device carries no verity hash partition (type \
                 {VERITY_TYPE_GUID_X86_64}) — there are no hash regions to recompute: \
                 refusing (wrong device, or not a flashed mission image)"
            )
        })?;
    if hash.partuuid != slot.hash_partuuid {
        return Err(miette::miette!(
            "hash partition PARTUUID mismatch: manifest '{image_name} {image_version}' \
             derives {} but the device carries partition #{} ('{}', '{}') — refusing \
             (wrong device, or the partition table was rewritten after the flash)",
            slot.hash_partuuid,
            hash.partno,
            hash.name,
            hash.partuuid
        ));
    }
    if hash.name != slot.hash_partlabel {
        eprintln!(
            "  ⚠ hash partition PARTLABEL is '{}' but the manifest derives '{}' — \
             build-time fail-open metadata; identity rests on the PARTUUID, which \
             matched",
            hash.name, slot.hash_partlabel
        );
    }
    Ok(hash)
}

fn resolve_slot_a_regions<'t>(
    table: &'t GptTable,
    slot: &SlotAIdentity,
    image_name: &str,
    image_version: &str,
) -> miette::Result<(&'t GptEntry, &'t GptEntry)> {
    let root = resolve_root_region(table, slot, image_name, image_version)?;
    let hash = resolve_hash_region(table, slot, image_name, image_version)?;
    Ok((root, hash))
}

/// Pin the ESP identity when the manifest resolved it at build time: the
/// recorded PARTUUID must still sit on an ESP-typed partition. Skipped
/// for the documented nil placeholder (an unresolvable build-time capture
/// must not demand a partition with the nil GUID).
fn check_esp_identity(table: &GptTable, slot: &SlotAIdentity) -> miette::Result<()> {
    let Some(esp_uuid) = &slot.esp_partuuid else {
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

/// Any partition extending past the end of the medium is an interrupted
/// flash — refuse by name before any recompute.
fn check_truncation(device: &Path, table: &GptTable) -> miette::Result<()> {
    let meta = std::fs::metadata(device)
        .into_diagnostic()
        .wrap_err_with(|| format!("stating {}", device.display()))?;
    let len = meta.len();
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
            r#"{{"partitiontable": {{"label": "gpt", "sector-size": 512, "partitions": [
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
            r#"{{"partitiontable": {{"label": "gpt", "sector-size": 512, "partitions": [
                {{"start": 2048, "size": 2048, "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "uuid": "AABBCCDD-0011-2233-4455-667788990011", "name": "ESP"}},
                {{"start": 4096, "size": 4096, "type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "uuid": "00000000-1111-2222-3333-444444444444", "name": "other_2.0.0_a"}},
                {{"start": 8192, "size": 256, "type": "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5", "uuid": "{hash_up}", "name": "{}"}}
            ]}}}}"#,
            hash_partlabel("nau-demo", "1.0.0", 0),
        )
    }

    /// A GPT with only a swap partition — no root slot at all.
    fn rootless_gpt_json() -> String {
        r#"{"partitiontable": {"label": "gpt", "sector-size": 512, "partitions": [
                {"start": 2048, "size": 2048, "type": "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "uuid": "AABB-CCDD", "name": "swap"}
            ]}}"#
            .to_string()
    }

    /// A DOS-labeled table — mission images are GPT-only.
    fn dos_gpt_json() -> String {
        r#"{"partitiontable": {"label": "dos", "sector-size": 512, "partitions": []}}"#.to_string()
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

    /// A sparse device file with all three extents: ESP at 1 MiB (1 MiB),
    /// root at 2 MiB (2 MiB), hash at 4 MiB (128 KiB) — matching the
    /// fixture's sfdisk geometry (512-byte sectors).
    fn device_file(dir: &Path) -> PathBuf {
        let path = dir.join("device.img");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(5 * 1024 * 1024).unwrap();
        drop(f);
        path
    }

    fn args(device: &Path, manifest: &Path, key: Option<&Path>) -> VerifyImageArgs {
        VerifyImageArgs {
            device: device.to_path_buf(),
            manifest: manifest.to_path_buf(),
            key: key.map(|k| k.to_path_buf()),
        }
    }

    // ── Golden manifest passes ──

    #[test]
    fn golden_manifest_verifies_and_records_the_key_id() {
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

    // ── GPT identity refusals ──

    #[test]
    fn non_gpt_table_is_refused_by_name() {
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
        let dir = tempfile::tempdir().unwrap();
        let device = device_file(dir.path());
        let kp = test_kp(7);
        let m = signed(manifest(Some(ROOTHASH), None), &kp);
        let manifest_path = dir.path().join("m.json");
        std::fs::write(&manifest_path, serde_json::to_string(&m).unwrap()).unwrap();
        let key_anchor = dir.path().join("anchor.pub");
        std::fs::write(&key_anchor, crate::sign::public_key_file(&kp)).unwrap();
        // A different image's table: root type present, identity foreign.
        let runner = FakeTools::new(foreign_gpt_json(), 0);
        let err = verify_device_with(
            &runner,
            &args(&device, &manifest_path, Some(&key_anchor)),
            Some(Path::new(FAKE_VERITYSETUP)),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("root slot PARTUUID mismatch") && err.contains("wrong device"),
            "{err}"
        );
    }

    #[test]
    fn medium_without_a_root_slot_refuses_by_name() {
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
            r#"{{"partitiontable": {{"label": "gpt", "sector-size": 512, "partitions": [
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

    // ── Truncation ──

    #[test]
    fn truncated_medium_refuses_by_name() {
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

    // ── Verity recompute ──

    #[test]
    fn flipped_byte_refuses_naming_the_slot_a_regions() {
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
            r#"{"partitiontable": {"label": "gpt", "sector-size": 512, "partitions": [
                {"size": 100, "type": "x", "uuid": "y"}
            ]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no valid 'start'"), "{err}");
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
