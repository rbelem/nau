//! `nau verify-image` end to end (ADR-0044 D4, issue #265).
//!
//! Builds a REAL whole-disk GPT image file — sfdisk lays out ESP + root +
//! verity-hash partitions with the build's type GUIDs and the identity
//! PARTUUIDs derived from a real `veritysetup format` roothash, and the
//! ESP extent holds a REAL mtools FAT carrying the generation's UKI
//! (#284: the ESP is the one region dm-verity does not cover, so the
//! signed manifest pins its UKI digest and the verb recomputes it) —
//! signs an image manifest over it in-process, and drives the real
//! binary against the file. Then each refusal gate: a flipped byte, a
//! wrong device, an unsigned manifest, a truncated medium, and the #284
//! ESP shapes — tampered UKI bytes, a replaced ESP, a flipped ESP from
//! another generation, the boot-count-suffixed name sysupdate installs.
//!
//! This is the deterministic half of the live axis: a FILE is a valid
//! `--device` (the verb opens it read-only), so everything short of
//! flashing an actual USB stick runs here. Gated on sfdisk + veritysetup
//! + mtools (the build-host tools the suite spawns).

use std::io::{Read, Seek, Write};
use std::path::Path;
use std::process::Command;

// ── Gating ──

fn has_tool(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some()
}

fn chain_available() -> bool {
    ["sfdisk", "veritysetup", "mformat", "mmd", "mcopy"]
        .iter()
        .all(|t| has_tool(t))
}

macro_rules! gated_test {
    ($fn_name:ident, $($body:tt)*) => {
        #[test]
        fn $fn_name() {
            if !chain_available() {
                eprintln!("skipping: sfdisk/veritysetup unavailable");
                return;
            }
            $($body)*
        }
    };
}

// ── Fixture ──

/// Sector geometry (512 B sectors): ESP @2 MiB (2 MiB), root @4 MiB
/// (8 MiB), hash @12 MiB (2 MiB) — the hash partition comfortably over
/// the build's sizing floor for an 8 MiB root.
const ESP_START: u64 = 4096;
const ESP_SIZE: u64 = 4096;
const ROOT_START: u64 = 8192;
const ROOT_SIZE: u64 = 16384;
const HASH_START: u64 = 24576;
const HASH_SIZE: u64 = 4096;
const SECTOR: u64 = 512;
const ESP_UUID: &str = "aabbccdd-0011-2233-4455-667788990011";

fn test_kp(seed_byte: u8) -> nau::sign::KeyPair {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    nau::sign::KeyPair {
        seed,
        public: sk.verifying_key().to_bytes(),
    }
}

/// The fixture UKI's filename on the ESP — the build's
/// `{name}_{version}.efi` shape, and the name the fixture manifest pins.
const UKI_NAME: &str = "nau-demo_1.0.0.efi";

/// Deterministic UKI content — enough bytes to cross several FAT cluster
/// boundaries, stable across runs (the digest is pinned in the manifest).
fn uki_bytes() -> Vec<u8> {
    (0..16384usize).map(|i| (i % 251) as u8).collect()
}

/// The fixture UKI's sha3-384, hashed through the same seam the binary
/// uses ([`nau::store::sha3_384_file`]) so a divergence there fails
/// here too.
fn uki_digest_of(bytes: &[u8], dir: &Path) -> String {
    let path = dir.join("uki-digest.payload");
    std::fs::write(&path, bytes).unwrap();
    nau::store::sha3_384_file(&path).unwrap()
}

/// Run one mtools/sfdisk tool, asserting success — the fixture's raw
/// tool calls.
fn run_tool(tool: &str, args: &[&str]) {
    let out = Command::new(tool).args(args).output().unwrap_or_else(|e| {
        panic!("{tool} failed to spawn: {e}");
    });
    assert!(
        out.status.success(),
        "{tool} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A REAL FAT ESP image at `path`: mformat + mmd + mcopy (the build's
/// unmounted populate shape), carrying `names` under EFI/Linux/ with
/// [`uki_bytes`] content. Returns the bytes of the installed UKI.
fn write_fat_esp(path: &Path, names: &[&str]) -> Vec<u8> {
    std::fs::write(path, vec![0u8; (ESP_SIZE * SECTOR) as usize]).unwrap();
    run_tool(
        "mformat",
        &[
            "-i",
            path.to_str().unwrap(),
            "::",
            "-C",
            "-T",
            &format!("{}", ESP_SIZE * SECTOR / 512),
            "-F",
        ],
    );
    run_tool("mmd", &["-i", path.to_str().unwrap(), "::/EFI"]);
    run_tool("mmd", &["-i", path.to_str().unwrap(), "::/EFI/Linux"]);
    let payload = path.with_extension("uki-payload");
    std::fs::write(&payload, uki_bytes()).unwrap();
    for name in names {
        run_tool(
            "mcopy",
            &[
                "-i",
                path.to_str().unwrap(),
                payload.to_str().unwrap(),
                &format!("::/EFI/Linux/{name}"),
            ],
        );
    }
    let _ = std::fs::remove_file(&payload);
    uki_bytes()
}

/// Replace one UKI name's content on an existing ESP FAT (mcopy
/// overwrite) — the tampered-UKI shape.
fn overwrite_esp_uki(esp: &Path, name: &str, content: &[u8], dir: &Path) {
    let payload = dir.join("overwrite.payload");
    std::fs::write(&payload, content).unwrap();
    run_tool(
        "mcopy",
        &[
            "-o",
            "-i",
            esp.to_str().unwrap(),
            payload.to_str().unwrap(),
            &format!("::/EFI/Linux/{name}"),
        ],
    );
}

/// GUIDs a roothash derives (data, hash), dashed — the same derivation
/// `src/image/verity.rs` performs at build time; the build stamps these
/// onto the table, so the fixture stamps them the same way.
fn derived_guids(roothash: &str) -> (String, String) {
    let dashed = |hex: &str| {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32],
        )
    };
    (dashed(&roothash[32..64]), dashed(&roothash[0..32]))
}

/// One assembled mission-image file: a real sfdisk GPT whose root/hash
/// PARTUUIDs derive from a real verity roothash over the root region,
/// with a manifest signed over that roothash and the matching trust
/// anchor beside it.
struct Fixture {
    dir: tempfile::TempDir,
    device: std::path::PathBuf,
    manifest: std::path::PathBuf,
    key: std::path::PathBuf,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("nau-demo-1.0.0-amd64.img");

    // 1. The root region content, verity-formatted into the hash region —
    //    default sha256/4K/4K format 1, the build's argv shape. The
    //    resulting roothash is what the manifest (and the table identity)
    //    must carry.
    let root_file = dir.path().join("root.part");
    let hash_file = dir.path().join("hash.part");
    std::fs::write(&root_file, vec![0xA5u8; (ROOT_SIZE * SECTOR) as usize]).unwrap();
    std::fs::write(&hash_file, vec![0u8; (HASH_SIZE * SECTOR) as usize]).unwrap();
    let out = Command::new("veritysetup")
        .args([
            "format",
            root_file.to_str().unwrap(),
            hash_file.to_str().unwrap(),
        ])
        .output()
        .expect("veritysetup format");
    assert!(
        out.status.success(),
        "veritysetup format failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let roothash = stdout
        .lines()
        .find(|l| l.starts_with("Root hash:"))
        .map(|l| l["Root hash:".len()..].trim().to_ascii_lowercase())
        .expect("Root hash: line in veritysetup output");

    // 2. The whole-disk GPT: the build's type GUIDs, PARTUUIDs derived
    //    from the real roothash, PARTLABELs the build stamps.
    let (data_guid, hash_guid) = derived_guids(&roothash);
    let script = format!(
        "label: gpt\n\
         unit: sectors\n\
         start={ESP_START}, size={ESP_SIZE}, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b, \
         uuid={ESP_UUID}, name=\"ESP\"\n\
         start={ROOT_START}, size={ROOT_SIZE}, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, \
         uuid={data_guid}, name=\"nau-demo_1.0.0_a\"\n\
         start={HASH_START}, size={HASH_SIZE}, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, \
         uuid={hash_guid}, name=\"nau-demo_1.0.0_hash_a\"\n",
    );
    let total = 15 * 1024 * 1024;
    std::fs::File::create(&device)
        .unwrap()
        .set_len(total)
        .unwrap();
    let out = Command::new("sfdisk")
        .arg(&device)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(script.as_bytes())?;
            child.wait_with_output()
        })
        .expect("sfdisk");
    assert!(
        out.status.success(),
        "sfdisk failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 3. The ESP extent: a real FAT carrying the generation's UKI — the
    //    content the signed manifest pins (#284).
    let esp_file = dir.path().join("esp.part");
    write_fat_esp(&esp_file, &[UKI_NAME]);
    let uki_digest = uki_digest_of(&uki_bytes(), dir.path());
    splice(&device, &esp_file, ESP_START * SECTOR);

    // 4. Splice the formatted regions into their extents.
    splice(&device, &root_file, ROOT_START * SECTOR);
    splice(&device, &hash_file, HASH_START * SECTOR);

    // 5. The published pair: the signed manifest + the downloaded anchor.
    let manifest = dir.path().join("nau-demo-1.0.0-amd64.manifest.json");
    write_signed_manifest(&manifest, &roothash, Some(&uki_digest));
    let key = dir.path().join("downloaded.pub");
    std::fs::write(&key, nau::sign::public_key_file(&test_kp(7))).unwrap();

    Fixture {
        dir,
        device,
        manifest,
        key,
    }
}

/// Copy `src`'s bytes into `dst` at `offset` — the build's splice, in
/// miniature.
fn splice(dst: &std::path::Path, src: &std::path::Path, offset: u64) {
    let mut reader = std::fs::File::open(src).unwrap();
    let mut writer = std::fs::OpenOptions::new().write(true).open(dst).unwrap();
    writer.seek(std::io::SeekFrom::Start(offset)).unwrap();
    std::io::copy(&mut reader, &mut writer).unwrap();
}

/// The manifest nau publishes beside a mission image, signed over its
/// canonical body (the typed manifest serialized with the signatures map
/// emptied) — the exact shape `nau image --release` attaches (#266).
/// `uki_sha3_384` rides the canonical body (#284); `None` models a
/// manifest predating ESP coverage.
fn write_signed_manifest(path: &std::path::Path, roothash: &str, uki_sha3_384: Option<&str>) {
    use nau::image::{ImageManifest, ImageSnapEntry};
    let manifest = ImageManifest {
        name: "nau-demo".into(),
        version: "1.0.0".into(),
        arch: "amd64".into(),
        snaps: vec![ImageSnapEntry {
            name: "core22".into(),
            revision: 1847,
            sha3_384: "abc".into(),
            role: "base".into(),
        }],
        kernel_version: Some("6.11.0".into()),
        cmdline: Some("root=PARTUUID=... quiet".into()),
        uki: Some(UKI_NAME.into()),
        uki_sha3_384: uki_sha3_384.map(|s| s.to_string()),
        esp_partuuid: Some(ESP_UUID.into()),
        roothash: Some(roothash.into()),
        signatures: Default::default(),
    };
    let canonical = serde_json::to_vec(&manifest).unwrap();
    let kp = test_kp(7);
    let sig = nau::sign::sign_bytes(&canonical, &kp);
    let mut v = serde_json::to_value(&manifest).unwrap();
    v["signatures"] = serde_json::json!({ (kp.key_id()): sig });
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Run the real binary with HOME isolated to `dir`, so the operator
/// keychain is empty and `--key` is the only trust anchor in play.
fn run_in(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nau"))
        .args(args)
        .env("HOME", dir)
        .current_dir(dir)
        .output()
        .expect("failed to spawn nau");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn verify_args(fx: &Fixture) -> Vec<String> {
    vec![
        "verify-image".into(),
        "--device".into(),
        fx.device.to_str().unwrap().into(),
        "--manifest".into(),
        fx.manifest.to_str().unwrap().into(),
        "--key".into(),
        fx.key.to_str().unwrap().into(),
    ]
}

fn run_verify(fx: &Fixture) -> (Option<i32>, String, String) {
    let args = verify_args(fx);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_in(fx.dir.path(), &refs)
}

// ── The gates ──

gated_test!(verify_image_passes_on_a_fresh_flash, {
    let fx = build_fixture();
    let (code, _stdout, stderr) = run_verify(&fx);
    assert_eq!(code, Some(0), "fresh flash must verify: {stderr}");
    assert!(
        stderr.contains("verified 'nau-demo' 1.0.0"),
        "success names the image: {stderr}"
    );
    // #284: the ESP was actually inspected, not skipped — the success
    // output names the UKI it recomputed.
    assert!(
        stderr.contains(UKI_NAME) && stderr.contains("ESP"),
        "success names the covered ESP UKI: {stderr}"
    );
});

gated_test!(verify_image_refuses_a_flipped_byte_by_name, {
    let fx = build_fixture();
    // Flip one byte in the middle of the root region.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fx.device)
        .unwrap();
    let off = ROOT_START * SECTOR + (ROOT_SIZE * SECTOR) / 2;
    f.seek(std::io::SeekFrom::Start(off)).unwrap();
    let mut one = [0u8; 1];
    f.read_exact(&mut one).unwrap();
    one[0] ^= 0xFF;
    f.seek(std::io::SeekFrom::Start(off)).unwrap();
    f.write_all(&one).unwrap();
    drop(f);

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0), "a flipped byte must refuse");
    // Match against the flattened text: miette wraps long lines mid-word.
    let flat = flatten(&stderr);
    assert!(
        flat.contains("dm-verityverificationFAILEDinslotA"),
        "refusal names the region: {stderr}"
    );
    assert!(
        flat.contains("nau-demo_1.0.0_a") && flat.contains("nau-demo_1.0.0_hash_a"),
        "refusal names both slot-A partitions: {stderr}"
    );
});

/// Collapse miette's line wrapping: drop whitespace and the `│` gutter
/// entirely, so assertions can match phrases and identifiers that miette
/// wrapped mid-word.
fn flatten(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect()
}

gated_test!(verify_image_refuses_a_wrong_device_by_name, {
    let fx = build_fixture();
    // Rewrite the root partition's PARTUUID to a foreign identity — a
    // different image's table.
    let out = Command::new("sfdisk")
        .args([
            "--part-uuid",
            fx.device.to_str().unwrap(),
            "2",
            "00000000-1111-2222-3333-444444444444",
        ])
        .output()
        .expect("sfdisk --part-uuid");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0), "a wrong device must refuse");
    assert!(
        // The message head — always on the first render line, before any
        // miette wrapping — names the identity mismatch.
        stderr.contains("no root slot partition carries"),
        "refusal names the mismatch: {stderr}"
    );
});

gated_test!(verify_image_refuses_an_unsigned_manifest, {
    let fx = build_fixture();
    let body = std::fs::read_to_string(&fx.manifest).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v.as_object_mut().unwrap().remove("signatures");
    let unsigned = fx.dir.path().join("unsigned.manifest.json");
    std::fs::write(&unsigned, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let args = vec![
        "verify-image".to_string(),
        "--device".to_string(),
        fx.device.to_str().unwrap().to_string(),
        "--manifest".to_string(),
        unsigned.to_str().unwrap().to_string(),
        "--key".to_string(),
        fx.key.to_str().unwrap().to_string(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run_in(fx.dir.path(), &refs);
    assert_ne!(code, Some(0));
    assert!(
        stderr.contains("carries no signatures"),
        "unsigned must refuse by name: {stderr}"
    );
});

gated_test!(verify_image_refuses_a_truncated_medium, {
    let fx = build_fixture();
    std::fs::File::options()
        .write(true)
        .open(&fx.device)
        .unwrap()
        .set_len(HASH_START * SECTOR) // cuts off the GPT backup area
        .unwrap();

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0));
    // A physically truncated GPT is unreadable to sfdisk (it falls back
    // to a 'dos' label), so the refusal fires at the table check — and
    // names the interrupted-flash possibility. The extent-vs-medium
    // truncation refusal itself is unit-tested in src/image/verify.rs.
    assert!(flatten(&stderr).contains("interrupted"), "{stderr}");
});

// ── The #284 ESP shapes ──

/// The path of the fixture's ESP extent file (kept inside the fixture's
/// tempdir; `build_fixture` names it deterministically).
fn esp_part_path(fx: &Fixture) -> std::path::PathBuf {
    fx.dir.path().join("esp.part")
}

/// Re-splice the (mutated) ESP extent into the device after editing it.
fn resplice_esp(fx: &Fixture) {
    splice(&fx.device, &esp_part_path(fx), ESP_START * SECTOR);
}

// THE ticket acceptance, tamper shape: flipping a byte INSIDE the ESP's
// UKI (outside every verity region) must refuse BY NAME — the pinned
// sha3-384 is the only witness.
gated_test!(verify_image_refuses_tampered_esp_content_by_name, {
    let fx = build_fixture();
    let esp = esp_part_path(&fx);
    let mut tampered = uki_bytes();
    tampered[512] ^= 0xFF;
    overwrite_esp_uki(&esp, UKI_NAME, &tampered, fx.dir.path());
    resplice_esp(&fx);

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0), "a tampered ESP UKI must refuse");
    let flat = flatten(&stderr);
    assert!(
        flat.contains("ESPcontentmismatch") && flat.contains(UKI_NAME),
        "refusal names the ESP and the UKI: {stderr}"
    );
});

// THE ticket acceptance, replaced shape: a whole-ESP replacement (fresh
// FAT, correct PARTUUID re-stamped into the table) without the manifest's
// UKI must refuse, listing what it did find.
gated_test!(verify_image_refuses_a_replaced_esp, {
    let fx = build_fixture();
    let esp = esp_part_path(&fx);
    write_fat_esp(&esp, &["nau-demo_0.9.0.efi"]);
    resplice_esp(&fx);

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0), "a replaced ESP must refuse");
    let flat = flatten(&stderr);
    assert!(
        flat.contains("doesnotcarrythemanifest'sUKI")
            && flat.contains(UKI_NAME)
            && flat.contains("nau-demo_0.9.0.efi"),
        "refusal names the expected UKI and the foreign content: {stderr}"
    );
});

// THE ticket acceptance, flipped shape: an ESP from ANOTHER generation —
// same filename stem on the foreign UKI is irrelevant; what the manifest
// pins is absent. Here the foreign generation's UKI carries different
// bytes UNDER the manifest's own name — the digest refuses it.
gated_test!(verify_image_refuses_a_flipped_esp, {
    let fx = build_fixture();
    let esp = esp_part_path(&fx);
    let foreign = vec![0x5Au8; uki_bytes().len()];
    overwrite_esp_uki(&esp, UKI_NAME, &foreign, fx.dir.path());
    resplice_esp(&fx);

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_ne!(code, Some(0), "a flipped ESP must refuse");
    let flat = flatten(&stderr);
    assert!(
        flat.contains("ESPcontentmismatch"),
        "the flipped content refuses through the pinned digest: {stderr}"
    );
});

// Post-sysupdate compatibility (#286): sysupdate installs the generation's
// UKI WITH its boot-count suffix — byte-identical content under
// `<name>+<left>-<done>.efi`. The verb must still verify that ESP.
gated_test!(verify_image_verifies_the_boot_counted_uki_name, {
    let fx = build_fixture();
    let esp = esp_part_path(&fx);
    let payload = fx.dir.path().join("uki-counted.payload");
    std::fs::write(&payload, uki_bytes()).unwrap();
    run_tool(
        "mcopy",
        &[
            "-i",
            esp.to_str().unwrap(),
            payload.to_str().unwrap(),
            &format!("::/EFI/Linux/nau-demo_1.0.0+3-0.efi"),
        ],
    );
    run_tool(
        "mdel",
        &[
            "-i",
            esp.to_str().unwrap(),
            &format!("::/EFI/Linux/{UKI_NAME}"),
        ],
    );
    resplice_esp(&fx);

    let (code, _stdout, stderr) = run_verify(&fx);
    assert_eq!(
        code,
        Some(0),
        "the boot-count-suffixed UKI is the same generation: {stderr}"
    );
    assert!(
        stderr.contains("nau-demo_1.0.0+3-0.efi"),
        "success names the counted name it verified: {stderr}"
    );
});

// The backward-compat call, at the binary level: a manifest signed before
// ESP coverage existed refuses with the named gap — it must not pass as
// if the ESP had been verified.
gated_test!(verify_image_refuses_a_manifest_predating_esp_coverage, {
    let fx = build_fixture();
    let body = std::fs::read_to_string(&fx.manifest).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("uki_sha3_384").is_some(), "fixture carries the pin");
    v.as_object_mut().unwrap().remove("uki_sha3_384");
    // The signature no longer covers this body either — but the REFUSAL
    // must be the coverage gap, reached only through a VALID signature.
    // So re-sign the reduced body exactly as the release signer would.
    let kp = test_kp(7);
    let mut reduced: nau::image::ImageManifest =
        serde_json::from_value(v).expect("the old field set still parses");
    reduced.signatures.clear();
    let canonical = serde_json::to_vec(&reduced).unwrap();
    let sig = nau::sign::sign_bytes(&canonical, &kp);
    reduced
        .signatures
        .insert(kp.key_id(), serde_json::Value::String(sig));
    let legacy = fx.dir.path().join("legacy.manifest.json");
    std::fs::write(&legacy, serde_json::to_string_pretty(&reduced).unwrap()).unwrap();

    let args = vec![
        "verify-image".to_string(),
        "--device".to_string(),
        fx.device.to_str().unwrap().to_string(),
        "--manifest".to_string(),
        legacy.to_str().unwrap().to_string(),
        "--key".to_string(),
        fx.key.to_str().unwrap().to_string(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run_in(fx.dir.path(), &refs);
    assert_ne!(code, Some(0));
    assert!(
        flatten(&stderr).contains("predatesESPcoverage"),
        "the refusal names the coverage gap: {stderr}"
    );
});

// #288: the block-device axis. A loop device's inode carries st_size 0,
// so the medium-size probe must lseek(SEEK_END), not stat — before the
// fix every real /dev target falsely refused as "truncated medium".
// `losetup` needs root (or CAP_SYS_ADMIN); skip cleanly when it cannot
// attach (the gate runs unprivileged — this is the live-axis gate).
gated_test!(verify_image_verifies_a_real_block_device, {
    let fx = build_fixture();
    let Ok(out) = Command::new("losetup")
        .args(["--find", "--show", fx.device.to_str().unwrap()])
        .output()
    else {
        eprintln!("skipping: losetup not runnable");
        return;
    };
    if !out.status.success() {
        eprintln!(
            "skipping: losetup could not attach ({})",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return;
    }
    let loop_dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(!loop_dev.is_empty(), "losetup --show printed the device");

    let mut args = verify_args(&fx);
    args[2] = loop_dev.clone();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (code, _stdout, stderr) = run_in(fx.dir.path(), &refs);

    let _ = Command::new("losetup").args(["-d", &loop_dev]).status();
    assert_eq!(
        code,
        Some(0),
        "a real block device must verify end to end: {stderr}"
    );
});
