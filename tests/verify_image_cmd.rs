//! `shuttle verify-image` end to end (ADR-0044 D4, issue #265).
//!
//! Builds a REAL whole-disk GPT image file — sfdisk lays out ESP + root +
//! verity-hash partitions with the build's type GUIDs and the identity
//! PARTUUIDs derived from a real `veritysetup format` roothash — signs an
//! image manifest over it in-process, and drives the real binary against
//! the file. Then each refusal gate: a flipped byte, a wrong device, an
//! unsigned manifest, a truncated medium.
//!
//! This is the deterministic half of the live axis: a FILE is a valid
//! `--device` (the verb opens it read-only), so everything short of
//! flashing an actual USB stick runs here. Gated on sfdisk + veritysetup
//! (the build-host tools the suite spawns).

use std::io::{Read, Seek, Write};
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
    ["sfdisk", "veritysetup"].iter().all(|t| has_tool(t))
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

fn test_kp(seed_byte: u8) -> shuttle::sign::KeyPair {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    shuttle::sign::KeyPair {
        seed,
        public: sk.verifying_key().to_bytes(),
    }
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

    // 3. Splice the formatted regions into their extents.
    splice(&device, &root_file, ROOT_START * SECTOR);
    splice(&device, &hash_file, HASH_START * SECTOR);

    // 4. The published pair: the signed manifest + the downloaded anchor.
    let manifest = dir.path().join("nau-demo-1.0.0-amd64.manifest.json");
    write_signed_manifest(&manifest, &roothash);
    let key = dir.path().join("downloaded.pub");
    std::fs::write(&key, shuttle::sign::public_key_file(&test_kp(7))).unwrap();

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

/// The manifest shuttle publishes beside a mission image, signed over its
/// canonical body (the typed manifest serialized with the signatures map
/// emptied) — the exact shape `shuttle image --release` attaches (#266).
fn write_signed_manifest(path: &std::path::Path, roothash: &str) {
    use shuttle::image::{ImageManifest, ImageSnapEntry};
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
        uki: Some("nau-demo_1.0.0.efi".into()),
        esp_partuuid: Some(ESP_UUID.into()),
        roothash: Some(roothash.into()),
        signatures: Default::default(),
    };
    let canonical = serde_json::to_vec(&manifest).unwrap();
    let kp = test_kp(7);
    let sig = shuttle::sign::sign_bytes(&canonical, &kp);
    let mut v = serde_json::to_value(&manifest).unwrap();
    v["signatures"] = serde_json::json!({ (kp.key_id()): sig });
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Run the real binary with HOME isolated to `dir`, so the operator
/// keychain is empty and `--key` is the only trust anchor in play.
fn run_in(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_shuttle"))
        .args(args)
        .env("HOME", dir)
        .current_dir(dir)
        .output()
        .expect("failed to spawn shuttle");
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
        stderr.contains("root slot PARTUUID mismatch"),
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
