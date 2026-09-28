//! `shuttle image --release` ↔ `shuttle verify-image` interop, end to end
//! (ADR-0044 D4+D5, issues #266 and #265).
//!
//! The trust contract: the release signer attaches the operator's Ed25519
//! signature over the IMAGE manifest's canonical body
//! (`image::verify::image_manifest_canonical_bytes` — NOT the eval
//! manifest scheme), and the real binary must verify the published pair.
//! These tests build the same REAL whole-disk GPT fixture
//! verify_image_cmd.rs uses — sfdisk table + a real `veritysetup format`
//! roothash — but the manifest is signed by the RELEASE signer, exactly
//! as `--release` publishes it (pretty JSON with the signatures map
//! attached), then round-tripped through the file system into
//! `shuttle verify-image`.
//!
//! Gated on sfdisk + veritysetup + mtools (the build-host tools the suite
//! spawns; the fixture ESP is a real mtools FAT — #284's covered region).
//! The live axis — a real mission through `shuttle image --release` into
//! a scratch export tree (full ukify/mtools/mkfs chain), two-machine
//! rebuild-compare byte-identity, and hardware — stays deferred; nothing
//! here fakes it.

use std::io::Write;
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

// ── Fixture (the verify_image_cmd.rs geometry, re-signed via release) ──

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

/// The fixture UKI's filename on the ESP (the manifest's `uki`).
const UKI_NAME: &str = "nau_1.0.0.efi";

/// Deterministic UKI content the fixture FAT carries.
fn uki_bytes() -> Vec<u8> {
    (0..16384usize).map(|i| (i % 251) as u8).collect()
}

/// One mtools call, asserting success.
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

/// A REAL FAT ESP at `path` carrying the generation's UKI under
/// EFI/Linux/ — the mtools populate shape, unmounted.
fn write_fat_esp(path: &Path) {
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
    run_tool(
        "mcopy",
        &[
            "-i",
            path.to_str().unwrap(),
            payload.to_str().unwrap(),
            &format!("::/EFI/Linux/{UKI_NAME}"),
        ],
    );
}

/// GUIDs a roothash derives (data, hash), dashed — the build's derivation,
/// mirrored by the fixture table.
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

struct Fixture {
    dir: tempfile::TempDir,
    device: std::path::PathBuf,
    /// The release-published manifest (signed by the release signer,
    /// pretty JSON — the exact serialization `--release` writes).
    manifest: std::path::PathBuf,
    key: std::path::PathBuf,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("nau-cassini-1.0.0-amd64.img");

    // 1. The root region, verity-formatted into the hash region (default
    //    sha256/4K/4K format 1 — the build's argv shape). The roothash the
    //    release manifest must carry.
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
    //    from the real roothash.
    let (data_guid, hash_guid) = derived_guids(&roothash);
    let script = format!(
        "label: gpt\n\
         unit: sectors\n\
         start={ESP_START}, size={ESP_SIZE}, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b, \
         uuid={ESP_UUID}, name=\"ESP\"\n\
         start={ROOT_START}, size={ROOT_SIZE}, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, \
         uuid={data_guid}, name=\"nau_1.0.0_a\"\n\
         start={HASH_START}, size={HASH_SIZE}, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, \
         uuid={hash_guid}, name=\"nau_1.0.0_hash_a\"\n",
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

    // 3. The ESP extent: a real FAT carrying the generation's UKI, whose
    //    digest the release-signed manifest pins (#284).
    let esp_file = dir.path().join("esp.part");
    write_fat_esp(&esp_file);
    let uki_payload = dir.path().join("uki.digest-payload");
    std::fs::write(&uki_payload, uki_bytes()).unwrap();
    let uki_digest = shuttle::store::sha3_384_file(&uki_payload).unwrap();
    splice(&device, &esp_file, ESP_START * SECTOR);

    // 4. Splice the formatted regions into their extents.
    splice(&device, &root_file, ROOT_START * SECTOR);
    splice(&device, &hash_file, HASH_START * SECTOR);

    // 5. The published manifest — signed by the RELEASE signer over the
    //    image manifest's canonical body, serialized exactly as
    //    `--release` publishes it (pretty JSON, signatures map attached),
    //    and round-tripped through the file system like a download.
    let manifest = dir
        .path()
        .join(shuttle::image::release::release_stem("1.0.0", "amd64") + ".manifest.json");
    assert_eq!(
        manifest.file_name().unwrap().to_str().unwrap(),
        "nau-cassini-1.0.0-amd64.manifest.json",
        "the media name carries the ADR-0013 vocabulary"
    );
    write_release_signed_manifest(&manifest, &roothash, &uki_digest);
    let key = dir.path().join("downloaded.pub");
    std::fs::write(&key, shuttle::sign::public_key_file(&test_kp(7))).unwrap();

    Fixture {
        dir,
        device,
        manifest,
        key,
    }
}

fn splice(dst: &std::path::Path, src: &std::path::Path, offset: u64) {
    use std::io::Seek;
    let mut reader = std::fs::File::open(src).unwrap();
    let mut writer = std::fs::OpenOptions::new().write(true).open(dst).unwrap();
    writer.seek(std::io::SeekFrom::Start(offset)).unwrap();
    std::io::copy(&mut reader, &mut writer).unwrap();
}

/// Sign with the release signer and publish the exact bytes `--release`
/// writes: the typed image manifest, pretty-printed, signature attached.
fn write_release_signed_manifest(path: &std::path::Path, roothash: &str, uki_sha3_384: &str) {
    use shuttle::image::{ImageManifest, ImageSnapEntry};
    let mut manifest = ImageManifest {
        name: "nau".into(),
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
        uki_sha3_384: Some(uki_sha3_384.to_string()),
        esp_partuuid: Some(ESP_UUID.into()),
        roothash: Some(roothash.into()),
        signatures: Default::default(),
    };
    shuttle::image::release::sign_image_manifest(&mut manifest, &test_kp(7)).unwrap();
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    std::fs::write(path, json).unwrap();
}

/// Run the real binary with HOME isolated to `dir` (empty keychain —
/// `--key` is the only anchor in play, the download posture).
fn run_verify(fx: &Fixture, manifest: &std::path::Path) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_shuttle"))
        .args([
            "verify-image",
            "--device",
            fx.device.to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--key",
            fx.key.to_str().unwrap(),
        ])
        .env("HOME", fx.dir.path())
        .current_dir(fx.dir.path())
        .output()
        .expect("failed to spawn shuttle");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn flatten(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect()
}

// ── The interop gates ──

// THE sign↔verify pin: a manifest signed by the release signer verifies
// under the real binary with the operator anchor beside it.
gated_test!(release_signed_manifest_verifies_end_to_end, {
    let fx = build_fixture();
    let (code, stderr) = run_verify(&fx, &fx.manifest);
    assert_eq!(
        code,
        Some(0),
        "release-published pair must verify: {stderr}"
    );
    assert!(
        stderr.contains("verified 'nau' 1.0.0"),
        "success names the image: {stderr}"
    );
    // #284: the release-pinned ESP UKI digest is recomputed from the
    // flashed medium in the same pass.
    assert!(
        stderr.contains(UKI_NAME) && stderr.contains("ESP"),
        "success names the covered ESP UKI: {stderr}"
    );
});

// A body byte edited after signing — here the version, the published
// manifest's most visible claim — must refuse by name.
gated_test!(tampered_release_manifest_refuses, {
    let fx = build_fixture();
    let body = std::fs::read_to_string(&fx.manifest).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["version"] = serde_json::json!("9.9.9");
    let tampered = fx.dir.path().join("tampered.manifest.json");
    std::fs::write(&tampered, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let (code, stderr) = run_verify(&fx, &tampered);
    assert_ne!(code, Some(0), "a tampered release manifest must refuse");
    assert!(
        flatten(&stderr).contains("notrustedsignatureverifies"),
        "refusal names the signature failure: {stderr}"
    );
});

// The ADR-0024 §4 ordering through the release path: a signature under a
// revoked key id refuses even when the key is also an installed anchor.
gated_test!(revoked_release_key_refuses, {
    let fx = build_fixture();
    let keys_dir = fx.dir.path().join(".config/shuttle/keys");
    std::fs::create_dir_all(&keys_dir).unwrap();
    let kp = test_kp(7);
    std::fs::write(
        keys_dir.join(format!("{}.pub", kp.key_id())),
        shuttle::sign::public_key_file(&kp),
    )
    .unwrap();
    std::fs::write(keys_dir.join("revoked-keys"), format!("{}\n", kp.key_id())).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_shuttle"))
        .args([
            "verify-image",
            "--device",
            fx.device.to_str().unwrap(),
            "--manifest",
            fx.manifest.to_str().unwrap(),
        ])
        .env("HOME", fx.dir.path())
        .current_dir(fx.dir.path())
        .output()
        .expect("failed to spawn shuttle");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        flatten(&stderr).contains("REVOKED"),
        "revoked-first must outrank the anchor set: {stderr}"
    );
});
