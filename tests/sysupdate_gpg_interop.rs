//! Real-gpg interop for the sysupdate signature layer (#291, council M2).
//!
//! The sign↔verify round-trip was proven pgp-crate↔pgp-crate only
//! (`src/image/release.rs`): the same crate produced the pubring, the
//! sums, and the signature, and the same crate verified them. But the
//! DEVICE's verifier is the real `gpg` binary that systemd-sysupdate
//! shells out to for `Verify=yes` — pointing gpg at the embedded
//! keyring (`--keyring <import-pubring.pgp>`, the VENDOR_KEYRING_PATH
//! shape) and asking it to verify a detached binary signature over the
//! downloaded `SHA256SUMS` bytes. This test produces the trust anchor
//! and a signed manifest through the landed producers
//! ([`shuttle::sign::import_pubring_pgp`],
//! [`shuttle::sign::sign_sysupdate_manifest`]) and hands BOTH to the
//! real gpg. If gpg rejects the EdDSALegacy(22)+SHA256 framing, every
//! fielded device refuses every update — that verdict must come from
//! gpg, not from the crate grading its own homework.
//!
//! Gated on the `gpg` binary (skip-if-absent on a dev host). In the
//! automated gate the skip is NOT allowed: `SHUTTLE_GATE=1` turns a
//! missing gpg into a hard failure (#291 M3 — a silently-skipped
//! round-trip is what hid the trust-slice council's H1), unless the
//! host opts out with `SHUTTLE_GATE_ALLOW_SKIP=1`. `scripts/gate.sh`
//! provisions gpg via nix, so the gate runs this for real.

use std::path::{Path, PathBuf};
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

fn gpg_available() -> bool {
    has_tool("gpg")
}

/// The gate exports SHUTTLE_GATE=1; the tests treat a missing gpg as a
/// failure there, never a silent skip.
fn in_gate() -> bool {
    std::env::var("SHUTTLE_GATE").as_deref() == Ok("1")
}

/// The documented per-host opt-out: a gate host that cannot carry the
/// tools (no nix, offline) proceeds with VISIBLE skips.
fn gate_skips_allowed() -> bool {
    std::env::var("SHUTTLE_GATE_ALLOW_SKIP").as_deref() == Ok("1")
}

/// Skip-if-absent on a dev host; panic in the gate (#291 M3).
fn skip_or_gate_fail() {
    if in_gate() && !gate_skips_allowed() {
        panic!(
            "SHUTTLE_GATE=1 but gpg is unavailable — the gate must RUN the \
             real-gpg sysupdate interop, not skip it (scripts/gate.sh \
             provisions nixpkgs#gnupg; a silent skip here is the #291 M3 \
             meta-cause). Set SHUTTLE_GATE_ALLOW_SKIP=1 to proceed with \
             visible skips on a host that cannot carry gpg."
        );
    }
    eprintln!("skipping: gpg unavailable");
}

// ── Fixture ──

fn test_kp(seed_byte: u8) -> shuttle::sign::KeyPair {
    let seed = [seed_byte; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    shuttle::sign::KeyPair {
        seed,
        public: sk.verifying_key().to_bytes(),
    }
}

/// The published sysupdate artifacts, produced by the landed producers:
/// the device trust anchor (`import-pubring.pgp`), the coreutils-format
/// `SHA256SUMS` body, and its detached signature (`SHA256SUMS.gpg`).
struct SysupdateArtifacts {
    dir: tempfile::TempDir,
    pubring: PathBuf,
    sums: PathBuf,
    sig: PathBuf,
}

fn produce_artifacts() -> SysupdateArtifacts {
    let dir = tempfile::tempdir().unwrap();
    let kp = test_kp(7);

    let pubring = dir.path().join("import-pubring.pgp");
    std::fs::write(&pubring, shuttle::sign::import_pubring_pgp(&kp).unwrap()).unwrap();

    // The coreutils-format manifest the release layer publishes: one
    // `<sha256>␠␠<name>` line per media file, over real bytes.
    let media: Vec<(&str, Vec<u8>)> = vec![
        ("nau-cassini-1.0.0-amd64.img", vec![0xA5u8; 4096]),
        (
            "nau-cassini-1.0.0-amd64.manifest.json",
            br#"{"name":"nau-cassini","version":"1.0.0"}"#.to_vec(),
        ),
    ];
    use sha2::Digest;
    let sums = dir.path().join(shuttle::sign::SYSUPDATE_MANIFEST_NAME);
    let mut body = String::new();
    for (name, bytes) in &media {
        let digest = sha2::Sha256::digest(bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        body.push_str(&format!("{hex}  {name}\n"));
    }
    std::fs::write(&sums, &body).unwrap();

    let sig = dir
        .path()
        .join(shuttle::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME);
    std::fs::write(
        &sig,
        shuttle::sign::sign_sysupdate_manifest(&kp, body.as_bytes()).unwrap(),
    )
    .unwrap();

    SysupdateArtifacts {
        dir,
        pubring,
        sums,
        sig,
    }
}

/// Invoke the real gpg the way the device's verifier does: a fresh
/// GNUPGHOME, the embedded keyring passed as `--keyring`, a detached
/// `--verify` of the signature over the manifest bytes.
fn gpg_verify(home: &Path, fx: &SysupdateArtifacts, sums: &Path) -> std::process::Output {
    gpg_verify_paths(home, &fx.pubring, &fx.sig, sums)
}

/// The path-addressed spelling of [`gpg_verify`], for fixtures built
/// outside [`SysupdateArtifacts`] (the #290 overlap-window pubring).
fn gpg_verify_paths(home: &Path, pubring: &Path, sig: &Path, sums: &Path) -> std::process::Output {
    Command::new("gpg")
        .args(["--batch", "--no-secmem-warning", "--no-permission-warning"])
        .arg("--homedir")
        .arg(home)
        .arg("--keyring")
        .arg(pubring)
        .arg("--verify")
        .arg(sig)
        .arg(sums)
        .output()
        .expect("failed to spawn gpg")
}

fn output_text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── The interop ──

#[test]
fn gpg_verifies_the_produced_sysupdate_artifacts() {
    if !gpg_available() {
        skip_or_gate_fail();
        return;
    }
    let fx = produce_artifacts();
    let home = tempfile::tempdir().unwrap();

    let out = gpg_verify(home.path(), &fx, &fx.sums);
    assert!(
        out.status.success(),
        "real gpg must accept the produced import-pubring.pgp + \
         SHA256SUMS.gpg over SHA256SUMS (device-facing verdict): {}",
        output_text(&out)
    );
    let text = output_text(&out);
    assert!(
        text.contains("Good signature"),
        "gpg's verdict must be a Good signature: {text}"
    );
}

#[test]
fn gpg_refuses_a_tampered_sysupdate_manifest() {
    if !gpg_available() {
        skip_or_gate_fail();
        return;
    }
    let fx = produce_artifacts();
    let home = tempfile::tempdir().unwrap();

    // Flip one byte inside the manifest body: the device-side refusal
    // must be gpg's own BAD-signature verdict, so a positive control
    // (the test above) is only half the interop.
    let tampered = fx.dir.path().join("SHA256SUMS.tampered");
    let mut body = std::fs::read(&fx.sums).unwrap();
    let last = body.len() - 2;
    body[last] ^= 0x01;
    std::fs::write(&tampered, &body).unwrap();

    let out = gpg_verify(home.path(), &fx, &tampered);
    assert!(
        !out.status.success(),
        "gpg must refuse a tampered SHA256SUMS: {}",
        output_text(&out)
    );
    let text = output_text(&out);
    assert!(
        text.contains("BAD signature"),
        "gpg's verdict must name the bad signature: {text}"
    );
}

/// #290: the overlap-window pubring is a KEYRING of two ceremony keys,
/// and the real gpg accepts a signature from EITHER during the window.
/// Driven through the landed ceremony (rotate mints both pubring
/// fragments; the pre-promotion state is the rollout-critical one: the
/// transition release signs under the OLD key while already carrying the
/// successor's identity, so a fielded single-key device both accepts it
/// and comes out of the window trusting the successor).
#[test]
fn gpg_accepts_signatures_from_either_key_in_the_overlap_pubring() {
    if !gpg_available() {
        skip_or_gate_fail();
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let old = shuttle::sign::create_secret_key(dir.path()).unwrap();
    let keys_dir = shuttle::sign::keys_dir(dir.path());
    shuttle::sign::install_public_key(&old, &keys_dir).unwrap();
    let successor = shuttle::sign::mint_rotation_key(dir.path()).unwrap();

    // The pre-promotion trust set: {current, designated successor}.
    let pubring = dir.path().join("import-pubring.pgp");
    std::fs::write(
        &pubring,
        shuttle::sign::sysupdate_pubring_pgp(&old, dir.path()).unwrap(),
    )
    .unwrap();

    // The coreutils-format SHA256SUMS over real bytes.
    let media: Vec<(&str, Vec<u8>)> = vec![("nau-cassini-1.0.1-amd64.img", vec![0x5Au8; 4096])];
    use sha2::Digest;
    let mut body = String::new();
    for (name, bytes) in &media {
        let digest = sha2::Sha256::digest(bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        body.push_str(&format!("{hex}  {name}\n"));
    }
    let sums = dir.path().join(shuttle::sign::SYSUPDATE_MANIFEST_NAME);
    std::fs::write(&sums, &body).unwrap();

    for (role, signer) in [("current", &old), ("designated-successor", &successor)] {
        let sig = dir
            .path()
            .join(shuttle::sign::SYSUPDATE_MANIFEST_SIGNATURE_NAME);
        std::fs::write(
            &sig,
            shuttle::sign::sign_sysupdate_manifest(signer, body.as_bytes()).unwrap(),
        )
        .unwrap();
        let gpg_home = tempfile::tempdir().unwrap();
        let out = gpg_verify_paths(gpg_home.path(), &pubring, &sig, &sums);
        assert!(
            out.status.success(),
            "real gpg must accept the {role} key's signature against the overlap pubring: {}",
            output_text(&out)
        );
        let text = output_text(&out);
        assert!(
            text.contains("Good signature"),
            "gpg's verdict must be a Good signature: {text}"
        );
    }
}
