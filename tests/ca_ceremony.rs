//! The SSH host CA ceremony (ADR-0045 amendment, #283 decided) end to
//! end through the real binary with the REAL `ssh-keygen`: `nau ca
//! keygen` mints a dedicated ed25519 keypair at
//! `~/.config/nau/ca/` (`ca` 0600 private, `ca.pub` public), the
//! fingerprint is introspectable (`nau ca list`), an existing CA
//! refuses overwrite without `--force`, and `--force` regenerates both
//! halves. Every path runs under an isolated `--home` — the operator's
//! real CA is never touched.

use std::process::Command;

/// Run nau with an isolated HOME so the CA ceremony is private to
/// the test. Returns (exit code, stdout, stderr).
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

/// JSON stdout of a `--json` ceremony command.
fn report_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("--json report must parse ({e}): {stdout}"))
}

#[test]
fn ca_ceremony_lifecycle_through_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let ca_dir = dir.path().join(".config/nau/ca");
    let secret = ca_dir.join("ca");
    let public = ca_dir.join("ca.pub");

    // ── list on an empty ceremony home: a hint, not an error ──
    let (code, stdout, stderr) = run_in(dir.path(), &["ca", "list", &home, "--json"]);
    assert_eq!(code, Some(0), "empty list: {stderr}");
    assert_eq!(report_json(&stdout)["present"], serde_json::json!(false));
    // The human form carries the hint (the JSON form intentionally
    // stays machine-clean — status lines are suppressed under --json).
    let (code, _, stderr) = run_in(dir.path(), &["ca", "list", &home]);
    assert_eq!(code, Some(0));
    assert!(
        stderr.contains("ca keygen"),
        "hint names the mint verb: {stderr}"
    );

    // ── keygen: mints the keypair at the contract paths ──
    let (code, stdout, stderr) = run_in(dir.path(), &["ca", "keygen", &home, "--json"]);
    assert_eq!(code, Some(0), "keygen: {stderr}");
    let report = report_json(&stdout);
    let fingerprint_a = report["fingerprint"].as_str().unwrap().to_string();
    assert!(fingerprint_a.starts_with("SHA256:"), "{fingerprint_a}");
    let public_line_a = report["public_line"].as_str().unwrap().to_string();
    assert!(
        public_line_a.starts_with("ssh-ed25519 "),
        "the CA is an ed25519 key: {public_line_a}"
    );
    assert!(
        public_line_a.ends_with(" nau-host-ca"),
        "the minted comment marks the CA: {public_line_a}"
    );
    assert!(secret.exists(), "private half at {secret:?}");
    assert!(public.exists(), "public half at {public:?}");

    // The private half is 0600 — the high-value trust root is private.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the CA secret is 0600");

    // ── list now introspects the minted CA ──
    let (code, stdout, stderr) = run_in(dir.path(), &["ca", "list", &home, "--json"]);
    assert_eq!(code, Some(0), "list: {stderr}");
    let listed = report_json(&stdout);
    assert_eq!(listed["present"], serde_json::json!(true));
    assert_eq!(listed["secret_present"], serde_json::json!(true));
    assert_eq!(listed["fingerprint"], serde_json::json!(fingerprint_a));
    assert_eq!(listed["public_line"], serde_json::json!(public_line_a));

    // ── re-keygen refuses without --force ──
    let (code, _, stderr) = run_in(dir.path(), &["ca", "keygen", &home]);
    assert_ne!(code, Some(0), "overwrite without --force must fail");
    assert!(stderr.contains("already exists"), "named refusal: {stderr}");
    assert!(
        stderr.contains("--force"),
        "refusal names the opt-in: {stderr}"
    );
    // The original CA survives the refusal.
    let (code, stdout, _) = run_in(dir.path(), &["ca", "list", &home, "--json"]);
    assert_eq!(code, Some(0));
    assert_eq!(
        report_json(&stdout)["fingerprint"],
        serde_json::json!(fingerprint_a),
        "refusal left the original CA in place"
    );

    // ── --force regenerates both halves (fresh ed25519 keypair) ──
    let (code, stdout, stderr) = run_in(dir.path(), &["ca", "keygen", &home, "--force", "--json"]);
    assert_eq!(code, Some(0), "force keygen: {stderr}");
    let fingerprint_b = report_json(&stdout)["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        fingerprint_a, fingerprint_b,
        "a forced mint produces a NEW root"
    );
    let (code, stdout, _) = run_in(dir.path(), &["ca", "list", &home, "--json"]);
    assert_eq!(code, Some(0));
    assert_eq!(
        report_json(&stdout)["fingerprint"],
        serde_json::json!(fingerprint_b),
        "list reports the regenerated root"
    );
}

#[test]
fn ca_secret_without_its_public_half_is_a_named_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let (code, _, stderr) = run_in(dir.path(), &["ca", "keygen", &home]);
    assert_eq!(code, Some(0), "keygen: {stderr}");

    // Sabotage: drop the public half behind the ceremony's back.
    let public = dir.path().join(".config/nau/ca/ca.pub");
    std::fs::remove_file(&public).unwrap();
    let (code, _, stderr) = run_in(dir.path(), &["ca", "list", &home, "--json"]);
    assert_ne!(code, Some(0), "incomplete keypair must fail closed");
    assert!(stderr.contains("incomplete"), "named error: {stderr}");
    assert!(
        stderr.contains("ca.pub"),
        "names the missing half: {stderr}"
    );
}

#[test]
fn ca_corrupt_public_half_fails_fingerprint_introspection() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let (code, _, stderr) = run_in(dir.path(), &["ca", "keygen", &home]);
    assert_eq!(code, Some(0), "keygen: {stderr}");

    // Sabotage: the public half stops being a key.
    let public = dir.path().join(".config/nau/ca/ca.pub");
    std::fs::write(&public, "not a key\n").unwrap();
    let (code, _, stderr) = run_in(dir.path(), &["ca", "list", &home]);
    assert_ne!(code, Some(0), "corrupt public half must fail closed");
    assert!(
        stderr.contains("not a usable public key"),
        "named error: {stderr}"
    );
    assert!(stderr.contains("ca.pub"), "names the file: {stderr}");
}
