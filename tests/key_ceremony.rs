//! Issue #51 — the key ceremony (generation, rotation, revocation) end to
//! end through the real binary: `shuttle key keygen → rotate --manifest →
//! promote → rotate → revoke → verify → list`. The ceremony ledger at
//! `keys/ceremony.json` records the generation chain and the dates; the
//! transition window accepts either key until revoked; a manifest signed
//! only by a revoked key fails with the named error. Every path runs
//! under an isolated `--home` — the operator's real keychain is never
//! touched.

use std::process::Command;

use shuttle::manifest::ImageManifest;

/// Run shuttle with an isolated HOME so the key ceremony is private to
/// the test. Returns (exit code, stdout, stderr).
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

fn write_unsigned_manifest(dir: &tempfile::TempDir, name: &str) {
    std::fs::write(
        dir.path().join(name),
        r#"{"manifest_version":1,"inputs":{},"outputs":{},"images":{},"signatures":{}}"#,
    )
    .unwrap();
}

fn read_manifest(dir: &tempfile::TempDir, name: &str) -> ImageManifest {
    let text = std::fs::read_to_string(dir.path().join(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// JSON stdout of a `--json` ceremony command.
fn report_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("--json report must parse ({e}): {stdout}"))
}

#[test]
fn key_ceremony_lifecycle_through_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    let keys = dir.path().join(".config/shuttle/keys");
    write_unsigned_manifest(&dir, "m.json");

    // ── gen ──
    let (code, _, stderr) = run_in(dir.path(), &["key", "keygen", &home]);
    assert_eq!(code, Some(0), "keygen: {stderr}");
    let ledger: shuttle::sign::CeremonyLedger =
        serde_json::from_str(&std::fs::read_to_string(keys.join("ceremony.json")).unwrap())
            .unwrap();
    let id_a = shuttle::sign::load_secret_key(dir.path())
        .unwrap()
        .unwrap()
        .key_id();
    assert!(
        ledger.keys.contains_key(&id_a),
        "keygen recorded: {ledger:?}"
    );

    // ── sign ── (the release path signs at eval; here the old key signs
    // directly so the rotation has a prior signature to keep)
    let old = shuttle::sign::load_secret_key(dir.path()).unwrap().unwrap();
    let mut manifest = read_manifest(&dir, "m.json");
    shuttle::sign::cosign(&mut manifest, &old).unwrap();
    std::fs::write(dir.path().join("m.json"), manifest.to_json().unwrap()).unwrap();

    // ── rotate ── dual-signs the manifest under the successor and
    // records the generation chain with a 7-day window.
    let (code, stdout, stderr) = run_in(
        dir.path(),
        &[
            "key",
            "rotate",
            "--manifest",
            "m.json",
            "--window-days",
            "7",
            &home,
            "--json",
        ],
    );
    assert_eq!(code, Some(0), "rotate: {stderr}");
    let report = report_json(&stdout);
    assert_eq!(report["replaces"], serde_json::json!(id_a));
    assert_eq!(report["window_days"], serde_json::json!(7));
    assert_eq!(report["trusted"], serde_json::json!(false));
    let id_b = report["key_id"].as_str().unwrap().to_string();

    let manifest = read_manifest(&dir, "m.json");
    assert_eq!(
        manifest.signatures.len(),
        2,
        "old signature kept, successor added: {:?}",
        manifest.signatures
    );
    assert!(manifest.signatures.contains_key(&id_a));
    assert!(manifest.signatures.contains_key(&id_b));

    // Either key's rule holds inside the window: the anchored (old) key
    // still verifies; the successor's signature exists but is not yet
    // trusted (no anchor until promote).
    let (code, _, stderr) = run_in(dir.path(), &["key", "verify", "m.json", &home]);
    assert_eq!(code, Some(0), "verify inside window: {stderr}");
    assert!(stderr.contains("verified under key id"));

    // ── promote ── the successor becomes the signing key.
    let (code, stdout, stderr) = run_in(dir.path(), &["key", "promote", &home, "--json"]);
    assert_eq!(code, Some(0), "promote: {stderr}");
    assert_eq!(report_json(&stdout)["key_id"], serde_json::json!(id_b));

    // ── rotate again ── second generation, default 30-day window,
    // dual-signing the manifest (now three signatures).
    let (code, stdout, stderr) = run_in(
        dir.path(),
        &["key", "rotate", "--manifest", "m.json", &home, "--json"],
    );
    assert_eq!(code, Some(0), "second rotate: {stderr}");
    let id_c = report_json(&stdout)["key_id"].as_str().unwrap().to_string();
    assert_ne!(id_c, id_b);
    let (code, _, stderr) = run_in(dir.path(), &["key", "promote", &home]);
    assert_eq!(code, Some(0), "second promote: {stderr}");
    assert_eq!(read_manifest(&dir, "m.json").signatures.len(), 3);

    // ── revoke ── the middle generation drops out; dated in the ledger.
    let (code, stdout, stderr) = run_in(dir.path(), &["key", "revoke", &id_b, &home, "--json"]);
    assert_eq!(code, Some(0), "revoke: {stderr}");
    assert!(report_json(&stdout)["revoked_at"].is_string());

    // only-new (and old-a) verify: the revoked key is skipped, not a
    // retroactive break.
    let (code, _, stderr) = run_in(dir.path(), &["key", "verify", "m.json", &home]);
    assert_eq!(code, Some(0), "post-revoke verify: {stderr}");
    assert!(
        !stderr.contains("REVOKED"),
        "no revocation warning for a re-signed manifest: {stderr}"
    );

    // A manifest signed ONLY by the revoked key fails with the named
    // error, naming the key.
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("m.json")).unwrap()).unwrap();
    let sigs = value["signatures"].as_object_mut().unwrap();
    let keep = sigs[&id_b].clone();
    sigs.clear();
    sigs.insert(id_b.clone(), keep);
    std::fs::write(dir.path().join("old-only.json"), value.to_string()).unwrap();
    let (code, _, stderr) = run_in(dir.path(), &["key", "verify", "old-only.json", &home]);
    assert_ne!(code, Some(0), "revoked-only manifest must fail");
    assert!(stderr.contains("REVOKED"), "named error: {stderr}");
    assert!(stderr.contains(&id_b), "names the revoked key: {stderr}");

    // ── list ── the audit trail shows the chain and the revocation.
    let (code, stdout, stderr) = run_in(dir.path(), &["key", "list", &home, "--json"]);
    assert_eq!(code, Some(0), "list: {stderr}");
    let ledger: shuttle::sign::CeremonyLedger =
        serde_json::from_value(report_json(&stdout)).expect("ledger json");
    let chain_a = &ledger.keys[&id_a];
    assert_eq!(chain_a.replaced_by.as_deref(), Some(id_b.as_str()));
    assert!(chain_a.rotated_at.is_some());
    assert_eq!(chain_a.window_days, Some(7));
    let chain_b = &ledger.keys[&id_b];
    assert_eq!(chain_b.replaced_by.as_deref(), Some(id_c.as_str()));
    assert_eq!(chain_b.window_days, Some(30));
    assert!(chain_b.revoked_at.is_some(), "revocation is dated");
    let chain_c = &ledger.keys[&id_c];
    assert!(chain_c.replaced_by.is_none(), "current generation");
    assert!(chain_c.revoked_at.is_none());
}

#[test]
fn tampered_ceremony_ledger_fails_key_verify() {
    let dir = tempfile::tempdir().unwrap();
    let home = format!("--home={}", dir.path().display());
    write_unsigned_manifest(&dir, "m.json");

    for args in [
        vec!["key", "keygen", home.as_str()],
        vec!["key", "rotate", "--manifest", "m.json", home.as_str()],
        vec!["key", "promote", home.as_str()],
    ] {
        let (code, _, stderr) = run_in(dir.path(), &args);
        assert_eq!(code, Some(0), "{args:?}: {stderr}");
    }
    let (code, _, _) = run_in(dir.path(), &["key", "verify", "m.json", home.as_str()]);
    assert_eq!(code, Some(0), "clean ledger verifies");

    // Tamper: the ledger stops being interpretable, verify fails closed.
    let ledger = dir.path().join(".config/shuttle/keys/ceremony.json");
    std::fs::write(&ledger, "{\"version\":1,\"keys\":{\"zz\":").unwrap();
    let (code, _, stderr) = run_in(dir.path(), &["key", "verify", "m.json", home.as_str()]);
    assert_ne!(code, Some(0), "tampered ledger must fail closed");
    assert!(stderr.contains("corrupt"), "named error: {stderr}");
}
