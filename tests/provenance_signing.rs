//! Issue #56 — SLSA-lite provenance under the manifest signature, end to
//! end through the real binary. `shuttle key keygen` + `shuttle eval`
//! attach the attested envelope (`{"signature": …, "provenance": …}`) to
//! the signatures map; the claims ride UNDER the signature, never in the
//! canonical body, and an unsigned eval keeps `signatures` exactly `{}`.
//! All paths are network-free (offline eval over definition pins).

use std::process::Command;

const HASH_BASE: &str = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
const HASH_EXTRA: &str = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

/// Run shuttle with an isolated HOME so the key ceremony and inputs cache
/// are private to the test.
fn run_in(
    dir: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_shuttle"))
        .args(args)
        .env("HOME", home)
        .current_dir(dir)
        .output()
        .expect("failed to spawn shuttle");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A fully offline-capable project (same shape as eval_manifest.rs).
fn setup_project() -> (tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        format!(
            r#"
inputs = {{ vendored = {{ url = "path:vendor" }} }}
return {{
    app = snap {{
        name = "demo-app",
        version = "1.2.3",
        summary = "provenance fixture",
        architectures = {{ "amd64" }},
    }},
    system = image {{
        name = "demo-system",
        version = "2.0.0",
        base = pin("core22", {{ revision = 1847, sha3_384 = "{HASH_BASE}" }}),
        snaps = {{ pin("extra-snap", {{ revision = 30000, sha3_384 = "{HASH_EXTRA}" }}) }},
    }},
}}
"#
        ),
    )
    .unwrap();
    (dir, home)
}

#[test]
fn eval_with_a_signing_key_attaches_provenance() {
    let (dir, home) = setup_project();
    let home_str = home.path().to_str().unwrap().to_string();

    // Mint the key the eval path looks for.
    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["key", "keygen", "--home", &home_str],
    );
    assert_eq!(code, Some(0), "keygen: {stderr}");

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "eval: {stderr}");
    assert!(
        stderr.contains("manifest signed with provenance"),
        "sign success must be surfaced: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}): {stdout}"));

    // Exactly one entry, shaped as the attested envelope.
    let sigs = v["signatures"].as_object().expect("signatures object");
    assert_eq!(sigs.len(), 1, "one signer: {v}");
    let entry = sigs.values().next().unwrap();
    assert!(
        entry.get("signature").is_some() && entry.get("provenance").is_some(),
        "attested envelope, not a bare string: {entry}"
    );

    // The SLSA-lite claims: builder, invocation, materials, subject.
    let prov = &entry["provenance"];
    assert_eq!(prov["version"], 1, "{prov}");
    assert_eq!(
        prov["builder_id"],
        format!("shuttle:{}", env!("CARGO_PKG_VERSION")),
        "builder id is the running shuttle version: {prov}"
    );
    assert_eq!(prov["invocation"]["arch"], "amd64", "{prov}");
    assert_eq!(prov["invocation"]["channel"], "latest/stable", "{prov}");
    assert_eq!(prov["invocation"]["offline"], true, "{prov}");

    // Materials mirror the manifest's own declared inputs.
    assert_eq!(
        prov["materials"], v["inputs"],
        "attested inventory must equal the manifest inputs: {prov} vs {}",
        v["inputs"]
    );

    // The subject digest is a sha3-384 hex over the (never-visible-here)
    // canonical body — 96 hex chars is the shape contract.
    let digest = prov["subject"]["manifest_sha3_384"]
        .as_str()
        .expect("subject digest");
    assert_eq!(digest.len(), 96, "sha3-384 hex: {prov}");
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()), "{prov}");
    assert_eq!(prov["subject"]["name"], "manifest", "{prov}");
}

#[test]
fn signed_evals_stay_byte_identical_and_unsigned_evals_keep_the_reservation() {
    let (dir, home) = setup_project();
    let home_str = home.path().to_str().unwrap().to_string();
    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["key", "keygen", "--home", &home_str],
    );
    assert_eq!(code, Some(0), "keygen: {stderr}");

    for name in ["m1.json", "m2.json"] {
        let (code, _, stderr) = run_in(
            dir.path(),
            home.path(),
            &["eval", "--offline", "--lockfile", "proj.lock", "-o", name],
        );
        assert_eq!(code, Some(0), "{name}: {stderr}");
    }
    let m1 = std::fs::read(dir.path().join("m1.json")).unwrap();
    let m2 = std::fs::read(dir.path().join("m2.json")).unwrap();
    assert_eq!(
        m1, m2,
        "provenance carries no timestamps — signed evals stay byte-identical"
    );

    // A project without a signing key keeps the reserved empty object —
    // the compat anchor for every pre-#56 consumer.
    let (dir2, home2) = setup_project();
    let (code, stdout, stderr) = run_in(
        dir2.path(),
        home2.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["signatures"],
        serde_json::json!({}),
        "no key → empty reservation: {v}"
    );
}
