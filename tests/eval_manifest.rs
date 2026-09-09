//! Phase 23 image manifest IR integration tests.
//!
//! Drives the real `shuttle eval` binary over network-free paths: fully
//! pinned image snaps, `path:` inputs, lockfile pins, and package-index
//! pins. Covers determinism (byte-identical reruns), the schema version
//! field, `--offline` behavior, fail-closed on missing pins (no manifest
//! file may appear on failure), and selection. All store/github fetching
//! paths are deliberately avoided.

use std::process::Command;

const HASH_BASE: &str = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
const HASH_EXTRA: &str = "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

/// Run shuttle with an isolated HOME so the inputs cache root is private
/// to the test and no global state can leak in.
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

/// A fully offline-capable project: one `path:` input, one snap output,
/// one image whose snaps carry full pins (revision + content hash) in the
/// definition — eval never needs the network.
fn setup_pinned_project() -> (tempfile::TempDir, tempfile::TempDir) {
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
        summary = "manifest fixture",
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

// ── Determinism ──

#[test]
fn eval_twice_produces_byte_identical_manifests() {
    let (dir, home) = setup_pinned_project();

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "eval",
            "--offline",
            "--lockfile",
            "proj.lock",
            "-o",
            "m1.json",
        ],
    );
    assert_eq!(code, Some(0), "first eval: {stderr}");

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "eval",
            "--offline",
            "--lockfile",
            "proj.lock",
            "-o",
            "m2.json",
        ],
    );
    assert_eq!(code, Some(0), "second eval: {stderr}");

    let m1 = std::fs::read(dir.path().join("m1.json")).unwrap();
    let m2 = std::fs::read(dir.path().join("m2.json")).unwrap();
    assert_eq!(
        m1, m2,
        "same definition + lockfile must give byte-identical JSON"
    );

    // No temp residue from either atomic write.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(entries.is_empty(), "no .tmp residue: {entries:?}");
}

#[test]
fn eval_stdout_and_file_output_agree() {
    let (dir, home) = setup_pinned_project();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "stdout eval: {stderr}");

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "eval",
            "--offline",
            "--lockfile",
            "proj.lock",
            "-o",
            "m.json",
        ],
    );
    assert_eq!(code, Some(0), "file eval: {stderr}");

    let from_file = std::fs::read_to_string(dir.path().join("m.json")).unwrap();
    assert_eq!(
        stdout, from_file,
        "stdout mode must emit the same bytes as -o"
    );
}

// ── Schema ──

#[test]
fn eval_manifest_carries_version_inputs_outputs_images_signatures() {
    let (dir, home) = setup_pinned_project();
    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}): {stdout}"));

    assert_eq!(v["manifest_version"], 1, "schema version field: {v}");
    assert_eq!(
        v["signatures"],
        serde_json::json!({}),
        "signatures reserved: {v}"
    );

    // Inputs: the path: input is local and unlocked.
    assert_eq!(v["inputs"]["vendored"]["url"], "path:vendor");
    assert_eq!(v["inputs"]["vendored"]["local"], true);

    // Outputs: identity + Phase 22a closure key + explicit unbuilt artifact.
    assert_eq!(v["outputs"]["app"]["name"], "demo-app");
    assert_eq!(v["outputs"]["app"]["version"], "1.2.3");
    assert_eq!(v["outputs"]["app"]["archs"], serde_json::json!(["amd64"]));
    let key = v["outputs"]["app"]["closure_key"]
        .as_str()
        .expect("closure key");
    assert!(
        key.starts_with("v3:"),
        "Phase 22a closure key required: {v}"
    );
    assert_eq!(v["outputs"]["app"]["artifact"]["state"], "unbuilt");

    // Images: resolved contents with full pins.
    let img = &v["images"]["system"];
    assert_eq!(img["name"], "demo-system");
    assert_eq!(img["version"], "2.0.0");
    assert_eq!(img["arch"], "amd64");
    assert_eq!(img["artifact"]["state"], "unbuilt");
    let snaps = img["snaps"].as_array().expect("snaps array");
    assert_eq!(snaps.len(), 2, "base + extra: {v}");
    assert_eq!(snaps[0]["role"], "base");
    assert_eq!(snaps[0]["name"], "core22");
    assert_eq!(snaps[0]["revision"], 1847);
    assert_eq!(snaps[0]["sha3_384"], HASH_BASE);
    assert_eq!(snaps[0]["pin_source"], "definition");
    assert_eq!(snaps[1]["role"], "extra");
    assert_eq!(snaps[1]["pin_source"], "definition");
}

// ── Lockfile + index pin sources ──

#[test]
fn eval_resolves_lockfile_pins_offline() {
    let (dir, home) = setup_pinned_project();
    // Name-only pin in the definition; the lockfile carries the pin.
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    system = image {
        name = "demo-system",
        version = "2.0.0",
        base = pin("core22"),
    },
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("proj.lock"),
        format!(
            r#"{{
  "version": 1,
  "snaps": {{
    "core22": {{ "revision": 1847, "sha3-384": "{HASH_BASE}" }}
  }}
}}"#
        ),
    )
    .unwrap();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "lockfile pin must resolve offline: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["images"]["system"]["snaps"][0]["pin_source"], "lockfile");
    assert_eq!(v["images"]["system"]["snaps"][0]["sha3_384"], HASH_BASE);
}

#[test]
fn eval_resolves_package_index_pins_offline() {
    let (dir, home) = setup_pinned_project();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    system = image {
        name = "demo-system",
        version = "2.0.0",
        base = pin("indexed-snap"),
    },
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("package-index.json"),
        format!(
            r#"{{
  "version": 1,
  "snaps": [
    {{
      "name": "indexed-snap",
      "pins": {{ "amd64": {{ "revision": 4242, "sha3-384": "{HASH_EXTRA}" }} }}
    }}
  ]
}}"#
        ),
    )
    .unwrap();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "index pin must resolve offline: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let snap = &v["images"]["system"]["snaps"][0];
    assert_eq!(snap["pin_source"], "index");
    assert_eq!(snap["revision"], 4242);
    assert_eq!(snap["sha3_384"], HASH_EXTRA);
}

// ── Fail-closed ──

#[test]
fn eval_fails_closed_on_missing_pins_and_writes_nothing() {
    let (dir, home) = setup_pinned_project();
    // Unpinned base, no lockfile, no index: nothing to resolve from.
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
return {
    system = image {
        name = "demo-system",
        version = "2.0.0",
        base = pin("core22"),
    },
}
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &[
            "eval",
            "--offline",
            "--lockfile",
            "proj.lock",
            "-o",
            "image.json",
        ],
    );
    assert_ne!(code, Some(0), "missing pins must fail eval");
    assert!(
        stdout.is_empty(),
        "no manifest may be emitted as success: {stdout}"
    );
    // miette wraps with continuation bars; flatten before matching.
    let flat = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("core22") && flat.contains("unresolved"),
        "named fail-closed error required, got: {stderr}"
    );
    assert!(
        !dir.path().join("image.json").exists(),
        "a failed eval must never leave a manifest behind"
    );
}

#[test]
fn eval_offline_github_input_without_lock_pin_fails_named() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("shuttle.lua"),
        r#"
inputs = { remote = { url = "github:owner/repo/main" } }
return {}
"#,
    )
    .unwrap();

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_ne!(code, Some(0), "uncached github input must fail offline");
    // miette wraps with continuation bars; strip them before matching.
    let flat = stderr.replace('│', " ");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("--offline prevents fetching"),
        "named offline error required, got: {stderr}"
    );
    assert!(
        !dir.path().join("image.json").exists(),
        "no manifest on failure"
    );
}

// ── Selection ──

#[test]
fn eval_selects_a_single_output_or_image() {
    let (dir, home) = setup_pinned_project();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock", "system"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["images"].as_object().map(|o| o.len()), Some(1));
    assert_eq!(
        v["outputs"].as_object().map(|o| o.len()),
        Some(0),
        "selection filters both maps: {v}"
    );

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock", "app"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["outputs"].as_object().map(|o| o.len()), Some(1));
    assert_eq!(v["images"].as_object().map(|o| o.len()), Some(0));

    let (code, _, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock", "nope"],
    );
    assert_ne!(code, Some(0), "unknown selection must fail");
    assert!(stderr.contains("nope"), "named error required: {stderr}");
}

// ── Closure keys over local dependency packages ──

#[test]
fn eval_closure_key_resolves_local_requires() {
    let (dir, home) = setup_pinned_project();
    // requires resolved from the CWD pkgs/ tree — no inputs needed.
    std::fs::create_dir_all(dir.path().join("pkgs/m")).unwrap();
    std::fs::write(
        dir.path().join("pkgs/m/mylib.lua"),
        r#"
return { mylib = snap { name = "mylib", version = "0.1.0" } }
"#,
    )
    .unwrap();
    let def = dir.path().join("shuttle.lua");
    let mut src = std::fs::read_to_string(&def).unwrap();
    src = src.replace(
        "summary = \"manifest fixture\",",
        "summary = \"manifest fixture\",\n        requires = { \"mylib\" },",
    );
    std::fs::write(&def, src).unwrap();

    let (code, stdout, stderr) = run_in(
        dir.path(),
        home.path(),
        &["eval", "--offline", "--lockfile", "proj.lock"],
    );
    assert_eq!(code, Some(0), "{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let key = v["outputs"]["app"]["closure_key"]
        .as_str()
        .expect("closure key");
    assert!(key.starts_with("v3:"), "{v}");
}
