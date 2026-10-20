//! `nau pod list` version provenance (issue #3).
//!
//! A listed version may come from three places, and the output must say
//! which: the pod's ACTIVE generation (installed), the pod lockfile
//! (pinned), or the package recipe (recipe). The lockfile may also carry
//! the pre-rename `shuttle.lock` name (ADR-0031) — its pins must be
//! honoured exactly like a `nau.lock` pin.
//!
//! Drives the real binary against tempdir state roots, like
//! `tests/pod_cmd.rs`: nothing touches the real home.

use std::path::Path;
use std::process::Command;

fn run(project: &Path, root: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nau"));
    cmd.arg("pod").args(args).arg("--root").arg(root);
    cmd.current_dir(project);
    cmd.env("NAU_DATA_HOME", root.join("data-home"));
    cmd.env("NAU_SYSTEMD", "off");
    for var in ["LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "COMPILER_PATH"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("failed to spawn nau pod");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Create a resolvable package declaration in the project's `pkgs/` tree.
fn write_pkg(project: &Path, name: &str, version: &str) {
    let letter = name.chars().next().unwrap().to_ascii_lowercase();
    let dir = project.join("pkgs").join(letter.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.lua")),
        format!("return {{ default = snap {{ name = \"{name}\", version = \"{version}\" }} }}\n"),
    )
    .unwrap();
}

/// Write a pod declaration. `extra` is spliced in as an additional
/// top-level `pod {}` field (an overlay, typically).
fn write_pod(root: &Path, pod: &str, packages: &[&str], extra: &str) {
    let dir = root.join(pod);
    std::fs::create_dir_all(&dir).unwrap();
    let list = packages
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        dir.join("pod.lua"),
        format!("pod {{\n    packages = {{ {list} }},\n{extra}}}\n"),
    )
    .unwrap();
}

/// Write a lockfile under `filename` pinning `name` to `version`.
fn write_lock(root: &Path, pod: &str, filename: &str, name: &str, version: &str) {
    let lock = serde_json::json!({
        "version": 1,
        "packages": { name: { "version": version } },
    });
    std::fs::write(
        root.join(pod).join(filename),
        serde_json::to_string(&lock).unwrap(),
    )
    .unwrap();
}

/// Write generation `n` recording `packages` as installed, and point the
/// pod's `active` link at it.
fn write_generation(root: &Path, pod: &str, n: u64, packages: &[(&str, &str)]) {
    let installed: serde_json::Map<String, serde_json::Value> = packages
        .iter()
        .map(|(name, version)| {
            (
                name.to_string(),
                serde_json::json!({
                    "name": name,
                    "version": version,
                    "revision": 0,
                    "sha3_384": "00",
                    "files": [],
                    "units": [],
                }),
            )
        })
        .collect();
    let manifest = serde_json::json!({
        "n": n,
        "base_version": "24.04",
        "packages": installed,
        "created_epoch": 0,
        "boot_entry": null,
    });
    let gen_dir = root.join(pod).join("generations").join(n.to_string());
    std::fs::create_dir_all(&gen_dir).unwrap();
    std::fs::write(
        gen_dir.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(format!("generations/{n}"), root.join(pod).join("active")).unwrap();
}

/// The whitespace-separated tokens of the output line for `name`.
fn row(output: &str, name: &str) -> Vec<String> {
    let line = output
        .lines()
        .find(|line| line.split_whitespace().next() == Some(name))
        .unwrap_or_else(|| panic!("no output row for '{name}' in:\n{output}"));
    line.split_whitespace().map(str::to_string).collect()
}

// ── the pre-rename lockfile ──

#[test]
fn shuttle_lock_pins_are_honoured() {
    // A pod created before the shuttle → nau rename (ADR-0031) carries
    // only `shuttle.lock`. Its pins are the pod's resolution record and
    // must beat the recipe, which now declares a newer version.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pod(root.path(), "gate", &["gcc"], "");
    write_lock(root.path(), "gate", "shuttle.lock", "gcc", "14.2.0");

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "gate"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let cells = row(&stderr, "gcc");
    assert_eq!(cells[1], "14.2.0", "shuttle.lock pin must win: {stderr}");
    assert_eq!(cells[2], "pinned", "source must say pinned: {stderr}");
    assert!(
        !stderr.contains("16.2.0"),
        "the recipe version must not appear: {stderr}"
    );
}

#[test]
fn canonical_lock_wins_when_both_names_exist() {
    // Pods written after the rename carry both names; the canonical file
    // is the complete, newer record.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pod(root.path(), "gate", &["gcc"], "");
    write_lock(root.path(), "gate", "shuttle.lock", "gcc", "13.0.0");
    write_lock(root.path(), "gate", "nau.lock", "gcc", "15.0.0");

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "gate"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(row(&stderr, "gcc")[1], "15.0.0", "{stderr}");
}

// ── installed version wins ──

#[test]
fn installed_version_wins_over_pin_and_recipe() {
    // The gate pod's real shape: the active generation records the
    // installed version, the lockfile pins another, the recipe another.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pkg(project.path(), "rust", "1.99.0");
    write_pod(root.path(), "gate", &["gcc", "rust"], "");
    write_lock(root.path(), "gate", "shuttle.lock", "gcc", "15.0.0");
    write_generation(
        root.path(),
        "gate",
        41,
        &[("gcc", "14.2.0"), ("rust", "1.97.1")],
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "gate"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let gcc = row(&stderr, "gcc");
    assert_eq!(gcc[1], "14.2.0", "installed version must win: {stderr}");
    assert_eq!(gcc[2], "installed", "source must say installed: {stderr}");
    let rust = row(&stderr, "rust");
    assert_eq!(rust[1], "1.97.1", "{stderr}");
    assert_eq!(rust[2], "installed", "{stderr}");
    assert!(
        !stderr.contains("16.2.0") && !stderr.contains("1.99.0"),
        "recipe versions must not be reported for installed packages: {stderr}"
    );
}

#[test]
fn recipe_fills_a_package_the_generation_does_not_have() {
    // A package added after the last sync has no installed record; the
    // row falls back through pin to the recipe, per package.
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pkg(project.path(), "jq", "1.7.1");
    write_pod(root.path(), "gate", &["gcc", "jq"], "");
    write_generation(root.path(), "gate", 41, &[("gcc", "14.2.0")]);

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "gate"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(row(&stderr, "gcc")[2], "installed", "{stderr}");
    let jq = row(&stderr, "jq");
    assert_eq!(jq[1], "1.7.1", "{stderr}");
    assert_eq!(jq[2], "recipe", "{stderr}");
}

// ── the three-way split with no generation ──

#[test]
fn no_generation_no_lock_reports_the_recipe() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "jq", "1.7.1");
    write_pod(root.path(), "work", &["jq"], "");

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "work"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let cells = row(&stderr, "jq");
    assert_eq!(cells[1], "1.7.1", "{stderr}");
    assert_eq!(
        cells[2], "recipe",
        "a recipe match must not look pinned: {stderr}"
    );
}

#[test]
fn pin_and_recipe_are_distinguishable_in_one_listing() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pkg(project.path(), "jq", "1.7.1");
    write_pod(root.path(), "gate", &["gcc", "jq"], "");
    write_lock(root.path(), "gate", "nau.lock", "gcc", "14.2.0");

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "gate"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(row(&stderr, "gcc")[2], "pinned", "{stderr}");
    assert_eq!(row(&stderr, "jq")[2], "recipe", "{stderr}");
}

// ── float marking survives ──

#[test]
fn float_marking_survives_beside_the_source() {
    let project = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write_pkg(project.path(), "gcc", "16.2.0");
    write_pod(
        root.path(),
        "work",
        &["gcc"],
        "    overlay = { gcc = { floating = true } },\n",
    );

    let (code, _, stderr) = run(project.path(), root.path(), &["list", "--name", "work"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let cells = row(&stderr, "gcc");
    assert_eq!(cells[2], "recipe", "{stderr}");
    assert_eq!(
        cells[3], "(float)",
        "the ADR-0017 float tag survives: {stderr}"
    );
}
