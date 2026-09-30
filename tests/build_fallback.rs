//! `nau build`'s fallback must never launder a direct-eval refusal into
//! a silent local-only build (#297): an existing config file whose eval
//! fails — a malformed workers table, say — is terminal. The fallback
//! (the default input + package-name resolution) exists only for a
//! nonexistent positional, and its plain eval never validates the
//! workers surface. Drives the real binary, exactly like
//! tests/stage_lock.rs.

use std::process::Command;

/// A shape-valid workers entry except the pin: a retired/garbage
/// `host_key` — the exact live failure that found #297 (a template
/// error became a successful local-only build).
const WORKERS_SHAPE_ERROR: &str = r#"
workers = {
    { address = "ssh://farm-worker.example", host_key = "not-a-pin" },
}
return {
    default = snap {
        name = "farm-hello",
        version = "1.0",
    },
}
"#;

#[test]
fn broken_workers_config_refuses_the_build_instead_of_building_locally() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("nau.lua"), WORKERS_SHAPE_ERROR).unwrap();
    let out = project.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_nau"))
        .arg("build")
        .arg("snap")
        .arg("--output")
        .arg(&out)
        .arg("--offline")
        .current_dir(project.path())
        .output()
        .expect("failed to spawn nau build");

    assert_ne!(
        result.status.code(),
        Some(0),
        "a broken workers config must refuse the build"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("workers[1]"),
        "refusal must be the direct eval error, named by entry: {stderr}"
    );
    // Short fragments: miette wraps stderr, so no long literal survives.
    assert!(
        stderr.contains("got 'not-a-pin'") && stderr.contains("re-pin"),
        "refusal must carry the workers shape error, not a fallback diagnostic: {stderr}"
    );
    assert!(
        !out.join("farm-hello_1.0_amd64.snap").exists(),
        "no snap may be produced off a refused config"
    );
}

// ── `pool burst --count auto` (#304): the extracted pending
// computation, driven end to end through the real binary. The sizing
// decision must land on stderr BEFORE any API call — these bursts never
// get past it (no CA, no publish channel), which is exactly the
// fail-closed point.

/// A minimal dep recipe; served from `pkgs/<letter>/<name>.lua`, which is
/// how the dep graph's names resolve (nodes carry the DECLARED name, not
/// the seed path).
fn burst_dep_recipe(letter: &str) -> String {
    format!("return {{ d = snap {{ name = \"dep-{letter}\", version = \"1.0\" }} }}\n")
}

#[test]
fn burst_auto_sizes_the_wrapped_builds_pending_jobs() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("pkgs/d")).unwrap();
    for letter in ["a", "b", "c", "d", "e"] {
        std::fs::write(
            project.path().join(format!("pkgs/d/dep-{letter}.lua")),
            burst_dep_recipe(letter),
        )
        .unwrap();
    }
    // An offline-resolvable declared input: an empty config would fall
    // through init_global_inputs_with to the default github input, which
    // is exactly the refusal the wrapped build itself would hit offline.
    std::fs::create_dir_all(project.path().join("fixtures")).unwrap();
    let deps = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|l| format!("\"dep-{l}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        project.path().join("nau.lua"),
        format!(
            "inputs = {{ lib = {{ url = \"path:fixtures\" }} }}\n\
             return {{ app = snap {{ name = \"burst-auto\", version = \"1.0\", \
             build_deps = {{ {deps} }} }} }}\n"
        ),
    )
    .unwrap();

    // No cache, no --all overrides: all five deps are pending. With the
    // default 2 jobs/worker and --max 4, ceil(5/2) = 3. The burst wraps
    // the build in the ADR-0049 domain spelling — `pool burst` sizing
    // `build snap` — the same pending set the legacy spellings size.
    let result = Command::new(env!("CARGO_BIN_EXE_nau"))
        .env("HOME", project.path())
        .args([
            "pool",
            "burst",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
            "--count",
            "auto",
            "--max",
            "4",
            "--",
            "build",
            "snap",
            "--offline",
            "--output",
            "out",
        ])
        .current_dir(project.path())
        .output()
        .expect("failed to spawn nau pool burst");

    assert_ne!(
        result.status.code(),
        Some(0),
        "no CA / no publish channel must stop the burst after sizing"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("5 pending"),
        "the sizing line must name the pending count: {stderr}"
    );
    assert!(
        stderr.contains("provisioning 3 workers"),
        "the sizing decision must name the chosen count (ceil(5/2)=3): {stderr}"
    );
    assert!(
        stderr.contains("max 4"),
        "the sizing line must name the guard: {stderr}"
    );
}

#[test]
fn burst_auto_refuses_zero_pending_before_any_api_call() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("fixtures")).unwrap();
    std::fs::write(
        project.path().join("nau.lua"),
        "inputs = { lib = { url = \"path:fixtures\" } }\n\
         return { app = snap { name = \"burst-zero\", version = \"1.0\" } }\n",
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_nau"))
        .env("HOME", project.path())
        .args([
            "pool",
            "burst",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
            "--count",
            "auto",
            "--",
            "build",
            "snap",
            "--offline",
        ])
        .current_dir(project.path())
        .output()
        .expect("failed to spawn nau pool burst");

    assert_ne!(result.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("0 pending"),
        "zero pending must refuse by name: {stderr}"
    );
    assert!(
        stderr.contains("nothing to build"),
        "the refusal must say why nothing is provisioned: {stderr}"
    );
}

#[test]
fn burst_auto_refuses_a_non_build_wrapped_command() {
    let project = tempfile::tempdir().unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_nau"))
        .env("HOME", project.path())
        .args([
            "pool",
            "burst",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
            "--count",
            "auto",
            "--",
            "echo",
            "hi",
        ])
        .current_dir(project.path())
        .output()
        .expect("failed to spawn nau pool burst");

    assert_ne!(result.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&result.stderr);
    // Short fragments only: miette wraps stderr mid-sentence.
    assert!(
        stderr.contains("echo hi"),
        "the refusal must name the wrapped command: {stderr}"
    );
    assert!(
        stderr.contains("no pending set"),
        "the refusal must name why sizing is impossible: {stderr}"
    );
}

#[test]
fn burst_auto_refuses_a_domain_non_build_wrapped_command() {
    // `build cache` sits INSIDE the build group but is not a build —
    // the sizing must refuse it by name, never size a cache verb.
    let project = tempfile::tempdir().unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_nau"))
        .env("HOME", project.path())
        .args([
            "pool",
            "burst",
            "--provider",
            "hetzner",
            "--type",
            "CX33",
            "--location",
            "hel1",
            "--count",
            "auto",
            "--",
            "nau",
            "build",
            "cache",
            "info",
        ])
        .current_dir(project.path())
        .output()
        .expect("failed to spawn nau pool burst");

    assert_ne!(result.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&result.stderr);
    // Short fragments only: miette wraps stderr mid-sentence.
    assert!(
        stderr.contains("nau build cache"),
        "the refusal must name the wrapped command: {stderr}"
    );
    assert!(
        stderr.contains("no pending set"),
        "the refusal must name why sizing is impossible: {stderr}"
    );
}
