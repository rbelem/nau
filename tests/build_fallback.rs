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
