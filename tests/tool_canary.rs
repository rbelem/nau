//! Fail-loud canaries for the tools `gated_test!` skips on (issue #134).
//!
//! `gated_test!` early-returns with an eprintln cargo hides, so a missing
//! tool leaves whole suites green while never running — a devbox pin
//! regression used to surface only in CI, months late. One ungated test
//! per gated tool asserts the tool resolves on the PATH the test process
//! sees, using the same `which` resolution the gates use, so a missing
//! tool fails here instead of skipping.

use std::process::Command;

/// Resolve `tool` on the test process's PATH, panicking with the tool's
/// name and where it is expected from when absent.
fn assert_on_path(tool: &str, origin: &str) {
    let found = Command::new("which")
        .arg(tool)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some();
    assert!(
        found,
        "`{tool}` does not resolve on PATH — the gated suites would skip \
         silently; expected from {origin}"
    );
}

#[test]
fn canary_mksquashfs_on_path() {
    assert_on_path("mksquashfs", "the devbox.json squashfsTools pin");
}

#[test]
fn canary_unsquashfs_on_path() {
    assert_on_path("unsquashfs", "the devbox.json squashfsTools pin");
}

#[test]
fn canary_curl_on_path() {
    assert_on_path("curl", "the devbox environment or host system");
}

#[test]
fn canary_tar_on_path() {
    assert_on_path("tar", "the devbox environment (see devbox.json)");
}

#[test]
fn canary_gcc_on_path() {
    assert_on_path("gcc", "the devbox environment (see devbox.json)");
}

#[test]
fn canary_node_on_path() {
    assert_on_path("node", "the devbox.json nodejs pin");
}

#[test]
fn canary_python3_on_path() {
    assert_on_path("python3", "the devbox.json python3 pin");
}

/// The go closure tests additionally require host `go` to be
/// sandbox-visible (a go resolving only from an unbound PATH entry fails
/// the build pre-flight by design); this canary covers the resolution
/// half — that a `go` exists on PATH at all.
#[test]
fn canary_go_on_path() {
    assert_on_path(
        "go",
        "the host toolchain (not a devbox.json pin; must also be \
         sandbox-visible for the go closure tests)",
    );
}
