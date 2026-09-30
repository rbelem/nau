//! External-subcommand dispatch (ADR-0049 Decision 5, issue #324).
//!
//! Drives a copy of the real binary: `nau <unknown>` resolves
//! `nau-<unknown>` (exe-dir sibling first, then PATH — never an env
//! override), execs it with the remaining argv verbatim, and propagates
//! its exit code. Known verbs are never shadowable by planted
//! `nau-<name>` lookalikes; invalid verb names are named refusals
//! before any lookup.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A copy of the nau binary inside its own directory, so the exe-dir
/// sibling stage of the resolution order is fully controlled by the
/// test (the real target/debug dir must stay untouched). Hard-link
/// when the temp dir shares the source's filesystem — a link never
/// write-opens the exec'd inode, the ETXTBSY-safe path — falling back
/// to a byte copy (which preserves permission bits) across
/// filesystems.
fn nau_copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("nau");
    if std::fs::hard_link(env!("CARGO_BIN_EXE_nau"), &copy).is_err() {
        std::fs::copy(env!("CARGO_BIN_EXE_nau"), &copy).unwrap();
    }
    (dir, copy)
}

/// Plant an executable shell script.
fn plant(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Spawn and wait, retrying briefly on ETXTBSY (`ExecutableFileBusy`):
/// exec'ing a just-materialized binary can transiently race a writer
/// still holding the inode open — a harness artifact, not a nau
/// behavior.
fn output_retrying_busy(cmd: &mut Command) -> std::process::Output {
    const ATTEMPTS: u32 = 3;
    for attempt in 1..=ATTEMPTS {
        match cmd.output() {
            Ok(out) => return out,
            Err(err)
                if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < ATTEMPTS =>
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("failed to spawn nau: {err}"),
        }
    }
    unreachable!("the retry loop either returns or panics")
}

/// Run the copied nau with PATH pinned to `path_dir` (only).
fn run_with_path(nau: &Path, path_dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = output_retrying_busy(Command::new(nau).args(args).env("PATH", path_dir));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        flatten(&out.stderr),
    )
}

/// Collapse miette's rendered line-wrapping (whitespace + the `│`
/// gutter it inserts at wrap points) so assertions can match on the
/// message text rather than the wrap layout.
fn flatten(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '│')
        .collect()
}

/// Match a needle against [`flatten`]ed output.
fn contains_flat(haystack: &str, needle: &str) -> bool {
    haystack.contains(&flatten(needle.as_bytes()))
}

const SHADOW: &str = "#!/bin/sh\necho SHADOWED\nexit 99\n";

// ── Resolution order + exec semantics ──

#[test]
fn helper_on_path_runs_and_forwards_argv() {
    let (_nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap();
    plant(
        path_dir.path(),
        "nau-foo",
        "#!/bin/sh\necho \"foo-argv: $*\"\n",
    );
    let (code, stdout, stderr) = run_with_path(&nau, path_dir.path(), &["foo", "a", "-b"]);
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    // The verb is consumed; the remaining argv arrives verbatim
    // (hyphen-prefixed args included).
    assert_eq!(stdout, "foo-argv: a -b\n");
}

#[test]
fn helper_exit_code_propagates() {
    let (_nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap();
    plant(path_dir.path(), "nau-foo", "#!/bin/sh\nexit 42\n");
    let (code, _stdout, stderr) = run_with_path(&nau, path_dir.path(), &["foo"]);
    assert_eq!(code, Some(42), "stderr: {stderr}");
}

#[test]
fn exe_dir_sibling_takes_precedence_over_path() {
    let (nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap();
    plant(
        nau_dir.path(),
        "nau-foo",
        "#!/bin/sh\necho \"sibling $*\"\n",
    );
    plant(
        path_dir.path(),
        "nau-foo",
        "#!/bin/sh\necho \"pathdir $*\"\n",
    );
    let (code, stdout, stderr) = run_with_path(&nau, path_dir.path(), &["foo", "x"]);
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    assert_eq!(stdout, "sibling x\n");
}

// ── Known verbs are never shadowable ──

#[test]
fn planted_lookalikes_never_shadow_real_verbs() {
    let (nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap();
    // Shadows planted BOTH beside the binary and on PATH, for names
    // covering the public domain groups, the tooling verb, and the
    // hidden `__*` workers.
    for name in ["nau-chart", "nau-completion", "nau-__eval-worker"] {
        plant(nau_dir.path(), name, SHADOW);
        plant(path_dir.path(), name, SHADOW);
    }

    // A public domain group runs the real subcommand tree.
    let (code, stdout, stderr) = run_with_path(&nau, path_dir.path(), &["completion", "bash"]);
    assert_eq!(code, Some(0), "stdout: {stdout} stderr: {stderr}");
    assert!(stdout.contains("_nau()"), "real completion, got: {stdout}");
    assert!(!stdout.contains("SHADOWED") && !stderr.contains("SHADOWED"));

    // The chart group dispatches the real check (which fails on the
    // missing definition — but fails as ITSELF, never as the shadow).
    let (code, stdout, stderr) = run_with_path(&nau, path_dir.path(), &["chart", "check"]);
    assert_ne!(code, Some(99), "the planted nau-chart shadow ran");
    assert!(!stdout.contains("SHADOWED") && !stderr.contains("SHADOWED"));

    // A hidden internal worker still reaches the real worker main (it
    // refuses the empty request its parent never wrote — fast, nonzero,
    // and decidedly not the planted script).
    let out = output_retrying_busy(
        Command::new(&nau)
            .args(["__eval-worker"])
            .env("PATH", path_dir.path())
            .stdin(std::process::Stdio::null()),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = flatten(&out.stderr);
    assert_ne!(out.status.code(), Some(99), "the planted shadow ran");
    assert!(!stdout.contains("SHADOWED") && !stderr.contains("SHADOWED"));
}

// ── Named refusals ──

#[test]
fn invalid_verb_names_are_named_refusals_before_any_lookup() {
    let (_nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap();
    for bad in [
        vec!["foo.bar"],
        vec!["--", "-x"],
        vec!["Foo"],
        vec!["foo/bar"],
        vec![""],
    ] {
        let (code, _stdout, stderr) = run_with_path(&nau, path_dir.path(), &bad);
        assert_ne!(code, Some(0), "{bad:?} must be refused");
        assert!(
            contains_flat(&stderr, "must match [a-z][a-z0-9-]*"),
            "{bad:?}: expected the charset refusal, got: {stderr}"
        );
    }
}

#[test]
fn unknown_verb_without_helper_is_a_named_refusal() {
    let (_nau_dir, nau) = nau_copy();
    let path_dir = tempfile::tempdir().unwrap(); // empty PATH: no helper anywhere
    let (code, _stdout, stderr) = run_with_path(&nau, path_dir.path(), &["definitely-not-a-verb"]);
    assert_ne!(code, Some(0));
    assert!(
        contains_flat(&stderr, "unknown command `definitely-not-a-verb`")
            && contains_flat(&stderr, "no `nau-definitely-not-a-verb` extension found"),
        "expected the named not-found refusal, got: {stderr}"
    );
}

#[test]
fn no_environment_variable_overrides_the_lookup() {
    let (_nau_dir, nau) = nau_copy();
    let helper_dir = tempfile::tempdir().unwrap();
    plant(helper_dir.path(), "nau-foo", "#!/bin/sh\necho HIJACKED\n");
    let path_dir = tempfile::tempdir().unwrap();
    // Planted override candidates must be ignored; the helper found
    // only via PATH runs.
    let out = output_retrying_busy(
        Command::new(&nau)
            .args(["foo"])
            .env("PATH", path_dir.path())
            .env("NAU_EXT_PATH", helper_dir.path())
            .env("NAU_PATH", helper_dir.path())
            .env("NAU_EXEC_PATH", helper_dir.path())
            .env("NAU_HELPER_DIR", helper_dir.path()),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = flatten(&out.stderr);
    assert!(!stdout.contains("HIJACKED") && !stderr.contains("HIJACKED"));
    assert!(
        contains_flat(&stderr, "no `nau-foo` extension found"),
        "expected the named not-found refusal, got: {stderr}"
    );
}
