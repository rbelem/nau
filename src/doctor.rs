//! System readiness checks — `shuttle doctor`.
//!
//! Verifies that all required tools are installed and working before
//! attempting a build. Run via `shuttle doctor`.

use std::path::PathBuf;

use crate::snap;

/// Result of one dependency check.
#[derive(Debug)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub hint: Option<String>,
}

#[derive(Debug)]
pub enum CheckStatus {
    Ok,
    Missing,
    Error,
}

impl Check {
    fn ok(name: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Ok,
            hint: None,
        }
    }

    fn ok_at(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Ok,
            hint: Some(hint.into()),
        }
    }

    fn missing(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Missing,
            hint: Some(hint.into()),
        }
    }

    fn error(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Error,
            hint: Some(hint.into()),
        }
    }
}

/// Build tools checked AS THE SANDBOX SEES THEM — resolved through the
/// same bind roots the build sandbox mounts ([`snap::SANDBOX_RO_ROOTS`]),
/// not the raw host PATH. A tool that resolves on the host but outside
/// those roots (a project `.devbox` profile dir, an unbound `$HOME` path)
/// or that a `nix store` GC removed from a stale shell's PATH breaks
/// builds with obscure mid-build errors; these checks turn that into a
/// named pre-build diagnostic. Value is the per-tool fix.
///
/// Only tools that run INSIDE the sandbox are listed: `sh` (the sandbox
/// wrapper), `make`, and the C toolchain entry point. Host-side tools
/// (`mksquashfs`, `bwrap`) are invoked by shuttle itself before/after the
/// sandbox and are covered by the host-PATH checks above — listing them
/// here would flag every devbox setup (devbox puts declared packages on
/// PATH via the unbound `.devbox` profile dir, while stdenv toolchain
/// tools also get direct `/nix/store` entries).
const SANDBOX_TOOLS: [(&str, &str); 3] = [
    (
        "sh",
        "the sandbox runs every build via sh — /bin or /usr/bin must provide it",
    ),
    (
        "make",
        "add gnumake to devbox.json packages (or install make system-wide)",
    ),
    ("cc", "add gcc to devbox.json packages (or apt install gcc)"),
];

/// Run all system checks. Returns a list of results.
pub fn run_all() -> Vec<Check> {
    let mut checks = vec![
        check_cmd(
            "mksquashfs",
            "install squashfs-tools (e.g. apt install squashfs-tools)",
        ),
        check_cmd(
            "unsquashfs",
            "install squashfs-tools (e.g. apt install squashfs-tools)",
        ),
        check_cmd("curl", "install curl (e.g. apt install curl)"),
        check_cmd("tar", "install tar (e.g. apt install tar)"),
        check_bwrap(),
        check_squashfs_version(),
    ];
    checks.extend(check_sandbox_tools_with(&snap::path_entries()));
    checks
}

/// Check that a command exists on PATH.
fn check_cmd(name: &'static str, hint: &'static str) -> Check {
    let found = std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()
        .is_some_and(|o| o.status.success());

    if found {
        Check::ok(name)
    } else {
        Check::missing(name, hint)
    }
}

/// Check bubblewrap with a basic no-op invocation.
fn check_bwrap() -> Check {
    let output = std::process::Command::new("bwrap")
        .args(["--version"])
        .output()
        .ok();

    match output {
        Some(o) if o.status.success() => Check::ok("bwrap"),
        Some(_) => Check::error(
            "bwrap",
            "bwrap found but failed to run — check user namespaces are enabled",
        ),
        None => Check::missing("bwrap", "install bubblewrap (e.g. apt install bubblewrap)"),
    }
}

/// Check that mksquashfs supports SOURCE_DATE_EPOCH (4.4+).
fn check_squashfs_version() -> Check {
    let output = std::process::Command::new("mksquashfs")
        .args(["-version"])
        .output()
        .ok();

    match output {
        Some(o) if o.status.success() => {
            let version = String::from_utf8_lossy(&o.stdout);
            if version.contains("4.4") || version.contains("4.5") || version.contains("4.6") {
                Check::ok("mksquashfs >= 4.4 (SOURCE_DATE_EPOCH)")
            } else {
                Check::ok("mksquashfs (SOURCE_DATE_EPOCH untested)")
            }
        }
        _ => Check::missing("mksquashfs", "install squashfs-tools"),
    }
}

/// Check one tool the way the build sandbox would resolve it: through the
/// sandbox-visible PATH only ([`snap::sandbox_visible_entries`]). A tool
/// shadowed by an unbound entry but also present under a bind root passes;
/// a tool visible only outside the bind roots is flagged even though the
/// host can run it.
fn check_sandbox_tool(tool: &str, fix: &str, entries: &[PathBuf]) -> Check {
    let visible = snap::sandbox_visible_entries(entries);
    match snap::resolve_in_path(tool, &visible) {
        Some(path) => Check::ok_at(format!("sandbox: {tool}"), format!("resolves to {path:?}")),
        None => match snap::resolve_in_path(tool, entries) {
            Some(host_path) => Check::error(
                format!("sandbox: {tool}"),
                format!(
                    "host PATH resolves it to '{}' — outside the sandbox bind roots \
                     ({}), so sandboxed builds cannot see it. Fix: {fix}",
                    host_path.display(),
                    snap::SANDBOX_RO_ROOTS.join(", "),
                ),
            ),
            None => Check::missing(
                format!("sandbox: {tool}"),
                format!(
                    "not found on PATH — {fix} (a 'nix store' GC can also remove /nix/store \
                     paths a stale shell still exports on PATH)"
                ),
            ),
        },
    }
}

/// Check the sandbox build toolchain against sandbox-visible PATH entries.
fn check_sandbox_tools_with(entries: &[PathBuf]) -> Vec<Check> {
    SANDBOX_TOOLS
        .iter()
        .map(|(tool, fix)| check_sandbox_tool(tool, fix, entries))
        .collect()
}

/// Print a formatted doctor report to stdout.
pub fn print_report(checks: &[Check]) {
    let mut all_ok = true;

    println!("shuttle doctor — system readiness check");
    println!();

    for check in checks {
        let (symbol, status_str) = match check.status {
            CheckStatus::Ok => ("✓", "ok"),
            CheckStatus::Missing => ("✗", "missing"),
            CheckStatus::Error => ("⚠", "error"),
        };

        let hint_str: String = check
            .hint
            .as_deref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();

        println!("  {symbol} {:<40} {status_str}{hint_str}", check.name);

        if !matches!(check.status, CheckStatus::Ok) {
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("  All checks passed — ready to build.");
    } else {
        println!("  Some checks failed — install missing tools and try again.");
    }
}

/// Return true only if all checks passed.
pub fn all_ok(checks: &[Check]) -> bool {
    checks.iter().all(|c| matches!(c.status, CheckStatus::Ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_all_returns_checks() {
        let checks = run_all();
        // At minimum: mksquashfs, unsquashfs, curl, tar, bwrap, version +
        // sandbox visibility checks.
        assert!(
            checks.len() >= 8,
            "expected at least 8 checks, got {}",
            checks.len()
        );
    }

    #[test]
    fn test_check_cmd_found() {
        // 'which' itself should always be findable
        let check = check_cmd("which", "should not happen");
        assert!(matches!(check.status, CheckStatus::Ok));
    }

    #[test]
    fn test_check_cmd_not_found() {
        let check = check_cmd("this-command-definitely-does-not-exist-12345", "install it");
        assert!(matches!(check.status, CheckStatus::Missing));
    }

    #[test]
    fn test_print_report_doesnt_panic() {
        let checks = vec![
            Check::ok("test-tool"),
            Check::missing("missing-tool", "install it"),
            Check::error("broken-tool", "fix it"),
        ];
        print_report(&checks);
        assert!(!all_ok(&checks));
    }

    #[test]
    fn test_all_ok_true() {
        let checks = vec![Check::ok("a"), Check::ok("b")];
        assert!(all_ok(&checks));
    }

    #[test]
    fn test_all_ok_false() {
        let checks = vec![Check::ok("a"), Check::missing("b", "do it")];
        assert!(!all_ok(&checks));
    }

    #[test]
    fn run_all_includes_sandbox_visibility_checks() {
        let checks = run_all();
        for (tool, _) in SANDBOX_TOOLS {
            assert!(
                checks.iter().any(|c| c.name == format!("sandbox: {tool}")),
                "missing sandbox visibility check for {tool}"
            );
        }
    }

    /// `make` executable inside a tempdir — an unwritable stand-in for an
    /// unbound host path like a project `.devbox` profile dir.
    fn write_exec(dir: &std::path::Path, name: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn doctor_flags_tool_visible_only_outside_bind_set() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "make");
        // The tempdir PATH entry is outside the sandbox bind set — make is
        // host-visible but invisible to sandboxed builds.
        let entries = vec![
            dir.path().to_path_buf(),
            PathBuf::from("/nix/store/0000-garbage-collected/bin"),
        ];

        let checks = check_sandbox_tools_with(&entries);
        let make = checks
            .iter()
            .find(|c| c.name == "sandbox: make")
            .expect("make check present");

        assert!(matches!(make.status, CheckStatus::Error));
        let hint = make.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains(&dir.path().display().to_string()),
            "hint must name the resolved host path: {hint}"
        );
        assert!(
            hint.contains("bind roots") && hint.contains("/nix"),
            "hint must name the bind roots and the fix: {hint}"
        );
    }

    #[test]
    fn doctor_reports_absent_sandbox_tool_as_missing() {
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];
        let checks = check_sandbox_tools_with(&entries);
        let make = checks
            .iter()
            .find(|c| c.name == "sandbox: make")
            .expect("make check present");
        assert!(matches!(make.status, CheckStatus::Missing));
        let hint = make.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("devbox.json"),
            "hint must carry the fix: {hint}"
        );
    }
}
