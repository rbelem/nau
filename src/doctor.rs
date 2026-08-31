//! System readiness checks — `shuttle doctor`.
//!
//! Verifies that all required tools are installed and working before
//! attempting a build. Run via `shuttle doctor`.

/// Result of one dependency check.
#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub hint: Option<&'static str>,
}

#[derive(Debug)]
pub enum CheckStatus {
    Ok,
    Missing,
    Error,
}

impl Check {
    fn ok(name: &'static str) -> Self {
        Check {
            name,
            status: CheckStatus::Ok,
            hint: None,
        }
    }

    fn missing(name: &'static str, hint: &'static str) -> Self {
        Check {
            name,
            status: CheckStatus::Missing,
            hint: Some(hint),
        }
    }

    fn error(name: &'static str, hint: &'static str) -> Self {
        Check {
            name,
            status: CheckStatus::Error,
            hint: Some(hint),
        }
    }
}

/// Run all system checks. Returns a list of results.
pub fn run_all() -> Vec<Check> {
    vec![
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
    ]
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

        let hint_str: String = check.hint.map(|h| format!(" ({h})")).unwrap_or_default();

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
        // At minimum: mksquashfs, unsquashfs, curl, tar, bwrap
        assert!(
            checks.len() >= 5,
            "expected at least 5 checks, got {}",
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
}
