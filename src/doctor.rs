//! System readiness checks — `shuttle doctor`.
//!
//! Verifies that all required tools are installed and working before
//! attempting a build. Run via `shuttle doctor`.

use std::path::{Path, PathBuf};

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
        check_ukify(),
        check_efi_stub(),
        check_veritysetup(),
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

/// Standard locations of the systemd sd-stub for x86_64, shared with the
/// image builder ([`crate::image`]) — all under the sandbox bind roots.
pub const EFI_STUB_CANDIDATES: [&str; 3] = [
    "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
    "/usr/local/lib/systemd/boot/efi/linuxx64.efi.stub",
    "/run/current-system/sw/lib/systemd/boot/efi/linuxx64.efi.stub",
];

/// Check that ukify is resolvable. Kernel disk images (ADR-0011 step (a))
/// build a UKI with the real `ukify` CLI and fail closed without it, so a
/// missing ukify must be named before any build starts.
fn check_ukify() -> Check {
    match snap::resolve_in_path("ukify", &snap::path_entries()) {
        Some(path) => Check::ok_at("ukify", format!("resolves to {path:?}")),
        None => Check::missing(
            "ukify",
            "kernel disk images need ukify to build the UKI (systemd >= 254) — \
             e.g. apt install systemd-ukify, or add systemd to devbox.json packages",
        ),
    }
}

/// Check that the systemd sd-stub the UKI is built on is present.
fn check_efi_stub() -> Check {
    match EFI_STUB_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
    {
        Some(path) => Check::ok_at("linuxx64.efi.stub", format!("found at {}", path.display())),
        None => Check::missing(
            "linuxx64.efi.stub",
            format!(
                "the UKI sd-stub was not found in any of: {} — install systemd's \
                 boot stub (ships with systemd >= 254)",
                EFI_STUB_CANDIDATES.join(", ")
            ),
        ),
    }
}

/// Check that veritysetup is resolvable. Kernel disk images (ADR-0011 step
/// (c)) format dm-verity over the root partition with the real
/// `veritysetup` CLI and fail closed without it, so a missing veritysetup
/// must be named before any build starts.
fn check_veritysetup() -> Check {
    match snap::resolve_in_path("veritysetup", &snap::path_entries()) {
        Some(path) => Check::ok_at("veritysetup", format!("resolves to {path:?}")),
        None => Check::missing(
            "veritysetup",
            "kernel disk images need veritysetup for dm-verity (cryptsetup >= 2.4) — \
             e.g. apt install cryptsetup, or add cryptsetup to devbox.json packages",
        ),
    }
}

/// Outcome of the kernel dm-verity config audit ([`audit_kernel_verity_config`]).
#[derive(Debug, PartialEq, Eq)]
pub enum VerityConfigAudit {
    /// CONFIG_DM_VERITY=y found in the config at this path.
    Confirmed(PathBuf),
    /// The kernel version carries prior in-guest boot proof of dm-verity
    /// (module load + `status: verified` activation), even though the
    /// shipped config lacks CONFIG_DM_VERITY=y (=m from the initrd works
    /// identically) or no config file exists. Value is the provenance note.
    ConfirmedByProof(&'static str),
    /// A kernel config exists at this path but CONFIG_DM_VERITY=y is absent.
    Unconfirmed(PathBuf),
    /// No kernel config source found — support cannot be confirmed either
    /// way (common: many kernel snaps ship no config).
    NoConfig,
}

/// Kernel versions whose dm-verity support was behaviorally verified in
/// QEMU missions (module load + `veritysetup status: verified` from the
/// dm device), with provenance. Checked when the config-based audit would
/// otherwise report Unconfirmed or NoConfig.
const KNOWN_GOOD_VERITY_KERNELS: &[(&str, &str)] = &[(
    "6.18.45",
    "nixpkgs linux 6.18.45: DM_VERITY=m + CRYPTO_SHA256=y proven in-guest \
     (QEMU verity mission 2026-09-04, ADR-0011 kernel-config audit)",
)];

fn known_good_verity_kernel(version: &str) -> Option<&'static str> {
    KNOWN_GOOD_VERITY_KERNELS
        .iter()
        .find(|(v, _)| *v == version)
        .map(|(_, note)| *note)
}

/// Audit the kernel payload for dm-verity support (ADR-0011 step (c)).
/// Best-effort by design: looks for a config source under `payload_dir`
/// (`boot/config-<version>`, any `boot/config-*`, or
/// `lib/modules/<version>/config*`) and warns — NEVER fails — when
/// CONFIG_DM_VERITY=y cannot be confirmed. Absent VERIFY_ROOTHASH_SIG only
/// means no signature enforcement, so only DM_VERITY itself is checked;
/// the kernel decides at boot whether dm-verity is actually available.
pub fn audit_kernel_verity_config(payload_dir: &Path, kernel_version: &str) -> VerityConfigAudit {
    let outcome = find_kernel_config(payload_dir, kernel_version)
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.lines().any(|l| l.trim() == "CONFIG_DM_VERITY=y") {
                VerityConfigAudit::Confirmed(path)
            } else {
                VerityConfigAudit::Unconfirmed(path)
            }
        })
        .unwrap_or(VerityConfigAudit::NoConfig);
    // Boot proof trumps a missing or =y-less config: dm-verity may ship as
    // a module from the initrd (see ADR-0011 kernel-config audit).
    let outcome = match outcome {
        VerityConfigAudit::Confirmed(_) => outcome,
        _ => match known_good_verity_kernel(kernel_version) {
            Some(note) => VerityConfigAudit::ConfirmedByProof(note),
            None => outcome,
        },
    };
    match &outcome {
        VerityConfigAudit::Confirmed(path) => eprintln!(
            "  ✓ kernel dm-verity: CONFIG_DM_VERITY=y ({})",
            path.display()
        ),
        VerityConfigAudit::ConfirmedByProof(note) => eprintln!(
            "  ✓ kernel {kernel_version}: dm-verity confirmed by prior boot proof ({note})"
        ),
        VerityConfigAudit::Unconfirmed(path) => eprintln!(
            "  ⚠ kernel config {} lacks CONFIG_DM_VERITY=y — dm-verity boot \
             (ADR-0011 step (c)) may fail on this kernel",
            path.display()
        ),
        VerityConfigAudit::NoConfig => eprintln!(
            "  ⚠ no kernel config (boot/config-*, lib/modules/{kernel_version}/config*) \
             found — cannot confirm CONFIG_DM_VERITY=y; dm-verity boot \
             (ADR-0011 step (c)) may fail on this kernel"
        ),
    }
    outcome
}

/// Locate the best kernel config source under the payload dir, first hit
/// wins: `boot/config-<version>`, then any `boot/config-*`, then
/// `lib/modules/<version>/config*` (sorted for determinism).
fn find_kernel_config(payload_dir: &Path, kernel_version: &str) -> Option<PathBuf> {
    let mut candidates = vec![payload_dir
        .join("boot")
        .join(format!("config-{kernel_version}"))];
    let boot = payload_dir.join("boot");
    if let Ok(read) = std::fs::read_dir(&boot) {
        let mut globs: Vec<PathBuf> = read
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("config-"))
            })
            .collect();
        globs.sort();
        candidates.extend(globs);
    }
    let modules = payload_dir.join("lib").join("modules").join(kernel_version);
    if let Ok(read) = std::fs::read_dir(&modules) {
        let mut globs: Vec<PathBuf> = read
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("config"))
            })
            .collect();
        globs.sort();
        candidates.extend(globs);
    }
    candidates.into_iter().find(|p| p.is_file())
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

    #[test]
    fn run_all_includes_uki_checks() {
        let checks = run_all();
        for name in ["ukify", "linuxx64.efi.stub"] {
            assert!(
                checks.iter().any(|c| c.name == name),
                "missing UKI readiness check for {name}"
            );
        }
    }

    #[test]
    fn run_all_includes_verity_check() {
        let checks = run_all();
        assert!(
            checks.iter().any(|c| c.name == "veritysetup"),
            "missing veritysetup readiness check"
        );
    }

    #[test]
    fn veritysetup_check_hint_names_cryptsetup_when_missing() {
        let check = check_veritysetup();
        match check.status {
            CheckStatus::Ok => assert!(check.hint.is_some()),
            _ => {
                let hint = check.hint.as_deref().unwrap_or_default();
                assert!(
                    hint.contains("cryptsetup"),
                    "hint must name the fix: {hint}"
                );
            }
        }
    }

    #[test]
    fn kernel_config_audit_confirms_dm_verity() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("boot").join("config-6.8.0-42-generic");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "CONFIG_CRYPTO_SHA256=y\nCONFIG_DM_VERITY=y\nCONFIG_BLK_DEV_DM=y\n",
        )
        .unwrap();
        assert_eq!(
            audit_kernel_verity_config(dir.path(), "6.8.0-42-generic"),
            VerityConfigAudit::Confirmed(config)
        );
    }

    #[test]
    fn kernel_config_audit_warns_when_dm_verity_absent() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("boot").join("config-6.8.0");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "CONFIG_CRYPTO_SHA256=y\n# CONFIG_DM_VERITY is not set\n",
        )
        .unwrap();
        assert_eq!(
            audit_kernel_verity_config(dir.path(), "6.8.0"),
            VerityConfigAudit::Unconfirmed(config)
        );
    }

    #[test]
    fn kernel_config_audit_without_config_is_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            audit_kernel_verity_config(dir.path(), "6.8.0"),
            VerityConfigAudit::NoConfig
        );
    }

    #[test]
    fn kernel_config_audit_finds_modules_tree_config() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir
            .path()
            .join("lib")
            .join("modules")
            .join("6.8.0")
            .join("config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "CONFIG_DM_VERITY=y\n").unwrap();
        assert!(matches!(
            audit_kernel_verity_config(dir.path(), "6.8.0"),
            VerityConfigAudit::Confirmed(_)
        ));
    }

    #[test]
    fn kernel_config_audit_confirms_known_good_kernel_without_config() {
        // nix 6.18.45 ships no config file in its payload but has in-guest
        // boot proof (ADR-0011 kernel-config audit, 2026-09-04).
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            audit_kernel_verity_config(dir.path(), "6.18.45"),
            VerityConfigAudit::ConfirmedByProof(_)
        ));
    }

    #[test]
    fn kernel_config_audit_boot_proof_overrides_absent_y() {
        // The nix kernel config has DM_VERITY=m (not =y); boot proof wins.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("boot").join("config-6.18.45");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "# CONFIG_DM_VERITY is not set\n").unwrap();
        assert!(matches!(
            audit_kernel_verity_config(dir.path(), "6.18.45"),
            VerityConfigAudit::ConfirmedByProof(_)
        ));
    }

    #[test]
    fn unknown_kernel_version_still_unconfirmed_without_y() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("boot").join("config-6.18.45");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "# CONFIG_DM_VERITY is not set\n").unwrap();
        // A different version string with the same config stays Unconfirmed.
        assert_eq!(
            audit_kernel_verity_config(dir.path(), "6.18.46"),
            VerityConfigAudit::Unconfirmed(config)
        );
    }

    #[test]
    fn uki_stub_check_names_candidates_when_missing() {
        let check = check_efi_stub();
        // On hosts with the stub this is Ok; either way the check must be
        // one of the two with a meaningful hint path.
        match check.status {
            CheckStatus::Ok => assert!(check.hint.is_some()),
            _ => {
                let hint = check.hint.as_deref().unwrap_or_default();
                assert!(
                    hint.contains("/usr/lib/systemd/boot/efi/linuxx64.efi.stub"),
                    "hint must name the stub candidates: {hint}"
                );
            }
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
