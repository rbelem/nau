//! `shuttle test` — the QEMU boot-and-assert harness (issue #50).
//!
//! Boots a built disk image in QEMU and asserts the guest actually reached
//! userspace. This is the programmatic "did the image boot?" proof behind
//! Phase 24's try-boot auto-revert (issue #63): a revert/boot claim is only
//! credible when the log is archived and the assertion is machine-checked.
//!
//! # Why UEFI (and not SeaBIOS)
//!
//! Shuttle disk images boot a UKI discovered by systemd-boot from the EFI
//! System Partition. The legacy SeaBIOS firmware has no EFI execution
//! environment, so a BIOS boot cannot start that image at all — QEMU is
//! therefore driven with UEFI firmware (OVMF/edk2) through two pflash
//! drives: a read-only code image and a writable NVRAM copy.
//!
//! # What counts as "booted"
//!
//! Deliberately **not** "QEMU started" and **not** "the kernel printed its
//! banner" — both are rejected by the ticket. Success requires, in the
//! captured serial console:
//!
//! 1. no kernel panic, **and**
//! 2. a userspace marker (`systemd[1]:`, a `Reached target …` line, `Started …`,
//!    or the `Welcome to …` banner), **and**
//! 3. at least one service-level line (`Reached target …` or `Started …`).
//!
//! The exact markers live in [`USERSPACE_MARKERS`]/[`PANIC_MARKERS`] and can
//! be tightened per run with `--require <substring>`.
//!
//! # Honest caveat: quiet images
//!
//! The examples declare `params = { "quiet", "console=ttyS0" }`. `quiet`
//! makes the kernel and systemd suppress console output, which can leave the
//! serial log without the systemd target lines this harness asserts on. A
//! failure therefore names the possibility explicitly and suggests
//! `systemd.show_status=1`. The markers are the single place to change when a
//! real image's boot log is known.
//!
//! # Timeout seam
//!
//! QEMU is a long-lived process: a booted system that never powers off runs
//! forever, and [`CommandRunner::run`] blocks until the child exits. The
//! harness therefore wraps QEMU in GNU coreutils `timeout` (see
//! [`wrapper_argv`]) so the seam stays a single blocking call and the bound
//! is visible in the exact argv the fake runner asserts. `timeout` exits
//! `124` when it had to kill the guest; that code alone is **not** a failure
//! — a boot that produced the userspace markers before the kill passes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::{IntoDiagnostic, WrapErr};

use crate::command::{CommandRunner, RunnerOutput};

/// Default boot timeout, in seconds. A full systemd boot under KVM is
/// typically tens of seconds; the default leaves generous headroom.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Userspace-reached markers, matched case-sensitively against any serial
/// line. Any one of these proves PID 1 (systemd) ran in the guest.
///
/// Note that systemd's console output uses unit *descriptions*
/// (`Reached target Multi-User System.`), not unit names — so the markers
/// are deliberately loose here and the exact target requirement is what
/// `--require "Reached target Multi-User System."` is for.
pub const USERSPACE_MARKERS: &[&str] =
    &["systemd[1]:", "Reached target ", "Started ", "Welcome to "];

/// Kernel-panic markers; any one fails the run regardless of exit code or
/// other evidence.
pub const PANIC_MARKERS: &[&str] = &["Kernel panic", "end Kernel panic", "panic - not syncing"];

/// The boot-time shuttle activation unit (ADR-0023 §4). Its presence in the
/// log is reported (`activate`) but not required — a plain image need not
/// carry it.
pub const ACTIVATE_UNIT: &str = "shuttle-runtime-activate";

// ── Firmware ────────────────────────────────────────────────────────────

/// A UEFI firmware code/VARS pair. `code` is opened read-only by QEMU;
/// `vars` MUST be a writable copy of the template (the store/system copy is
/// usually read-only, and QEMU writes boot variables back into NVRAM).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firmware {
    pub code: PathBuf,
    pub vars: PathBuf,
}

/// Known firmware (code, vars) file-name pairs, in preference order.
/// OVMF first (the canonical x86_64 UEFI build), then QEMU's own bundled
/// edk2 firmware (present in the devbox `qemu` package).
pub const FIRMWARE_PAIRS: &[(&str, &str)] = &[
    ("OVMF_CODE.fd", "OVMF_VARS.fd"),
    ("edk2-x86_64-code.fd", "edk2-i386-vars.fd"),
    ("edk2-i386-code.fd", "edk2-i386-vars.fd"),
];

// ── Accelerator ─────────────────────────────────────────────────────────

/// QEMU accelerator. `Kvm` is the default; when KVM is unavailable the
/// harness falls back to `Tcg` (software emulation, much slower).
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accel {
    Kvm,
    Tcg,
}

impl Accel {
    /// The value handed to QEMU's `-accel`.
    pub fn qemu_arg(self) -> &'static str {
        match self {
            Accel::Kvm => "kvm",
            Accel::Tcg => "tcg",
        }
    }
}

// ── Boot spec ───────────────────────────────────────────────────────────

/// Everything one QEMU boot needs. Constructed by the CLI after resolving
/// the host environment and by tests directly.
#[derive(Clone, Debug)]
pub struct BootTest {
    /// The built disk image under test.
    pub image: PathBuf,
    /// Where the serial console is captured (the auditable evidence).
    pub log: PathBuf,
    /// Requested accelerator.
    pub accel: Accel,
    /// Wall-clock bound handed to `timeout`.
    pub timeout: Duration,
    /// UEFI firmware pair.
    pub firmware: Firmware,
    /// QEMU binary (absolute path from PATH resolution).
    pub qemu: PathBuf,
    /// `timeout` binary (absolute path from PATH resolution).
    pub timeout_bin: PathBuf,
    /// Whether KVM is usable on this host (pre-flight for the fallback).
    pub kvm_available: bool,
    /// Extra substrings that MUST appear in the serial log to pass.
    pub required: Vec<String>,
}

/// The exact QEMU argv the harness builds. Exposed so both the fake runner
/// and the operator can see precisely what is launched.
pub fn qemu_argv(test: &BootTest, accel: Accel) -> Vec<String> {
    vec![
        test.qemu.to_string_lossy().into_owned(),
        "-machine".into(),
        "q35".into(),
        "-accel".into(),
        accel.qemu_arg().into(),
        "-m".into(),
        "2048".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            test.firmware.code.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", test.firmware.vars.display()),
        "-drive".into(),
        format!("file={},format=raw,if=virtio", test.image.display()),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{}", test.log.display()),
        "-no-reboot".into(),
    ]
}

/// The argv actually handed to the [`CommandRunner`]: [`qemu_argv`] wrapped
/// in GNU `timeout` (signal TERM, hard kill after 5s).
pub fn wrapper_argv(test: &BootTest, accel: Accel) -> Vec<String> {
    let mut argv = vec![
        test.timeout_bin.to_string_lossy().into_owned(),
        "-s".into(),
        "TERM".into(),
        "-k".into(),
        "5".into(),
        test.timeout.as_secs().to_string(),
    ];
    argv.extend(qemu_argv(test, accel));
    argv
}

// ── Serial-log analysis ─────────────────────────────────────────────────

/// What the serial log proved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    /// A userspace marker appeared (systemd started).
    pub userspace: bool,
    /// First `Reached target …` line, if any.
    pub target: Option<String>,
    /// First service-level line (`Reached target …` or `Started …`), if any.
    pub service: Option<String>,
    /// First panic marker line, if any.
    pub panic: Option<String>,
    /// The shuttle activation unit was mentioned.
    pub activate: bool,
    /// Which [`USERSPACE_MARKERS`] matched.
    pub markers: Vec<String>,
}

fn first_line_containing(text: &str, needle: &str) -> Option<String> {
    text.lines()
        .find(|line| line.contains(needle))
        .map(|line| line.trim().to_string())
}

fn is_target_line(line: &str) -> bool {
    line.contains("Reached target ")
}

fn is_service_line(line: &str) -> bool {
    is_target_line(line) || (line.contains("Started ") && line.contains(".service"))
}

/// Parse a captured serial console into [`Evidence`]. Pure and hermetic —
/// the unit tests drive it with synthetic logs.
pub fn analyze_log(text: &str) -> Evidence {
    let panic = PANIC_MARKERS
        .iter()
        .find_map(|marker| first_line_containing(text, marker));
    let markers: Vec<String> = USERSPACE_MARKERS
        .iter()
        .filter(|marker| text.contains(**marker))
        .map(|marker| (*marker).to_string())
        .collect();
    let target = text
        .lines()
        .find(|line| is_target_line(line))
        .map(|line| line.trim().to_string());
    let service = text
        .lines()
        .find(|line| is_service_line(line))
        .map(|line| line.trim().to_string());
    Evidence {
        userspace: !markers.is_empty(),
        target,
        service,
        panic,
        activate: text.contains(ACTIVATE_UNIT),
        markers,
    }
}

// ── Verdict ─────────────────────────────────────────────────────────────

/// Why a run did not pass. `None` in [`Outcome::failure`] means success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A kernel panic marker appeared.
    Panic,
    /// The bound elapsed with no userspace marker.
    Timeout,
    /// QEMU finished without reaching userspace (and without a panic).
    NoUserspace,
    /// Userspace was reached but no service/target line appeared.
    NoService,
    /// A `--require` substring was absent from the log.
    MissingRequirement(String),
    /// QEMU itself failed to run (non-zero exit, non-empty stderr).
    Qemu { code: i32, stderr: String },
}

impl Failure {
    /// Stable machine-readable label (JSON `failure` field).
    pub fn label(&self) -> &'static str {
        match self {
            Failure::Panic => "panic",
            Failure::Timeout => "timeout",
            Failure::NoUserspace => "no-userspace",
            Failure::NoService => "no-service",
            Failure::MissingRequirement(_) => "missing-requirement",
            Failure::Qemu { .. } => "qemu-error",
        }
    }
}

/// The result of one boot attempt.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// Accelerator actually used (may differ from the request after a fallback).
    pub accel: Accel,
    /// The exact argv handed to the runner.
    pub argv: Vec<String>,
    /// The parsed serial evidence.
    pub evidence: Evidence,
    /// `None` when the boot assertions passed.
    pub failure: Option<Failure>,
    /// The bound that was applied.
    pub timeout: Duration,
}

impl Outcome {
    /// True when every boot assertion passed.
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }

    /// A precise, one-line explanation of the outcome.
    pub fn message(&self) -> String {
        let Some(failure) = &self.failure else {
            let what = self
                .evidence
                .target
                .as_deref()
                .or(self.evidence.service.as_deref())
                .unwrap_or("userspace");
            let activate = if self.evidence.activate {
                format!("; {ACTIVATE_UNIT} ran")
            } else {
                String::new()
            };
            return format!("booted ({}): {}{}", self.accel.qemu_arg(), what, activate);
        };
        match failure {
            Failure::Panic => format!(
                "kernel panic in guest: {}",
                self.evidence.panic.as_deref().unwrap_or("panic")
            ),
            Failure::Timeout => format!(
                "boot timed out after {}s with no userspace marker — the image may boot \
                 with 'quiet' (systemd console output suppressed); add 'systemd.show_status=1' \
                 to the kernel params or raise --timeout",
                self.timeout.as_secs()
            ),
            Failure::NoUserspace => {
                "boot did not reach userspace (no systemd/target marker in the serial log)"
                    .to_string()
            }
            Failure::NoService => {
                "userspace reached but no service/target line appeared in the serial log"
                    .to_string()
            }
            Failure::MissingRequirement(needle) => {
                format!("required marker not found in the serial log: {needle}")
            }
            Failure::Qemu { code, stderr } => {
                format!("QEMU failed (exit {code}): {}", stderr.trim())
            }
        }
    }
}

/// Classify a completed run. Panic wins over everything; a timeout is only
/// reported when no userspace marker appeared (a boot killed after reaching
/// userspace passes).
fn classify(
    text: &str,
    evidence: &Evidence,
    code: i32,
    stderr: &str,
    required: &[String],
) -> Option<Failure> {
    if evidence.panic.is_some() {
        return Some(Failure::Panic);
    }
    if !evidence.userspace {
        if code == 124 {
            return Some(Failure::Timeout);
        }
        if code != 0 && !stderr.trim().is_empty() {
            return Some(Failure::Qemu {
                code,
                stderr: stderr.trim().to_string(),
            });
        }
        return Some(Failure::NoUserspace);
    }
    if evidence.service.is_none() {
        return Some(Failure::NoService);
    }
    for needle in required {
        if !text.contains(needle) {
            return Some(Failure::MissingRequirement(needle.clone()));
        }
    }
    None
}

fn read_log(path: &Path) -> String {
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn is_kvm_failure(code: i32, stderr: &str, log: &str) -> bool {
    if code == 0 || code == 124 {
        return false;
    }
    format!("{stderr}\n{log}")
        .to_ascii_lowercase()
        .contains("kvm")
}

/// Run one boot attempt through the injected [`CommandRunner`].
///
/// KVM handling: if the caller reports KVM unavailable, the run starts on
/// TCG; if an explicit KVM attempt fails at QEMU startup, it is retried once
/// on TCG. The returned [`Outcome`] records the accelerator actually used.
pub fn run_boot(runner: &dyn CommandRunner, test: &BootTest) -> miette::Result<Outcome> {
    let mut accel = test.accel;
    if accel == Accel::Kvm && !test.kvm_available {
        crate::output::warn(
            "KVM unavailable (/dev/kvm not accessible) — falling back to TCG (slow)",
        );
        accel = Accel::Tcg;
    }

    let mut argv = wrapper_argv(test, accel);
    let mut out = run_command(runner, &argv)?;
    let mut text = read_log(&test.log);

    if accel == Accel::Kvm && is_kvm_failure(out.code, &out.stderr, &text) {
        crate::output::warn("QEMU could not use KVM — retrying with TCG (slow)");
        accel = Accel::Tcg;
        argv = wrapper_argv(test, accel);
        out = run_command(runner, &argv)?;
        text = read_log(&test.log);
    }

    let evidence = analyze_log(&text);
    let failure = classify(&text, &evidence, out.code, &out.stderr, &test.required);
    Ok(Outcome {
        accel,
        argv,
        evidence,
        failure,
        timeout: test.timeout,
    })
}

fn run_command(runner: &dyn CommandRunner, argv: &[String]) -> miette::Result<RunnerOutput> {
    runner.run(argv).into_diagnostic().wrap_err_with(|| {
        format!(
            "failed to run '{}'",
            argv.first().map(String::as_str).unwrap_or("")
        )
    })
}

// ── Host environment resolution ─────────────────────────────────────────

/// Resolve `name` against a PATH-style string, returning the first existing
/// file. Pure (the caller supplies the PATH) so tests stay hermetic.
pub fn resolve_on_path(name: &str, path_var: &str) -> Option<PathBuf> {
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .find_map(|dir| {
            let candidate = Path::new(dir).join(name);
            candidate.is_file().then_some(candidate)
        })
}

fn system_path() -> String {
    std::env::var("PATH").unwrap_or_default()
}

/// Resolve `qemu-system-x86_64` from PATH with an actionable error.
pub fn resolve_qemu() -> miette::Result<PathBuf> {
    resolve_on_path("qemu-system-x86_64", &system_path()).ok_or_else(|| {
        miette::miette!(
            "qemu-system-x86_64 not found on PATH — install QEMU to run 'shuttle test' \
             (devbox provides it via the 'qemu' package)"
        )
    })
}

/// Resolve GNU coreutils `timeout` from PATH with an actionable error.
pub fn resolve_timeout() -> miette::Result<PathBuf> {
    resolve_on_path("timeout", &system_path()).ok_or_else(|| {
        miette::miette!(
            "GNU coreutils 'timeout' not found on PATH — it bounds the QEMU boot; \
             install coreutils"
        )
    })
}

/// Whether `/dev/kvm` is openable read-write (the KVM pre-flight).
pub fn kvm_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Default evidence path: `<image>.serial.log` next to the image.
pub fn default_log_path(image: &Path) -> PathBuf {
    let mut name = image.as_os_str().to_owned();
    name.push(".serial.log");
    PathBuf::from(name)
}

/// Directories searched for UEFI firmware, in order: an explicit override,
/// `$SHUTTLE_FIRMWARE_DIR`, QEMU's own share directory (derived from the
/// resolved binary), then standard system locations.
pub fn firmware_search_dirs(qemu: &Path, extra: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(dir) = extra {
        dirs.push(dir.to_path_buf());
    }
    if let Ok(env_dir) = std::env::var("SHUTTLE_FIRMWARE_DIR") {
        if !env_dir.is_empty() {
            dirs.push(PathBuf::from(env_dir));
        }
    }
    if let Some(share) = qemu_share_dir(qemu) {
        dirs.push(share.clone());
        dirs.push(share.join("firmware"));
    }
    for dir in [
        "/usr/share/OVMF",
        "/usr/share/OVMF/",
        "/usr/share/ovmf",
        "/usr/share/edk2/x64",
        "/usr/share/edk2-ovmf/x64",
        "/usr/share/edk2/ovmf",
        "/usr/share/qemu",
        "/usr/share/qemu/firmware",
    ] {
        dirs.push(PathBuf::from(dir));
    }
    dirs.dedup();
    dirs
}

fn qemu_share_dir(qemu: &Path) -> Option<PathBuf> {
    let real = qemu.canonicalize().ok()?;
    let prefix = real.parent()?.parent()?;
    Some(prefix.join("share/qemu"))
}

/// Find a complete firmware pair in `dirs`.
pub fn find_firmware_in(dirs: &[PathBuf]) -> Option<(PathBuf, PathBuf)> {
    for dir in dirs {
        for (code, vars) in FIRMWARE_PAIRS {
            let code_path = dir.join(code);
            let vars_path = dir.join(vars);
            if code_path.is_file() && vars_path.is_file() {
                return Some((code_path, vars_path));
            }
        }
    }
    None
}

/// Find a firmware pair in an explicit directory list and stage a writable
/// VARS copy in `scratch`. Errors with the searched directories when no
/// firmware is present.
pub fn prepare_firmware_in(dirs: &[PathBuf], scratch: &Path) -> miette::Result<Firmware> {
    let Some((code, vars_template)) = find_firmware_in(dirs) else {
        let searched = dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(miette::miette!(
            "UEFI firmware not found — a shuttle image boots a UKI via systemd-boot, so \
             SeaBIOS is not sufficient. Looked for OVMF_CODE.fd/OVMF_VARS.fd (or the edk2 \
             equivalents) in: {searched}. Install OVMF/edk2 or pass --firmware-dir"
        ));
    };
    let vars = scratch.join("OVMF_VARS.fd");
    std::fs::copy(&vars_template, &vars)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to stage writable firmware from {}",
                vars_template.display()
            )
        })?;
    make_owner_writable(&vars)?;
    Ok(Firmware { code, vars })
}

/// Give the staged firmware copy owner write permission. Deliberately
/// owner-only (0600 keeps the group/other bits the source had, plus `u+w`)
/// — the store template is typically read-only mode 0444, and QEMU must be
/// able to write NVRAM variables back into the copy.
#[cfg(unix)]
fn make_owner_writable(path: &Path) -> miette::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .into_diagnostic()
        .wrap_err("failed to read staged firmware permissions")?
        .permissions();
    let mode = perms.mode() | 0o200;
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
        .into_diagnostic()
        .wrap_err("failed to make staged firmware writable")
}

#[cfg(not(unix))]
fn make_owner_writable(path: &Path) -> miette::Result<()> {
    let mut perms = std::fs::metadata(path)
        .into_diagnostic()
        .wrap_err("failed to read staged firmware permissions")?
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms)
        .into_diagnostic()
        .wrap_err("failed to make staged firmware writable")
}

/// Host-side firmware resolution: search the standard locations and stage a
/// writable VARS copy in `scratch`.
pub fn prepare_firmware(
    qemu: &Path,
    extra: Option<&Path>,
    scratch: &Path,
) -> miette::Result<Firmware> {
    let dirs = firmware_search_dirs(qemu, extra);
    prepare_firmware_in(&dirs, scratch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ── Fake runner ──

    struct Script {
        code: i32,
        stderr: String,
        log: String,
    }

    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        scripts: Mutex<VecDeque<Script>>,
    }

    impl FakeRunner {
        fn new(scripts: Vec<Script>) -> FakeRunner {
            FakeRunner {
                calls: Mutex::new(Vec::new()),
                scripts: Mutex::new(scripts.into()),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn arg_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .map(String::as_str)
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let script = self.scripts.lock().unwrap().pop_front().unwrap_or(Script {
                code: 124,
                stderr: String::new(),
                log: String::new(),
            });
            // QEMU itself writes the serial log; the fake mirrors that by
            // honoring the `-serial file:<path>` argument.
            if let Some(serial) = arg_after(argv, "-serial") {
                if let Some(path) = serial.strip_prefix("file:") {
                    std::fs::write(path, &script.log).unwrap();
                }
            }
            Ok(RunnerOutput {
                code: script.code,
                stdout: Vec::new(),
                stderr: script.stderr,
            })
        }
    }

    // ── Fixtures ──

    const PASS_LOG: &str = "\
[    0.000000] Linux version 6.8.0\n\
[    2.100000] systemd[1]: systemd 255 running in system mode.\n\
[    3.200000] systemd[1]: Reached target Basic System.\n\
[    4.400000] systemd[1]: Reached target Multi-User System.\n\
[    4.900000] systemd[1]: Starting shuttle-runtime-activate.service...\n\
[    5.100000] systemd[1]: Started shuttle: activate the current runtime generation.\n";

    const PANIC_LOG: &str = "\
[    0.000000] Linux version 6.8.0\n\
[    1.000000] Kernel panic - not syncing: VFS: Unable to mount root fs\n\
[    1.000000] end Kernel panic - not syncing\n";

    const TRUNCATED_LOG: &str = "[    0.000000] Linux version 6.8.0\n";

    fn sample_test(tmp: &Path, accel: Accel, kvm_available: bool) -> BootTest {
        BootTest {
            image: tmp.join("image_1.0.0_amd64.img"),
            log: tmp.join("serial.log"),
            accel,
            timeout: Duration::from_secs(5),
            firmware: Firmware {
                code: tmp.join("OVMF_CODE.fd"),
                vars: tmp.join("OVMF_VARS.fd"),
            },
            qemu: PathBuf::from("/usr/bin/qemu-system-x86_64"),
            timeout_bin: PathBuf::from("/usr/bin/timeout"),
            kvm_available,
            required: Vec::new(),
        }
    }

    // ── argv construction ──

    #[test]
    fn wrapper_argv_kvm_is_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let expected: Vec<String> = [
            "/usr/bin/timeout",
            "-s",
            "TERM",
            "-k",
            "5",
            "5",
            "/usr/bin/qemu-system-x86_64",
            "-machine",
            "q35",
            "-accel",
            "kvm",
            "-m",
            "2048",
            "-drive",
            "PFLASH_CODE",
            "-drive",
            "PFLASH_VARS",
            "-drive",
            "DISK",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "SERIAL",
            "-no-reboot",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let argv = wrapper_argv(&test, Accel::Kvm);
        // The three `-drive`/`-serial` values embed the tempdir path, so
        // assert the stable prefix/suffix rather than a brittle full string.
        assert_eq!(argv.len(), expected.len());
        let t = tmp.path().display().to_string();
        for (i, (got, want)) in argv.iter().zip(expected.iter()).enumerate() {
            let want = match want.as_str() {
                "PFLASH_CODE" => format!("if=pflash,format=raw,readonly=on,file={t}/OVMF_CODE.fd"),
                "PFLASH_VARS" => format!("if=pflash,format=raw,file={t}/OVMF_VARS.fd"),
                "DISK" => format!("file={t}/image_1.0.0_amd64.img,format=raw,if=virtio"),
                "SERIAL" => format!("file:{t}/serial.log"),
                other => other.to_string(),
            };
            assert_eq!(*got, want, "argv[{i}]");
        }
    }

    #[test]
    fn wrapper_argv_tcg_uses_tcg() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Tcg, true);
        let argv = wrapper_argv(&test, Accel::Tcg);
        assert_eq!(arg_after(&argv, "-accel"), Some("tcg"));
        // No `-nographic`; serial is a file, display is disabled.
        assert!(argv.iter().any(|a| a == "-display"));
        assert!(!argv.iter().any(|a| a == "-nographic"));
    }

    // ── environment resolution ──

    #[test]
    fn resolve_on_path_finds_first_existing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("qemu-system-x86_64");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let path_var = format!("/nonexistent:{}", dir.path().display());
        assert_eq!(resolve_on_path("qemu-system-x86_64", &path_var), Some(bin));
        assert_eq!(resolve_on_path("does-not-exist", &path_var), None);
    }

    #[test]
    fn find_firmware_in_returns_pair() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("OVMF_CODE.fd"), b"code").unwrap();
        std::fs::write(dir.path().join("OVMF_VARS.fd"), b"vars").unwrap();
        let found = find_firmware_in(&[dir.path().to_path_buf()]);
        assert_eq!(
            found,
            Some((
                dir.path().join("OVMF_CODE.fd"),
                dir.path().join("OVMF_VARS.fd")
            ))
        );
    }

    #[test]
    fn find_firmware_in_none_when_vars_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("OVMF_CODE.fd"), b"code").unwrap();
        assert_eq!(find_firmware_in(&[dir.path().to_path_buf()]), None);
    }

    #[test]
    fn prepare_firmware_missing_is_actionable() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let err = prepare_firmware_in(&[dir.path().to_path_buf()], scratch.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("UEFI firmware not found"), "{msg}");
        assert!(msg.contains("OVMF"), "{msg}");
        assert!(msg.contains("--firmware-dir"), "{msg}");
    }

    #[test]
    fn prepare_firmware_stages_writable_vars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("OVMF_CODE.fd"), b"code").unwrap();
        std::fs::write(dir.path().join("OVMF_VARS.fd"), b"vars").unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let fw = prepare_firmware_in(&[dir.path().to_path_buf()], scratch.path()).unwrap();
        assert_eq!(fw.code, dir.path().join("OVMF_CODE.fd"));
        assert_eq!(fw.vars, scratch.path().join("OVMF_VARS.fd"));
        assert_eq!(std::fs::read(&fw.vars).unwrap(), b"vars");
        let perms = std::fs::metadata(&fw.vars).unwrap().permissions();
        assert!(!perms.readonly(), "staged VARS must be writable");
    }

    #[test]
    fn default_log_path_appends_suffix() {
        assert_eq!(
            default_log_path(Path::new("/tmp/img_1.0_amd64.img")),
            PathBuf::from("/tmp/img_1.0_amd64.img.serial.log")
        );
    }

    // ── log analysis ──

    #[test]
    fn analyze_userspace_and_service_pass() {
        let ev = analyze_log(PASS_LOG);
        assert!(ev.userspace);
        assert!(ev.target.is_some());
        assert!(ev.service.is_some());
        assert!(ev.panic.is_none());
    }

    /// Excerpt of a *real* serial console capture: the host's NixOS kernel +
    /// initrd booted under QEMU/KVM on 2026-09-11 (see the module docs). This
    /// pins the parser to genuine systemd output, not just a synthetic
    /// fixture. Only the lines the parser keys on are kept.
    const REAL_BOOT_EXCERPT: &str = "\
[    1.975769] systemd[1]: systemd 261.2 running in system mode (+PAM +AUDIT -SELINUX)\n\
[    1.977862] systemd[1]: Detected virtualization kvm.\n\
[    1.978184] systemd[1]: Detected architecture x86-64.\n\
[    1.978501] systemd[1]: Running in initrd.\n\
[    2.081988] systemd[1]: Queued start job for default target Initrd Default Target.\n\
[    2.085533] systemd[1]: Reached target Slice Units.\n\
[    2.086214] systemd[1]: Reached target Swaps.\n\
[    2.086841] systemd[1]: Reached target Timer Units.\n";

    #[test]
    fn analyze_parses_real_boot_excerpt_as_pass() {
        let ev = analyze_log(REAL_BOOT_EXCERPT);
        assert!(ev.userspace, "real systemd output must count as userspace");
        assert!(ev.panic.is_none());
        assert_eq!(
            ev.target.as_deref(),
            Some("[    2.085533] systemd[1]: Reached target Slice Units.")
        );
        assert!(ev.service.is_some());
    }

    #[test]
    fn run_boot_passes_on_real_boot_excerpt() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: REAL_BOOT_EXCERPT.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
    }

    #[test]
    fn analyze_detects_activate_unit() {
        let ev = analyze_log(PASS_LOG);
        assert!(ev.activate);
        assert!(!analyze_log(TRUNCATED_LOG).activate);
    }

    #[test]
    fn analyze_panic_is_detected() {
        let ev = analyze_log(PANIC_LOG);
        assert!(ev.panic.is_some());
        assert!(!ev.userspace);
    }

    #[test]
    fn analyze_truncated_has_no_userspace() {
        let ev = analyze_log(TRUNCATED_LOG);
        assert!(!ev.userspace);
        assert!(ev.target.is_none());
        assert!(ev.service.is_none());
    }

    // ── run_boot: verdicts ──

    #[test]
    fn run_boot_passes_after_timeout_kill() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: PASS_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(out.accel, Accel::Kvm);
        assert_eq!(out.argv, wrapper_argv(&test, Accel::Kvm));
    }

    #[test]
    fn run_boot_timeout_is_distinct() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: TRUNCATED_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(Failure::Timeout));
        assert!(out.message().contains("timed out"));
    }

    #[test]
    fn run_boot_panic_fails_even_when_exit_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 0,
            stderr: String::new(),
            log: PANIC_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(out.failure, Some(Failure::Panic));
        assert!(out.message().contains("kernel panic"));
    }

    #[test]
    fn run_boot_no_service_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        // Userspace marker present, but no target/started line.
        let log = "[    2.000000] systemd[1]: systemd 255 running in system mode.\n";
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: log.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(out.failure, Some(Failure::NoService));
    }

    #[test]
    fn run_boot_required_marker_tightens() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.required = vec!["Reached target Boot-Complete".into()];
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: PASS_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(
            out.failure,
            Some(Failure::MissingRequirement(
                "Reached target Boot-Complete".into()
            ))
        );
    }

    #[test]
    fn run_boot_qemu_failure_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 1,
            stderr: "qemu-system-x86_64: -drive file=x: Could not open 'x': No such file"
                .to_string(),
            log: String::new(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        match out.failure {
            Some(Failure::Qemu { code, .. }) => assert_eq!(code, 1),
            other => panic!("expected Qemu failure, got {other:?}"),
        }
    }

    // ── run_boot: KVM fallback ──

    #[test]
    fn run_boot_preflight_falls_back_to_tcg() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, false);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: PASS_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(out.accel, Accel::Tcg);
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(arg_after(&calls[0], "-accel"), Some("tcg"));
    }

    #[test]
    fn run_boot_runtime_kvm_failure_retries_tcg() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![
            Script {
                code: 1,
                stderr: "Could not access KVM kernel module: No such file or directory".into(),
                log: String::new(),
            },
            Script {
                code: 124,
                stderr: String::new(),
                log: PASS_LOG.to_string(),
            },
        ]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(out.accel, Accel::Tcg);
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(arg_after(&calls[0], "-accel"), Some("kvm"));
        assert_eq!(arg_after(&calls[1], "-accel"), Some("tcg"));
        assert_eq!(out.argv, wrapper_argv(&test, Accel::Tcg));
    }
}
