//! System readiness checks — `shuttle doctor`.
//!
//! Verifies that all required tools are installed and working before
//! attempting a build. Run via `shuttle doctor`.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use crate::command::CommandRunner;
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
///
/// Host-only checks live here. Checks that need an [`ImageDeclaration`] (the
/// state-partition readiness and the initrd module inventory) cannot run in
/// this host-readiness command — `doctor` is invoked with no image — so they
/// are exposed as builder-context functions called from the image build with
/// the image in hand, mirroring [`audit_kernel_verity_config`]
/// (`src/image/mod.rs`). Both never fail the build; they add a report line.
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
        check_sysupdate_prereqs(),
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

// ── systemd-sysupdate prerequisites (ADR-0024 §1–§2) ──

/// Minimum systemd major version that reads `*.transfer` transfer files
/// from `sysupdate.d`. As of v257 transfer definitions carry the
/// `.transfer` extension; <=256 reads `*.conf`, so the `.transfer` files
/// shuttle emits are silently ignored on an older systemd (systemd-devel
/// v257.5 report; `sysupdate.d(5)`).
const SYSUPDATE_TRANSFER_MIN_MAJOR: u32 = 257;

/// Parse the systemd major version from `systemd-sysupdate --version` /
/// `systemctl --version` output. The first line is `systemd <major>
/// (<full>)`; the major is the leading integer of the second field. Never
/// panics: an empty, malformed, or non-numeric version yields `None`.
fn parse_systemd_major(version_output: &str) -> Option<u32> {
    let first = version_output.lines().next()?;
    let second = first.split_whitespace().nth(1)?;
    // The field is `<major>` or `<major> (<full>)`; take the leading digits.
    let digits: String = second.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Check the prerequisites of the emitted `systemd-sysupdate` trigger pair
/// (ADR-0024 §2): the `systemd-sysupdate` binary, `bootctl` (the rollback
/// path runs `bootctl set-default` in `src/runtime.rs`), and systemd >=
/// 257 (`.transfer` definitions are silently unread on <=256).
///
/// Warn-never-fail: every outcome is a report status. The version is read
/// from `systemd-sysupdate --version` when the binary exists, falling back
/// to `systemctl --version`; an undetectable or unparseable version warns
/// rather than panics.
fn check_sysupdate_prereqs() -> Check {
    check_sysupdate_version().into()
}

/// One [`Check`] for the whole sysupdate prerequisite set, naming the
/// missing piece precisely.
fn check_sysupdate_version() -> SysupdatePrereq {
    let Some(sysupdate) = snap::resolve_in_path("systemd-sysupdate", &snap::path_entries()) else {
        return SysupdatePrereq::MissingBinary;
    };
    if snap::resolve_in_path("bootctl", &snap::path_entries()).is_none() {
        return SysupdatePrereq::MissingBootctl;
    }
    let version = std::process::Command::new(&sysupdate)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .or_else(|| {
            std::process::Command::new("systemctl")
                .arg("--version")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        });
    match version {
        Some(text) => match parse_systemd_major(&text) {
            Some(major) if major >= SYSUPDATE_TRANSFER_MIN_MAJOR => {
                SysupdatePrereq::Ready { major }
            }
            Some(major) => SysupdatePrereq::TooOld { major },
            None => SysupdatePrereq::Undetectable {
                reason: format!("unparseable version output: {:?}", text.trim()),
            },
        },
        None => SysupdatePrereq::Undetectable {
            reason: "running 'systemd-sysupdate --version' and 'systemctl --version' \
                     both failed"
                .to_string(),
        },
    }
}

/// Outcome of [`check_sysupdate_version`].
#[derive(Debug, PartialEq, Eq)]
enum SysupdatePrereq {
    /// Binary present, systemd new enough to read `.transfer` definitions.
    Ready { major: u32 },
    /// `systemd-sysupdate` is not on PATH.
    MissingBinary,
    /// `bootctl` is not on PATH — the rollback path cannot select a boot entry.
    MissingBootctl,
    /// systemd is present but older than [`SYSUPDATE_TRANSFER_MIN_MAJOR`].
    TooOld { major: u32 },
    /// The version could not be read or parsed.
    Undetectable { reason: String },
}

impl From<SysupdatePrereq> for Check {
    fn from(prereq: SysupdatePrereq) -> Check {
        match prereq {
            SysupdatePrereq::Ready { major } => Check::ok_at(
                "systemd-sysupdate",
                format!("systemd {major} reads *.transfer definitions (needs >= 257)"),
            ),
            SysupdatePrereq::MissingBinary => Check::missing(
                "systemd-sysupdate",
                "the emitted systemd-sysupdate.timer/service pair needs the \
                 systemd-sysupdate binary — install systemd >= 257",
            ),
            SysupdatePrereq::MissingBootctl => Check::missing(
                "bootctl",
                "the sysupdate rollback path runs 'bootctl set-default' — install \
                 systemd-boot (systemd >= 257)",
            ),
            SysupdatePrereq::TooOld { major } => Check::error(
                "systemd-sysupdate",
                format!(
                    "systemd {major} reads sysupdate.d/*.conf, but shuttle emits \
                     *.transfer — transfer definitions are only read from systemd {min}+; \
                     upgrade systemd to {min} or newer",
                    min = SYSUPDATE_TRANSFER_MIN_MAJOR,
                ),
            ),
            SysupdatePrereq::Undetectable { reason } => Check::error(
                "systemd-sysupdate",
                format!(
                    "cannot determine the systemd version ({reason}) — shuttle emits \
                     *.transfer definitions, which only systemd {min}+ reads; verify the \
                     target has systemd {min} or newer",
                    min = SYSUPDATE_TRANSFER_MIN_MAJOR,
                ),
            ),
        }
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
/// `lib/modules/<version>/config*` (sorted for determinism). Shared with
/// the initrd-module build gate (ADR-0024 §1).
pub(crate) fn find_kernel_config(payload_dir: &Path, kernel_version: &str) -> Option<PathBuf> {
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

// ── Initrd boot-chain module audit (ADR-0024 §1) ──

/// The kernel-config symbols the boot chain depends on (ADR-0024 §1): the
/// virtio block driver and PCI transport, device-mapper and dm-verity, and
/// the root filesystem. A symbol set `=m` makes its driver a module the
/// initrd must carry; `=y` is built in and needs no module; an absent
/// symbol imposes nothing. The symbol set is fixed by the boot chain — the
/// required initrd MODULES are derived from what the config actually says.
const BOOT_CHAIN_CONFIG_SYMBOLS: &[&str] = &[
    "CONFIG_VIRTIO_BLK",
    "CONFIG_VIRTIO_PCI",
    "CONFIG_DM_MOD",
    "CONFIG_BLK_DEV_DM",
    "CONFIG_DM_VERITY",
    "CONFIG_EXT4_FS",
];

/// Symbol→module-name irregularities. The module name is normally the
/// config symbol minus `CONFIG_`, lowercased (`CONFIG_VIRTIO_BLK` →
/// `virtio_blk`); these three do not follow that rule and carry an
/// explicit name. This is the irregularity shim, not the rule — there is
/// no unconditional module list.
const MODULE_NAME_OVERRIDES: &[(&str, &str)] = &[
    // Pre-4.4 alias of CONFIG_DM_MOD; both name the same module.
    ("CONFIG_BLK_DEV_DM", "dm_mod"),
    // The repo's boot-chain spelling (hyphen), not the symbol's `_`.
    ("CONFIG_DM_VERITY", "dm-verity"),
    // The module is `ext4`, not the symbol's `ext4_fs`.
    ("CONFIG_EXT4_FS", "ext4"),
];

/// Module name for a boot-chain config symbol: the override shim when one
/// exists, otherwise the symbol minus `CONFIG_`, lowercased.
pub(crate) fn module_name_for_symbol(symbol: &str) -> String {
    if let Some((_, module)) = MODULE_NAME_OVERRIDES.iter().find(|(s, _)| *s == symbol) {
        return (*module).to_string();
    }
    symbol
        .strip_prefix("CONFIG_")
        .unwrap_or(symbol)
        .to_lowercase()
}

/// The initrd modules a kernel config requires: every boot-chain symbol
/// set `=m` contributes its module; `=y` and absent symbols contribute
/// none. Sorted for a deterministic required set and error message.
pub(crate) fn required_initrd_modules(config_text: &str) -> Vec<String> {
    let mut modules: Vec<String> = Vec::new();
    for line in config_text.lines() {
        let line = line.trim();
        let Some((symbol, value)) = line.split_once('=') else {
            continue;
        };
        let symbol = symbol.trim();
        if !BOOT_CHAIN_CONFIG_SYMBOLS.contains(&symbol) || value.trim() != "m" {
            continue;
        }
        let module = module_name_for_symbol(symbol);
        if !modules.contains(&module) {
            modules.push(module);
        }
    }
    modules.sort();
    modules
}

/// Whether an initrd member path is the loadable module `module`: the
/// basename is `<module>.ko` or that plus a compression suffix, regardless
/// of where in the archive it lives (`kernels/<ver>/...` or any path).
pub(crate) fn member_is_module(member: &str, module: &str) -> bool {
    let base = member.rsplit('/').next().unwrap_or(member);
    let Some(rest) = base.strip_prefix(module) else {
        return false;
    };
    matches!(rest, ".ko" | ".ko.xz" | ".ko.zst" | ".ko.gz")
}

/// gzip magic (`\x1f\x8b`) — the most common initrd wrapper.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// zstd magic (`\x28\xb5\x2f\xfd`).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// xz magic (`\xfd7zXZ`).
const XZ_MAGIC: [u8; 5] = [0xfd, 0x37, 0x7a, 0x58, 0x5a];
/// lz4 frame magic (`\x04\x22\x4d\x18`).
const LZ4_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
/// `newc` cpio archive magics (`070701` and its CRC variant `070702`).
const NEWC_MAGICS: [&[u8]; 2] = [b"070701", b"070702"];

/// `true` when `data` begins with a `newc` cpio member header.
fn is_newc(data: &[u8]) -> bool {
    NEWC_MAGICS.iter().any(|magic| data.starts_with(magic))
}

/// Host decompressor for a recognized initrd compression magic, or `None`
/// when the bytes carry no recognized wrapper.
fn decompressor_for(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(&GZIP_MAGIC) {
        Some("gzip")
    } else if head.starts_with(&ZSTD_MAGIC) {
        Some("zstd")
    } else if head.starts_with(&XZ_MAGIC) {
        Some("xz")
    } else if head.starts_with(&LZ4_MAGIC) {
        Some("lz4")
    } else {
        None
    }
}

/// 4-byte alignment used by every `newc` cpio member field boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Decompress (through the injected [`CommandRunner`]) and walk `initrd`,
/// returning every cpio member path. An uncompressed `newc` archive is
/// read directly; a wrapped one is piped through `gzip -dc` / `zstd -dc` /
/// `xz -dc` / `lz4 -dc` into memory. Fails closed on an unrecognized
/// format or a failed decompressor — an initrd that cannot be read cannot
/// be verified.
pub(crate) fn read_initrd_members(
    runner: &dyn CommandRunner,
    initrd: &Path,
) -> miette::Result<Vec<String>> {
    let raw = std::fs::read(initrd)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading initrd {}", initrd.display()))?;
    let data = if is_newc(&raw) {
        raw
    } else if let Some(program) = decompressor_for(&raw) {
        let argv = vec![
            program.to_string(),
            "-dc".to_string(),
            initrd.to_string_lossy().into_owned(),
        ];
        let out = runner.run(&argv).map_err(|e| {
            miette::miette!("failed to run {program} for {}: {e}", initrd.display())
        })?;
        if out.code != 0 {
            return Err(miette::miette!(
                "{program} failed (exit {}) decompressing {} — the initrd cannot be read, \
                 so the boot-chain modules cannot be verified",
                out.code,
                initrd.display()
            ));
        }
        out.stdout
    } else {
        return Err(miette::miette!(
            "unrecognized initrd format at {}: not gzip/zstd/xz/lz4 and not a newc cpio \
             archive — refusing to ship a kernel whose initrd cannot be verified",
            initrd.display()
        ));
    };
    cpio_newc_members(&data).wrap_err_with(|| format!("walking initrd {}", initrd.display()))
}

/// Walk a `newc` cpio archive, collecting member names. The 110-byte ASCII
/// header (6-byte magic + thirteen 8-hex fields) is followed by the
/// NUL-terminated name and the file data, each padded to a 4-byte
/// boundary; the archive ends at the `TRAILER!!!` member.
pub(crate) fn cpio_newc_members(data: &[u8]) -> miette::Result<Vec<String>> {
    let mut members = Vec::new();
    let mut pos = 0usize;
    loop {
        if data.len() < pos + 110 {
            return Err(miette::miette!(
                "truncated cpio archive ({} bytes, no room for a header at offset {pos})",
                data.len()
            ));
        }
        let header = &data[pos..pos + 110];
        if !is_newc(header) {
            return Err(miette::miette!(
                "unrecognized cpio member magic at offset {pos} — not a newc initrd"
            ));
        }
        let field = |index: usize| -> miette::Result<u64> {
            let raw = &header[6 + index * 8..6 + index * 8 + 8];
            let text = std::str::from_utf8(raw)
                .map_err(|_| miette::miette!("non-ASCII cpio header field at offset {pos}"))?;
            u64::from_str_radix(text, 16)
                .map_err(|_| miette::miette!("invalid hex cpio header field '{text}'"))
        };
        let filesize = field(6)? as usize;
        let namesize = field(11)? as usize;
        if namesize == 0 {
            return Err(miette::miette!(
                "zero-length cpio member name at offset {pos}"
            ));
        }
        let name_start = pos + 110;
        let name_end = name_start
            .checked_add(namesize)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| miette::miette!("truncated cpio member name at offset {pos}"))?;
        let name = String::from_utf8_lossy(&data[name_start..name_end - 1]).into_owned();
        let data_end = align4(name_end)
            .checked_add(filesize)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| miette::miette!("truncated cpio member '{name}' data"))?;
        if name == "TRAILER!!!" {
            break;
        }
        members.push(name);
        pos = align4(data_end);
    }
    Ok(members)
}

/// Outcome of the initrd boot-chain module audit
/// ([`audit_kernel_initrd_modules`]).
#[derive(Debug, PartialEq, Eq)]
pub enum InitrdModuleAudit {
    /// Every module the config requires is reachable from the initrd
    /// (empty when the config builds the whole boot chain in).
    Satisfied(Vec<String>),
    /// The config requires these modules but the initrd does not carry
    /// them; `config` is the provenance of the required set.
    Missing {
        config: PathBuf,
        missing: Vec<String>,
    },
    /// No kernel config source found — the required set cannot be derived.
    NoConfig,
    /// The initrd could not be read or decompressed as a recognized format.
    Unreadable(String),
}

/// Core inspection shared by the build gate and the doctor twin: locate the
/// kernel config under `payload_dir`, derive the required boot-chain
/// modules, and check them against the initrd members. Never panics; every
/// failure mode is represented in [`InitrdModuleAudit`].
pub(crate) fn inspect_initrd_modules(
    runner: &dyn CommandRunner,
    payload_dir: &Path,
    kernel_version: &str,
    initrd: &Path,
) -> InitrdModuleAudit {
    let Some(config) = find_kernel_config(payload_dir, kernel_version) else {
        return InitrdModuleAudit::NoConfig;
    };
    let Ok(text) = std::fs::read_to_string(&config) else {
        return InitrdModuleAudit::NoConfig;
    };
    let required = required_initrd_modules(&text);
    // A fully built-in boot chain needs nothing from the initrd, so there
    // is nothing to verify — do not punish an empty/odd initrd for it.
    if required.is_empty() {
        return InitrdModuleAudit::Satisfied(Vec::new());
    }
    let members = match read_initrd_members(runner, initrd) {
        Ok(members) => members,
        Err(e) => return InitrdModuleAudit::Unreadable(format!("{e:#}")),
    };
    let missing: Vec<String> = required
        .iter()
        .filter(|module| !members.iter().any(|m| member_is_module(m, module)))
        .cloned()
        .collect();
    if missing.is_empty() {
        InitrdModuleAudit::Satisfied(required)
    } else {
        InitrdModuleAudit::Missing { config, missing }
    }
}

/// Audit the kernel initrd for the boot-chain modules its config requires
/// (ADR-0024 §1) and yield a [`Check`] for the doctor report surface.
/// Non-fatal twin of the build gate: warns — NEVER fails — so `doctor` can
/// report the same finding the image build enforces. `payload_dir` is
/// searched for the config ([`find_kernel_config`]); `initrd` is the
/// resolved kernel's initrd. Needs the kernel payload, so it is called from
/// the image build — not from the host-only [`run_all`].
pub fn audit_kernel_initrd_modules(
    runner: &dyn CommandRunner,
    payload_dir: &Path,
    kernel_version: &str,
    initrd: &Path,
) -> Check {
    let outcome = inspect_initrd_modules(runner, payload_dir, kernel_version, initrd);
    initrd_modules_check(kernel_version, &outcome)
}

// ── Builder-context readiness checks (need the image in hand) ──

/// Render the state-partition readiness result as a [`Check`]. Pure so the
/// pass/warn mapping is unit-testable without a full [`ImageDeclaration`].
///
/// `needs_split` is [`crate::image::needs_state_split`]; `state_present` is
/// whether any declared partition carries the state role. A `Ok` when the
/// split is not requested, or when it is requested and a state partition
/// exists; `Missing` naming the affected paths when it is requested but
/// absent (the build fails closed on this via `resolve_state_split`).
fn state_partition_check(
    image_name: &str,
    needs_split: bool,
    state_present: bool,
    paths: [&str; 2],
) -> Check {
    if !needs_split {
        return Check::ok_at(
            "state partition",
            "not requested (no state role, no update_source) — no /var split",
        );
    }
    if state_present {
        return Check::ok_at(
            "state partition",
            format!(
                "declared; {} and {} persist across A/B flips",
                paths[0], paths[1]
            ),
        );
    }
    Check::missing(
        "state partition",
        format!(
            "image '{image_name}' needs the /var split (state role or update_source) but \
             the disk layout declares no role = \"state\" partition — {} and {} would live \
             in the read-only verity root and be lost on the first A/B flip; declare a \
             state partition (the build fails closed on this)",
            paths[0], paths[1]
        ),
    )
}

/// Builder-context readiness check for the state partition (ADR-0023,
/// issue #65). Needs the [`ImageDeclaration`] and its [`DiskLayout`], which
/// the host-only [`run_all`] has no access to — so this is called from the
/// image build with the image in hand, mirroring
/// [`audit_kernel_verity_config`]. Warn-never-fail: prints a report line
/// and returns the [`Check`]; the build's own fail-closed path is
/// `resolve_state_split`, untouched here.
pub fn audit_state_partition(
    image: &crate::image::ImageDeclaration,
    layout: &crate::image::DiskLayout,
) -> Check {
    let needs_split = crate::image::needs_state_split(image, layout);
    let state_present = layout
        .partitions
        .iter()
        .any(crate::image::is_state_partition);
    let check = state_partition_check(
        &image.name,
        needs_split,
        state_present,
        crate::image::state_dirs(),
    );
    match &check.status {
        CheckStatus::Ok => eprintln!("  ✓ doctor: state partition — {}", hint_of(&check)),
        _ => eprintln!("  ⚠ doctor: state partition — {}", hint_of(&check)),
    }
    check
}

/// `hint` for a report line, or a fallback when a check carries none.
fn hint_of(check: &Check) -> &str {
    check.hint.as_deref().unwrap_or("ok")
}

/// Render an [`InitrdModuleAudit`] as a [`Check`]. Pure so the
/// Satisfied/Missing/NoConfig/Unreadable mapping is unit-testable without a
/// real initrd.
fn initrd_module_check_for(kernel_version: &str, outcome: &InitrdModuleAudit) -> Check {
    match outcome {
        InitrdModuleAudit::Satisfied(modules) if modules.is_empty() => Check::ok_at(
            "initrd module inventory",
            format!("kernel {kernel_version} builds the boot chain in — no modules required"),
        ),
        InitrdModuleAudit::Satisfied(modules) => Check::ok_at(
            "initrd module inventory",
            format!(
                "kernel {kernel_version} initrd carries: {}",
                modules.join(", ")
            ),
        ),
        InitrdModuleAudit::Missing { config, missing } => Check::missing(
            "initrd module inventory",
            format!(
                "kernel {kernel_version} initrd is missing boot-chain module(s): {} \
                 (required by {}) — the kernel cannot see its own disk at boot",
                missing.join(", "),
                config.display()
            ),
        ),
        InitrdModuleAudit::NoConfig => Check::missing(
            "initrd module inventory",
            format!(
                "no kernel config for {kernel_version} — cannot derive the required \
                 boot-chain modules and confirm the initrd carries them"
            ),
        ),
        InitrdModuleAudit::Unreadable(reason) => Check::error(
            "initrd module inventory",
            format!("kernel {kernel_version} initrd could not be read: {reason}"),
        ),
    }
}

/// Build an initrd-inventory [`Check`] from an already-computed
/// [`InitrdModuleAudit`] outcome and print its report line. Split from
/// [`inspect_initrd_modules`] so the build computes the audit ONCE and both
/// renders it here and applies its own hard gate — no duplicate
/// decompression. Warn-never-fail: the hard gate is the build's own
/// `audit_initrd_modules`.
pub fn initrd_modules_check(kernel_version: &str, outcome: &InitrdModuleAudit) -> Check {
    let check = initrd_module_check_for(kernel_version, outcome);
    match &check.status {
        CheckStatus::Ok => eprintln!("  ✓ doctor: {} — {}", check.name, hint_of(&check)),
        _ => eprintln!("  ⚠ doctor: {} — {}", check.name, hint_of(&check)),
    }
    check
}

// ── Host tooling checks ──

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

    // ── Initrd boot-chain module audit (ADR-0024 §1) ──

    /// A fake runner that answers every recognized decompressor with a
    /// fixed payload, recording the argv it was handed (the module reader
    /// test needs no host tools).
    struct DecompressRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        stdout: Vec<u8>,
        code: i32,
    }

    impl DecompressRunner {
        fn new(stdout: Vec<u8>, code: i32) -> DecompressRunner {
            DecompressRunner {
                calls: std::sync::Mutex::new(Vec::new()),
                stdout,
                code,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for DecompressRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            Ok(crate::command::RunnerOutput {
                code: self.code,
                stdout: self.stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    /// 4-byte align, matching the newc member boundary.
    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    /// Build one `newc` cpio member: header + NUL-terminated name + data,
    /// each padded to a 4-byte boundary. `mode` 0o100644 marks a plain file.
    fn cpio_member(name: &str, data: &[u8]) -> Vec<u8> {
        let namesize = name.len() + 1;
        let mut out = format!(
            "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{filesize:08x}\
             {devmajor:08x}{devminor:08x}{rdevmajor:08x}{rdevminor:08x}{namesize:08x}{check:08x}",
            ino = 1,
            mode = 0o100644,
            uid = 0,
            gid = 0,
            nlink = 1,
            mtime = 0,
            filesize = data.len(),
            devmajor = 0,
            devminor = 0,
            rdevmajor = 0,
            rdevminor = 0,
            namesize = namesize,
            check = 0,
        )
        .into_bytes();
        assert_eq!(out.len(), 110, "newc header is 110 ASCII bytes");
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(align4(out.len()), 0);
        out.extend_from_slice(data);
        out.resize(align4(out.len()), 0);
        out
    }

    /// A complete `newc` archive from `(name, data)` members plus the
    /// `TRAILER!!!` terminator.
    fn newc_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in members {
            out.extend_from_slice(&cpio_member(name, data));
        }
        out.extend_from_slice(&cpio_member("TRAILER!!!", b""));
        out
    }

    /// A minimal gzip wrapper: fixed header (no name/mtime) + payload +
    /// stored (uncompressed) DEFLATE blocks + CRC32 + ISIZE. Enough to
    /// carry a recognized magic without a host compressor.
    fn gzip_stored(payload: &[u8]) -> Vec<u8> {
        // A single stored DEFLATE block can carry at most 65535 bytes.
        assert!(payload.len() <= 65535, "test gzip carries one stored block");
        let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        out.push(0x01); // BFINAL=1, BTYPE=00 (stored)
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        out.extend_from_slice(payload);
        let crc = crc32(payload);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out
    }

    /// CRC-32 (IEEE) — the gzip trailer.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn config_with(lines: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("boot").join("config-6.8.0");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, lines).unwrap();
        dir
    }

    #[test]
    fn required_modules_derive_m_symbols() {
        let config = "\
CONFIG_VIRTIO_BLK=m
CONFIG_VIRTIO_PCI=m
CONFIG_DM_MOD=m
CONFIG_DM_VERITY=m
CONFIG_EXT4_FS=m
";
        assert_eq!(
            required_initrd_modules(config),
            vec!["dm-verity", "dm_mod", "ext4", "virtio_blk", "virtio_pci"]
        );
    }

    #[test]
    fn built_in_y_symbols_require_no_module() {
        // =y is compiled in — the initrd needs nothing for it.
        let config = "\
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_PCI=y
CONFIG_DM_MOD=y
CONFIG_DM_VERITY=y
CONFIG_EXT4_FS=y
";
        assert!(required_initrd_modules(config).is_empty());
    }

    #[test]
    fn absent_symbol_is_not_required() {
        // Only VIRTIO_BLK is present; nothing else is imposed.
        let config = "CONFIG_VIRTIO_BLK=m\nCONFIG_RANDOM_OTHER=m\n";
        assert_eq!(required_initrd_modules(config), vec!["virtio_blk"]);
    }

    #[test]
    fn blk_dev_dm_alias_maps_to_dm_mod() {
        // Pre-4.4 alias of CONFIG_DM_MOD: same module, no duplicate.
        let config = "CONFIG_BLK_DEV_DM=m\nCONFIG_DM_MOD=m\n";
        assert_eq!(required_initrd_modules(config), vec!["dm_mod"]);
    }

    #[test]
    fn module_name_is_derived_from_symbol() {
        assert_eq!(module_name_for_symbol("CONFIG_VIRTIO_BLK"), "virtio_blk");
        assert_eq!(module_name_for_symbol("CONFIG_VIRTIO_PCI"), "virtio_pci");
        assert_eq!(module_name_for_symbol("CONFIG_DM_MOD"), "dm_mod");
        assert_eq!(module_name_for_symbol("CONFIG_DM_VERITY"), "dm-verity");
        assert_eq!(module_name_for_symbol("CONFIG_EXT4_FS"), "ext4");
        // Unlisted symbols still derive by the rule, never a hardcoded list.
        assert_eq!(module_name_for_symbol("CONFIG_NVME_CORE"), "nvme_core");
    }

    #[test]
    fn member_match_accepts_compression_suffixes_and_any_path() {
        assert!(member_is_module("virtio_blk.ko", "virtio_blk"));
        assert!(member_is_module(
            "kernels/6.8.0/virtio_blk.ko.xz",
            "virtio_blk"
        ));
        assert!(member_is_module(
            "lib/modules/x/dm-verity.ko.zst",
            "dm-verity"
        ));
        assert!(member_is_module("ext4.ko.gz", "ext4"));
        // A prefix collision is not a match.
        assert!(!member_is_module("virtio_blk_extra.ko", "virtio_blk"));
        assert!(!member_is_module("virtio_blk.ko.txt", "virtio_blk"));
        assert!(!member_is_module("nvme.ko", "virtio_blk"));
    }

    #[test]
    fn initrd_reader_walks_uncompressed_newc() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        let archive = newc_archive(&[
            ("kernels/6.8.0/virtio_blk.ko", b"blob"),
            ("kernels/6.8.0/dm-verity.ko.xz", b"blob"),
            ("init", b"#!/bin/sh"),
        ]);
        std::fs::write(&initrd, &archive).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let members = read_initrd_members(&runner, &initrd).unwrap();
        assert_eq!(
            members,
            vec![
                "kernels/6.8.0/virtio_blk.ko",
                "kernels/6.8.0/dm-verity.ko.xz",
                "init",
            ]
        );
        assert!(
            runner.calls().is_empty(),
            "an uncompressed newc needs no host tool"
        );
    }

    #[test]
    fn initrd_reader_pipes_gzip_through_the_runner() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd.img");
        let archive = newc_archive(&[("kernels/6.8.0/virtio_blk.ko", b"blob")]);
        std::fs::write(&initrd, gzip_stored(&archive)).unwrap();
        let runner = DecompressRunner::new(archive, 0);
        let members = read_initrd_members(&runner, &initrd).unwrap();
        assert_eq!(members, vec!["kernels/6.8.0/virtio_blk.ko"]);
        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "one decompressor invocation: {calls:?}");
        assert_eq!(calls[0][0], "gzip", "magic selects gzip: {calls:?}");
        assert_eq!(calls[0][1], "-dc");
        assert_eq!(calls[0][2], initrd.to_string_lossy());
    }

    #[test]
    fn initrd_reader_rejects_unrecognized_format() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        std::fs::write(&initrd, b"not an initrd at all, just bytes").unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let err = read_initrd_members(&runner, &initrd).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unrecognized initrd format"),
            "must fail closed naming the format: {msg}"
        );
        assert!(runner.calls().is_empty(), "no decompressor for garbage");
    }

    #[test]
    fn initrd_reader_fails_closed_when_decompressor_fails() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        std::fs::write(&initrd, gzip_stored(b"payload")).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 1);
        let err = read_initrd_members(&runner, &initrd).unwrap_err();
        assert!(
            format!("{err:#}").contains("gzip failed"),
            "a failed decompressor is a hard error: {err:#}"
        );
    }

    #[test]
    fn audit_reports_missing_module_with_precise_name() {
        let config = config_with("CONFIG_VIRTIO_BLK=m\nCONFIG_EXT4_FS=m\n");
        let initrd = config.path().join("boot").join("initrd.img-6.8.0");
        // ext4 is present, virtio_blk is not.
        std::fs::write(&initrd, newc_archive(&[("kernels/6.8.0/ext4.ko", b"k")])).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let outcome = inspect_initrd_modules(&runner, config.path(), "6.8.0", &initrd);
        match outcome {
            InitrdModuleAudit::Missing { missing, .. } => {
                assert_eq!(missing, vec!["virtio_blk"]);
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn audit_satisfied_when_all_modules_present() {
        let config = config_with("CONFIG_VIRTIO_BLK=m\nCONFIG_EXT4_FS=m\n");
        let initrd = config.path().join("boot").join("initrd.img-6.8.0");
        std::fs::write(
            &initrd,
            newc_archive(&[
                ("kernels/6.8.0/virtio_blk.ko", b"k"),
                ("kernels/6.8.0/ext4.ko.xz", b"k"),
            ]),
        )
        .unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let outcome = inspect_initrd_modules(&runner, config.path(), "6.8.0", &initrd);
        assert_eq!(
            outcome,
            InitrdModuleAudit::Satisfied(vec!["ext4".into(), "virtio_blk".into()])
        );
    }

    #[test]
    fn audit_without_config_reports_no_config() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        std::fs::write(&initrd, newc_archive(&[])).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        assert_eq!(
            inspect_initrd_modules(&runner, dir.path(), "6.8.0", &initrd),
            InitrdModuleAudit::NoConfig
        );
    }

    #[test]
    fn audit_unreadable_initrd_reports_unreadable() {
        let config = config_with("CONFIG_VIRTIO_BLK=m\n");
        let initrd = config.path().join("initrd");
        std::fs::write(&initrd, b"garbage bytes").unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        match inspect_initrd_modules(&runner, config.path(), "6.8.0", &initrd) {
            InitrdModuleAudit::Unreadable(reason) => {
                assert!(
                    reason.contains("unrecognized initrd format"),
                    "reason names the format: {reason}"
                );
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn audit_all_built_in_needs_no_readable_initrd() {
        // A fully built-in config requires nothing, so an initrd that would
        // otherwise be unreadable is not consulted (no false failure).
        let config = config_with("CONFIG_VIRTIO_BLK=y\nCONFIG_DM_VERITY=y\n");
        let initrd = config.path().join("initrd");
        std::fs::write(&initrd, b"not an archive").unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        assert_eq!(
            inspect_initrd_modules(&runner, config.path(), "6.8.0", &initrd),
            InitrdModuleAudit::Satisfied(Vec::new())
        );
    }

    // ── systemd-sysupdate prerequisites (#65) ──

    #[test]
    fn run_all_includes_sysupdate_prereq_check() {
        let checks = run_all();
        assert!(
            checks.iter().any(|c| c.name == "systemd-sysupdate"),
            "missing systemd-sysupdate readiness check"
        );
    }

    #[test]
    fn sysupdate_check_carries_a_hint() {
        // Whichever branch the host lands on, a non-Ok check names the fix
        // (the report invariant) and an Ok check explains itself.
        let check = check_sysupdate_prereqs();
        assert!(check.hint.is_some(), "check must carry a hint: {check:?}");
        if !matches!(check.status, CheckStatus::Ok) {
            let hint = check.hint.as_deref().unwrap_or_default();
            assert!(
                hint.contains("257") || hint.contains("systemd"),
                "hint must name the fix: {hint}"
            );
        }
    }

    #[test]
    fn parse_systemd_major_reads_major_from_version_line() {
        assert_eq!(
            parse_systemd_major("systemd 261 (261.2)\n+PAM ...\n"),
            Some(261)
        );
        assert_eq!(parse_systemd_major("systemd 256 (256.4)"), Some(256));
        assert_eq!(parse_systemd_major("systemd 257"), Some(257));
    }

    #[test]
    fn parse_systemd_major_never_panics_on_garbage() {
        assert_eq!(parse_systemd_major(""), None);
        assert_eq!(parse_systemd_major("no version here"), None);
        assert_eq!(parse_systemd_major("systemd"), None);
        assert_eq!(parse_systemd_major("systemd (nope)"), None);
    }

    #[test]
    fn sysupdate_version_at_or_above_257_is_ok() {
        let check: Check = SysupdatePrereq::Ready { major: 257 }.into();
        assert!(matches!(check.status, CheckStatus::Ok));
        assert!(check.hint.as_deref().unwrap_or_default().contains("257"));
    }

    #[test]
    fn sysupdate_version_below_257_warns_with_precise_hint() {
        let check: Check = SysupdatePrereq::TooOld { major: 256 }.into();
        assert!(matches!(check.status, CheckStatus::Error));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("256") && hint.contains("257") && hint.contains(".transfer"),
            "hint must name the detected and required versions and the cause: {hint}"
        );
    }

    #[test]
    fn sysupdate_version_undetectable_warns_never_panics() {
        let check: Check = SysupdatePrereq::Undetectable {
            reason: "unparseable".into(),
        }
        .into();
        assert!(matches!(check.status, CheckStatus::Error));
        assert!(check.hint.as_deref().unwrap_or_default().contains("257"));
    }

    #[test]
    fn sysupdate_missing_binary_and_bootctl_name_the_fix() {
        let missing_bin: Check = SysupdatePrereq::MissingBinary.into();
        assert!(matches!(missing_bin.status, CheckStatus::Missing));
        assert!(missing_bin
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("systemd-sysupdate"));

        let missing_bootctl: Check = SysupdatePrereq::MissingBootctl.into();
        assert!(matches!(missing_bootctl.status, CheckStatus::Missing));
        assert!(missing_bootctl
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("bootctl"));
    }

    // ── State-partition readiness (#65) ──

    #[test]
    fn state_partition_not_requested_is_ok() {
        let check = state_partition_check(
            "img",
            false,
            false,
            ["/var/lib/shuttle", "/var/lib/extensions"],
        );
        assert!(matches!(check.status, CheckStatus::Ok));
        assert!(check.hint.is_some());
    }

    #[test]
    fn state_partition_requested_and_present_is_ok() {
        let check = state_partition_check(
            "img",
            true,
            true,
            ["/var/lib/shuttle", "/var/lib/extensions"],
        );
        assert!(matches!(check.status, CheckStatus::Ok));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("/var/lib/shuttle"),
            "hint names the paths: {hint}"
        );
    }

    #[test]
    fn state_partition_requested_but_absent_names_the_paths() {
        let check = state_partition_check(
            "img",
            true,
            false,
            ["/var/lib/shuttle", "/var/lib/extensions"],
        );
        assert!(matches!(check.status, CheckStatus::Missing));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("/var/lib/shuttle") && hint.contains("/var/lib/extensions"),
            "hint must name the affected paths: {hint}"
        );
        assert!(hint.contains("img"), "hint names the image: {hint}");
    }

    // ── Initrd module inventory as a Check (#65) ──

    #[test]
    fn initrd_inventory_satisfied_lists_modules() {
        let outcome = InitrdModuleAudit::Satisfied(vec!["ext4".into(), "virtio_blk".into()]);
        let check = initrd_module_check_for("6.8.0", &outcome);
        assert!(matches!(check.status, CheckStatus::Ok));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("ext4") && hint.contains("virtio_blk"),
            "{hint}"
        );
    }

    #[test]
    fn initrd_inventory_all_built_in_is_ok() {
        let check = initrd_module_check_for("6.8.0", &InitrdModuleAudit::Satisfied(Vec::new()));
        assert!(matches!(check.status, CheckStatus::Ok));
    }

    #[test]
    fn initrd_inventory_missing_names_modules_and_config() {
        let outcome = InitrdModuleAudit::Missing {
            config: PathBuf::from("/payload/boot/config-6.8.0"),
            missing: vec!["virtio_blk".into()],
        };
        let check = initrd_module_check_for("6.8.0", &outcome);
        assert!(matches!(check.status, CheckStatus::Missing));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(hint.contains("virtio_blk"), "names the module: {hint}");
        assert!(hint.contains("config-6.8.0"), "names the config: {hint}");
    }

    #[test]
    fn initrd_inventory_no_config_and_unreadable_warn_with_hints() {
        let no_config = initrd_module_check_for("6.8.0", &InitrdModuleAudit::NoConfig);
        assert!(matches!(no_config.status, CheckStatus::Missing));
        assert!(no_config.hint.is_some());

        let unreadable =
            initrd_module_check_for("6.8.0", &InitrdModuleAudit::Unreadable("bad magic".into()));
        assert!(matches!(unreadable.status, CheckStatus::Error));
        assert!(unreadable
            .hint
            .as_deref()
            .unwrap_or_default()
            .contains("bad magic"));
    }

    #[test]
    fn initrd_inventory_check_never_fails_the_caller() {
        // The Check is a report status, not a Result: even a Missing
        // outcome is returned (never an Err), which is what makes the
        // builder-context call warn-never-fail.
        let config = config_with("CONFIG_VIRTIO_BLK=m\n");
        let initrd = config.path().join("boot").join("initrd.img-6.8.0");
        std::fs::write(&initrd, newc_archive(&[("kernels/6.8.0/ext4.ko", b"k")])).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let check = audit_kernel_initrd_modules(&runner, config.path(), "6.8.0", &initrd);
        assert!(matches!(check.status, CheckStatus::Missing));
        assert!(check.hint.is_some());
    }

    #[test]
    fn doctor_report_smoke_renders_all_new_checks() {
        let checks = run_all();
        let mut with_builder = checks;
        with_builder.push(Check::missing("state partition", "declare role = state"));
        with_builder.push(Check::error(
            "initrd module inventory",
            "missing virtio_blk",
        ));
        // print_report must render every status without panicking, and must
        // keep reporting a non-Ok result through all_ok.
        print_report(&with_builder);
        assert!(!all_ok(&with_builder));
    }
}
