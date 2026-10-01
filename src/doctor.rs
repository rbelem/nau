//! System readiness checks — `nau doctor`.
//!
//! Verifies that all required tools are installed and working before
//! attempting a build. Run via `nau doctor` (full surface) or
//! `nau doctor --pod` (pod-verb surface only, issue #97).

use std::io;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use crate::command::CommandRunner;
use crate::snap;
use crate::tools::{self, ResolvedTool, ToolName};

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
/// (`mksquashfs`, `bwrap`) are invoked by nau itself before/after the
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
        "install make system-wide so it is on the login PATH (e.g. NixOS \
         systemPackages, apt install make)",
    ),
    (
        "cc",
        "install gcc system-wide so it is on the login PATH (e.g. NixOS \
         systemPackages, apt install gcc)",
    ),
];

/// The pod-surface floor tools (#101): doctor resolves each through
/// [`tools::resolve`] and reports origin (provisioned vs PATH) + version.
/// The fix text is the distro-package FALLBACK — the primary fix for a
/// missing floor tool is `nau doctor --fix`, which self-provisions.
const POD_TOOL_FIXES: [(ToolName, &str); 5] = [
    (
        ToolName::Mksquashfs,
        "install squashfs-tools (e.g. apt install squashfs-tools)",
    ),
    (
        ToolName::Unsquashfs,
        "install squashfs-tools (e.g. apt install squashfs-tools)",
    ),
    (
        ToolName::Bwrap,
        "install bubblewrap (e.g. apt install bubblewrap)",
    ),
    (ToolName::Tar, "install tar (e.g. apt install tar)"),
    (ToolName::Curl, "install curl (e.g. apt install curl)"),
];

/// The distro-package fallback fix for one floor tool.
fn distro_fix_for(name: ToolName) -> &'static str {
    POD_TOOL_FIXES
        .iter()
        .find(|(tool, _)| *tool == name)
        .map(|(_, fix)| *fix)
        .unwrap_or("install the tool")
}

/// Pod-scope build toolchain (#97): the sandbox tools plus the C++
/// driver the vendored Luau analyzer needs. The cc/c++ fixes lead with
/// the gcc payload sideload (issue #164 follow-up: one payload carries
/// cc and c++), keeping the distro packages as the fallback per
/// install.sh's map (g++, gcc-c++ on dnf/zypper); `sh`/`make` have no
/// payload, so they keep the sandbox phrasing. cc/c++ additionally get
/// the pod-env credit ([`POD_ENV_TOOLS`], issue #178) — the hint below
/// is for the genuinely-absent case only.
const POD_SANDBOX_TOOLS: [(&str, &str); 4] = [
    (
        "sh",
        "the sandbox runs every build via sh — /bin or /usr/bin must provide it",
    ),
    (
        "make",
        "install make system-wide so it is on the login PATH (e.g. NixOS \
         systemPackages, apt install make)",
    ),
    (
        "cc",
        "sideload the gcc payload (`nau pod add --ack-unsigned --snap \
         gcc_14.2.0.snap` — carries cc and c++), or install gcc system-wide \
         (e.g. NixOS systemPackages, apt install gcc)",
    ),
    (
        "c++",
        "sideload the gcc payload (`nau pod add --ack-unsigned --snap \
         gcc_14.2.0.snap` — carries cc and c++), or install g++ (e.g. apt \
         install g++, dnf install gcc-c++)",
    ),
];

/// The pod-scope tools that additionally credit the pod farms (issue
/// #178): both C toolchain names ride the gcc payload's farm shims
/// (commit 77964ae), and `nau run --pod` composes a farm-first
/// PATH ([`crate::confine`] `overlay_pod_env_with`) that resolves them
/// with no host install — the check must read readiness the same way
/// the run form does. `sh`/`make` have no payload-shim contract, so
/// they keep the sandbox-visibility semantics only.
const POD_ENV_TOOLS: [&str; 2] = ["cc", "c++"];

/// Which tool surface `doctor` gates (issue #97).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Default: the pod surface plus the image-verb surface (ukify,
    /// the sd-stub, veritysetup, systemd-sysupdate). The mksquashfs
    /// version gate runs in both scopes (#155) — pod builds pay the
    /// pack cost too.
    Full,
    /// `--pod`: what the pod verbs need — the pod tools, the build
    /// toolchain, and the mksquashfs version gate (#155: pod builds
    /// pay the pack cost). A healthy pod-only machine passes even with
    /// no image tools installed.
    Pod,
}

/// Run the full system checks (the default scope). Returns a list of results.
///
/// Host-only checks live here. Checks that need an [`ImageDeclaration`] (the
/// state-partition readiness and the initrd module inventory) cannot run in
/// this host-readiness command — `doctor` is invoked with no image — so they
/// are exposed as builder-context functions called from the image build with
/// the image in hand, mirroring [`audit_kernel_verity_config`]
/// (`src/image/mod.rs`). Both never fail the build; they add a report line.
pub fn run_all() -> Vec<Check> {
    run_scoped(Scope::Full)
}

/// Run the pod-verb checks (`nau doctor --pod`, issue #97): the pod
/// tools (mksquashfs/unsquashfs, bwrap, curl, tar), the sandbox build
/// toolchain (sh, make, cc, c++), and — since #155 — the mksquashfs
/// version gate, because pod builds pay the pack cost. The remaining
/// image-verb checks are skipped — the installer's verify step gates on
/// this scope, so a machine with the pod set but no image tools reads as
/// ready. The cc/c++ checks also credit toolchains reachable through the
/// farm-first pod env of any healthy pod (issue #178) — readiness as
/// `nau run --pod` would see it.
pub fn run_pod() -> Vec<Check> {
    run_scoped(Scope::Pod)
}

/// Run the checks for one [`Scope`].
fn run_scoped(scope: Scope) -> Vec<Check> {
    let mut checks: Vec<Check> = ToolName::ALL
        .iter()
        .copied()
        .map(check_floor_tool)
        .collect();
    checks.extend(probe_checks());
    // The mksquashfs version gate runs in BOTH scopes (#155): pod builds
    // pay the pack cost too (mksquashfs is a pod-surface floor tool).
    checks.push(check_squashfs_version());
    if scope == Scope::Full {
        checks.extend([
            check_ukify(),
            check_efi_stub(),
            check_veritysetup(),
            check_sysupdate_prereqs(),
        ]);
    }
    let toolchain: &[(&str, &str)] = match scope {
        Scope::Full => &SANDBOX_TOOLS,
        Scope::Pod => &POD_SANDBOX_TOOLS,
    };
    let entries = snap::path_entries();
    match scope {
        Scope::Full => checks.extend(check_sandbox_tools_with(toolchain, &entries)),
        // Pod scope takes the #178 variant: cc/c++ also credit the pod
        // farms (`nau run --pod`'s farm-first PATH surface).
        Scope::Pod => checks.extend(
            toolchain
                .iter()
                .map(|(tool, fix)| check_pod_toolchain_tool(tool, fix, &entries)),
        ),
    }
    // Issue #180 item 3: the sync env's cc must read as the farm/pool
    // toolchain, or doctor names the collect2/ld skew before a sync
    // dies mid-link on it. Hint-only — see [`check_cc_provenance`].
    checks.push(check_cc_provenance());
    // Cross-pod version-line report (ADR-0047 D3, #260): the same
    // package on different lines across pods, named instead of folklore.
    // Hint-only — see [`check_pod_version_lines`].
    checks.push(check_pod_version_lines());
    checks
}

/// Check one floor tool through [`tools::resolve`]: the origin report
/// (#101 AC-5) — `provisioned <upstream version> (tools v<set>)` vs
/// `PATH <path> <version>` — so shadowing is visible, and a missing tool
/// names `nau doctor --fix` plus the escape hatches (#101 AC-6).
/// Resolution is stat-only (never executes), matching `tools`' policy.
fn check_floor_tool(name: ToolName) -> Check {
    let manifest = tools::manifest();
    let spec_version = manifest.spec(name).map(|s| s.version.as_str());
    floor_tool_check_with(
        name,
        tools::resolve(name),
        spec_version,
        distro_fix_for(name),
    )
}

/// [`check_floor_tool`] over explicit inputs — the test seam (no env or
/// manifest dependency).
fn floor_tool_check_with(
    name: ToolName,
    resolved: tools::ToolsResult<ResolvedTool>,
    spec_version: Option<&str>,
    distro_fix: &str,
) -> Check {
    match resolved {
        Ok(ResolvedTool::Provisioned { version: set, .. }) => Check::ok_at(
            name.as_str(),
            format!(
                "provisioned {} (tools v{set})",
                spec_version.unwrap_or("unknown")
            ),
        ),
        Ok(ResolvedTool::Path { path, version }) => {
            let discovered = version.or_else(|| tools::discover_version(&path));
            match discovered {
                Some(v) => Check::ok_at(name.as_str(), format!("PATH {} {v}", path.display())),
                None => Check::ok_at(
                    name.as_str(),
                    format!("PATH {} (version unknown)", path.display()),
                ),
            }
        }
        Err(_) => Check::missing(
            name.as_str(),
            format!(
                "run: nau doctor --fix (distro fallback: {distro_fix}; overrides: \
                 NAU_TOOLS_DIR, {})",
                name.env_var()
            ),
        ),
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
             e.g. apt install systemd-ukify, or install systemd system-wide \
             (NixOS systemPackages)",
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
             e.g. apt install cryptsetup, or install cryptsetup system-wide \
             (NixOS systemPackages)",
        ),
    }
}

// ── systemd-sysupdate prerequisites (ADR-0024 §1–§2) ──

/// Minimum systemd major version that reads `*.transfer` transfer files
/// from `sysupdate.d`. As of v257 transfer definitions carry the
/// `.transfer` extension; <=256 reads `*.conf`, so the `.transfer` files
/// nau emits are silently ignored on an older systemd (systemd-devel
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
                    "systemd {major} reads sysupdate.d/*.conf, but nau emits \
                     *.transfer — transfer definitions are only read from systemd {min}+; \
                     upgrade systemd to {min} or newer",
                    min = SYSUPDATE_TRANSFER_MIN_MAJOR,
                ),
            ),
            SysupdatePrereq::Undetectable { reason } => Check::error(
                "systemd-sysupdate",
                format!(
                    "cannot determine the systemd version ({reason}) — nau emits \
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
/// wins: `boot/config-<version>`, then any `boot/config-*`, then the
/// snap-root `config-<version>` (the real Ubuntu Core `pc-kernel` layout,
/// #70), then `lib/modules/<version>/config*` (sorted for determinism).
/// Shared with the initrd-module build gate (ADR-0024 §1).
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
    candidates.push(payload_dir.join(format!("config-{kernel_version}")));
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

/// Upper bound on the number of `newc`/compressed layers a single initrd may
/// concatenate. Ubuntu Core kernel snaps ship a microcode archive followed by
/// one compressed main archive; four leaves ample headroom while keeping a
/// malformed file from spinning the walk.
const MAX_INITRD_LAYERS: usize = 4;

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
/// returning every cpio member path from every concatenated layer.
///
/// An initrd may be a *concatenation* of archives: Ubuntu Core kernel snaps
/// ship an uncompressed `newc` microcode archive followed by a compressed
/// (e.g. zstd) main archive. The leading archive is walked first; on its
/// trailer the walk continues past the 4-byte alignment/padding into the next
/// archive, decompressing it through `gzip -dc` / `zstd -dc` / `xz -dc` /
/// `lz4 -dc` when it carries a recognized magic or parsing it directly when it
/// is already `newc`. Members from all layers are unioned — the boot-chain
/// gate needs module paths from *any* layer to count.
///
/// Never silently succeeds: an unrecognized format, a failed decompressor, or
/// a truncated/unparseable archive is a hard error. A trailing zero-padding
/// run after the final trailer is normal and does not error.
pub(crate) fn read_initrd_members(
    runner: &dyn CommandRunner,
    initrd: &Path,
) -> miette::Result<Vec<String>> {
    let raw = std::fs::read(initrd)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading initrd {}", initrd.display()))?;
    if is_newc(&raw) {
        return walk_concatenated_initrd(runner, initrd, &raw)
            .wrap_err_with(|| format!("walking initrd {}", initrd.display()));
    }
    let Some(program) = decompressor_for(&raw) else {
        return Err(miette::miette!(
            "unrecognized initrd format at {}: not gzip/zstd/xz/lz4 and not a newc cpio \
             archive — refusing to ship a kernel whose initrd cannot be verified",
            initrd.display()
        ));
    };
    let data = decompress_layer(runner, program, initrd, 0, &raw)?;
    cpio_newc_members(&data).wrap_err_with(|| format!("walking initrd {}", initrd.display()))
}

/// Walk a concatenation of archives beginning at `raw[0]` (already a `newc`
/// header). Each layer advances the cursor past its trailer and the padding
/// that follows; a recognized compressed layer is decompressed whole and its
/// members collected, ending the walk. Trailing zeros terminate the walk
/// silently.
fn walk_concatenated_initrd(
    runner: &dyn CommandRunner,
    initrd: &Path,
    raw: &[u8],
) -> miette::Result<Vec<String>> {
    let mut members = Vec::new();
    let mut offset = 0usize;
    for _layer in 0..MAX_INITRD_LAYERS {
        while offset < raw.len() && raw[offset] == 0 {
            offset += 1;
        }
        if offset >= raw.len() {
            return Ok(members);
        }
        let rest = &raw[offset..];
        if is_newc(rest) {
            let (mut layer, next) = cpio_newc_members_from(raw, offset)?;
            members.append(&mut layer);
            offset = next;
        } else if let Some(program) = decompressor_for(rest) {
            let data = decompress_layer(runner, program, initrd, offset, raw)?;
            let mut layer = cpio_newc_members(&data)?;
            members.append(&mut layer);
            return Ok(members);
        } else {
            return Err(miette::miette!(
                "unrecognized initrd format at offset {offset} of {}: not gzip/zstd/xz/lz4 \
                 and not a newc cpio archive — refusing to ship a kernel whose initrd \
                 cannot be verified",
                initrd.display()
            ));
        }
    }
    Err(miette::miette!(
        "initrd {} carries more than {MAX_INITRD_LAYERS} concatenated archives — refusing \
         to verify a malformed initrd",
        initrd.display()
    ))
}

/// Decompress the layer beginning at `offset` in `raw` through the injected
/// runner. When the layer starts at offset zero it *is* the file, so the
/// initrd path is handed to the tool directly; a trailing layer is spooled to
/// a temporary file first.
fn decompress_layer(
    runner: &dyn CommandRunner,
    program: &str,
    initrd: &Path,
    offset: usize,
    raw: &[u8],
) -> miette::Result<Vec<u8>> {
    if offset == 0 {
        return run_decompressor(runner, program, initrd, initrd);
    }
    let spool = tempfile::NamedTempFile::new()
        .into_diagnostic()
        .wrap_err_with(|| format!("spooling trailing initrd layer from {}", initrd.display()))?;
    std::fs::write(spool.path(), &raw[offset..])
        .into_diagnostic()
        .wrap_err_with(|| format!("spooling trailing initrd layer from {}", initrd.display()))?;
    run_decompressor(runner, program, initrd, spool.path())
}

/// Run one injected decompressor (`<program> -dc <input>`) and return its
/// stdout, failing closed on a spawn error or a non-zero exit.
fn run_decompressor(
    runner: &dyn CommandRunner,
    program: &str,
    initrd: &Path,
    input: &Path,
) -> miette::Result<Vec<u8>> {
    let argv = vec![
        program.to_string(),
        "-dc".to_string(),
        input.to_string_lossy().into_owned(),
    ];
    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("failed to run {program} for {}: {e}", initrd.display()))?;
    if out.code != 0 {
        return Err(miette::miette!(
            "{program} failed (exit {}) decompressing {} — the initrd cannot be read, \
             so the boot-chain modules cannot be verified",
            out.code,
            initrd.display()
        ));
    }
    Ok(out.stdout)
}

/// Walk a `newc` cpio archive, collecting member names. The 110-byte ASCII
/// header (6-byte magic + thirteen 8-hex fields) is followed by the
/// NUL-terminated name and the file data, each padded to a 4-byte
/// boundary; the archive ends at the `TRAILER!!!` member.
pub(crate) fn cpio_newc_members(data: &[u8]) -> miette::Result<Vec<String>> {
    cpio_newc_members_from(data, 0).map(|(members, _end)| members)
}

/// Walk one `newc` archive starting at `start`, returning its member names
/// and the offset just past the aligned `TRAILER!!!` (where a concatenated
/// archive would begin).
fn cpio_newc_members_from(data: &[u8], start: usize) -> miette::Result<(Vec<String>, usize)> {
    let mut members = Vec::new();
    let mut pos = start;
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
            return Ok((members, align4(data_end)));
        }
        members.push(name);
        pos = align4(data_end);
    }
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

/// Check mksquashfs: SOURCE_DATE_EPOCH support (4.4+, #101) and the
/// #155 pack-performance advice. The detected `mksquashfs -version`
/// triple is printed on every parsed report line; anything below
/// [`SQUASHFS_PERF_MIN`] (4.7 parallelized reads) carries the upgrade
/// hint on its existing status — the advice is advisory and never fails
/// a command. The version gate is a tolerant triple parse (#101 AC-8:
/// the closed 4.4/4.5/4.6 allowlist rejected the provisioner's 4.7.x
/// builds and labelled nau's own provisioned tool "untested").
fn check_squashfs_version() -> Check {
    let manifest = tools::manifest();
    let spec_version = manifest
        .spec(ToolName::Mksquashfs)
        .map(|s| s.version.as_str());
    check_squashfs_version_with(tools::resolve(ToolName::Mksquashfs), spec_version)
}

/// [`check_squashfs_version`] over explicit inputs — the test seam.
fn check_squashfs_version_with(
    resolved: tools::ToolsResult<ResolvedTool>,
    spec_version: Option<&str>,
) -> Check {
    let name = "mksquashfs >= 4.4 (SOURCE_DATE_EPOCH)";
    match resolved {
        Ok(ResolvedTool::Provisioned { version: set, .. }) => {
            // The provisioner installs a manifest-pinned, CI-verified
            // version (#101 AC-8): never "untested" — the manifest pin is
            // the source of truth and the round-trip probe is the gate.
            match spec_version.and_then(parse_squashfs_version) {
                Some(v) if v >= SQUASHFS_SDE_MIN => Check::ok_at(
                    name,
                    with_upgrade_advice(
                        format!(
                            "provisioned {} (tools v{set}) — pinned by the verified manifest",
                            spec_version.unwrap_or_default(),
                        ),
                        v,
                    ),
                ),
                Some(v) => Check::error(
                    name,
                    with_upgrade_advice(
                        format!(
                            "the manifest pins squashfs-tools {}, which predates \
                             SOURCE_DATE_EPOCH support (needs >= 4.4)",
                            version_string(v)
                        ),
                        v,
                    ),
                ),
                None => Check::ok_at(
                    name,
                    format!(
                        "provisioned tools v{set} — version pinned by the verified \
                         manifest, exercised by the round-trip probe"
                    ),
                ),
            }
        }
        Ok(ResolvedTool::Path { path, .. }) => match mksquashfs_version(&path) {
            Some(v) if v >= SQUASHFS_SDE_MIN => Check::ok_at(
                name,
                with_upgrade_advice(format!("PATH {} {}", path.display(), version_string(v)), v),
            ),
            Some(v) => Check::error(
                name,
                with_upgrade_advice(
                    format!(
                        "PATH {} {} predates SOURCE_DATE_EPOCH support (needs >= 4.4)",
                        path.display(),
                        version_string(v)
                    ),
                    v,
                ),
            ),
            None => Check::ok_at(
                name,
                format!(
                    "PATH {} (version unparsable — SOURCE_DATE_EPOCH untested)",
                    path.display()
                ),
            ),
        },
        Err(_) => Check::missing(name, "install squashfs-tools"),
    }
}

/// The minimum (major, minor, patch) with SOURCE_DATE_EPOCH support.
const SQUASHFS_SDE_MIN: (u32, u32, u32) = (4, 4, 0);

/// The (major, minor, patch) that parallelized reads landed in
/// (squashfs-tools 4.7, June 2025) — packs on older tools leave real
/// build time on the table (issue #155: 20% to >10x on I/O-bound packs).
const SQUASHFS_PERF_MIN: (u32, u32, u32) = (4, 7, 0);

/// The #155 upgrade advice appended to a report line whose detected
/// version predates [`SQUASHFS_PERF_MIN`]. Advisory only: it changes
/// hint text, never a status — the check must not fail a command on it.
const SQUASHFS_UPGRADE_HINT: &str = "upgrade squashfs-tools to >= 4.7 for faster builds \
     (4.7 parallelized reads — worth 20% to >10x on I/O-bound packs; \
     `nau doctor --fix` provisions a pinned 4.7.x)";

/// Append [`SQUASHFS_UPGRADE_HINT`] to a report line whose detected
/// version is below [`SQUASHFS_PERF_MIN`].
fn with_upgrade_advice(hint: String, v: (u32, u32, u32)) -> String {
    if v < SQUASHFS_PERF_MIN {
        format!("{hint}; {SQUASHFS_UPGRADE_HINT}")
    } else {
        hint
    }
}

/// Render a parsed (major, minor, patch) triple for report lines.
fn version_string(v: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Run `-version` on a resolved mksquashfs and parse the leading
/// `<major>.<minor>[.<patch>]` triple.
fn mksquashfs_version(path: &Path) -> Option<(u32, u32, u32)> {
    // A transient fork/exec failure under heavy parallel load (test hosts,
    // CI runners) must not read as "version unparsable" — the probe retries
    // before degrading to the advisory unknown-version check. The retry
    // covers both a failed spawn AND a child that spawned but died on a
    // transient resource error (non-zero exit: under fork pressure the
    // interpreter's own exec can fail after the parent's spawn succeeded).
    // Only the failure path pays the backoff; a healthy probe returns on
    // the first attempt.
    for attempt in 0..3u64 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt));
        }
        if let Ok(out) = std::process::Command::new(path).arg("-version").output() {
            if out.status.success() {
                if let Some(v) = parse_squashfs_version(&String::from_utf8_lossy(&out.stdout)) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Parse the first `<major>.<minor>[.<patch>]` token of the version
/// output's first line ("mksquashfs version 4.7.5 (…)" → (4, 7, 5)).
/// Defensive about pre/suffix forms: each component contributes only its
/// leading digits ("4.7.5-pre" → 5), and a missing or non-numeric patch
/// reads as 0 ("4.4" → (4, 4, 0), "4.9.x" → (4, 9, 0)). A token with
/// fewer than two numeric components is skipped. Never panics: no
/// numeric pair in the first line → `None` (reported as unknown).
fn parse_squashfs_version(text: &str) -> Option<(u32, u32, u32)> {
    let first = text.lines().next()?;
    first.split_whitespace().find_map(|token| {
        let mut parts = token.split('.');
        let major = leading_u32(parts.next()?)?;
        let minor = leading_u32(parts.next()?)?;
        let patch = parts.next().and_then(leading_u32).unwrap_or(0);
        Some((major, minor, patch))
    })
}

/// The leading ASCII digits of `s` as a `u32` (the
/// [`parse_systemd_major`] pattern) — an empty or non-digit leading run
/// is `None`.
fn leading_u32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

// ── Functional probes (issue #101 AC-2) ──
//
// Stat/version checks cannot tell a working tool from a shipped-bytes
// one: the probes execute the resolved binaries. They run whenever the
// tools they exercise resolve; their failures carry named diagnostics
// (noexec mount, disabled user namespaces, kernel restriction) mirroring
// tools::ToolsError::Noexec's wording.

/// A probe file's content, asserted verbatim after the round-trip.
const PROBE_CONTENT: &str = "nau doctor squashfs round-trip probe\n";
/// The user xattr exercised when the host carries setfattr/getfattr.
const XATTR_PROBE: &str = "user.probe";
/// The marker value stored in [`XATTR_PROBE`].
const XATTR_MARKER: &str = "nau-probe";

/// The probe checks for one doctor run: the squashfs round-trip when the
/// pair resolves, the bwrap sandbox exec when bwrap resolves.
fn probe_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    let mksquashfs = resolved_path(&tools::resolve(ToolName::Mksquashfs));
    let unsquashfs = resolved_path(&tools::resolve(ToolName::Unsquashfs));
    if let (Some(mk), Some(us)) = (mksquashfs, unsquashfs) {
        checks.push(squashfs_probe_check(&mk, &us));
    }
    if let Some(bwrap) = resolved_path(&tools::resolve(ToolName::Bwrap)) {
        checks.push(bwrap_probe_check(&bwrap));
    }
    checks
}

/// The path behind a resolution — both origins carry one.
fn resolved_path(resolved: &tools::ToolsResult<ResolvedTool>) -> Option<PathBuf> {
    match resolved {
        Ok(ResolvedTool::Provisioned { path, .. }) | Ok(ResolvedTool::Path { path, .. }) => {
            Some(path.clone())
        }
        Err(_) => None,
    }
}

/// One probe execution with the spawn failure classified: EACCES/EPERM at
/// spawn is the noexec-mount signature, distinct from other spawn errors.
#[derive(Debug)]
enum ProbeRun {
    Ran {
        code: i32,
        stdout: String,
        stderr: String,
    },
    Noexec(io::Error),
    Spawn(io::Error),
}

fn run_probe(bin: &Path, args: &[&str]) -> ProbeRun {
    match std::process::Command::new(bin).args(args).output() {
        Ok(out) => ProbeRun::Ran {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => ProbeRun::Noexec(e),
        Err(e) => ProbeRun::Spawn(e),
    }
}

/// Run one probe step, mapping every failure class to a named diagnostic.
fn probe_step(bin: &Path, args: &[&str], what: &str) -> Result<(), String> {
    match run_probe(bin, args) {
        ProbeRun::Ran { code: 0, .. } => Ok(()),
        ProbeRun::Ran { code, stderr, .. } => {
            let line = first_line(&stderr);
            Err(format!("{what} exited {code}: {line}"))
        }
        ProbeRun::Noexec(e) => Err(noexec_hint(what, &e)),
        ProbeRun::Spawn(e) => Err(format!("cannot spawn {what}: {e}")),
    }
}

/// The noexec diagnostic, mirroring tools::ToolsError::Noexec's wording
/// and workaround (#101 AC-3/AC-6).
fn noexec_hint(what: &str, source: &io::Error) -> String {
    format!(
        "cannot execute {what}: {source} — the path is likely mounted noexec; \
         relocate the tools root by setting NAU_TOOLS_DIR to an exec-mounted \
         path (e.g. NAU_TOOLS_DIR=/var/tmp/nau-tools) and re-run \
         `nau doctor --fix`"
    )
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default().trim()
}

fn squashfs_probe_check(mksquashfs: &Path, unsquashfs: &Path) -> Check {
    let name = "probe: squashfs round-trip";
    match squashfs_roundtrip(mksquashfs, unsquashfs) {
        Ok(note) => Check::ok_at(name, note),
        Err(msg) => Check::error(name, msg),
    }
}

/// Pack a probe tree with the resolved mksquashfs, unpack it with the
/// resolved unsquashfs, and assert the content (and, when the host carries
/// setfattr, the `user.probe` xattr) survives. Ok carries the one-line
/// report, including the named note when xattr fidelity was NOT exercised.
fn squashfs_roundtrip(mksquashfs: &Path, unsquashfs: &Path) -> Result<String, String> {
    let work = tempfile::tempdir().map_err(|e| format!("create probe workdir: {e}"))?;
    let file = work.path().join("probe.txt");
    std::fs::write(&file, PROBE_CONTENT).map_err(|e| format!("write probe file: {e}"))?;

    let entries = snap::path_entries();
    let setfattr = snap::resolve_in_path("setfattr", &entries);
    let getfattr = snap::resolve_in_path("getfattr", &entries);
    // The xattr is set BEFORE packing: the probe asserts that the packed
    // bytes carry it and the unpack restores it — setting it after the
    // round-trip would prove nothing.
    let xattr_note = match setfattr {
        None => Some("xattr fidelity not exercised (setfattr not installed)".into()),
        Some(tool) => set_probe_xattr(&tool, &file).err(),
    };

    let img = work.path().join("probe.squashfs");
    let img_arg = img.to_string_lossy().into_owned();
    let file_arg = file.to_string_lossy().into_owned();
    // Packing the single probe file keeps the unpack layout deterministic
    // (the archive root IS probe.txt); a directory source would carry the
    // source basename as its archive root and move the probe file deeper.
    probe_step(
        mksquashfs,
        &[&file_arg, &img_arg, "-noappend"],
        "probe mksquashfs",
    )?;

    let out = work.path().join("probe-out");
    let out_arg = out.to_string_lossy().into_owned();
    probe_step(unsquashfs, &["-d", &out_arg, &img_arg], "probe unsquashfs")?;

    finish_roundtrip(xattr_note, getfattr.as_deref(), &out.join("probe.txt"))
}

/// Assert the unpacked probe file and produce the one-line report.
fn finish_roundtrip(
    xattr_note: Option<String>,
    getfattr: Option<&Path>,
    unpacked: &Path,
) -> Result<String, String> {
    let round = std::fs::read_to_string(unpacked)
        .map_err(|e| format!("read the unpacked probe file: {e}"))?;
    if round != PROBE_CONTENT {
        return Err("probe file content did not survive the squashfs round-trip".into());
    }
    match (xattr_note, getfattr) {
        (Some(note), _) => Ok(format!("content survived the round-trip — {note}")),
        (None, None) => Ok(
            "content survived the round-trip — user.probe was set but could not be \
             verified (getfattr not installed)"
                .into(),
        ),
        (None, Some(getfattr)) => {
            read_probe_xattr(getfattr, unpacked)?;
            Ok("content and user.probe xattr survived the round-trip".into())
        }
    }
}

/// Set the probe xattr. `Err` carries a non-fatal named note: the probe
/// filesystem may simply not support user xattrs (e.g. tmpfs), which is a
/// fidelity gap in the TEST BED, not a failing tool.
fn set_probe_xattr(setfattr: &Path, file: &Path) -> Result<(), String> {
    let file_arg = file.to_string_lossy().into_owned();
    match run_probe(
        setfattr,
        &["-n", XATTR_PROBE, "-v", XATTR_MARKER, &file_arg],
    ) {
        ProbeRun::Ran { code: 0, .. } => Ok(()),
        ProbeRun::Ran { code, stderr, .. } => Err(format!(
            "setfattr could not set {XATTR_PROBE} on the probe file (exit {code}: {}) — \
             the filesystem may not support user xattrs",
            first_line(&stderr)
        )),
        ProbeRun::Noexec(e) => Err(format!("cannot execute setfattr: {e}")),
        ProbeRun::Spawn(e) => Err(format!("cannot spawn setfattr: {e}")),
    }
}

/// Read the probe xattr back. `Err` is fatal: the xattr WAS set, so losing
/// it in the round-trip is a real payload-fidelity failure.
fn read_probe_xattr(getfattr: &Path, file: &Path) -> Result<(), String> {
    let file_arg = file.to_string_lossy().into_owned();
    match run_probe(getfattr, &["-n", XATTR_PROBE, &file_arg]) {
        ProbeRun::Ran {
            code: 0, stdout, ..
        } => match parse_getfattr_value(&stdout) {
            Some(v) if v == XATTR_MARKER => Ok(()),
            Some(v) => Err(format!(
                "{XATTR_PROBE} did not survive the round-trip: set '{XATTR_MARKER}', \
                 read '{v}'"
            )),
            None => Err(format!(
                "{XATTR_PROBE} did not survive the round-trip: set '{XATTR_MARKER}', \
                 getfattr reported none"
            )),
        },
        ProbeRun::Ran { code, stderr, .. } => Err(format!(
            "reading {XATTR_PROBE} back failed (exit {code}: {})",
            first_line(&stderr)
        )),
        ProbeRun::Noexec(e) => Err(format!("cannot execute getfattr: {e}")),
        ProbeRun::Spawn(e) => Err(format!("cannot spawn getfattr: {e}")),
    }
}

/// Extract the quoted value from `getfattr -n` output — GNU prints a
/// `# file:` header plus `user.probe="value"`, busybox prints just the
/// `name="value"` line; both quote a printable value.
fn parse_getfattr_value(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix(XATTR_PROBE)?;
        let value = rest.strip_prefix('=')?.strip_prefix('"')?;
        let end = value.find('"')?;
        Some(value[..end].to_string())
    })
}

/// The sandbox exec target: the first existing of the classic minimal
/// binaries. `/bin/true` is absent on NixOS, `/bin/sh` exists on every
/// Linux (NixOS ships it as a system symlink); a static-true-less host
/// still needs the probe to exercise a real exec.
fn bwrap_probe_target_from(
    candidates: &'static [&'static str],
) -> Option<(&'static str, Vec<&'static str>)> {
    candidates.iter().find_map(|c| {
        let path = Path::new(c);
        (path.exists()).then(|| match *c {
            "/bin/sh" | "/usr/bin/sh" => (*c, vec!["-c", "exit 0"]),
            _ => (*c, Vec::new()),
        })
    })
}

fn bwrap_probe_check(bwrap: &Path) -> Check {
    let name = "probe: bwrap sandbox exec";
    let Some((target, args)) = bwrap_probe_target_from(&["/bin/true", "/usr/bin/true", "/bin/sh"])
    else {
        return Check::error(
            name,
            "no sandbox exec target found (tried /bin/true, /usr/bin/true, /bin/sh) — \
             the probe gates a real sandboxed exec, so it fails closed",
        );
    };
    let mut probe_args = vec!["--ro-bind", "/", "/", target];
    probe_args.extend(args);
    let rendered = probe_args.join(" ");
    match run_probe(bwrap, &probe_args) {
        ProbeRun::Ran { code: 0, .. } => {
            Check::ok_at(name, format!("real sandboxed exec succeeded ({rendered})"))
        }
        ProbeRun::Ran { code, stderr, .. } => Check::error(name, bwrap_failure_hint(code, &stderr)),
        ProbeRun::Noexec(e) => Check::error(name, noexec_hint("the resolved bwrap", &e)),
        ProbeRun::Spawn(e) => Check::error(name, format!("cannot spawn {}: {e}", bwrap.display())),
    }
}

/// Name the bwrap failure cause: user namespaces, a kernel/seccomp-style
/// restriction, a missing exec target, or an unnamed sandbox setup
/// failure. Never bare "failed".
fn bwrap_failure_hint(code: i32, stderr: &str) -> String {
    let cause = if stderr.contains("user namespace")
        || stderr.contains("uid map")
        || stderr.contains("unshare")
    {
        "user namespaces appear disabled (kernel.unprivileged_userns_clone or a \
         hardened sandbox) — enable unprivileged user namespaces"
    } else if stderr.contains("Operation not permitted") || stderr.contains("EPERM") {
        "the kernel or a seccomp/gVisor-style restriction denied the namespace setup"
    } else if stderr.contains("execvp") || stderr.contains("No such file") {
        "the sandbox exec target is missing on this host — \
         the probe gates a real sandboxed exec, so it fails closed"
    } else {
        "bwrap could not set up the sandbox"
    };
    format!("bwrap exited {code}: {} — {cause}", first_line(stderr))
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

/// Check one set of sandbox build tools against sandbox-visible PATH
/// entries.
fn check_sandbox_tools_with(tools: &[(&str, &str)], entries: &[PathBuf]) -> Vec<Check> {
    tools
        .iter()
        .map(|(tool, fix)| check_sandbox_tool(tool, fix, entries))
        .collect()
}

/// Check one pod-scope toolchain tool (issue #178):
/// [`check_sandbox_tool`] plus a pod-env credit — the pod farms under
/// the pod root are the surface `nau run --pod` searches FIRST
/// (farm-first PATH), so a cc/c++ that only resolves there is ready for
/// pod-side work and must not read as missing. The pre-#178 check
/// flagged exactly that setup on gate pods carrying the gcc payload
/// (whose farm shims provide both names), advising the user to
/// sideload what the pod already carries.
fn check_pod_toolchain_tool(tool: &str, fix: &str, entries: &[PathBuf]) -> Check {
    let farms = pod_farm_dirs();
    check_pod_toolchain_tool_with(tool, fix, entries, &farms)
}

/// The resolution proper over explicit pod farms — split out so tests
/// can point the farms at a tempdir without touching the real pod root.
fn check_pod_toolchain_tool_with(
    tool: &str,
    fix: &str,
    entries: &[PathBuf],
    farms: &[PathBuf],
) -> Check {
    let check = check_sandbox_tool(tool, fix, entries);
    if !POD_ENV_TOOLS.contains(&tool) || matches!(check.status, CheckStatus::Ok) {
        return check;
    }
    if resolve_pod_tool_in(tool, farms).is_some() {
        // The pod provides the tool — pass, no hint (issue #178).
        Check::ok(format!("sandbox: {tool}"))
    } else {
        check
    }
}

/// Resolve `tool` through the pod farms — the first PATH entries
/// `nau run --pod` composes, one farm per healthy pod.
fn resolve_pod_tool_in(tool: &str, farms: &[PathBuf]) -> Option<PathBuf> {
    farms
        .iter()
        .find_map(|farm| snap::resolve_in_path(tool, std::slice::from_ref(farm)))
}

/// The sync environment's `cc` provenance (issue #180 item 3): warns
/// when `cc` resolves to a FOREIGN toolchain while the pod farms carry
/// the pool one — the collect2/ld version-skew class (nixpkgs gcc
/// 15.3's collect2 execing the farm's deb ld 2.44 dies on
/// `libbfd-…-system.so` in degraded-direct mode, where the build
/// inherits the caller's PATH). Resolution follows the surfaces a sync
/// build actually sees: the host PATH (what degraded-direct inherits;
/// inside the bwrap sandbox the merged prefix's `usr/bin` leads
/// instead, so a gcc `build_dep` build is unaffected by a foreign host
/// cc), judged against the farms a healthy pod composes
/// ([`resolve_pod_tool_in`], `nau run --pod`'s first entries).
/// Status stays Ok in every verdict — this is the issue's "doctor
/// hint": a wrong-tool warning, never a second missing-tool flag
/// (absence already has the `sandbox: cc` check) and never a hard
/// failure for the usually-working foreign cc.
fn check_cc_provenance() -> Check {
    let entries = snap::path_entries();
    let farms = pod_farm_dirs();
    check_cc_provenance_with(&entries, &farms)
}

/// The provenance resolution proper over an explicit host-PATH entry
/// list and pod farm dirs — split out so tests can point both at
/// tempdirs without touching the real PATH or pod root.
fn check_cc_provenance_with(entries: &[PathBuf], farms: &[PathBuf]) -> Check {
    let name = "sync cc provenance";
    match snap::resolve_in_path("cc", entries) {
        // Absence is the `sandbox: cc` check's verdict — this hint
        // would only duplicate it.
        None => Check::ok(name),
        Some(path) if farms.iter().any(|f| path.starts_with(f)) => Check::ok_at(
            name,
            format!("resolves to the pod toolchain farm: {}", path.display()),
        ),
        Some(path) => {
            let hint = if resolve_pod_tool_in("cc", farms).is_some() {
                format!(
                    "warning: cc resolves to {} — not the farm/pool toolchain, so a \
                     degraded-direct build can pair a foreign collect2 with the farm's \
                     ld and die on version skew (issue #180: nix gcc 15.3 collect2 + \
                     deb ld 2.44). Sync from an environment without a foreign gcc \
                     (e.g. `nix shell` without gcc) so cc resolves to the farm; \
                     sandboxed builds with a gcc build_dep are unaffected — the merged \
                     prefix leads their PATH.",
                    path.display()
                )
            } else {
                format!("resolves to {}", path.display())
            };
            Check::ok_at(name, hint)
        }
    }
}

/// Farm bin dirs of every pod under the pod root whose `current` link
/// resolves to an active generation — the farm-first PATH entries
/// `nau run --pod` prepends. `doctor --pod` takes no pod name, so
/// any healthy pod's farm counts as reachable. A missing or dangling
/// `current` contributes nothing — doctor is a diagnostic, never a
/// state initializer.
fn pod_farm_dirs() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(crate::pod::pod_root(None)) else {
        return Vec::new();
    };
    let mut farms: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path().join(crate::farm::CURRENT_LINK))
        .filter(|farm| std::fs::metadata(farm).is_ok_and(|m| m.is_dir()))
        .collect();
    farms.sort();
    farms
}

/// The line a pod pin sits on (ADR-0047): the declared constraint when
/// the pod pinned one (`node@22` → "22"), else the leading dotted
/// component of the resolved version — an unconstrained pin takes the
/// current line, so 26.7.0 sits on the 26 line. The lockfile already
/// records `{version, constraint}` per pin ([`crate::lock`]).
fn pin_line(entry: &crate::lock::PodPackageLockEntry) -> String {
    entry.constraint.clone().unwrap_or_else(|| {
        entry
            .version
            .split('.')
            .next()
            .unwrap_or(&entry.version)
            .to_string()
    })
}

/// Cross-pod version-line report (ADR-0047 D3, #260): the same package
/// pinned to different lines across pods is coexistence working as
/// designed — `node@26` here, `node@22` in another pod — but only
/// discoverable when named, so doctor reports the divergence and the
/// remedy vocabulary. Read-only over the lockfiles; never fails the
/// report (a pod whose lockfile is absent or unreadable contributes
/// nothing — doctor is a diagnostic, never a state initializer).
pub fn check_pod_version_lines() -> Check {
    check_pod_version_lines_with(&crate::pod::pod_root(None))
}

/// [`check_pod_version_lines`] over an explicit pod root — the test seam.
pub(crate) fn check_pod_version_lines_with(root: &Path) -> Check {
    let name = "pod version lines";
    let Ok(entries) = std::fs::read_dir(root) else {
        return Check::ok(name);
    };
    let mut pods: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    pods.sort();
    // package → [(pod, line)], pods in sorted order.
    let mut lines: std::collections::BTreeMap<String, Vec<(String, String)>> = Default::default();
    for pod in pods {
        let lock =
            crate::lock::LockFile::load(&root.join(&pod).join(crate::lock::LockFile::FILENAME));
        let Ok(Some(lock)) = lock else {
            continue;
        };
        for (pkg, entry) in lock.packages {
            lines
                .entry(pkg)
                .or_default()
                .push((pod.clone(), pin_line(&entry)));
        }
    }
    let mut divergent: Vec<String> = Vec::new();
    for (pkg, pins) in &lines {
        let mut distinct: Vec<&str> = pins.iter().map(|(_, l)| l.as_str()).collect();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() < 2 {
            continue;
        }
        let detail = pins
            .iter()
            .map(|(pod, line)| format!("'{pod}' has {pkg}@{line}"))
            .collect::<Vec<_>>()
            .join(", ");
        divergent.push(format!("{pkg}: {detail}"));
    }
    if divergent.is_empty() {
        Check::ok(name)
    } else {
        // Informational: divergence is sanctioned coexistence, never a
        // failure — the hint names the pins and the ADR-0047 remedy.
        Check::ok_at(
            name,
            format!(
                "{} — cross-pod coexistence via `name@constraint`, one line per pod (ADR-0047)",
                divergent.join("; ")
            ),
        )
    }
}

/// The check name of the pod failed-unit scan ([`check_pod_failed_units`]).
const POD_FAILED_UNITS_CHECK: &str = "pod failed units";

/// Pod failed-unit scan (ADR-0042 D3 boot story, issue #231): after a
/// reboot the tmpfs secrets tree is gone, so every unit recorded with a
/// mandatory `EnvironmentFile=` starts failed until
/// `pod secrets refresh` re-resolves and restarts the consumers (the
/// rotate-restart contract landed in #224). This check names that fix —
/// `nau doctor --pod <name>` selects the pod. Advisory by
/// construction: the status stays `Ok` (hint-only, the
/// [`check_pod_version_lines`] idiom); only tool absence turns into a
/// NAMED skip, never a failed check.
pub fn check_pod_failed_units(pod: &str) -> Check {
    check_pod_failed_units_with(
        &crate::pod::pod_root(None),
        pod,
        None,
        &crate::runtime::RuntimeTools::for_pod_runtime(),
    )
}

/// [`check_pod_failed_units`] over an explicit pod root, cache base, and
/// tool set — the test seam (the `check_pod_version_lines_with`
/// pattern; the cache override and the fake systemctl keep tests off the
/// host's `$XDG_RUNTIME_DIR` and systemd).
pub(crate) fn check_pod_failed_units_with(
    root: &Path,
    pod: &str,
    cache_base: Option<&Path>,
    tools: &crate::runtime::RuntimeTools,
) -> Check {
    let name = POD_FAILED_UNITS_CHECK;
    let pod_dir = root.join(pod);
    if !pod_dir.is_dir() {
        // Unknown pod: nothing recorded to scan — not applicable.
        return Check::ok(name);
    }
    // The generation the verbs address (`current` → `generations/<n>`,
    // the same source `pod secrets refresh` reads). No link = never
    // synced = no recorded units.
    let Some(generation) = crate::farm::current_generation(&pod_dir).ok().flatten() else {
        return Check::ok(name);
    };
    // The envfile path the sync would have baked into unit text —
    // derived PASSIVELY from the folded references, no provider calls.
    // A pod with no secrets (or an undervivable path — no runtime dir,
    // under which D7 keeps sync from recording a secret-bearing unit at
    // all) has no `EnvironmentFile=` to scan for: not applicable.
    let refs = match crate::pod::load_declaration(root, pod)
        .and_then(|decl| crate::pod::resolve_pod_secrets(root, pod, &decl))
    {
        Ok(refs) => refs,
        Err(_) => return Check::ok(name),
    };
    let Some(envfile) = crate::secrets::pod_envfile_path_passive(pod, &refs, cache_base)
        .ok()
        .flatten()
    else {
        return Check::ok(name);
    };
    // The scan's direct input: the generation's recorded units
    // (services::units_referencing_envfile — the same reader #224's
    // restart half uses). A corrupt file fails loudly there — trusted
    // data — so the scan surfaces it as a doctor error, not a silent
    // skip.
    let consumers = match crate::services::units_referencing_envfile(
        &crate::pod::pod_store(&pod_dir),
        generation,
        pod,
        &envfile,
    ) {
        Ok(consumers) => consumers,
        Err(e) => return Check::error(name, e.to_string()),
    };
    if consumers.is_empty() {
        // No unit references the envfile: the scan has no consumers.
        return Check::ok(name);
    }
    let Some(systemctl) = tools.systemctl.as_ref() else {
        // Reconcile semantics (issue #107): the tool's absence is a
        // named skip, never a failed check.
        return Check::ok_at(
            name,
            format!(
                "skipped: systemctl unavailable — cannot probe the failed \
                 state of {}",
                consumers.join(", ")
            ),
        );
    };
    let mut notices: Vec<String> = Vec::new();
    for unit in &consumers {
        // The D3 boot story needs BOTH halves: the envfile is gone
        // (tmpfs died at reboot) AND the unit actually starts failed.
        if envfile.exists() {
            continue;
        }
        let failed = std::process::Command::new(systemctl)
            .arg("--user")
            .arg("is-failed")
            .arg(unit)
            .status();
        match failed {
            Ok(status) if status.success() => notices.push(failed_unit_notice(unit, &envfile)),
            // Active, inactive, or a probe exit the state mapping does
            // not cover: nothing to name.
            Ok(_) => {}
            // systemctl exists but cannot run: the same named skip as
            // absence — doctor never fails on the tool alone.
            Err(e) => {
                return Check::ok_at(
                    name,
                    format!("skipped: systemctl could not be run ({e}) — cannot probe the failed state of {}", consumers.join(", ")),
                );
            }
        }
    }
    if notices.is_empty() {
        Check::ok(name)
    } else {
        Check::ok_at(name, notices.join("; "))
    }
}

/// The verbatim per-unit notice (drafted in the #224 review, issue
/// #231): names the unit, the gone envfile, and the fix.
fn failed_unit_notice(unit: &str, envfile: &Path) -> String {
    format!(
        "unit '{unit}' starts failed: envfile {} is gone (tmpfs secrets die \
         at reboot) — run `pod secrets refresh` to re-resolve the pod's \
         secrets and restart its consumers",
        envfile.display()
    )
}

/// Print a formatted doctor report to stdout.
pub fn print_report(checks: &[Check]) {
    let mut all_ok = true;

    println!("nau doctor — system readiness check");
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

/// Print the warn-only post-table notices (#101): the stale provisioned
/// set (AC-5) and the `min_kernel` advisory (AC-10). Neither affects the
/// exit code — the functional probes are the real gate.
pub fn print_notices() {
    if let Some(msg) = stale_notice() {
        println!("  ⚠ {msg}");
    }
    if let Some(msg) = min_kernel_notice() {
        println!("  ⚠ {msg}");
    }
}

/// The stale-shadow warning (#101 AC-5): the installed tools set is not
/// the manifest's version. Warn-only; `nau doctor --fix` re-provisions.
/// Carries the escape hatches (AC-6 — this reports a stale provisioned set).
fn stale_notice() -> Option<String> {
    let stale = tools::detect_stale()?;
    Some(format!(
        "provisioned tools stale (installed v{}, manifest v{}) — run: \
         nau doctor --fix (overrides: NAU_TOOLS_DIR, NAU_TOOL_<NAME>)",
        stale.installed, stale.manifest
    ))
}

/// The `min_kernel` advisory (#101 AC-10): the running kernel is older
/// than the manifest's floor. Warn-only, best-effort; an unparsable
/// release string is named, never silently skipped.
fn min_kernel_notice() -> Option<String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok();
    min_kernel_notice_with(release.as_deref(), tools::manifest().min_kernel.as_deref())
}

/// [`min_kernel_notice`] over explicit inputs — the test seam.
fn min_kernel_notice_with(release: Option<&str>, min_kernel: Option<&str>) -> Option<String> {
    let min = min_kernel?;
    let min_parsed = parse_kernel_version(min)?;
    let Some(release) = release else {
        return Some(format!(
            "warning: kernel version unparsable (no release string) — cannot \
             compare against the floor tools' min_kernel {min}"
        ));
    };
    let release = release.trim();
    match parse_kernel_version(release) {
        Some(running) if kernel_below(&running, &min_parsed) => Some(format!(
            "warning: kernel {release} is older than the floor tools' min_kernel \
             {min} — provisioned tools may not run; the functional probes are \
             the real gate"
        )),
        Some(_) => None,
        None => Some(format!(
            "warning: kernel version unparsable ('{release}') — cannot compare \
             against the floor tools' min_kernel {min}"
        )),
    }
}

/// Parse a kernel release into its leading numeric components:
/// "6.8.0-42-generic" → [6, 8] (the "0-42-generic" component is not a bare
/// number); "5.10" → [5, 10]. None when no leading numeric component exists.
fn parse_kernel_version(release: &str) -> Option<Vec<u32>> {
    let components: Vec<u32> = release
        .split('.')
        .map_while(|c| c.parse::<u32>().ok())
        .collect();
    (!components.is_empty()).then_some(components)
}

/// Whether `running` sorts strictly below `min`, comparing numeric
/// components and padding the shorter side with zeros (5.9 < 5.10,
/// 6.1 ≥ 5.10, 5.10.1 ≥ 5.10).
fn kernel_below(running: &[u32], min: &[u32]) -> bool {
    for i in 0..running.len().max(min.len()) {
        let a = running.get(i).copied().unwrap_or(0);
        let b = min.get(i).copied().unwrap_or(0);
        if a != b {
            return a < b;
        }
    }
    false
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

    // ── Cross-pod version-line report (ADR-0047 D3, #260) ──

    /// One pod directory with a lockfile pinning `node` on `line`
    /// (`constraint: None` derives the line from the resolved version).
    fn pod_with_node_pin(root: &Path, pod: &str, version: &str, constraint: Option<&str>) {
        let dir = root.join(pod);
        std::fs::create_dir_all(&dir).unwrap();
        let mut lock = crate::lock::LockFile::empty();
        lock.packages.insert(
            "node".to_string(),
            crate::lock::PodPackageLockEntry {
                version: version.to_string(),
                constraint: constraint.map(String::from),
                deps: None,
                recipe_sha256: None,
                recipe_digest_scheme: None,
            },
        );
        lock.save(&dir.join(crate::lock::LockFile::FILENAME))
            .unwrap();
    }

    #[test]
    fn cross_pod_line_divergence_is_named_with_the_adr_vocabulary() {
        let dir = tempfile::tempdir().unwrap();
        // 'default' takes the current 26 line unconstrained; 'legacy'
        // pins the LTS line by constraint — the ADR-0047 example shape.
        pod_with_node_pin(dir.path(), "default", "26.7.0", None);
        pod_with_node_pin(dir.path(), "legacy", "22.23.3", Some("22"));
        let check = check_pod_version_lines_with(dir.path());
        assert!(
            matches!(check.status, CheckStatus::Ok),
            "hint-only: {check:?}"
        );
        let hint = check.hint.expect("divergence must be reported");
        assert!(
            hint.contains("'default' has node@26") && hint.contains("'legacy' has node@22"),
            "snapshot: both pins named in pod order: {hint}"
        );
        assert!(
            hint.contains("`name@constraint`") && hint.contains("ADR-0047"),
            "the remedy vocabulary must point at name@constraint (ADR-0047): {hint}"
        );
    }

    #[test]
    fn same_line_across_pods_and_missing_pods_stay_silent() {
        // Both pods on the 22 line: coexistence with no divergence — ok,
        // no hint.
        let dir = tempfile::tempdir().unwrap();
        pod_with_node_pin(dir.path(), "a", "22.23.3", Some("22"));
        pod_with_node_pin(dir.path(), "b", "22.23.3", Some("22"));
        let check = check_pod_version_lines_with(dir.path());
        assert!(matches!(check.status, CheckStatus::Ok));
        assert!(check.hint.is_none(), "no divergence, no hint: {check:?}");
        // No pod root at all: silent ok (doctor never initializes state).
        let empty = tempfile::tempdir().unwrap();
        let check = check_pod_version_lines_with(empty.path());
        assert!(matches!(check.status, CheckStatus::Ok) && check.hint.is_none());
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

        let checks = check_sandbox_tools_with(&SANDBOX_TOOLS, &entries);
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
        let checks = check_sandbox_tools_with(&SANDBOX_TOOLS, &entries);
        let make = checks
            .iter()
            .find(|c| c.name == "sandbox: make")
            .expect("make check present");
        assert!(matches!(make.status, CheckStatus::Missing));
        let hint = make.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("login PATH"),
            "hint must carry the fix: {hint}"
        );
    }

    // ── Pod-env credit for the cc/c++ toolchain checks (issue #178) ──

    /// A stand-in pod farm: `<pod>/current` with an executable tool shim
    /// inside — the shape the gcc payload's farm emission leaves behind
    /// (direct store links and the 77964ae dispatch shims).
    fn write_pod_farm(dir: &std::path::Path, pod: &str, tool: &str) -> PathBuf {
        let farm = dir.join(pod).join(crate::farm::CURRENT_LINK);
        std::fs::create_dir_all(&farm).unwrap();
        write_exec(&farm, tool);
        farm
    }

    /// The tool entry named by `POD_SANDBOX_TOOLS`, so tests exercise the
    /// real (tool, fix) pair run_scoped maps over.
    fn pod_tool(name: &str) -> (&'static str, &'static str) {
        POD_SANDBOX_TOOLS
            .iter()
            .find(|(tool, _)| *tool == name)
            .copied()
            .unwrap_or_else(|| panic!("{name} must be a POD_SANDBOX_TOOLS entry"))
    }

    #[test]
    fn doctor_pod_scope_credits_cc_and_cxx_from_a_pod_farm() {
        let dir = tempfile::tempdir().unwrap();
        let farm = write_pod_farm(dir.path(), "gate", "cc");
        write_exec(&farm, "c++");
        // Host PATH offers nothing (a garbage-collected store entry), so
        // the pod farm is the only provider — the live gate-pod shape.
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];

        for tool in ["cc", "c++"] {
            let (name, fix) = pod_tool(tool);
            let check =
                check_pod_toolchain_tool_with(name, fix, &entries, std::slice::from_ref(&farm));
            assert!(
                matches!(check.status, CheckStatus::Ok),
                "pod-provided {tool} must pass: {check:?}"
            );
            assert!(
                check.hint.is_none(),
                "pod-provided {tool} passes with no hint: {check:?}"
            );
        }
    }

    #[test]
    fn doctor_pod_scope_keeps_the_gcc_payload_hint_when_absent_everywhere() {
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];
        let (name, fix) = pod_tool("cc");
        let check = check_pod_toolchain_tool_with(name, fix, &entries, &[]);
        assert!(matches!(check.status, CheckStatus::Missing));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("gcc payload") && hint.contains("not found on PATH"),
            "genuinely-absent cc must keep the sideload hint: {hint}"
        );
    }

    #[test]
    fn doctor_pod_scope_farm_credit_wins_over_the_out_of_roots_error() {
        let dir = tempfile::tempdir().unwrap();
        // Host-resolvable cc outside the bind roots reads as the error
        // verdict on its own…
        write_exec(dir.path(), "cc");
        let farm = write_pod_farm(dir.path(), "gate", "cc");
        let entries = vec![
            dir.path().to_path_buf(),
            PathBuf::from("/nix/store/0000-garbage-collected/bin"),
        ];

        let bare = check_pod_toolchain_tool_with("cc", pod_tool("cc").1, &entries, &[]);
        assert!(
            matches!(bare.status, CheckStatus::Error),
            "host-only out-of-roots cc must stay the error verdict: {bare:?}"
        );

        // …but `nau run --pod` composes the farm FIRST, so with the
        // farm present the tool resolves and the check must say so.
        let check = check_pod_toolchain_tool_with("cc", pod_tool("cc").1, &entries, &[farm]);
        assert!(
            matches!(check.status, CheckStatus::Ok),
            "farm-first PATH resolves cc — must pass: {check:?}"
        );
    }

    #[test]
    fn doctor_pod_scope_farm_credit_requires_an_executable_shim() {
        let dir = tempfile::tempdir().unwrap();
        let farm = dir.path().join("gate").join(crate::farm::CURRENT_LINK);
        std::fs::create_dir_all(&farm).unwrap();
        std::fs::write(farm.join("cc"), "#!/bin/sh\n").unwrap(); // mode 644
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];

        let check = check_pod_toolchain_tool_with("cc", pod_tool("cc").1, &entries, &[farm]);
        assert!(
            matches!(check.status, CheckStatus::Missing),
            "a non-executable farm entry is no shim: {check:?}"
        );
    }

    #[test]
    fn doctor_pod_scope_credits_only_the_pod_env_tools_from_farms() {
        let dir = tempfile::tempdir().unwrap();
        let farm = write_pod_farm(dir.path(), "gate", "make");
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];

        let check = check_pod_toolchain_tool_with("make", pod_tool("make").1, &entries, &[farm]);
        assert!(
            matches!(check.status, CheckStatus::Missing),
            "make has no pod-shim contract — no farm credit: {check:?}"
        );
    }

    // ── Sync cc provenance (issue #180 item 3) ──

    /// The #180 incident shape: the sync PATH leads `cc` to a foreign
    /// compiler while a healthy pod's farm carries the pool toolchain —
    /// the collect2/ld skew doctor must name. Hint-only: status stays
    /// Ok, the warning lives in the hint.
    #[test]
    fn doctor_warns_when_the_path_cc_is_foreign_while_the_farm_carries_the_toolchain() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "cc");
        // The farm cc lives under gate/current/ — a subdir the PATH
        // entry does not recurse into, so the foreign dir/cc wins the
        // PATH resolution exactly like the incident's nix gcc.
        let farm = write_pod_farm(dir.path(), "gate", "cc");
        let entries = vec![dir.path().to_path_buf()];

        let check = check_cc_provenance_with(&entries, &[farm]);
        assert!(
            matches!(check.status, CheckStatus::Ok),
            "the skew warning is a hint, never fatal: {check:?}"
        );
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("warning") && hint.contains("collect2"),
            "the hint must name the skew class: {hint}"
        );
        assert!(
            hint.contains("nix shell"),
            "the hint must carry the issue's workaround: {hint}"
        );
    }

    /// A cc resolving from a farm dir (the `nau run --pod` PATH
    /// shape) IS the pool toolchain — no warning.
    #[test]
    fn doctor_credits_a_cc_that_resolves_from_a_pod_farm() {
        let dir = tempfile::tempdir().unwrap();
        let farm = write_pod_farm(dir.path(), "gate", "cc");
        let entries = vec![farm.clone()];

        let check = check_cc_provenance_with(&entries, &[farm]);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("pod toolchain farm") && !hint.contains("warning"),
            "{hint}"
        );
    }

    /// No cc anywhere: quiet Ok — absence already has the `sandbox: cc`
    /// verdict, and this check never double-flags it.
    #[test]
    fn doctor_stays_quiet_when_no_cc_resolves_anywhere() {
        let entries = vec![PathBuf::from("/nix/store/0000-garbage-collected/bin")];
        let check = check_cc_provenance_with(&entries, &[]);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "{check:?}");
    }

    /// A foreign cc with NO farm toolchain to skew against is plain
    /// host readiness — informational, not the #180 warning.
    #[test]
    fn doctor_hints_without_warning_when_only_a_foreign_cc_exists() {
        let dir = tempfile::tempdir().unwrap();
        write_exec(dir.path(), "cc");
        let entries = vec![dir.path().to_path_buf()];

        let check = check_cc_provenance_with(&entries, &[]);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("resolves to") && !hint.contains("warning"),
            "{hint}"
        );
    }

    /// Both doctor scopes gate the sync surface, so both carry the
    /// provenance check.
    #[test]
    fn run_all_and_pod_scope_include_the_sync_cc_provenance_check() {
        for checks in [run_all(), run_pod()] {
            assert!(
                checks.iter().any(|c| c.name == "sync cc provenance"),
                "missing sync cc provenance check"
            );
        }
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

    /// A minimal zstd wrapper: the 4-byte magic plus an opaque body. The
    /// injected fake runner answers the `zstd` invocation with canned bytes,
    /// so the body never needs to be a real frame — only the magic matters.
    fn zstd_wrapped(body: &[u8]) -> Vec<u8> {
        let mut out = ZSTD_MAGIC.to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn initrd_reader_walks_concatenated_newc_and_zstd_layers() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        // Ubuntu Core shape: uncompressed microcode archive first, then a
        // zstd-wrapped main archive.
        let microcode = newc_archive(&[("kernel/x86/microcode/AuthenticAMD.bin", b"microcode")]);
        let main = newc_archive(&[
            (
                "usr/lib/modules/5.15.0-186-generic/kernel/drivers/block/virtio_blk.ko",
                b"blob",
            ),
            ("usr/lib/snapd/snap-bootstrap", b"blob"),
        ]);
        let mut raw = microcode;
        raw.extend_from_slice(&[0u8; 12]); // trailer block padding
        raw.extend_from_slice(&zstd_wrapped(b"opaque zstd frame"));
        std::fs::write(&initrd, &raw).unwrap();
        let runner = DecompressRunner::new(main, 0);
        let members = read_initrd_members(&runner, &initrd).unwrap();
        assert_eq!(
            members,
            vec![
                "kernel/x86/microcode/AuthenticAMD.bin",
                "usr/lib/modules/5.15.0-186-generic/kernel/drivers/block/virtio_blk.ko",
                "usr/lib/snapd/snap-bootstrap",
            ]
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "one decompressor invocation: {calls:?}");
        assert_eq!(calls[0][0], "zstd", "zstd magic selects zstd: {calls:?}");
        assert_eq!(calls[0][1], "-dc");
        assert!(
            !calls[0][2].is_empty(),
            "a trailing layer is spooled to a real path: {calls:?}"
        );
    }

    #[test]
    fn initrd_reader_accepts_zero_padding_after_final_trailer() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        let mut raw = newc_archive(&[("kernels/6.8.0/virtio_blk.ko", b"blob")]);
        raw.extend_from_slice(&[0u8; 512]); // block-boundary zero fill
        std::fs::write(&initrd, &raw).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let members = read_initrd_members(&runner, &initrd).unwrap();
        assert_eq!(members, vec!["kernels/6.8.0/virtio_blk.ko"]);
        assert!(runner.calls().is_empty(), "zero padding needs no host tool");
    }

    #[test]
    fn initrd_reader_fails_closed_on_garbage_after_trailer() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        let mut raw = newc_archive(&[("kernels/6.8.0/virtio_blk.ko", b"blob")]);
        raw.extend_from_slice(b"not an archive at all");
        std::fs::write(&initrd, &raw).unwrap();
        let runner = DecompressRunner::new(Vec::new(), 0);
        let err = read_initrd_members(&runner, &initrd).unwrap_err();
        assert!(
            format!("{err:#}").contains("unrecognized initrd format at offset"),
            "an unrecognized trailing blob is a hard error: {err:#}"
        );
        assert!(runner.calls().is_empty(), "no decompressor for garbage");
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
        let check =
            state_partition_check("img", false, false, ["/var/lib/nau", "/var/lib/extensions"]);
        assert!(matches!(check.status, CheckStatus::Ok));
        assert!(check.hint.is_some());
    }

    #[test]
    fn state_partition_requested_and_present_is_ok() {
        let check =
            state_partition_check("img", true, true, ["/var/lib/nau", "/var/lib/extensions"]);
        assert!(matches!(check.status, CheckStatus::Ok));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("/var/lib/nau"),
            "hint names the paths: {hint}"
        );
    }

    #[test]
    fn state_partition_requested_but_absent_names_the_paths() {
        let check =
            state_partition_check("img", true, false, ["/var/lib/nau", "/var/lib/extensions"]);
        assert!(matches!(check.status, CheckStatus::Missing));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("/var/lib/nau") && hint.contains("/var/lib/extensions"),
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

    // ── Pod scope (#97) ──

    /// Every check name the pod scope may produce: the pod surface tools,
    /// the mksquashfs version gate (#155 — pod builds pay the pack cost),
    /// and the sandbox build toolchain (`sandbox:`-prefixed).
    const POD_SCOPE_NAMES: [&str; 10] = [
        "mksquashfs",
        "mksquashfs >= 4.4 (SOURCE_DATE_EPOCH)",
        "unsquashfs",
        "bwrap",
        "curl",
        "tar",
        "sandbox: sh",
        "sandbox: make",
        "sandbox: cc",
        "sandbox: c++",
    ];

    /// The image-verb check names that must never appear in pod scope.
    const IMAGE_SCOPE_NAMES: [&str; 4] = [
        "ukify",
        "linuxx64.efi.stub",
        "veritysetup",
        "systemd-sysupdate",
    ];

    #[test]
    fn pod_scope_gates_exactly_the_pod_surface() {
        let pod = run_pod();
        for name in POD_SCOPE_NAMES {
            assert!(
                pod.iter().any(|c| c.name == name),
                "pod scope must gate {name}"
            );
        }
        for name in IMAGE_SCOPE_NAMES {
            assert!(
                !pod.iter().any(|c| c.name == name),
                "image check {name} must not run in pod scope"
            );
        }
        // #155 flipped the old exclusion: the mksquashfs version gate now
        // gates pod scope too (pod builds pay the pack cost).
        assert!(
            pod.iter().any(|c| c.name.contains("SOURCE_DATE_EPOCH")),
            "the mksquashfs version gate must run in pod scope (#155)"
        );
    }

    #[test]
    fn full_scope_keeps_pod_surface_plus_image_checks() {
        // The default scope must still gate everything the pod scope does
        // PLUS exactly the four image-verb checks — no behavior change.
        // (Only the pod-surface checks must appear in full; the toolchain
        // lists differ by design — pod adds the c++ driver, full keeps
        // sh/make/cc.) The env lock keeps concurrent probe/env tests from
        // skewing the probe-check counts mid-run.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let full = run_all();
        let pod = run_pod();
        for check in pod.iter().filter(|c| !c.name.starts_with("sandbox: ")) {
            assert!(
                full.iter().any(|c| c.name == check.name),
                "full scope lost the pod check {}",
                check.name
            );
        }
        let full_toolchain: Vec<&str> = full
            .iter()
            .filter(|c| c.name.starts_with("sandbox: "))
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            full_toolchain,
            ["sandbox: sh", "sandbox: make", "sandbox: cc"],
            "full scope toolchain must stay sh/make/cc"
        );
        // The non-toolchain part of the full scope is exactly the pod
        // surface (6 checks, including the mksquashfs version gate that
        // runs in both scopes since #155) plus the four image-verb
        // checks; the toolchain lists differ by design (pod adds the c++
        // driver).
        let full_base = full
            .iter()
            .filter(|c| !c.name.starts_with("sandbox: "))
            .count();
        let pod_base = pod
            .iter()
            .filter(|c| !c.name.starts_with("sandbox: "))
            .count();
        assert_eq!(
            full_base,
            pod_base + 4,
            "full scope = pod surface + 4 image checks (ukify, sd-stub, \
             veritysetup, sysupdate); got full={} pod={}",
            full_base,
            pod_base
        );
        for name in IMAGE_SCOPE_NAMES {
            assert!(
                full.iter().any(|c| c.name == name),
                "full scope must keep the image check {name}"
            );
        }
    }

    #[test]
    fn pod_scope_failures_name_only_pod_surface_tools() {
        // Whatever the host is missing, a pod-scope failure can only name
        // a pod tool, a toolchain entry, or a functional probe (#101) —
        // never an image tool.
        let pod = run_pod();
        let failing: Vec<&str> = pod
            .iter()
            .filter(|c| !matches!(c.status, CheckStatus::Ok))
            .map(|c| c.name.as_str())
            .collect();
        assert!(
            failing
                .iter()
                .all(|name| POD_SCOPE_NAMES.contains(name) || name.starts_with("probe: ")),
            "pod scope must only fail on pod-surface tools or probes, got: {failing:?}"
        );
    }

    #[test]
    fn pod_scope_passes_with_pod_tools_present_and_image_tools_absent() {
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // On a host provisioned with the pod surface (the container-distro
        // evidence case), every pod-tool check must pass — image tools are
        // structurally absent from the scope (the surface test above), so
        // their absence cannot fail it.
        let have = |tool: &str| {
            std::process::Command::new("which")
                .arg(tool)
                .output()
                .ok()
                .is_some_and(|o| o.status.success())
        };
        if !POD_TOOL_FIXES.iter().all(|(tool, _)| have(tool.as_str()))
            || !have("bwrap")
            || bwrap_probe_target_from(&["/bin/true", "/usr/bin/true", "/bin/sh"]).is_none()
        {
            // Host without the pod set — or without any sandbox exec
            // target (/bin/true absent on NixOS; /bin/sh is the fallback):
            // the pass branch is exercised on a provisioned machine instead.
            return;
        }
        let pod = run_pod();
        let surface: Vec<&Check> = pod
            .iter()
            .filter(|c| !c.name.starts_with("sandbox: "))
            .collect();
        assert!(
            surface.iter().all(|c| matches!(c.status, CheckStatus::Ok)),
            "a machine with the pod tool set must pass the pod-surface checks: {surface:?}"
        );
        assert!(
            !pod.iter()
                .any(|c| IMAGE_SCOPE_NAMES.contains(&c.name.as_str())),
            "image checks leaked into pod scope"
        );
    }

    #[test]
    fn pod_scope_hints_lead_with_payload_and_keep_distro_fallback() {
        // install.sh's pkg_for map: squashfs-tools, bubblewrap, curl, tar,
        // and g++ (gcc-c++ on dnf/zypper) for cc/c++ — the latter now the
        // FALLBACK text behind the gcc payload sideload (#164 follow-up).
        // The floor tools' PRIMARY fix is `nau doctor --fix` (#101);
        // the distro text stays as the named fallback.
        for (tool, fix) in POD_TOOL_FIXES {
            assert!(!fix.is_empty(), "{tool} must carry a fix hint");
            assert!(
                fix.contains("install"),
                "hint must phrase the install fix: {fix}"
            );
        }
        let bwrap = check_floor_tool(ToolName::Bwrap);
        if let CheckStatus::Missing = bwrap.status {
            let hint = bwrap.hint.as_deref().unwrap_or_default();
            assert!(
                hint.contains("bubblewrap"),
                "bwrap hint must name the distro package: {hint}"
            );
            assert!(
                hint.contains("nau doctor --fix"),
                "missing floor tool must lead with the provision fix: {hint}"
            );
        }
        for (tool, fix) in POD_SANDBOX_TOOLS {
            match tool {
                "cc" | "c++" => {
                    // The gcc payload sideload leads (#164 follow-up: one
                    // payload carries cc and c++); the install.sh distro
                    // packages stay as the fallback text.
                    assert!(
                        fix.contains("gcc payload")
                            && fix.contains("pod add")
                            && fix.contains("cc and c++"),
                        "{tool} hint must lead with the gcc payload sideload: {fix}"
                    );
                    match tool {
                        "cc" => assert!(
                            fix.contains("apt install gcc"),
                            "cc hint must keep the distro fallback per install.sh: {fix}"
                        ),
                        _ => assert!(
                            fix.contains("g++") && fix.contains("gcc-c++"),
                            "c++ hint must keep the distro packages per install.sh: {fix}"
                        ),
                    }
                }
                _ => assert!(!fix.is_empty(), "{tool} must carry a fix hint"),
            }
        }
    }

    // ── Floor-tool origin report, probes, notices (issue #101) ──

    /// Env vars are process-global; cargo runs tests in parallel threads.
    /// Tests that read or mutate tool-related env hold the shared
    /// crate-wide lock (src/test_env.rs) — the per-module statics of the
    /// pre-#186 era excluded nothing across modules.
    use crate::test_env::ENV_LOCK;

    /// Points `NAU_TOOLS_DIR` at a tempdir for the test's lifetime and
    /// restores the previous value on drop.
    struct ToolsDirGuard {
        saved: Option<std::ffi::OsString>,
    }

    impl ToolsDirGuard {
        fn at(path: &Path) -> Self {
            const ENV_TOOLS_DIR: &str = "NAU_TOOLS_DIR";
            let saved = std::env::var_os(ENV_TOOLS_DIR);
            std::env::set_var(ENV_TOOLS_DIR, path);
            ToolsDirGuard { saved }
        }
    }

    impl Drop for ToolsDirGuard {
        fn drop(&mut self) {
            const ENV_TOOLS_DIR: &str = "NAU_TOOLS_DIR";
            match self.saved.take() {
                Some(v) => std::env::set_var(ENV_TOOLS_DIR, v),
                None => std::env::remove_var(ENV_TOOLS_DIR),
            }
        }
    }

    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Fake squashfs pair that round-trips by copying, speaking the probe's
    /// exact argv. A real squashfs pair stores and restores xattrs; busybox
    /// `cp` (the devbox profile's cp) drops them, so the fakes carry
    /// `user.probe` across explicitly via getfattr/setfattr.
    const FAKE_MKSQUASHFS_BODY: &str = r#"#!/bin/sh
set -e
mkdir -p "$2"
cp "$1" "$2/"
v=$(getfattr -n user.probe "$1" 2>/dev/null | sed -n 's/^user.probe="\([^"]*\)"$/\1/p')
[ -z "$v" ] || setfattr -n user.probe -v "$v" "$2/$(basename "$1")"
"#;
    const FAKE_UNSQUASHFS_BODY: &str = r#"#!/bin/sh
set -e
out="$2"
img="$3"
mkdir -p "$out"
for f in "$img"/*; do
  cp "$f" "$out/"
  v=$(getfattr -n user.probe "$f" 2>/dev/null | sed -n 's/^user.probe="\([^"]*\)"$/\1/p')
  [ -z "$v" ] || setfattr -n user.probe -v "$v" "$out/$(basename "$f")"
done
"#;

    /// Hand-builds the on-disk provisioned-set shape for `tools` at
    /// `<root>/<version>/bin` + the `current` pointer — the read side
    /// (resolve) needs only an executable file behind the pointer.
    fn provision_fake_set(root: &Path, version: u64, bodies: &[(&str, &str)]) {
        let bin = root.join(version.to_string()).join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for (name, body) in bodies {
            write_script(&bin, name, body);
        }
        std::fs::write(root.join("current"), format!("{version}\n")).unwrap();
    }

    #[test]
    fn floor_tool_check_reports_provisioned_origin_with_manifest_version() {
        let resolved = Ok(ResolvedTool::Provisioned {
            path: PathBuf::from("/tools/3/bin/mksquashfs"),
            version: "3".into(),
        });
        let check = floor_tool_check_with(
            ToolName::Mksquashfs,
            resolved,
            Some("4.7.5"),
            "install squashfs-tools",
        );
        assert!(matches!(check.status, CheckStatus::Ok));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert_eq!(hint, "provisioned 4.7.5 (tools v3)");
    }

    #[test]
    fn floor_tool_check_reports_path_origin_with_version() {
        // Spawning the probe helper resolves through PATH, so the whole
        // window rides the shared crate test-env lock — concurrent
        // PATH-swapping tests otherwise flake the version discovery
        // (the four-per-module-lock era raced exactly here).
        let _lock = crate::test_env::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let fake = write_script(
            dir.path(),
            "curl",
            "#!/bin/sh\necho curl 8.20.0 libcurl/8.20.0\n",
        );
        let resolved = Ok(ResolvedTool::Path {
            path: fake.clone(),
            version: None,
        });
        let check = floor_tool_check_with(ToolName::Curl, resolved, None, "install curl");
        assert!(matches!(check.status, CheckStatus::Ok));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains(&fake.display().to_string()) && hint.contains("8.20.0"),
            "PATH origin carries path + discovered version: {hint}"
        );
        assert!(hint.starts_with("PATH "), "{hint}");
    }

    #[test]
    fn floor_tool_check_missing_names_fix_and_escape_hatches() {
        let resolved = Err(tools::ToolsError::NotResolved {
            tool: "bwrap".into(),
            detail: "nothing anywhere".into(),
        });
        let check = floor_tool_check_with(
            ToolName::Bwrap,
            resolved,
            None,
            "install bubblewrap (e.g. apt install bubblewrap)",
        );
        assert!(matches!(check.status, CheckStatus::Missing));
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("nau doctor --fix"),
            "the primary fix is the provisioner: {hint}"
        );
        assert!(
            hint.contains("NAU_TOOLS_DIR") && hint.contains("NAU_TOOL_BWRAP"),
            "missing floor tools must list the escape hatches (AC-6): {hint}"
        );
        assert!(
            hint.contains("bubblewrap"),
            "the distro fallback stays named: {hint}"
        );
    }

    #[test]
    fn squashfs_version_parse_is_tolerant_not_a_closed_list() {
        // AC-8: the old closed allowlist (4.4/4.5/4.6 substring sniffing)
        // is now a leading numeric triple parse (#155: major.minor.patch).
        assert_eq!(
            parse_squashfs_version("mksquashfs version 4.6.1 (2023-08-31)"),
            Some((4, 6, 1))
        );
        assert_eq!(
            parse_squashfs_version("mksquashfs version 4.7.5"),
            Some((4, 7, 5))
        );
        assert_eq!(parse_squashfs_version("4.4"), Some((4, 4, 0)));
        assert_eq!(
            parse_squashfs_version("mksquashfs version 3.1"),
            Some((3, 1, 0))
        );
        // Defensive about pre/suffix forms: leading digits per component;
        // a missing or non-numeric patch reads as 0. Never panics.
        assert_eq!(
            parse_squashfs_version("mksquashfs version 4.7.5-pre (2025-06-01)"),
            Some((4, 7, 5))
        );
        assert_eq!(
            parse_squashfs_version("mksquashfs version 4.9.x"),
            Some((4, 9, 0))
        );
        assert_eq!(parse_squashfs_version("no version here"), None);
        assert_eq!(parse_squashfs_version(""), None);
        assert_eq!(parse_squashfs_version("version 4"), None);
        assert!((4, 7, 5) >= SQUASHFS_SDE_MIN);
        assert!((5, 0, 0) >= SQUASHFS_SDE_MIN);
        assert!((4, 3, 9) < SQUASHFS_SDE_MIN);
        // #155: the pack-performance floor sits above the
        // SOURCE_DATE_EPOCH floor.
        assert!((4, 6, 1) < SQUASHFS_PERF_MIN);
        assert!((4, 7, 0) >= SQUASHFS_PERF_MIN);
    }

    #[test]
    fn provisioned_squashfs_is_never_labelled_untested() {
        // AC-8: doctor's own provisioned tool, whatever its binary answers
        // to -version, is accepted via the manifest pin.
        let resolved = Ok(ResolvedTool::Provisioned {
            path: PathBuf::from("/tools/3/bin/mksquashfs"),
            version: "3".into(),
        });
        let check = check_squashfs_version_with(resolved, Some("4.7.5"));
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("4.7.5") && hint.contains("tools v3"),
            "{hint}"
        );
        assert!(!hint.contains("untested"), "{hint}");
        assert!(
            !hint.contains("faster builds"),
            "a 4.7+ pin carries no upgrade advice: {hint}"
        );
    }

    #[test]
    fn provisioned_squashfs_with_unparsable_pin_stays_ok() {
        let resolved = Ok(ResolvedTool::Provisioned {
            path: PathBuf::from("/tools/3/bin/mksquashfs"),
            version: "3".into(),
        });
        let check = check_squashfs_version_with(resolved, Some("opaque"));
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("verified manifest") && !hint.contains("untested"),
            "{hint}"
        );
    }

    #[test]
    fn path_squashfs_gate_accepts_4_7_and_rejects_3_x() {
        let dir = tempfile::tempdir().unwrap();
        let modern = write_script(
            dir.path(),
            "mksquashfs-modern",
            "#!/bin/sh\necho 'mksquashfs version 4.7.5 (2024)'\n",
        );
        let ok = check_squashfs_version_with(
            Ok(ResolvedTool::Path {
                path: modern,
                version: None,
            }),
            None,
        );
        assert!(matches!(ok.status, CheckStatus::Ok), "{ok:?}");
        // #155: the detected version is printed, full triple.
        let ok_hint = ok.hint.as_deref().unwrap_or_default();
        assert!(ok_hint.contains("4.7.5"), "{ok_hint}");
        assert!(
            !ok_hint.contains("faster builds"),
            "4.7+ carries no upgrade advice: {ok_hint}"
        );

        let ancient = write_script(
            dir.path(),
            "mksquashfs-ancient",
            "#!/bin/sh\necho mksquashfs version 3.1\n",
        );
        let old = check_squashfs_version_with(
            Ok(ResolvedTool::Path {
                path: ancient,
                version: None,
            }),
            None,
        );
        assert!(matches!(old.status, CheckStatus::Error), "{old:?}");
        assert!(
            old.hint
                .as_deref()
                .unwrap_or_default()
                .contains("predates SOURCE_DATE_EPOCH"),
            "{old:?}"
        );
    }

    #[test]
    fn squashfs_upgrade_advice_fires_below_4_7_and_stays_advisory() {
        // #155: a detected version below 4.7 carries the upgrade advice
        // on an OK line — the advice never fails a command; 4.7+ gets no
        // advice.
        let dir = tempfile::tempdir().unwrap();
        let mk = |name: &str, body: &str| {
            check_squashfs_version_with(
                Ok(ResolvedTool::Path {
                    path: write_script(dir.path(), name, body),
                    version: None,
                }),
                None,
            )
        };

        let older = mk(
            "mksquashfs-461",
            "#!/bin/sh\necho 'mksquashfs version 4.6.1 (2023-08-31)'\n",
        );
        assert!(
            matches!(older.status, CheckStatus::Ok),
            "the perf advice is advisory only: {older:?}"
        );
        let hint = older.hint.as_deref().unwrap_or_default();
        assert!(hint.contains("4.6.1"), "detected version printed: {hint}");
        assert!(
            hint.contains("faster builds") && hint.contains("parallelized reads"),
            "below 4.7 advises the upgrade: {hint}"
        );

        let modern = mk(
            "mksquashfs-475",
            "#!/bin/sh\necho mksquashfs version 4.7.5\n",
        );
        assert!(matches!(modern.status, CheckStatus::Ok), "{modern:?}");
        let hint = modern.hint.as_deref().unwrap_or_default();
        assert!(hint.contains("4.7.5"), "{hint}");
        assert!(
            !hint.contains("faster builds") && !hint.contains("parallelized reads"),
            "4.7+ carries no upgrade advice: {hint}"
        );

        // The same advice on a provisioned tool whose manifest pin is
        // below 4.7 — advisory there too.
        let pinned = check_squashfs_version_with(
            Ok(ResolvedTool::Provisioned {
                path: PathBuf::from("/tools/3/bin/mksquashfs"),
                version: "3".into(),
            }),
            Some("4.6.1"),
        );
        assert!(matches!(pinned.status, CheckStatus::Ok), "{pinned:?}");
        assert!(
            pinned
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("faster builds"),
            "{pinned:?}"
        );

        // The advisory outcomes all read as ok: `nau doctor` exits 0.
        assert!(
            all_ok(&[older, modern, pinned]),
            "the version advice must never fail a command"
        );
    }

    #[test]
    fn unparsable_path_squashfs_version_is_unknown_advisory() {
        // #155: unparseable -version output reports the version as
        // unknown on an OK line — never a failure, and no upgrade advice
        // (with no version there is nothing to compare against 4.7).
        let dir = tempfile::tempdir().unwrap();
        let opaque = write_script(
            dir.path(),
            "mksquashfs-opaque",
            "#!/bin/sh\necho 'mksquashfs: some future output shape'\n",
        );
        let check = check_squashfs_version_with(
            Ok(ResolvedTool::Path {
                path: opaque,
                version: None,
            }),
            None,
        );
        assert!(
            matches!(check.status, CheckStatus::Ok),
            "unknown version stays advisory: {check:?}"
        );
        let hint = check.hint.as_deref().unwrap_or_default();
        assert!(hint.contains("unparsable"), "{hint}");
        assert!(
            !hint.contains("faster builds"),
            "no advice without a detected version: {hint}"
        );
        assert!(all_ok(&[check]));
    }

    /// #155: pod builds pay the pack cost, so both scopes gate the
    /// mksquashfs version.
    #[test]
    fn run_all_and_pod_scope_include_the_mksquashfs_version_gate() {
        for checks in [run_all(), run_pod()] {
            assert!(
                checks
                    .iter()
                    .any(|c| c.name == "mksquashfs >= 4.4 (SOURCE_DATE_EPOCH)"),
                "missing the mksquashfs version gate"
            );
        }
    }

    #[test]
    fn kernel_version_parse_and_compare() {
        assert_eq!(parse_kernel_version("6.8.0-42-generic"), Some(vec![6, 8]));
        assert_eq!(parse_kernel_version("5.10"), Some(vec![5, 10]));
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("generic"), None);

        assert!(kernel_below(&[5, 9], &[5, 10]));
        assert!(!kernel_below(&[5, 10], &[5, 10]));
        assert!(!kernel_below(&[6, 0], &[5, 10]));
        assert!(!kernel_below(&[5, 10, 1], &[5, 10]));
        assert!(kernel_below(&[5, 9, 9], &[5, 10]));
    }

    #[test]
    fn min_kernel_notice_warns_only_below_the_floor() {
        // Below the floor: warn-only line naming both versions.
        let below = min_kernel_notice_with(Some("5.4.0-42-generic\n"), Some("5.10")).unwrap();
        assert!(below.contains("5.4.0") && below.contains("5.10"), "{below}");
        assert!(below.contains("warning"), "{below}");

        // At or above: quiet.
        assert_eq!(
            min_kernel_notice_with(Some("6.8.0-42-generic"), Some("5.10")),
            None
        );
        assert_eq!(min_kernel_notice_with(Some("5.10.0"), Some("5.10")), None);

        // No floor in the manifest: nothing at all.
        assert_eq!(min_kernel_notice_with(Some("4.1.0"), None), None);

        // An unparsable release is named, never silently skipped.
        let unparsable = min_kernel_notice_with(Some("generic-build"), Some("5.10")).unwrap();
        assert!(
            unparsable.contains("kernel version unparsable"),
            "{unparsable}"
        );
        let missing = min_kernel_notice_with(None, Some("5.10")).unwrap();
        assert!(missing.contains("kernel version unparsable"), "{missing}");
    }

    #[test]
    fn stale_notice_fires_only_on_a_version_mismatch() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());

        // Nothing installed: not stale.
        assert_eq!(stale_notice(), None);

        // A pointer off the manifest's tools_version is stale.
        std::fs::write(root.path().join("current"), "7\n").unwrap();
        let notice = stale_notice().unwrap();
        let manifest_v = format!("manifest v{}", tools::manifest().tools_version);
        assert!(
            notice.contains("installed v7") && notice.contains(&manifest_v),
            "{notice}"
        );
        assert!(
            notice.contains("nau doctor --fix")
                && notice.contains("NAU_TOOLS_DIR")
                && notice.contains("NAU_TOOL_<NAME>"),
            "stale reports must carry the fix and the escape hatches: {notice}"
        );
    }

    #[test]
    fn run_probe_classifies_a_nonexecutable_file_as_noexec() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("data.bin");
        std::fs::write(&plain, b"not executable").unwrap();
        match run_probe(&plain, &[]) {
            ProbeRun::Noexec(e) => {
                let hint = noexec_hint("the resolved tool", &e);
                assert!(
                    hint.contains("noexec") && hint.contains("NAU_TOOLS_DIR"),
                    "the noexec diagnostic names the cause and workaround: {hint}"
                );
            }
            other => panic!("expected Noexec, got {other:?}"),
        }
    }

    #[test]
    fn squashfs_probe_round_trips_content_with_a_fake_pair() {
        let dir = tempfile::tempdir().unwrap();
        let mk = write_script(dir.path(), "mksquashfs", FAKE_MKSQUASHFS_BODY);
        let us = write_script(dir.path(), "unsquashfs", FAKE_UNSQUASHFS_BODY);
        let note = squashfs_roundtrip(&mk, &us).unwrap_or_else(|e| panic!("probe failed: {e}"));
        assert!(note.contains("content"), "{note}");
    }

    #[test]
    fn squashfs_probe_fails_named_when_unpacking_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mk = write_script(dir.path(), "mksquashfs", FAKE_MKSQUASHFS_BODY);
        let us = write_script(
            dir.path(),
            "unsquashfs",
            "#!/bin/sh\necho boom >&2\nexit 7\n",
        );
        let err = squashfs_roundtrip(&mk, &us).unwrap_err();
        assert!(
            err.contains("unsquashfs exited 7"),
            "the failing step is named: {err}"
        );
    }

    #[test]
    fn squashfs_probe_fails_named_when_content_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mk = write_script(dir.path(), "mksquashfs", FAKE_MKSQUASHFS_BODY);
        // "Packs" but writes an empty probe file: content lost in transit.
        let us = write_script(
            dir.path(),
            "unsquashfs",
            "#!/bin/sh\nmkdir -p \"$2\"\n: > \"$2/probe.txt\"\n",
        );
        let err = squashfs_roundtrip(&mk, &us).unwrap_err();
        assert!(
            err.contains("did not survive"),
            "a silent fidelity loss is an error, not a pass: {err}"
        );
    }

    #[test]
    fn bwrap_probe_target_falls_through_to_sh_and_fails_named_when_none() {
        let sh = bwrap_probe_target_from(&["/nonexistent-probe-true", "/bin/sh"])
            .expect("/bin/sh exists on every Linux");
        assert_eq!(sh.0, "/bin/sh");
        assert_eq!(sh.1, vec!["-c", "exit 0"]);
        assert_eq!(
            bwrap_probe_target_from(&["/nonexistent-probe-true"]),
            None,
            "no candidate exists -> the probe fails closed with a named cause"
        );
    }

    #[test]
    fn bwrap_probe_passes_a_real_sandbox_exec_and_names_failures() {
        let dir = tempfile::tempdir().unwrap();
        let good = write_script(dir.path(), "bwrap", "#!/bin/sh\nexit 0\n");
        let ok = bwrap_probe_check(&good);
        assert!(matches!(ok.status, CheckStatus::Ok), "{ok:?}");
        assert!(
            ok.hint.as_deref().unwrap_or_default().contains("--ro-bind"),
            "the pass line names the real sandbox exec: {ok:?}"
        );

        let userns = write_script(
            dir.path(),
            "bwrap-userns",
            "#!/bin/sh\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n",
        );
        let failed = bwrap_probe_check(&userns);
        assert!(matches!(failed.status, CheckStatus::Error), "{failed:?}");
        let hint = failed.hint.as_deref().unwrap_or_default();
        assert!(
            hint.contains("user namespaces appear disabled"),
            "a uid-map failure names the userns cause: {hint}"
        );
    }

    #[test]
    fn getfattr_output_parser_reads_both_shapes() {
        // GNU getfattr prints a header plus the quoted attribute.
        let gnu = "# file: probe.txt\nuser.probe=\"nau-probe\"\n";
        assert_eq!(parse_getfattr_value(gnu).as_deref(), Some("nau-probe"));
        // busybox getfattr prints just the name="value" line.
        assert_eq!(
            parse_getfattr_value("user.probe=\"nau-probe\"\n").as_deref(),
            Some("nau-probe")
        );
        assert_eq!(parse_getfattr_value(""), None);
        assert_eq!(parse_getfattr_value("# file: x\n"), None);
    }

    #[test]
    fn probe_checks_resolve_through_the_provisioned_set() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guard = ToolsDirGuard::at(root.path());
        provision_fake_set(
            root.path(),
            3,
            &[
                ("mksquashfs", FAKE_MKSQUASHFS_BODY),
                ("unsquashfs", FAKE_UNSQUASHFS_BODY),
                ("bwrap", "#!/bin/sh\nexit 0\n"),
            ],
        );

        let checks = probe_checks();
        assert_eq!(checks.len(), 2, "pair + bwrap resolve: {checks:?}");
        for name in ["probe: squashfs round-trip", "probe: bwrap sandbox exec"] {
            let check = checks.iter().find(|c| c.name == name).unwrap();
            assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        }
        // The floor-tool origin report reads the same set.
        let origin = check_floor_tool(ToolName::Mksquashfs);
        assert!(matches!(origin.status, CheckStatus::Ok), "{origin:?}");
        let hint = origin.hint.as_deref().unwrap_or_default();
        assert!(
            hint.starts_with("provisioned") && hint.contains("tools v3"),
            "{hint}"
        );
    }

    // ── pod failed-unit scan (ADR-0042 D3, issue #231) ──

    /// A `+x` shell script; returns its absolute path (argv[0] form) —
    /// the secrets.rs test-module fixture shape.
    fn secret_provider_script(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// A pod declaration with one exec-secret reference — the same
    /// minimal `pod.lua` the secrets.rs fixtures use.
    fn seed_secret_pod(root: &Path, name: &str, provider: &str) {
        let pod = root.join(name);
        std::fs::create_dir_all(&pod).unwrap();
        std::fs::write(
            pod.join("pod.lua"),
            format!(
                r#"pod {{
    secrets = {{ K = {{ source = "exec", command = {{ "{provider}" }} }} }},
}}
"#
            ),
        )
        .unwrap();
    }

    /// Give the pod an active generation 3 (`current` →
    /// `generations/3/farm`) — the verbs only parse the link.
    fn activate_generation(root: &Path, name: &str) {
        let pod = root.join(name);
        std::fs::create_dir_all(pod.join("generations").join("3")).unwrap();
        std::os::unix::fs::symlink("generations/3/farm", pod.join("current")).unwrap();
    }

    /// Record generation `gen`'s units.json with (service name, rendered
    /// text) pairs — the fixture shape `units_referencing_envfile`
    /// reads (the secrets.rs `seed_units` shape).
    fn seed_generation_units(pod_dir: &Path, gen: u64, units: &[(&str, String)]) {
        let dir = pod_dir
            .join("generations")
            .join(gen.to_string())
            .join(crate::services::SERVICES_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let units: Vec<serde_json::Value> = units
            .iter()
            .map(|(name, text)| {
                serde_json::json!({
                    "name": name, "pkg": "pkg", "layer": "own",
                    "daemon": "simple", "enabled": true, "exec": "/exec",
                    "args": [], "environment": {}, "after": [],
                    "text": text, "hash": "h",
                })
            })
            .collect();
        std::fs::write(
            dir.join("units.json"),
            serde_json::to_vec(&serde_json::json!({ "units": units })).unwrap(),
        )
        .unwrap();
    }

    /// A fake systemctl for the `is-failed` probe: exits 0 (failed)
    /// only when the unit argument is on the list, 1 otherwise.
    fn fake_is_failed(dir: &Path, failed_units: &[&str]) -> crate::runtime::RuntimeTools {
        let path = dir.join("fake-systemctl");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nunit=\"$3\"\ncase \" {} \" in *\" $unit \"*) exit 0;; *) exit 1;; esac\n",
                failed_units.join(" ")
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        crate::runtime::RuntimeTools {
            systemctl: Some(path),
            ..Default::default()
        }
    }

    /// Stand up pod `work` with a consumer unit (`web`) and a
    /// non-consumer (`side`); returns the derived envfile path (the
    /// passive derivation the check itself uses) and the pod dir.
    fn seed_consumer_pod(
        tmp: &Path,
        failed_envfile: bool,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let cache = tmp.join("cache");
        let provider = secret_provider_script(tmp, "provider", "echo SECRET");
        seed_secret_pod(tmp, "work", &provider);
        activate_generation(tmp, "work");
        let pod_dir = tmp.join("work");
        let refs = {
            let decl = crate::pod::load_declaration(tmp, "work").unwrap();
            crate::pod::resolve_pod_secrets(tmp, "work", &decl).unwrap()
        };
        let envfile = crate::secrets::pod_envfile_path_passive("work", &refs, Some(&cache))
            .unwrap()
            .unwrap();
        let consumer_text = format!(
            "ExecStart=/bin/true\nEnvironmentFile=\"{}\"\n",
            envfile.display()
        );
        seed_generation_units(
            &pod_dir,
            3,
            &[
                ("web", consumer_text),
                ("side", "ExecStart=/bin/true\n".to_string()),
            ],
        );
        if !failed_envfile {
            // Refresh materializes the envfile tree; the fixture does
            // the minimum: the parent dir, then the file.
            std::fs::create_dir_all(envfile.parent().unwrap()).unwrap();
            std::fs::write(&envfile, "K=\"SECRET\"\n").unwrap();
        }
        (cache, envfile)
    }

    #[test]
    fn pod_failed_units_names_refresh_when_envfile_gone_and_unit_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, envfile) = seed_consumer_pod(tmp.path(), true);
        let tools = fake_is_failed(tmp.path(), &["nau-pod-work-web.service"]);
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        // Hint-only: the boot story is advisory, never a failing check.
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.expect("the failed unit must be named");
        assert_eq!(
            hint,
            format!(
                "unit 'nau-pod-work-web.service' starts failed: envfile {} \
                 is gone (tmpfs secrets die at reboot) — run `pod secrets \
                 refresh` to re-resolve the pod's secrets and restart its \
                 consumers",
                envfile.display()
            )
        );
    }

    #[test]
    fn pod_failed_units_quiet_when_envfile_present() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, _) = seed_consumer_pod(tmp.path(), false);
        let tools = fake_is_failed(tmp.path(), &["nau-pod-work-web.service"]);
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "nothing to name: {check:?}");
    }

    #[test]
    fn pod_failed_units_quiet_when_unit_not_failed() {
        let tmp = tempfile::tempdir().unwrap();
        // Envfile gone (the D3 state) but the probe says the unit is
        // not failed (never started / already recovered): no notice.
        let (cache, _) = seed_consumer_pod(tmp.path(), true);
        let tools = fake_is_failed(tmp.path(), &[]);
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "nothing to name: {check:?}");
    }

    #[test]
    fn pod_failed_units_ignores_units_not_referencing_the_envfile() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, _) = seed_consumer_pod(tmp.path(), true);
        // `side` references no envfile: even reported failed, it is out
        // of scope for the scan — only the consumer is named.
        let tools = fake_is_failed(
            tmp.path(),
            &["nau-pod-work-web.service", "nau-pod-work-side.service"],
        );
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        let hint = check.hint.expect("the consumer must be named");
        assert!(hint.contains("nau-pod-work-web.service"), "{hint}");
        assert!(
            !hint.contains("nau-pod-work-side.service"),
            "non-consumer is out of scope: {hint}"
        );
    }

    #[test]
    fn pod_failed_units_skips_named_when_systemctl_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, _) = seed_consumer_pod(tmp.path(), true);
        let tools = crate::runtime::RuntimeTools::default();
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        // Reconcile semantics: tool absence is a NAMED skip, never a
        // failed check.
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        let hint = check.hint.expect("the skip must be named");
        assert!(hint.starts_with("skipped: systemctl unavailable"), "{hint}");
        assert!(hint.contains("nau-pod-work-web.service"), "{hint}");
    }

    #[test]
    fn pod_failed_units_passes_silently_without_pod_state() {
        let tmp = tempfile::tempdir().unwrap();
        let tools = fake_is_failed(tmp.path(), &["anything"]);
        // Unknown pod.
        let check =
            check_pod_failed_units_with(tmp.path(), "ghost", Some(&tmp.path().join("c")), &tools);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "{check:?}");
        // Known pod, never synced (no active generation).
        let provider = secret_provider_script(tmp.path(), "provider", "echo SECRET");
        seed_secret_pod(tmp.path(), "work", &provider);
        let check =
            check_pod_failed_units_with(tmp.path(), "work", Some(&tmp.path().join("c")), &tools);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "{check:?}");
    }

    #[test]
    fn pod_failed_units_passes_silently_without_secret_refs() {
        let tmp = tempfile::tempdir().unwrap();
        // A synced pod whose declaration carries no secrets: no envfile
        // to scan for, no units to select.
        let pod = tmp.path().join("plain");
        std::fs::create_dir_all(&pod).unwrap();
        std::fs::write(pod.join("pod.lua"), "pod {}\n").unwrap();
        activate_generation(tmp.path(), "plain");
        seed_generation_units(&pod, 3, &[("web", "ExecStart=/bin/true\n".to_string())]);
        let tools = fake_is_failed(tmp.path(), &["nau-pod-plain-web.service"]);
        let check =
            check_pod_failed_units_with(tmp.path(), "plain", Some(&tmp.path().join("c")), &tools);
        assert!(matches!(check.status, CheckStatus::Ok), "{check:?}");
        assert!(check.hint.is_none(), "{check:?}");
    }

    #[test]
    fn pod_failed_units_surfaces_a_corrupt_units_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (cache, _) = seed_consumer_pod(tmp.path(), true);
        // Corrupt the scan's direct input: trusted data fails loudly
        // (services.rs read_units_file contract), surfaced as a doctor
        // error — never a silent skip.
        let units = tmp.path().join("work/generations/3/services/units.json");
        std::fs::write(&units, b"{ not json").unwrap();
        let tools = fake_is_failed(tmp.path(), &[]);
        let check = check_pod_failed_units_with(tmp.path(), "work", Some(&cache), &tools);
        assert!(matches!(check.status, CheckStatus::Error), "{check:?}");
        let hint = check.hint.expect("the corruption must be named");
        assert!(hint.contains("corrupt units file"), "{hint}");
    }
}
