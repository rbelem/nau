//! The image-layout audits + their report vocabulary (issue #326 PR 3).
//!
//! Three builder-context audits need the image in hand — the kernel
//! dm-verity config, the initrd module set, and the state-partition
//! split — so they live beside the image machinery they inspect, and
//! the root doctor calls them through its shim re-export. [`Check`]/
//! [`CheckStatus`] ride along: they are the audits' output vocabulary
//! (every pre-existing `crate::audit::Check` path keeps resolving
//! through the root doctor's re-export).

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};

use nau_infra::command::CommandRunner;

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
    pub fn ok(name: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Ok,
            hint: None,
        }
    }

    pub fn ok_at(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Ok,
            hint: Some(hint.into()),
        }
    }

    pub fn missing(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Missing,
            hint: Some(hint.into()),
        }
    }

    pub fn error(name: impl Into<String>, hint: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status: CheckStatus::Error,
            hint: Some(hint.into()),
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
pub fn find_kernel_config(payload_dir: &Path, kernel_version: &str) -> Option<PathBuf> {
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
pub fn module_name_for_symbol(symbol: &str) -> String {
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
pub fn required_initrd_modules(config_text: &str) -> Vec<String> {
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
pub fn member_is_module(member: &str, module: &str) -> bool {
    let base = member.rsplit('/').next().unwrap_or(member);
    let Some(rest) = base.strip_prefix(module) else {
        return false;
    };
    matches!(rest, ".ko" | ".ko.xz" | ".ko.zst" | ".ko.gz")
}

/// gzip magic (`\x1f\x8b`) — the most common initrd wrapper.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// zstd magic (`\x28\xb5\x2f\xfd`).
/// The zstd magic — exposed for the root doctor fixture assertions.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
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
pub fn read_initrd_members(
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
pub fn cpio_newc_members(data: &[u8]) -> miette::Result<Vec<String>> {
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
pub fn inspect_initrd_modules(
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
pub fn state_partition_check(
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
pub fn hint_of(check: &Check) -> &str {
    check.hint.as_deref().unwrap_or("ok")
}

/// Render an [`InitrdModuleAudit`] as a [`Check`]. Pure so the
/// Satisfied/Missing/NoConfig/Unreadable mapping is unit-testable without a
/// real initrd.
pub fn initrd_module_check_for(kernel_version: &str, outcome: &InitrdModuleAudit) -> Check {
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
