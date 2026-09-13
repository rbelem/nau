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
//! # What counts as "booted" (and *completed*)
//!
//! Deliberately **not** "QEMU started" and **not** "the kernel printed its
//! banner" — both are rejected by the ticket. Since issue #84, success
//! requires, in the captured serial console:
//!
//! 1. no kernel panic, **and**
//! 2. a userspace marker (`systemd[1]:`, a `Reached target …` line, `Started …`,
//!    or the `Welcome to …` banner), **and**
//! 3. the shuttle init handoff that this project's own initramfs prints after
//!    the verified root is mounted and `switch_root` is issued (required
//!    minimum, never sufficient alone), **and**
//! 4. a *completion* signal: a `Reached target …` line for a target that
//!    systemd only reaches when the boot transaction finished —
//!    `boot-complete.target` (`Boot Completion Check`, the synchronization
//!    point ADR-0024 §3 uses for try-boot assessment) on A/B images, or
//!    otherwise `multi-user.target` / `graphical.target`, i.e. a completed
//!    `default.target`.
//!
//! The exact markers live in [`COMPLETION_MARKERS`]/[`PANIC_MARKERS`] and can
//! be tightened per run with `--require <substring>`. Images that legitimately
//! never reach a completed target opt out with `--allow-no-completion`, which
//! restores the pre-#84 handoff-only gate.
//!
//! # Why "completion", and not the init handoff alone
//!
//! Through the 2026-09 QEMU session the default gate was the handoff marker
//! alone. That is a *liveness* assertion — "the initramfs handed off to
//! systemd" — and it blessed four boots that were actually broken: two that
//! rebooted into `emergency.target` seconds into userspace, one that stalled
//! at console-conf before `default.target`, and one whose
//! `systemd-bless-boot.service` unit failed after the handoff (issue #84, see
//! also #63). A `Type=oneshot` failure or a stall after the handoff leaves no
//! trace the handoff-only gate can see, and a timeout kill after the markers
//! were written passed for the same reason. Completion is the difference
//! try-boot assessment exists to detect, so the default must require it.
//!
//! # boot-complete.target vs multi-user.target
//!
//! An image built with an A/B disk and an `update_source` additionally emits
//! `boot-complete.target` and a health gate (ADR-0024 §3); it is the first
//! entry in [`COMPLETION_MARKERS`] and the strongest assertion. On an image
//! without the boot-assessment machinery, `multi-user.target` (or
//! `graphical.target`) is the completed `default.target` systemd renders as
//! `Reached target Multi-User System.` / `Reached target Graphical
//! Interface.`, so any image that finishes its boot transaction passes.
//!
//! **The boot-complete line is not proof that the try-boot machinery ran.**
//! It is reached whenever the health unit does not hard-fail, whether or not
//! boot counting was ever in effect: the factory UKI is installed counterless
//! (`{name}_{version}.efi`, no `+N-M` suffix — `src/image/boot.rs`), and
//! `systemd-bless-boot-generator` only pulls `systemd-bless-boot.service` into
//! the initial transaction when the *selected* entry carries counters. The
//! counters are written by `systemd-sysupdate` at install time. So on an image
//! that has never taken a real update, the target is reached with nothing to
//! mark good and nothing to count down.
//!
//! Asserting the machinery therefore requires the ESP, not the console: the
//! authoritative evidence is the UKI filename losing (or shedding) its `+N-M`
//! suffix. The serial line conflates "the target was reached" with "the
//! counter cleared", and those are different claims (see #63).
//!
//! # Timeout seam
//!
//! QEMU is a long-lived process: a booted system that never powers off runs
//! forever, and [`CommandRunner::run`] blocks until the child exits. The
//! harness therefore wraps QEMU in GNU coreutils `timeout` (see
//! [`wrapper_argv`]) so the seam stays a single blocking call and the bound
//! is visible in the exact argv the fake runner asserts. `timeout` exits
//! `124` when it had to kill the guest; that code alone is **not** a failure
//! — but a kill only passes once a completion signal was seen (or the run
//! opted out with `--allow-no-completion`). A boot killed before any
//! completion target fails regardless of how many earlier markers it wrote.

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

/// The line shuttle's own `/init` prints immediately before it hands PID 1 to
/// `systemd` (see `src/image/initramfs/init`, `main()` step 6).
///
/// This is the default "the image booted" proof. It appears in the serial log
/// only after the whole boot chain this project owns has succeeded: the
/// `proc`/`sys`/`dev` mounts, the module closure from `/modules.load`, PARTUUID
/// resolution without udev, `veritysetup open` on the dm-verity mapping, the
/// read-only mount of the verified root, and the `switch_root` handoff itself.
/// It is present in every image shuttle builds, unlike `boot-complete.target`,
/// which only an A/B image with an `update_source` emits.
pub const BOOT_HANDOFF_MARKER: &str = "SHUTTLE-INIT: switch-root";

/// The systemd line for the completion target an A/B image emits
/// (`src/image/boot.rs`, `Description=Boot Completion Check`). Reaching this
/// target clears the try-boot counters, so `--require "Reached target Boot
/// Completion Check"` is the strongest assertion available for an image that
/// carries it.
///
/// systemd names a target by its `Description=`, not its unit name, which is
/// why this string is the description. A unit test pins it to the emitted
/// unit so the two cannot drift.
pub const BOOT_COMPLETE_MARKER: &str = "Reached target Boot Completion Check";

/// The systemd line for `multi-user.target` — the rendered `Description=` of
/// the classic `default.target`. systemd prints it only when the boot
/// transaction reached the default target, which is what "completed" means
/// for an image without the boot-assessment machinery.
pub const MULTI_USER_MARKER: &str = "Reached target Multi-User System";

/// The systemd line for `graphical.target` — the other `default.target` an
/// image can link. Kept alongside [`MULTI_USER_MARKER`] so a graphical image
/// is not failed for completing.
pub const GRAPHICAL_MARKER: &str = "Reached target Graphical Interface";

/// The default gate's completion signals (issue #84): the boot must have
/// reached one of these targets, not merely handed off to systemd. A failed
/// oneshot, an `emergency.target` reboot, or a stall at a console prompt all
/// leave the log without any of them.
pub const COMPLETION_MARKERS: &[&str] =
    &[BOOT_COMPLETE_MARKER, MULTI_USER_MARKER, GRAPHICAL_MARKER];

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
    /// How many boots to run in sequence (default 1). Values > 1 boot a single
    /// sparse copy repeatedly so guest mutations persist across boots.
    pub runs: u32,
    /// Expected try-boot counter sequence, one element per boot, observed
    /// BEFORE each boot. Empty disables counter assertions.
    pub expect_counters: Vec<ExpectedCounters>,
    /// Opt-out of the completion gate (issue #84): a boot that reached the
    /// init handoff passes without a completed target. For images that
    /// legitimately never reach one.
    pub allow_no_completion: bool,
}

/// One expected try-boot observation, parsed from `--expect-counter-seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedCounters {
    /// Expected `tries_left` before the boot.
    pub tries_left: u32,
    /// Expected `tries_done`, or `None` when the spec did not pin it.
    pub tries_done: Option<u32>,
}

/// Parse a `--expect-counter-seq` spec: `"3-0,2-1"` pins both halves of each
/// observation, while a bare `"3,2,1,0"` leaves `tries_done` unchecked.
pub fn parse_expect_counters(spec: &str) -> miette::Result<Vec<ExpectedCounters>> {
    spec.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (left, done) = match part.split_once('-') {
                Some((left, done)) => (left, Some(done)),
                None => (part, None),
            };
            let tries_left = left.trim().parse::<u32>().map_err(|_| {
                miette::miette!(
                    "invalid --expect-counter-seq entry '{part}': '{left}' is not a number"
                )
            })?;
            let tries_done = match done {
                Some(d) => Some(d.trim().parse::<u32>().map_err(|_| {
                    miette::miette!(
                        "invalid --expect-counter-seq entry '{part}': '{d}' is not a number"
                    )
                })?),
                None => None,
            };
            Ok(ExpectedCounters {
                tries_left,
                tries_done,
            })
        })
        .collect()
}

// ── Boot sequence (issue #77) ───────────────────────────────────────────

/// One boot's auditable record: what the ESP held *before* it, and what the
/// serial log proved *after*.
#[derive(Clone, Debug)]
pub struct BootRecord {
    /// 1-based boot index within the sequence.
    pub index: u32,
    /// The serial log path for this boot.
    pub log: PathBuf,
    /// The ESP listing captured before this boot.
    pub esp_listing: PathBuf,
    /// The raw ESP directory entries.
    pub esp_entries: Vec<String>,
    /// The first counter-bearing UKI in the sorted listing, if any.
    pub uki: Option<String>,
    /// The counters observed BEFORE this boot.
    pub counters: Option<crate::esp::TryCounters>,
    /// The serial-log verdict for this boot.
    pub outcome: Outcome,
}

/// Why a boot sequence did not pass (distinct from an individual boot's
/// [`Failure`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SequenceFailure {
    /// `--expect-counter-seq` was set but no ESP entry carried counters.
    NoCountedUki,
    /// The observed counters before boot `index` did not match the expected
    /// element.
    CountersMismatch {
        index: u32,
        expected: ExpectedCounters,
        observed: crate::esp::TryCounters,
    },
    /// Counting never engaged: two consecutive observations were equal.
    Stuck { index: u32 },
    /// The ESP could not be inspected (missing tools or no `esp` partition).
    EspUnavailable(String),
}

impl SequenceFailure {
    /// Stable machine-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            SequenceFailure::NoCountedUki => "no-counted-uki",
            SequenceFailure::CountersMismatch { .. } => "counters-mismatch",
            SequenceFailure::Stuck { .. } => "counters-stuck",
            SequenceFailure::EspUnavailable(_) => "esp-unavailable",
        }
    }

    /// A precise, one-line explanation.
    pub fn message(&self) -> String {
        match self {
            SequenceFailure::NoCountedUki => {
                "expected a try-boot counter sequence but no UKI on the ESP carries a \
                 '+N-M' counter"
                    .to_string()
            }
            SequenceFailure::CountersMismatch {
                index,
                expected,
                observed,
            } => {
                let want = match expected.tries_done {
                    Some(done) => format!("+{}-{}", expected.tries_left, done),
                    None => format!("+{}", expected.tries_left),
                };
                format!(
                    "boot {index}: ESP held +{}-{} before the boot, expected {want}",
                    observed.tries_left, observed.tries_done
                )
            }
            SequenceFailure::Stuck { index } => format!(
                "boot {index}: try-boot counters did not change from the previous boot — \
                 counting never engaged"
            ),
            SequenceFailure::EspUnavailable(message) => {
                format!("cannot inspect the ESP for try-boot counters: {message}")
            }
        }
    }
}

/// The full result of a boot sequence: every boot's record, the first
/// sequence-level failure (if any), the resolved paths, and the image booted.
#[derive(Clone, Debug)]
pub struct SequenceOutcome {
    pub records: Vec<BootRecord>,
    pub failure: Option<SequenceFailure>,
    pub run_root: Option<PathBuf>,
    pub image: PathBuf,
}

impl SequenceOutcome {
    /// True when every boot passed and no sequence assertion failed.
    pub fn passed(&self) -> bool {
        self.failure.is_none() && self.records.iter().all(|r| r.outcome.passed())
    }

    /// One-line summary covering both axes.
    pub fn message(&self) -> String {
        if let Some(failure) = &self.failure {
            return failure.message();
        }
        let boots = self.records.len();
        for record in &self.records {
            if !record.outcome.passed() {
                return format!("boot {}: {}", record.index, record.outcome.message());
            }
        }
        format!("{boots} boot(s) passed")
    }
}

fn first_counted_uki(entries: &[String]) -> Option<(String, crate::esp::TryCounters)> {
    entries.iter().find_map(|name| {
        let parsed = crate::esp::parse_uki_name(name);
        parsed.counters.map(|counters| (name.clone(), counters))
    })
}

/// Write the per-boot ESP listing, ignoring write failure (the listing is
/// advisory evidence; a missing tool or a read-only run root must not mask a
/// boot verdict).
fn write_listing(path: &Path, entries: &[String]) {
    let body = if entries.is_empty() {
        String::new()
    } else {
        let mut body = entries.join("\n");
        body.push('\n');
        body
    };
    let _ = std::fs::write(path, body);
}

/// Run a whole boot sequence through the injected [`CommandRunner`].
///
/// `runs == 1` boots the image **in place** (today's behaviour, no
/// regression) and records the ESP into `<log>.esp.txt`. `runs > 1` makes ONE
/// sparse copy at `<log>.d/img` and boots that same copy every time, so guest
/// mutations persist; per-boot logs and listings land under `<log>.d/`, and a
/// `sequence.json` summarises every boot. `-snapshot` is never used — it would
/// discard the decrements and make the test self-deceiving.
///
/// The ESP is inspected BEFORE each boot, so a `+3-0` start over four boots
/// observes `3-0, 2-1, 1-2, 0-3`.
pub fn run_sequence(
    runner: &dyn CommandRunner,
    test: &BootTest,
) -> miette::Result<SequenceOutcome> {
    let runs = test.runs.max(1);
    let expect = &test.expect_counters;

    let run_root = (runs > 1).then(|| {
        let mut name = test.log.as_os_str().to_owned();
        name.push(".d");
        PathBuf::from(name)
    });
    if let Some(root) = &run_root {
        std::fs::create_dir_all(root)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create run root {}", root.display()))?;
    }

    let boot_image = match &run_root {
        Some(root) => {
            let copy = root.join("img");
            sparse_copy(&test.image, &copy).wrap_err_with(|| {
                format!(
                    "failed to make the per-run image copy {} -> {}",
                    test.image.display(),
                    copy.display()
                )
            })?;
            copy
        }
        None => test.image.clone(),
    };

    // ESP offset is a property of the image; recover it once, before the
    // first boot. A failure is hard when counting is asserted or the sequence
    // boots a copy (mutations under test), and a soft warning otherwise so a
    // plain single boot on a host without mtools still works.
    let hard = !expect.is_empty() || runs > 1;
    let esp_offset = match crate::esp::esp_partition_offset(runner, &boot_image) {
        Ok(offset) => Some(offset),
        Err(err) => {
            if hard {
                return Ok(SequenceOutcome {
                    records: Vec::new(),
                    failure: Some(SequenceFailure::EspUnavailable(format!("{err}"))),
                    run_root,
                    image: boot_image,
                });
            }
            crate::output::warn(format!(
                "ESP inspection unavailable ({err}); boot counting was not observed"
            ));
            None
        }
    };

    let mut records: Vec<BootRecord> = Vec::new();
    let mut failure: Option<SequenceFailure> = None;

    for i in 1..=runs {
        let (log, listing) = match &run_root {
            Some(root) => (
                root.join(format!("boot-{i}.serial.log")),
                root.join(format!("boot-{i}.esp.txt")),
            ),
            None => {
                let mut listing = test.log.as_os_str().to_owned();
                listing.push(".esp.txt");
                (test.log.clone(), PathBuf::from(listing))
            }
        };

        let mut esp_entries = Vec::new();
        let mut uki = None;
        let mut counters = None;
        if let Some(offset) = esp_offset {
            match crate::esp::list_ukis(runner, &boot_image, offset) {
                Ok(entries) => {
                    esp_entries = entries;
                    if let Some((name, observed)) = first_counted_uki(&esp_entries) {
                        uki = Some(name);
                        counters = Some(observed);
                    }
                }
                Err(err) => {
                    if failure.is_none() {
                        failure = Some(SequenceFailure::EspUnavailable(format!("{err}")));
                    }
                    write_listing(&listing, &[]);
                    let boot_test = BootTest {
                        image: boot_image.clone(),
                        log: log.clone(),
                        ..test.clone()
                    };
                    let outcome = run_boot(runner, &boot_test)?;
                    records.push(BootRecord {
                        index: i,
                        log,
                        esp_listing: listing,
                        esp_entries,
                        uki,
                        counters,
                        outcome,
                    });
                    break;
                }
            }
        }
        write_listing(&listing, &esp_entries);

        // Assert against the observation BEFORE boot i.
        if failure.is_none() && !expect.is_empty() {
            let expected = expect.get((i - 1) as usize).copied();
            match (counters, expected) {
                (None, _) => failure = Some(SequenceFailure::NoCountedUki),
                (Some(_), None) => {}
                (Some(observed), Some(want)) => {
                    let left_ok = observed.tries_left == want.tries_left;
                    let done_ok = want.tries_done.is_none_or(|d| observed.tries_done == d);
                    if !left_ok || !done_ok {
                        failure = Some(SequenceFailure::CountersMismatch {
                            index: i,
                            expected: want,
                            observed,
                        });
                    } else if let Some(previous) = records.last() {
                        if previous.counters == Some(observed) {
                            failure = Some(SequenceFailure::Stuck { index: i });
                        }
                    }
                }
            }
        }

        let boot_test = BootTest {
            image: boot_image.clone(),
            log: log.clone(),
            ..test.clone()
        };
        let outcome = run_boot(runner, &boot_test)?;
        records.push(BootRecord {
            index: i,
            log,
            esp_listing: listing,
            esp_entries,
            uki,
            counters,
            outcome,
        });
    }

    if let Some(root) = &run_root {
        write_sequence_json(root, &records, failure.as_ref(), &boot_image);
    }

    Ok(SequenceOutcome {
        records,
        failure,
        run_root,
        image: boot_image,
    })
}

fn write_sequence_json(
    root: &Path,
    records: &[BootRecord],
    failure: Option<&SequenceFailure>,
    image: &Path,
) {
    let boots: Vec<serde_json::Value> = records
        .iter()
        .map(|record| {
            serde_json::json!({
                "index": record.index,
                "log": record.log.display().to_string(),
                "esp_listing": record.esp_listing.display().to_string(),
                "esp_entries": record.esp_entries,
                "uki": record.uki,
                "counters": record.counters.map(|c| serde_json::json!({
                    "tries_left": c.tries_left,
                    "tries_done": c.tries_done,
                })),
                "passed": record.outcome.passed(),
                "message": record.outcome.message(),
            })
        })
        .collect();
    let report = serde_json::json!({
        "image": image.display().to_string(),
        "boots": boots,
        "failure": failure.map(|f| f.label()),
        "message": failure.map(|f| f.message()),
    });
    let path = root.join("sequence.json");
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string()),
    );
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
    /// The shuttle init handoff line, if any.
    pub handoff: Option<String>,
    /// First boot-complete line, if any (only an A/B image emits it).
    pub boot_complete: Option<String>,
    /// First line matching a [`COMPLETION_MARKERS`] entry, if any — the
    /// default gate's "the boot completed" signal.
    pub completion: Option<String>,
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

fn is_boot_complete_line(line: &str) -> bool {
    line.contains(BOOT_COMPLETE_MARKER)
}

fn is_completion_line(line: &str) -> bool {
    COMPLETION_MARKERS
        .iter()
        .any(|marker| line.contains(marker))
}

fn is_handoff_line(line: &str) -> bool {
    line.contains(BOOT_HANDOFF_MARKER)
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
    let boot_complete = text
        .lines()
        .find(|line| is_boot_complete_line(line))
        .map(|line| line.trim().to_string());
    let completion = text
        .lines()
        .find(|line| is_completion_line(line))
        .map(|line| line.trim().to_string());
    let handoff = text
        .lines()
        .find(|line| is_handoff_line(line))
        .map(|line| line.trim().to_string());
    Evidence {
        userspace: !markers.is_empty(),
        target,
        service,
        handoff,
        boot_complete,
        completion,
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
    /// Userspace was reached but the shuttle init handoff never appeared.
    NoHandoff,
    /// The handoff happened but no completion target was reached (and the
    /// run did not pass `--allow-no-completion`): a stall, a failed oneshot,
    /// or an `emergency.target` reboot after the handoff (issue #84).
    NoCompletion,
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
            Failure::NoHandoff => "no-handoff",
            Failure::NoCompletion => "no-completion",
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
                .completion
                .as_deref()
                .or(self.evidence.handoff.as_deref())
                .or(self.evidence.target.as_deref())
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
            Failure::NoHandoff => format!(
                "userspace reached but no shuttle init handoff ('{BOOT_HANDOFF_MARKER}') in the \
                 serial log — the image did not boot through shuttle's own initramfs, or the \
                 boot never got as far as the verify+switch_root handoff; raise --timeout or \
                 inspect the serial evidence"
            ),
            Failure::NoCompletion => format!(
                "boot handed off to systemd but never completed: no completion target line \
                 ('{BOOT_COMPLETE_MARKER}', '{MULTI_USER_MARKER}', or '{GRAPHICAL_MARKER}') in \
                 the serial log — the boot stalled, a unit failed, or it rebooted into \
                 emergency/rescue after the handoff (possibly killed by the --timeout bound \
                 first). Pass --allow-no-completion only for images that legitimately never \
                 reach a completed target"
            ),
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
/// reported when no userspace marker appeared (otherwise the run is judged by
/// the completion gate below). Since issue #84 the boot must have reached a
/// completion target ([`COMPLETION_MARKERS`]) after the handoff; the
/// `allow_no_completion` opt-out restores the handoff-only gate.
fn classify(
    text: &str,
    evidence: &Evidence,
    code: i32,
    stderr: &str,
    required: &[String],
    allow_no_completion: bool,
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
    if evidence.handoff.is_none() {
        return Some(Failure::NoHandoff);
    }
    // Completion gate (issue #84). The handoff proves the initramfs worked;
    // only a completed target proves the boot did. A timeout kill (124) after
    // the markers were written fails here too — the markers are liveness, not
    // completion.
    if evidence.completion.is_none() && !allow_no_completion {
        return Some(Failure::NoCompletion);
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
    let failure = classify(
        &text,
        &evidence,
        out.code,
        &out.stderr,
        &test.required,
        test.allow_no_completion,
    );
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

/// Copy `src` to `dst`, preserving sparseness.
///
/// Deliberately NOT `cp --sparse=always`: that flag is GNU coreutils-only, and
/// the `cp` on this project's own devbox PATH is BusyBox, which rejects it
/// ("unrecognized option: sparse=always"). Shelling out would therefore fail on
/// the very host the harness runs on — and the failure would be silent, because
/// a failed `cp` surfaces much later as a confusing "cannot open .../img".
///
/// Doing it in-process also avoids depending on any particular `cp`
/// implementation. A 12 GiB virtual / ~1.2 GiB real image would otherwise
/// expand to its full apparent size; `SEEK_DATA`/`SEEK_HOLE` copies only the
/// data extents, leaving holes as holes.
pub fn sparse_copy(src: &Path, dst: &Path) -> miette::Result<()> {
    use std::io::Write as _;

    let input = std::fs::File::open(src)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to open {}", src.display()))?;
    let mut output = std::fs::File::create(dst)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", dst.display()))?;

    let len = input
        .metadata()
        .into_diagnostic()
        .wrap_err("failed to stat the source image")?
        .len();
    output
        .set_len(len)
        .into_diagnostic()
        .wrap_err("failed to size the destination image")?;

    let mut pos: u64 = 0;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    while pos < len {
        let Some(data) = seek_extent(&input, pos, libc::SEEK_DATA) else {
            break; // no more data: the remainder is a hole
        };
        if data >= len {
            break;
        }
        let hole = seek_extent(&input, data, libc::SEEK_HOLE).unwrap_or(len);
        copy_extent(&input, &output, data, hole, &mut buf)?;
        pos = hole;
    }
    output
        .flush()
        .into_diagnostic()
        .wrap_err("failed to flush the image copy")?;
    Ok(())
}

/// `lseek(fd, offset, whence)` for `SEEK_DATA`/`SEEK_HOLE`, returning `None`
/// when there is nothing further in that direction (or the filesystem does not
/// support the hint, in which case `ENXIO` is the documented answer).
fn seek_extent(file: &std::fs::File, offset: u64, whence: i32) -> Option<u64> {
    use std::os::fd::AsRawFd;
    // SAFETY: `lseek` on a valid owned fd with a plain integer offset.
    let rc = unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, whence) };
    (rc >= 0).then_some(rc as u64)
}

/// Copy bytes `[start, end)` from `input` into `output` at the same offsets.
fn copy_extent(
    input: &std::fs::File,
    output: &std::fs::File,
    start: u64,
    end: u64,
    buf: &mut [u8],
) -> miette::Result<()> {
    use std::os::unix::fs::FileExt;

    let mut cursor = start;
    while cursor < end {
        let want = std::cmp::min(buf.len() as u64, end - cursor) as usize;
        let read = input
            .read_at(&mut buf[..want], cursor)
            .into_diagnostic()
            .wrap_err("failed to read the source image")?;
        if read == 0 {
            break;
        }
        output
            .write_all_at(&buf[..read], cursor)
            .into_diagnostic()
            .wrap_err("failed to write the image copy")?;
        cursor += read as u64;
    }
    Ok(())
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
SHUTTLE-INIT: start\n\
SHUTTLE-INIT: modules-loaded\n\
SHUTTLE-INIT: root=/dev/vda2 hash=/dev/vda3\n\
SHUTTLE-INIT: verity-open\n\
SHUTTLE-INIT: mounted\n\
SHUTTLE-INIT: switch-root\n\
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
        // The multi-boot path makes a real in-process copy of `image`, so the
        // fixture must exist on disk rather than being a bare path.
        let image = tmp.join("image_1.0.0_amd64.img");
        std::fs::write(&image, b"fixture").unwrap();
        BootTest {
            image,
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
            runs: 1,
            expect_counters: Vec::new(),
            allow_no_completion: false,
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

    /// The strict marker is systemd's rendering of the target's
    /// `Description=`, so it must track the unit shuttle actually emits. Read
    /// the emitted unit text and assert the description is the one the marker
    /// expects; if either side moves, this fails rather than silently never
    /// matching.
    ///
    /// This pins the *string*, not the machinery: reaching the target does not
    /// by itself prove boot counting was in effect. See the module docs.
    #[test]
    fn boot_complete_marker_matches_the_emitted_target_description() {
        let unit = crate::image::boot_complete_target_content();
        let description = unit
            .lines()
            .find_map(|l| l.strip_prefix("Description="))
            .expect("emitted boot-complete.target must declare a Description");
        assert_eq!(
            BOOT_COMPLETE_MARKER,
            format!("Reached target {description}"),
            "systemd renders a target as 'Reached target <Description>.'"
        );
    }

    #[test]
    fn analyze_userspace_and_handoff_pass() {
        let ev = analyze_log(PASS_LOG);
        assert!(ev.userspace);
        assert!(ev.target.is_some());
        assert_eq!(ev.handoff.as_deref(), Some("SHUTTLE-INIT: switch-root"));
        assert!(ev.panic.is_none());
    }

    /// Excerpt of a *real* serial console capture: the host's NixOS kernel +
    /// initrd booted under QEMU/KVM on 2026-09-11 (see the module docs). This
    /// pins the parser to genuine systemd output, not just a synthetic
    /// fixture. Only the lines the parser keys on are kept.
    ///
    /// This is an **initrd** boot, so it never runs shuttle's `/init` and
    /// prints no handoff marker. It proves userspace is parsed; the default
    /// gate is covered by [`PASS_LOG`] and [`CONSOLE_CONF_LOG`].
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
    fn analyze_parses_real_boot_excerpt_userspace() {
        let ev = analyze_log(REAL_BOOT_EXCERPT);
        assert!(ev.userspace, "real systemd output must count as userspace");
        assert!(ev.panic.is_none());
        assert_eq!(
            ev.target.as_deref(),
            Some("[    2.085533] systemd[1]: Reached target Slice Units.")
        );
        assert!(
            ev.handoff.is_none(),
            "an initrd excerpt never runs shuttle's /init"
        );
    }

    #[test]
    fn run_boot_without_handoff_fails() {
        // Userspace is up, but this boot did not go through shuttle's own
        // initramfs, so the default gate must fail.
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: REAL_BOOT_EXCERPT.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(out.failure, Some(Failure::NoHandoff));
    }

    /// A *real* console-conf boot: the pc-rootfs image built from pc-kernel
    /// rev 3654 booted under QEMU/KVM on 2026-09-11, reaching the interactive
    /// console prompt. Reproduced verbatim (minus ANSI escapes) because it is
    /// the regression this harness exists for: userspace is up, but a `quiet`
    /// boot that parks on `Press enter to configure.` prints no generic
    /// service line.
    const CONSOLE_CONF_LOG: &str = "\
BdsDxe: starting Boot0001 \"UEFI Misc Device\"\n\
SHUTTLE-INIT: start\n\
SHUTTLE-INIT: modules-loaded\n\
SHUTTLE-INIT: root=/dev/vda2 hash=/dev/vda3\n\
SHUTTLE-INIT: verity-open\n\
[    0.545547] EXT4-fs (dm-0): write access unavailable, skipping orphan cleanup\n\
SHUTTLE-INIT: mounted\n\
SHUTTLE-INIT: switch-root\n\
[    0.786046] systemd[1]: network-manager-networkmanager.service: Two services allocated for the same bus name fi.w1.wpa_supplicant1, refusing operation.\n\
[FAILED] Failed to start Network Time Synchronization.\n\
[FAILED] Failed to start Network Time Synchronization.\n\
/usr/share/subiquity/console-conf-wrapper: line 40: snap: command not found\n\
Press enter to configure.\n";

    #[test]
    fn console_conf_stall_fails_by_default() {
        // The regression from issue #84: userspace is up and shuttle's own
        // /init handed off, but the boot parks on console-conf and never
        // reaches default.target. The handoff-only gate passed it; the
        // default completion gate must fail it.
        let ev = analyze_log(CONSOLE_CONF_LOG);
        assert!(ev.userspace, "console-conf proves userspace");
        assert!(ev.panic.is_none());
        assert_eq!(ev.handoff.as_deref(), Some("SHUTTLE-INIT: switch-root"));
        assert!(
            ev.completion.is_none(),
            "a console-conf stall never reaches a completed target"
        );

        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: CONSOLE_CONF_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(Failure::NoCompletion));
        assert!(
            out.message().contains("never completed"),
            "{}",
            out.message()
        );
    }

    #[test]
    fn allow_no_completion_restores_the_handoff_gate() {
        // The explicit opt-out: an image that legitimately parks before any
        // completed target passes again, handoff required as the minimum.
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.allow_no_completion = true;
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: CONSOLE_CONF_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert!(out.message().contains("switch-root"), "{}", out.message());
    }

    /// A *real* failure shape from issue #84: a zeroed state partition sent
    /// userspace into `local-fs.target` -> `emergency.target` ->
    /// `OnFailure=reboot.target` about 2s after the handoff. QEMU `-no-reboot`
    /// exits 0 on the guest reboot. Userspace and handoff markers are all
    /// present — which is exactly why the old gate passed it.
    const EMERGENCY_REBOOT_LOG: &str = "\
SHUTTLE-INIT: switch-root\n\
[    1.512003] systemd[1]: systemd 255 running in system mode.\n\
[    2.113744] systemd[1]: Reached target Local File Systems.\n\
[    2.204112] systemd[1]: Reached target Emergency Mode.\n\
[    2.310884] systemd[1]: Starting Reboot...\n\
[    2.402551] systemd[1]: Reached target Reboot.\n\
[    2.512290] reboot: Restarting system\n";

    #[test]
    fn emergency_reboot_after_handoff_fails_by_default() {
        // Issue #84 acceptance: the handoff is liveness, not completion. The
        // machine rebooted into emergency ~2s into userspace; the log has
        // userspace + handoff markers and a clean exit, but no completed
        // target, so the default gate must fail it.
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 0,
            stderr: String::new(),
            log: EMERGENCY_REBOOT_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(Failure::NoCompletion));
    }

    #[test]
    fn timeout_after_markers_fails_without_completion() {
        // Issue #84 acceptance: a timeout kill (exit 124) after the userspace
        // markers were written used to pass; without a completion signal it
        // must fail — the markers say systemd ran, not that boot finished.
        let log = "\
SHUTTLE-INIT: switch-root\n\
[    2.100000] systemd[1]: systemd 255 running in system mode.\n\
[    3.200000] systemd[1]: Reached target Basic System.\n\
[    4.900000] systemd[1]: Started some-long-running-unit.service.\n";
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: log.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(Failure::NoCompletion));
    }

    #[test]
    fn boot_complete_target_passes_by_default() {
        // Issue #84 acceptance: an A/B boot that reaches
        // boot-complete.target passes with no flags at all — the completion
        // gate is the default, not an opt-in.
        let log = format!(
            "\
SHUTTLE-INIT: switch-root\n\
[    2.100000] systemd[1]: systemd 255 running in system mode.\n\
[    3.200000] systemd[1]: Reached target Basic System.\n\
[    4.400000] systemd[1]: {BOOT_COMPLETE_MARKER}.\n"
        );
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log,
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(
            out.evidence.completion.as_deref(),
            Some("[    4.400000] systemd[1]: Reached target Boot Completion Check.")
        );
    }

    #[test]
    fn multi_user_target_passes_without_boot_assessment() {
        // Issue #84 acceptance: an image without the boot-assessment
        // machinery (no boot-complete.target) still passes when the boot
        // transaction completes — multi-user.target is a completed
        // default.target. [`PASS_LOG`] reaches Multi-User System and carries
        // no Boot Completion Check line.
        let ev = analyze_log(PASS_LOG);
        assert_eq!(
            ev.boot_complete, None,
            "fixture must exercise the no-boot-assessment path"
        );
        assert!(ev.completion.is_some());
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: PASS_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert!(
            out.message().contains("Multi-User System"),
            "{}",
            out.message()
        );
    }

    #[test]
    fn strict_require_boot_complete_is_opt_in() {
        // An A/B image that emits the completion target: --require tightens
        // the gate beyond the default to the line the try-boot machinery
        // waits on.
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.required = vec![BOOT_COMPLETE_MARKER.to_string()];

        // A multi-user completion alone does not satisfy the stricter
        // --require assertion.
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: PASS_LOG.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(
            out.failure,
            Some(Failure::MissingRequirement(
                BOOT_COMPLETE_MARKER.to_string()
            ))
        );

        // With it, the boot passes and the target line is reported.
        let log = "\
SHUTTLE-INIT: switch-root\n\
[    0.786046] systemd[1]: systemd 255 running in system mode.\n\
[    4.400000] systemd[1]: Reached target Boot Completion Check.\n";
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: log.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(
            out.evidence.boot_complete.as_deref(),
            Some("[    4.400000] systemd[1]: Reached target Boot Completion Check.")
        );
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
        assert!(ev.handoff.is_none());
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
    fn run_boot_no_handoff_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        // Userspace marker present, but no shuttle init handoff.
        let log = "[    2.000000] systemd[1]: systemd 255 running in system mode.\n";
        let runner = FakeRunner::new(vec![Script {
            code: 124,
            stderr: String::new(),
            log: log.to_string(),
        }]);
        let out = run_boot(&runner, &test).unwrap();
        assert_eq!(out.failure, Some(Failure::NoHandoff));
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

    // ── run_sequence (issue #77) ──

    use crate::esp::{parse_dir_listing, TryCounters};

    /// The `sfdisk -J` output the fake runner answers with in sequence tests.
    const SFDISK_STDOUT: &str = r#"{"partitiontable":{"partitions":[
        {"start":2048,"name":"esp"},{"start":6144,"name":"root"}]}}"#;

    /// A fake runner whose `mdir` answers are popped in order and whose QEMU
    /// serial writes the pass log. `sfdisk`/`cp` calls are answered trivially.
    struct SeqRunner {
        calls: Mutex<Vec<Vec<String>>>,
        listings: Mutex<VecDeque<Vec<String>>>,
        esp_ok: bool,
    }

    impl SeqRunner {
        fn new(listings: Vec<Vec<String>>, esp_ok: bool) -> SeqRunner {
            SeqRunner {
                calls: Mutex::new(Vec::new()),
                listings: Mutex::new(listings.into()),
                esp_ok,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for SeqRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let program = argv.first().map(String::as_str).unwrap_or("");
            match program {
                "sfdisk" if self.esp_ok => Ok(RunnerOutput {
                    code: 0,
                    stdout: SFDISK_STDOUT.as_bytes().to_vec(),
                    stderr: String::new(),
                }),
                "sfdisk" => Ok(RunnerOutput {
                    code: 1,
                    stdout: Vec::new(),
                    stderr: "sfdisk: not found".to_string(),
                }),
                "mdir" => {
                    let names = self
                        .listings
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_default();
                    Ok(RunnerOutput {
                        code: 0,
                        stdout: names.join("\n").into_bytes(),
                        stderr: String::new(),
                    })
                }
                _ => {
                    if let Some(serial) = arg_after(argv, "-serial") {
                        if let Some(path) = serial.strip_prefix("file:") {
                            std::fs::write(path, PASS_LOG).unwrap();
                        }
                    }
                    Ok(RunnerOutput {
                        code: 124,
                        stdout: Vec::new(),
                        stderr: String::new(),
                    })
                }
            }
        }
    }

    fn counted(name: &str) -> String {
        name.to_string()
    }

    #[test]
    fn sequence_multi_boot_argv_uses_copy_with_per_boot_logs() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        let runner = SeqRunner::new(
            vec![
                vec![counted("foo_1.0+3-0.efi")],
                vec![counted("foo_1.0+2-1.efi")],
            ],
            true,
        );
        let out = run_sequence(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(out.records.len(), 2);
        assert_eq!(
            out.run_root,
            Some(PathBuf::from(format!("{}.d", test.log.display())))
        );

        let calls = runner.calls();
        // The copy is done in-process (never `cp --sparse=always`, which is
        // GNU-only and broken under the BusyBox `cp` on this project's devbox
        // PATH), so there is no copy argv to assert. Assert the effect instead:
        // the copy exists on disk before the first boot.
        assert!(
            !calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("cp")),
            "the copy must not shell out to cp: {calls:?}"
        );
        let first_qemu = calls
            .iter()
            .position(|c| c.iter().any(|a| a == "-serial"))
            .expect("a QEMU boot must be issued");
        let root = out.run_root.as_ref().unwrap();
        assert!(
            root.join("img").is_file(),
            "the per-run copy must exist before the first boot"
        );

        // Both boots target the copy, never the source image, and each has
        // its own serial log.
        let serials: Vec<&str> = calls
            .iter()
            .filter_map(|c| arg_after(c, "-serial"))
            .collect();
        assert_eq!(serials.len(), 2);
        assert!(serials[0].contains(&root.join("boot-1.serial.log").display().to_string()));
        assert!(serials[1].contains(&root.join("boot-2.serial.log").display().to_string()));
        let _ = first_qemu;
        for call in calls.iter().filter(|c| c.iter().any(|a| a == "-serial")) {
            let drive = call
                .iter()
                .find(|a| a.starts_with("file=") && a.ends_with(",format=raw,if=virtio"))
                .unwrap();
            // The booted disk is the copy (the source image path is a prefix
            // of the copy path, so require the copy path exactly).
            assert!(
                drive.contains(&root.join("img").display().to_string()),
                "boot must use the copy: {drive}"
            );
        }
        assert!(root.join("sequence.json").is_file());
    }

    #[test]
    fn sequence_no_snapshot_in_boot_argv() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        let runner = SeqRunner::new(
            vec![vec!["x+2-0.efi".into()], vec!["x+1-1.efi".into()]],
            true,
        );
        run_sequence(&runner, &test).unwrap();
        for call in runner.calls() {
            assert!(
                !call.iter().any(|a| a.contains("snapshot")),
                "boot argv must never use -snapshot: {call:?}"
            );
        }
    }

    #[test]
    fn sequence_matching_counters_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 4;
        test.expect_counters = parse_expect_counters("3-0,2-1,1-2,0-3").unwrap();
        let runner = SeqRunner::new(
            vec![
                vec!["foo_1.0+3-0.efi".into()],
                vec!["foo_1.0+2-1.efi".into()],
                vec!["foo_1.0+1-2.efi".into()],
                vec!["foo_1.0+0-3.efi".into()],
            ],
            true,
        );
        let out = run_sequence(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert!(out.failure.is_none());
        assert_eq!(
            out.records[0].counters,
            Some(TryCounters {
                tries_left: 3,
                tries_done: 0
            })
        );
        assert_eq!(
            out.records[3].counters,
            Some(TryCounters {
                tries_left: 0,
                tries_done: 3
            })
        );
    }

    #[test]
    fn sequence_mismatch_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        test.expect_counters = parse_expect_counters("3-0,2-1").unwrap();
        let runner = SeqRunner::new(
            vec![vec!["foo+3-0.efi".into()], vec!["foo+3-0.efi".into()]],
            true,
        );
        let out = run_sequence(&runner, &test).unwrap();
        assert!(!out.passed());
        match out.failure {
            Some(SequenceFailure::CountersMismatch { index, .. }) => assert_eq!(index, 2),
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn sparse_copy_preserves_holes_and_content() {
        // Regression guard for a defect the fake runner could not catch: the
        // per-run copy used to shell out to `cp --sparse=always`, which is
        // GNU-only. The `cp` on this project's devbox PATH is BusyBox, which
        // rejects that flag, so the copy silently failed and the run died much
        // later with a confusing "cannot open .../img" from sfdisk. This must
        // hold with NO external `cp` involved.
        use std::io::{Read, Seek, SeekFrom, Write};

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.img");
        let dst = tmp.path().join("dst.img");

        // A sparse file: data, a large hole, then more data.
        const HOLE: u64 = 64 * 1024 * 1024;
        {
            let mut f = std::fs::File::create(&src).unwrap();
            f.write_all(b"head").unwrap();
            f.seek(SeekFrom::Start(HOLE)).unwrap();
            f.write_all(b"tail").unwrap();
            f.flush().unwrap();
        }

        sparse_copy(&src, &dst).unwrap();

        // Content matches, including the zeros inside the hole.
        let mut a = std::fs::File::open(&src).unwrap();
        let mut b = std::fs::File::open(&dst).unwrap();
        let mut av = Vec::new();
        let mut bv = Vec::new();
        a.read_to_end(&mut av).unwrap();
        b.read_to_end(&mut bv).unwrap();
        assert_eq!(av, bv, "copy must be byte-identical, holes included");
        assert_eq!(av.len() as u64, HOLE + 4);

        // And the destination is actually sparse: its allocated size is a
        // fraction of its apparent length. Without this the copy would expand a
        // 12 GiB virtual image to its full size on disk.
        let st = std::os::unix::fs::MetadataExt::blocks(&std::fs::metadata(&dst).unwrap());
        let allocated = st * 512;
        assert!(
            allocated < HOLE / 2,
            "destination should stay sparse: {allocated} bytes allocated for {} apparent",
            av.len()
        );
    }

    #[test]
    fn sequence_stuck_counters_fail_even_when_expected() {
        // Both boots observe +3-0 (counting never engaged). If the operator
        // (wrongly) expects 3-0,3-0, the equality must still fail: a healthy
        // boot count strictly decrements.
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        test.expect_counters = parse_expect_counters("3-0,3-0").unwrap();
        let runner = SeqRunner::new(
            vec![vec!["foo+3-0.efi".into()], vec!["foo+3-0.efi".into()]],
            true,
        );
        let out = run_sequence(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(SequenceFailure::Stuck { index: 2 }));
    }

    #[test]
    fn sequence_missing_counted_uki_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        test.expect_counters = parse_expect_counters("3-0,2-1").unwrap();
        let runner = SeqRunner::new(vec![vec!["foo.efi".into()], vec!["foo.efi".into()]], true);
        let out = run_sequence(&runner, &test).unwrap();
        assert!(!out.passed());
        assert_eq!(out.failure, Some(SequenceFailure::NoCountedUki));
    }

    #[test]
    fn sequence_esp_unavailable_hard_when_counting_expected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut test = sample_test(tmp.path(), Accel::Kvm, true);
        test.runs = 2;
        test.expect_counters = parse_expect_counters("3-0").unwrap();
        // The CLI rejects this combination, but the library must still
        // hard-fail when the ESP cannot be inspected and counting is asserted.
        let runner = SeqRunner::new(vec![], false);
        let out = run_sequence(&runner, &test).unwrap();
        assert!(!out.passed());
        assert!(matches!(
            out.failure,
            Some(SequenceFailure::EspUnavailable(_))
        ));
    }

    #[test]
    fn sequence_esp_unavailable_soft_for_plain_single_boot() {
        // runs == 1, no expectations: a host without mtools still boots.
        let tmp = tempfile::tempdir().unwrap();
        let test = sample_test(tmp.path(), Accel::Kvm, true);
        let runner = SeqRunner::new(vec![], false);
        let out = run_sequence(&runner, &test).unwrap();
        assert!(out.passed(), "{}", out.message());
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.run_root, None);
    }

    #[test]
    fn parse_expect_counters_accepts_dash_and_bare() {
        assert_eq!(
            parse_expect_counters("3-0,2-1").unwrap(),
            vec![
                ExpectedCounters {
                    tries_left: 3,
                    tries_done: Some(0)
                },
                ExpectedCounters {
                    tries_left: 2,
                    tries_done: Some(1)
                },
            ]
        );
        assert_eq!(
            parse_expect_counters("3,2,1,0").unwrap(),
            vec![
                ExpectedCounters {
                    tries_left: 3,
                    tries_done: None
                },
                ExpectedCounters {
                    tries_left: 2,
                    tries_done: None
                },
                ExpectedCounters {
                    tries_left: 1,
                    tries_done: None
                },
                ExpectedCounters {
                    tries_left: 0,
                    tries_done: None
                },
            ]
        );
        assert!(parse_expect_counters("x").is_err());
    }

    #[test]
    fn dir_listing_parses_mdir_output() {
        assert_eq!(
            parse_dir_listing("ubuntu-core-pc_22.04.efi\nfoo+3-0.efi\n"),
            vec![
                "ubuntu-core-pc_22.04.efi".to_string(),
                "foo+3-0.efi".to_string()
            ]
        );
    }
}
