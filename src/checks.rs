//! Package lint — the check battery behind `shuttle lint` (issue #53).
//!
//! One function per check, registered in [`registry`]; the CLI iterates the
//! registry, so adding a check is one function plus one registration line.
//! Unlike the confinement lint ([`crate::lint`], warn-only) and the leak
//! scan ([`crate::leak_scan`], hard build error, ADR-0018), this battery is
//! a standalone pass over DECLARATIONS — it runs before any build, needs no
//! network, and reports every finding with a name, the package it belongs
//! to, a severity, and a one-line fix hint.
//!
//! # Severity contract
//!
//! `Error` means the build (or pod mutation) would fail — or provably ship
//! a broken artifact. `Warn` means suspicious: the build would succeed, but
//! the declaration carries a shape this repo has already been burned by.
//! `shuttle lint` exits nonzero ONLY on errors, never warnings.
//!
//! # Offline guarantee
//!
//! Every check consumes only local data: the evaluated declaration (raw
//! eval JSON plus validated outputs), the package index (pins, store
//! aliases), the declared stage directory, and the pod's resolved package
//! metas. A lint that needed the store would be a lint nobody runs.
//!
//! # Incident map (why these checks exist)
//!
//! | Check | Catches | Incident |
//! |---|---|---|
//! | `dead-store-pin` | pins whose recorded channel mismatches the channel the build derives from the base track | #69 (pc rev 103, delisted) |
//! | `store-alias` | store snaps the index cannot name (wrong store name) | #68 (`pc-gadget` vs `pc`) |
//! | `shadow-mount` | partition mounts over system paths | rootfs shadowing at boot |
//! | `bootloader-type` | `bootloader.type` values declaration validation rejects | #71 (silent `grub`) |
//! | `shebang-requires` | wrapper interpreters resolving to neither payload nor `requires` | #90 (perltidy, meson family) |
//! | `pod-duplicate-apps` | one app name shipped by two packages of a pod | farm shadowing (#7 desktop IDs) |
//! | `unparsed-declaration` | outputs validating as neither package nor image | ADR-0010 no-silent-drops |

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use crate::index::{IndexEntry, PackageIndex};

// ── Findings ──

/// Severity of one lint finding. `Error` = the build would fail (or ship a
/// provably broken artifact); `Warn` = suspicious, build would succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

/// One lint finding. `check` is the stable check name (registry key),
/// `package` the declaration it belongs to (output key, image name, or pod
/// package spec), `message` what was caught, `hint` the one-line fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: &'static str,
    pub package: String,
    pub severity: Severity,
    pub message: String,
    pub hint: String,
}

impl Finding {
    fn new(
        check: &'static str,
        package: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Finding {
            check,
            package: package.into(),
            severity,
            message: message.into(),
            hint: hint.into(),
        }
    }
}

// ── Input model ──

/// One resolved pod package: the declared spec, the resolved package name,
/// and — when the package resolved from local inputs — its validated meta.
/// `meta: None` means "could not resolve offline"; the pod check warns and
/// skips app analysis for it.
#[derive(Debug, Clone)]
pub struct PodPackageMeta {
    pub spec: String,
    pub name: String,
    pub meta: Option<crate::snap::SnapMeta>,
}

/// The pod half of the lint input (populated by `shuttle lint --pod`).
#[derive(Debug, Clone, Default)]
pub struct PodLintData {
    pub name: String,
    pub packages: Vec<PodPackageMeta>,
}

/// Everything the check battery sees. Built once by `shuttle lint`, shared
/// by every check — the seam where future inputs (lockfiles for the #52
/// audit, built payload listings) would land.
pub struct LintInput<'a> {
    /// The linted definition file (label only — findings name it via the
    /// CLI, not per finding).
    pub file: &'a Path,
    /// Target architecture; index pins are keyed `"<arch>@<channel>"`.
    pub arch: &'a str,
    /// Store channel for base/extra snaps (the `--channel` default,
    /// "latest/stable"); kernel/gadget derive from the base track on top.
    pub channel: &'a str,
    /// Outputs that validated as snap declarations, keyed by output name.
    pub outputs: &'a crate::lua::Outputs,
    /// Outputs that validated as image declarations, keyed by name.
    pub images: &'a HashMap<String, crate::image::ImageDeclaration>,
    /// The worker's raw per-key eval JSON, PRE-Rust-validation — checks
    /// that must see values validation rejects (e.g. `bootloader.type`)
    /// read here. Every key of `outputs`/`images` also appears here.
    pub raw: &'a BTreeMap<String, serde_json::Value>,
    /// Keys that validated as neither package nor image.
    pub unparsed: &'a [String],
    /// The package index (pins, store aliases, store names).
    pub index: &'a PackageIndex,
    /// Pod packages (the `--pod` surface); `None` when linting a file.
    pub pod: Option<&'a PodLintData>,
    /// The declared stage directory to scan for shebang wrappers, when it
    /// exists. Absent → the shebang check has nothing to scan.
    pub stage_dir: Option<&'a Path>,
}

// ── Registry ──

/// One registered check: a stable name, a one-line summary, and the run
/// function. The registry is the CLI's iteration order.
pub struct Check {
    pub name: &'static str,
    pub summary: &'static str,
    pub run: fn(&LintInput) -> Vec<Finding>,
}

/// The battery, in registry order. Adding a check = one function plus one
/// line here.
pub fn registry() -> &'static [Check] {
    &[
        Check {
            name: "dead-store-pin",
            summary: "index pins whose channel mismatches the channel the build derives (#69)",
            run: check_dead_store_pins,
        },
        Check {
            name: "store-alias",
            summary: "store snaps referenced by images but unresolvable through the index (#68)",
            run: check_store_aliases,
        },
        Check {
            name: "shadow-mount",
            summary: "partition mounts over system paths the rootfs owns",
            run: check_partition_mounts,
        },
        Check {
            name: "bootloader-type",
            summary: "bootloader.type values declaration validation would reject (#71)",
            run: check_bootloader_type,
        },
        Check {
            name: "shebang-requires",
            summary: "wrapper interpreters resolving to neither payload nor requires (#90)",
            run: check_shebang_interpreters,
        },
        Check {
            name: "pod-duplicate-apps",
            summary: "one app name shipped by two packages of the same pod (#7)",
            run: check_pod_duplicate_apps,
        },
        Check {
            name: "unparsed-declaration",
            summary: "outputs validating as neither package nor image (ADR-0010)",
            run: check_unparsed_declarations,
        },
    ]
}

/// Run the whole battery over `input`, findings sorted deterministically
/// (package, check, message) across checks.
pub fn run_battery(input: &LintInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    for check in registry() {
        findings.extend((check.run)(input));
    }
    findings
        .sort_by(|a, b| (&a.package, a.check, &a.message).cmp(&(&b.package, b.check, &b.message)));
    findings
}

/// Whether any finding is an error — the only thing `shuttle lint` gates on.
pub fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Error)
}

// ── Raw image extraction ──

/// The lenient view of an image declaration, read straight off the worker's
/// raw JSON. `bootloader.type = "grub"` and other shapes Rust-side
/// validation rejects never reach [`crate::image::ImageDeclaration`] — they
/// are exactly what the linter must still see.
struct RawImage {
    base: Option<String>,
    /// (name, explicit channel) pairs.
    kernel: Option<(Option<String>, Option<String>)>,
    gadget: Option<(Option<String>, Option<String>)>,
    extras: Vec<Option<String>>,
    bootloader_type: Option<String>,
    /// (partition name, mount) in declaration order.
    partitions: Vec<(String, String)>,
}

/// A pin-shaped raw table's `name` field.
fn pin_name(v: &serde_json::Value) -> Option<String> {
    v.get("name").and_then(|n| n.as_str()).map(String::from)
}

/// A pin-shaped raw table's optional `channel` field.
fn pin_channel(v: &serde_json::Value) -> Option<String> {
    v.get("channel").and_then(|c| c.as_str()).map(String::from)
}

/// (name, explicit channel) off one kernel/gadget raw pin entry.
fn pin_name_channel(v: &serde_json::Value) -> (Option<String>, Option<String>) {
    (pin_name(v), pin_channel(v))
}

/// The declared partitions of a raw disk layout: (name, mount) pairs in
/// declaration order. Entries missing either field are skipped — the
/// schema errors for those are the eval path's job, not the lint's.
fn raw_partitions(v: &serde_json::Value) -> Vec<(String, String)> {
    v.get("disk")
        .and_then(|d| d.get("partitions"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let name = p.get("name")?.as_str()?.to_string();
                    let mount = p.get("mount")?.as_str()?.to_string();
                    Some((name, mount))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The extra `snaps` array of a raw image, as names (missing names skipped).
fn raw_extra_snaps(v: &serde_json::Value) -> Vec<Option<String>> {
    v.get("snaps")
        .and_then(|s| s.as_array())
        .map(|arr| arr.iter().map(pin_name).collect())
        .unwrap_or_default()
}

impl RawImage {
    /// Extract from raw eval JSON. `None` when the value is not
    /// image-shaped (no `base` object carrying a string `name`).
    fn from_raw(v: &serde_json::Value) -> Option<RawImage> {
        let obj = v.as_object()?;
        let base = obj.get("base").and_then(pin_name)?;
        let kernel = obj
            .get("kernel")
            .filter(|k| k.is_object())
            .map(pin_name_channel);
        let gadget = obj
            .get("gadget")
            .filter(|g| g.is_object())
            .map(pin_name_channel);
        let bootloader_type = obj
            .get("bootloader")
            .and_then(|b| b.get("type"))
            .and_then(|t| t.as_str())
            .map(String::from);
        Some(RawImage {
            base: Some(base),
            kernel,
            gadget,
            extras: raw_extra_snaps(v),
            bootloader_type,
            partitions: raw_partitions(v),
        })
    }
}

/// Every raw value that is image-shaped, keyed by output key, in sorted key
/// order (the `images` map carries parsed images; raw is the superset).
fn raw_images<'a>(input: &'a LintInput<'a>) -> Vec<(&'a str, RawImage)> {
    let mut keys: Vec<&String> = input.raw.keys().collect();
    keys.sort();
    keys.into_iter()
        .filter_map(|k| RawImage::from_raw(&input.raw[k]).map(|img| (k.as_str(), img)))
        .collect()
}

/// The index pins for a referenced snap name, when the entry exists and
/// carries pins.
fn entry_pins<'a>(
    index: &'a PackageIndex,
    name: &str,
) -> Option<&'a std::collections::HashMap<String, crate::index::PinEntry>> {
    index
        .find_by_name_or_alias(name)
        .and_then(|e| e.pins.as_ref())
}

// ── Check 1: dead-store-pin (#69) ──

/// One image-referenced snap: (name, explicit channel, base-tracked).
/// Base-tracked snaps (kernel/gadget) derive their channel from the image
/// base's track (ADR-0019); base and extras ride the lint channel verbatim.
type ImageSnapRef = (String, Option<String>, bool);

/// Every store snap an image references, in a stable order.
fn image_snap_refs(img: &RawImage) -> Vec<ImageSnapRef> {
    let mut entries: Vec<ImageSnapRef> = Vec::new();
    if let Some((name, channel)) = &img.kernel {
        entries.push((name.clone().unwrap_or_default(), channel.clone(), true));
    }
    if let Some((name, channel)) = &img.gadget {
        entries.push((name.clone().unwrap_or_default(), channel.clone(), true));
    }
    for name in &img.extras {
        entries.push((name.clone().unwrap_or_default(), None, false));
    }
    // The base itself resolves on the lint channel verbatim.
    let base = img.base.clone().unwrap_or_default();
    if !base.is_empty() {
        entries.push((base, None, false));
    }
    entries.retain(|(name, _, _)| !name.is_empty());
    entries
}

/// (bare pins with no channel, keyed pins for other channels) among one
/// entry's pins for the lint arch. Pin keys are `"<arch>@<channel>"` or
/// the legacy bare `"<arch>"`.
fn dead_pin_summary(
    pins: &std::collections::HashMap<String, crate::index::PinEntry>,
    arch: &str,
) -> (usize, usize) {
    let mut bare = 0;
    let mut other_channel = 0;
    for (k, pin) in pins {
        let key_arch = k.split('@').next().unwrap_or(k);
        if key_arch != arch {
            continue;
        }
        match (k.contains('@'), pin.channel.as_deref()) {
            (true, _) => other_channel += 1,
            (false, None) => bare += 1,
            (false, Some(_)) => {} // bare with a channel: live on that channel
        }
    }
    (bare, other_channel)
}

/// Audit one referenced snap's index pins against its derived channel.
fn audit_snap_pins(
    input: &LintInput,
    key: &str,
    base: &str,
    name: &str,
    explicit: Option<&str>,
    base_tracked: bool,
) -> Vec<Finding> {
    const CHECK: &str = "dead-store-pin";
    let mut findings = Vec::new();
    let (derived, _override) = if base_tracked {
        crate::image::staging::image_snap_channel(input.channel, base, explicit)
    } else {
        (input.channel.to_string(), false)
    };
    let Some(pins) = entry_pins(input.index, name) else {
        return findings; // missing entries are the store-alias check's job
    };
    // Keyed-pin trust mirrors PackageIndex::channel_pin: the keyed entry
    // wins regardless of its recorded channel — a disagreeing record is
    // exactly the trusted-but-dead shape of #69.
    let keyed = pins.get(&format!("{}@{derived}", input.arch));
    if let Some(pin) = keyed {
        if pin.channel.as_deref() != Some(derived.as_str()) {
            findings.push(Finding::new(
                CHECK,
                key,
                Severity::Error,
                format!(
                    "{name}: pin {}@{derived} (rev {}) records channel '{}' — the build \
                     trusts the key and downloads this revision, but a pin resolved on \
                     another channel may be delisted (issue #69)",
                    input.arch,
                    pin.revision,
                    pin.channel.as_deref().unwrap_or("(none)"),
                ),
                format!(
                    "re-record the pin on the channel it was resolved from \
                     (`shuttle index resolve --base {base}`) or delete it"
                ),
            ));
        }
        return findings;
    }
    // No usable pin for the derived channel. Classify the dead pins.
    let (bare, other_channel) = dead_pin_summary(pins, input.arch);
    if bare > 0 {
        findings.push(Finding::new(
            CHECK,
            key,
            Severity::Warn,
            format!(
                "{name}: {bare} bare pin(s) record no channel — never trusted on the \
                 derived channel '{derived}' (issue #69)",
            ),
            "re-resolve so the pins record their channel, or delete them",
        ));
    }
    if other_channel > 0 {
        findings.push(Finding::new(
            CHECK,
            key,
            Severity::Warn,
            format!(
                "{name}: {other_channel} pin(s) exist but none for channel '{derived}' — \
                 the build ignores them and resolves from the store (offline builds fail \
                 here)",
            ),
            format!("bake pins for the derived channel: `shuttle index resolve --base {base}`"),
        ));
    }
    findings
}

/// Pins whose channel mismatches the channel the build derives (issue #69).
///
/// For every image-referenced store snap the check derives the effective
/// channel exactly as the build does — kernel/gadget ride the base track
/// ([`crate::image::staging::image_snap_channel`]), base/extra use the
/// lint channel verbatim — then audits the index pins for that arch:
///
/// - a keyed pin whose recorded channel disagrees with its key is trusted
///   by the build (the key wins) yet may point at a delisted blob — the
///   exact #69 404 — so it is an **error**;
/// - pins that exist only for other channels are dead weight on a derived
///   channel (the build warns "not trusting them" and falls back to the
///   store) — a **warning**;
/// - a legacy bare pin recording no channel is never trusted on a derived
///   channel (#69) — a **warning**.
fn check_dead_store_pins(input: &LintInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (key, img) in raw_images(input) {
        let base = img.base.clone().unwrap_or_default();
        for (name, explicit, base_tracked) in image_snap_refs(&img) {
            findings.extend(audit_snap_pins(
                input,
                key,
                &base,
                &name,
                explicit.as_deref(),
                base_tracked,
            ));
        }
    }
    findings
}

// ── Check 2: store-alias (#68) ──

/// Alias-integrity findings over the index: an alias colliding with
/// another entry's primary name is unreachable (exact-name lookup wins);
/// an alias declared twice is order-dependent.
fn alias_integrity_findings(index: &PackageIndex) -> Vec<Finding> {
    const CHECK: &str = "store-alias";
    let mut findings = Vec::new();
    let by_name: BTreeMap<&str, &IndexEntry> =
        index.snaps.iter().map(|e| (e.name.as_str(), e)).collect();
    let mut seen_aliases: BTreeMap<&str, &str> = BTreeMap::new();
    for e in &index.snaps {
        for alias in &e.aliases {
            if let Some(other) = by_name.get(alias.as_str()) {
                if other.name != e.name {
                    findings.push(Finding::new(
                        CHECK,
                        e.name.clone(),
                        Severity::Warn,
                        format!(
                            "alias '{alias}' of index entry '{}' collides with the primary \
                             name of entry '{}' — exact-name lookup wins, so the alias is \
                             unreachable",
                            e.name, other.name
                        ),
                        "rename or drop the alias",
                    ));
                }
            }
            if let Some(prev) = seen_aliases.insert(alias.as_str(), e.name.as_str()) {
                if prev != e.name.as_str() {
                    findings.push(Finding::new(
                        CHECK,
                        e.name.clone(),
                        Severity::Warn,
                        format!(
                            "alias '{alias}' is declared by both '{prev}' and '{}' — \
                             resolution is order-dependent",
                            e.name
                        ),
                        "keep the alias on one entry only",
                    ));
                }
            }
        }
    }
    findings
}

/// Every store snap name the linted images reference (deduplicated, sorted).
fn referenced_store_names(input: &LintInput) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    for (_, img) in raw_images(input) {
        let base = img.base.clone().unwrap_or_default();
        if !base.is_empty() {
            referenced.insert(base);
        }
        if let Some((Some(name), _)) = &img.kernel {
            referenced.insert(name.clone());
        }
        if let Some((Some(name), _)) = &img.gadget {
            referenced.insert(name.clone());
        }
        for name in img.extras.into_iter().flatten() {
            referenced.insert(name);
        }
    }
    referenced
}

/// Store snaps the index cannot name (issue #68).
///
/// Image resolution tries the STORE FIRST under the declared local name;
/// only on failure does it consult the index (`find_by_name_or_alias`,
/// then the entry's `store.name`). A local name with no index entry is
/// therefore resolved against the store verbatim — `pc-gadget` failed
/// exactly this way (`resource-not-found`; the store snap is `pc`). The
/// lint cannot query the store offline, so an unreferenced-by-index name
/// is a warning carrying the incident's fix, plus two alias-integrity
/// checks on the index itself.
fn check_store_aliases(input: &LintInput) -> Vec<Finding> {
    const CHECK: &str = "store-alias";
    let mut findings = Vec::new();
    for name in referenced_store_names(input) {
        if input.index.find_by_name_or_alias(&name).is_none() {
            findings.push(Finding::new(
                CHECK,
                name,
                Severity::Warn,
                "not in the package index — the build resolves it against the Snap \
                 Store by this exact name; a wrong store name fails like issue #68 \
                 ('pc-gadget' has no store snap; the gadget is 'pc')",
                "add the index entry with the store's real name: \
                 `shuttle index add <name> --store-name <store-name>`",
            ));
        }
    }
    findings.extend(alias_integrity_findings(input.index));
    findings
}

// ── Check 3: shadow-mount ──

/// FHS subtrees the base rootfs owns; a partition mounted on any of them
/// (or a child of them) shadows the rootfs content at boot. `/var` is
/// included deliberately: the ADR-0023 state partition mounts at
/// `/var/lib`, and a data mount at `/var` would shadow it.
const SYSTEM_PATHS: [&str; 13] = [
    "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/dev", "/proc",
    "/sys", "/run", "/var",
];

/// Whether `mount` is or lives under a system path (`/usr/local` shadows
/// under `/usr`).
fn shadows_system_path(mount: &str) -> bool {
    SYSTEM_PATHS
        .iter()
        .any(|sys| mount == *sys || mount.starts_with(&format!("{sys}/")))
}

/// Findings for one image's declared mounts.
fn mount_findings(key: &str, partitions: &[(String, String)]) -> Vec<Finding> {
    const CHECK: &str = "shadow-mount";
    let mut findings = Vec::new();
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (part, mount) in partitions {
        if mount != "/" && !mount.starts_with('/') {
            findings.push(Finding::new(
                CHECK,
                key,
                Severity::Warn,
                format!("partition '{part}' mounts at '{mount}' — not an absolute path"),
                "use an absolute mount point (leading '/')",
            ));
            continue;
        }
        if shadows_system_path(mount) {
            findings.push(Finding::new(
                CHECK,
                key,
                Severity::Warn,
                format!(
                    "partition '{part}' mounts at '{mount}' — shadows a system path \
                     the base rootfs owns; the subtree is hidden at boot"
                ),
                "mount data under /srv, /opt-adjacent state, or the state partition \
                 (/var/lib) instead",
            ));
        }
        if let Some(prev) = seen.insert(mount.as_str(), part) {
            findings.push(Finding::new(
                CHECK,
                key,
                Severity::Warn,
                format!(
                    "partitions '{prev}' and '{part}' both mount '{mount}' — the second \
                     mount fails at boot"
                ),
                "give each partition a distinct mount point",
            ));
        }
    }
    findings
}

/// Declared partition mounts that shadow system paths, mount one path
/// twice, or are relative (issue #53; the build renders every mount
/// verbatim into `etc/fstab`, so these surface at boot, not at build).
fn check_partition_mounts(input: &LintInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (key, img) in raw_images(input) {
        findings.extend(mount_findings(key, &img.partitions));
    }
    findings
}

// ── Check 4: bootloader-type (#71) ──

/// `bootloader.type` values declaration validation rejects (issues #71/#87).
///
/// Two backends are implemented — `systemd-boot` (UEFI targets) and
/// `piboot` (Raspberry Pi firmware chain, #87); `ImageDeclaration::
/// from_lua_table` fails the image on anything else — the eval path then
/// skips the image with a warning and the build dies later with a lost
/// cause. Reading the RAW eval JSON, lint reports the rejected value
/// directly, before any build: an **error**, because the build would fail.
fn check_bootloader_type(input: &LintInput) -> Vec<Finding> {
    const CHECK: &str = "bootloader-type";
    let mut findings = Vec::new();
    for (key, img) in raw_images(input) {
        if let Some(t) = &img.bootloader_type {
            if t != "systemd-boot" && t != crate::image::BOOTLOADER_PIBOOT {
                findings.push(Finding::new(
                    CHECK,
                    key,
                    Severity::Error,
                    format!(
                        "bootloader.type = \"{t}\" is not implemented — declaration \
                         validation rejects it, so the image build fails (issue #71: the \
                         GRUB backend does not exist, the declaration would silently \
                         install systemd-boot)"
                    ),
                    "set bootloader.type = \"systemd-boot\" or \"piboot\" (issue #87), or \
                     drop the bootloader field",
                ));
            }
        }
    }
    findings
}

// ── Check 5: shebang-requires (#90) ──

/// Parse the interpreter out of a shebang line. `#!/usr/bin/env perl`
/// yields `("perl", true)`; `#!/usr/bin/perl` yields
/// ("/usr/bin/perl", false); `None` when the line is not a shebang.
fn shebang_interpreter(first_line: &str) -> Option<(String, bool)> {
    let rest = first_line.strip_prefix("#!")?;
    let mut tokens = rest.split_whitespace();
    let first = tokens.next()?;
    if first == "/usr/bin/env" || first == "/bin/env" {
        // `env -S ...` and flags are skipped: the next bare token is the
        // interpreter name env resolves from PATH.
        let name = tokens.find(|t| !t.starts_with('-') && !t.contains('=') && *t != "-S")?;
        Some((name.to_string(), true))
    } else {
        Some((first.to_string(), false))
    }
}

/// Whether the staged tree provides `path` (a `usr/...`-relative payload
/// file) or `usr/bin/<basename>`.
///
/// Shebang interpreters arrive absolute (`/usr/bin/perl`); `Path::join`
/// with an absolute argument would REPLACE the stage root and probe the
/// host filesystem instead of the payload — on any machine shipping
/// `/usr/bin/perl` the check silently no-ops (issue #90 follow-up).
fn tree_provides(stage: &Path, path: &str) -> bool {
    let rel = path.strip_prefix('/').unwrap_or(path);
    if stage.join(rel).is_file() {
        return true;
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    stage.join("usr/bin").join(base).is_file()
}

/// Base-guaranteed interpreters: every snap base runtime ships these
/// before the merged prefix assembles, so a payload script pointing at
/// one is not a broken wrapper. core22/core24 also carry
/// `/usr/bin/sh -> /bin/sh`. (Before the host-fs probe fix, this case
/// resolved by ACCIDENT — stage.join("/bin/sh") probed the host.)
fn base_guaranteed(interp: &str) -> bool {
    matches!(
        interp,
        "/bin/sh" | "/usr/bin/sh" | "/bin/bash" | "/usr/bin/bash"
    )
}

/// Findings for one package's staged scripts.
fn package_shebang_findings(key: &str, meta: &crate::snap::SnapMeta, stage: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rel in staged_scripts(stage) {
        let path = stage.join(&rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some((interp, via_env)) = text.lines().next().and_then(shebang_interpreter) else {
            continue;
        };
        if tree_provides(stage, &interp) || base_guaranteed(&interp) {
            continue;
        }
        let basename = interp.rsplit('/').next().unwrap_or(&interp).to_string();
        if meta.requires.iter().any(|r| r == &basename) {
            continue;
        }
        if via_env {
            findings.push(Finding::new(
                "shebang-requires",
                key,
                Severity::Warn,
                format!(
                    "{rel}: shebang resolves '{interp}' via env from PATH — nothing in the \
                     payload or requires provides '{basename}'"
                ),
                format!(
                    "declare the interpreter package in requires (e.g. '{{ \"{basename}\" }}')"
                ),
            ));
        } else {
            findings.push(Finding::new(
                "shebang-requires",
                key,
                Severity::Error,
                format!(
                    "{rel}: interpreter '{interp}' resolves to neither the payload nor a \
                     declared requires — the merged-prefix build fails closed on this \
                     wrapper (issue #90)"
                ),
                format!("add '{basename}' to requires, or stage the interpreter into the payload"),
            ));
        }
    }
    findings
}

/// Wrapper interpreters resolving to neither the payload nor a declared
/// `requires` (issue #90).
///
/// Scans the declared stage directory for scripts carrying shebangs and
/// resolves each interpreter the way the merged-prefix build does
/// ([`crate::build_prefix`] fail-closed rule): into the payload tree, a
/// declared `requires`, or the base-guaranteed set ([`base_guaranteed`]).
/// An unresolvable interpreter is an **error** — the
/// prefix build fails closed on exactly this shape (#90: "a silently
/// broken wrapper is what ships today"), and a plain snap build ships the
/// broken wrapper. `#!/usr/bin/env X` is a **warning** when nothing
/// provides `X`: env resolves from PATH at runtime, so the finding is
/// suspicious rather than certain.
///
/// The requires match is by pool-package name ≈ interpreter basename (the
/// `perl` package provides `/usr/bin/perl`); an absent stage directory
/// leaves the check silent.
fn check_shebang_interpreters(input: &LintInput) -> Vec<Finding> {
    let Some(stage) = input.stage_dir else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    // Single-output definitions stage at the stage dir itself; multi-output
    // ones nest one directory per package name.
    let single = input.outputs.len() == 1;
    for (key, meta) in input.outputs {
        let pkg_stage = if single {
            stage.to_path_buf()
        } else {
            stage.join(&meta.name)
        };
        if !pkg_stage.is_dir() {
            continue;
        }
        findings.extend(package_shebang_findings(key, meta, &pkg_stage));
    }
    findings
}

/// Deterministic list of payload-relative text files under `stage` whose
/// first bytes are `#!` (symlinked dirs are not followed).
fn staged_scripts(stage: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(stage.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(_) => continue,
        };
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let rel = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push((entry.path(), rel));
            } else if ft.is_file() && starts_with_shebang(&entry.path()) {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

fn starts_with_shebang(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"#!"
}

// ── Check 6: pod-duplicate-apps (#7) ──

/// Duplicate app names across one pod's resolved packages, plus the
/// unresolved-package warnings. See [`check_pod_duplicate_apps`].
fn pod_app_findings(pod: &PodLintData) -> Vec<Finding> {
    let mut findings = Vec::new();
    // app name -> [(spec, pkg name, carries desktop?)]
    let mut apps: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    for pkg in &pod.packages {
        match &pkg.meta {
            Some(meta) => {
                for (app, a) in &meta.apps {
                    apps.entry(app.clone()).or_default().push((
                        pkg.spec.clone(),
                        meta.name.clone(),
                        a.desktop.is_some(),
                    ));
                }
            }
            None => findings.push(Finding::new(
                "pod-duplicate-apps",
                pkg.spec.clone(),
                Severity::Warn,
                format!(
                    "package '{}' could not be resolved from local inputs — app checks \
                     skipped for it (lint is offline)",
                    pkg.name
                ),
                "materialize the package inputs locally, then re-lint",
            )),
        }
    }
    for (app, owners) in &apps {
        if owners.len() < 2 {
            continue;
        }
        findings.push(duplicate_app_finding(pod, app, owners));
    }
    findings
}

/// One duplicate-app finding: an error when every duplicate carries a
/// `.desktop` (pod mutation fails, issue #7), else a warning (the farm
/// shadows deterministically).
fn duplicate_app_finding(
    pod: &PodLintData,
    app: &str,
    owners: &[(String, String, bool)],
) -> Finding {
    let names: Vec<&str> = owners.iter().map(|(_, n, _)| n.as_str()).collect();
    let all_desktop = owners.iter().all(|(_, _, d)| *d);
    if all_desktop {
        Finding::new(
            "pod-duplicate-apps",
            pod.name.clone(),
            Severity::Error,
            format!(
                "app '{app}' is declared by both {} — same-precedence desktop app-ID \
                 collision fails pod mutation (issue #7)",
                names.join(" and ")
            ),
            "rename one of the apps or drop one of the packages",
        )
    } else {
        Finding::new(
            "pod-duplicate-apps",
            pod.name.clone(),
            Severity::Warn,
            format!(
                "app '{app}' is shipped by both {} — the farm shadows the earlier \
                 package's app deterministically",
                names.join(" and ")
            ),
            "rename one app or drop one of the packages so `shuttle run` is unambiguous",
        )
    }
}

/// One app name shipped by two packages of the same pod.
///
/// The farm resolves duplicate binary names deterministically with a
/// warning (`farm::warn_emit_collision`) — the earlier package's app
/// becomes unreachable by name, which is a real foot-gun (`shuttle run`
/// execs the survivor). When BOTH duplicates carry `.desktop` files, pod
/// mutation fails outright (same-precedence desktop app-ID collision,
/// issue #7) — an **error**. Plain duplicates are a **warning**.
fn check_pod_duplicate_apps(input: &LintInput) -> Vec<Finding> {
    let Some(pod) = input.pod else {
        return Vec::new();
    };
    pod_app_findings(pod)
}

// ── Check 7: unparsed-declaration ──

/// Outputs validating as neither package nor image (ADR-0010: no silent
/// drops). The eval path warns and skips these; lint surfaces them as
/// findings so `--json` consumers see them in the same shape.
fn check_unparsed_declarations(input: &LintInput) -> Vec<Finding> {
    input
        .unparsed
        .iter()
        .map(|key| {
            Finding::new(
                "unparsed-declaration",
                key.clone(),
                Severity::Warn,
                "validates as neither a package nor an image declaration — eval skips it",
                "fix the schema error `shuttle check` reports for this output",
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{IndexEntry, PinEntry, StoreRef};
    use crate::lua::Outputs;
    use crate::snap::SnapMeta;
    use serde_json::json;
    use std::collections::HashMap;

    // ── Fixtures ──

    fn bare_meta(name: &str) -> SnapMeta {
        SnapMeta {
            name: name.to_string(),
            version: "1.0".into(),
            version_adopted: false,
            summary: None,
            description: None,
            license: None,
            source: None,
            sources: None,
            architectures: None,
            build: None,
            parts: None,
            grade: "stable".into(),
            confinement: "strict".into(),
            type_: None,
            adopt_info: None,
            icon_source: None,
            icon: None,
            compression: None,
            environment: None,
            layout: None,
            hooks: None,
            plugs: None,
            slots: None,
            aliases: vec![],
            requires: vec![],
            build_deps: vec![],
            leaks_ok: vec![],
            target: None,
            toolchain: None,
            inputs: None,
            confined: None,
            apps: HashMap::new(),
            services: BTreeMap::new(),
            deps: None,
            floating: false,
            definition_dir: None,
        }
    }

    fn pin_entry(revision: u32, channel: Option<&str>) -> PinEntry {
        PinEntry {
            revision,
            sha3_384: "a".repeat(96),
            channel: channel.map(String::from),
        }
    }

    fn store_entry(
        name: &str,
        store_name: Option<&str>,
        pins: Vec<(&str, PinEntry)>,
    ) -> IndexEntry {
        IndexEntry {
            name: name.to_string(),
            summary: None,
            store: Some(StoreRef {
                name: store_name.map(String::from),
                channel: "latest/stable".into(),
            }),
            pins: Some(pins.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            source: None,
            build: None,
            apps: None,
            aliases: vec![],
        }
    }

    fn index(entries: Vec<IndexEntry>) -> PackageIndex {
        PackageIndex {
            version: 1,
            snaps: entries,
        }
    }

    /// An image raw table: core22 base, pc-kernel kernel, pc-gadget gadget.
    fn pc_image_raw() -> serde_json::Value {
        json!({
            "name": "ubuntu-core-pc",
            "version": "22.04",
            "base": { "name": "core22" },
            "kernel": { "name": "pc-kernel", "params": ["quiet"] },
            "gadget": { "name": "pc-gadget" },
            "snaps": [ { "name": "snapd" } ],
            "bootloader": { "type": "systemd-boot", "timeout": 3 },
            "disk": {
                "label": "gpt",
                "partitions": [
                    { "name": "esp", "size": "512M", "fs": "vfat", "mount": "/boot" },
                    { "name": "root", "size": "3G", "fs": "ext4", "mount": "/" },
                ],
            },
        })
    }

    struct Builder {
        raw: BTreeMap<String, serde_json::Value>,
        outputs: Outputs,
        images: HashMap<String, crate::image::ImageDeclaration>,
        unparsed: Vec<String>,
        index: PackageIndex,
    }

    impl Builder {
        fn new() -> Self {
            Builder {
                raw: BTreeMap::new(),
                outputs: Outputs::new(),
                images: HashMap::new(),
                unparsed: Vec::new(),
                index: index(Vec::new()),
            }
        }
        fn image(mut self, key: &str, v: serde_json::Value) -> Self {
            self.raw.insert(key.to_string(), v);
            self
        }
        fn output(mut self, meta: SnapMeta) -> Self {
            self.outputs.insert(meta.name.clone(), meta);
            self
        }
        fn idx(mut self, index: PackageIndex) -> Self {
            self.index = index;
            self
        }
        fn build(&self) -> LintInput<'_> {
            LintInput {
                file: Path::new("shuttle.lua"),
                arch: "amd64",
                channel: "latest/stable",
                outputs: &self.outputs,
                images: &self.images,
                raw: &self.raw,
                unparsed: &self.unparsed,
                index: &self.index,
                pod: None,
                stage_dir: None,
            }
        }
    }

    fn for_check(input: &LintInput, name: &str) -> Vec<Finding> {
        registry()
            .iter()
            .find(|c| c.name == name)
            .map(|c| (c.run)(input))
            .unwrap()
    }

    // ── dead-store-pin ──

    #[test]
    fn keyed_pin_with_mismatched_recorded_channel_errors() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![store_entry(
                "pc-gadget",
                Some("pc"),
                vec![(
                    "amd64@22/stable",
                    pin_entry(103, Some("latest/stable")), // keyed 22/stable, recorded latest
                )],
            )]));
        let input = b.build();
        let findings = for_check(&input, "dead-store-pin");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("pc-gadget")
                && findings[0].message.contains("rev 103")
                && findings[0].message.contains("#69"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn channel_matched_keyed_pin_is_clean() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![
                store_entry(
                    "pc-kernel",
                    None,
                    vec![("amd64@22/stable", pin_entry(3654, Some("22/stable")))],
                ),
                store_entry(
                    "pc-gadget",
                    Some("pc"),
                    vec![("amd64@22/stable", pin_entry(227, Some("22/stable")))],
                ),
            ]));
        let input = b.build();
        assert!(for_check(&input, "dead-store-pin").is_empty());
    }

    #[test]
    fn pins_only_for_other_channels_warn() {
        // pc-kernel pinned only on latest/stable; the core22 base derives
        // 22/stable for the kernel — dead pins, build falls back to store.
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![store_entry(
                "pc-kernel",
                None,
                vec![(
                    "amd64@latest/stable",
                    pin_entry(2000, Some("latest/stable")),
                )],
            )]));
        let input = b.build();
        let findings = for_check(&input, "dead-store-pin");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("none for channel '22/stable'")
                && findings[0].hint.contains("--base core22"),
            "{} / {}",
            findings[0].message,
            findings[0].hint
        );
    }

    #[test]
    fn legacy_bare_pin_without_channel_warns() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![store_entry(
                "pc-kernel",
                None,
                vec![("amd64", pin_entry(3654, None))],
            )]));
        let input = b.build();
        let findings = for_check(&input, "dead-store-pin");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("record no channel"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn explicit_gadget_channel_skips_derivation() {
        // gadget pinned to latest/stable verbatim: no 22/stable derivation,
        // so a latest/stable pin is LIVE, not dead.
        let mut raw = pc_image_raw();
        raw["gadget"]["channel"] = json!("latest/stable");
        let b = Builder::new()
            .image("rootfs", raw)
            .idx(index(vec![store_entry(
                "pc-gadget",
                Some("pc"),
                vec![("amd64@latest/stable", pin_entry(103, Some("latest/stable")))],
            )]));
        let input = b.build();
        assert!(for_check(&input, "dead-store-pin").is_empty());
    }

    #[test]
    fn base_pins_are_checked_on_the_lint_channel() {
        // core22 has only latest/stable pins; base rides the lint channel
        // verbatim — clean. A stray 22/stable-only core22 pin set warns.
        let mut core22 = store_entry(
            "core22",
            None,
            vec![("amd64@22/stable", pin_entry(2404, Some("22/stable")))],
        );
        core22.pins.as_mut().unwrap().remove("amd64@latest/stable");
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![core22]));
        let input = b.build();
        let findings = for_check(&input, "dead-store-pin");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("core22"),
            "{}",
            findings[0].message
        );
    }

    // ── store-alias ──

    #[test]
    fn referenced_snap_not_in_index_warns_with_68_hint() {
        let b = Builder::new().image("rootfs", pc_image_raw());
        let input = b.build();
        let findings = for_check(&input, "store-alias");
        // pc-kernel, pc-gadget, core22, snapd all missing from the index.
        let pkgs: Vec<&str> = findings.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(
            pkgs,
            vec!["core22", "pc-gadget", "pc-kernel", "snapd"],
            "{findings:?}"
        );
        assert!(findings.iter().all(|f| f.severity == Severity::Warn));
        assert!(
            findings[1].message.contains("#68") && findings[1].hint.contains("--store-name"),
            "{}",
            findings[1].message
        );
    }

    #[test]
    fn index_resolvable_references_are_clean() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![
                store_entry("core22", None, vec![]),
                store_entry("pc-kernel", None, vec![]),
                store_entry("pc-gadget", Some("pc"), vec![]),
                store_entry("snapd", None, vec![]),
            ]));
        let input = b.build();
        assert!(for_check(&input, "store-alias").is_empty());
    }

    #[test]
    fn alias_shadowing_a_primary_name_warns() {
        let mut shadowed = store_entry("pc", None, vec![]);
        shadowed.aliases = vec!["pc-gadget".into()];
        let b = Builder::new().idx(index(vec![
            store_entry("pc-gadget", Some("pc"), vec![]),
            shadowed,
        ]));
        let input = b.build();
        let findings = for_check(&input, "store-alias");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("unreachable"),
            "{}",
            findings[0].message
        );
    }

    // ── shadow-mount ──

    #[test]
    fn mount_over_system_path_warns() {
        let mut raw = pc_image_raw();
        raw["disk"]["partitions"][1]["mount"] = json!("/usr");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        let findings = for_check(&input, "shadow-mount");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("/usr"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn mount_under_system_path_child_warns() {
        let mut raw = pc_image_raw();
        raw["disk"]["partitions"][1]["mount"] = json!("/usr/local/data");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        let findings = for_check(&input, "shadow-mount");
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn relative_mount_warns() {
        let mut raw = pc_image_raw();
        raw["disk"]["partitions"][1]["mount"] = json!("boot");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        let findings = for_check(&input, "shadow-mount");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("absolute"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn duplicate_mount_points_warn() {
        let mut raw = pc_image_raw();
        raw["disk"]["partitions"][1]["mount"] = json!("/boot");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        let findings = for_check(&input, "shadow-mount");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("both mount '/boot'"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn esp_root_and_data_mounts_are_clean() {
        let b = Builder::new().image("rootfs", pc_image_raw());
        let input = b.build();
        assert!(for_check(&input, "shadow-mount").is_empty());
    }

    // ── bootloader-type ──

    #[test]
    fn grub_bootloader_type_errors_before_the_build() {
        let mut raw = pc_image_raw();
        raw["bootloader"]["type"] = json!("grub");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        let findings = for_check(&input, "bootloader-type");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("grub") && findings[0].message.contains("#71"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn systemd_boot_and_absent_bootloader_are_clean() {
        let b = Builder::new().image("rootfs", pc_image_raw());
        let input = b.build();
        assert!(for_check(&input, "bootloader-type").is_empty());
        let mut raw = pc_image_raw();
        raw.as_object_mut().unwrap().remove("bootloader");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        assert!(for_check(&input, "bootloader-type").is_empty());
    }

    /// Issue #87: `piboot` is the second implemented backend — the lint
    /// must accept it (the pi-rootfs example declares it).
    #[test]
    fn piboot_bootloader_is_clean() {
        let mut raw = pc_image_raw();
        raw["bootloader"]["type"] = json!("piboot");
        let b = Builder::new().image("rootfs", raw);
        let input = b.build();
        assert!(for_check(&input, "bootloader-type").is_empty());
    }

    // ── shebang-requires ──

    fn stage_file(stage: &Path, rel: &str, content: &str) {
        let path = stage.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn unresolvable_interpreter_errors() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "usr/bin/perltidy",
            "#!/usr/bin/perl\nprint 1;\n",
        );
        let mut meta = bare_meta("perltidy");
        meta.requires = vec![];
        let b = Builder::new().output(meta);
        let input = b.build();
        let input = LintInput {
            stage_dir: Some(dir.path()),
            ..input
        };
        let findings = for_check(&input, "shebang-requires");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("/usr/bin/perl") && findings[0].message.contains("#90"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn interpreter_from_requires_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "usr/bin/perltidy",
            "#!/usr/bin/perl\nprint 1;\n",
        );
        let mut meta = bare_meta("perltidy");
        meta.requires = vec!["perl".into()];
        let b = Builder::new().output(meta);
        let input = b.build();
        let input = LintInput {
            stage_dir: Some(dir.path()),
            ..input
        };
        assert!(for_check(&input, "shebang-requires").is_empty());
    }

    #[test]
    fn interpreter_shipped_in_payload_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "usr/bin/perltidy",
            "#!/usr/bin/perl\nprint 1;\n",
        );
        stage_file(dir.path(), "usr/bin/perl", "#!/bin/sh\nexec perl.real\n");
        let b = Builder::new().output(bare_meta("perltidy"));
        let input = b.build();
        let input = LintInput {
            stage_dir: Some(dir.path()),
            ..input
        };
        assert!(for_check(&input, "shebang-requires").is_empty());
    }

    #[test]
    fn env_interpreter_without_provider_warns() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(dir.path(), "usr/bin/cli", "#!/usr/bin/env node\nrun();\n");
        let b = Builder::new().output(bare_meta("cli"));
        let input = b.build();
        let input = LintInput {
            stage_dir: Some(dir.path()),
            ..input
        };
        let findings = for_check(&input, "shebang-requires");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("env"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn absent_stage_dir_is_silent() {
        let b = Builder::new().output(bare_meta("hello"));
        let input = b.build();
        assert!(for_check(&input, "shebang-requires").is_empty());
    }

    #[test]
    fn shebang_interpreter_parses_env_and_direct_forms() {
        assert_eq!(
            shebang_interpreter("#!/usr/bin/perl"),
            Some(("/usr/bin/perl".into(), false))
        );
        assert_eq!(
            shebang_interpreter("#!/usr/bin/env node"),
            Some(("node".into(), true))
        );
        assert_eq!(
            shebang_interpreter("#!/usr/bin/env -S node --max-old-space-size=1"),
            Some(("node".into(), true))
        );
        assert_eq!(shebang_interpreter("print 1"), None);
    }

    // ── pod-duplicate-apps ──

    fn pod_data(packages: Vec<PodPackageMeta>) -> PodLintData {
        PodLintData {
            name: "daily".into(),
            packages,
        }
    }

    fn meta_with_apps(name: &str, apps: &[(&str, bool)]) -> SnapMeta {
        let mut meta = bare_meta(name);
        for (app, desktop) in apps {
            let mut a = crate::snap::SnapApp {
                command: format!("bin/{app}"),
                daemon: None,
                plugs: None,
                slots: None,
                environment: None,
                desktop: None,
                interpreter: None,
                confined: None,
            };
            if *desktop {
                a.desktop = Some("meta/desktop.app".into());
            }
            meta.apps.insert(app.to_string(), a);
        }
        meta
    }

    #[test]
    fn duplicate_plain_app_warns() {
        let pod = pod_data(vec![
            PodPackageMeta {
                spec: "jq".into(),
                name: "jq".into(),
                meta: Some(meta_with_apps("jq", &[("query", false)])),
            },
            PodPackageMeta {
                spec: "yq".into(),
                name: "yq".into(),
                meta: Some(meta_with_apps("yq", &[("query", false)])),
            },
        ]);
        let b = Builder::new();
        let input = b.build();
        let input = LintInput {
            pod: Some(&pod),
            ..input
        };
        let findings = for_check(&input, "pod-duplicate-apps");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0].message.contains("'query'") && findings[0].message.contains("jq and yq"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn duplicate_desktop_app_errors() {
        let pod = pod_data(vec![
            PodPackageMeta {
                spec: "a".into(),
                name: "pkg-a".into(),
                meta: Some(meta_with_apps("pkg-a", &[("editor", true)])),
            },
            PodPackageMeta {
                spec: "b".into(),
                name: "pkg-b".into(),
                meta: Some(meta_with_apps("pkg-b", &[("editor", true)])),
            },
        ]);
        let b = Builder::new();
        let input = b.build();
        let input = LintInput {
            pod: Some(&pod),
            ..input
        };
        let findings = for_check(&input, "pod-duplicate-apps");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(
            findings[0].message.contains("desktop app-ID"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn unique_apps_and_unresolved_packages() {
        let pod = pod_data(vec![
            PodPackageMeta {
                spec: "jq".into(),
                name: "jq".into(),
                meta: Some(meta_with_apps("jq", &[("query", false)])),
            },
            PodPackageMeta {
                spec: "ripgrep@14".into(),
                name: "ripgrep".into(),
                meta: None,
            },
        ]);
        let b = Builder::new();
        let input = b.build();
        let input = LintInput {
            pod: Some(&pod),
            ..input
        };
        let findings = for_check(&input, "pod-duplicate-apps");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("ripgrep"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn pod_check_is_silent_without_pod_data() {
        let b = Builder::new();
        let input = b.build();
        assert!(for_check(&input, "pod-duplicate-apps").is_empty());
    }

    // ── unparsed-declaration ──

    #[test]
    fn unparsed_keys_become_warnings() {
        let mut b = Builder::new();
        b.unparsed = vec!["broken".into()];
        let input = b.build();
        let findings = for_check(&input, "unparsed-declaration");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].package, "broken");
    }

    // ── Registry & battery ──

    #[test]
    fn registry_names_are_unique_and_nonempty() {
        let reg = registry();
        assert!(reg.len() >= 6);
        let mut names: Vec<_> = reg.iter().map(|c| c.name).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "duplicate check names");
    }

    #[test]
    fn battery_is_clean_on_a_well_pinned_pc_image() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .idx(index(vec![
                store_entry(
                    "core22",
                    None,
                    vec![(
                        "amd64@latest/stable",
                        pin_entry(2411, Some("latest/stable")),
                    )],
                ),
                store_entry(
                    "pc-kernel",
                    None,
                    vec![("amd64@22/stable", pin_entry(3654, Some("22/stable")))],
                ),
                store_entry(
                    "pc-gadget",
                    Some("pc"),
                    vec![("amd64@22/stable", pin_entry(227, Some("22/stable")))],
                ),
                store_entry(
                    "snapd",
                    None,
                    vec![(
                        "amd64@latest/stable",
                        pin_entry(24446, Some("latest/stable")),
                    )],
                ),
            ]));
        let input = b.build();
        let findings = run_battery(&input);
        assert!(findings.is_empty(), "{findings:?}");
        assert!(!has_errors(&findings));
    }

    #[test]
    fn battery_sorts_findings_deterministically() {
        let b = Builder::new()
            .image("rootfs", pc_image_raw())
            .image("aaa", {
                let mut v = pc_image_raw();
                v["bootloader"]["type"] = json!("grub");
                v
            });
        let input = b.build();
        let findings = run_battery(&input);
        let mut sorted = findings.clone();
        sorted.sort_by(|a, b| {
            (&a.package, a.check, &a.message).cmp(&(&b.package, b.check, &b.message))
        });
        assert_eq!(findings, sorted);
        assert!(has_errors(&findings));
    }
}
