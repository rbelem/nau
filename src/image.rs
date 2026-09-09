//! Image assembly — compose multiple pinned snaps into a single reproducible
//! rootfs SquashFS image.
//!
//! The `image()` DSL function defines a system image built from component
//! snaps (base + kernel + gadget + extras). The pipeline:
//!
//! 1. Resolve pinned snaps (from DSL or lockfile)
//! 2. Download all snaps to content-addressed cache
//! 3. Verify sha3-384 of every snap
//! 4. Extract base snap as rootfs foundation
//! 5. Merge kernel modules/firmware
//! 6. Bundle all snaps as `.snap` files
//! 7. Generate manifest
//! 8. Pack into SquashFS with `SOURCE_DATE_EPOCH`

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr};
use mlua::Value;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

use crate::doctor;
use crate::lock::LockFile;
use crate::snap::{self, SnapRef};
use crate::store::{ResolvedSnap, StoreClient};

#[cfg(test)]
pub mod test_support {
    //! Shared test fixtures — a minimal UC image declaration usable from
    //! sibling module tests (e.g. [`crate::uc`]). Constructing an
    //! [`ImageDeclaration`] requires private-adjacent fields; this small
    //! builder keeps sibling test modules from duplicating it.

    use super::{ImageDeclaration, KernelEntry};
    use crate::snap::SnapRef;

    pub fn sample_image() -> ImageDeclaration {
        ImageDeclaration {
            name: "test-uc".into(),
            version: "1.0.0".into(),
            base: SnapRef {
                name: "core24".into(),
                revision: Some(42),
                sha3_384: Some("aabb".into()),
            },
            kernel: Some(KernelEntry {
                snap: SnapRef {
                    name: "pc-kernel".into(),
                    revision: Some(7),
                    sha3_384: Some("ccdd".into()),
                },
                params: vec![],
                modules: vec![],
                modprobe_config: None,
                channel: None,
            }),
            gadget: Some(SnapRef {
                name: "pc".into(),
                revision: Some(9),
                sha3_384: Some("eeff".into()),
            }),
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        }
    }
}

// ── Additional types ──

/// Kernel snap reference plus kernel configuration.
#[derive(Debug, Clone)]
pub struct KernelEntry {
    pub snap: SnapRef,
    pub params: Vec<String>,
    pub modules: Vec<String>,
    pub modprobe_config: Option<String>,
    /// ADR-0019 escape hatch: an author-pinned store channel (e.g.
    /// "latest/stable") carried on the kernel pin entry
    /// (`pin("pc-kernel", { channel = "…" })`). When set, resolution uses
    /// the channel verbatim — no base-track derivation — and the
    /// declared-base check is skipped; the override is logged at build
    /// time.
    pub channel: Option<String>,
}

/// Bootloader configuration for disk images.
#[derive(Debug, Clone)]
pub struct BootloaderConfig {
    pub type_: String, // "systemd-boot" or "grub"
    pub timeout: u32,
}

/// Full disk layout definition.
#[derive(Debug, Clone)]
pub struct DiskLayout {
    pub label: String, // "gpt" or "mbr"
    pub partitions: Vec<Partition>,
    pub swap: Option<SwapConfig>,
    /// A/B slot updates (ADR-0011 step (d)). Opt-in, default off —
    /// kernel-free and single-slot images build byte-identically without
    /// it. When set, the root (and its dm-verity hash partition, for kernel
    /// images) is cloned into a same-size slot B after slot A, sysupdate
    /// transfer files are emitted when `update_source` is declared, and GPT
    /// type GUIDs + PARTLABELs are applied so systemd-sysupdate can match
    /// the slots. Requires a "gpt" label.
    pub ab: bool,
}

/// One partition in the disk layout.
#[derive(Debug, Clone)]
pub struct Partition {
    pub name: String,
    pub size: String,         // e.g. "512M", "0" for remaining
    pub fs: String,           // e.g. "vfat", "btrfs", "ext4"
    pub mount: String,        // mount point
    pub options: Vec<String>, // mount options
    /// UC gadget role (issue #32): `"system-seed"`, `"system-boot"`,
    /// `"system-data"` (or `"system-save"`). Only honored when the image
    /// base is a UC coreN base; the role selects the UC PARTLABEL
    /// (`ubuntu-seed` / `ubuntu-boot` / `ubuntu-data`) and the populate
    /// routing (seed / boot / data). Empty for non-UC partitions — the
    /// simplified path is untouched.
    pub role: String,
}

/// Swap configuration.
#[derive(Debug, Clone)]
pub struct SwapConfig {
    pub size: String, // e.g. "8G"
}

// ── Image declaration ──

/// A declarative image composed from multiple snaps.
///
/// Created by the `image()` DSL function:
/// ```lua
/// image {
///     name = "my-system",
///     version = "1.0.0",
///     base = pin("core22"),
///     kernel = pin("pc-kernel"),
///     gadget = pin("pi-gadget"),
///     snaps = { pin("lxd") },
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ImageDeclaration {
    pub name: String,
    pub version: String,
    pub base: SnapRef,
    pub kernel: Option<KernelEntry>,
    pub gadget: Option<SnapRef>,
    /// ADR-0019 escape hatch for the gadget entry — an author-pinned store
    /// channel (`gadget = pin("pc", { channel = "…" })`). Semantics match
    /// [`KernelEntry::channel`]: verbatim channel, no track derivation, no
    /// declared-base check, logged override.
    pub gadget_channel: Option<String>,
    pub extra_snaps: Vec<SnapRef>,
    pub bootloader: Option<BootloaderConfig>,
    pub disk: Option<DiskLayout>,
    pub sysctl: Vec<String>,
    /// Base URL of the systemd-sysupdate payload source (ADR-0011 step
    /// (d)); transfer files are emitted only when set — a local-source
    /// transfer would carry no verification, and unverifiable update
    /// config is never emitted silently.
    pub update_source: Option<String>,
}

/// Serialize as the name string (for `meta/snap.yaml`).
impl Serialize for ImageDeclaration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.name.serialize(serializer)
    }
}

// ── Conversion from Lua ──

impl ImageDeclaration {
    /// Create from a validated Lua table (from `image()`).
    pub fn from_lua_table(table: &mlua::Table) -> miette::Result<Self> {
        let name: String =
            get_required(table, "name").map_err(|e| miette::miette!("image(): {e}"))?;
        let version: String =
            get_required(table, "version").map_err(|e| miette::miette!("image(): {e}"))?;

        let base = get_required_snap_ref(table, "base")?;
        let kernel = get_opt_kernel_entry(table)?;
        let gadget = get_opt_snap_ref(table, "gadget")?;
        let gadget_channel = get_opt_pin_channel(table, "gadget")?;
        let extra_snaps = get_snap_ref_array(table, "snaps")?;

        // NEW: bootloader
        let bootloader = get_opt_bootloader(table)?;
        // NEW: disk layout
        let disk = get_opt_disk_layout(table)?;
        // NEW: sysctl
        let sysctl: Vec<String> = table.get("sysctl").unwrap_or_default();
        // ADR-0011 step (d): optional sysupdate payload source URL
        let update_source = match table
            .get::<Value>("update_source")
            .map_err(|e| miette::miette!("image(): update_source: {e}"))?
        {
            Value::String(s) => Some(
                s.to_str()
                    .map_err(|e| miette::miette!("image(): update_source: {e}"))?
                    .to_string(),
            ),
            Value::Nil => None,
            other => Err(miette::miette!(
                "image(): 'update_source' must be a string URL, got {}",
                other.type_name()
            ))?,
        };

        Ok(ImageDeclaration {
            name,
            version,
            base,
            kernel,
            gadget,
            gadget_channel,
            extra_snaps,
            bootloader,
            disk,
            sysctl,
            update_source,
        })
    }

    /// Collect all snap references (base + kernel + gadget + extras).
    pub fn all_snaps(&self) -> Vec<&SnapRef> {
        let mut snaps: Vec<&SnapRef> = vec![&self.base];
        if let Some(ref k) = self.kernel {
            snaps.push(&k.snap);
        }
        if let Some(ref g) = self.gadget {
            snaps.push(g);
        }
        for s in &self.extra_snaps {
            snaps.push(s);
        }
        snaps
    }
}

// ── Lua extraction helpers (for image tables) ──

fn get_required<T: mlua::FromLua>(table: &mlua::Table, key: &str) -> miette::Result<T> {
    table
        .get::<T>(key)
        .map_err(|e| miette::miette!("missing or invalid required field '{key}': {e}"))
}

fn get_opt_snap_ref(table: &mlua::Table, key: &str) -> miette::Result<Option<SnapRef>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => Ok(Some(SnapRef::from_pin_table(&t)?)),
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): '{key}' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

fn get_required_snap_ref(table: &mlua::Table, key: &str) -> miette::Result<SnapRef> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => Ok(SnapRef::from_pin_table(&t)?),
        other => Err(miette::miette!(
            "image(): required field '{key}' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

fn get_snap_ref_array(table: &mlua::Table, key: &str) -> miette::Result<Vec<SnapRef>> {
    match table
        .get::<Value>(key)
        .map_err(|e| miette::miette!("{key}: {e}"))?
    {
        Value::Table(t) => {
            let mut snaps = Vec::new();
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("{key}[n]: {e}"))?;
                match value {
                    Value::Table(tbl) => snaps.push(SnapRef::from_pin_table(&tbl)?),
                    other => {
                        return Err(miette::miette!(
                            "image(): each entry in '{key}' must be a pin, got {}",
                            other.type_name()
                        ));
                    }
                }
            }
            Ok(snaps)
        }
        Value::Nil => Ok(Vec::new()),
        other => Err(miette::miette!(
            "image(): '{key}' must be an array of pins, got {}",
            other.type_name()
        )),
    }
}

fn get_opt_kernel_entry(table: &mlua::Table) -> miette::Result<Option<KernelEntry>> {
    match table
        .get::<Value>("kernel")
        .map_err(|e| miette::miette!("kernel: {e}"))?
    {
        Value::Table(t) => {
            let snap = SnapRef::from_pin_table(&t)?;
            let params: Vec<String> = t.get("params").unwrap_or_default();
            let modules: Vec<String> = t.get("modules").unwrap_or_default();
            let modprobe_config: Option<String> = t.get("modprobe_config").ok();
            let channel = get_opt_pin_channel(table, "kernel")?;
            Ok(Some(KernelEntry {
                snap,
                params,
                modules,
                modprobe_config,
                channel,
            }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'kernel' must be a pin table, got {}",
            other.type_name()
        )),
    }
}

/// Read the ADR-0019 explicit `channel` opt off a kernel/gadget pin table
/// (`pin("pc-kernel", { channel = "22/stable" })`). The DSL passes unknown
/// pin fields through, so the opt reaches this boundary without being part
/// of [`SnapRef`]; an author-pinned channel escapes track derivation and
/// the declared-base check.
fn get_opt_pin_channel(table: &mlua::Table, key: &str) -> miette::Result<Option<String>> {
    match table.get::<Value>(key).unwrap_or(Value::Nil) {
        Value::Table(t) => match t.get::<Value>("channel").unwrap_or(Value::Nil) {
            Value::Nil => Ok(None),
            Value::String(s) => Ok(Some(
                s.to_str()
                    .map_err(|e| miette::miette!("{key}.channel: {e}"))?
                    .to_string(),
            )),
            other => Err(miette::miette!(
                "image(): '{key}.channel' must be a string, got {}",
                other.type_name()
            )),
        },
        _ => Ok(None),
    }
}

fn get_opt_bootloader(table: &mlua::Table) -> miette::Result<Option<BootloaderConfig>> {
    match table
        .get::<Value>("bootloader")
        .map_err(|e| miette::miette!("bootloader: {e}"))?
    {
        Value::Table(t) => {
            let type_: String = t.get("type").unwrap_or_else(|_| "systemd-boot".into());
            let timeout: u32 = t.get("timeout").unwrap_or(3);
            Ok(Some(BootloaderConfig { type_, timeout }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'bootloader' must be a table, got {}",
            other.type_name()
        )),
    }
}

fn get_opt_disk_layout(table: &mlua::Table) -> miette::Result<Option<DiskLayout>> {
    match table
        .get::<Value>("disk")
        .map_err(|e| miette::miette!("disk: {e}"))?
    {
        Value::Table(t) => {
            let label: String = t.get("label").unwrap_or_else(|_| "gpt".into());
            let partitions = get_partitions(&t)?;
            let swap = get_opt_swap(&t)?;
            // ADR-0011 step (d): opt-in A/B slots — default off so existing
            // (kernel-free, single-slot) definitions behave identically.
            let ab: bool = t.get("ab").unwrap_or(false);
            Ok(Some(DiskLayout {
                label,
                partitions,
                swap,
                ab,
            }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'disk' must be a table, got {}",
            other.type_name()
        )),
    }
}

fn get_partitions(table: &mlua::Table) -> miette::Result<Vec<Partition>> {
    let mut partitions = Vec::new();
    let parts: Value = table.get("partitions").unwrap_or(Value::Nil);
    match parts {
        Value::Table(t) => {
            for pair in t.pairs::<usize, Value>() {
                let (_, value) = pair.map_err(|e| miette::miette!("partitions[n]: {e}"))?;
                match value {
                    Value::Table(pt) => {
                        let name: String = pt
                            .get("name")
                            .map_err(|_| miette::miette!("partition: missing 'name'"))?;
                        let size: String = pt
                            .get("size")
                            .map_err(|_| miette::miette!("partition '{}': missing 'size'", name))?;
                        let fs: String = pt
                            .get("fs")
                            .map_err(|_| miette::miette!("partition '{}': missing 'fs'", name))?;
                        let mount: String = pt.get("mount").map_err(|_| {
                            miette::miette!("partition '{}': missing 'mount'", name)
                        })?;
                        let options: Vec<String> = pt.get("options").unwrap_or_default();
                        // UC gadget role (issue #32) — optional; only honored
                        // under a UC base.
                        let role: String = pt.get("role").unwrap_or_default();
                        partitions.push(Partition {
                            name,
                            size,
                            fs,
                            mount,
                            options,
                            role,
                        });
                    }
                    other => {
                        return Err(miette::miette!(
                            "each partition must be a table, got {}",
                            other.type_name()
                        ))
                    }
                }
            }
        }
        Value::Nil => {}
        other => {
            return Err(miette::miette!(
                "'partitions' must be a table, got {}",
                other.type_name()
            ))
        }
    }
    Ok(partitions)
}

fn get_opt_swap(table: &mlua::Table) -> miette::Result<Option<SwapConfig>> {
    match table
        .get::<Value>("swap")
        .map_err(|e| miette::miette!("swap: {e}"))?
    {
        Value::Table(t) => {
            let size: String = t.get("size").unwrap_or_else(|_| "0".into());
            Ok(Some(SwapConfig { size }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'disk.swap' must be a table, got {}",
            other.type_name()
        )),
    }
}

// ── Image output ──

/// Named image outputs from a `shuttle.lua`.
pub type ImageOutputs = HashMap<String, ImageDeclaration>;

// ── Image assembly pipeline ──

// ── ADR-0019: base-aware kernel/gadget resolution ──

/// The role an image snap plays; kernel and gadget snaps ride the image
/// base's store track (ADR-0019), base and extra snaps never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapRole {
    Base,
    Kernel,
    Gadget,
    Extra,
}

/// Derive the store channel track from an image base name:
/// "core22" → Some("22"), "core26" → Some("26"); bases without a numeric
/// series ("core", custom bases) derive nothing.
pub(crate) fn base_track(base_name: &str) -> Option<&str> {
    let series = base_name.strip_prefix("core")?;
    if !series.is_empty() && series.bytes().all(|b| b.is_ascii_digit()) {
        Some(series)
    } else {
        None
    }
}

/// Replace the track of a "track/risk" (or bare risk) channel, keeping the
/// risk: "latest/stable" + track "22" → "22/stable"; "stable" → "22/stable".
fn channel_on_track(channel: &str, track: &str) -> String {
    // Mirrors the StoreClient channel parse: one part is a risk, two parts
    // are track/risk.
    let risk = channel.split('/').nth(1).unwrap_or(channel);
    format!("{track}/{risk}")
}

/// The effective store channel for a kernel/gadget image snap (ADR-0019).
///
/// An author-pinned channel (`channel` opt on the pin entry) wins verbatim
/// and marks the override; otherwise the image base's track replaces the
/// default track ("core22" + "latest/stable" → "22/stable" — the
/// `latest` kernel line carries the legacy 4.4 ESM payloads); a base with
/// no numeric series leaves the channel untouched.
///
/// Returns `(channel, override_used)`.
fn image_snap_channel(
    default_channel: &str,
    base_name: &str,
    explicit: Option<&str>,
) -> (String, bool) {
    if let Some(explicit) = explicit {
        return (explicit.to_string(), true);
    }
    match base_track(base_name) {
        Some(track) => (channel_on_track(default_channel, track), false),
        None => (default_channel.to_string(), false),
    }
}

/// The declared `base:` of a downloaded snap's `meta/snap.yaml`, if the
/// metadata carries one.
#[derive(Debug, Deserialize)]
struct PayloadBase {
    #[serde(rename = "base")]
    base: Option<String>,
}

fn snap_yaml_base(yaml_text: &str) -> Option<String> {
    serde_yaml::from_str::<PayloadBase>(yaml_text)
        .ok()
        .and_then(|meta| meta.base)
        .filter(|b| !b.is_empty())
}

/// ADR-0019 backstop: a resolved kernel/gadget snap whose declared base
/// mismatches the image base fails the build, naming both. A snap with no
/// declared base skips the check (and says so) — store metadata quality is
/// outside shuttle's control.
fn check_declared_base(
    role: &str,
    snap_name: &str,
    declared_base: Option<&str>,
    image_base: &str,
) -> miette::Result<()> {
    match declared_base {
        None => {
            eprintln!(
                "  ℹ {role} {snap_name}: declares no base (or meta/snap.yaml unreadable) \
                 — ADR-0019 base check skipped"
            );
            Ok(())
        }
        Some(declared) if declared == image_base => Ok(()),
        Some(declared) => Err(miette::miette!(
            "{role} snap '{snap_name}' declares base '{declared}' but the image base is \
             '{image_base}' — refusing to pair them (ADR-0019): the mismatch is silent at \
             build time and bricks at first boot. To accept it deliberately, pin an \
             explicit channel on the {role} entry, e.g. \
             {role} = pin(\"{snap_name}\", {{ channel = \"latest/stable\" }})"
        )),
    }
}

/// Read the declared `base:` out of a downloaded snap payload by
/// single-file extracting `meta/snap.yaml` (same tool + flags as the
/// runtime emitter). `Ok(None)` means the metadata could not be read or
/// carries no base — the caller logs the skip.
fn payload_declared_base(payload: &Path) -> Option<String> {
    let work = tempfile::tempdir().ok()?;
    let extract_dir = work.path().join("extract");
    let status = std::process::Command::new("unsquashfs")
        .args([
            "-no-xattrs",
            "-d",
            &extract_dir.to_string_lossy(),
            &payload.to_string_lossy(),
            "meta/snap.yaml",
        ])
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let yaml_text = std::fs::read_to_string(extract_dir.join("meta").join("snap.yaml")).ok()?;
    snap_yaml_base(&yaml_text)
}

/// ADR-0019 enforcement point: after the kernel/gadget payloads are
/// downloaded and hash-verified, their declared `base:` must match the
/// image base (mismatch = build error) or be absent (logged skip). An
/// author-pinned channel is the recorded override for both the track
/// derivation and this check.
fn enforce_base_contract(
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    has_unsquashfs: bool,
) -> miette::Result<()> {
    let checks = [
        (
            image.kernel.as_ref().map(|k| k.snap.name.as_str()),
            "kernel",
            image.kernel.as_ref().and_then(|k| k.channel.as_ref()),
        ),
        (
            image.gadget.as_ref().map(|g| g.name.as_str()),
            "gadget",
            image.gadget_channel.as_ref(),
        ),
    ];
    for (entry, role, explicit) in checks {
        let Some(name) = entry else {
            continue;
        };
        if let Some(channel) = explicit {
            eprintln!(
                "  ⚠ {role} {name}: author-pinned channel '{channel}' — ADR-0019 base \
                 check skipped (recorded override)"
            );
            continue;
        }
        if !has_unsquashfs {
            eprintln!(
                "  ⚠ {role} {name}: unsquashfs unavailable — ADR-0019 declared-base \
                 check skipped"
            );
            continue;
        }
        let Some(snap) = resolved.iter().find(|s| s.name == name) else {
            continue;
        };
        let payload = cache_dir.join(format!(
            "{}_{}_{}.snap",
            snap.name, snap.revision, snap.sha3_384
        ));
        let declared_base = payload_declared_base(&payload);
        check_declared_base(role, name, declared_base.as_deref(), &image.base.name)?;
    }
    Ok(())
}

/// Resolve all snaps in an image declaration, using the lockfile for defaults.
///
/// Kernel and gadget snaps resolve from the image base's store track
/// (ADR-0019) unless the author pinned an explicit channel on the entry.
fn resolve_image_snaps(
    image: &ImageDeclaration,
    lockfile: &LockFile,
    channel: &str,
    arch: &str,
) -> miette::Result<Vec<ResolvedSnap>> {
    let mut resolved = Vec::new();

    let mut entries: Vec<(&SnapRef, SnapRole)> = vec![(&image.base, SnapRole::Base)];
    if let Some(ref k) = image.kernel {
        entries.push((&k.snap, SnapRole::Kernel));
    }
    if let Some(ref g) = image.gadget {
        entries.push((g, SnapRole::Gadget));
    }
    for s in &image.extra_snaps {
        entries.push((s, SnapRole::Extra));
    }

    for (snap_ref, role) in entries {
        let pin = if snap_ref.revision.is_none() || snap_ref.sha3_384.is_none() {
            if let Some(locked) = lockfile.lookup_snap(&snap_ref.name) {
                eprintln!("  ℹ {}: using lockfile pin", snap_ref.name);
                locked
            } else {
                snap_ref.clone()
            }
        } else {
            snap_ref.clone()
        };

        // ADR-0019: kernel/gadget snaps ride the image base's track unless
        // the author pinned an explicit channel on the entry.
        let (effective_channel, override_used) = match role {
            SnapRole::Kernel => image_snap_channel(
                channel,
                &image.base.name,
                image.kernel.as_ref().and_then(|k| k.channel.as_deref()),
            ),
            SnapRole::Gadget => {
                image_snap_channel(channel, &image.base.name, image.gadget_channel.as_deref())
            }
            SnapRole::Base | SnapRole::Extra => (channel.to_string(), false),
        };
        if override_used {
            eprintln!(
                "  ⚠ {}: author-pinned channel '{effective_channel}' — ADR-0019 track \
                 derivation + base check skipped (recorded override)",
                snap_ref.name
            );
        } else if matches!(role, SnapRole::Kernel | SnapRole::Gadget)
            && effective_channel != channel
        {
            eprintln!(
                "  ℹ {}: image base {} → channel {effective_channel} (ADR-0019)",
                snap_ref.name, image.base.name
            );
        }

        // Try Snap Store first, then fall back to package index
        let snap = match StoreClient::resolve(&pin, &effective_channel, arch) {
            Ok(s) => s,
            Err(_) => {
                // Try resolving through the package index
                let index_path = std::path::PathBuf::from(crate::index::DEFAULT_INDEX);
                if let Ok(idx) = crate::index::PackageIndex::load_or_default(&index_path) {
                    if let Some(entry) = idx.find_by_name_or_alias(&snap_ref.name) {
                        // Check if the index already has pre-resolved pins for this arch
                        if let Some(ref pins) = entry.pins {
                            if let Some(pin_entry) = pins.get(arch) {
                                eprintln!(
                                    "  ℹ {}: using pre-resolved pin from index (rev {})",
                                    snap_ref.name, pin_entry.revision
                                );
                                resolved.push(ResolvedSnap {
                                    name: snap_ref.name.clone(),
                                    revision: pin_entry.revision,
                                    sha3_384: pin_entry.sha3_384.clone(),
                                    download_url: String::new(),
                                });
                                continue;
                            }
                        }
                        // If index has a store name, try resolving with it.
                        // ADR-0019: the derived track wins over the index's
                        // store channel for kernel/gadget roles too — the
                        // empirical failure came from an index entry
                        // carrying the default `latest` track.
                        if let Some(ref store) = entry.store {
                            let store_name =
                                store.name.as_deref().unwrap_or(&snap_ref.name).to_string();
                            let resolved_pin = SnapRef {
                                name: store_name,
                                revision: pin.revision,
                                sha3_384: pin.sha3_384,
                            };
                            match StoreClient::resolve(&resolved_pin, &effective_channel, arch) {
                                Ok(s) => {
                                    eprintln!(
                                        "  ℹ {}: resolved via index (store: {})",
                                        snap_ref.name, resolved_pin.name
                                    );
                                    s
                                }
                                Err(e) => {
                                    return Err(miette::miette!(
                                        "cannot resolve '{}': not in Snap Store or package index ({})",
                                        snap_ref.name, e
                                    ));
                                }
                            }
                        } else {
                            return Err(miette::miette!(
                                "cannot resolve '{}': found in index but has no store reference",
                                snap_ref.name
                            ));
                        }
                    } else {
                        return Err(miette::miette!(
                            "cannot resolve '{}': not in Snap Store or package index",
                            snap_ref.name
                        ));
                    }
                } else {
                    return Err(miette::miette!(
                        "cannot resolve '{}': not in Snap Store",
                        snap_ref.name
                    ));
                }
            }
        };

        eprintln!(
            "  ✓ {} revision {} — sha3-384: {}",
            snap.name,
            snap.revision,
            &snap.sha3_384[..16]
        );
        resolved.push(snap);
    }

    Ok(resolved)
}

/// Build a rootfs image from an image declaration.
pub fn build_image(
    image: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
) -> miette::Result<PathBuf> {
    // 1. Resolve all snaps
    let resolved = resolve_image_snaps(image, lockfile, channel, arch)?;

    // 2. Download and verify all snaps
    let mut snap_paths: Vec<(String, ResolvedSnap)> = Vec::new();
    for snap in &resolved {
        let path = StoreClient::download(snap, cache_dir)?;
        StoreClient::verify(&path, &snap.sha3_384)?;
        eprintln!(
            "  ✓ {} revision {} — sha3-384 verified",
            snap.name, snap.revision
        );
        snap_paths.push((snap.name.clone(), snap.clone()));
    }

    // 3. Check tool availability
    let has_unsquashfs = std::process::Command::new("which")
        .arg("unsquashfs")
        .output()
        .ok()
        .is_some_and(|o| o.status.success());

    // 3a. ADR-0019: the kernel/gadget payloads must declare the image's
    // base — mismatch fails the build before anything is assembled.
    enforce_base_contract(image, &resolved, cache_dir, has_unsquashfs)?;

    // 4. Create staging directory
    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {e}"))?;
    let root = build_dir.path().to_path_buf(); // owned path

    // 5. Extract base snap as rootfs foundation
    let base_snap_name = &image.base.name;
    let base_snap = resolved
        .iter()
        .find(|s| s.name == *base_snap_name)
        .ok_or_else(|| miette::miette!("base snap '{base_snap_name}' not resolved"))?;

    let base_filename = format!(
        "{}_{}_{}.snap",
        base_snap.name, base_snap.revision, base_snap.sha3_384
    );
    let base_path = cache_dir.join(&base_filename);

    if has_unsquashfs {
        // Make sure the dir is empty before extraction
        eprintln!("  extracting base snap into {:?}", root);
        let status = std::process::Command::new("unsquashfs")
            .args([
                "-d",
                &root.to_string_lossy(),
                "-no-xattrs",
                &base_path.to_string_lossy(),
            ])
            .status()
            .map_err(|e| miette::miette!("unsquashfs not found: {e}"))?;

        let exit_code = status.code().unwrap_or(1);
        if exit_code >= 128 {
            return Err(miette::miette!(
                "failed to unsquashfs base snap '{}' (exit {exit_code})",
                image.base.name
            ));
        }
        if exit_code != 0 {
            eprintln!("  ⚠ unsquashfs warnings (exit {exit_code}) — files should be extracted");
        }
    } else {
        eprintln!("  ⚠ unsquashfs not found — base snap not extracted");
    }

    // 5b. Verify rootfs was actually extracted
    let has_rootfs = root.join("bin").exists() || root.join("usr").exists();
    if has_rootfs {
        eprintln!("  ✓ rootfs extracted ({})", image.base.name);
    } else {
        eprintln!("  ⚠ no rootfs files found — check unsquashfs");
    }

    // 6. Merge kernel snap if provided
    if let Some(ref kernel_entry) = image.kernel {
        if has_unsquashfs {
            let kernel_snap = resolved.iter().find(|s| s.name == kernel_entry.snap.name);
            if let Some(ks) = kernel_snap {
                let k_filename = format!("{}_{}_{}.snap", ks.name, ks.revision, ks.sha3_384);
                let kpath = cache_dir.join(&k_filename);

                eprintln!("  merging kernel snap: {}", kernel_entry.snap.name);
                let kernel_img = tempfile::tempdir().map_err(|e| miette::miette!("{e}"))?;
                let kernel_dir = kernel_img.path().to_path_buf();

                let status = std::process::Command::new("unsquashfs")
                    .args([
                        "-d",
                        &kernel_dir.to_string_lossy(),
                        "-no-xattrs",
                        &kpath.to_string_lossy(),
                    ])
                    .status()
                    .map_err(|e| miette::miette!("unsquashfs: {e}"))?;

                let krn_exit = status.code().unwrap_or(1);
                if krn_exit < 128 {
                    for dir in ["lib/modules", "lib/firmware"] {
                        let src = kernel_dir.join(dir);
                        let dst = root.join(dir);
                        if src.exists() {
                            std::fs::create_dir_all(dst.parent().unwrap())
                                .into_diagnostic()
                                .wrap_err_with(|| format!("creating {dir}"))?;
                            cp_r(&src, &dst)?;
                        }
                    }
                }
            }
        }
    }

    // 6b. Write kernel cmdline if params provided
    if let Some(ref kernel_entry) = image.kernel {
        if !kernel_entry.params.is_empty() {
            let cmdline = kernel_entry.params.join(" ");
            let kernel_dir = root.join("etc");
            std::fs::create_dir_all(&kernel_dir)
                .into_diagnostic()
                .wrap_err("creating /etc")?;
            std::fs::write(kernel_dir.join("kernelcmdline"), &cmdline)
                .into_diagnostic()
                .wrap_err("writing kernel cmdline")?;
            eprintln!("  ✓ kernel cmdline: {cmdline}");
        }
    }

    // 6c. Write sysctl if provided
    if !image.sysctl.is_empty() {
        let sysctl_dir = root.join("etc").join("sysctl.d");
        std::fs::create_dir_all(&sysctl_dir)
            .into_diagnostic()
            .wrap_err("creating /etc/sysctl.d")?;
        let sysctl_content = image.sysctl.join("\n") + "\n";
        std::fs::write(sysctl_dir.join("99-shuttle.conf"), &sysctl_content)
            .into_diagnostic()
            .wrap_err("writing sysctl")?;
        eprintln!("  ✓ sysctl written ({} entries)", image.sysctl.len());
    }

    // 7. Create snap directory and copy all snap files
    let snap_dir = root.join("snap");
    std::fs::create_dir_all(&snap_dir)
        .into_diagnostic()
        .wrap_err("creating snap/ directory")?;

    for (name, snap) in &snap_paths {
        let filename = format!("{}_{}_{}.snap", name, snap.revision, snap.sha3_384);
        let cache_path = cache_dir.join(&filename);
        let dest = snap_dir.join(&filename);
        if cache_path.exists() {
            std::fs::copy(&cache_path, &dest)
                .into_diagnostic()
                .wrap_err_with(|| format!("copying {name} snap"))?;
        }
    }

    // 8. Write manifest — the squashfs path has no ESP/UKI, so no boot facts
    let manifest_path = root.join("image-manifest.json");
    let manifest = ImageManifest::from_resolved(image, &snap_paths, arch, None);
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| miette::miette!("failed to serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, &manifest_json)
        .into_diagnostic()
        .wrap_err("writing manifest")?;

    // 9. Pack into output SquashFS
    let output_filename = if arch == "all" {
        format!("{}_{}.img", image.name, image.version)
    } else {
        format!("{}_{}_{}.img", image.name, image.version, arch)
    };
    let output_path = output_dir.join(&output_filename);

    std::fs::create_dir_all(output_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating output dir {:?}", output_dir))?;

    let mut mksquashfs = std::process::Command::new("mksquashfs");
    mksquashfs
        .arg(&root)
        .arg(&output_path)
        .arg("-noappend")
        .arg("-comp")
        .arg("xz")
        .arg("-all-root");

    let status = mksquashfs
        .status()
        .map_err(|e| miette::miette!("mksquashfs not found: {e}"))?;

    if !status.success() {
        return Err(miette::miette!(
            "mksquashfs exited with error while creating image"
        ));
    }

    // 10. Update lockfile with resolved snaps
    for snap in &resolved {
        lockfile.record_snap(&snap.to_snap_ref());
    }

    eprintln!("  ✓ image built: {output_filename}");

    Ok(output_path)
}

/// Build a full disk image with partitions — fully unprivileged: every
/// partition is built as a standalone file at its read-back extent and
/// spliced into the image; no loop device is attached and nothing is
/// mounted.
///
/// ADR-0011 step (a): when a kernel is declared, a UKI (Unified Kernel
/// Image) is assembled with `ukify` and installed on the ESP at
/// `EFI/Linux/<name>_<version>.efi` alongside a `loader/loader.conf`, so
/// declared kernel params land on the real boot cmdline. ADR-0011 step (c):
/// the root partition file is populated first, then dm-verity is formatted
/// over the quiescent file (`veritysetup`) into an auto-appended hash
/// partition, and the captured roothash is embedded in the UKI cmdline
/// (explicit `systemd.verity_root_data`/`systemd.verity_root_hash`
/// by-partuuid devices — boot needs no dm-verity type GUIDs). Every
/// condition that would yield an unbootable or unverifiable image —
/// missing ukify, missing sd-stub, missing veritysetup, missing mtools or
/// mkfs tools, no kernel payload, no root partition — fails closed, before
/// any partition is formatted.
pub fn build_disk_image(
    image: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
) -> miette::Result<PathBuf> {
    // 1. Resolve all snaps
    let resolved = resolve_image_snaps(image, lockfile, channel, arch)?;

    // 2. Download and verify all snaps
    let mut snap_paths: Vec<(String, ResolvedSnap)> = Vec::new();
    for snap in &resolved {
        let path = StoreClient::download(snap, cache_dir)?;
        StoreClient::verify(&path, &snap.sha3_384)?;
        eprintln!(
            "  ✓ {} revision {} — sha3-384 verified",
            snap.name, snap.revision
        );
        snap_paths.push((snap.name.clone(), snap.clone()));
    }

    let has_unsquashfs = std::process::Command::new("which")
        .arg("unsquashfs")
        .output()
        .ok()
        .is_some_and(|o| o.status.success());

    // ADR-0019: the kernel/gadget payloads must declare the image's base —
    // mismatch fails the build before anything is assembled.
    enforce_base_contract(image, &resolved, cache_dir, has_unsquashfs)?;

    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {e}"))?;
    let root = build_dir.path().to_path_buf();
    // Scratch dir for build ARTIFACTS (disk.img, standalone partition files,
    // UKI stage, kernel-snap extraction) — deliberately separate from
    // build_dir, because build_dir IS the staged rootfs: anything left here
    // would be copied into the partitions by `mkfs.ext4 -d`.
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create scratch directory: {e}"))?;

    // 3. Extract base snap and merge the kernel payload
    let kernel_payload = extract_base_and_kernel(
        image,
        &resolved,
        cache_dir,
        &root,
        scratch.path(),
        has_unsquashfs,
    )?;

    // 4. Write kernel cmdline (legacy etc/kernelcmdline echo — the real
    // boot cmdline now lives in the UKI, step 8)
    if let Some(ref kernel_entry) = image.kernel {
        if !kernel_entry.params.is_empty() {
            let cmdline = kernel_entry.params.join(" ");
            let kernel_dir = root.join("etc");
            std::fs::create_dir_all(&kernel_dir).into_diagnostic()?;
            std::fs::write(kernel_dir.join("kernelcmdline"), &cmdline).into_diagnostic()?;
            eprintln!("  ✓ kernel cmdline: {cmdline}");
        }
    }

    // 5. Write sysctl
    if !image.sysctl.is_empty() {
        let sysctl_dir = root.join("etc").join("sysctl.d");
        std::fs::create_dir_all(&sysctl_dir).into_diagnostic()?;
        let sysctl_content = image.sysctl.join("\n") + "\n";
        std::fs::write(sysctl_dir.join("99-shuttle.conf"), &sysctl_content).into_diagnostic()?;
        eprintln!("  ✓ sysctl written ({} entries)", image.sysctl.len());
    }

    let disk_layout = image
        .disk
        .as_ref()
        .ok_or_else(|| miette::miette!("disk() must declare partitions for disk image"))?;

    let output_filename = if arch == "all" {
        format!("{}_{}.img", image.name, image.version)
    } else {
        format!("{}_{}_{}.img", image.name, image.version, arch)
    };
    let output_path = output_dir.join(&output_filename);
    std::fs::create_dir_all(output_dir).into_diagnostic()?;

    // 5c. ADR-0011 step (d): systemd-sysupdate transfer files into the
    // staged rootfs (both slots carry them). Emitted only for a declared
    // update_source — a local-source transfer would carry no verification,
    // and unverifiable update config is never emitted silently.
    if let Some(ref disk) = image.disk {
        if disk.ab {
            if image.update_source.is_some() {
                write_sysupdate_transfers(&root, image, disk)?;
            } else {
                eprintln!(
                    "  ℹ disk.ab = true without update_source — sysupdate transfer \
                     files skipped (a local-source transfer carries no verification)"
                );
            }
        }
    }

    // 5d. ADR-0011 step (d): when the image declares an update source, the
    // update public key is embedded for the device-side verify path
    // (/etc/shuttle/update-key.pub). A missing local key is created here —
    // a build with an update source is a deliberate signing engagement.
    if image.update_source.is_some() {
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        let kp = match crate::sign::load_secret_key(&home)? {
            Some(kp) => kp,
            None => crate::sign::create_secret_key(&home)?,
        };
        let key_path = root.join(crate::sign::PUBKEY_EMBED_PATH);
        std::fs::create_dir_all(key_path.parent().unwrap()).into_diagnostic()?;
        std::fs::write(&key_path, crate::sign::public_key_file(&kp)).into_diagnostic()?;
        eprintln!(
            "  ✓ update public key embedded: /{} (key id {})",
            crate::sign::PUBKEY_EMBED_PATH,
            kp.key_id()
        );
    }

    // 5e. ADR-0011 step (f), Phase 24a: app execution — materialize the
    // command binaries of shoot-built app snaps into /usr/bin/<snap>-<app>
    // and emit hardened systemd units (plus enablement) for
    // daemon-bearing apps. Written here, after payload staging and BEFORE
    // root populate + dm-verity: binaries and units must be inside the
    // hashed tree — the same write-before-hash constraint as the manifest.
    crate::units::emit_app_runtime(&snap_paths, cache_dir, &root, has_unsquashfs)?;

    // 6. ADR-0011 step (c) pre-flight — kernel images need ukify, the
    // sd-stub, and veritysetup; fail closed BEFORE any destructive step
    // (dd/parted/mkfs), so an unbootable or unverifiable image is never
    // half-written. The kernel config audit is warn-only: dm-verity needs
    // CONFIG_DM_VERITY=y, but a config-less payload is common and the
    // kernel decides at boot, so the audit never fails the build.
    let verity = image.kernel.is_some();
    if verity {
        preflight_disk_tools_with(
            find_ukify().as_deref(),
            find_efi_stub().as_deref(),
            find_veritysetup().as_deref(),
        )?;
        if let Some(payload) = kernel_payload.as_ref() {
            doctor::audit_kernel_verity_config(&root, &payload.version);
        }
    }

    // 6a. Unprivileged populate pre-flight — the standalone-partition-file
    // build formats and fills partitions with these host tools and leaves
    // no loop device behind that could hide a missing one; fail closed
    // BEFORE dd, mirroring the verity pre-flight above.
    let populate_tools = [
        ("sfdisk", find_host_tool("sfdisk")),
        ("mmd", find_host_tool("mmd")),
        ("mcopy", find_host_tool("mcopy")),
        ("mkfs.ext4", find_host_tool("mkfs.ext4")),
        ("mkfs.vfat", find_host_tool("mkfs.vfat")),
    ];
    preflight_populate_tools_with(&populate_tools)?;

    // 6b. Effective layout: kernel images get a dm-verity hash partition
    // appended after the declared partitions, and `disk.ab = true` clones
    // the root (+ hash) into slot B — existing indices never shift and the
    // parted flow is untouched.
    let mut effective_layout = disk_layout.clone();
    let slots = expand_ab_slots(&mut effective_layout, verity)?;
    if slots.roots.len() > 1 {
        eprintln!(
            "  ✓ A/B slots: root at partitions {:?} (+ hash partitions {:?})",
            slots.roots.iter().map(|i| i + 1).collect::<Vec<_>>(),
            slots
                .hashes
                .iter()
                .flatten()
                .map(|i| i + 1)
                .collect::<Vec<_>>(),
        );
    }

    // 6c. Ubuntu Core seed/role-model wiring (issue #32): when the image
    // base is a UC coreN base AND the layout marks a partition with a UC
    // gadget role (system-seed/boot/data), remap those partitions to their
    // UC PARTLABELs and stage the seed + modeenv trees. The role remap
    // happens BEFORE partitioning so the parted-created GPT PARTLABELs come
    // out as `ubuntu-seed`/`ubuntu-boot`/`ubuntu-data`. Non-UC bases (and
    // coreN bases without a role-marked partition) are untouched, keeping
    // the simplified path bit-identical.
    let uc = setup_uc_context(
        image,
        &mut effective_layout,
        scratch.path(),
        arch,
        &resolved,
    )?;

    // Calculate total image size: sum partitions + swap + 4M for GPT headers
    let total_mb = calculate_disk_size_mb(&effective_layout);
    eprintln!("  creating disk image: {} MB", total_mb);

    // 7. Create and partition the raw image — GPT PARTUUIDs exist from
    // parted mkpart time, before anything is formatted or copied.
    let img_path = scratch.path().join("disk.img");
    create_partitions(&img_path, &effective_layout, total_mb)?;
    // ADR-0011 step (d): A/B layouts additionally get GPT partition type
    // GUIDs + PARTLABELs so systemd-sysupdate can match the slots.
    apply_gpt_slot_metadata(&img_path, image, &effective_layout, &slots)?;

    // 8. Read back the authoritative partition extents with one `sfdisk -J`
    // call — parted's "MB" units are decimal (10^6) and sector-aligned
    // ("36MB" lands on sector 69632), so the in-memory MB ledger is never
    // trusted for byte offsets. Every partition needing content is then
    // built as a standalone file at its exact extent size and spliced in.
    let expected_partitions = effective_layout.partitions.len()
        + usize::from(
            effective_layout
                .swap
                .as_ref()
                .is_some_and(|s| parse_size_mb(&s.size, 0) > 0),
        );
    let extents = read_partition_extents(&img_path, expected_partitions)?;
    eprintln!(
        "  ✓ partition table read back: {} partitions at verified extents",
        extents.len()
    );

    // 9. ADR-0011 step (c): the pipeline order below is mandatory — the
    // root partition file is populated first and stays quiescent, then
    // dm-verity formats the file (the data device must be final before
    // hashing; a cmdline is immutable once the UKI is later signed), then
    // the UKI embeds the captured roothash in its cmdline.
    let (uki, uki_stage, populated_roots) = if verity {
        // 9a. Rootfs-level manifest only: boot facts (cmdline, roothash) are
        // unknowable until after verity format, and a post-format write
        // would break the Merkle tree. The root partition therefore carries
        // the content manifest; the authoritative boot-facts manifest is
        // written below and lands on the remaining partitions.
        write_manifest(&root, image, &snap_paths, arch, None)?;
        // 9b-c. The root partition FILE is built once — populated and then
        // dm-verity-formatted (data quiescent) — and spliced into slot A;
        // A/B layouts splice byte-identical copies into every other slot.
        // Same data + same explicit salt (`shared_salt`) by construction:
        // one format, one roothash, identical bytes behind every slot —
        // the historical per-slot roothash-match assert is subsumed, and
        // slot B stays a usable day-one rollback twin.
        let shared_salt = if effective_layout.ab {
            Some(random_salt_hex()?)
        } else {
            None
        };
        let root_idx = slots.roots[0];
        refuse_non_ext4_vfat(&effective_layout.partitions[root_idx])?;
        let part_label = format!("{}_{}_{}", image.name, image.version, slot_suffix(0));
        // 9a. Rootfs-level manifest only: boot facts (cmdline, roothash) are
        // unknowable until after verity format, and a post-format write would
        // break the Merkle tree. The root partition therefore carries the
        // content manifest (boot = None); the authoritative boot-facts
        // manifest is written below and lands on the remaining partitions.
        write_manifest(&root, image, &snap_paths, arch, None)?;
        // Unprivileged populate prerequisite: snap packaging ships sentinel
        // dirs with no-owner-read modes (snapd's `var/lib/snapd/void` is
        // 111 --x--x--x), which `mkfs.ext4 -d` cannot scan without root.
        // Normalize to owner-accessible (u+rwX) before any `-d` populate;
        // the adjusted modes are what the filesystem — and the verity hash
        // over it — will carry.
        let status = std::process::Command::new("chmod")
            .args(["-R", "u+rwX", root.to_string_lossy().as_ref()])
            .status()
            .map_err(|e| miette::miette!("chmod not found: {e}"))?;
        if !status.success() {
            return Err(miette::miette!(
                "chmod -R u+rwX failed on the staged rootfs — refusing to populate \
                 from a tree mkfs cannot scan"
            ));
        }
        let root_file = extent_file(scratch.path(), "root.img", &extents[root_idx])?;
        // Root populate failure fails closed (exit status carries it): an
        // empty verity data device would brick the boot — unlike the
        // historical silent-skip on the other partitions.
        build_ext4_partition(
            &root_file,
            &root,
            &effective_layout.partitions[root_idx],
            &extents[root_idx],
            true,
        )?;
        eprintln!(
            "  ✓ {}: {} populated (slot a / {part_label}, standalone file)",
            effective_layout.partitions[root_idx].name, effective_layout.partitions[root_idx].fs
        );
        let hash_idx = slots.hashes[0].expect("verity ⇒ hash partition was appended");
        let hash_file = extent_file(scratch.path(), "verity-hash.img", &extents[hash_idx])?;
        let roothash = verity_format(
            &root_file.to_string_lossy(),
            &hash_file.to_string_lossy(),
            shared_salt.as_deref(),
        )?;
        eprintln!(
            "  ✓ dm-verity formatted over {} (slot a / {part_label})",
            root_file.display()
        );
        splice_into(&img_path, &root_file, &extents[root_idx])?;
        splice_into(&img_path, &hash_file, &extents[hash_idx])?;
        for (s, &r) in slots.roots.iter().enumerate().skip(1) {
            let h = slots.hashes[s].expect("verity ⇒ hash partition was appended");
            splice_into(&img_path, &root_file, &extents[r])?;
            splice_into(&img_path, &hash_file, &extents[h])?;
            eprintln!(
                "  ✓ slot {} spliced byte-identical from slot a (rollback twin)",
                slot_suffix(s)
            );
        }
        // The UKI boots slot A: its hash PARTUUID is slot A's hash extent.
        let hash_partuuid = extents[hash_idx].partuuid.clone();
        if hash_partuuid.is_none() {
            eprintln!(
                "  ⚠ hash PARTUUID unresolvable — cmdline carries the documented \
                 nil-GUID placeholder"
            );
        }
        let verity_args = VerityBootArgs {
            roothash,
            hash_partuuid,
        };
        // 9d. ADR-0011 step (a): assemble the UKI with the verity trailer;
        // `root=` stays slot A (first declared root).
        let (uki, stage) = assemble_uki(
            image,
            kernel_payload.as_ref(),
            &extents,
            &effective_layout,
            scratch.path(),
            Some(&verity_args),
        )?;
        (uki, stage, slots.skip_indices())
    } else {
        // Kernel-free images boot without a UKI — no verity, no trailer.
        let (uki, stage) = assemble_uki(
            image,
            kernel_payload.as_ref(),
            &extents,
            &effective_layout,
            scratch.path(),
            None,
        )?;
        (uki, stage, slots.skip_indices())
    };

    // 10. Write the authoritative manifest — threaded with the boot facts
    // the image boots with, including the dm-verity roothash (step (c)).
    write_manifest(&root, image, &snap_paths, arch, uki.as_ref())?;

    // 11. Format and populate the remaining partitions as standalone files
    // spliced at their read-back extents — the ESP gets the UKI +
    // loader.conf via mtools (no mount); other data partitions receive the
    // staged rootfs (with the authoritative manifest) through `mkfs.ext4
    // -d`. The root slots and verity-hash partitions are skipped: they were
    // populated and verity-formatted above (slot B's spliced bytes make it
    // the rollback twin).
    let populate = PopulateCtx {
        image,
        extents: &extents,
        scratch_dir: scratch.path(),
        root: &root,
        uki: uki.as_ref(),
        uki_stage: &uki_stage,
        uc: uc.as_ref(),
    };
    populate_remaining_partitions(&populate, &effective_layout, &populated_roots)?;

    // 12. Copy final image to output
    std::fs::copy(&img_path, &output_path).into_diagnostic()?;
    eprintln!(
        "  ✓ disk image built: {} ({} MB)",
        output_filename, total_mb
    );

    // 13. Update lockfile
    for snap in &resolved {
        lockfile.record_snap(&snap.to_snap_ref());
    }

    Ok(output_path)
}

/// Extract the base snap as the rootfs foundation, then merge the kernel
/// snap's modules/firmware. Returns the located kernel boot payload when a
/// kernel is declared; the payload feeds UKI assembly (ADR-0011 step (a))
/// later in the build.
fn extract_base_and_kernel(
    image: &ImageDeclaration,
    resolved: &[ResolvedSnap],
    cache_dir: &Path,
    root: &Path,
    work_dir: &Path,
    has_unsquashfs: bool,
) -> miette::Result<Option<KernelPayload>> {
    // 3a. Extract base snap
    let base_snap = resolved
        .iter()
        .find(|s| s.name == image.base.name)
        .ok_or_else(|| miette::miette!("base snap '{}' not resolved", image.base.name))?;
    let base_filename = format!(
        "{}_{}_{}.snap",
        base_snap.name, base_snap.revision, base_snap.sha3_384
    );
    let base_path = cache_dir.join(&base_filename);

    if has_unsquashfs {
        eprintln!("  extracting base snap into {:?}", root);
        let status = std::process::Command::new("unsquashfs")
            .args([
                "-d",
                &root.to_string_lossy(),
                "-no-xattrs",
                &base_path.to_string_lossy(),
            ])
            .status()
            .map_err(|e| miette::miette!("unsquashfs not found: {e}"))?;
        let exit_code = status.code().unwrap_or(1);
        if exit_code >= 128 {
            return Err(miette::miette!(
                "failed to unsquashfs base snap '{}'",
                image.base.name
            ));
        }
    }

    // 3b. Merge kernel modules and locate the boot payload
    let Some(kernel_entry) = image.kernel.as_ref() else {
        return Ok(None);
    };
    let Some(ks) = resolved.iter().find(|s| s.name == kernel_entry.snap.name) else {
        return Ok(None);
    };
    let k_filename = format!("{}_{}_{}.snap", ks.name, ks.revision, ks.sha3_384);
    let kpath = cache_dir.join(&k_filename);
    eprintln!("  merging kernel snap: {}", kernel_entry.snap.name);
    let kernel_dir = work_dir.join("kernel-snap");
    let status = std::process::Command::new("unsquashfs")
        .args([
            "-d",
            &kernel_dir.to_string_lossy(),
            "-no-xattrs",
            &kpath.to_string_lossy(),
        ])
        .status()
        .map_err(|e| miette::miette!("unsquashfs: {e}"))?;
    if status.code().unwrap_or(1) >= 128 {
        return Err(miette::miette!(
            "failed to unsquashfs kernel snap '{}'",
            kernel_entry.snap.name
        ));
    }
    for dir in ["lib/modules", "lib/firmware"] {
        let src = kernel_dir.join(dir);
        let dst = root.join(dir);
        if src.exists() {
            std::fs::create_dir_all(dst.parent().unwrap()).into_diagnostic()?;
            cp_r(&src, &dst)?;
        }
    }
    // Fail closed on a payload that cannot boot the image.
    let payload = locate_kernel_payload(&kernel_dir, root).map_err(|e| {
        miette::miette!(
            "kernel snap '{}': {e}; refusing to build a disk image that cannot boot",
            kernel_entry.snap.name
        )
    })?;
    Ok(Some(payload))
}

/// GPT partition name passed to `parted mkpart` — the partition's declared
/// `name` becomes BOTH the GPT PARTLABEL (matched by the UC initrd's
/// `90-ubuntu-core-partitions.rules` as `ID_PART_ENTRY_NAME`) and the mkfs
/// filesystem label, so the two never diverge. For GPT labels the first
/// positional arg after `mkpart` IS the partition name; for MBR (msdos)
/// labels it is the partition TYPE, which the code always hardcodes to
/// `"primary"`. A partition with no declared name defaults to `"primary"`
/// so existing non-UC images are byte-identical.
fn mkpart_name(label: &str, part: &Partition) -> String {
    if label == "gpt" {
        if part.name.is_empty() {
            "primary".to_string()
        } else {
            part.name.clone()
        }
    } else {
        "primary".to_string()
    }
}

/// Build the `parted mkpart` argv for one partition (name, fs-type, start,
/// end) so the GPT PARTLABEL source is unit-testable without running
/// parted. `mkpart_name` supplies the partition name / MBR type.
fn parted_mkpart_args(
    img_path: &Path,
    label: &str,
    part: &Partition,
    start_mb: u64,
    end_mb: u64,
) -> Vec<String> {
    let fs_type = if part.fs == "vfat" {
        "fat32".to_string()
    } else {
        part.fs.clone()
    };
    vec![
        "-s".to_string(),
        img_path.to_string_lossy().into_owned(),
        "mkpart".to_string(),
        mkpart_name(label, part),
        fs_type,
        format!("{start_mb}MB"),
        format!("{end_mb}MB"),
    ]
}

/// Create the raw disk image with dd, lay out partitions with parted, and
/// set the ESP flag on the first partition.
fn create_partitions(img_path: &Path, layout: &DiskLayout, total_mb: u64) -> miette::Result<()> {
    let status = std::process::Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", img_path.display()),
            "bs=1M",
            &format!("count={total_mb}"),
        ])
        .status()
        .map_err(|e| miette::miette!("dd not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("dd failed to create disk image"));
    }

    let status = std::process::Command::new("parted")
        .args(["-s", &img_path.to_string_lossy(), "mklabel", &layout.label])
        .status()
        .map_err(|e| miette::miette!("parted not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("parted failed to create partition table"));
    }

    let mut part_start_mb = 4u64; // after GPT
    for (part_num, part) in layout.partitions.iter().enumerate() {
        let size_mb = parse_size_mb(&part.size, total_mb - part_start_mb);
        let end_mb = part_start_mb + size_mb;

        let status = std::process::Command::new("parted")
            .args(parted_mkpart_args(
                img_path,
                &layout.label,
                part,
                part_start_mb,
                end_mb,
            ))
            .status()
            .map_err(|e| miette::miette!("parted: {e}"))?;
        if !status.success() {
            return Err(miette::miette!(
                "parted failed to create partition '{}'",
                part.name
            ));
        }

        if part_num == 0 {
            set_esp_flag(img_path);
        }

        part_start_mb = end_mb;
    }

    if let Some(ref swap) = layout.swap {
        create_swap_partition(img_path, swap, part_start_mb)?;
    }
    Ok(())
}

/// Set the GPT esp flag on partition 1; a failure is reported but not
/// fatal (matching the historical behavior — the vfat fs still works).
fn set_esp_flag(img_path: &Path) {
    let status = std::process::Command::new("parted")
        .args(["-s", &img_path.to_string_lossy(), "set", "1", "esp", "on"])
        .status();
    if !status.is_ok_and(|s| s.success()) {
        eprintln!("  ⚠ failed to set ESP flag");
    }
}

/// Add the declared swap partition (if any) after the data partitions.
fn create_swap_partition(
    img_path: &Path,
    swap: &SwapConfig,
    part_start_mb: u64,
) -> miette::Result<()> {
    let swap_size = parse_size_mb(&swap.size, 0);
    if swap_size == 0 {
        return Ok(());
    }
    let end_mb = part_start_mb + swap_size;
    let status = std::process::Command::new("parted")
        .args([
            "-s",
            &img_path.to_string_lossy(),
            "mkpart",
            "primary",
            "linux-swap",
            &format!("{}MB", part_start_mb),
            &format!("{}MB", end_mb),
        ])
        .status()
        .map_err(|e| miette::miette!("parted: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("parted failed to create swap partition"));
    }
    Ok(())
}

/// One partition's authoritative geometry + GPT PARTUUID, read back from
/// the finished partition table. `start_bytes`/`size_bytes` are derived
/// from sfdisk's 512-byte-sector `start`/`size` fields (scaled by the
/// table's reported sector-size when present); the vec index equals the
/// parted partition number - 1.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PartitionExtent {
    start_bytes: u64,
    size_bytes: u64,
    partuuid: Option<String>,
}

/// Parse `sfdisk -J` JSON into partition extents. Fail closed: a missing
/// partitiontable, a missing/invalid start or size, or unparseable JSON is
/// an error — a guessed offset would splice a filesystem over the wrong
/// partition.
fn parse_partition_extents(json: &str) -> miette::Result<Vec<PartitionExtent>> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        miette::miette!(
            "sfdisk -J printed unparseable JSON ({e}) — refusing to guess partition offsets"
        )
    })?;
    let table = value.get("partitiontable").ok_or_else(|| {
        miette::miette!(
            "sfdisk -J output carries no 'partitiontable' — refusing to guess \
             partition offsets"
        )
    })?;
    let sector_size = table
        .get("sector-size")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(512);
    let partitions = table
        .get("partitions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            miette::miette!(
                "sfdisk -J output carries no 'partitiontable.partitions' array — \
                 refusing to guess partition offsets"
            )
        })?;
    partitions
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let sector = |key: &str| -> miette::Result<u64> {
                part.get(key)
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        miette::miette!(
                            "sfdisk -J partition {} carries no valid '{key}' sector \
                             field — refusing to guess partition offsets",
                            i + 1
                        )
                    })
            };
            Ok(PartitionExtent {
                start_bytes: sector("start")? * sector_size,
                size_bytes: sector("size")? * sector_size,
                partuuid: part
                    .get("uuid")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect()
}

/// Read the authoritative partition geometry back from the finished image
/// with one `sfdisk -J` call. `expected` is the partition count
/// [`create_partitions`] laid out (declared partitions + swap); a mismatch
/// fails closed — populating from misaligned extents would corrupt
/// neighboring partitions.
fn read_partition_extents(
    img_path: &Path,
    expected: usize,
) -> miette::Result<Vec<PartitionExtent>> {
    let out = std::process::Command::new("sfdisk")
        .args(["-J", &img_path.to_string_lossy()])
        .output()
        .map_err(|e| miette::miette!("sfdisk not found: {e}"))?;
    if !out.status.success() {
        return Err(miette::miette!(
            "sfdisk -J failed reading back the partition table ({}): {}",
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let extents = parse_partition_extents(&String::from_utf8_lossy(&out.stdout))?;
    if extents.len() != expected {
        return Err(miette::miette!(
            "partition table read-back found {} partitions but the layout created \
             {expected} — refusing to populate from misaligned extents",
            extents.len()
        ));
    }
    Ok(extents)
}

/// Shared context for the populate stage — everything the per-partition
/// workers need besides the partition itself. Partition geometry comes
/// from the read-back [`PartitionExtent`]s; every partition is built as a
/// standalone file and spliced, so nothing here is a device path.
struct PopulateCtx<'a> {
    image: &'a ImageDeclaration,
    extents: &'a [PartitionExtent],
    scratch_dir: &'a Path,
    root: &'a Path,
    uki: Option<&'a UkiFacts>,
    uki_stage: &'a Path,
    /// Ubuntu Core seed/role-model staging (issue #32). `None` for the
    /// non-UC/unsimplified path — content routing falls back to the
    /// historical behavior.
    uc: Option<&'a UcCtx>,
}

/// Ubuntu Core seed/role-model context threaded into the populate stage.
/// Carries the staged seed tree (`ubuntu-seed`) and boot tree
/// (`ubuntu-boot` with `device/modeenv`) built by [`setup_uc_context`].
struct UcCtx {
    seed_stage: PathBuf,
    boot_stage: PathBuf,
}

impl PopulateCtx<'_> {
    /// The staged tree a UC role-marked partition should be populated from,
    /// or `None` when the partition carries no UC role (falls through to the
    /// ESP/data behavior).
    fn uc_route_stage(&self, part: &Partition) -> Option<&Path> {
        let uc = self.uc?;
        match partition_uc_role(part)? {
            crate::uc::ROLE_SEED => Some(&uc.seed_stage),
            crate::uc::ROLE_BOOT => Some(&uc.boot_stage),
            _ => None,
        }
    }
}

/// Create (or truncate) a standalone partition file at the EXACT extent
/// size — a larger file would make [`splice_into`] overrun the next
/// partition; a smaller one would splice short. Sparse, zero-filled.
fn extent_file(build_dir: &Path, name: &str, extent: &PartitionExtent) -> miette::Result<PathBuf> {
    let path = build_dir.join(name);
    let f = std::fs::File::create(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", path.display()))?;
    f.set_len(extent.size_bytes)
        .into_diagnostic()
        .wrap_err_with(|| format!("sizing {} to {} bytes", path.display(), extent.size_bytes))?;
    Ok(path)
}

/// Splice a fully-built standalone partition file into the image at its
/// extent offset — in-process `io::copy` bounded by `.take()`, so neither
/// a mis-sized source nor a future regression can overrun the next
/// partition.
fn splice_into(img: &Path, part_file: &Path, extent: &PartitionExtent) -> miette::Result<()> {
    use std::io::{Read, Seek, Write};
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .open(img)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {}", img.display()))?;
    dst.seek(std::io::SeekFrom::Start(extent.start_bytes))
        .into_diagnostic()
        .wrap_err("seeking into the disk image")?;
    let src = std::fs::File::open(part_file)
        .into_diagnostic()
        .wrap_err_with(|| format!("opening {}", part_file.display()))?;
    let copied = std::io::copy(&mut src.take(extent.size_bytes), &mut dst)
        .into_diagnostic()
        .wrap_err("splicing a partition into the disk image")?;
    if copied != extent.size_bytes {
        return Err(miette::miette!(
            "partition file {} is {} bytes short of its extent — refusing to splice \
             a short partition (the tail would carry stale image bytes)",
            part_file.display(),
            extent.size_bytes - copied
        ));
    }
    dst.flush().into_diagnostic()?;
    Ok(())
}

/// Fail closed on filesystems the file-based (unprivileged) build cannot
/// populate: `mkfs.btrfs` cannot fill a filesystem from a directory tree,
/// so btrfs needs a loop-device backend.
fn refuse_non_ext4_vfat(part: &Partition) -> miette::Result<()> {
    match part.fs.as_str() {
        "ext4" | "vfat" => Ok(()),
        other => Err(miette::miette!(
            "partition '{}' declares filesystem '{other}' — the unprivileged image \
             build supports ext4 and vfat; btrfs needs a loop-device backend",
            part.name
        )),
    }
}

/// mkfs + populate a standalone ext4 partition file from a staged tree in
/// one `mkfs.ext4 -d` pass — no mount, no root. The file must already be
/// truncated to the exact extent ([`extent_file`]); the block count pins
/// the filesystem inside it (mkfs may leave an unused tail — fine, it can
/// never overrun). The verity variant pins [`VERITY_BLOCK_SIZE`] fs blocks
/// via [`mkfs_flags_for`] so the root mounts over its dm-verity mapping.
fn build_ext4_partition(
    part_file: &Path,
    staged_root: &Path,
    part: &Partition,
    extent: &PartitionExtent,
    verity: bool,
) -> miette::Result<()> {
    let (tool, flags) = mkfs_flags_for(&part.fs, verity)?;
    let block_count = (extent.size_bytes / u64::from(VERITY_BLOCK_SIZE)).to_string();
    let mut args: Vec<String> = flags;
    args.push(part.name.clone()); // label — mkfs_flags_for ends its flags with the label option
    args.push("-d".into());
    args.push(staged_root.to_string_lossy().into_owned());
    args.push(part_file.to_string_lossy().into_owned());
    args.push(block_count);
    let status = std::process::Command::new(tool)
        .args(&args)
        .status()
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!(
            "{tool} -d failed to build the {} partition '{}' (exit {})",
            part.fs,
            part.name,
            status.code().unwrap_or(1)
        ));
    }
    Ok(())
}

/// Sorted-walk helper for [`mtools_populate_vfat`]: relative paths of
/// every file and directory under `staged`, parents before children.
fn collect_staged_entries(
    staged: &Path,
    rel: &Path,
    out: &mut Vec<(String, bool)>,
) -> miette::Result<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(staged)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", staged.display()))?
        .collect::<Result<Vec<_>, _>>()
        .into_diagnostic()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let child_rel = rel.join(entry.file_name());
        if entry.path().is_dir() {
            out.push((child_rel.to_string_lossy().into_owned(), true));
            collect_staged_entries(&entry.path(), &child_rel, out)?;
        } else {
            out.push((child_rel.to_string_lossy().into_owned(), false));
        }
    }
    Ok(())
}

/// Populate a standalone vfat file (the ESP) with mtools — no mount, no
/// root. The staged tree is walked in sorted order (directories before
/// their contents fall out of a lexicographic sort: a parent path is a
/// strict prefix of its children) so the FAT layout is deterministic;
/// each directory is created with `mmd`, each file copied with `mcopy`.
/// Only the exit status decides — mkfs/mtools may print benign warnings
/// (e.g. "less than suggested minimum clusters" on small extents).
fn mtools_populate_vfat(vfat_file: &Path, staged: &Path) -> miette::Result<()> {
    let mut entries: Vec<(String, bool)> = Vec::new();
    collect_staged_entries(staged, Path::new(""), &mut entries)?;
    entries.sort();
    for (rel, is_dir) in entries {
        let target = format!("::/{rel}");
        if is_dir {
            let status = std::process::Command::new("mmd")
                .args(["-i", &vfat_file.to_string_lossy(), &target])
                .status()
                .map_err(|e| miette::miette!("mmd not found: {e}"))?;
            if !status.success() {
                return Err(miette::miette!("mmd failed creating {target} on the ESP"));
            }
        } else {
            let status = std::process::Command::new("mcopy")
                .args(["-i", &vfat_file.to_string_lossy()])
                .arg(staged.join(&rel))
                .arg(&target)
                .status()
                .map_err(|e| miette::miette!("mcopy not found: {e}"))?;
            if !status.success() {
                return Err(miette::miette!("mcopy failed copying /{rel} onto the ESP"));
            }
        }
    }
    Ok(())
}

/// Build and splice every partition EXCEPT the root slots (already
/// populated + verity-formatted in [`build_disk_image`] step 9) and the
/// auto-appended verity-hash partitions (raw `veritysetup` output — never
/// mkfs'd, never mounted) — both carried in `skip`. Partition 1 when vfat
/// is the ESP (systemd-boot fallback binary, UKI, loader.conf — staged
/// into a tree and copied on with mtools); every other partition receives
/// the staged rootfs through `mkfs.ext4 -d`.
fn populate_remaining_partitions(
    ctx: &PopulateCtx,
    layout: &DiskLayout,
    skip: &[usize],
) -> miette::Result<()> {
    for (i, part) in layout.partitions.iter().enumerate() {
        if skip.contains(&i) || part.name == VERITY_HASH_PART_NAME {
            continue;
        }
        populate_side_partition(ctx, i, part)?;
    }
    Ok(())
}

/// Build one non-root partition as a standalone file and splice it in:
/// the ESP (partition 1, vfat) is mkfs.vfat'd and populated with mtools
/// from the staged EFI tree; other data partitions receive the staged
/// rootfs via `mkfs.ext4 -d`. Failures here leave the partition
/// unpopulated (historical warn-not-fatal side-partition behavior); a
/// btrfs (or other unpopulatable) filesystem fails closed
/// ([`refuse_non_ext4_vfat`]).
fn populate_side_partition(
    ctx: &PopulateCtx,
    index: usize,
    part: &Partition,
) -> miette::Result<()> {
    refuse_non_ext4_vfat(part)?;
    let extent = &ctx.extents[index];
    let part_file = extent_file(ctx.scratch_dir, &format!("part-{}.img", index + 1), extent)?;
    // Ubuntu Core routing (issue #32): a role-marked seed/boot partition is
    // populated from its dedicated staged tree (seed / modeenv), never the
    // rootfs — the UC role model replaces the simplified "everything is the
    // rootfs" routing for those partitions.
    if let Some(stage) = ctx.uc_route_stage(part) {
        build_staged_partition(&part_file, part, stage, extent)?;
    } else if index == 0 && part.fs == "vfat" {
        build_esp_partition(ctx, &part_file, part)?;
    } else {
        build_data_partition(ctx, &part_file, part, extent)?;
    }
    splice_into(&ctx.scratch_dir.join("disk.img"), &part_file, extent)
}

/// mkfs.vfat the standalone ESP file and copy the staged boot tree on with
/// mtools (no offset syntax needed — the file IS the partition).
/// Warn-not-fatal: a failure leaves the ESP unpopulated (historical
/// side-partition behavior — the mount attempt used to decide).
fn build_esp_partition(
    ctx: &PopulateCtx,
    part_file: &Path,
    part: &Partition,
) -> miette::Result<()> {
    let esp_stage = ctx.scratch_dir.join("esp-staging");
    populate_esp(&esp_stage.join("EFI").join("BOOT"))?;
    install_uki(ctx.image, &esp_stage, ctx.uki, ctx.uki_stage)?;
    let (tool, flags) = mkfs_flags_for("vfat", false)?;
    let mut args: Vec<String> = flags;
    args.push(part.name.clone()); // -n label
    args.push(part_file.to_string_lossy().into_owned());
    let status = std::process::Command::new(tool)
        .args(&args)
        .status()
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if !status.success() {
        eprintln!("  ⚠ {tool} failed for {} — ESP left unpopulated", part.name);
        return Ok(());
    }
    if let Err(e) = mtools_populate_vfat(part_file, &esp_stage) {
        eprintln!(
            "  ⚠ mtools failed populating the ESP ({}): {e:#}",
            part.name
        );
        return Ok(());
    }
    eprintln!("  ✓ ESP: {} (vfat)", part.name);
    Ok(())
}

/// mkfs + populate one partition from a dedicated staged tree (the UC seed
/// or boot tree) through `mkfs.ext4 -d`. Unlike the historical
/// warn-not-fatal side-partition behavior, a UC seed/boot populate failure
/// is FATAL: an `ubuntu-seed`/`ubuntu-boot` that cannot be read would leave
/// snap-bootstrap without a model/seed/modeenv and stop at `cannot detect
/// mode` — a silently-broken UC image is worse than a loud build failure.
fn build_staged_partition(
    part_file: &Path,
    part: &Partition,
    stage: &Path,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    build_ext4_partition(part_file, stage, part, extent, false)
        .wrap_err_with(|| format!("UC {} partition '{}' populate failed", part.fs, part.name))?;
    eprintln!("  ✓ {}: {} populated (UC staged tree)", part.name, part.fs);
    Ok(())
}

/// mkfs + populate one data partition from the staged rootfs (authoritative
/// manifest included) through `mkfs.ext4 -d`, then splice it in.
/// Warn-not-fatal: a failure leaves the partition unpopulated (historical
/// side-partition behavior — the mount attempt used to decide).
fn build_data_partition(
    ctx: &PopulateCtx,
    part_file: &Path,
    part: &Partition,
    extent: &PartitionExtent,
) -> miette::Result<()> {
    if let Err(e) = build_ext4_partition(part_file, ctx.root, part, extent, false) {
        eprintln!(
            "  ⚠ {}: {} populate failed ({e:#}) — partition left unpopulated",
            part.name, part.fs
        );
        return Ok(());
    }
    eprintln!("  ✓ {}: {} populated", part.name, part.fs);
    Ok(())
}

/// mkfs tool + leading flags for one partition filesystem (the label and
/// remaining args are appended by the caller). `verity` marks the partition as
/// a dm-verity data device (a root slot in the verity branch): the
/// filesystem is then pinned to [`VERITY_BLOCK_SIZE`] blocks so it mounts
/// over the verity mapping — ext4 via `-b`, btrfs via nodesize +
/// sectorsize. vfat + verity fails closed: FAT has no block-size knob and
/// cannot serve as a verity data device.
fn mkfs_flags_for(fs: &str, verity: bool) -> miette::Result<(&'static str, Vec<String>)> {
    let bs = VERITY_BLOCK_SIZE.to_string();
    let (tool, flags): (&'static str, Vec<String>) = match (fs, verity) {
        ("vfat", true) => {
            return Err(miette::miette!(
                "root filesystem 'vfat' is incompatible with dm-verity — FAT has no \
                 {VERITY_BLOCK_SIZE}-byte block-size knob and cannot be a verity data \
                 device; declare an ext4 (or btrfs) root"
            ));
        }
        ("vfat", false) => ("mkfs.vfat", vec!["-F".into(), "32".into(), "-n".into()]),
        ("btrfs", true) => (
            "mkfs.btrfs",
            vec![
                "-f".into(),
                "--nodesize".into(),
                bs.clone(),
                "--sectorsize".into(),
                bs,
                "-L".into(),
            ],
        ),
        ("btrfs", false) => ("mkfs.btrfs", vec!["-f".into(), "-L".into()]),
        (_, true) => ("mkfs.ext4", vec!["-F".into(), "-b".into(), bs, "-L".into()]),
        (_, false) => ("mkfs.ext4", vec!["-F".into(), "-L".into()]),
    };
    Ok((tool, flags))
}

// ── dm-verity over the root partition (ADR-0011 step (c)) ──

/// Block size shared by `veritysetup format` (--data-block-size /
/// --hash-block-size) AND the root mkfs invocation (ext4 `-b`, btrfs
/// nodesize/sectorsize). dm-verity hashes the data device in these blocks,
/// so a root filesystem built with smaller blocks cannot mount over the
/// verity mapping: a 1 KiB-block ext4 root fails with "bad block size
/// 1024". Proven in QEMU — the identical verity setup mounts fine
/// (veritysetup status `verified`) once the rootfs is built with 4 KiB
/// blocks. ONE constant so the two argv builders cannot drift.
const VERITY_BLOCK_SIZE: u32 = 4096;

/// Name of the auto-appended dm-verity hash partition. It is formatted only
/// implicitly by `veritysetup format` — never mkfs'd, never mounted — and
/// is identified by this name in the populate stage.
const VERITY_HASH_PART_NAME: &str = "verity-hash";

/// `veritysetup format` stdout marker of the root hash line.
const ROOT_HASH_PREFIX: &str = "Root hash:";

/// dm-verity boot arguments captured during `veritysetup format` and
/// threaded into UKI assembly.
struct VerityBootArgs {
    /// 64-hex sha256 root hash from `veritysetup format`.
    roothash: String,
    /// GPT PARTUUID of the hash partition, when resolvable.
    hash_partuuid: Option<String>,
}

/// Indices of ALL declared root partitions (mount = "/"), in declaration
/// order — the ordered A/B slots (ADR-0011 step (d)). Slot A is the first;
/// slot B (when `disk.ab = true`) is appended by [`expand_ab_slots`].
fn root_partition_indices(layout: &DiskLayout) -> Vec<usize> {
    layout
        .partitions
        .iter()
        .enumerate()
        .filter(|(_, p)| p.mount == "/")
        .map(|(i, _)| i)
        .collect()
}

/// Index of the FIRST declared root partition (mount = "/") — the slot A
/// the factory UKI boots. Fail closed when absent: both the UKI `root=`
/// target and dm-verity formatting need it.
fn root_partition_index(layout: &DiskLayout) -> miette::Result<usize> {
    root_partition_indices(layout)
        .first()
        .copied()
        .ok_or_else(|| {
            miette::miette!(
                "disk layout declares no root partition (mount = \"/\") — the UKI needs \
             a root= target; refusing to build an unbootable image"
            )
        })
}

/// Slot bookkeeping after layout expansion: ordered root-slot indices and
/// the per-slot dm-verity hash partition index (`Some` exactly when the
/// build verity-formats).
#[derive(Debug, Clone)]
struct Slots {
    roots: Vec<usize>,
    hashes: Vec<Option<usize>>,
}

impl Slots {
    /// Indices populate must skip: every slot root and every verity hash
    /// partition (already populated + formatted before this stage).
    fn skip_indices(&self) -> Vec<usize> {
        let mut skip: Vec<usize> = self
            .roots
            .iter()
            .copied()
            .chain(self.hashes.iter().flatten().copied())
            .collect();
        skip.sort_unstable();
        skip
    }
}

/// Expand the effective layout for A/B slots (ADR-0011 step (d)): each
/// declared root gets its dm-verity hash partition appended (kernel images),
/// then `disk.ab = true` clones the (single) declared root + its hash into a
/// same-size, same-fs slot B directly after slot A — the day-one rollback
/// twin. Existing indices never shift. Requires "gpt" (sysupdate slot
/// matching keys off GPT type GUIDs) and exactly one declared root (slot B
/// is derived, not declared).
fn expand_ab_slots(layout: &mut DiskLayout, verity: bool) -> miette::Result<Slots> {
    if layout.ab && layout.label != "gpt" {
        return Err(miette::miette!(
            "disk.ab = true requires label = \"gpt\" — systemd-sysupdate matches A/B \
             slots by GPT partition type GUIDs, which MBR cannot carry"
        ));
    }
    let mut roots = root_partition_indices(layout);
    if verity && roots.is_empty() {
        return Err(miette::miette!(
            "disk layout declares no root partition (mount = \"/\") — dm-verity needs \
             a root data device; refusing to build an unverifiable image"
        ));
    }
    let mut hashes: Vec<Option<usize>> = vec![None; roots.len()];
    if verity {
        for i in 0..roots.len() {
            hashes[i] = Some(append_verity_hash_partition_at(layout, roots[i])?);
        }
    }
    if layout.ab {
        if roots.len() != 1 {
            return Err(miette::miette!(
                "disk.ab = true requires exactly one declared root partition (mount = \
                 \"/\"); found {} — slot B is derived from the root, not declared",
                roots.len()
            ));
        }
        let a = roots[0];
        // Clone AFTER slot A's hash partition so slot B stays contiguous
        // behind slot A. Same size/fs/options; mount stays "/" — the clone
        // is a full root slot, not a data partition.
        let root_a = layout.partitions[a].clone();
        layout.partitions.push(Partition {
            name: format!("{}_b", root_a.name),
            ..root_a
        });
        roots.push(layout.partitions.len() - 1);
        if let Some(h) = hashes[0] {
            let hash_a = layout.partitions[h].clone();
            layout.partitions.push(Partition {
                name: format!("{}_b", hash_a.name),
                ..hash_a
            });
            hashes.push(Some(layout.partitions.len() - 1));
        } else {
            hashes.push(None);
        }
    }
    Ok(Slots { roots, hashes })
}

/// Size in bytes of the dm-verity hash partition for a data device of
/// `data_bytes`: with sha256 over 4K data blocks and 4K hash blocks, one
/// hash block covers 512 KiB of data (128 × 32-byte digests), so the Merkle
/// tree needs ceil(data_bytes / 4096 / 128) 4K blocks; +1 MiB slack covers
/// the veritysetup superblock and alignment; floored at 2 MiB so tiny roots
/// still get a usable partition.
fn verity_hash_partition_bytes(data_bytes: u64) -> u64 {
    (data_bytes.div_ceil(4096 * 128) * 4096 + 1024 * 1024).max(2 * 1024 * 1024)
}

/// Append the dm-verity hash partition for the root device at the END of
/// the layout — existing partition indices never shift. Returns the new
/// partition's index.
///
/// The root size is parsed the same way [`calculate_disk_size_mb`] does
/// ("0"/fill roots use the same 1024 MB default): overshooting the hash
/// area is harmless, undersizing it fails `veritysetup format`.
fn append_verity_hash_partition_at(
    layout: &mut DiskLayout,
    root_idx: usize,
) -> miette::Result<usize> {
    let root_mb = parse_size_mb(&layout.partitions[root_idx].size, 1024);
    let hash_bytes = verity_hash_partition_bytes(root_mb * 1024 * 1024);
    let hash_mb = hash_bytes.div_ceil(1024 * 1024);
    layout.partitions.push(Partition {
        name: VERITY_HASH_PART_NAME.to_string(),
        size: format!("{hash_mb}M"),
        // "ext2" is a valid parted fs-type hint for both GPT and MBR labels;
        // the partition is never mkfs'd (see VERITY_HASH_PART_NAME).
        fs: "ext2".to_string(),
        mount: String::new(),
        options: vec![],
        role: String::new(),
    });
    Ok(layout.partitions.len() - 1)
}

/// Resolve `veritysetup` with the same bind-aware PATH resolution ukify
/// uses ([`find_ukify`]).
fn find_veritysetup() -> Option<PathBuf> {
    snap::resolve_in_path("veritysetup", &snap::path_entries())
}

/// Host tool pre-flight for kernel disk images — fail closed BEFORE any
/// destructive step (dd/parted/mkfs) so an unbootable or unverifiable image
/// is never half-written. Each Option is the host resolution of a required
/// tool; None fires the matching doctor-hinted error without running
/// anything (mirrors [`build_uki_with`]'s injected-tool pattern).
fn preflight_disk_tools_with(
    ukify: Option<&Path>,
    stub: Option<&Path>,
    veritysetup: Option<&Path>,
) -> miette::Result<()> {
    if ukify.is_none() {
        return Err(miette::miette!(
            "ukify not found on PATH — a kernel disk image cannot boot without a UKI, \
             so refusing to produce an unbootable image. Run 'shuttle doctor' and \
             install ukify (systemd >= 254; e.g. apt install systemd-ukify or add \
             systemd to devbox.json packages)"
        ));
    }
    if stub.is_none() {
        return Err(miette::miette!(
            "systemd sd-stub (linuxx64.efi.stub) not found — the UKI cannot be assembled \
             without it. Run 'shuttle doctor'; checked locations: {}",
            EFI_STUB_CANDIDATES.join(", ")
        ));
    }
    if veritysetup.is_none() {
        return Err(miette::miette!(
            "veritysetup not found on PATH — dm-verity over the root partition cannot \
             be formatted, so refusing to emit an unverifiable boot path. Run \
             'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; e.g. \
             apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    }
    Ok(())
}

/// Host tool pre-flight for the unprivileged populate stage: the disk
/// build formats and fills standalone partition files with these tools
/// (extent read-back via sfdisk, ESP via mtools, ext4/vfat via mkfs), so a
/// missing one fails closed BEFORE dd — half-written images are never
/// emitted. `required` pairs each tool name with its host resolution.
fn preflight_populate_tools_with(required: &[(&str, Option<PathBuf>)]) -> miette::Result<()> {
    for (name, resolved) in required {
        if resolved.is_none() {
            let package = populate_tool_package(name);
            return Err(miette::miette!(
                "{name} not found on PATH — the disk build reads back partition \
                 extents and formats + populates standalone partition files with \
                 it, so refusing to start. Run 'shuttle doctor' and install it \
                 (e.g. apt install {package} or add {package} to devbox.json \
                 packages)"
            ));
        }
    }
    Ok(())
}

/// OS package that ships each pre-flighted populate tool (doctor hint).
fn populate_tool_package(name: &str) -> &'static str {
    match name {
        "sfdisk" => "util-linux",
        "mmd" | "mcopy" => "mtools",
        "mkfs.ext4" => "e2fsprogs",
        "mkfs.vfat" => "dosfstools",
        _ => "the matching OS package",
    }
}

/// Resolve a host build tool with the shared bind-aware PATH resolution
/// ([`crate::snap::resolve_in_path`]) — the same search set as
/// [`find_ukify`]/[`find_veritysetup`].
fn find_host_tool(name: &str) -> Option<PathBuf> {
    snap::resolve_in_path(name, &snap::path_entries())
}

/// veritysetup argv for a sha256/4K format-1 invocation, optional pinned
/// salt, devices last.
fn verity_format_args(salt: Option<&str>, data_dev: &str, hash_dev: &str) -> Vec<String> {
    let bs = VERITY_BLOCK_SIZE.to_string();
    let mut args = vec![
        "format".to_string(),
        "--hash".to_string(),
        "sha256".to_string(),
        "--data-block-size".to_string(),
        bs.clone(),
        "--hash-block-size".to_string(),
        bs,
        "--format".to_string(),
        "1".to_string(),
    ];
    if let Some(salt) = salt {
        args.push("--salt".to_string());
        args.push(salt.to_string());
    }
    args.push(data_dev.to_string());
    args.push(hash_dev.to_string());
    args
}

/// `veritysetup format` invocation (ADR-0011 step (c)): sha256 over 4K data
/// and hash blocks, on-disk format 1. `veritysetup` is injected so the
/// fail-closed behavior is testable on hosts without cryptsetup;
/// [`verity_format`] resolves it from the host. Returns the root hash
/// printed on stdout. `salt` pins the format salt explicitly — A/B slot
/// twins format with the SAME salt so byte-identical data yields the SAME
/// roothash (the roothash covers data + salt, not the hash superblock).
fn verity_format_with(
    veritysetup: Option<&Path>,
    data_dev: &str,
    hash_dev: &str,
    salt: Option<&str>,
) -> miette::Result<String> {
    let Some(tool) = veritysetup else {
        return Err(miette::miette!(
            "veritysetup not found on PATH — dm-verity over the root partition cannot \
             be formatted, so refusing to emit an unverifiable boot path. Run \
             'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; e.g. \
             apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    };
    let args = verity_format_args(salt, data_dev, hash_dev);
    let out = std::process::Command::new(tool)
        .args(&args)
        .output()
        .map_err(|e| miette::miette!("failed to run veritysetup: {e}"))?;
    if !out.status.success() {
        return Err(miette::miette!(
            "veritysetup format failed ({}): {}",
            out.status.code().unwrap_or(1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    parse_roothash(&String::from_utf8_lossy(&out.stdout))
}

/// Format dm-verity over `data_dev` into `hash_dev` with host-resolved
/// veritysetup (fail-closed when absent). `salt` pins the format salt
/// (A/B slot twins share one salt so identical data → identical roothash).
/// In the unprivileged flow both "devices" are standalone partition files
/// — veritysetup format/verify run userspace and accept plain files.
fn verity_format(data_dev: &str, hash_dev: &str, salt: Option<&str>) -> miette::Result<String> {
    verity_format_with(find_veritysetup().as_deref(), data_dev, hash_dev, salt)
}

/// Extract the root hash from `veritysetup format` stdout — the
/// `Root hash: <64-hex>` line. Anything else fails closed: a mangled hash
/// would be baked into a cmdline that is immutable once signed.
fn parse_roothash(stdout: &str) -> miette::Result<String> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with(ROOT_HASH_PREFIX))
        .ok_or_else(|| {
            miette::miette!(
                "veritysetup format printed no '{ROOT_HASH_PREFIX}' line — refusing to \
                 guess the root hash"
            )
        })?;
    let hash = line[ROOT_HASH_PREFIX.len()..].trim();
    if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hash.to_ascii_lowercase())
    } else {
        Err(miette::miette!(
            "veritysetup printed a malformed root hash ({hash:?}) — expected 64 hex chars"
        ))
    }
}

/// The dm-verity trailing cmdline args (ADR-0011 step (c)): the roothash
/// plus EXPLICIT by-partuuid data/hash devices, so boot needs no dm-verity
/// type GUIDs and the parted flow is untouched. Unresolvable PARTUUIDs fall
/// back to the documented nil-GUID placeholder — loud failure at boot, no
/// silent boot from the wrong volume.
fn verity_trailing(
    roothash: &str,
    root_partuuid: Option<&str>,
    hash_partuuid: Option<&str>,
) -> Vec<String> {
    vec![
        format!("roothash={roothash}"),
        format!(
            "systemd.verity_root_data=/dev/disk/by-partuuid/{}",
            root_partuuid.unwrap_or(NIL_PARTUUID)
        ),
        format!(
            "systemd.verity_root_hash=/dev/disk/by-partuuid/{}",
            hash_partuuid.unwrap_or(NIL_PARTUUID)
        ),
    ]
}

// ── A/B slots + systemd-sysupdate (ADR-0011 step (d)) ──

/// GPT partition type GUIDs systemd-sysupdate matches slots by (x86-64
/// types). Set on the image at build time via sfdisk; the UKI boot path
/// needs none of them (cmdline carries explicit by-partuuid devices), but
/// sysupdate's MatchPartitionType does.
pub const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const ROOT_TYPE_GUID_X86_64: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const VERITY_TYPE_GUID_X86_64: &str = "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5";

/// Slot letter for the n-th root slot (0 → "a", 1 → "b").
fn slot_suffix(slot: usize) -> &'static str {
    const SUFFIXES: [&str; 2] = ["a", "b"];
    SUFFIXES[slot % SUFFIXES.len()]
}

/// GPT PARTLABEL of root slot `slot` — the label scheme sysupdate's
/// MatchPattern keys off: `{image}_{version}_{a|b}` (36-char GPT label
/// budget; longer names degrade to a documented sfdisk warning).
fn slot_partlabel(image_name: &str, image_version: &str, slot: usize) -> String {
    format!("{image_name}_{image_version}_{}", slot_suffix(slot))
}

/// GPT PARTLABEL of the dm-verity hash partition of root slot `slot`:
/// `{image}_{version}_hash_{a|b}`.
fn hash_partlabel(image_name: &str, image_version: &str, slot: usize) -> String {
    format!("{image_name}_{image_version}_hash_{}", slot_suffix(slot))
}

/// MatchPattern for root slot partitions: the two slot labels (version
/// wildcarded) plus the documented `_empty` fallback for factory partitions
/// not yet labeled. First pattern wins for newly created partitions.
fn root_match_pattern(image_name: &str) -> String {
    format!("{image_name}_@v_a {image_name}_@v_b {image_name}_empty")
}

/// MatchPattern for verity-hash slot partitions.
fn hash_match_pattern(image_name: &str) -> String {
    format!("{image_name}_@v_hash_a {image_name}_@v_hash_b {image_name}_hash_empty")
}

/// 64-hex random salt from /dev/urandom — shared across A/B slot formats so
/// byte-identical twins produce the same roothash.
fn random_salt_hex() -> miette::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| miette::miette!("cannot open /dev/urandom: {e}"))?;
    let mut bytes = [0u8; 32];
    f.read_exact(&mut bytes)
        .map_err(|e| miette::miette!("cannot read salt from /dev/urandom: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Apply GPT slot metadata (type GUIDs + PARTLABELs) for A/B layouts via
/// `sfdisk` (util-linux — the same tool the extents read-back uses; the
/// parted `type` command needs 3.5+, sgdisk is not required). Runs on the
/// raw image file BEFORE the extents read-back, so the table carries final
/// metadata. Fail-open, never silent: a missing or failing sfdisk warns
/// loudly — sysupdate partition matching degrades, the image still boots —
/// mirroring the historical ESP-flag posture. (The unprivileged populate
/// pre-flight already fails closed on a missing sfdisk; this guard covers
/// a resolve-vs-which PATH mismatch.)
fn apply_gpt_slot_metadata(
    img_path: &Path,
    image: &ImageDeclaration,
    layout: &DiskLayout,
    slots: &Slots,
) -> miette::Result<()> {
    if !layout.ab {
        return Ok(());
    }
    let sfdisk = match std::process::Command::new("which")
        .arg("sfdisk")
        .output()
        .ok()
        .filter(|o| o.status.success())
    {
        Some(_) => "sfdisk",
        None => {
            eprintln!(
                "  ⚠ sfdisk not found — GPT type GUIDs + PARTLABELs NOT set; \
                 systemd-sysupdate will be unable to match the A/B slots by \
                 MatchPartitionType/MatchPattern (documented fail-open: install \
                 util-linux sfdisk for sysupdate-capable images)"
            );
            return Ok(());
        }
    };
    // (partition number 1-based, type GUID, PARTLABEL)
    let mut ops: Vec<(usize, &str, Option<String>)> = Vec::new();
    if layout.partitions[0].fs == "vfat" {
        ops.push((1, ESP_TYPE_GUID, None));
    }
    for (s, &idx) in slots.roots.iter().enumerate() {
        ops.push((
            idx + 1,
            ROOT_TYPE_GUID_X86_64,
            Some(slot_partlabel(&image.name, &image.version, s)),
        ));
    }
    for (s, hash) in slots.hashes.iter().enumerate() {
        if let Some(idx) = hash {
            ops.push((
                idx + 1,
                VERITY_TYPE_GUID_X86_64,
                Some(hash_partlabel(&image.name, &image.version, s)),
            ));
        }
    }
    for (partno, type_guid, label) in ops {
        let set = |flag: &str, value: &str| -> miette::Result<()> {
            let status = std::process::Command::new(sfdisk)
                .args([
                    flag,
                    &img_path.to_string_lossy(),
                    &partno.to_string(),
                    value,
                ])
                .status()
                .map_err(|e| miette::miette!("sfdisk not runnable: {e}"))?;
            if !status.success() {
                // Raw-file images may warn about partition re-read; treat
                // nonzero as degraded metadata, never a silent skip.
                eprintln!(
                    "  ⚠ sfdisk {flag} failed for partition {partno} ({value}) — \
                     sysupdate slot matching may miss this partition (fail-open)"
                );
            }
            Ok(())
        };
        set("--part-type", type_guid)?;
        if let Some(ref label) = label {
            set("--part-label", label)?;
        }
    }
    eprintln!(
        "  ✓ GPT slot metadata: {} type GUIDs + PARTLABELs (root/verity per slot)",
        slots.roots.len() + slots.hashes.iter().flatten().count()
    );
    Ok(())
}

// ── Ubuntu Core seed / role-model wiring (issue #32) ──

/// UC gadget role of a partition, inferred from its explicit `role` opt or
/// its `ubuntu-*` PARTLABEL name. Returns the gadget role (`system-seed`,
/// `system-boot`, `system-data`) when the partition participates in the UC
/// role model; `None` for ordinary partitions (the simplified path).
fn partition_uc_role(part: &Partition) -> Option<&'static str> {
    // Explicit role opt wins; a recognized role maps to a UC PARTLABEL.
    if crate::uc::role_partlabel(&part.role).is_some() {
        return crate::uc::role_partlabel(&part.role).and_then(uc_role_for_partlabel);
    }
    // Infer from the PARTLABEL name.
    uc_role_for_partlabel(&part.name)
}

/// Map a UC PARTLABEL name back to its gadget role.
fn uc_role_for_partlabel(label: &str) -> Option<&'static str> {
    match label {
        crate::uc::UC_SEED_PART => Some(crate::uc::ROLE_SEED),
        crate::uc::UC_BOOT_PART => Some(crate::uc::ROLE_BOOT),
        crate::uc::UC_DATA_PART => Some(crate::uc::ROLE_DATA),
        _ => None,
    }
}

/// Activate the Ubuntu Core seed/role-model path (issue #32).
///
/// Active only when BOTH conditions hold:
/// - the image base is a UC coreN base (`core22`/`core24`/`core26` …), and
/// - the layout declares at least one partition with a UC gadget role
///   (`role = "system-seed"` … or a `ubuntu-*` name).
///
/// When active, role-marked partitions are remapped to their UC PARTLABEL
/// (`ubuntu-seed`/`ubuntu-boot`/`ubuntu-data`) — the remap runs BEFORE
/// partitioning so the parted-created GPT PARTLABELs come out correct — and
/// the seed tree (`seed.yaml` + signed model assertion) and boot tree
/// (`device/modeenv`) are staged into scratch dirs for the populate stage.
///
/// Non-UC bases, and coreN bases that mark no partition for a UC role, are
/// returned as `Ok(None)` unchanged — the simplified path is bit-identical.
fn setup_uc_context(
    image: &ImageDeclaration,
    layout: &mut DiskLayout,
    scratch: &Path,
    arch: &str,
    resolved: &[ResolvedSnap],
) -> miette::Result<Option<UcCtx>> {
    if !crate::uc::is_uc_base(&image.base.name) {
        return Ok(None);
    }
    let any_role = layout
        .partitions
        .iter()
        .any(|p| partition_uc_role(p).is_some());
    if !any_role {
        eprintln!(
            "  ℹ image base {} is Ubuntu Core but no partition declares a UC gadget role \
             (role = \"system-seed\"/\"system-boot\"/\"system-data\") — simplified path kept",
            image.base.name
        );
        return Ok(None);
    }

    // Remap role-marked partitions to their UC PARTLABEL. This mutates the
    // effective layout BEFORE `create_partitions` so parted's mkpart emits
    // the right GPT names (and `mkfs` labels).
    for part in &mut layout.partitions {
        if let Some(role) = partition_uc_role(part) {
            if let Some(label) = crate::uc::role_partlabel(role) {
                if part.name != label {
                    eprintln!(
                        "  ✓ UC role {role}: partition '{}' → PARTLABEL '{label}'",
                        part.name
                    );
                    part.name = label.to_string();
                }
            }
        }
    }

    // Build the signed model assertion and stage the seed + modeenv trees.
    let model = crate::uc::ModelAssertion::from_image(image, arch)?;
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let kp = match crate::sign::load_secret_key(&home)? {
        Some(kp) => kp,
        None => crate::sign::create_secret_key(&home)?,
    };
    let seed_stage = scratch.join("uc-seed-staging");
    crate::uc::emit_seed(&seed_stage, image, resolved, &model, &kp)?;
    let label = crate::uc::recovery_label(image);
    let boot_stage = scratch.join("uc-boot-staging");
    let kernel_name = image.kernel.as_ref().map(|k| k.snap.name.as_str());
    let gadget_name = image.gadget.as_ref().map(|g| g.name.as_str());
    crate::uc::emit_modeenv(
        &boot_stage,
        &label,
        kernel_name,
        &image.base.name,
        gadget_name,
    )?;
    eprintln!(
        "  ✓ UC seed + modeenv staged (recovery system label {label}, key id {})",
        kp.key_id()
    );
    Ok(Some(UcCtx {
        seed_stage,
        boot_stage,
    }))
}

/// sysupdate.d file name prefix for shuttle-generated transfers — ordering
/// keeps root+verity ahead of the UKI within one sysupdate transaction.
const SYSUPDATE_DIR: &str = "usr/lib/sysupdate.d";

/// Emit the systemd-sysupdate transfer files into the staged rootfs
/// (`/usr/lib/sysupdate.d/`), pre-populate, so both slots carry them.
/// Called only for `disk.ab = true` images with a declared
/// `update_source`. Artifacts share one `@v` version: `{v}/root.img`,
/// `{v}/verity-hash.img`, `{v}/{name}_@v.efi` under the base URL.
fn write_sysupdate_transfers(
    root: &Path,
    image: &ImageDeclaration,
    disk: &DiskLayout,
) -> miette::Result<()> {
    let dir = root.join(SYSUPDATE_DIR);
    std::fs::create_dir_all(&dir).into_diagnostic()?;
    let root_mb = parse_size_mb(
        &disk
            .partitions
            .iter()
            .find(|p| p.mount == "/")
            .map(|p| p.size.clone())
            .unwrap_or_else(|| "1024".into()),
        1024,
    );
    let files = [
        ("50-root.transfer", root_transfer(&image.name, root_mb)),
        (
            "50-verity.transfer",
            hash_transfer(&image.name, verity_hash_partition_mb(disk)),
        ),
        ("60-uki.transfer", uki_transfer(&image.name)),
    ];
    for (name, content) in files {
        std::fs::write(dir.join(name), content)
            .into_diagnostic()
            .wrap_err_with(|| format!("writing sysupdate.d/{name}"))?;
    }
    eprintln!(
        "  ✓ sysupdate transfers: {SYSUPDATE_DIR}/50-root, 50-verity, 60-uki \
         (source: {})",
        image.update_source.as_deref().unwrap_or("")
    );
    Ok(())
}

/// Hash-partition size in MB for MinSize, mirroring the appended hash
/// partition for the layout's root.
fn verity_hash_partition_mb(disk: &DiskLayout) -> u64 {
    let root_mb = parse_size_mb(
        &disk
            .partitions
            .iter()
            .find(|p| p.mount == "/")
            .map(|p| p.size.clone())
            .unwrap_or_else(|| "1024".into()),
        1024,
    );
    verity_hash_partition_bytes(root_mb * 1024 * 1024).div_ceil(1024 * 1024)
}

fn transfer_header() -> String {
    // Requires systemd >= 256 (PathRelativeTo=boot needs >= 254; the
    // tries-suffix install flow is stable from 256 on).
    "# Generated by shuttle (ADR-0011 step d) — do not edit.\n\
     # systemd-sysupdate >= 256 recommended (PathRelativeTo=boot needs >= 254).\n"
        .to_string()
}

/// Root slot partition transfer: in-place update of the two root slots,
/// matched by the x86-64 root type GUID + the slot label scheme.
fn root_transfer(image_name: &str, min_size_mb: u64) -> String {
    format!(
        "{header}\n\
         [Transfer]\n\
         ProtectVersion=%A\n\
         \n\
         [Source]\n\
         Type=url-file\n\
         Path=%v/root.img\n\
         \n\
         [Target]\n\
         Type=partition\n\
         Path=in-places\n\
         MatchPartitionType={ROOT_TYPE_GUID_X86_64}\n\
         MatchPattern={pattern}\n\
         MinSize={min_size_mb}M\n\
         InstancesMax=2\n",
        header = transfer_header(),
        pattern = root_match_pattern(image_name),
    )
}

/// Verity-hash slot partition transfer — rewritten together with its root
/// slot (both artifacts carry the same @v; the roothash is build-time
/// embedded in the UKI cmdline and never modified at update time).
fn hash_transfer(image_name: &str, min_size_mb: u64) -> String {
    format!(
        "{header}\n\
         [Transfer]\n\
         ProtectVersion=%A\n\
         \n\
         [Source]\n\
         Type=url-file\n\
         Path=%v/verity-hash.img\n\
         \n\
         [Target]\n\
         Type=partition\n\
         Path=in-places\n\
         MatchPartitionType={VERITY_TYPE_GUID_X86_64}\n\
         MatchPattern={pattern}\n\
         MinSize={min_size_mb}M\n\
         InstancesMax=2\n",
        header = transfer_header(),
        pattern = hash_match_pattern(image_name),
    )
}

/// UKI regular-file transfer: installed under $BOOT/EFI/Linux with
/// boot-try counters added by sysupdate AT INSTALL (the factory UKI ships
/// without counters — always-good). systemd-boot's Automatic Boot
/// Assessment counts TriesLeft down and systemd-bless-boot.service clears
/// the counters on a good boot. The factory filename stays
/// `{name}_{version}.efi` (tries-compatible).
fn uki_transfer(image_name: &str) -> String {
    format!(
        "{header}\n\
         [Transfer]\n\
         ProtectVersion=%A\n\
         \n\
         [Source]\n\
         Type=url-file\n\
         Path=%v/{image_name}_@v.efi\n\
         \n\
         [Target]\n\
         Type=regular-file\n\
         Path=EFI/Linux\n\
         PathRelativeTo=boot\n\
         MatchPattern={image_name}_@v+@l-@d.efi {image_name}_@v+3-0.efi {image_name}_@v.efi\n\
         TriesLeft=3\n\
         TriesDone=0\n\
         InstancesMax=2\n",
        header = transfer_header(),
    )
}

/// Serialize and write the image manifest into the staged rootfs.
fn write_manifest(
    root: &Path,
    image: &ImageDeclaration,
    snaps: &[(String, ResolvedSnap)],
    arch: &str,
    boot: Option<&UkiFacts>,
) -> miette::Result<()> {
    let manifest = ImageManifest::from_resolved(image, snaps, arch, boot);
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| miette::miette!("failed to serialize manifest: {e}"))?;
    std::fs::write(root.join("image-manifest.json"), manifest_json)
        .into_diagnostic()
        .wrap_err("writing manifest")?;
    Ok(())
}

/// Copy the systemd-boot fallback binary onto the ESP (EFI/BOOT). When no
/// host systemd-boot EFI binary is found the ESP simply lacks the fallback
/// — the UKI + loader path does not depend on it.
fn populate_esp(efi_boot: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(efi_boot).into_diagnostic()?;
    if efi_boot.join("BOOTX64.EFI").exists() {
        return Ok(());
    }
    // systemd-boot fallback binary: exact name first (a `*.efi` glob would
    // also match linuxx64.efi.stub — the WRONG binary for BOOTX64.EFI),
    // across the standard FHS roots and the NixOS system profile.
    const BOOT_ROOTS: [&str; 3] = [
        "/usr/lib/systemd/boot",
        "/usr/local/lib/systemd/boot",
        "/run/current-system/sw/lib/systemd/boot",
    ];
    let mut src: Option<PathBuf> = None;
    for root in BOOT_ROOTS {
        let root = Path::new(root);
        let exact = root.join("efi/systemd-bootx64.efi");
        if exact.is_file() {
            src = Some(exact);
            break;
        }
        if let Ok(out) = std::process::Command::new("find")
            .arg(root)
            .arg("-name")
            .arg("systemd-boot*.efi")
            .output()
        {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let hit = stdout.lines().next().unwrap_or("");
            if !hit.trim().is_empty() {
                src = Some(PathBuf::from(hit.trim()));
                break;
            }
        }
    }
    if let Some(src) = src {
        let _ = std::fs::copy(&src, efi_boot.join("BOOTX64.EFI"));
        let _ = std::fs::copy(&src, efi_boot.join("systemd-bootx64.efi"));
    }
    Ok(())
}

/// Install the UKI and the systemd-boot loader config onto the mounted
/// ESP. Type-2 UKIs in EFI/Linux/*.efi are auto-discovered by systemd-boot
/// — no per-entry loader file is needed.
fn install_uki(
    image: &ImageDeclaration,
    esp_mount: &Path,
    uki: Option<&UkiFacts>,
    uki_stage: &Path,
) -> miette::Result<()> {
    let Some(facts) = uki else {
        return Ok(());
    };
    let efi_linux = esp_mount.join("EFI").join("Linux");
    std::fs::create_dir_all(&efi_linux).into_diagnostic()?;
    std::fs::copy(uki_stage, efi_linux.join(&facts.uki_filename))
        .into_diagnostic()
        .wrap_err_with(|| format!("installing {}", facts.uki_filename))?;
    let loader_dir = esp_mount.join("loader");
    std::fs::create_dir_all(&loader_dir).into_diagnostic()?;
    std::fs::write(loader_dir.join("loader.conf"), loader_conf(image)).into_diagnostic()?;
    eprintln!(
        "  ✓ UKI installed: EFI/Linux/{} (cmdline: {})",
        facts.uki_filename, facts.cmdline
    );
    Ok(())
}

// ── UKI assembly (ADR-0011 step (a)) ──

/// A kernel snap's boot assets, located per the payload convention in
/// [`locate_kernel_payload`].
#[derive(Debug)]
struct KernelPayload {
    kernel: PathBuf,
    initrd: PathBuf,
    version: String,
}

/// Boot facts captured during UKI assembly (ADR-0011 step (a)) and threaded
/// into the build manifest — the image records what will actually boot,
/// not just what was packed.
struct UkiFacts {
    kernel_version: String,
    cmdline: String,
    uki_filename: String,
    esp_partuuid: Option<String>,
    /// dm-verity root hash embedded in the cmdline (ADR-0011 step (c));
    /// None for images that boot without verity.
    roothash: Option<String>,
}

/// GPT PARTUUID emitted when the real root PARTUUID could not be resolved.
/// Documented placeholder strategy: the nil GUID makes the failure loud —
/// nothing can mount a partition that does not exist, so the image never
/// silently boots from the wrong volume. In practice the real PARTUUID is
/// captured: parted assigns GPT GUIDs at mkpart time and `sfdisk -J` reads
/// them back from the finished table before the UKI is built.
const NIL_PARTUUID: &str = "00000000-0000-0000-0000-000000000000";

/// Standard locations of the systemd sd-stub for x86_64 — all under the
/// sandbox bind roots ([`crate::snap::SANDBOX_RO_ROOTS`]).
const EFI_STUB_CANDIDATES: [&str; 3] = [
    "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
    "/usr/local/lib/systemd/boot/efi/linuxx64.efi.stub",
    "/run/current-system/sw/lib/systemd/boot/efi/linuxx64.efi.stub",
];

/// Kernel-snap payload convention (ADR-0011 step (a)) — defined explicitly
/// because no convention existed: pkgs/*-kernel.lua snaps are source-type
/// with no packed kernel. After the snap is extracted, boot assets are read
/// from the payload in this fixed order, with the version taken from the
/// merged rootfs module tree (`lib/modules/<version>` — the only kernel
/// payload path this repo already merges):
///
///   kernel: boot/vmlinuz-<ver> → boot/vmlinuz → vmlinuz-<ver> → vmlinuz
///   initrd: boot/initrd.img-<ver> → boot/initrd.img → initrd.img → initrd
///
/// Raw kernel binaries only: a snapd-style `kernel.img` squashfs payload is
/// not unpacked (that is gadget-stage behavior, out of scope).
fn locate_kernel_payload(kernel_dir: &Path, root: &Path) -> miette::Result<KernelPayload> {
    let version = discover_kernel_version(root)?;
    let kernel = first_existing([
        kernel_dir.join("boot").join(format!("vmlinuz-{version}")),
        kernel_dir.join("boot").join("vmlinuz"),
        kernel_dir.join(format!("vmlinuz-{version}")),
        kernel_dir.join("vmlinuz"),
    ])
    .ok_or_else(|| {
        miette::miette!(
            "payload has no kernel image (searched boot/vmlinuz-{version}, boot/vmlinuz, \
             vmlinuz-{version}, vmlinuz)"
        )
    })?;
    let initrd = first_existing([
        kernel_dir
            .join("boot")
            .join(format!("initrd.img-{version}")),
        kernel_dir.join("boot").join("initrd.img"),
        kernel_dir.join("initrd.img"),
        kernel_dir.join("initrd"),
    ])
    .ok_or_else(|| {
        miette::miette!(
            "payload has no initrd (searched boot/initrd.img-{version}, boot/initrd.img, \
             initrd.img, initrd)"
        )
    })?;
    Ok(KernelPayload {
        kernel,
        initrd,
        version,
    })
}

/// First path in `candidates` that exists as a file.
fn first_existing(candidates: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    candidates.into_iter().find(|p| p.is_file())
}

/// Kernel version from the merged rootfs module tree: the single directory
/// under `lib/modules/`. Ambiguous or absent trees fail closed.
fn discover_kernel_version(root: &Path) -> miette::Result<String> {
    let modules_dir = root.join("lib").join("modules");
    let mut versions: Vec<String> = std::fs::read_dir(&modules_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {}", modules_dir.display()))?
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    versions.sort();
    match versions.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(miette::miette!(
            "no kernel module tree (lib/modules/<version>) in the merged rootfs — \
             the kernel snap carries no recognizable version"
        )),
        many => Err(miette::miette!(
            "ambiguous kernel module trees {many:?} in the merged rootfs — a kernel \
             snap must carry exactly one lib/modules/<version>"
        )),
    }
}

/// Resolve ukify with the same bind-aware PATH resolution the sandbox
/// toolchain uses ([`crate::snap::resolve_in_path`]). ukify runs host-side
/// — like mksquashfs/dd — so the full host PATH is the right search set;
/// the shared helper keeps one resolution behavior across shuttle.
fn find_ukify() -> Option<PathBuf> {
    snap::resolve_in_path("ukify", &snap::path_entries())
}

/// Locate the systemd sd-stub the UKI is built on.
fn find_efi_stub() -> Option<PathBuf> {
    for candidate in EFI_STUB_CANDIDATES {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Filename of the UKI on the ESP (systemd-boot auto-discovers Type-2 UKIs
/// in EFI/Linux/, and the loader.conf default pattern keys off this name).
fn uki_filename(image: &ImageDeclaration) -> String {
    format!("{}_{}.efi", image.name, image.version)
}

/// Compose the UKI kernel command line from parts — never one opaque
/// string. A UKI's `.cmdline` section is immutable once built, and dm-verity
/// boot (ADR-0011 step (c)) appends `roothash=` plus the explicit verity
/// device arguments ([`verity_trailing`]) and Secure Boot will later sign
/// the result, so composition stays programmatic: declared kernel params
/// first (user intent), then the `root=` argument derived from the target
/// root partition, then the trailing verity args (appended last).
fn compose_cmdline(params: &[String], root_partuuid: Option<&str>, trailing: &[String]) -> String {
    let mut args: Vec<String> = params.to_vec();
    args.push(match root_partuuid {
        Some(uuid) => format!("root=PARTUUID={uuid}"),
        None => format!("root=PARTUUID={NIL_PARTUUID}"),
    });
    args.extend(trailing.iter().cloned());
    args.join(" ")
}

/// Deterministic os-release for the UKI: no timestamps, no host facts —
/// the same definition always yields byte-identical boot assets.
fn write_uki_os_release(stage_dir: &Path, image: &ImageDeclaration) -> miette::Result<PathBuf> {
    let path = stage_dir.join("os-release");
    std::fs::write(
        &path,
        format!(
            "ID=shuttle\nNAME=\"{name}\"\nVERSION_ID={version}\nPRETTY_NAME=\"shuttle {name} {version}\"\n",
            name = image.name,
            version = image.version,
        ),
    )
    .into_diagnostic()?;
    Ok(path)
}

/// Build one UKI with the real `ukify` CLI. `ukify` and `stub` are
/// injected so the fail-closed behavior is testable on hosts without
/// systemd's tools; [`build_uki`] resolves them from the host.
fn build_uki_with(
    ukify: Option<&Path>,
    stub: Option<&Path>,
    kernel: &Path,
    initrd: &Path,
    cmdline: &str,
    os_release: &Path,
    output: &Path,
) -> miette::Result<()> {
    let Some(ukify) = ukify else {
        return Err(miette::miette!(
            "ukify not found on PATH — a kernel disk image cannot boot without a UKI, \
             so refusing to produce an unbootable image. Run 'shuttle doctor' and \
             install ukify (systemd >= 254; e.g. apt install systemd-ukify or add \
             systemd to devbox.json packages)"
        ));
    };
    let Some(stub) = stub else {
        return Err(miette::miette!(
            "systemd sd-stub (linuxx64.efi.stub) not found — the UKI cannot be assembled \
             without it. Run 'shuttle doctor'; checked locations: {}",
            EFI_STUB_CANDIDATES.join(", ")
        ));
    };
    let status = std::process::Command::new(ukify)
        .arg("build")
        .arg(format!("--linux={}", kernel.display()))
        .arg(format!("--initrd={}", initrd.display()))
        .arg(format!("--cmdline={cmdline}"))
        .arg(format!("--os-release=@{}", os_release.display()))
        .arg(format!("--stub={}", stub.display()))
        .arg(format!("--output={}", output.display()))
        .status()
        .map_err(|e| miette::miette!("failed to run ukify: {e}"))?;
    if !status.success() || !output.is_file() {
        return Err(miette::miette!(
            "ukify failed to build the UKI — the disk image would not boot; \
             refusing to emit it"
        ));
    }
    Ok(())
}

/// Build the UKI with host-resolved ukify and sd-stub (fail-closed when
/// either is absent).
fn build_uki(
    kernel: &Path,
    initrd: &Path,
    cmdline: &str,
    os_release: &Path,
    output: &Path,
) -> miette::Result<()> {
    build_uki_with(
        find_ukify().as_deref(),
        find_efi_stub().as_deref(),
        kernel,
        initrd,
        cmdline,
        os_release,
        output,
    )
}

/// Compose the cmdline, build the UKI into `stage_dir`, and capture the
/// boot facts for the manifest. The facts are `None` only for kernel-free
/// images (nothing to boot, no UKI needed); the staged UKI path is empty
/// then and never used. `verity` carries the ADR-0011 step (c) format-time
/// roothash — Some exactly when the build verity-formatted the root
/// partition (kernel images).
fn assemble_uki(
    image: &ImageDeclaration,
    payload: Option<&KernelPayload>,
    extents: &[PartitionExtent],
    layout: &DiskLayout,
    stage_dir: &Path,
    verity: Option<&VerityBootArgs>,
) -> miette::Result<(Option<UkiFacts>, PathBuf)> {
    let Some(entry) = image.kernel.as_ref() else {
        return Ok((None, PathBuf::new()));
    };
    let Some(payload) = payload else {
        return Err(miette::miette!(
            "kernel snap '{}' declared but its boot payload was not extracted — \
             refusing to build a disk image that cannot boot",
            entry.snap.name
        ));
    };
    let root_idx = root_partition_index(layout)?;

    // GPT PARTUUIDs exist from parted mkpart time and are read back from
    // the finished table (`sfdisk -J`) before anything is formatted. ESP
    // is partition 1 (extent index 0).
    let root_partuuid = extents[root_idx].partuuid.clone();
    let esp_partuuid = extents[0].partuuid.clone();
    if root_partuuid.is_none() {
        eprintln!(
            "  ⚠ root PARTUUID unresolvable — cmdline carries the documented \
             nil-GUID placeholder (see compose_cmdline)"
        );
    }

    let trailing: Vec<String> = verity
        .map(|v| {
            verity_trailing(
                &v.roothash,
                root_partuuid.as_deref(),
                v.hash_partuuid.as_deref(),
            )
        })
        .unwrap_or_default();
    let cmdline = compose_cmdline(&entry.params, root_partuuid.as_deref(), &trailing);
    let filename = uki_filename(image);
    let uki_stage = stage_dir.join(&filename);
    let os_release = write_uki_os_release(stage_dir, image)?;
    build_uki(
        &payload.kernel,
        &payload.initrd,
        &cmdline,
        &os_release,
        &uki_stage,
    )?;
    eprintln!("  ✓ UKI built: {filename}");

    Ok((
        Some(UkiFacts {
            kernel_version: payload.version.clone(),
            cmdline,
            uki_filename: filename,
            esp_partuuid,
            roothash: verity.map(|v| v.roothash.clone()),
        }),
        uki_stage,
    ))
}

/// systemd-boot loader configuration at the ESP root. Type-2 UKIs in
/// EFI/Linux/*.efi are auto-discovered — no per-entry loader file needed —
/// but the timeout and default pattern live here.
fn loader_conf(image: &ImageDeclaration) -> String {
    let timeout = image.bootloader.as_ref().map(|b| b.timeout).unwrap_or(3);
    // `default` is a glob: any UKI built for this image name matches,
    // regardless of version.
    format!(
        "# Generated by shuttle — do not edit.\ntimeout {timeout}\ndefault {}_*\n",
        image.name
    )
}

/// Parse a size string like "512M" or "4G" or "0" to MB.
fn parse_size_mb(size: &str, default_if_zero: u64) -> u64 {
    let size = size.trim();
    if size == "0" {
        return default_if_zero.max(256);
    }
    if let Some(n) = size.strip_suffix('G').or_else(|| size.strip_suffix('g')) {
        n.parse::<u64>().unwrap_or(1) * 1024
    } else if let Some(n) = size.strip_suffix('M').or_else(|| size.strip_suffix('m')) {
        n.parse::<u64>().unwrap_or(256)
    } else if let Some(n) = size.strip_suffix('K').or_else(|| size.strip_suffix('k')) {
        n.parse::<u64>().unwrap_or(256) / 1024 + 1
    } else {
        size.parse::<u64>().unwrap_or(default_if_zero.max(256))
    }
}

/// Calculate total disk size in MB.
fn calculate_disk_size_mb(layout: &DiskLayout) -> u64 {
    let mut total = 4u64; // GPT headers
    for part in &layout.partitions {
        total += parse_size_mb(&part.size, 1024);
    }
    if let Some(ref swap) = layout.swap {
        total += parse_size_mb(&swap.size, 0);
    }
    total
}

// ── Image manifest ──

#[derive(Debug, Clone, Serialize)]
pub struct ImageManifest {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub snaps: Vec<ImageSnapEntry>,

    /// Kernel version of the packed payload (lib/modules/<ver>) — set when
    /// the image declares a kernel (ADR-0011 step (a)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,

    /// Composed UKI cmdline actually installed on the ESP (declared params
    /// + root= + verity trailer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,

    /// UKI filename on the ESP (EFI/Linux/<uki>).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uki: Option<String>,

    /// GPT PARTUUID of the ESP, when resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esp_partuuid: Option<String>,

    /// dm-verity root hash embedded in the UKI cmdline (ADR-0011 step (c))
    /// — the hash lives on the dedicated trailing verity-hash partition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roothash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageSnapEntry {
    pub name: String,
    pub revision: u32,
    #[serde(rename = "sha3-384")]
    pub sha3_384: String,
    pub role: String,
}

impl ImageManifest {
    fn from_resolved(
        image: &ImageDeclaration,
        snaps: &[(String, ResolvedSnap)],
        arch: &str,
        boot: Option<&UkiFacts>,
    ) -> Self {
        let entries: Vec<ImageSnapEntry> = snaps
            .iter()
            .map(|(name, snap)| {
                let role = if *name == image.base.name {
                    "base"
                } else if image.kernel.as_ref().is_some_and(|k| k.snap.name == *name) {
                    "kernel"
                } else if image.gadget.as_ref().is_some_and(|g| g.name == *name) {
                    "gadget"
                } else {
                    "app"
                };
                ImageSnapEntry {
                    name: name.clone(),
                    revision: snap.revision,
                    sha3_384: snap.sha3_384.clone(),
                    role: role.to_string(),
                }
            })
            .collect();

        ImageManifest {
            name: image.name.clone(),
            version: image.version.clone(),
            arch: arch.to_string(),
            snaps: entries,
            kernel_version: boot.map(|b| b.kernel_version.clone()),
            cmdline: boot.map(|b| b.cmdline.clone()),
            uki: boot.map(|b| b.uki_filename.clone()),
            esp_partuuid: boot.and_then(|b| b.esp_partuuid.clone()),
            roothash: boot.and_then(|b| b.roothash.clone()),
        }
    }
}

/// Recursive copy of directory contents into destination.
fn cp_r(src: &Path, dst: &Path) -> miette::Result<()> {
    let mut dirs = vec![src.to_path_buf()];
    while let Some(current) = dirs.pop() {
        let relative = current.strip_prefix(src).unwrap_or(Path::new(""));
        let target = dst.join(relative);

        if current.is_dir() && current != src {
            std::fs::create_dir_all(&target)
                .into_diagnostic()
                .wrap_err_with(|| format!("creating {:?}", target))?;
        }

        if let Ok(read) = std::fs::read_dir(&current) {
            for entry in read.flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(src).unwrap_or(Path::new(""));
                let dest = dst.join(rel);

                if path.is_dir() {
                    std::fs::create_dir_all(&dest)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("creating {:?}", dest))?;
                    dirs.push(path);
                } else {
                    std::fs::copy(&path, &dest)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("copying {:?} to {:?}", path, dest))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lua_env() -> mlua::Lua {
        let lua = mlua::Lua::new();
        lua.load(crate::dsl::INIT_LUA)
            .exec()
            .expect("DSL init failed");
        lua
    }

    #[test]
    fn test_image_declaration_full() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "my-system",
                    version = "1.0.0",
                    base = pin("core22", { revision = 1847, sha3_384 = "abc" }),
                    kernel = pin("pc-kernel", { revision = 1241 }),
                    gadget = pin("pi-gadget"),
                    snaps = {
                        pin("lxd", { revision = 30192 }),
                        pin("my-app", { revision = 42, sha3_384 = "def" }),
                    },
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        assert_eq!(decl.name, "my-system");
        assert_eq!(decl.version, "1.0.0");
        assert_eq!(decl.base.name, "core22");
        assert_eq!(decl.base.revision, Some(1847));
        assert_eq!(decl.base.sha3_384.as_deref(), Some("abc"));
        assert_eq!(decl.kernel.as_ref().unwrap().snap.name, "pc-kernel");
        assert_eq!(decl.kernel.as_ref().unwrap().snap.revision, Some(1241));
        assert_eq!(decl.gadget.as_ref().unwrap().name, "pi-gadget");
        assert_eq!(decl.extra_snaps.len(), 2);
        assert_eq!(decl.extra_snaps[0].name, "lxd");
        assert_eq!(decl.extra_snaps[0].revision, Some(30192));
        assert_eq!(decl.extra_snaps[1].name, "my-app");
        assert_eq!(decl.extra_snaps[1].sha3_384.as_deref(), Some("def"));
    }

    #[test]
    fn test_image_declaration_minimal() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "minimal",
                    version = "0.1.0",
                    base = pin("core22"),
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        assert_eq!(decl.name, "minimal");
        assert_eq!(decl.base.name, "core22");
        assert!(decl.kernel.is_none());
        assert!(decl.gadget.is_none());
        assert!(decl.extra_snaps.is_empty());
    }

    #[test]
    fn test_image_rejects_missing_base() {
        let lua = lua_env();
        let result: std::result::Result<Value, mlua::Error> = lua
            .load(
                r#"
                return image {
                    name = "no-base",
                    version = "1.0",
                }
                "#,
            )
            .eval();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing required field 'base'"),
            "error should mention base: {err}"
        );
    }

    #[test]
    fn test_all_snaps_collects_everything() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "all",
                    version = "1",
                    base = pin("core22"),
                    kernel = pin("pc-kernel"),
                    gadget = pin("pi-gadget"),
                    snaps = { pin("lxd"), pin("app") },
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        let all: Vec<&str> = decl.all_snaps().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(all, vec!["core22", "pc-kernel", "pi-gadget", "lxd", "app"]);
    }

    #[test]
    fn test_manifest_roles() {
        let decl = ImageDeclaration {
            name: "test".into(),
            version: "1.0".into(),
            base: SnapRef {
                name: "core22".into(),
                revision: Some(1),
                sha3_384: Some("a".into()),
            },
            kernel: Some(KernelEntry {
                snap: SnapRef {
                    name: "pc-kernel".into(),
                    revision: Some(2),
                    sha3_384: Some("b".into()),
                },
                params: vec![],
                modules: vec![],
                modprobe_config: None,
                channel: None,
            }),
            gadget: Some(SnapRef {
                name: "pi-gadget".into(),
                revision: Some(3),
                sha3_384: Some("c".into()),
            }),
            gadget_channel: None,
            extra_snaps: vec![SnapRef {
                name: "my-app".into(),
                revision: Some(4),
                sha3_384: Some("d".into()),
            }],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        };

        let snaps: Vec<(String, ResolvedSnap)> = vec![
            (
                "core22".into(),
                ResolvedSnap {
                    name: "core22".into(),
                    revision: 1,
                    sha3_384: "a".into(),
                    download_url: "".into(),
                },
            ),
            (
                "pc-kernel".into(),
                ResolvedSnap {
                    name: "pc-kernel".into(),
                    revision: 2,
                    sha3_384: "b".into(),
                    download_url: "".into(),
                },
            ),
            (
                "pi-gadget".into(),
                ResolvedSnap {
                    name: "pi-gadget".into(),
                    revision: 3,
                    sha3_384: "c".into(),
                    download_url: "".into(),
                },
            ),
            (
                "my-app".into(),
                ResolvedSnap {
                    name: "my-app".into(),
                    revision: 4,
                    sha3_384: "d".into(),
                    download_url: "".into(),
                },
            ),
        ];

        let manifest = ImageManifest::from_resolved(&decl, &snaps, "amd64", None);
        assert_eq!(manifest.snaps.len(), 4);
        assert_eq!(manifest.snaps[0].role, "base");
        assert_eq!(manifest.snaps[1].role, "kernel");
        assert_eq!(manifest.snaps[2].role, "gadget");
        assert_eq!(manifest.snaps[3].role, "app");
        // Kernel-free image: boot facts stay absent.
        assert!(manifest.kernel_version.is_none());
        assert!(manifest.cmdline.is_none());
        assert!(manifest.uki.is_none());
        assert!(manifest.esp_partuuid.is_none());
        assert!(manifest.roothash.is_none());
    }

    #[test]
    fn test_image_with_kernel_params() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "kparams",
                    version = "1.0",
                    base = pin("core22"),
                    kernel = pin("pc-kernel", { params = { "quiet", "splash" } }),
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        let kernel = decl.kernel.as_ref().unwrap();
        assert_eq!(kernel.snap.name, "pc-kernel");
        assert_eq!(kernel.params, vec!["quiet", "splash"]);
        assert!(kernel.modules.is_empty());
        assert!(kernel.modprobe_config.is_none());
    }

    #[test]
    fn test_image_with_bootloader() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "boot",
                    version = "1.0",
                    base = pin("core22"),
                    bootloader = { type = "grub", timeout = 5 },
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        let bl = decl.bootloader.as_ref().unwrap();
        assert_eq!(bl.type_, "grub");
        assert_eq!(bl.timeout, 5);
    }

    #[test]
    fn test_image_with_disk_layout() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "disk",
                    version = "1.0",
                    base = pin("core22"),
                    disk = {
                        label = "gpt",
                        partitions = {
                            { name = "ESP", size = "512M", fs = "vfat", mount = "/boot/efi" },
                            { name = "root", size = "4G", fs = "ext4", mount = "/" },
                        },
                        swap = { size = "2G" },
                    },
                }
                "#,
            )
            .eval()
            .unwrap();

        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };

        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        let disk = decl.disk.as_ref().unwrap();
        assert_eq!(disk.label, "gpt");
        assert_eq!(disk.partitions.len(), 2);
        assert_eq!(disk.partitions[0].name, "ESP");
        assert_eq!(disk.partitions[0].size, "512M");
        assert_eq!(disk.partitions[0].fs, "vfat");
        assert_eq!(disk.partitions[1].name, "root");
        assert_eq!(disk.partitions[1].fs, "ext4");
        let swap = disk.swap.as_ref().unwrap();
        assert_eq!(swap.size, "2G");
    }

    #[test]
    fn test_parse_size_mb() {
        assert_eq!(parse_size_mb("512M", 0), 512);
        assert_eq!(parse_size_mb("4G", 0), 4096);
        assert_eq!(parse_size_mb("1024K", 0), 2); // 1024/1024 + 1 (ceiling)
        assert_eq!(parse_size_mb("0", 1024), 1024);
        assert_eq!(parse_size_mb("0", 0), 256);
        assert_eq!(parse_size_mb("2048", 0), 2048);
        assert_eq!(parse_size_mb("1g", 0), 1024);
        assert_eq!(parse_size_mb("256m", 0), 256);
    }

    // ── GPT PARTLABEL from the partition name (UC boot prerequisite) ──

    fn part_named(name: &str) -> Partition {
        Partition {
            name: name.into(),
            size: "512M".into(),
            fs: "ext4".into(),
            mount: "/".into(),
            options: vec![],
            role: String::new(),
        }
    }

    #[test]
    fn mkpart_name_gpt_uses_declared_name_as_partlabel() {
        // The UC initrd matches ID_PART_ENTRY_NAME (the GPT PARTLABEL), so a
        // declared name must become the PARTLABEL — not the hardcoded
        // "primary". part.name also becomes the mkfs label (elsewhere), so
        // the two no longer diverge.
        assert_eq!(mkpart_name("gpt", &part_named("esp")), "esp");
        assert_eq!(mkpart_name("gpt", &part_named("root")), "root");
        assert_eq!(mkpart_name("gpt", &part_named("writable")), "writable");
        assert_eq!(
            mkpart_name("gpt", &part_named("ubuntu-seed")),
            "ubuntu-seed"
        );
    }

    #[test]
    fn mkpart_name_gpt_defaults_primary_when_unnamed() {
        // Partitions with no declared name fall back to "primary", so
        // existing non-UC (unlabelled) images are byte-identical.
        assert_eq!(mkpart_name("gpt", &part_named("")), "primary");
    }

    #[test]
    fn mkpart_name_mbr_keeps_primary_type() {
        // MBR (msdos) labels interpret the first positional after `mkpart`
        // as the partition TYPE, not a name — always "primary", regardless
        // of the declared name. MBR has no PARTLABEL to set.
        assert_eq!(mkpart_name("mbr", &part_named("root")), "primary");
        assert_eq!(mkpart_name("mbr", &part_named("")), "primary");
    }

    // ── Ubuntu Core role/seed wiring (issue #32) ──

    #[test]
    fn partition_uc_role_detects_role_opt_and_ubuntu_names() {
        // Explicit role opt.
        let mut p = part_named("p1");
        p.role = "system-seed".into();
        assert_eq!(partition_uc_role(&p), Some("system-seed"));
        // Inferred from a ubuntu-* PARTLABEL name.
        assert_eq!(
            partition_uc_role(&part_named("ubuntu-boot")),
            Some("system-boot")
        );
        assert_eq!(
            partition_uc_role(&part_named("ubuntu-data")),
            Some("system-data")
        );
        assert_eq!(
            partition_uc_role(&part_named("ubuntu-seed")),
            Some("system-seed")
        );
        // Ordinary partitions carry no UC role.
        assert_eq!(partition_uc_role(&part_named("root")), None);
        assert_eq!(partition_uc_role(&part_named("esp")), None);
        // An unimplemented role (system-save) is not routed.
        let mut p = part_named("p1");
        p.role = "system-save".into();
        assert_eq!(partition_uc_role(&p), None);
    }

    fn uc_layout() -> DiskLayout {
        DiskLayout {
            label: "gpt".into(),
            partitions: vec![
                Partition {
                    name: "esp".into(),
                    size: "128M".into(),
                    fs: "vfat".into(),
                    mount: "/boot/efi".into(),
                    options: vec![],
                    role: String::new(),
                },
                Partition {
                    name: "esp-data".into(),
                    size: "2G".into(),
                    fs: "ext4".into(),
                    mount: "/".into(),
                    options: vec![],
                    role: String::new(),
                },
                Partition {
                    name: "seedpool".into(),
                    size: "1G".into(),
                    fs: "ext4".into(),
                    mount: "/seed".into(),
                    options: vec![],
                    role: "system-seed".into(),
                },
                Partition {
                    name: "bootpool".into(),
                    size: "512M".into(),
                    fs: "ext4".into(),
                    mount: "/boot".into(),
                    options: vec![],
                    role: "system-boot".into(),
                },
            ],
            swap: None,
            ab: false,
        }
    }

    #[test]
    fn setup_uc_context_remaps_role_partitions_and_stages() {
        let image = test_support::sample_image();
        assert!(crate::uc::is_uc_base(&image.base.name));
        let mut layout = uc_layout();
        let scratch = tempfile::tempdir().unwrap();
        let uc = setup_uc_context(&image, &mut layout, scratch.path(), "amd64", &[])
            .unwrap()
            .expect("UC base + role partitions ⇒ UC active");
        // Role partitions remapped to their UC PARTLABEL; unmarked ones keep
        // their names (the simplified path is untouched).
        assert_eq!(layout.partitions[2].name, "ubuntu-seed");
        assert_eq!(layout.partitions[3].name, "ubuntu-boot");
        assert_eq!(layout.partitions[0].name, "esp");
        assert_eq!(layout.partitions[1].name, "esp-data");
        // Seed + boot trees staged.
        assert!(uc.seed_stage.join("seed.yaml").exists());
        assert!(uc.boot_stage.join("device").join("modeenv").exists());
        // The staged boot tree's modeenv declares a run mode (snap-bootstrap
        // stops at "cannot detect mode" without it).
        let modeenv =
            std::fs::read_to_string(uc.boot_stage.join("device").join("modeenv")).unwrap();
        assert!(modeenv.starts_with("mode=run\n"));
        // The staged recovery-system model assertion is a signed assertion
        // that roundtrips with the project's keychain.
        let sys = std::fs::read_dir(uc.seed_stage.join("systems"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.is_dir())
            .expect("a recovery-system label dir");
        let model_text = std::fs::read_to_string(sys.join("model")).unwrap();
        assert!(model_text.contains("type: model"));
        assert!(model_text.contains("base: core24"));
    }

    #[test]
    fn setup_uc_context_is_inactive_for_non_uc_base() {
        let mut image = test_support::sample_image();
        image.base.name = "my-base".into();
        assert!(!crate::uc::is_uc_base(&image.base.name));
        let mut layout = uc_layout();
        let scratch = tempfile::tempdir().unwrap();
        let uc = setup_uc_context(&image, &mut layout, scratch.path(), "amd64", &[]).unwrap();
        assert!(uc.is_none(), "non-UC base keeps the simplified path");
        // Names unchanged — no remap.
        assert_eq!(layout.partitions[2].name, "seedpool");
    }

    #[test]
    fn setup_uc_context_is_inactive_without_role_partitions() {
        let image = test_support::sample_image();
        let mut layout = uc_layout();
        // Strip every role so no partition participates in the UC model.
        for p in &mut layout.partitions {
            p.role.clear();
            if p.name == "seedpool" {
                p.name = "seed".into();
            }
            if p.name == "bootpool" {
                p.name = "bootd".into();
            }
        }
        let scratch = tempfile::tempdir().unwrap();
        let uc = setup_uc_context(&image, &mut layout, scratch.path(), "amd64", &[]).unwrap();
        assert!(
            uc.is_none(),
            "no UC role-marked partition ⇒ simplified path kept"
        );
    }

    #[test]
    fn uc_route_stage_routes_seed_and_boot_trees() {
        let seed_dir = Path::new("/seed");
        let boot_dir = Path::new("/boot");
        let uc = UcCtx {
            seed_stage: seed_dir.to_path_buf(),
            boot_stage: boot_dir.to_path_buf(),
        };
        let ctx = PopulateCtx {
            image: &test_support::sample_image(),
            extents: &[],
            scratch_dir: Path::new("/scratch"),
            root: Path::new("/root"),
            uki: None,
            uki_stage: Path::new("/stage"),
            uc: Some(&uc),
        };
        assert_eq!(
            ctx.uc_route_stage(&part_named("seedpool")),
            None,
            "no role ⇒ no route"
        );
        let mut seed = part_named("seedpool");
        seed.role = "system-seed".into();
        assert_eq!(ctx.uc_route_stage(&seed), Some(seed_dir));
        let mut boot = part_named("bootpool");
        boot.role = "system-boot".into();
        assert_eq!(ctx.uc_route_stage(&boot), Some(boot_dir));
        // No UC ctx at all ⇒ no routing (simplified path).
        let empty = PopulateCtx {
            image: &test_support::sample_image(),
            extents: &[],
            scratch_dir: Path::new("/scratch"),
            root: Path::new("/root"),
            uki: None,
            uki_stage: Path::new("/stage"),
            uc: None,
        };
        assert_eq!(empty.uc_route_stage(&seed), None);
    }

    #[test]
    fn parted_mkpart_args_thread_the_partlabel_name() {
        // The argv handed to `parted mkpart` carries the declared name in the
        // name slot (position 3) alongside the fs-type, start and end.
        let img = Path::new("/tmp/disk.img");
        let args = parted_mkpart_args(img, "gpt", &part_named("writable"), 4, 4100);
        assert_eq!(
            args,
            vec![
                "-s",
                "/tmp/disk.img",
                "mkpart",
                "writable",
                "ext4",
                "4MB",
                "4100MB",
            ]
        );
    }

    // ── UKI assembly (ADR-0011 step (a)) ──

    #[test]
    fn cmdline_composes_params_then_root() {
        let cmdline = compose_cmdline(
            &["quiet".to_string(), "console=ttyS0".to_string()],
            Some("1234abcd-00aa-bbcc-ddee-ff0011223344"),
            &[],
        );
        assert_eq!(
            cmdline,
            "quiet console=ttyS0 root=PARTUUID=1234abcd-00aa-bbcc-ddee-ff0011223344"
        );
    }

    #[test]
    fn cmdline_placeholder_root_is_nil_guid() {
        let cmdline = compose_cmdline(&[], None, &[]);
        assert_eq!(cmdline, format!("root=PARTUUID={NIL_PARTUUID}"));
    }

    #[test]
    fn cmdline_leaves_room_for_verity_trailer() {
        // Future dm-verity boot appends roothash= — composition is
        // programmatic from parts so the trailer lands after root=.
        let base = compose_cmdline(&["ro".to_string()], Some("abcd"), &[]);
        let full = compose_cmdline(
            &["ro".to_string()],
            Some("abcd"),
            &["roothash=9f86d081".to_string()],
        );
        assert_eq!(full, format!("{base} roothash=9f86d081"));
        assert!(full.ends_with("root=PARTUUID=abcd roothash=9f86d081"));
    }

    // ── dm-verity over the root partition (ADR-0011 step (c)) ──

    #[test]
    fn verity_cmdline_composes_root_then_roothash_then_devices() {
        // Exact trailer shape: roothash= first, then the explicit
        // by-partuuid data/hash devices — boot needs no dm-verity type
        // GUIDs, and every verity argument lands AFTER root=.
        let trailing = verity_trailing(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            Some("1234abcd-00aa-bbcc-ddee-ff0011223344"),
            Some("abcdef01-00aa-bbcc-ddee-ff0011223344"),
        );
        let cmdline = compose_cmdline(
            &["quiet".to_string()],
            Some("1234abcd-00aa-bbcc-ddee-ff0011223344"),
            &trailing,
        );
        assert_eq!(
            cmdline,
            "quiet root=PARTUUID=1234abcd-00aa-bbcc-ddee-ff0011223344 \
             roothash=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
             systemd.verity_root_data=/dev/disk/by-partuuid/1234abcd-00aa-bbcc-ddee-ff0011223344 \
             systemd.verity_root_hash=/dev/disk/by-partuuid/abcdef01-00aa-bbcc-ddee-ff0011223344"
        );
        let root = cmdline.find("root=PARTUUID=").unwrap();
        assert!(cmdline.find("roothash=").unwrap() > root, "{cmdline}");
        assert!(
            cmdline.find("systemd.verity_root_hash=").unwrap() > root,
            "{cmdline}"
        );
    }

    #[test]
    fn verity_trailer_falls_back_to_nil_guid() {
        // Unresolvable PARTUUIDs carry the documented nil-GUID placeholder:
        // loud failure at boot, never a silent boot from the wrong volume.
        let hash = "a".repeat(64);
        let trailing = verity_trailing(&hash, None, None);
        assert_eq!(
            trailing,
            vec![
                format!("roothash={hash}"),
                format!("systemd.verity_root_data=/dev/disk/by-partuuid/{NIL_PARTUUID}"),
                format!("systemd.verity_root_hash=/dev/disk/by-partuuid/{NIL_PARTUUID}"),
            ]
        );
    }

    #[test]
    fn roothash_parse_extracts_sha256_hex() {
        // Real veritysetup shape: padded labels, the hash value lowercase
        // hex. Uppercase input is normalized.
        let out = "UUID:                     882db884-0000-0000-0000-000000000000\n\
                   Hash type:                1\n\
                   Data blocks:              8\n\
                   Data block size:          4096\n\
                   Hash block size:          4096\n\
                   Hash algorithm:           sha256\n\
                   Salt:                     0000...\n\
                   Root hash:            9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08\n";
        assert_eq!(
            parse_roothash(out).unwrap(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn roothash_parse_fails_closed_without_marker() {
        let err = parse_roothash("UUID: 882db884\nHash algorithm: sha256\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Root hash:") && msg.contains("refusing"),
            "missing-marker failure must be loud: {msg}"
        );
    }

    #[test]
    fn roothash_parse_fails_closed_on_malformed_hash() {
        for bad in [
            "Root hash: 9f86",
            "Root hash: not-hex-at-all-aaaaaaaaaaaaaaaaaaaa",
        ] {
            let err = parse_roothash(bad).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("malformed root hash"),
                "malformed hash must be refused: {msg}"
            );
        }
    }

    #[test]
    fn verity_hash_size_follows_formula() {
        // sha256/4K: one 4K hash block covers 512 KiB of data.
        // 1 GiB root → 2048 hash blocks (8 MiB) + 1 MiB slack = 9 MiB.
        assert_eq!(
            verity_hash_partition_bytes(1024 * 1024 * 1024),
            9 * 1024 * 1024
        );
        // 512 MiB → 1024 blocks (4 MiB) + 1 MiB = 5 MiB.
        assert_eq!(
            verity_hash_partition_bytes(512 * 1024 * 1024),
            5 * 1024 * 1024
        );
        // Ceil rounds partial blocks up: 128 MiB + 1 byte → 257 blocks.
        assert_eq!(
            verity_hash_partition_bytes(128 * 1024 * 1024 + 1),
            257 * 4096 + 1024 * 1024
        );
        // Minimum 2 MiB floor for tiny roots.
        assert_eq!(verity_hash_partition_bytes(0), 2 * 1024 * 1024);
    }

    #[test]
    fn verity_hash_partition_is_appended_last_without_shifting_indices() {
        let mut layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![
                Partition {
                    name: "ESP".into(),
                    size: "512M".into(),
                    fs: "vfat".into(),
                    mount: "/boot/efi".into(),
                    options: vec![],
                    role: String::new(),
                },
                Partition {
                    name: "root".into(),
                    size: "4G".into(),
                    fs: "ext4".into(),
                    mount: "/".into(),
                    options: vec![],
                    role: String::new(),
                },
            ],
            swap: None,
            ab: false,
        };
        let idx = append_verity_hash_partition_at(&mut layout, 1).unwrap();
        assert_eq!(idx, 2, "hash partition goes last");
        assert_eq!(layout.partitions[0].name, "ESP", "indices never shift");
        assert_eq!(layout.partitions[1].name, "root");
        assert_eq!(layout.partitions[2].name, VERITY_HASH_PART_NAME);
        // 4 GiB root: 1048576 4K blocks / 128 = 8192 hash blocks = 32 MiB
        // + 1 MiB slack = 33 MiB.
        assert_eq!(layout.partitions[2].size, "33M");
    }

    #[test]
    fn verity_hash_partition_requires_a_root_partition() {
        let mut layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![Partition {
                name: "data".into(),
                size: "1G".into(),
                fs: "ext4".into(),
                mount: "/data".into(),
                options: vec![],
                role: String::new(),
            }],
            swap: None,
            ab: false,
        };
        // Expansion (verity on) fails closed before any partitioning: no
        // root means no data device to hash.
        let err = expand_ab_slots(&mut layout, true).unwrap_err();
        assert!(
            format!("{err:#}").contains("root partition"),
            "no-root failure must be loud: {err:#}"
        );
    }

    #[test]
    fn preflight_ukify_missing_fails_closed_with_doctor_hint() {
        let err = preflight_disk_tools_with(
            None,
            Some(Path::new("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")),
            Some(Path::new("/usr/sbin/veritysetup")),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ukify") && msg.contains("shuttle doctor"),
            "fail-closed error must name ukify and the doctor hint: {msg}"
        );
    }

    #[test]
    fn preflight_stub_missing_fails_closed() {
        let err = preflight_disk_tools_with(
            Some(Path::new("/usr/bin/ukify")),
            None,
            Some(Path::new("/usr/sbin/veritysetup")),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sd-stub") && msg.contains("linuxx64.efi.stub"),
            "fail-closed error must name the stub: {msg}"
        );
    }

    #[test]
    fn preflight_veritysetup_missing_fails_closed_with_doctor_hint() {
        let err = preflight_disk_tools_with(
            Some(Path::new("/usr/bin/ukify")),
            Some(Path::new("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")),
            None,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("veritysetup") && msg.contains("shuttle doctor"),
            "fail-closed error must name veritysetup and the doctor hint: {msg}"
        );
    }

    #[test]
    fn preflight_all_tools_present_passes() {
        preflight_disk_tools_with(
            Some(Path::new("/usr/bin/ukify")),
            Some(Path::new("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")),
            Some(Path::new("/usr/sbin/veritysetup")),
        )
        .unwrap();
    }

    #[test]
    fn verity_format_without_veritysetup_fails_closed() {
        // Injected None: the fail-closed path fires before any device is
        // touched, so device names are irrelevant.
        let err = verity_format_with(None, "/dev/loop0p2", "/dev/loop0p3", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("veritysetup") && msg.contains("shuttle doctor"),
            "fail-closed error must name veritysetup and the doctor hint: {msg}"
        );
    }

    #[test]
    fn manifest_threads_roothash_from_boot_facts() {
        let decl = ImageDeclaration {
            name: "verity".into(),
            version: "1.0".into(),
            base: SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        };
        let snaps: Vec<(String, ResolvedSnap)> = vec![(
            "core22".into(),
            ResolvedSnap {
                name: "core22".into(),
                revision: 1,
                sha3_384: "a".into(),
                download_url: "".into(),
            },
        )];
        let hash = "ab".repeat(32);
        let facts = UkiFacts {
            kernel_version: "6.8.0".into(),
            cmdline: format!("ro roothash={hash}"),
            uki_filename: "verity_1.0.efi".into(),
            esp_partuuid: Some("esp".into()),
            roothash: Some(hash.clone()),
        };
        let manifest = ImageManifest::from_resolved(&decl, &snaps, "amd64", Some(&facts));
        assert_eq!(manifest.roothash.as_deref(), Some(hash.as_str()));
        let v = serde_json::to_value(&manifest).unwrap();
        assert_eq!(v["roothash"], hash, "roothash must serialize: {v}");

        // No boot facts → the field is skipped, never null.
        let plain = ImageManifest::from_resolved(&decl, &snaps, "amd64", None);
        let v2 = serde_json::to_value(&plain).unwrap();
        assert!(
            v2.get("roothash").is_none(),
            "roothash must be skipped: {v2}"
        );
    }

    #[test]
    fn kernel_payload_discovery_follows_convention() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("lib/modules/6.8.0-42-generic")).unwrap();
        std::fs::create_dir_all(kdir.path().join("boot")).unwrap();
        std::fs::write(kdir.path().join("boot/vmlinuz-6.8.0-42-generic"), "K").unwrap();
        std::fs::write(kdir.path().join("boot/initrd.img-6.8.0-42-generic"), "I").unwrap();

        let payload = locate_kernel_payload(kdir.path(), root.path()).unwrap();
        assert_eq!(payload.version, "6.8.0-42-generic");
        assert_eq!(
            payload.kernel,
            kdir.path().join("boot/vmlinuz-6.8.0-42-generic")
        );
        assert_eq!(
            payload.initrd,
            kdir.path().join("boot/initrd.img-6.8.0-42-generic")
        );
    }

    #[test]
    fn kernel_payload_missing_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("lib/modules/6.8.0")).unwrap();
        let err = locate_kernel_payload(kdir.path(), root.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("vmlinuz"),
            "error must name the missing kernel asset: {err:#}"
        );
    }

    #[test]
    fn kernel_version_missing_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let err = discover_kernel_version(root.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("lib/modules"),
            "error must name the module tree: {err:#}"
        );
    }

    #[test]
    fn uki_without_ukify_fails_closed_with_doctor_hint() {
        // Injected None ukify: the fail-closed path fires before any file
        // is touched, so dummy paths are safe.
        let err = build_uki_with(
            None,
            Some(Path::new("/usr/lib/systemd/boot/efi/linuxx64.efi.stub")),
            Path::new("/nonexistent/vmlinuz"),
            Path::new("/nonexistent/initrd"),
            "quiet",
            Path::new("/nonexistent/os-release"),
            Path::new("/nonexistent/out.efi"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ukify") && msg.contains("shuttle doctor"),
            "fail-closed error must name ukify and the doctor hint: {msg}"
        );
    }

    #[test]
    fn uki_without_stub_fails_closed() {
        // A fake executable ukify proves the stub check fires BEFORE the
        // command runs — the fake must never be executed.
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("ukify");
        std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = build_uki_with(
            Some(&fake),
            None,
            Path::new("/nonexistent/vmlinuz"),
            Path::new("/nonexistent/initrd"),
            "quiet",
            Path::new("/nonexistent/os-release"),
            Path::new("/nonexistent/out.efi"),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("sd-stub") && msg.contains("linuxx64.efi.stub"),
            "fail-closed error must name the stub: {msg}"
        );
    }

    #[test]
    fn uki_filename_is_deterministic() {
        let image = ImageDeclaration {
            name: "my-system".into(),
            version: "1.2.3".into(),
            base: SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        };
        assert_eq!(uki_filename(&image), "my-system_1.2.3.efi");
        assert_eq!(
            loader_conf(&image),
            "# Generated by shuttle — do not edit.\ntimeout 3\ndefault my-system_*\n"
        );
    }

    #[test]
    fn loader_conf_uses_declared_timeout() {
        let image = ImageDeclaration {
            name: "my-system".into(),
            version: "1.2.3".into(),
            base: SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: Some(BootloaderConfig {
                type_: "systemd-boot".into(),
                timeout: 5,
            }),
            disk: None,
            sysctl: vec![],
            update_source: None,
        };
        assert!(
            loader_conf(&image).contains("timeout 5"),
            "declared bootloader timeout must win: {}",
            loader_conf(&image)
        );
    }

    // ── A/B slots + sysupdate (ADR-0011 step (d)) ──

    fn esp() -> Partition {
        Partition {
            name: "ESP".into(),
            size: "512M".into(),
            fs: "vfat".into(),
            mount: "/boot/efi".into(),
            options: vec![],
            role: String::new(),
        }
    }

    fn root_part() -> Partition {
        Partition {
            name: "root".into(),
            size: "4G".into(),
            fs: "ext4".into(),
            mount: "/".into(),
            options: vec![],
            role: String::new(),
        }
    }

    fn ab_layout() -> DiskLayout {
        DiskLayout {
            label: "gpt".into(),
            partitions: vec![esp(), root_part()],
            swap: None,
            ab: true,
        }
    }

    #[test]
    fn ab_flag_defaults_off_and_parses_opt_in() {
        let lua = lua_env();
        let off: Value = lua
            .load(
                r#"
                return image {
                    name = "d", version = "1", base = pin("core22"),
                    disk = { partitions = { { name = "root", size = "4G", fs = "ext4", mount = "/" } } },
                }
                "#,
            )
            .eval()
            .unwrap();
        let decl = ImageDeclaration::from_lua_table(off.as_table().unwrap()).unwrap();
        assert!(!decl.disk.as_ref().unwrap().ab, "ab defaults off");
        assert!(decl.update_source.is_none(), "update_source defaults off");

        let on: Value = lua
            .load(
                r#"
                return image {
                    name = "d", version = "1", base = pin("core22"),
                    update_source = "https://updates.example.com/os/",
                    disk = { ab = true, partitions = { { name = "root", size = "4G", fs = "ext4", mount = "/" } } },
                }
                "#,
            )
            .eval()
            .unwrap();
        let decl = ImageDeclaration::from_lua_table(on.as_table().unwrap()).unwrap();
        assert!(decl.disk.as_ref().unwrap().ab, "disk.ab = true parses");
        assert_eq!(
            decl.update_source.as_deref(),
            Some("https://updates.example.com/os/"),
            "update_source parses"
        );
    }

    #[test]
    fn ab_expansion_clones_root_and_hash_into_slot_b() {
        let mut layout = ab_layout();
        let slots = expand_ab_slots(&mut layout, true).unwrap();
        // [ESP, root_a, hash_a, root_b, hash_b]
        assert_eq!(slots.roots, vec![1, 3], "slot A first, slot B after hash_a");
        assert_eq!(slots.hashes, vec![Some(2), Some(4)]);
        assert_eq!(layout.partitions.len(), 5);

        let b = &layout.partitions[3];
        assert_eq!(b.name, "root_b", "slot B name carries the _b suffix");
        assert_eq!(b.mount, "/", "slot B IS a root slot, not a data partition");
        assert_eq!(b.fs, "ext4", "same fs as slot A");
        assert_eq!(b.size, "4G", "same size as slot A");
        // Indices never shift.
        assert_eq!(layout.partitions[0].name, "ESP");
        assert_eq!(layout.partitions[1].name, "root");
        assert_eq!(layout.partitions[2].name, VERITY_HASH_PART_NAME);
        assert_eq!(
            layout.partitions[4].name,
            format!("{VERITY_HASH_PART_NAME}_b")
        );
    }

    #[test]
    fn ab_expansion_without_verity_has_no_hash_partitions() {
        let mut layout = ab_layout();
        let slots = expand_ab_slots(&mut layout, false).unwrap();
        // [ESP, root_a, root_b]
        assert_eq!(slots.roots, vec![1, 2]);
        assert_eq!(slots.hashes, vec![None, None]);
        assert_eq!(layout.partitions.len(), 3, "ESP + two roots, no hashes");
        assert_eq!(layout.partitions[2].name, "root_b");
    }

    #[test]
    fn ab_skip_indices_cover_all_slots_and_hashes() {
        let mut layout = ab_layout();
        let slots = expand_ab_slots(&mut layout, true).unwrap();
        assert_eq!(slots.skip_indices(), vec![1, 2, 3, 4]);
        // The ESP (0) stays in the populate stage.
        assert!(!slots.skip_indices().contains(&0));
    }

    #[test]
    fn ab_expansion_doubles_root_and_hash_disk_contributions() {
        let base = DiskLayout {
            label: "gpt".into(),
            partitions: vec![esp(), root_part()],
            swap: None,
            ab: false,
        };
        // Single-slot (ab off) adds only its hash partition (4G root → 33M).
        let mut single = base.clone();
        let _ = expand_ab_slots(&mut single, true).unwrap();
        let mut ab = ab_layout();
        let _ = expand_ab_slots(&mut ab, true).unwrap();
        assert_eq!(
            calculate_disk_size_mb(&single),
            calculate_disk_size_mb(&base) + 33
        );
        // Slot B mirrors root + hash exactly, on top of the single-slot image.
        assert_eq!(
            calculate_disk_size_mb(&ab) - calculate_disk_size_mb(&single),
            4096 + 33
        );
    }

    #[test]
    fn ab_requires_gpt_label() {
        let mut layout = ab_layout();
        layout.label = "mbr".into();
        let err = expand_ab_slots(&mut layout, true).unwrap_err();
        assert!(
            format!("{err:#}").contains("gpt"),
            "MBR + ab must fail closed: {err:#}"
        );
    }

    #[test]
    fn ab_requires_exactly_one_declared_root() {
        let mut layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![root_part(), root_part()],
            swap: None,
            ab: true,
        };
        let err = expand_ab_slots(&mut layout, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("exactly one declared root"),
            "two declared roots must fail closed: {err:#}"
        );
    }

    #[test]
    fn root_partition_indices_orders_declared_roots() {
        let layout = DiskLayout {
            label: "gpt".into(),
            partitions: vec![esp(), root_part(), esp(), root_part()],
            swap: None,
            ab: false,
        };
        assert_eq!(root_partition_indices(&layout), vec![1, 3]);
        // Slot A stays the UKI root target.
        assert_eq!(root_partition_index(&layout).unwrap(), 1);
    }

    #[test]
    fn slot_label_scheme_is_versioned_and_slot_suffixed() {
        assert_eq!(slot_suffix(0), "a");
        assert_eq!(slot_suffix(1), "b");
        assert_eq!(slot_partlabel("os", "1.2.3", 0), "os_1.2.3_a");
        assert_eq!(slot_partlabel("os", "1.2.3", 1), "os_1.2.3_b");
        assert_eq!(hash_partlabel("os", "1.2.3", 0), "os_1.2.3_hash_a");
        assert_eq!(hash_partlabel("os", "1.2.3", 1), "os_1.2.3_hash_b");
    }

    #[test]
    fn sysupdate_type_guids_are_the_documented_x86_64_ids() {
        assert_eq!(ESP_TYPE_GUID, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
        assert_eq!(
            ROOT_TYPE_GUID_X86_64,
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
        );
        assert_eq!(
            VERITY_TYPE_GUID_X86_64,
            "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"
        );
    }

    #[test]
    fn root_transfer_carries_ab_slot_contract() {
        let t = root_transfer("os", 4096);
        assert!(t.contains("[Transfer]"), "sections: {t}");
        assert!(t.contains("[Source]"), "sections: {t}");
        assert!(t.contains("[Target]"), "sections: {t}");
        assert!(
            t.lines().any(|l| l.trim() == "ProtectVersion=%A"),
            "every transfer protects %A: {t}"
        );
        assert!(t.contains("Type=url-file"), "remote source: {t}");
        assert!(t.contains("Path=%v/root.img"), "versioned artifact: {t}");
        assert!(t.contains("Type=partition"), "partition target: {t}");
        assert!(t.contains("Path=in-places"), "in-place slots: {t}");
        assert!(
            t.contains(&format!("MatchPartitionType={ROOT_TYPE_GUID_X86_64}")),
            "matched by x86-64 root TYPE UUID: {t}"
        );
        let pattern = t.lines().find(|l| l.starts_with("MatchPattern=")).unwrap();
        assert_eq!(
            pattern, "MatchPattern=os_@v_a os_@v_b os_empty",
            "both slot labels + the _empty factory fallback: {t}"
        );
        assert!(t.contains("MinSize=4096M"), "slot size floor: {t}");
        assert!(t.contains("InstancesMax=2"), "A/B = two instances: {t}");
        assert!(
            !t.contains("Instances="),
            "no Instances= key (it would override InstancesMax): {t}"
        );
    }

    #[test]
    fn hash_transfer_matches_verity_type_and_shares_version() {
        let t = hash_transfer("os", 33);
        assert!(
            t.contains(&format!("MatchPartitionType={VERITY_TYPE_GUID_X86_64}")),
            "matched by the verity TYPE UUID: {t}"
        );
        assert!(
            t.contains("Path=%v/verity-hash.img"),
            "versioned artifact: {t}"
        );
        assert_eq!(
            t.lines().find(|l| l.starts_with("MatchPattern=")).unwrap(),
            "MatchPattern=os_@v_hash_a os_@v_hash_b os_hash_empty",
            "hash slot labels mirror the root scheme: {t}"
        );
        assert!(t.contains("ProtectVersion=%A"));
        assert!(t.contains("InstancesMax=2"));
        assert!(t.contains("MinSize=33M"));
    }

    #[test]
    fn uki_transfer_installs_with_tries_and_boot_relative_path() {
        let t = uki_transfer("os");
        assert!(
            t.lines().any(|l| l.trim() == "ProtectVersion=%A"),
            "ProtectVersion everywhere: {t}"
        );
        assert!(t.contains("Type=regular-file"), "UKI is a file target: {t}");
        assert!(t.contains("Path=EFI/Linux"), "UKI install dir: {t}");
        assert!(
            t.contains("PathRelativeTo=boot"),
            "regular-file target resolves against $BOOT: {t}"
        );
        let pattern = t
            .lines()
            .find(|l| l.starts_with("MatchPattern="))
            .unwrap()
            .to_string();
        assert!(
            pattern.contains("os_@v+@l-@d.efi"),
            "tries-suffix pattern: {pattern}"
        );
        assert!(
            pattern.contains("os_@v+3-0.efi"),
            "install-time counter state (TriesLeft=3/TriesDone=0): {pattern}"
        );
        assert!(
            pattern.contains("os_@v.efi"),
            "factory UKI ships counter-less and still matches: {pattern}"
        );
        assert!(
            t.lines().any(|l| l.trim() == "TriesLeft=3"),
            "TriesLeft in [Target]: {t}"
        );
        assert!(
            t.lines().any(|l| l.trim() == "TriesDone=0"),
            "TriesDone in [Target]: {t}"
        );
        assert!(t.contains("InstancesMax=2"));
        assert!(t.contains("Path=%v/os_@v.efi"), "versioned artifact: {t}");
    }

    #[test]
    fn factory_uki_filename_stays_tries_compatible() {
        // sysupdate adds +3-0 counters at install; the build emits the
        // counter-less name so a fresh image is always-good (no countdown).
        assert_eq!(uki_filename(&mini_decl("os", "1.2.3")), "os_1.2.3.efi");
        assert!(!uki_filename(&mini_decl("os", "1.2.3")).contains('+'));
    }

    fn mini_decl(name: &str, version: &str) -> ImageDeclaration {
        ImageDeclaration {
            name: name.into(),
            version: version.into(),
            base: SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: None,
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        }
    }

    #[test]
    fn verity_salt_flag_is_threaded_into_the_invocation_shape() {
        // The AB twin contract: same data + same salt ⇒ same roothash. The
        // salt is passed as an explicit --salt argument (before the
        // devices), so both slot formats can share one value.
        let salt = "a".repeat(64);
        let with = verity_format_args(Some(&salt), "DATA", "HASH");
        assert_eq!(&with[9], "--salt");
        assert_eq!(&with[10], &salt);
        assert_eq!(&with[11], "DATA", "devices come last");
        assert_eq!(&with[12], "HASH");
        let without = verity_format_args(None, "DATA", "HASH");
        assert_eq!(without.len(), 11, "no salt flag by default");
        assert!(
            !without.iter().any(|a| a == "--salt"),
            "non-AB single-slot keeps the historical random-salt invocation"
        );
    }

    #[test]
    fn mkfs_pins_4k_blocks_only_under_verity() {
        // The QEMU-proven boot bug: dm-verity hashes 4K data blocks, so the
        // root fs MUST be built with matching blocks — a 1 KiB-block ext4
        // root fails to mount over the verity mapping ("bad block size
        // 1024"). The shared constant's value is asserted exactly here.
        assert_eq!(VERITY_BLOCK_SIZE, 4096);

        let (tool, flags) = mkfs_flags_for("ext4", true).unwrap();
        assert_eq!(tool, "mkfs.ext4");
        let bs = VERITY_BLOCK_SIZE.to_string();
        let pos = flags
            .iter()
            .position(|f| f == "-b")
            .expect("verity ext4 pins -b");
        assert_eq!(flags[pos + 1], bs, "-b takes the shared constant");

        let (tool, flags) = mkfs_flags_for("ext4", false).unwrap();
        assert_eq!(tool, "mkfs.ext4");
        assert_eq!(
            flags,
            vec!["-F", "-L"],
            "non-verity keeps the historical argv (no -b)"
        );
    }

    #[test]
    fn mkfs_btrfs_pins_nodesize_and_sectorsize_only_under_verity() {
        let bs = VERITY_BLOCK_SIZE.to_string();
        let (tool, flags) = mkfs_flags_for("btrfs", true).unwrap();
        assert_eq!(tool, "mkfs.btrfs");
        let n = flags
            .iter()
            .position(|f| f == "--nodesize")
            .expect("verity btrfs pins --nodesize");
        let s = flags
            .iter()
            .position(|f| f == "--sectorsize")
            .expect("verity btrfs pins --sectorsize");
        assert_eq!(flags[n + 1], bs);
        assert_eq!(flags[s + 1], bs);

        let (tool, flags) = mkfs_flags_for("btrfs", false).unwrap();
        assert_eq!(tool, "mkfs.btrfs");
        assert_eq!(flags, vec!["-f", "-L"], "non-verity keeps historical flags");
    }

    #[test]
    fn mkfs_vfat_root_under_verity_fails_closed() {
        let err = mkfs_flags_for("vfat", true).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("vfat"), "error names the fs: {msg}");
        assert!(
            msg.to_lowercase().contains("verity"),
            "error names the conflict: {msg}"
        );
        // Non-verity vfat (the ESP) keeps the historical flags.
        let (tool, flags) = mkfs_flags_for("vfat", false).unwrap();
        assert_eq!(tool, "mkfs.vfat");
        assert_eq!(flags, vec!["-F", "32", "-n"]);
    }

    #[test]
    fn verity_block_size_constant_feeds_both_arg_builders() {
        // One constant, two consumers: the root mkfs flags and
        // veritysetup's --data-block-size/--hash-block-size must agree or
        // the root cannot mount over the verity device.
        let bs = VERITY_BLOCK_SIZE.to_string();
        let (_, flags) = mkfs_flags_for("ext4", true).unwrap();
        assert!(flags.windows(2).any(|w| w[0] == "-b" && w[1] == bs));
        let args = verity_format_args(None, "DATA", "HASH");
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--data-block-size" && w[1] == bs),
            "veritysetup data blocks share the constant: {args:?}"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--hash-block-size" && w[1] == bs),
            "veritysetup hash blocks share the constant: {args:?}"
        );
    }

    #[test]
    fn random_salt_is_64_hex_chars() {
        let salt = random_salt_hex().unwrap();
        assert_eq!(salt.len(), 64, "32 bytes hex: {salt}");
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(random_salt_hex().unwrap(), salt, "fresh entropy per call");
    }

    // ── Unprivileged partition assembly (file-based extents) ──

    /// Realistic `sfdisk -J` shape (validated host output): 512-byte
    /// sectors, hyphenated-uppercase GPT PARTUUIDs, and a partition whose
    /// uuid is null (swap-like entries / sparse GPT entries).
    const SFDISK_J_FIXTURE: &str = r#"{
      "partitiontable": {
        "label": "gpt",
        "id": "9F86D081-0000-0000-0000-000000000000",
        "sector-size": 512,
        "grain": 512,
        "partitions": [
         {
          "node": "loop0p1",
          "start": 8192,
          "size": 61440,
          "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
          "uuid": "ECEBC506-9E2D-4A62-9B0D-3B17F8A41C10"
         },
         {
          "node": "loop0p2",
          "start": 69632,
          "size": 204800,
          "type": "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
          "uuid": "11223344-5566-7788-99AA-BBCCDDEEFF00"
         },
         {
          "node": "loop0p3",
          "start": 274432,
          "size": 204800,
          "type": "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
          "uuid": null
         }
        ]
      }
    }"#;

    #[test]
    fn partition_extents_parse_sectors_bytes_and_partuuids() {
        let extents = parse_partition_extents(SFDISK_J_FIXTURE).unwrap();
        assert_eq!(extents.len(), 3);
        assert_eq!(extents[0].start_bytes, 8192 * 512);
        assert_eq!(extents[0].size_bytes, 61440 * 512);
        assert_eq!(
            extents[0].partuuid.as_deref(),
            Some("ECEBC506-9E2D-4A62-9B0D-3B17F8A41C10")
        );
        // Index = parted partition number - 1, in table order.
        assert_eq!(extents[1].start_bytes, 69632 * 512);
        assert_eq!(extents[1].size_bytes, 204800 * 512);
        // A null uuid is the documented Option path — never an error.
        assert_eq!(extents[2].partuuid, None);
    }

    #[test]
    fn partition_extents_scale_by_reported_sector_size() {
        let json = r#"{"partitiontable":{"sector-size":4096,"partitions":[
            {"start":8,"size":16,"uuid":null}]}}"#;
        let extents = parse_partition_extents(json).unwrap();
        assert_eq!(extents[0].start_bytes, 8 * 4096);
        assert_eq!(extents[0].size_bytes, 16 * 4096);
    }

    #[test]
    fn partition_extents_default_to_512b_sectors() {
        // The validated minimal host shape: no sector-size key at all.
        let json = r#"{"partitiontable":{"partitions":[{"start":8192,"size":61440,"uuid":"X"}]}}"#;
        let extents = parse_partition_extents(json).unwrap();
        assert_eq!(extents[0].start_bytes, 8192 * 512);
        assert_eq!(extents[0].size_bytes, 61440 * 512);
    }

    #[test]
    fn partition_extents_fail_closed_without_table_or_sectors() {
        for bad in [
            r#"{"something":1}"#,
            r#"{"partitiontable":{}}"#,
            r#"{"partitiontable":{"partitions":[{"size":10}]}}"#,
            r#"{"partitiontable":{"partitions":[{"start":10}]}}"#,
            r#"{"partitiontable":{"partitions":[{"start":null,"size":10}]}}"#,
            "not json",
        ] {
            let err = parse_partition_extents(bad).unwrap_err();
            assert!(
                format!("{err:#}").contains("refusing"),
                "must refuse to guess offsets: {err:#}"
            );
        }
    }

    #[test]
    fn splice_places_exact_bytes_at_the_extent_offset() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("img");
        std::fs::write(&img, vec![0xFFu8; 16]).unwrap();
        let part = dir.path().join("part.img");
        std::fs::write(&part, vec![0xAAu8; 8]).unwrap();
        let extent = PartitionExtent {
            start_bytes: 4,
            size_bytes: 8,
            partuuid: None,
        };
        splice_into(&img, &part, &extent).unwrap();
        let bytes = std::fs::read(&img).unwrap();
        assert_eq!(bytes.len(), 16, "image size never changes");
        assert!(bytes[..4].iter().all(|&b| b == 0xFF));
        assert!(bytes[4..12].iter().all(|&b| b == 0xAA));
        assert!(bytes[12..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn splice_refuses_a_short_partition_file() {
        // take() bounds the copy so an oversized source can never overrun
        // the next partition; a short source fails closed instead of
        // splicing stale image bytes.
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("img");
        std::fs::write(&img, vec![0xFFu8; 16]).unwrap();
        let part = dir.path().join("part.img");
        std::fs::write(&part, vec![0xAAu8; 4]).unwrap();
        let extent = PartitionExtent {
            start_bytes: 4,
            size_bytes: 8,
            partuuid: None,
        };
        let err = splice_into(&img, &part, &extent).unwrap_err();
        assert!(
            format!("{err:#}").contains("short"),
            "short splice must be loud: {err:#}"
        );
    }

    #[test]
    fn extent_file_is_truncated_to_the_exact_extent() {
        let dir = tempfile::tempdir().unwrap();
        let extent = PartitionExtent {
            start_bytes: 0,
            size_bytes: 4096,
            partuuid: None,
        };
        let path = extent_file(dir.path(), "p.img", &extent).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4096);
        // Re-creating truncates — a reused name never grows past its
        // extent (an oversized file would make the splice overrun).
        let smaller = PartitionExtent {
            start_bytes: 0,
            size_bytes: 1024,
            partuuid: None,
        };
        let path = extent_file(dir.path(), "p.img", &smaller).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 1024);
    }

    #[test]
    fn unprivileged_build_refuses_btrfs_fail_closed() {
        let part = Partition {
            name: "data".into(),
            size: "1G".into(),
            fs: "btrfs".into(),
            mount: "/data".into(),
            options: vec![],
            role: String::new(),
        };
        let err = refuse_non_ext4_vfat(&part).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ext4 and vfat") && msg.contains("loop-device"),
            "btrfs refusal must name the unprivileged constraint: {msg}"
        );
        // The supported pair passes.
        for fs in ["ext4", "vfat"] {
            let part = Partition {
                fs: fs.into(),
                ..part.clone()
            };
            refuse_non_ext4_vfat(&part).unwrap();
        }
    }

    #[test]
    fn preflight_populate_tools_missing_fails_closed_with_doctor_hint() {
        let err = preflight_populate_tools_with(&[
            ("sfdisk", Some(PathBuf::from("/usr/bin/sfdisk"))),
            ("mmd", None),
            ("mcopy", Some(PathBuf::from("/usr/bin/mcopy"))),
            ("mkfs.ext4", Some(PathBuf::from("/usr/sbin/mkfs.ext4"))),
            ("mkfs.vfat", Some(PathBuf::from("/usr/sbin/mkfs.vfat"))),
        ])
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mmd") && msg.contains("shuttle doctor") && msg.contains("mtools"),
            "fail-closed error must name the tool, the doctor hint, and the package: {msg}"
        );
    }

    #[test]
    fn preflight_populate_tools_all_present_passes() {
        preflight_populate_tools_with(&[
            ("sfdisk", Some(PathBuf::from("/usr/bin/sfdisk"))),
            ("mmd", Some(PathBuf::from("/usr/bin/mmd"))),
            ("mcopy", Some(PathBuf::from("/usr/bin/mcopy"))),
            ("mkfs.ext4", Some(PathBuf::from("/usr/sbin/mkfs.ext4"))),
            ("mkfs.vfat", Some(PathBuf::from("/usr/sbin/mkfs.vfat"))),
        ])
        .unwrap();
    }

    // ── ADR-0019: base-aware kernel/gadget resolution ──

    #[test]
    fn base_track_derives_the_numeric_series() {
        assert_eq!(base_track("core22"), Some("22"));
        assert_eq!(base_track("core24"), Some("24"));
        assert_eq!(base_track("core26"), Some("26"));
        // Non-numeric or differently-shaped bases derive nothing.
        assert_eq!(base_track("core"), None);
        assert_eq!(base_track("core-x"), None);
        assert_eq!(base_track("my-base"), None);
        assert_eq!(base_track(""), None);
    }

    #[test]
    fn core22_kernel_pin_without_channel_resolves_from_22_stable() {
        // The empirical incident: pin("pc-kernel") in a core22 image used
        // to resolve `latest/stable` — a Xenial 4.4 ESM kernel whose initrd
        // has no dm-verity and enforces the UC18 boot contract. ADR-0019
        // derives the base's track instead.
        let (channel, override_used) = image_snap_channel("latest/stable", "core22", None);
        assert_eq!(channel, "22/stable");
        assert!(!override_used);

        let (channel, _) = image_snap_channel("latest/stable", "core26", None);
        assert_eq!(channel, "26/stable");
        // A bare risk channel derives a full track/risk channel.
        let (channel, _) = image_snap_channel("stable", "core22", None);
        assert_eq!(channel, "22/stable");
        // Non-numeric bases leave the channel untouched.
        let (channel, _) = image_snap_channel("latest/stable", "core", None);
        assert_eq!(channel, "latest/stable");
    }

    #[test]
    fn explicit_channel_in_pin_is_untouched() {
        let (channel, override_used) =
            image_snap_channel("latest/stable", "core22", Some("latest/stable"));
        assert_eq!(channel, "latest/stable", "author channel must win verbatim");
        assert!(override_used, "explicit channel is a recorded override");

        let (channel, _) = image_snap_channel("latest/stable", "core22", Some("4.4/stable"));
        assert_eq!(channel, "4.4/stable");
    }

    #[test]
    fn declared_base_mismatch_fails_naming_both() {
        let err = check_declared_base("kernel", "pc-kernel", Some("core"), "core22").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pc-kernel") && msg.contains("core") && msg.contains("core22"),
            "error must name the snap and both bases: {msg}"
        );
        assert!(msg.contains("ADR-0019"), "error must cite the ADR: {msg}");

        // Gadget snaps get the same backstop.
        let err = check_declared_base("gadget", "pc", Some("core18"), "core24").unwrap_err();
        assert!(format!("{err:#}").contains("'core24'"));
    }

    #[test]
    fn matching_declared_base_passes() {
        check_declared_base("kernel", "pc-kernel", Some("core22"), "core22").unwrap();
        check_declared_base("gadget", "pc", Some("core24"), "core24").unwrap();
    }

    #[test]
    fn snap_yaml_base_parses_declared_base_or_none() {
        assert_eq!(
            snap_yaml_base("name: pc-kernel\nversion: 5.15.0\ntype: kernel\nbase: core22\n"),
            Some("core22".into())
        );
        // No base declaration → None (the check logs its skip).
        assert_eq!(
            snap_yaml_base("name: legacy\nversion: 4.4\ntype: kernel\n"),
            None
        );
        assert_eq!(snap_yaml_base("base:\n"), None);
        assert_eq!(snap_yaml_base("not: [valid: yaml"), None);
    }

    #[test]
    fn dsl_kernel_and_gadget_channel_opts_parse() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "override",
                    version = "1.0",
                    base = pin("core22"),
                    kernel = pin("pc-kernel", { channel = "latest/stable" }),
                    gadget = pin("pc", { channel = "24/stable" }),
                }
                "#,
            )
            .eval()
            .unwrap();
        let table = match value {
            Value::Table(t) => t,
            _ => panic!("expected table"),
        };
        let decl = ImageDeclaration::from_lua_table(&table).unwrap();
        assert_eq!(
            decl.kernel.as_ref().unwrap().channel.as_deref(),
            Some("latest/stable")
        );
        assert_eq!(decl.gadget_channel.as_deref(), Some("24/stable"));
    }

    #[test]
    fn dsl_rejects_non_string_channel_opt() {
        let lua = lua_env();
        let result: std::result::Result<Value, mlua::Error> = lua
            .load(
                r#"
                return image {
                    name = "bad",
                    version = "1.0",
                    base = pin("core22"),
                    kernel = pin("pc-kernel", { channel = 22 }),
                }
                "#,
            )
            .eval();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("'kernel.channel' must be a string"),
            "type error must name the field"
        );
    }

    #[test]
    fn base_contract_skips_overridden_kernel_without_touching_disk() {
        // The author-pinned channel is the recorded override: the check
        // returns before the payload is even located, so a missing payload
        // cannot fail it.
        let image = ImageDeclaration {
            name: "override".into(),
            version: "1.0".into(),
            base: SnapRef {
                name: "core22".into(),
                revision: None,
                sha3_384: None,
            },
            kernel: Some(KernelEntry {
                snap: SnapRef {
                    name: "pc-kernel".into(),
                    revision: Some(3720),
                    sha3_384: Some("deadbeef".into()),
                },
                params: vec![],
                modules: vec![],
                modprobe_config: None,
                channel: Some("latest/stable".into()),
            }),
            gadget: None,
            gadget_channel: None,
            extra_snaps: vec![],
            bootloader: None,
            disk: None,
            sysctl: vec![],
            update_source: None,
        };
        let resolved = vec![ResolvedSnap {
            name: "pc-kernel".into(),
            revision: 3720,
            sha3_384: "deadbeef".into(),
            download_url: String::new(),
        }];
        let cache = tempfile::tempdir().unwrap();
        enforce_base_contract(&image, &resolved, cache.path(), true).unwrap();
    }
}
