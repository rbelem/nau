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
use serde::Serialize;
use serde::Serializer;

use crate::command::CommandRunner;
use crate::doctor;
use crate::lock::LockFile;
use crate::snap::SnapRef;
use crate::store::ResolvedSnap;

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

/// The production image runner: every host tool the pipeline invokes runs
/// through this adapter. (`RealRunner` executes the exact argv handed to it;
/// `build_image`/`build_disk_image` pass this unit value down. Kept a named
/// alias so the seam has ONE production spelling for the whole pipeline.)
pub(crate) use crate::command::RealRunner as ImageTools;

// ── Image assembly pipeline ──

/// Build a rootfs image from an image declaration.
pub fn build_image(
    image: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
) -> miette::Result<PathBuf> {
    build_image_with(
        &ImageTools,
        image,
        output_dir,
        cache_dir,
        channel,
        arch,
        lockfile,
    )
}

/// [`build_image`] with the host tool runner injected — the seam a fake
/// runner drives end to end in-process.
pub(crate) fn build_image_with(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
) -> miette::Result<PathBuf> {
    // 1-6. Shared staging: resolve + download/verify + ADR-0019 base
    // contract + base extraction + best-effort kernel merge (issue #57).
    let staged = stage_rootfs(
        runner,
        image,
        cache_dir,
        channel,
        arch,
        lockfile,
        KernelPayloadPolicy::BestEffort,
    )?;
    let root = staged.root;
    let resolved = staged.resolved;
    let snap_paths = staged.snap_paths;
    let _kernel_snap_dir = staged.kernel_snap_dir; // #61 gate reads its config
    let _build_dir = staged.build_dir; // keep the staged rootfs alive

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

    let argv = vec![
        "mksquashfs".to_string(),
        root.to_string_lossy().into_owned(),
        output_path.to_string_lossy().into_owned(),
        "-noappend".to_string(),
        "-comp".to_string(),
        "xz".to_string(),
        "-all-root".to_string(),
    ];

    let out = runner
        .run(&argv)
        .map_err(|e| miette::miette!("mksquashfs not found: {e}"))?;

    if out.code != 0 {
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
    build_disk_image_with(
        &ImageTools,
        image,
        output_dir,
        cache_dir,
        channel,
        arch,
        lockfile,
    )
}

/// [`build_disk_image`] with the host tool runner injected.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_disk_image_with(
    runner: &dyn CommandRunner,
    image: &ImageDeclaration,
    output_dir: &Path,
    cache_dir: &Path,
    channel: &str,
    arch: &str,
    lockfile: &mut LockFile,
) -> miette::Result<PathBuf> {
    // Scratch dir for build ARTIFACTS (disk.img, standalone partition files,
    // UKI stage) — deliberately separate from the staged rootfs, because the
    // rootfs dir IS what gets copied into the partitions by `mkfs.ext4 -d`.
    let scratch = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create scratch directory: {e}"))?;

    // 1-3. Shared staging: resolve + download/verify + ADR-0019 base
    // contract + base extraction + fail-closed kernel merge with the boot
    // payload (issue #57). `Required` preserves the disk build's behavior.
    let staged = stage_rootfs(
        runner,
        image,
        cache_dir,
        channel,
        arch,
        lockfile,
        KernelPayloadPolicy::Required,
    )?;
    let root = staged.root;
    let resolved = staged.resolved;
    let snap_paths = staged.snap_paths;
    let kernel_payload = staged.payload;
    let kernel_snap_dir = staged.kernel_snap_dir;
    let has_unsquashfs = staged.has_unsquashfs;
    let _build_dir = staged.build_dir; // keep the staged rootfs alive

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
    //
    // ADR-0024 §2 (#62): the same gate emits the timer + service that
    // actually run systemd-sysupdate, so the definitions and their trigger
    // cannot drift apart. One predicate drives the pair.
    if emits_sysupdate(image, disk_layout) {
        write_sysupdate_transfers(&root, image, disk_layout)?;
        emit_sysupdate_units(&root)?;
        // The transfers carry ProtectVersion=%A, which resolves to the
        // running system's os-release IMAGE_VERSION= (not VERSION_ID=).
        // Without this the specifier is empty and ProtectVersion protects
        // nothing — an inert transfer is exactly what ADR-0024 closes.
        ensure_os_release_image_version(&root, image)?;
        // ADR-0024 §3 (#63): try-boot assessment on the same gate. The
        // sysupdate transfer writes TriesLeft=3/TriesDone=0 into the UKI;
        // without the bless-boot machinery nothing ever clears the counters,
        // so every update would count down to a spurious revert. The health
        // unit gates boot-complete.target, so a boot that passes marks the
        // generation good and a boot that never passes exhausts TriesLeft.
        emit_boot_assessment(&root)?;
    } else if disk_layout.ab {
        eprintln!(
            "  ℹ disk.ab = true without update_source — sysupdate transfer \
             files skipped (a local-source transfer carries no verification)"
        );
    }

    // 5d. ADR-0024 §4: when the image declares an update source, embed the
    // trusted key SET (/etc/shuttle/trusted-keys/<id>.pub), the revocation
    // list (/etc/shuttle/revoked-keys), and the current signing key's
    // anchor (/etc/shuttle/update-key.pub, kept for backward compatibility).
    // A missing local key FAILS CLOSED — an ordinary build never mints or
    // trusts a key (that would contradict "a rotation whose new key has not
    // been promoted is not trusted"). Keygen is the operator's ceremony.
    if image.update_source.is_some() {
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        let kp = load_signing_key_fail_closed(&home)?;

        // 5d-i. The trusted key set: every local anchor, plus the current
        // signing key (its anchor is installed by `keygen`/`promote`, but
        // be defensive — an operator who deleted the anchor still signs).
        let keys_dir = crate::sign::keys_dir(&home);
        let trusted_dir = root.join(crate::sign::TRUSTED_KEYS_EMBED_DIR);
        std::fs::create_dir_all(&trusted_dir).into_diagnostic()?;
        let chain = crate::sign::Keychain::load_dir(&keys_dir)?;
        let mut embedded = 0usize;
        for anchor in &local_anchor_files(&keys_dir)? {
            let name = anchor
                .file_name()
                .expect("anchor file has a name")
                .to_string_lossy()
                .into_owned();
            std::fs::copy(anchor, trusted_dir.join(&name))
                .into_diagnostic()
                .wrap_err_with(|| format!("embedding trust anchor {}", anchor.display()))?;
            embedded += 1;
        }
        if !chain.key_ids().contains(&kp.key_id()) {
            let path = crate::sign::install_public_key(&kp, &trusted_dir)?;
            eprintln!(
                "  ℹ embedding the signing key as its own trust anchor: {}",
                path.file_name().unwrap().to_string_lossy()
            );
            embedded += 1;
        }

        // 5d-ii. The revocation list (ids only, no key material) — the
        // device distinguisher between "revoked" and "never trusted".
        let revoked = crate::sign::read_revoked_keys(&keys_dir)?;
        let revoked_body: String = revoked.iter().map(|id| format!("{id}\n")).collect();
        std::fs::write(
            root.join(crate::sign::REVOKED_KEYS_EMBED_PATH),
            revoked_body,
        )
        .into_diagnostic()
        .wrap_err_with(|| format!("writing /{}", crate::sign::REVOKED_KEYS_EMBED_PATH))?;

        // 5d-iii. Backward-compatible signing-key anchor.
        let key_path = root.join(crate::sign::PUBKEY_EMBED_PATH);
        std::fs::create_dir_all(key_path.parent().unwrap()).into_diagnostic()?;
        std::fs::write(&key_path, crate::sign::public_key_file(&kp)).into_diagnostic()?;
        eprintln!(
            "  ✓ update trust material embedded: /{}/ ({} anchor(s), {} revoked) + /{} \
             (key id {})",
            crate::sign::TRUSTED_KEYS_EMBED_DIR,
            embedded,
            revoked.len(),
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
    crate::units::emit_app_runtime(runner, &snap_paths, cache_dir, &root, has_unsquashfs)?;

    // 5f. ADR-0023: the persistent state partition and the mutable-/var
    // split. Only images that ask for it (a native `role = "state"` /
    // UC `system-data` partition, or a declared update_source) get the
    // emission — a plain native image is byte-comparable to before.
    // Written here, BEFORE root populate + dm-verity, so /etc/fstab and
    // the tmpfiles land inside the hashed tree.
    // The doctor readiness twin (issue #65): warn-never-fail, unlike the
    // fail-closed `resolve_state_split` below. Reports on the same
    // condition so the build output carries the doctor's named finding.
    doctor::audit_state_partition(image, disk_layout);
    if needs_state_split(image, disk_layout) {
        let split = resolve_state_split(image, disk_layout)?;
        emit_state_split(&root, &split)?;
        // ADR-0023 §4: the boot-time activation oneshot. Gated with the
        // split — the store lives on the state partition, so without the
        // split there is nothing to activate.
        emit_runtime_activate_unit(&root)?;
    }

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
            // ADR-0024 §1 hard gate: the initrd must carry the boot-chain
            // modules the kernel config builds as modules. Fail closed
            // BEFORE any destructive step — a kernel that cannot see its
            // own disk is a brick, not a warning. The config is re-read
            // from the extracted kernel-snap tree (staging keeps it alive).
            let config_dir = kernel_snap_dir
                .as_ref()
                .map(|d| d.path().join("kernel-snap"))
                .unwrap_or_else(|| root.clone());
            let config_dir = config_dir.as_path();
            // Doctor's initrd inventory report line (issue #65) —
            // warn-never-fail; the gate below is the hard one.
            doctor::audit_kernel_initrd_modules(
                runner,
                config_dir,
                &payload.version,
                &payload.initrd,
            );
            audit_initrd_modules(runner, config_dir, payload)?;
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
    create_partitions(runner, &img_path, &effective_layout, total_mb)?;
    // ADR-0011 step (d): A/B layouts additionally get GPT partition type
    // GUIDs + PARTLABELs so systemd-sysupdate can match the slots.
    apply_gpt_slot_metadata(runner, &img_path, image, &effective_layout, &slots)?;

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
    let extents = read_partition_extents(runner, &img_path, expected_partitions)?;
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
        // Unprivileged populate prerequisite: snap packaging ships sentinel
        // dirs with no-owner-read modes (snapd's `var/lib/snapd/void` is
        // 111 --x--x--x), which `mkfs.ext4 -d` cannot scan without root.
        // Normalize to owner-accessible (u+rwX) before any `-d` populate;
        // the adjusted modes are what the filesystem — and the verity hash
        // over it — will carry.
        let root_arg = root.to_string_lossy().into_owned();
        let status = runner
            .run(&[
                "chmod".to_string(),
                "-R".to_string(),
                "u+rwX".to_string(),
                root_arg,
            ])
            .map_err(|e| miette::miette!("chmod not found: {e}"))?;
        if status.code != 0 {
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
            runner,
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
            runner,
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
            runner,
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
            runner,
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
    populate_remaining_partitions(runner, &populate, &effective_layout, &populated_roots)?;

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

/// Parse a size string like "512M" or "4G" or "0" to MB.
pub(super) fn parse_size_mb(size: &str, default_if_zero: u64) -> u64 {
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
pub(super) fn calculate_disk_size_mb(layout: &DiskLayout) -> u64 {
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

/// Load the update signing key for an `update_source` image, FAILING
/// CLOSED when there is none (ADR-0024 §4). A build never mints or trusts
/// a key: the ceremony (`shuttle key keygen`) is the operator's, and a
/// key minted but not promoted must not anchor device verification.
fn load_signing_key_fail_closed(home: &Path) -> miette::Result<crate::sign::KeyPair> {
    crate::sign::load_secret_key(home)?.ok_or_else(|| {
        miette::miette!(
            "image declares update_source but no signing key exists at {} — run \
             `shuttle key keygen` first (a build never mints a key: an untrusted key \
             cannot anchor device verification)",
            crate::sign::secret_key_path(home).display()
        )
    })
}

/// Every `*.pub` file in a local trust-anchor directory, sorted (the
/// byte-stable order an image embed needs). A missing directory is an
/// empty set — the build's no-anchor case fails earlier on the missing
/// signing key. Mirrors [`crate::sign::Keychain::load_dir`]'s selection.
fn local_anchor_files(dir: &Path) -> miette::Result<Vec<PathBuf>> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in read {
        let entry = entry
            .into_diagnostic()
            .wrap_err_with(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "pub") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

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
pub(super) fn cp_r(src: &Path, dst: &Path) -> miette::Result<()> {
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
                } else if let Ok(link) = std::fs::read_link(&path) {
                    // Preserve symlinks as symlinks. A kernel snap ships
                    // absolute links into its own runtime assembly path
                    // (e.g. modules/<ver>/kernel/nvidia-*/nvidia-drm.ko ->
                    // /var/snap/…/nvidia-driver/nvidia-drm.ko) which does not
                    // exist on the build host; following them fails the build
                    // and flattening them would corrupt the staged rootfs.
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)
                            .into_diagnostic()
                            .wrap_err_with(|| format!("creating {:?}", parent))?;
                    }
                    let _ = std::fs::remove_file(&dest);
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&link, &dest)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("linking {:?} to {:?}", dest, link))?;
                } else {
                    // The walk pushes sibling directories as it goes, so a
                    // file can be reached before its own parent has been
                    // created (the pop order is not depth-first in practice).
                    // Creating the parent here makes the copy independent of
                    // traversal order.
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent)
                            .into_diagnostic()
                            .wrap_err_with(|| format!("creating {:?}", parent))?;
                    }
                    std::fs::copy(&path, &dest)
                        .into_diagnostic()
                        .wrap_err_with(|| format!("copying {:?} to {:?}", path, dest))?;
                }
            }
        }
    }
    Ok(())
}

// ── Extracted lifecycle submodules (issue #57) ──
//
// Pure restructuring: partition (extent/fs/populate/splice/geometry/UC
// routing), verity (format/roothash/cmdline trailer/hash extent/A-B slots/
// GPT slot metadata), boot (UKI/ESP/sysupdate transfers), and staging
// (ADR-0019 resolution + the shared rootfs staging pipeline). The
// `pub(crate) use` globs re-export every moved item so existing
// `crate::image::<item>` paths keep resolving without widening visibility.
mod boot;
mod initramfs;
mod partition;
mod staging;
mod state;
mod verity;

pub(crate) use boot::*;
pub(crate) use initramfs::*;
pub(crate) use partition::*;
pub(crate) use staging::*;
pub(crate) use state::*;
pub(crate) use verity::*;

// Genuinely public partition-type GUIDs keep their original `pub` surface.
pub use verity::{ESP_TYPE_GUID, ROOT_TYPE_GUID_X86_64, VERITY_TYPE_GUID_X86_64};

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

    // ── State partition role + /var split (ADR-0023) ──

    fn state_layout() -> DiskLayout {
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
                    name: "root".into(),
                    size: "2G".into(),
                    fs: "ext4".into(),
                    mount: "/".into(),
                    options: vec![],
                    role: String::new(),
                },
                Partition {
                    name: "state".into(),
                    size: "4G".into(),
                    fs: "ext4".into(),
                    mount: "/var/lib".into(),
                    options: vec![],
                    role: ROLE_STATE.into(),
                },
            ],
            swap: None,
            ab: false,
        }
    }

    #[test]
    fn state_role_is_classified_for_native_images() {
        let mut p = part_named("persist");
        assert!(!is_state_partition(&p), "a plain partition is not state");
        p.role = ROLE_STATE.into();
        assert!(is_state_role(&p.role));
        assert!(
            is_state_partition(&p),
            "native role = \"state\" maps to state"
        );
        // UC system-data describes the same runtime concept.
        let mut uc = part_named("writable");
        uc.role = crate::uc::ROLE_DATA.into();
        assert!(is_state_partition(&uc));
        // ...and by its ubuntu-data PARTLABEL too.
        assert!(is_state_partition(&part_named("ubuntu-data")));
        // Root / ESP / swap are never state.
        assert!(!is_state_partition(&part_named("root")));
        assert!(!is_state_partition(&part_named("esp")));
    }

    #[test]
    fn state_role_on_a_uc_base_still_remaps_system_data() {
        // A UC image keeps its gadget role spelling; partition_uc_role is
        // unchanged, and the same partition is classified as state.
        let mut layout = uc_layout();
        for p in &mut layout.partitions {
            if p.name == "seedpool" {
                p.name = "statepool".into();
                p.role = crate::uc::ROLE_DATA.into();
                p.mount = "/var/lib".into();
            }
        }
        assert_eq!(
            partition_uc_role(&layout.partitions[2]),
            Some(crate::uc::ROLE_DATA)
        );
        assert!(is_state_partition(&layout.partitions[2]));
    }

    #[test]
    fn needs_state_split_is_opt_in() {
        let image = test_support::sample_image(); // no update_source, core24
                                                  // Plain native layout, no role → historical behavior.
        let plain = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part_named("root")],
            swap: None,
            ab: false,
        };
        assert!(!needs_state_split(&image, &plain));
        // A state role activates the split.
        assert!(needs_state_split(&image, &state_layout()));
        // An update_source activates it even without a declared role.
        let mut updating = image.clone();
        updating.update_source = Some("https://example.invalid/updates/".into());
        assert!(needs_state_split(&updating, &plain));
    }

    #[test]
    fn state_split_fails_closed_without_a_state_partition() {
        let plain = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part_named("root")],
            swap: None,
            ab: false,
        };
        let image = test_support::sample_image();
        let err = resolve_state_split(&image, &plain).unwrap_err().to_string();
        assert!(
            err.contains("no state partition")
                && err.contains("role = \"state\"")
                && err.contains(crate::runtime::DEFAULT_STATE_DIR)
                && err.contains(crate::runtime::DEFAULT_EXTENSIONS_LINK_DIR),
            "precise fail-closed message: {err}"
        );

        // The update_source trigger names itself in the message.
        let mut updating = image.clone();
        updating.update_source = Some("https://example.invalid/updates/".into());
        let err = resolve_state_split(&updating, &plain)
            .unwrap_err()
            .to_string();
        assert!(err.contains("update_source"), "names the trigger: {err}");
    }

    #[test]
    fn state_split_resolves_partlabel_and_submount_scope() {
        let image = test_support::sample_image();
        let split = resolve_state_split(&image, &state_layout()).unwrap();
        assert_eq!(split.partlabel, "state");
        assert_eq!(split.var_submount_partlabel, "", "no /var/* child mount");

        // A declared partition under /var scopes the tmpfs mount.
        let mut layout = state_layout();
        layout.partitions.push(Partition {
            name: "docker".into(),
            size: "8G".into(),
            fs: "ext4".into(),
            mount: "/var/lib/docker".into(),
            options: vec![],
            role: String::new(),
        });
        let split = resolve_state_split(&image, &layout).unwrap();
        assert_eq!(split.var_submount_partlabel, "docker");
    }

    #[test]
    fn fstab_mounts_state_at_var_lib_and_var_volatile() {
        let split = StateSplit {
            partlabel: "state".into(),
            var_submount_partlabel: String::new(),
        };
        let fstab = fstab_content(&split);
        // Persistent state partition → /var/lib, by PARTLABEL.
        assert!(
            fstab.contains("PARTLABEL=state /var/lib auto defaults,nofail"),
            "state mount line: {fstab}"
        );
        // /var itself is tmpfs — volatile skeleton.
        assert!(
            fstab.contains("tmpfs /var tmpfs mode=0755,nosuid,nodev"),
            "volatile /var line: {fstab}"
        );
        // The state mount never routes through the verity root.
        assert!(
            !fstab.contains("/dev/mapper") && !fstab.contains("verity_root"),
            "no verity device in fstab: {fstab}"
        );
    }

    #[test]
    fn fstab_scopes_var_tmpfs_to_a_var_submount() {
        let split = StateSplit {
            partlabel: "writable".into(),
            var_submount_partlabel: "docker".into(),
        };
        let fstab = fstab_content(&split);
        assert!(
            fstab.contains("x-systemd.requires-mounts-for=/dev/disk/by-partlabel/docker"),
            "tmpfs must require the /var/lib subvolume mount: {fstab}"
        );
    }

    #[test]
    fn tmpfiles_create_the_state_and_volatile_var_skeleton() {
        let state = state_tmpfiles_content();
        assert!(state.contains("d /var/lib 0755 root root -"));
        assert!(state.contains("d /var/lib/shuttle 0755 root root -"));
        assert!(state.contains("d /var/lib/extensions 0755 root root -"));

        let var = var_tmpfiles_content();
        for dir in ["/var", "/var/run", "/var/tmp", "/var/cache", "/var/log"] {
            assert!(
                var.contains(&format!("d {dir} 0755 root root -")),
                "tmpfiles create {dir}: {var}"
            );
        }
    }

    #[test]
    fn emit_state_split_writes_fstab_and_tmpfiles_into_the_rootfs() {
        let root = tempfile::tempdir().unwrap();
        let split = StateSplit {
            partlabel: "state".into(),
            var_submount_partlabel: String::new(),
        };
        emit_state_split(root.path(), &split).unwrap();
        assert!(root.path().join(FSTAB_PATH).is_file());
        assert!(root.path().join(STATE_TMPFILES_PATH).is_file());
        assert!(root.path().join(VAR_TMPFILES_PATH).is_file());
        let fstab = std::fs::read_to_string(root.path().join(FSTAB_PATH)).unwrap();
        assert!(fstab.contains("PARTLABEL=state /var/lib"));
    }

    #[test]
    fn state_partition_is_not_cloned_into_slot_b() {
        // A/B with a root + a state partition: only the root is cloned.
        let mut layout = state_layout();
        layout.ab = true;
        let slots = expand_ab_slots(&mut layout, false).unwrap();
        assert_eq!(slots.roots, vec![1, 3], "root A + its slot-B twin");
        // Slot B is the root twin; no second state partition appears.
        let state_parts: Vec<&Partition> = layout
            .partitions
            .iter()
            .filter(|p| is_state_partition(p))
            .collect();
        assert_eq!(state_parts.len(), 1, "state is never cloned: {layout:?}");
        assert_eq!(state_parts[0].name, "state");
        let clones: Vec<&Partition> = layout
            .partitions
            .iter()
            .filter(|p| p.name.ends_with("_b"))
            .collect();
        assert_eq!(clones.len(), 1, "exactly one slot-B twin: {clones:?}");
        assert_eq!(clones[0].name, "root_b");
    }

    #[test]
    fn expand_ab_slots_refuses_a_state_role_root() {
        let mut layout = state_layout();
        layout.ab = true;
        // Mark the root as state: the clone guard must fail closed rather
        // than turn the persistent partition into a slot twin.
        layout.partitions[1].role = ROLE_STATE.into();
        let err = expand_ab_slots(&mut layout, false).unwrap_err().to_string();
        assert!(
            err.contains("must not be an A/B root"),
            "state root refused: {err}"
        );
    }

    #[test]
    fn disk_role_parses_state_and_uc_roles_through_the_dsl() {
        let lua = lua_env();
        let value: Value = lua
            .load(
                r#"
                return image {
                    name = "native",
                    version = "1.0.0",
                    base = pin("my-base"),
                    disk = {
                        label = "gpt",
                        partitions = {
                            { name = "esp", size = "512M", fs = "vfat", mount = "/boot/efi" },
                            { name = "root", size = "2G", fs = "ext4", mount = "/" },
                            { name = "state", size = "4G", fs = "ext4", mount = "/var/lib",
                              role = "state" },
                            { name = "seed", size = "1G", fs = "ext4", mount = "/seed",
                              role = "system-seed" },
                        },
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
        assert_eq!(disk.partitions[2].role, "state");
        assert!(is_state_partition(&disk.partitions[2]));
        assert_eq!(disk.partitions[3].role, "system-seed");
        assert!(!is_state_partition(&disk.partitions[3]));
    }

    #[test]
    fn no_state_role_emits_no_split_artifacts_into_the_rootfs() {
        // Regression guard (ADR-0023): a plain native image must add NO
        // fstab, no tmpfiles.d and no /var mount. The emit function is
        // gated by `needs_state_split`; assert the gate is false and the
        // rootfs is untouched.
        let image = test_support::sample_image();
        let plain = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part_named("root")],
            swap: None,
            ab: false,
        };
        assert!(!needs_state_split(&image, &plain));
        let root = tempfile::tempdir().unwrap();
        // Simulate the pipeline's conditional emission.
        if needs_state_split(&image, &plain) {
            let split = resolve_state_split(&image, &plain).unwrap();
            emit_state_split(root.path(), &split).unwrap();
        }
        assert!(!root.path().join(FSTAB_PATH).exists());
        assert!(!root.path().join(STATE_TMPFILES_PATH).exists());
        assert!(!root.path().join(VAR_TMPFILES_PATH).exists());
    }

    // ── Boot-time activation oneshot (ADR-0023 §4, #60) ──

    #[test]
    fn activate_unit_golden_text() {
        // Pinned byte-for-byte, mirroring the emit.rs / units.rs
        // `render_unit` golden tests. The unit is emitted data (ADR-0011
        // §5), so its exact body is the contract.
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=shuttle: activate the current runtime generation
# The store lives on the persistent state partition (ADR-0023);
# wait for its mount before touching generations.
After=local-fs.target
RequiresMountsFor=/var/lib

[Service]
Type=oneshot
RemainAfterExit=yes
# Idempotent and boot-safe: a cold store is a no-op and a
# half-written journal is discarded (see activate_current).
ExecStart=shuttle runtime activate

[Install]
WantedBy=multi-user.target
";
        assert_eq!(activate_unit_content(), expected);
    }

    #[test]
    fn emit_runtime_activate_unit_writes_unit_and_enablement() {
        let root = tempfile::tempdir().unwrap();
        emit_runtime_activate_unit(root.path()).unwrap();

        let unit = root.path().join(ACTIVATE_UNIT_PATH);
        assert!(unit.is_file(), "unit written at {}", unit.display());
        let text = std::fs::read_to_string(&unit).unwrap();
        assert!(text.contains("Type=oneshot"), "oneshot: {text}");
        assert!(text.contains("RemainAfterExit=yes"));
        assert!(text.contains("ExecStart=shuttle runtime activate"));
        assert!(text.contains("WantedBy=multi-user.target"));
        assert!(
            text.contains("RequiresMountsFor=/var/lib"),
            "ordered after the state mount: {text}"
        );

        // Enablement is the relative symlink `emit::enable_unit` produces.
        let link = root
            .path()
            .join("etc/systemd/system/multi-user.target.wants")
            .join(ACTIVATE_UNIT_NAME);
        let meta = std::fs::symlink_metadata(&link)
            .unwrap_or_else(|e| panic!("enablement link missing at {}: {e}", link.display()));
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../shuttle-runtime-activate.service")
        );
    }

    #[test]
    fn no_state_split_emits_no_activate_unit() {
        // Boot-regression guard: an image with no state role must not gain
        // the activation oneshot, because there is no state partition
        // holding a runtime store to activate.
        let image = test_support::sample_image();
        let plain = DiskLayout {
            label: "gpt".into(),
            partitions: vec![part_named("root")],
            swap: None,
            ab: false,
        };
        assert!(!needs_state_split(&image, &plain));
        let root = tempfile::tempdir().unwrap();
        if needs_state_split(&image, &plain) {
            emit_runtime_activate_unit(root.path()).unwrap();
        }
        assert!(!root.path().join(ACTIVATE_UNIT_PATH).exists());
        assert!(!root
            .path()
            .join("etc/systemd/system/multi-user.target.wants")
            .join(ACTIVATE_UNIT_NAME)
            .exists());
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
        let err = verity_format_with(&ImageTools, None, "/dev/loop0p2", "/dev/loop0p3", None)
            .unwrap_err();
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

        let payload =
            locate_kernel_payload(&ImageTools, None, kdir.path(), kdir.path(), root.path())
                .unwrap();
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
        // No raw vmlinuz/initrd and no kernel.efi: the payload is absent.
        let err = locate_kernel_payload(&ImageTools, None, kdir.path(), kdir.path(), root.path())
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("vmlinuz") && msg.contains("kernel.efi"),
            "error must name the missing kernel assets: {msg}"
        );
    }

    /// The real Ubuntu Core `pc-kernel` layout (#70): root-level
    /// `kernel.efi` + `modules/<ver>/` + an empty `modules/<ver>/initrd`
    /// DIRECTORY. A fake objcopy writes the section payloads; the extracted
    /// bzImage carries the matching banner, so discovery succeeds.
    struct ObjcopyRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        banner: String,
    }

    impl crate::command::CommandRunner for ObjcopyRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let section = argv[3].clone();
            let out = &argv[5];
            let body = if section == "--only-section=.linux" {
                format!(
                    "....Linux version {} (buildd@lcy02) #1 SMP....",
                    self.banner
                )
            } else {
                "newc-initrd".to_string()
            };
            std::fs::write(out, body).unwrap();
            Ok(crate::command::RunnerOutput {
                code: 0,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    fn uc_kernel_snap_fixture(kdir: &Path, version: &str) {
        std::fs::create_dir_all(kdir.join("kernel").join("modules").join(version)).unwrap();
        std::fs::create_dir_all(kdir.join(format!("modules/{version}"))).unwrap();
        // The real snap ships an EMPTY initrd directory, not a file.
        std::fs::create_dir_all(kdir.join(format!("modules/{version}/initrd"))).unwrap();
        std::fs::write(kdir.join("kernel.efi"), b"MZ-fake-uki").unwrap();
        std::fs::write(
            kdir.join(format!("config-{version}")),
            b"CONFIG_DM_VERITY=y\n",
        )
        .unwrap();
    }

    #[test]
    fn kernel_payload_prebuilt_uki_is_split_with_objcopy() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        let version = "5.15.0-186-generic";
        // copy_kernel_tree mirrors modules/<ver> into lib/modules/<ver>.
        std::fs::create_dir_all(root.path().join("lib/modules").join(version)).unwrap();
        uc_kernel_snap_fixture(kdir.path(), version);
        // The empty modules/<ver>/initrd DIRECTORY must never be selected.
        std::fs::create_dir_all(kdir.path().join(format!("modules/{version}/initrd"))).unwrap();

        let runner = ObjcopyRunner {
            calls: std::sync::Mutex::new(Vec::new()),
            banner: version.to_string(),
        };
        let scratch = tempfile::tempdir().unwrap();
        let payload = locate_kernel_payload(
            &runner,
            Some(Path::new("/usr/bin/objcopy")),
            scratch.path(),
            kdir.path(),
            root.path(),
        )
        .unwrap();
        assert_eq!(payload.version, version);
        assert!(payload.kernel.is_file());
        assert!(payload.initrd.is_file());
        assert!(payload.kernel.starts_with(scratch.path()));

        let calls = runner.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2, "one objcopy per section: {calls:?}");
        assert_eq!(
            calls[0][..4],
            ["/usr/bin/objcopy", "-O", "binary", "--only-section=.linux"]
        );
        assert_eq!(
            calls[0][4],
            kdir.path().join("kernel.efi").to_string_lossy()
        );
        assert_eq!(calls[0][5], payload.kernel.to_string_lossy());
        assert_eq!(calls[1][..4][3], "--only-section=.initrd", "second section");
        assert_eq!(calls[1][5], payload.initrd.to_string_lossy());
    }

    #[test]
    fn kernel_payload_prebuilt_uki_without_objcopy_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        let version = "5.15.0-186-generic";
        std::fs::create_dir_all(root.path().join("lib/modules").join(version)).unwrap();
        uc_kernel_snap_fixture(kdir.path(), version);
        let scratch = tempfile::tempdir().unwrap();

        let err =
            locate_kernel_payload(&ImageTools, None, scratch.path(), kdir.path(), root.path())
                .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("objcopy") && msg.contains("binutils"),
            "missing objcopy must name the tool and the fix: {msg}"
        );
    }

    #[test]
    fn kernel_payload_prebuilt_uki_version_mismatch_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        let version = "5.15.0-186-generic";
        std::fs::create_dir_all(root.path().join("lib/modules").join(version)).unwrap();
        uc_kernel_snap_fixture(kdir.path(), version);
        let runner = ObjcopyRunner {
            calls: std::sync::Mutex::new(Vec::new()),
            banner: "5.15.0-90-generic".to_string(),
        };
        let scratch = tempfile::tempdir().unwrap();

        let err = locate_kernel_payload(
            &runner,
            Some(Path::new("/usr/bin/objcopy")),
            scratch.path(),
            kdir.path(),
            root.path(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("5.15.0-90-generic") && msg.contains(version),
            "mismatch must name both versions: {msg}"
        );
    }

    #[test]
    fn kernel_payload_failed_objcopy_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let kdir = tempfile::tempdir().unwrap();
        let version = "5.15.0-186-generic";
        std::fs::create_dir_all(root.path().join("lib/modules").join(version)).unwrap();
        uc_kernel_snap_fixture(kdir.path(), version);
        let runner = FailingObjcopyRunner;
        let scratch = tempfile::tempdir().unwrap();

        let err = locate_kernel_payload(
            &runner,
            Some(Path::new("/usr/bin/objcopy")),
            scratch.path(),
            kdir.path(),
            root.path(),
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("objcopy") && msg.contains(".linux"),
            "a failed section extraction must name the section: {msg}"
        );
    }

    struct FailingObjcopyRunner;

    impl crate::command::CommandRunner for FailingObjcopyRunner {
        fn run(&self, _argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            Ok(crate::command::RunnerOutput {
                code: 1,
                stdout: Vec::new(),
                stderr: "no such section".into(),
            })
        }
    }

    #[test]
    fn first_existing_never_selects_a_directory_named_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join("initrd");
        std::fs::create_dir_all(&candidate).unwrap();
        assert!(
            first_existing([candidate.clone()]).is_none(),
            "a directory named initrd is not a boot payload: {candidate:?}"
        );
    }

    #[test]
    fn bzimage_banner_version_reads_the_linux_version_string() {
        let mut image = vec![0u8; 4096];
        image.extend_from_slice(b"..Linux version 5.15.0-186-generic (buildd) #1 SMP..");
        assert_eq!(
            bzimage_banner_version(&image).as_deref(),
            Some("5.15.0-186-generic")
        );
        assert_eq!(bzimage_banner_version(b"no banner here"), None);
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

    // ── Initrd boot-chain module gate (ADR-0024 §1) ──

    /// A fake runner for the gate: answers every decompressor with the
    /// supplied stdout, recording calls (an uncompressed initrd needs none).
    struct GateRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        stdout: Vec<u8>,
    }

    impl GateRunner {
        fn new(stdout: Vec<u8>) -> GateRunner {
            GateRunner {
                calls: std::sync::Mutex::new(Vec::new()),
                stdout,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl crate::command::CommandRunner for GateRunner {
        fn run(&self, argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            Ok(crate::command::RunnerOutput {
                code: 0,
                stdout: self.stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    /// Minimal `newc` cpio archive carrying `members` and a trailer.
    fn gate_newc_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let align4 = |n: usize| (n + 3) & !3;
        let member = |name: &str, data: &[u8]| -> Vec<u8> {
            let mut out = format!(
                "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
                1,
                0o100644,
                0,
                0,
                1,
                0,
                data.len(),
                0,
                0,
                0,
                0,
                name.len() + 1,
                0,
            )
            .into_bytes();
            assert_eq!(out.len(), 110);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.resize(align4(out.len()), 0);
            out.extend_from_slice(data);
            out.resize(align4(out.len()), 0);
            out
        };
        let mut out = Vec::new();
        for (name, data) in members {
            out.extend_from_slice(&member(name, data));
        }
        out.extend_from_slice(&member("TRAILER!!!", b""));
        out
    }

    /// A kernel payload fixture at `payload_dir` whose initrd carries the
    /// given `.ko` members; returns the payload the gate consumes.
    fn gate_payload(
        payload_dir: &Path,
        kernel_version: &str,
        initrd_members: &[(&str, &[u8])],
        initrd_bytes: Option<&[u8]>,
    ) -> KernelPayload {
        let boot = payload_dir.join("boot");
        std::fs::create_dir_all(&boot).unwrap();
        let initrd = boot.join(format!("initrd.img-{kernel_version}"));
        let bytes = match initrd_bytes {
            Some(b) => b.to_vec(),
            None => gate_newc_archive(initrd_members),
        };
        std::fs::write(&initrd, bytes).unwrap();
        std::fs::write(boot.join(format!("vmlinuz-{kernel_version}")), b"K").unwrap();
        KernelPayload::raw(
            boot.join(format!("vmlinuz-{kernel_version}")),
            initrd,
            kernel_version.to_string(),
        )
    }

    fn gate_write_config(payload_dir: &Path, kernel_version: &str, body: &str) {
        let boot = payload_dir.join("boot");
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join(format!("config-{kernel_version}")), body).unwrap();
    }

    const GATE_ALL_MODULES_M: &str = "\
CONFIG_VIRTIO_BLK=m
CONFIG_VIRTIO_PCI=m
CONFIG_DM_MOD=m
CONFIG_DM_VERITY=m
CONFIG_EXT4_FS=m
";

    #[test]
    fn gate_missing_module_fails_closed_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        gate_write_config(dir.path(), "6.8.0", GATE_ALL_MODULES_M);
        // Every module but virtio_blk.
        let payload = gate_payload(
            dir.path(),
            "6.8.0",
            &[
                ("kernels/6.8.0/virtio_pci.ko", b"k"),
                ("kernels/6.8.0/dm_mod.ko", b"k"),
                ("kernels/6.8.0/dm-verity.ko.xz", b"k"),
                ("kernels/6.8.0/ext4.ko", b"k"),
            ],
            None,
        );
        let runner = GateRunner::new(Vec::new());
        let err = audit_initrd_modules(&runner, dir.path(), &payload).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("virtio_blk"),
            "the error must name the missing module: {msg}"
        );
        assert!(
            msg.contains("config-6.8.0"),
            "the error must name the config provenance: {msg}"
        );
    }

    #[test]
    fn gate_complete_module_set_builds_green() {
        let dir = tempfile::tempdir().unwrap();
        gate_write_config(dir.path(), "6.8.0", GATE_ALL_MODULES_M);
        let payload = gate_payload(
            dir.path(),
            "6.8.0",
            &[
                ("kernels/6.8.0/virtio_blk.ko", b"k"),
                ("kernels/6.8.0/virtio_pci.ko.gz", b"k"),
                ("kernels/6.8.0/dm_mod.ko", b"k"),
                ("kernels/6.8.0/dm-verity.ko.zst", b"k"),
                ("kernels/6.8.0/ext4.ko", b"k"),
            ],
            None,
        );
        let runner = GateRunner::new(Vec::new());
        audit_initrd_modules(&runner, dir.path(), &payload)
            .expect("a complete initrd must pass the gate");
    }

    #[test]
    fn gate_built_in_modules_need_no_initrd() {
        let dir = tempfile::tempdir().unwrap();
        gate_write_config(
            dir.path(),
            "6.8.0",
            "CONFIG_VIRTIO_BLK=y\nCONFIG_EXT4_FS=y\n",
        );
        // An otherwise unreadable initrd is irrelevant when nothing is a module.
        let payload = gate_payload(dir.path(), "6.8.0", &[], Some(b"garbage"));
        let runner = GateRunner::new(Vec::new());
        audit_initrd_modules(&runner, dir.path(), &payload)
            .expect("a fully built-in config requires nothing from the initrd");
    }

    #[test]
    fn gate_without_kernel_config_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let payload = gate_payload(
            dir.path(),
            "6.8.0",
            &[("kernels/6.8.0/virtio_blk.ko", b"k")],
            None,
        );
        let runner = GateRunner::new(Vec::new());
        let err = audit_initrd_modules(&runner, dir.path(), &payload).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no kernel config") && msg.contains("must not ship"),
            "an unavailable config must fail closed precisely: {msg}"
        );
    }

    #[test]
    fn gate_unrecognized_initrd_format_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        gate_write_config(dir.path(), "6.8.0", "CONFIG_VIRTIO_BLK=m\n");
        let payload = gate_payload(dir.path(), "6.8.0", &[], Some(b"random bytes, no magic"));
        let runner = GateRunner::new(Vec::new());
        let err = audit_initrd_modules(&runner, dir.path(), &payload).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unrecognized initrd format"),
            "an unreadable initrd must fail closed naming the format: {msg}"
        );
    }

    #[test]
    fn gate_routes_decompression_through_the_runner() {
        // A gzip-magic initrd: the gate must call `gzip -dc` through the
        // injected runner, never a real subprocess.
        let dir = tempfile::tempdir().unwrap();
        gate_write_config(dir.path(), "6.8.0", "CONFIG_VIRTIO_BLK=m\n");
        // Fixed gzip header is enough to select gzip; the fake runner
        // answers with a real newc archive carrying the module.
        let mut initrd = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        initrd.extend_from_slice(b"ignored-because-the-runner-answers");
        let payload = gate_payload(dir.path(), "6.8.0", &[], Some(&initrd));
        let runner = GateRunner::new(gate_newc_archive(&[("kernels/6.8.0/virtio_blk.ko", b"k")]));
        audit_initrd_modules(&runner, dir.path(), &payload)
            .expect("fake gzip output satisfies gate");
        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "one decompressor call: {calls:?}");
        assert_eq!(calls[0][0], "gzip");
        assert_eq!(calls[0][1], "-dc");
    }

    #[test]
    fn uki_without_ukify_fails_closed_with_doctor_hint() {
        // Injected None ukify: the fail-closed path fires before any file
        // is touched, so dummy paths are safe.
        let err = build_uki_with(
            &ImageTools,
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
            &ImageTools,
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

    // ── sysupdate trigger units (ADR-0024 §2, #62) ──

    fn sysupdate_decl(name: &str) -> ImageDeclaration {
        let mut image = mini_decl(name, "1.2.3");
        image.update_source = Some("https://updates.example.com/os/".into());
        image
    }

    #[test]
    fn sysupdate_service_golden_text() {
        // Pinned byte-for-byte, mirroring the activate-unit and emit.rs
        // golden tests. The unit is emitted data (ADR-0011 §5), so its
        // exact body is the contract.
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=shuttle: apply systemd-sysupdate A/B updates
# url-file transfers fetch over the network.
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# A disposable-root update is a discrete job, not a state to hold.
RemainAfterExit=no
ExecStart=systemd-sysupdate update
";
        assert_eq!(sysupdate_service_content(), expected);
    }

    #[test]
    fn sysupdate_timer_golden_text() {
        // Daily + a randomized delay: bounded staleness without a
        // fleet-wide thundering herd. `Unit=` pulls the service; the timer
        // is the only thing enabled.
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=shuttle: periodic systemd-sysupdate check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
Unit=systemd-sysupdate.service

[Install]
WantedBy=timers.target
";
        assert_eq!(sysupdate_timer_content(), expected);
    }

    #[test]
    fn emit_sysupdate_units_writes_units_and_timer_enablement() {
        let root = tempfile::tempdir().unwrap();
        emit_sysupdate_units(root.path()).unwrap();

        let service = root.path().join(SYSUPDATE_SERVICE_PATH);
        let timer = root.path().join(SYSUPDATE_TIMER_PATH);
        assert!(service.is_file(), "service at {}", service.display());
        assert!(timer.is_file(), "timer at {}", timer.display());

        // The timer is enabled into timers.target with the relative
        // symlink emit::enable_unit produces; the service is pulled by the
        // timer, not enabled anywhere.
        let link = root
            .path()
            .join("etc/systemd/system/timers.target.wants")
            .join(SYSUPDATE_TIMER_NAME);
        let meta = std::fs::symlink_metadata(&link)
            .unwrap_or_else(|e| panic!("enablement link missing at {}: {e}", link.display()));
        assert!(meta.file_type().is_symlink(), "enablement is a symlink");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../systemd-sysupdate.timer"),
            "relative symlink target"
        );
        let service_link = root
            .path()
            .join("etc/systemd/system/multi-user.target.wants")
            .join(SYSUPDATE_SERVICE_NAME);
        assert!(
            !service_link.exists(),
            "the service must not be separately enabled — the timer pulls it"
        );
    }

    #[test]
    fn sysupdate_units_agree_with_the_transfer_definitions_dir() {
        // The unit cannot name a transfer path: it relies on
        // systemd-sysupdate's default definitions search path, which is
        // where write_sysupdate_transfers writes. Assert BOTH halves of
        // that agreement — the constant is the default `usr/lib/sysupdate.d`
        // root and the unit deliberately carries no --definitions flag.
        assert_eq!(SYSUPDATE_DIR, "usr/lib/sysupdate.d");
        let service = sysupdate_service_content();
        assert!(
            service.contains("ExecStart=systemd-sysupdate update"),
            "runs systemd's update machinery: {service}"
        );
        assert!(
            !service.contains("--definitions") && !service.contains("--transfer-source"),
            "the unit must not restate the definitions path (drift): {service}"
        );
    }

    #[test]
    fn sysupdate_units_live_in_the_override_dir_not_the_vendor_path() {
        // The systemd package ships its own systemd-sysupdate.service/.timer
        // at /usr/lib/systemd/system/. We emit at the SAME unit names, so
        // writing the vendor path would collide (install-order-dependent
        // winner) rather than replace. /etc/systemd/system is the documented
        // override location that masks the vendor unit by precedence.
        for path in [SYSUPDATE_SERVICE_PATH, SYSUPDATE_TIMER_PATH] {
            assert!(
                path.starts_with("etc/systemd/system/"),
                "must be an admin override, not the vendor path: {path}"
            );
            assert!(
                !path.starts_with("usr/lib/systemd/system/"),
                "must not collide with the systemd package's own unit: {path}"
            );
        }
    }

    // ── Boot assessment: try-boot + revert (ADR-0024 §3, #63) ──

    #[test]
    fn bless_boot_service_golden_text() {
        // Pinned byte-for-byte, mirroring the sysupdate/activate golden
        // tests. Mirrors the stock systemd unit shape
        // (`systemd-bless-boot.service(8)`; systemd source
        // `units/systemd-bless-boot.service.in`): runs AFTER
        // boot-complete.target, so the target (and the health gate
        // ordering before it) must succeed before the counters are cleared.
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=Mark the Current Boot Loader Entry as Good
Documentation=man:systemd-bless-boot.service(8)
DefaultDependencies=no
Requires=boot-complete.target
After=local-fs.target boot-complete.target
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/systemd/systemd-bless-boot good
";
        assert_eq!(bless_boot_service_content(), expected);
        // The exact stock invocation: helper path + `good` subcommand
        // (`systemd-bless-boot.service(8)` SYNOPSIS + OPTIONS `good`).
        assert_eq!(BLESS_BOOT_EXEC, "/usr/lib/systemd/systemd-bless-boot good");
    }

    #[test]
    fn boot_complete_target_golden_text() {
        // Mirrors the stock systemd target body
        // (`systemd.special(7)`, `boot-complete.target`).
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=Boot Completion Check
Documentation=man:systemd.special(7)
Requires=sysinit.target
After=sysinit.target
";
        assert_eq!(boot_complete_target_content(), expected);
    }

    #[test]
    fn boot_health_service_golden_text() {
        // The per-image gate. Ordering/requirement shape mirrors systemd's
        // canonical `systemd-boot-check-no-failures.service`:
        // Before=boot-complete.target + RequiredBy=boot-complete.target.
        let expected = "\
# Generated by shuttle — do not edit.
[Unit]
Description=shuttle: boot health check (gates boot-complete.target)
# default.target catches the boot once the ordinary boot is up; multi-user and
# graphical are listed for images that enable those as their default.
After=default.target multi-user.target graphical.target
# Order before the completion target and pull it in; RequiredBy (installed as
# the boot-complete.target.requires/ link) makes a failure here block the
# target, so the boot is never marked good and the try-boot countdown
# exhausts into a revert.
Before=boot-complete.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=shuttle runtime activate

[Install]
RequiredBy=boot-complete.target
";
        assert_eq!(boot_health_service_content(), expected);
    }

    #[test]
    fn boot_health_command_is_the_single_constant() {
        // The follow-up health-check DSL ticket replaces BOOT_HEALTH_EXEC in
        // one place; assert the emitted unit spells that constant exactly so
        // the change is test-visible here.
        assert_eq!(BOOT_HEALTH_EXEC, "shuttle runtime activate");
        assert!(
            boot_health_service_content().contains(&format!("ExecStart={BOOT_HEALTH_EXEC}\n")),
            "health unit runs the single constant command: {}",
            boot_health_service_content()
        );
    }

    #[test]
    fn emit_boot_assessment_writes_units_and_gates_the_target() {
        let root = tempfile::tempdir().unwrap();
        emit_boot_assessment(root.path()).unwrap();

        for path in [
            BLESS_BOOT_UNIT_PATH,
            BOOT_COMPLETE_TARGET_PATH,
            BOOT_HEALTH_UNIT_PATH,
        ] {
            assert!(root.path().join(path).is_file(), "emitted unit at {path}");
        }

        // The health unit gates the target with a strong `requires` link —
        // NOT `.wants/`: a failing health check must BLOCK
        // boot-complete.target so the generation is never marked good.
        let link = root.path().join(BOOT_COMPLETE_TARGET_REQUIRES_PATH);
        let meta = std::fs::symlink_metadata(&link)
            .unwrap_or_else(|e| panic!("requires link missing at {}: {e}", link.display()));
        assert!(meta.file_type().is_symlink(), "requires is a symlink");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            Path::new("../shuttle-boot-health.service"),
            "relative symlink target"
        );
        assert!(
            !root
                .path()
                .join("etc/systemd/system/boot-complete.target.wants")
                .exists(),
            "the target is pulled in, not wanted"
        );

        // The target itself is not enabled anywhere, and bless-boot is
        // pulled by the stock generator — neither gets an enablement link.
        assert!(
            !root
                .path()
                .join("etc/systemd/system/multi-user.target.wants")
                .join(BLESS_BOOT_UNIT_NAME)
                .exists(),
            "systemd-bless-boot.service is pulled by the generator, not enabled"
        );

        let bless = std::fs::read_to_string(root.path().join(BLESS_BOOT_UNIT_PATH)).unwrap();
        assert!(
            bless.contains("After=local-fs.target boot-complete.target"),
            "bless-boot runs after the target: {bless}"
        );
        assert!(
            bless.contains("Requires=boot-complete.target"),
            "bless-boot requires the target: {bless}"
        );
        let health = std::fs::read_to_string(root.path().join(BOOT_HEALTH_UNIT_PATH)).unwrap();
        assert!(
            health.contains("Before=boot-complete.target"),
            "health check orders before the target: {health}"
        );
        assert!(
            health.contains("RequiredBy=boot-complete.target"),
            "health check is required by the target: {health}"
        );
    }

    #[test]
    fn boot_assessment_units_live_in_the_override_dir_not_the_vendor_path() {
        // Same class of bug as #62: the systemd package ships
        // systemd-bless-boot.service and boot-complete.target at
        // /usr/lib/systemd/system/. We emit at the SAME unit names, so the
        // vendor path would collide (install-order-dependent winner) rather
        // than replace; /etc/systemd/system masks the vendor unit by
        // precedence.
        for path in [
            BLESS_BOOT_UNIT_PATH,
            BOOT_COMPLETE_TARGET_PATH,
            BOOT_HEALTH_UNIT_PATH,
        ] {
            assert!(
                path.starts_with("etc/systemd/system/"),
                "must be an admin override, not the vendor path: {path}"
            );
            assert!(
                !path.starts_with("usr/lib/systemd/system/"),
                "must not collide with the systemd package's own unit: {path}"
            );
        }
    }

    #[test]
    fn update_source_unset_emits_no_boot_assessment() {
        // Regression guard: the try-boot machinery shares the sysupdate gate,
        // so an image without `update_source` emits none of it.
        let root = tempfile::tempdir().unwrap();
        let image = mini_decl("os", "1.2.3");
        let disk = ab_layout();
        if emits_sysupdate(&image, &disk) {
            emit_boot_assessment(root.path()).unwrap();
        }
        for path in [
            BLESS_BOOT_UNIT_PATH,
            BOOT_COMPLETE_TARGET_PATH,
            BOOT_HEALTH_UNIT_PATH,
            BOOT_COMPLETE_TARGET_REQUIRES_PATH,
        ] {
            assert!(
                !root.path().join(path).exists(),
                "no update source ⇒ no boot assessment at {path}"
            );
        }
    }

    #[test]
    fn ab_false_emits_no_boot_assessment() {
        let root = tempfile::tempdir().unwrap();
        let image = sysupdate_decl("os");
        let mut disk = ab_layout();
        disk.ab = false;
        if emits_sysupdate(&image, &disk) {
            emit_boot_assessment(root.path()).unwrap();
        }
        for path in [
            BLESS_BOOT_UNIT_PATH,
            BOOT_COMPLETE_TARGET_PATH,
            BOOT_HEALTH_UNIT_PATH,
        ] {
            assert!(
                !root.path().join(path).exists(),
                "no A/B ⇒ no boot assessment at {path}"
            );
        }
    }

    #[test]
    fn ensure_os_release_image_version_sets_image_version() {
        // %A resolves to IMAGE_VERSION= (not VERSION_ID=); without it
        // ProtectVersion=%A protects nothing.
        let root = tempfile::tempdir().unwrap();
        let image = sysupdate_decl("os");

        // No os-release yet: a minimal deterministic one is written.
        ensure_os_release_image_version(root.path(), &image).unwrap();
        let text = std::fs::read_to_string(root.path().join("etc/os-release")).unwrap();
        assert!(
            text.contains("IMAGE_VERSION=1.2.3"),
            "IMAGE_VERSION must be set for %A: {text}"
        );

        // An existing base os-release is preserved, only IMAGE_VERSION
        // added/replaced.
        std::fs::write(
            root.path().join("etc/os-release"),
            "ID=nixos\nVERSION_ID=24.11\nIMAGE_VERSION=stale\nCUSTOM=kept\n",
        )
        .unwrap();
        ensure_os_release_image_version(root.path(), &image).unwrap();
        let text = std::fs::read_to_string(root.path().join("etc/os-release")).unwrap();
        assert!(text.contains("ID=nixos"), "base keys preserved: {text}");
        assert!(
            text.contains("CUSTOM=kept"),
            "unknown keys preserved: {text}"
        );
        assert!(
            text.contains("VERSION_ID=24.11"),
            "VERSION_ID untouched: {text}"
        );
        assert!(
            text.contains("IMAGE_VERSION=1.2.3") && !text.contains("IMAGE_VERSION=stale"),
            "IMAGE_VERSION replaced, not duplicated: {text}"
        );
        assert_eq!(
            text.matches("IMAGE_VERSION=").count(),
            1,
            "exactly one IMAGE_VERSION line: {text}"
        );
    }

    #[test]
    fn os_release_image_version_is_gated_with_sysupdate() {
        // No update source ⇒ no transfers ⇒ the os-release must not be
        // rewritten either.
        let root = tempfile::tempdir().unwrap();
        let image = mini_decl("os", "1");
        let disk = ab_layout();
        assert!(!emits_sysupdate(&image, &disk));
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        std::fs::write(root.path().join("etc/os-release"), "ID=base\n").unwrap();
        // The gate is the caller's (`build_disk_image_with`); here we assert
        // the predicate does not fire, so the write would not happen.
        if emits_sysupdate(&image, &disk) {
            ensure_os_release_image_version(root.path(), &image).unwrap();
        }
        let text = std::fs::read_to_string(root.path().join("etc/os-release")).unwrap();
        assert!(
            !text.contains("IMAGE_VERSION"),
            "no update source ⇒ os-release untouched: {text}"
        );
    }

    #[test]
    fn emits_sysupdate_is_gated_on_ab_and_update_source() {
        let ab = ab_layout();
        let mut non_ab = ab.clone();
        non_ab.ab = false;

        assert!(emits_sysupdate(&sysupdate_decl("os"), &ab), "both set");
        assert!(
            !emits_sysupdate(&mini_decl("os", "1"), &ab),
            "no update_source ⇒ no sysupdate"
        );
        assert!(
            !emits_sysupdate(&sysupdate_decl("os"), &non_ab),
            "no A/B ⇒ no sysupdate"
        );
    }

    #[test]
    fn update_source_unset_emits_neither_units_nor_transfers() {
        // Regression guard: the trigger pair shares the transfer gate, so
        // an image without `update_source` emits nothing sysupdate at all.
        let root = tempfile::tempdir().unwrap();
        let image = mini_decl("os", "1.2.3");
        let disk = ab_layout();
        if emits_sysupdate(&image, &disk) {
            write_sysupdate_transfers(root.path(), &image, &disk).unwrap();
            emit_sysupdate_units(root.path()).unwrap();
        }
        assert!(!root.path().join(SYSUPDATE_SERVICE_PATH).exists());
        assert!(!root.path().join(SYSUPDATE_TIMER_PATH).exists());
        assert!(!root.path().join(SYSUPDATE_DIR).exists());
        assert!(!root
            .path()
            .join("etc/systemd/system/timers.target.wants")
            .exists());
    }

    #[test]
    fn ab_false_with_update_source_emits_neither_units_nor_transfers() {
        let root = tempfile::tempdir().unwrap();
        let image = sysupdate_decl("os");
        let mut disk = ab_layout();
        disk.ab = false;
        if emits_sysupdate(&image, &disk) {
            write_sysupdate_transfers(root.path(), &image, &disk).unwrap();
            emit_sysupdate_units(root.path()).unwrap();
        }
        assert!(!root.path().join(SYSUPDATE_SERVICE_PATH).exists());
        assert!(!root.path().join(SYSUPDATE_TIMER_PATH).exists());
        assert!(!root.path().join(SYSUPDATE_DIR).exists());
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
        enforce_base_contract(&ImageTools, &image, &resolved, cache.path(), true).unwrap();
    }

    // ── Shared staging + kernel-payload policy (issue #57) ──

    #[test]
    fn staging_best_effort_needs_no_kernel_payload_without_unsquashfs() {
        // Characterization for the dedup seam: `build_image` routes through
        // the shared extraction with `BestEffort`, which must preserve its
        // historical behavior — a missing `unsquashfs` skips the base
        // extraction and the kernel merge silently (no payload required, no
        // error), unlike `build_disk_image`'s fail-closed `Required` policy.
        let image = test_support::sample_image(); // core24 base + pc-kernel
        let resolved = vec![
            ResolvedSnap {
                name: "core24".into(),
                revision: 42,
                sha3_384: "aabb".into(),
                download_url: String::new(),
            },
            ResolvedSnap {
                name: "pc-kernel".into(),
                revision: 7,
                sha3_384: "ccdd".into(),
                download_url: String::new(),
            },
        ];
        let cache = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();

        let payload = extract_base_and_kernel(
            &ImageTools,
            &image,
            &resolved,
            cache.path(),
            root.path(),
            false, // no host unsquashfs
            KernelPayloadPolicy::BestEffort,
        )
        .expect("best-effort staging must not fail closed");
        assert!(
            payload.0.is_none(),
            "best-effort staging never requires a boot payload"
        );
        // Nothing was extracted — the staged tree stays empty.
        assert!(
            std::fs::read_dir(root.path()).unwrap().next().is_none(),
            "no unsquashfs ⇒ no files staged"
        );
    }

    #[test]
    fn staging_required_fails_closed_when_kernel_cannot_be_extracted() {
        // Counterpart to the best-effort test: with `Required` (the disk
        // path), a declared kernel forces an unsquashfs attempt even without
        // a host tool, and the missing payload is a hard error — never a
        // silent skip.
        let image = test_support::sample_image();
        let resolved = vec![
            ResolvedSnap {
                name: "core24".into(),
                revision: 42,
                sha3_384: "aabb".into(),
                download_url: String::new(),
            },
            ResolvedSnap {
                name: "pc-kernel".into(),
                revision: 7,
                sha3_384: "ccdd".into(),
                download_url: String::new(),
            },
        ];
        let cache = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();

        let result = extract_base_and_kernel(
            &ImageTools,
            &image,
            &resolved,
            cache.path(),
            root.path(),
            false, // no host unsquashfs
            KernelPayloadPolicy::Required,
        );
        assert!(
            result.is_err(),
            "required policy must fail closed when the kernel payload cannot be staged"
        );
    }

    // ── End-to-end pipeline driven by a fake runner (issue #58) ──
    //
    // The FIRST test that drives `build_image` / `build_disk_image` end to
    // end with NO host tooling and NO network: a single fake
    // `CommandRunner` answers every subprocess the pipeline would spawn —
    // store query, assertion fetch, download, unsquashfs, parted, sfdisk,
    // mkfs, mmd/mcopy, mksquashfs — and records the exact argv every call.
    // The test asserts BOTH the built artifact's in-process structure and
    // that the expected tools were invoked through the seam. If production
    // bypassed the seam the fake would see nothing and the argv assertions
    // would fail; the real tools are not on PATH in the gate anyway.

    mod command_seam {
        use super::*;
        use crate::command::{CommandRunner, RunnerOutput};
        use std::sync::Mutex;

        /// The production base pin used by the e2e fixtures; the dummy
        /// payload's real sha3-384 is patched in at fixture time.
        const BASE_NAME: &str = "e2etest-base";
        const BASE_REV: u32 = 42;
        const BASE_VER: &str = "6.8.0";

        /// Fake runner: records every argv and answers each tool from the
        /// scripted table. Any unrecognised invocation panics, so a
        /// bypassed (or unexpected) tool call is a hard test failure.
        struct E2eRunner {
            calls: Mutex<Vec<Vec<String>>>,
            arch: String,
            digest: String,
            /// `etc/fstab` contents observed in a populate source tree — the
            /// staged rootfs the fake `mkfs.ext4 -d` reads is removed when
            /// the build returns, so the fake captures the emitted split
            /// here for the ADR-0023 assertions.
            fstabs: Mutex<Vec<String>>,
            /// Relative split paths (`fstab`, tmpfiles) observed in a
            /// populate source tree — proves both presence (state images)
            /// and absence (regression guard).
            split_paths: Mutex<Vec<String>>,
        }

        impl E2eRunner {
            fn new(arch: &str, digest: &str) -> E2eRunner {
                E2eRunner {
                    calls: Mutex::new(Vec::new()),
                    arch: arch.to_string(),
                    digest: digest.to_string(),
                    fstabs: Mutex::new(Vec::new()),
                    split_paths: Mutex::new(Vec::new()),
                }
            }

            fn calls(&self) -> Vec<Vec<String>> {
                self.calls.lock().unwrap().clone()
            }

            fn fstabs(&self) -> Vec<String> {
                self.fstabs.lock().unwrap().clone()
            }

            fn split_paths(&self) -> Vec<String> {
                self.split_paths.lock().unwrap().clone()
            }

            fn saw(&self, program: &str) -> bool {
                self.calls()
                    .iter()
                    .any(|c| c.first().is_some_and(|p| p == program))
            }
        }

        fn out(code: i32, stdout: Vec<u8>) -> RunnerOutput {
            RunnerOutput {
                code,
                stdout,
                stderr: String::new(),
            }
        }

        /// The channel-map JSON `query_info_with` parses. The download URL
        /// is never fetched (the fixture pre-places the cache file).
        fn channel_map_json(name: &str, revision: u32, digest: &str, arch: &str) -> Vec<u8> {
            serde_json::json!({
                "snap-id": "e2etestsnapid",
                "channel-map": [{
                    "channel": { "architecture": arch, "name": name, "track": "latest", "risk": "stable" },
                    "download": { "sha3-384": digest, "size": 11, "url": format!("https://example.invalid/{name}.snap") },
                    "revision": revision
                }]
            })
            .to_string()
            .into_bytes()
        }

        /// The `sfdisk -J` read-back for the disk fixture's partitions at
        /// 512-byte sectors. `n` partitions are synthesized, each 256M,
        /// contiguous — enough for the pipeline's extents read-back.
        fn sfdisk_json(n: usize) -> Vec<u8> {
            let parts: Vec<serde_json::Value> = (0..n)
                .map(|i| {
                    serde_json::json!({
                        "start": 2048 + i * 524288,
                        "size": 524288,
                        "uuid": format!("{:08x}-1111-1111-1111-111111111111", i + 1),
                    })
                })
                .collect();
            serde_json::json!({
                "partitiontable": { "sector-size": 512, "partitions": parts }
            })
            .to_string()
            .into_bytes()
        }

        fn arg_after<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
            argv.iter()
                .position(|a| a == flag)
                .and_then(|i| argv.get(i + 1))
                .map(String::as_str)
        }

        /// Stage a rootfs tree the way a real `unsquashfs -d <dir>` would:
        /// a `bin/` dir (so the pipeline reports a real rootfs) and a single
        /// `lib/modules/<ver>/` tree (so kernel-version discovery works).
        fn stage_rootfs_tree(dir: &str) {
            std::fs::create_dir_all(Path::new(dir).join("bin")).unwrap();
            std::fs::create_dir_all(
                Path::new(dir)
                    .join("usr")
                    .join("lib")
                    .join("modules")
                    .join(BASE_VER),
            )
            .unwrap();
            std::fs::write(Path::new(dir).join("bin").join("busybox"), b"ELF").unwrap();
        }

        impl CommandRunner for E2eRunner {
            fn run(&self, argv: &[String]) -> std::io::Result<RunnerOutput> {
                self.calls.lock().unwrap().push(argv.to_vec());
                let program = argv.first().map(String::as_str).unwrap_or("");
                match program {
                    "which" => Ok(out(0, Vec::new())), // unsquashfs + sfdisk present
                    "curl" => {
                        let url = argv.last().map(String::as_str).unwrap_or("");
                        if url.contains("/assertions/") {
                            // Transport failure ⇒ tolerated for a user-pinned
                            // snap (never a parse failure, which fails closed).
                            Ok(RunnerOutput {
                                code: 7,
                                stdout: Vec::new(),
                                stderr: "could not resolve host".into(),
                            })
                        } else {
                            Ok(out(
                                0,
                                channel_map_json(BASE_NAME, BASE_REV, &self.digest, &self.arch),
                            ))
                        }
                    }
                    "unsquashfs" => {
                        if argv.iter().any(|a| a == "meta/snap.yaml") {
                            // No app metadata in the fixture — warn-and-skip.
                            return Ok(out(1, Vec::new()));
                        }
                        if let Some(dir) = arg_after(argv, "-d") {
                            stage_rootfs_tree(dir);
                        }
                        Ok(out(0, Vec::new()))
                    }
                    "dd" => {
                        // count=<MB> is carried as the 5th arg.
                        let mb: u64 = argv
                            .iter()
                            .find_map(|a| a.strip_prefix("count="))
                            .and_then(|n| n.parse().ok())
                            .unwrap_or(0);
                        let of = argv
                            .iter()
                            .find_map(|a| a.strip_prefix("of="))
                            .expect("dd argv must carry of=");
                        let f = std::fs::File::create(of).unwrap();
                        f.set_len(mb * 1024 * 1024).unwrap();
                        Ok(out(0, Vec::new()))
                    }
                    "parted" | "mkfs.vfat" | "mkfs.ext4" | "mmd" | "mcopy" | "find" => {
                        // For the ADR-0023 split, capture the emitted fstab
                        // from the populate source tree (removed when the
                        // build returns) before answering.
                        if program == "mkfs.ext4" {
                            if let Some(dir) = arg_after(argv, "-d") {
                                if let Ok(fstab) =
                                    std::fs::read_to_string(Path::new(dir).join(FSTAB_PATH))
                                {
                                    self.fstabs.lock().unwrap().push(fstab);
                                }
                                for rel in [
                                    FSTAB_PATH,
                                    STATE_TMPFILES_PATH,
                                    VAR_TMPFILES_PATH,
                                    ACTIVATE_UNIT_PATH,
                                    SYSUPDATE_DIR,
                                    SYSUPDATE_SERVICE_PATH,
                                    SYSUPDATE_TIMER_PATH,
                                    BLESS_BOOT_UNIT_PATH,
                                    BOOT_COMPLETE_TARGET_PATH,
                                    BOOT_HEALTH_UNIT_PATH,
                                    BOOT_COMPLETE_TARGET_REQUIRES_PATH,
                                ] {
                                    if Path::new(dir).join(rel).exists() {
                                        self.split_paths.lock().unwrap().push(rel.to_string());
                                    }
                                }
                            }
                        }
                        Ok(out(0, Vec::new()))
                    }
                    "sfdisk" => {
                        // Partition count: one `parted mkpart` per partition
                        // (plus swap uses mkpart too), so count the recorded
                        // mkpart calls.
                        let n = self
                            .calls
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|c| {
                                c.first().is_some_and(|p| p == "parted")
                                    && c.iter().any(|a| a == "mkpart")
                            })
                            .count();
                        Ok(out(0, sfdisk_json(n)))
                    }
                    "mksquashfs" => {
                        // Materialize the packed artifact as a JSON listing of
                        // the staged rootfs — the in-process structure the
                        // test asserts without unpacking anything.
                        let root = &argv[1];
                        let output = &argv[2];
                        let mut names: Vec<String> = Vec::new();
                        let mut stack = vec![std::path::PathBuf::from(root)];
                        while let Some(dir) = stack.pop() {
                            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                                let path = entry.path();
                                let rel = path
                                    .strip_prefix(root)
                                    .unwrap()
                                    .to_string_lossy()
                                    .into_owned();
                                if path.is_dir() {
                                    stack.push(path.clone());
                                }
                                names.push(rel);
                            }
                        }
                        names.sort();
                        std::fs::write(output, serde_json::to_vec(&names).unwrap()).unwrap();
                        Ok(out(0, Vec::new()))
                    }
                    other => panic!("unexpected tool invocation: {other} ({argv:?})"),
                }
            }
        }

        // ── fixtures ──

        /// A cache dir with a dummy `<name>_<rev>_<digest>.snap` whose real
        /// sha3-384 the fake store query reports back.
        fn cache_fixture() -> (tempfile::TempDir, PathBuf, String) {
            let dir = tempfile::tempdir().unwrap();
            let payload = dir.path().join("payload.snap");
            std::fs::write(&payload, b"dummy-snap").unwrap();
            let digest = crate::store::sha3_384_file(&payload).unwrap();
            let named = dir
                .path()
                .join(format!("{BASE_NAME}_{BASE_REV}_{digest}.snap"));
            std::fs::rename(&payload, &named).unwrap();
            let cache = dir.path().to_path_buf();
            (dir, cache, digest)
        }

        fn pinned_base(digest: &str) -> SnapRef {
            SnapRef {
                name: BASE_NAME.into(),
                revision: Some(BASE_REV),
                sha3_384: Some(digest.to_string()),
            }
        }

        #[test]
        fn build_image_with_fake_runner_packs_orchestrated_rootfs() {
            let (_cache_dir, cache, digest) = cache_fixture();

            let image = ImageDeclaration {
                name: "e2e".into(),
                version: "1.0.0".into(),
                base: pinned_base(&digest),
                kernel: None,
                gadget: None,
                gadget_channel: None,
                extra_snaps: vec![],
                bootloader: None,
                disk: None,
                sysctl: vec![],
                update_source: None,
            };

            let output = tempfile::tempdir().unwrap();
            let runner = E2eRunner::new("amd64", &digest);

            let mut lockfile = LockFile::empty();
            let img = build_image_with(
                &runner,
                &image,
                output.path(),
                &cache,
                "latest/stable",
                "amd64",
                &mut lockfile,
            )
            .expect("build_image must complete through the fake runner");

            // Artifact exists at the documented path.
            assert!(img.is_file(), "image artifact written: {}", img.display());
            assert_eq!(img.file_name().unwrap(), "e2e_1.0.0_amd64.img");

            // The fake `mksquashfs` recorded the staged rootfs as JSON —
            // assert the assembled structure in-process, no unpacking.
            let packed: Vec<String> =
                serde_json::from_slice(&std::fs::read(&img).unwrap()).unwrap();
            let snap_entry = format!("snap/{BASE_NAME}_{BASE_REV}_{digest}.snap");
            assert!(
                packed.iter().any(|p| p == &snap_entry),
                "packed rootfs carries the bundled snap: {packed:?}"
            );
            assert!(
                packed.iter().any(|p| p == "image-manifest.json"),
                "packed rootfs carries the manifest: {packed:?}"
            );
            assert!(
                packed.iter().any(|p| p == "bin"),
                "packed rootfs carries the extracted base tree: {packed:?}"
            );

            // Seam proof: the expected tools were invoked through the
            // runner — never as real subprocesses.
            let calls = runner.calls();
            assert!(
                calls.iter().any(|c| c == &["which", "unsquashfs"]),
                "unsquashfs availability checked through the runner: {calls:?}"
            );
            assert!(
                calls
                    .iter()
                    .any(|c| c.first().is_some_and(|p| p == "unsquashfs")
                        && c.iter().any(|a| a == "-no-xattrs")),
                "base snap extracted through the runner: {calls:?}"
            );
            let mk = calls
                .iter()
                .find(|c| c.first().is_some_and(|p| p == "mksquashfs"))
                .expect("mksquashfs routed through the runner");
            assert_eq!(mk[3..], ["-noappend", "-comp", "xz", "-all-root"]);
            assert!(
                !runner.saw("sfdisk") && !runner.saw("parted"),
                "the squashfs-only path must not partition"
            );
        }

        #[test]
        fn disk_partition_pipeline_drives_every_tool_through_the_runner() {
            // The full `build_disk_image` cannot be driven hermetically yet:
            // its populate pre-flight resolves `sfdisk`/`mkfs.*`/`mmd`/`mcopy`
            // from the HOST PATH (`find_host_tool`, the injected-Option<&Path>
            // precedent that #58 deliberately keeps), so a host without
            // e2fsprogs fails closed BEFORE any runner call. This test instead
            // drives the disk-side partition pipeline — `create_partitions`,
            // `read_partition_extents`, `apply_gpt_slot_metadata`, and
            // `populate_remaining_partitions` (with NO skip, so the root
            // populate also runs) — through the fake runner, proving every
            // tool call in partition.rs/verity.rs is routed through the seam.
            let work = tempfile::tempdir().unwrap();
            let runner = E2eRunner::new("amd64", "unused");
            let layout = DiskLayout {
                label: "gpt".into(),
                partitions: vec![
                    Partition {
                        name: "UEFI".into(),
                        size: "64M".into(),
                        fs: "vfat".into(),
                        mount: "/boot/efi".into(),
                        options: vec![],
                        role: String::new(),
                    },
                    Partition {
                        name: "root".into(),
                        size: "256M".into(),
                        fs: "ext4".into(),
                        mount: "/".into(),
                        options: vec![],
                        role: String::new(),
                    },
                    Partition {
                        name: "data".into(),
                        size: "256M".into(),
                        fs: "ext4".into(),
                        mount: "/data".into(),
                        options: vec![],
                        role: String::new(),
                    },
                ],
                swap: None,
                ab: false,
            };
            let img_path = work.path().join("disk.img");
            create_partitions(&runner, &img_path, &layout, 580).unwrap();
            assert!(img_path.is_file(), "dd formed the raw image");

            let extents = read_partition_extents(&runner, &img_path, 3).unwrap();
            assert_eq!(extents.len(), 3, "read-back yields every partition");
            assert_eq!(extents[1].size_bytes, 256 * 1024 * 1024);

            let image = ImageDeclaration {
                name: "e2edisk".into(),
                version: "2.0.0".into(),
                base: pinned_base("unused"),
                kernel: None,
                gadget: None,
                gadget_channel: None,
                extra_snaps: vec![],
                bootloader: None,
                disk: None,
                sysctl: vec![],
                update_source: None,
            };
            let root = tempfile::tempdir().unwrap();
            let esp = root.path().join("EFI").join("BOOT");
            std::fs::create_dir_all(&esp).unwrap();

            let ctx = PopulateCtx {
                image: &image,
                extents: &extents,
                scratch_dir: work.path(),
                root: root.path(),
                uki: None,
                uki_stage: Path::new(""),
                uc: None,
            };
            // Empty skip list: the root partition (index 1) is populated too.
            // A `roots: vec![1]` skip list would silently bypass the
            // assembled-rootfs `mkfs.ext4 -d` path this test exists to cover.
            populate_remaining_partitions(&runner, &ctx, &layout, &[]).unwrap();

            // `apply_gpt_slot_metadata` returns early unless `layout.ab`, so
            // drive it with an A/B twin to prove slot metadata reaches the seam.
            let ab_layout = DiskLayout {
                ab: true,
                ..layout.clone()
            };
            let slots = Slots {
                roots: vec![1],
                hashes: vec![None],
            };
            apply_gpt_slot_metadata(&runner, &img_path, &image, &ab_layout, &slots).unwrap();

            // Seam proof: each disk-side tool was routed through the runner.
            let calls = runner.calls();
            assert!(runner.saw("dd"), "dd through the runner: {calls:?}");
            assert!(runner.saw("parted"), "parted through the runner");
            assert!(runner.saw("sfdisk"), "sfdisk read-back through the runner");
            assert!(runner.saw("mkfs.vfat"), "ESP mkfs through the runner");
            assert!(runner.saw("mmd"), "mtools mmd through the runner");
            // Exactly two mkfs.ext4: the data partition AND the populated
            // root. One would mean the root populate was skipped.
            let mkfs_ext4 = calls
                .iter()
                .filter(|c| c.first().is_some_and(|p| p == "mkfs.ext4"))
                .count();
            assert_eq!(
                mkfs_ext4, 2,
                "data + populated root both formatted: {calls:?}"
            );
            let sf = calls
                .iter()
                .find(|c| c.first().is_some_and(|p| p == "sfdisk"))
                .expect("sfdisk read-back recorded");
            assert_eq!(sf[1], "-J", "extents are read back with -J: {sf:?}");
            assert!(
                calls
                    .iter()
                    .filter(|c| c.first().is_some_and(|p| p == "parted"))
                    .count()
                    >= 4,
                "mklabel + one mkpart per partition + esp flag: {calls:?}"
            );
        }

        /// Serialize PATH mutation across parallel tests (PATH is
        /// process-global) and restore it afterwards, even on panic.
        static STUB_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        struct PathGuard {
            old: String,
            _lock: std::sync::MutexGuard<'static, ()>,
        }

        impl Drop for PathGuard {
            fn drop(&mut self) {
                std::env::set_var("PATH", &self.old);
            }
        }

        /// Put no-op stubs for the disk pre-flight tools on the process
        /// PATH so `find_host_tool` resolves them and `build_disk_image_with`
        /// is not blocked before it runs. The fake runner answers every
        /// actual invocation, so the stubs are never executed. Returns a
        /// guard that restores PATH on drop.
        fn stub_disk_tool_path(stub_dir: &Path) -> PathGuard {
            use std::os::unix::fs::PermissionsExt;
            let lock = STUB_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            for tool in ["sfdisk", "mmd", "mcopy", "mkfs.ext4", "mkfs.vfat"] {
                let path = stub_dir.join(tool);
                std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let old = std::env::var("PATH").unwrap_or_default();
            std::env::set_var("PATH", format!("{}:{old}", stub_dir.display()));
            PathGuard { old, _lock: lock }
        }

        #[test]
        fn build_disk_image_with_state_role_emits_the_var_split() {
            let stub_dir = tempfile::tempdir().unwrap();
            let _path_guard = stub_disk_tool_path(stub_dir.path());

            let (_cache_dir, cache, digest) = cache_fixture();
            let image = ImageDeclaration {
                name: "e2estate".into(),
                version: "1.0.0".into(),
                base: pinned_base(&digest),
                kernel: None,
                gadget: None,
                gadget_channel: None,
                extra_snaps: vec![],
                bootloader: None,
                disk: Some(DiskLayout {
                    label: "gpt".into(),
                    partitions: vec![
                        Partition {
                            name: "UEFI".into(),
                            size: "64M".into(),
                            fs: "vfat".into(),
                            mount: "/boot/efi".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "root".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "state".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/var/lib".into(),
                            options: vec![],
                            role: ROLE_STATE.into(),
                        },
                    ],
                    swap: None,
                    ab: false,
                }),
                sysctl: vec![],
                update_source: None,
            };

            let output = tempfile::tempdir().unwrap();
            let runner = E2eRunner::new("amd64", &digest);
            let mut lockfile = LockFile::empty();
            let img = build_disk_image_with(
                &runner,
                &image,
                output.path(),
                &cache,
                "latest/stable",
                "amd64",
                &mut lockfile,
            )
            .expect("disk build with a state role must complete");
            assert!(img.is_file(), "disk artifact written: {}", img.display());
            // The split was emitted into the staged rootfs before populate.
            // The fake captured /etc/fstab out of each `mkfs.ext4 -d`
            // source tree (the staged root is removed once the build
            // returns), so assert the emitted split directly.
            let calls = runner.calls();
            assert!(runner.saw("sfdisk"));
            assert!(
                calls
                    .iter()
                    .any(|c| c.first().is_some_and(|p| p == "parted")
                        && c.iter().any(|a| a == "state")),
                "the state partition is declared to parted: {calls:?}"
            );
            let fstabs = runner.fstabs();
            assert!(
                fstabs
                    .iter()
                    .any(|f| f.contains("PARTLABEL=state /var/lib")),
                "state mount in an emitted fstab: {fstabs:?}"
            );
            assert!(
                fstabs
                    .iter()
                    .any(|f| f.contains("tmpfs /var tmpfs mode=0755,nosuid,nodev")),
                "volatile /var in an emitted fstab: {fstabs:?}"
            );
            let split_paths = runner.split_paths();
            for rel in [
                FSTAB_PATH,
                STATE_TMPFILES_PATH,
                VAR_TMPFILES_PATH,
                ACTIVATE_UNIT_PATH,
            ] {
                assert!(
                    split_paths.iter().any(|p| p == rel),
                    "state image emits {rel}: {split_paths:?}"
                );
            }
        }

        #[test]
        fn build_disk_image_with_ab_and_update_source_emits_sysupdate_units() {
            let stub_dir = tempfile::tempdir().unwrap();
            let _path_guard = stub_disk_tool_path(stub_dir.path());

            let (_cache_dir, cache, digest) = cache_fixture();
            let image = ImageDeclaration {
                name: "e2esysupdate".into(),
                version: "1.0.0".into(),
                base: pinned_base(&digest),
                kernel: None,
                gadget: None,
                gadget_channel: None,
                extra_snaps: vec![],
                bootloader: None,
                disk: Some(DiskLayout {
                    label: "gpt".into(),
                    partitions: vec![
                        Partition {
                            name: "UEFI".into(),
                            size: "64M".into(),
                            fs: "vfat".into(),
                            mount: "/boot/efi".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "root".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "state".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/var/lib".into(),
                            options: vec![],
                            role: ROLE_STATE.into(),
                        },
                    ],
                    swap: None,
                    ab: true,
                }),
                sysctl: vec![],
                update_source: Some("https://updates.example.invalid/os/".into()),
            };

            let output = tempfile::tempdir().unwrap();
            let runner = E2eRunner::new("amd64", &digest);
            let mut lockfile = LockFile::empty();
            let img = build_disk_image_with(
                &runner,
                &image,
                output.path(),
                &cache,
                "latest/stable",
                "amd64",
                &mut lockfile,
            )
            .expect("A/B + update_source disk build must complete");
            assert!(img.is_file(), "disk artifact written: {}", img.display());

            // The fake captures every sysupdate path it sees in a populate
            // source tree (the staged root is removed when the build
            // returns): the transfer definitions AND the trigger pair.
            let paths = runner.split_paths();
            for rel in [SYSUPDATE_DIR, SYSUPDATE_SERVICE_PATH, SYSUPDATE_TIMER_PATH] {
                assert!(
                    paths.iter().any(|p| p == rel),
                    "A/B + update_source emits {rel}: {paths:?}"
                );
            }
            // ADR-0024 §3 (#63): the boot-assessment machinery shares the
            // same gate — bless-boot unit, completion target, health gate,
            // and the `boot-complete.target.requires/` link.
            for rel in [
                BLESS_BOOT_UNIT_PATH,
                BOOT_COMPLETE_TARGET_PATH,
                BOOT_HEALTH_UNIT_PATH,
                BOOT_COMPLETE_TARGET_REQUIRES_PATH,
            ] {
                assert!(
                    paths.iter().any(|p| p == rel),
                    "A/B + update_source emits {rel}: {paths:?}"
                );
            }
        }

        #[test]
        fn build_disk_image_without_state_role_emits_no_split_files() {
            let stub_dir = tempfile::tempdir().unwrap();
            let _path_guard = stub_disk_tool_path(stub_dir.path());

            let (_cache_dir, cache, digest) = cache_fixture();
            let image = ImageDeclaration {
                name: "e2eplain".into(),
                version: "1.0.0".into(),
                base: pinned_base(&digest),
                kernel: None,
                gadget: None,
                gadget_channel: None,
                extra_snaps: vec![],
                bootloader: None,
                disk: Some(DiskLayout {
                    label: "gpt".into(),
                    partitions: vec![
                        Partition {
                            name: "UEFI".into(),
                            size: "64M".into(),
                            fs: "vfat".into(),
                            mount: "/boot/efi".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "root".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/".into(),
                            options: vec![],
                            role: String::new(),
                        },
                        Partition {
                            name: "data".into(),
                            size: "256M".into(),
                            fs: "ext4".into(),
                            mount: "/data".into(),
                            options: vec![],
                            role: String::new(),
                        },
                    ],
                    swap: None,
                    ab: false,
                }),
                sysctl: vec![],
                update_source: None,
            };

            let output = tempfile::tempdir().unwrap();
            let runner = E2eRunner::new("amd64", &digest);
            let mut lockfile = LockFile::empty();
            let img = build_disk_image_with(
                &runner,
                &image,
                output.path(),
                &cache,
                "latest/stable",
                "amd64",
                &mut lockfile,
            )
            .expect("plain disk build must complete");
            assert!(img.is_file());
            // The staged rootfs the runner saw must carry no ADR-0023
            // artifacts: the fake captures every split path it sees in a
            // populate source tree, and a plain image emits none.
            let split_paths = runner.split_paths();
            assert!(
                split_paths.is_empty(),
                "plain image must emit no split artifacts: {split_paths:?}"
            );
            assert!(runner.fstabs().is_empty(), "no fstab for a plain image");
        }
    }

    // ── Update-signing embed: fail closed, no auto-mint (ADR-0024 §4) ──

    #[test]
    fn update_source_without_a_secret_key_fails_closed_without_minting() {
        let home = tempfile::tempdir().unwrap();
        let err = load_signing_key_fail_closed(home.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("shuttle key keygen"),
            "the error tells the operator to run keygen: {err:#}"
        );
        assert!(
            !crate::sign::secret_key_path(home.path()).exists(),
            "a build must never mint a key"
        );
    }

    #[test]
    fn update_source_with_a_promoted_key_uses_it() {
        let home = tempfile::tempdir().unwrap();
        let kp = crate::sign::create_secret_key(home.path()).unwrap();
        let loaded = load_signing_key_fail_closed(home.path()).unwrap();
        assert_eq!(loaded, kp);
    }

    #[test]
    fn local_anchor_files_lists_only_pub_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.pub"), "x").unwrap();
        std::fs::write(dir.path().join("a.pub"), "x").unwrap();
        std::fs::write(dir.path().join("revoked-keys"), "x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        let names: Vec<String> = local_anchor_files(dir.path())
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["a.pub", "b.pub"]);
    }
}
