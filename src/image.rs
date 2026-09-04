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

use crate::doctor;
use crate::lock::LockFile;
use crate::snap::{self, SnapRef};
use crate::store::{ResolvedSnap, StoreClient};

// ── Additional types ──

/// Kernel snap reference plus kernel configuration.
#[derive(Debug, Clone)]
pub struct KernelEntry {
    pub snap: SnapRef,
    pub params: Vec<String>,
    pub modules: Vec<String>,
    pub modprobe_config: Option<String>,
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
            Ok(Some(KernelEntry {
                snap,
                params,
                modules,
                modprobe_config,
            }))
        }
        Value::Nil => Ok(None),
        other => Err(miette::miette!(
            "image(): 'kernel' must be a pin table, got {}",
            other.type_name()
        )),
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
                        partitions.push(Partition {
                            name,
                            size,
                            fs,
                            mount,
                            options,
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

/// Resolve all snaps in an image declaration, using the lockfile for defaults.
fn resolve_image_snaps(
    image: &ImageDeclaration,
    lockfile: &LockFile,
    channel: &str,
    arch: &str,
) -> miette::Result<Vec<ResolvedSnap>> {
    let mut resolved = Vec::new();

    for snap_ref in image.all_snaps() {
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

        // Try Snap Store first, then fall back to package index
        let snap = match StoreClient::resolve(&pin, channel, arch) {
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
                        // If index has a store name, try resolving with it
                        if let Some(ref store) = entry.store {
                            let store_name =
                                store.name.as_deref().unwrap_or(&snap_ref.name).to_string();
                            let resolved_pin = SnapRef {
                                name: store_name,
                                revision: pin.revision,
                                sha3_384: pin.sha3_384,
                            };
                            match StoreClient::resolve(&resolved_pin, &store.channel, arch) {
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

/// Build a full disk image with partitions.
///
/// ADR-0011 step (a): when a kernel is declared, a UKI (Unified Kernel
/// Image) is assembled with `ukify` and installed on the ESP at
/// `EFI/Linux/<name>_<version>.efi` alongside a `loader/loader.conf`, so
/// declared kernel params land on the real boot cmdline. ADR-0011 step (c):
/// the root partition is populated first, then dm-verity is formatted over
/// it (`veritysetup`) into an auto-appended hash partition, and the captured
/// roothash is embedded in the UKI cmdline (explicit
/// `systemd.verity_root_data`/`systemd.verity_root_hash` by-partuuid
/// devices — boot needs no dm-verity type GUIDs). Every condition that
/// would yield an unbootable or unverifiable image — missing ukify, missing
/// sd-stub, missing veritysetup, no kernel payload, no root partition —
/// fails closed, before any partition is formatted.
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

    let build_dir = tempfile::tempdir()
        .map_err(|e| miette::miette!("failed to create build directory: {e}"))?;
    let root = build_dir.path().to_path_buf();

    // 3. Extract base snap and merge the kernel payload
    let kernel_payload = extract_base_and_kernel(
        image,
        &resolved,
        cache_dir,
        &root,
        build_dir.path(),
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

    // Calculate total image size: sum partitions + swap + 4M for GPT headers
    let total_mb = calculate_disk_size_mb(&effective_layout);
    eprintln!("  creating disk image: {} MB", total_mb);

    // 7. Create and partition the raw image — GPT PARTUUIDs exist from
    // parted mkpart time, before anything is formatted or copied.
    let img_path = build_dir.path().join("disk.img");
    create_partitions(&img_path, &effective_layout, total_mb)?;
    // ADR-0011 step (d): A/B layouts additionally get GPT partition type
    // GUIDs + PARTLABELs so systemd-sysupdate can match the slots.
    apply_gpt_slot_metadata(&img_path, image, &effective_layout, &slots)?;

    // 8. Attach the image to a loop device with partition scanning.
    let loop_dev = attach_loop(&img_path)?;

    // 9. ADR-0011 step (c): the pipeline order below is mandatory — each
    // root slot is populated and UNMOUNTED first, then dm-verity formats it
    // (the data device must be final before hashing; a cmdline is immutable
    // once the UKI is later signed), then the UKI embeds the captured
    // roothash in its cmdline.
    let (uki, uki_stage, populated_roots) = if verity {
        // 9a. Rootfs-level manifest only: boot facts (cmdline, roothash) are
        // unknowable until after verity format, and a post-format write
        // would break the Merkle tree. The root partition therefore carries
        // the content manifest; the authoritative boot-facts manifest is
        // written below and lands on the remaining partitions.
        write_manifest(&root, image, &snap_paths, arch, None)?;
        // 9b-c. Per slot, in order: populate the root partition, then leave
        // it unmounted — veritysetup format requires the data device
        // quiescent — then format dm-verity over it into the slot's hash
        // partition. Slot B (A/B layouts) is populated and verity-formatted
        // identically: a same-version twin sharing slot A's roothash (same
        // data + same explicit salt), making it a usable day-one rollback
        // target. Any roothash divergence fails closed.
        let shared_salt = if effective_layout.ab {
            Some(random_salt_hex()?)
        } else {
            None
        };
        let mut slot_roothash: Option<String> = None;
        for (s, &root_idx) in slots.roots.iter().enumerate() {
            let part_label = format!("{}_{}_{}", image.name, image.version, slot_suffix(s));
            populate_root_partition_at(
                &effective_layout,
                root_idx,
                &loop_dev,
                &root,
                build_dir.path(),
            )?;
            let root_dev = partition_dev(&loop_dev, root_idx);
            let hash_idx = slots.hashes[s].expect("verity ⇒ hash partition was appended");
            let hash_dev = partition_dev(&loop_dev, hash_idx);
            let roothash = verity_format(&root_dev, &hash_dev, shared_salt.as_deref())?;
            eprintln!(
                "  ✓ dm-verity formatted over {root_dev} (slot {} / {part_label})",
                slot_suffix(s)
            );
            match &slot_roothash {
                None => slot_roothash = Some(roothash),
                Some(first) if *first == roothash => {}
                Some(first) => {
                    return Err(miette::miette!(
                        "slot twin roothash mismatch (slot a: {first}, slot {}: \
                         {roothash}) — the A/B roots must be byte-identical twins; \
                         refusing an image whose rollback slot cannot be verified",
                        slot_suffix(s)
                    ));
                }
            }
        }
        let roothash = slot_roothash.expect("verity branch formats at least one slot");
        // The UKI boots slot A: its hash PARTUUID is slot A's hash device.
        let hash_partuuid = partuuid_of(&partition_dev(
            &loop_dev,
            slots.hashes[0].expect("verity ⇒ hash partition was appended"),
        ));
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
            &loop_dev,
            &effective_layout,
            build_dir.path(),
            Some(&verity_args),
        )?;
        (uki, stage, slots.skip_indices())
    } else {
        // Kernel-free images boot without a UKI — no verity, no trailer.
        let (uki, stage) = assemble_uki(
            image,
            kernel_payload.as_ref(),
            &loop_dev,
            &effective_layout,
            build_dir.path(),
            None,
        )?;
        (uki, stage, slots.skip_indices())
    };

    // 10. Write the authoritative manifest — threaded with the boot facts
    // the image boots with, including the dm-verity roothash (step (c)).
    write_manifest(&root, image, &snap_paths, arch, uki.as_ref())?;

    // 11. Format and populate the remaining partitions — the ESP gets the
    // UKI + loader.conf; other data partitions receive the staged rootfs
    // (with the authoritative manifest). The root slots and verity-hash
    // partitions are skipped: they were populated and verity-formatted
    // above (slot B's identical staged rootfs makes it the rollback twin).
    let populate = PopulateCtx {
        image,
        loop_dev: &loop_dev,
        build_dir: build_dir.path(),
        root: &root,
        uki: uki.as_ref(),
        uki_stage: &uki_stage,
    };
    populate_remaining_partitions(&populate, &effective_layout, &populated_roots)?;

    // Detach loop device
    let _ = std::process::Command::new("losetup")
        .args(["-d", &loop_dev])
        .status();

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

        let fs_type = if part.fs == "vfat" { "fat32" } else { &part.fs };
        let status = std::process::Command::new("parted")
            .args([
                "-s",
                &img_path.to_string_lossy(),
                "mkpart",
                "primary",
                fs_type,
                &format!("{}MB", part_start_mb),
                &format!("{}MB", end_mb),
            ])
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

/// Attach the disk image to a free loop device with partition scanning
/// (`-P`), so partition devices exist for PARTUUID capture.
fn attach_loop(img_path: &Path) -> miette::Result<String> {
    let out = std::process::Command::new("losetup")
        .args(["--show", "-fP", &img_path.to_string_lossy()])
        .output()
        .map_err(|e| miette::miette!("losetup not found: {e}"))?;
    if !out.status.success() {
        return Err(miette::miette!("losetup failed"));
    }
    let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    eprintln!("  loop device: {}", dev);
    Ok(dev)
}

/// Shared context for the populate stage — everything the per-partition
/// workers need besides the partition itself.
struct PopulateCtx<'a> {
    image: &'a ImageDeclaration,
    loop_dev: &'a str,
    build_dir: &'a Path,
    root: &'a Path,
    uki: Option<&'a UkiFacts>,
    uki_stage: &'a Path,
}

/// Format, mount, and populate ONLY the given root slot partition (mount =
/// "/") from the staged rootfs, then unmount it. ADR-0011 step (c):
/// `veritysetup format` needs the data device final and quiescent, so each
/// root goes first and stays unmounted. A mount failure here fails closed —
/// an empty verity data device would brick the boot — unlike the historical
/// silent-skip on the other partitions.
fn populate_root_partition_at(
    layout: &DiskLayout,
    idx: usize,
    loop_dev: &str,
    root: &Path,
    build_dir: &Path,
) -> miette::Result<()> {
    let part = &layout.partitions[idx];
    let part_dev = partition_dev(loop_dev, idx);
    let mount_pt = build_dir.join(&part.name);
    std::fs::create_dir_all(&mount_pt).into_diagnostic()?;

    // The verity branch: this root IS the verity data device — pin the fs
    // to 4 KiB blocks (VERITY_BLOCK_SIZE) or the mount over the verity
    // mapping fails ("bad block size 1024").
    format_partition(&part_dev, part, true)?;
    if !mount_device(&part_dev, &mount_pt)? {
        return Err(miette::miette!(
            "failed to mount root partition '{}' ({part_dev}) — refusing to \
             dm-verity-format an unpopulated root",
            part.name
        ));
    }
    cp_r(root, &mount_pt)?;
    eprintln!("  ✓ {}: {} populated", part.name, part.fs);
    // Unmount
    let _ = std::process::Command::new("umount")
        .arg(mount_pt.to_string_lossy().as_ref())
        .status();
    Ok(())
}

/// Format and populate every partition EXCEPT the root slots (already
/// populated before dm-verity formatting, [`populate_root_partition_at`])
/// and the auto-appended verity-hash partitions (raw `veritysetup` output —
/// never mounted or mkfs'd) — both carried in `skip`. Partition 1 when vfat
/// is the ESP (systemd-boot fallback binary, UKI, loader.conf); every other
/// partition receives the staged rootfs.
fn populate_remaining_partitions(
    ctx: &PopulateCtx,
    layout: &DiskLayout,
    skip: &[usize],
) -> miette::Result<()> {
    let part_prefix = format!("{}p", ctx.loop_dev);
    for (i, part) in layout.partitions.iter().enumerate() {
        if skip.contains(&i) || part.name == VERITY_HASH_PART_NAME {
            continue;
        }
        populate_side_partition(ctx, i, part, &part_prefix)?;
    }
    Ok(())
}

/// Format, mount, populate, and unmount one non-root partition: the ESP
/// (partition 1, vfat) gets the systemd-boot fallback + UKI; other data
/// partitions receive the staged rootfs. A mount failure leaves the
/// partition unpopulated (historical silent-skip behavior).
fn populate_side_partition(
    ctx: &PopulateCtx,
    index: usize,
    part: &Partition,
    part_prefix: &str,
) -> miette::Result<()> {
    let part_dev = format!("{part_prefix}{}", index + 1);
    let mount_pt = ctx.build_dir.join(&part.name);
    std::fs::create_dir_all(&mount_pt).into_diagnostic()?;

    // Side partitions (ESP, data) are never verity data devices.
    format_partition(&part_dev, part, false)?;
    if !mount_device(&part_dev, &mount_pt)? {
        return Ok(());
    }
    if index == 0 && part.fs == "vfat" {
        populate_esp(&mount_pt.join("EFI").join("BOOT"))?;
        install_uki(ctx.image, &mount_pt, ctx.uki, ctx.uki_stage)?;
        eprintln!("  ✓ ESP: {} (vfat)", part.name);
    } else {
        // Data partition: copy the staged rootfs
        cp_r(ctx.root, &mount_pt)?;
        eprintln!("  ✓ {}: {} populated", part.name, part.fs);
    }
    // Unmount
    let _ = std::process::Command::new("umount")
        .arg(mount_pt.to_string_lossy().as_ref())
        .status();
    Ok(())
}

/// mkfs tool + leading flags for one partition filesystem (the label and
/// device args are appended by the caller). `verity` marks the partition as
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

/// mkfs a partition device; a formatting failure is reported but not fatal
/// (matching the historical behavior — the mount attempt below decides).
/// The `verity` precondition check fails closed before any command runs.
fn format_partition(part_dev: &str, part: &Partition, verity: bool) -> miette::Result<()> {
    let (tool, flags) = mkfs_flags_for(&part.fs, verity)?;
    let status = std::process::Command::new(tool)
        .args(&flags)
        .arg(&part.name)
        .arg(part_dev)
        .status()
        .map_err(|e| miette::miette!("{tool} not found: {e}"))?;
    if !status.success() {
        eprintln!("  ⚠ {tool} failed for {}", part.name);
    }
    Ok(())
}

/// Mount a formatted partition device. False when the mount failed — the
/// partition is then left unpopulated (historical silent-skip behavior).
fn mount_device(part_dev: &str, mount_pt: &Path) -> miette::Result<bool> {
    let mount_str = mount_pt.to_string_lossy().into_owned();
    let status = std::process::Command::new("mount")
        .args([part_dev, &mount_str])
        .status()
        .map_err(|e| miette::miette!("mount not found: {e}"))?;
    Ok(status.success())
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

/// Loop-device partition path for a 0-based layout index (index 0 → p1).
fn partition_dev(loop_dev: &str, index: usize) -> String {
    format!("{loop_dev}p{}", index + 1)
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
/// `sfdisk` (util-linux — same tool family as the build's losetup; the
/// parted `type` command needs 3.5+, sgdisk is not required). Runs on the
/// raw image file BEFORE loop attach, so the loop scan exposes final
/// metadata. Fail-open, never silent: a missing or failing sfdisk warns
/// loudly — sysupdate partition matching degrades, the image still boots —
/// mirroring the historical ESP-flag posture.
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
    if let Ok(out) = std::process::Command::new("sh")
        .args([
            "-c",
            "find /usr/lib/systemd/boot -name '*.efi' 2>/dev/null | head -1",
        ])
        .output()
    {
        let src = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !src.is_empty() {
            let _ = std::fs::copy(&src, efi_boot.join("BOOTX64.EFI"));
            let _ = std::fs::copy(&src, efi_boot.join("systemd-bootx64.efi"));
        }
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
/// captured: parted assigns GPT GUIDs at mkpart time and `losetup -P`
/// exposes the partition devices before the UKI is built.
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

/// GPT PARTUUID of a loop-device partition (e.g. /dev/loop0p2), read
/// host-side with lsblk (util-linux — the same tool family the disk build
/// already requires). None when lsblk is absent or the partition carries
/// no GPT entry.
fn partuuid_of(part_dev: &str) -> Option<String> {
    let out = std::process::Command::new("lsblk")
        .args(["-no", "PARTUUID", part_dev])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
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
    loop_dev: &str,
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

    // GPT PARTUUIDs exist from parted mkpart time; `losetup -P` exposes the
    // partition devices before anything is formatted. ESP is partition 1.
    let root_partuuid = partuuid_of(&format!("{loop_dev}p{}", root_idx + 1));
    let esp_partuuid = partuuid_of(&format!("{loop_dev}p1"));
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
            }),
            gadget: Some(SnapRef {
                name: "pi-gadget".into(),
                revision: Some(3),
                sha3_384: Some("c".into()),
            }),
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
                },
                Partition {
                    name: "root".into(),
                    size: "4G".into(),
                    fs: "ext4".into(),
                    mount: "/".into(),
                    options: vec![],
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
        }
    }

    fn root_part() -> Partition {
        Partition {
            name: "root".into(),
            size: "4G".into(),
            fs: "ext4".into(),
            mount: "/".into(),
            options: vec![],
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
}
