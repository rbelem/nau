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
            Ok(Some(DiskLayout {
                label,
                partitions,
                swap,
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
    // appended after the declared partitions — existing indices never shift
    // and the parted flow is untouched.
    let mut effective_layout = disk_layout.clone();
    let hash_partition_index = if verity {
        Some(append_verity_hash_partition(&mut effective_layout)?)
    } else {
        None
    };

    // Calculate total image size: sum partitions + swap + 4M for GPT headers
    let total_mb = calculate_disk_size_mb(&effective_layout);
    eprintln!("  creating disk image: {} MB", total_mb);

    // 7. Create and partition the raw image — GPT PARTUUIDs exist from
    // parted mkpart time, before anything is formatted or copied.
    let img_path = build_dir.path().join("disk.img");
    create_partitions(&img_path, &effective_layout, total_mb)?;

    // 8. Attach the image to a loop device with partition scanning.
    let loop_dev = attach_loop(&img_path)?;

    // 9. ADR-0011 step (c): the pipeline order below is mandatory — the root
    // partition is populated and UNMOUNTED first, then dm-verity formats it
    // (the data device must be final before hashing; a cmdline is immutable
    // once the UKI is later signed), then the UKI embeds the captured
    // roothash in its cmdline.
    let (uki, uki_stage, populated_root) = if verity {
        // 9a. Rootfs-level manifest only: boot facts (cmdline, roothash) are
        // unknowable until after verity format, and a post-format write
        // would break the Merkle tree. The root partition therefore carries
        // the content manifest; the authoritative boot-facts manifest is
        // written below and lands on the remaining partitions.
        write_manifest(&root, image, &snap_paths, arch, None)?;
        // 9b. Populate the root partition, then leave it unmounted —
        // veritysetup format requires the data device quiescent.
        populate_root_partition(&effective_layout, &loop_dev, &root, build_dir.path())?;
        // 9c. Format dm-verity over the root (data) device into the hash
        // partition and capture the root hash — fail closed on parse.
        let root_idx = root_partition_index(&effective_layout)?;
        let root_dev = partition_dev(&loop_dev, root_idx);
        let hash_idx = hash_partition_index.expect("verity ⇒ hash partition was appended");
        let hash_dev = partition_dev(&loop_dev, hash_idx);
        let roothash = verity_format(&root_dev, &hash_dev)?;
        eprintln!("  ✓ dm-verity formatted over {}", root_dev);
        let hash_partuuid = partuuid_of(&hash_dev);
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
        // 9d. ADR-0011 step (a): assemble the UKI with the verity trailer.
        let (uki, stage) = assemble_uki(
            image,
            kernel_payload.as_ref(),
            &loop_dev,
            &effective_layout,
            build_dir.path(),
            Some(&verity_args),
        )?;
        (uki, stage, Some(root_idx))
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
        (uki, stage, None)
    };

    // 10. Write the authoritative manifest — threaded with the boot facts
    // the image boots with, including the dm-verity roothash (step (c)).
    write_manifest(&root, image, &snap_paths, arch, uki.as_ref())?;

    // 11. Format and populate the remaining partitions — the ESP gets the
    // UKI + loader.conf; other data partitions receive the staged rootfs
    // (with the authoritative manifest). The root partition is skipped: it
    // was populated and verity-formatted above.
    let populate = PopulateCtx {
        image,
        loop_dev: &loop_dev,
        build_dir: build_dir.path(),
        root: &root,
        uki: uki.as_ref(),
        uki_stage: &uki_stage,
    };
    populate_remaining_partitions(&populate, &effective_layout, populated_root)?;

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

/// Format, mount, and populate ONLY the root partition (mount = "/") from
/// the staged rootfs, then unmount it. ADR-0011 step (c): `veritysetup
/// format` needs the data device final and quiescent, so the root goes
/// first and stays unmounted. A mount failure here fails closed — an empty
/// verity data device would brick the boot — unlike the historical
/// silent-skip on the other partitions.
fn populate_root_partition(
    layout: &DiskLayout,
    loop_dev: &str,
    root: &Path,
    build_dir: &Path,
) -> miette::Result<()> {
    let idx = root_partition_index(layout)?;
    let part = &layout.partitions[idx];
    let part_dev = partition_dev(loop_dev, idx);
    let mount_pt = build_dir.join(&part.name);
    std::fs::create_dir_all(&mount_pt).into_diagnostic()?;

    format_partition(&part_dev, part)?;
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

/// Format and populate every partition EXCEPT the root (already populated
/// before dm-verity formatting, [`populate_root_partition`]) and the
/// auto-appended verity-hash partition (raw `veritysetup` output — never
/// mounted or mkfs'd). Partition 1 when vfat is the ESP (systemd-boot
/// fallback binary, UKI, loader.conf); every other partition receives the
/// staged rootfs.
fn populate_remaining_partitions(
    ctx: &PopulateCtx,
    layout: &DiskLayout,
    populated_root: Option<usize>,
) -> miette::Result<()> {
    let part_prefix = format!("{}p", ctx.loop_dev);
    for (i, part) in layout.partitions.iter().enumerate() {
        if Some(i) == populated_root || part.name == VERITY_HASH_PART_NAME {
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

    format_partition(&part_dev, part)?;
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

/// mkfs a partition device; a formatting failure is reported but not fatal
/// (matching the historical behavior — the mount attempt below decides).
fn format_partition(part_dev: &str, part: &Partition) -> miette::Result<()> {
    let (tool, flags): (&str, &[&str]) = match part.fs.as_str() {
        "vfat" => ("mkfs.vfat", &["-F", "32", "-n"]),
        "btrfs" => ("mkfs.btrfs", &["-f", "-L"]),
        _ => ("mkfs.ext4", &["-F", "-L"]),
    };
    let status = std::process::Command::new(tool)
        .args(flags)
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

/// Index of the declared root partition (mount = "/") — fail closed when
/// absent: both the UKI `root=` target and dm-verity formatting need it.
fn root_partition_index(layout: &DiskLayout) -> miette::Result<usize> {
    layout
        .partitions
        .iter()
        .position(|p| p.mount == "/")
        .ok_or_else(|| {
            miette::miette!(
                "disk layout declares no root partition (mount = \"/\") — the UKI needs \
                 a root= target; refusing to build an unbootable image"
            )
        })
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
fn append_verity_hash_partition(layout: &mut DiskLayout) -> miette::Result<usize> {
    let root_idx = root_partition_index(layout)?;
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

/// `veritysetup format` invocation (ADR-0011 step (c)): sha256 over 4K data
/// and hash blocks, on-disk format 1. `veritysetup` is injected so the
/// fail-closed behavior is testable on hosts without cryptsetup;
/// [`verity_format`] resolves it from the host. Returns the root hash
/// printed on stdout.
fn verity_format_with(
    veritysetup: Option<&Path>,
    data_dev: &str,
    hash_dev: &str,
) -> miette::Result<String> {
    let Some(tool) = veritysetup else {
        return Err(miette::miette!(
            "veritysetup not found on PATH — dm-verity over the root partition cannot \
             be formatted, so refusing to emit an unverifiable boot path. Run \
             'shuttle doctor' and install veritysetup (cryptsetup >= 2.4; e.g. \
             apt install cryptsetup or add cryptsetup to devbox.json packages)"
        ));
    };
    let out = std::process::Command::new(tool)
        .args([
            "format",
            "--hash",
            "sha256",
            "--data-block-size",
            "4096",
            "--hash-block-size",
            "4096",
            "--format",
            "1",
            data_dev,
            hash_dev,
        ])
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
/// veritysetup (fail-closed when absent).
fn verity_format(data_dev: &str, hash_dev: &str) -> miette::Result<String> {
    verity_format_with(find_veritysetup().as_deref(), data_dev, hash_dev)
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
        };
        let idx = append_verity_hash_partition(&mut layout).unwrap();
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
        };
        let err = append_verity_hash_partition(&mut layout).unwrap_err();
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
        let err = verity_format_with(None, "/dev/loop0p2", "/dev/loop0p3").unwrap_err();
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
        };
        assert!(
            loader_conf(&image).contains("timeout 5"),
            "declared bootloader timeout must win: {}",
            loader_conf(&image)
        );
    }
}
