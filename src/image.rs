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

use crate::lock::LockFile;
use crate::snap::SnapRef;
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
    pub size: String,           // e.g. "512M", "0" for remaining
    pub fs: String,             // e.g. "vfat", "btrfs", "ext4"
    pub mount: String,          // mount point
    pub options: Vec<String>,   // mount options
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
                        let size: String = pt.get("size").map_err(|_| {
                            miette::miette!("partition '{}': missing 'size'", name)
                        })?;
                        let fs: String = pt.get("fs").map_err(|_| {
                            miette::miette!("partition '{}': missing 'fs'", name)
                        })?;
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

/// Named image outputs from a `shoot.lua`.
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
                            let store_name = store
                                .name
                                .as_deref()
                                .unwrap_or(&snap_ref.name)
                                .to_string();
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
        std::fs::write(sysctl_dir.join("99-shoot.conf"), &sysctl_content)
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

    // 8. Write manifest
    let manifest_path = root.join("image-manifest.json");
    let manifest = ImageManifest::from_resolved(image, &snap_paths, arch);
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

    // 3. Extract base snap
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

    // 4. Merge kernel modules
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
                if status.code().unwrap_or(1) < 128 {
                    for dir in ["lib/modules", "lib/firmware"] {
                        let src = kernel_dir.join(dir);
                        let dst = root.join(dir);
                        if src.exists() {
                            std::fs::create_dir_all(dst.parent().unwrap()).into_diagnostic()?;
                            cp_r(&src, &dst)?;
                        }
                    }
                }
            }
        }
    }

    // 5. Write kernel cmdline
    if let Some(ref kernel_entry) = image.kernel {
        if !kernel_entry.params.is_empty() {
            let cmdline = kernel_entry.params.join(" ");
            let kernel_dir = root.join("etc");
            std::fs::create_dir_all(&kernel_dir).into_diagnostic()?;
            std::fs::write(kernel_dir.join("kernelcmdline"), &cmdline).into_diagnostic()?;
            eprintln!("  ✓ kernel cmdline: {cmdline}");
        }
    }

    // 6. Write sysctl
    if !image.sysctl.is_empty() {
        let sysctl_dir = root.join("etc").join("sysctl.d");
        std::fs::create_dir_all(&sysctl_dir).into_diagnostic()?;
        let sysctl_content = image.sysctl.join("\n") + "\n";
        std::fs::write(sysctl_dir.join("99-shoot.conf"), &sysctl_content).into_diagnostic()?;
        eprintln!(
            "  ✓ sysctl written ({} entries)",
            image.sysctl.len()
        );
    }

    // 7. Write manifest
    let manifest_path = root.join("image-manifest.json");
    let manifest = ImageManifest::from_resolved(image, &snap_paths, arch);
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| miette::miette!("failed to serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, &manifest_json).into_diagnostic()?;

    // 8. Create disk image
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

    // Calculate total image size: sum partitions + swap + 4M for GPT headers
    let total_mb = calculate_disk_size_mb(disk_layout);
    eprintln!("  creating disk image: {} MB", total_mb);

    let img_path = build_dir.path().join("disk.img");
    let status = std::process::Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", img_path.display()),
            "bs=1M",
            &format!("count={}", total_mb),
        ])
        .status()
        .map_err(|e| miette::miette!("dd not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("dd failed to create disk image"));
    }

    // Partition with parted
    let status = std::process::Command::new("parted")
        .args([
            "-s",
            &img_path.to_string_lossy(),
            "mklabel",
            &disk_layout.label,
        ])
        .status()
        .map_err(|e| miette::miette!("parted not found: {e}"))?;
    if !status.success() {
        return Err(miette::miette!("parted failed to create partition table"));
    }

    // Create partitions
    let mut part_start_mb = 4u64; // after GPT
    for (part_num, part) in disk_layout.partitions.iter().enumerate() {
        let size_mb = parse_size_mb(&part.size, total_mb - part_start_mb);
        let end_mb = part_start_mb + size_mb;

        let fs_type = if part.fs == "vfat" {
            "fat32"
        } else {
            &part.fs
        };
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

        // ESP flag on first partition
        if part_num == 0 {
            let status = std::process::Command::new("parted")
                .args(["-s", &img_path.to_string_lossy(), "set", "1", "esp", "on"])
                .status()
                .map_err(|e| miette::miette!("parted: {e}"))?;
            if !status.success() {
                eprintln!("  ⚠ failed to set ESP flag");
            }
        }

        part_start_mb = end_mb;
    }

    // Swap partition
    if let Some(ref swap) = disk_layout.swap {
        let swap_size = parse_size_mb(&swap.size, 0);
        if swap_size > 0 {
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
        }
    }

    // Set up loopback device
    let losetup_out = std::process::Command::new("losetup")
        .args(["--show", "-fP", &img_path.to_string_lossy()])
        .output()
        .map_err(|e| miette::miette!("losetup not found: {e}"))?;
    if !losetup_out.status.success() {
        return Err(miette::miette!("losetup failed"));
    }
    let loop_dev = String::from_utf8_lossy(&losetup_out.stdout)
        .trim()
        .to_string();
    eprintln!("  loop device: {}", loop_dev);

    // Format and populate partitions
    let part_prefix = format!("{}p", loop_dev);
    for (i, part) in disk_layout.partitions.iter().enumerate() {
        let part_dev = format!("{}{}", part_prefix, i + 1);
        let mount_pt = build_dir.path().join(&part.name);
        std::fs::create_dir_all(&mount_pt).into_diagnostic()?;

        if part.fs == "vfat" {
            let status = std::process::Command::new("mkfs.vfat")
                .args(["-F", "32", "-n", &part.name, &part_dev])
                .status()
                .map_err(|e| miette::miette!("mkfs.vfat not found: {e}"))?;
            if !status.success() {
                eprintln!("  ⚠ mkfs.vfat failed for {}", part.name);
            }
        } else if part.fs == "btrfs" {
            let status = std::process::Command::new("mkfs.btrfs")
                .args(["-f", "-L", &part.name, &part_dev])
                .status()
                .map_err(|e| miette::miette!("mkfs.btrfs not found: {e}"))?;
            if !status.success() {
                eprintln!("  ⚠ mkfs.btrfs failed for {}", part.name);
            }
        } else {
            let status = std::process::Command::new("mkfs.ext4")
                .args(["-F", "-L", &part.name, &part_dev])
                .status()
                .map_err(|e| miette::miette!("mkfs.ext4 not found: {e}"))?;
            if !status.success() {
                eprintln!("  ⚠ mkfs.ext4 failed for {}", part.name);
            }
        }

        // Mount and populate
        let mount_str = mount_pt.to_string_lossy().into_owned();
        let status = std::process::Command::new("mount")
            .args([&part_dev, &mount_str])
            .status()
            .map_err(|e| miette::miette!("mount not found: {e}"))?;
        if status.success() {
            if i == 0 && part.fs == "vfat" {
                // ESP: create EFI/boot directory, copy systemd-boot
                let efi_dir = mount_pt.join("EFI").join("BOOT");
                std::fs::create_dir_all(&efi_dir).into_diagnostic()?;
                // Try to find systemd-bootx64.efi on the host
                let boot_efi = efi_dir.join("BOOTX64.EFI");
                if !boot_efi.exists() {
                    if let Ok(efi_status) = std::process::Command::new("sh")
                        .args([
                            "-c",
                            "find /usr/lib/systemd/boot -name '*.efi' 2>/dev/null | head -1",
                        ])
                        .output()
                    {
                        let src = String::from_utf8_lossy(&efi_status.stdout)
                            .trim()
                            .to_string();
                        if !src.is_empty() {
                            let _ = std::fs::copy(&src, efi_dir.join("BOOTX64.EFI"));
                            let _ = std::fs::copy(&src, efi_dir.join("systemd-bootx64.efi"));
                        }
                    }
                }
                eprintln!("  ✓ ESP: {} (vfat)", part.name);
            } else {
                // Root partition: copy rootfs
                cp_r(&root, &mount_pt)?;
                eprintln!("  ✓ {}: {} populated", part.name, part.fs);
            }
            // Unmount
            let _ = std::process::Command::new("umount")
                .arg(&mount_str)
                .status();
        }
    }

    // Detach loop device
    let _ = std::process::Command::new("losetup")
        .args(["-d", &loop_dev])
        .status();

    // 9. Copy final image to output
    std::fs::copy(&img_path, &output_path).into_diagnostic()?;
    eprintln!(
        "  ✓ disk image built: {} ({} MB)",
        output_filename, total_mb
    );

    // 10. Update lockfile
    for snap in &resolved {
        lockfile.record_snap(&snap.to_snap_ref());
    }

    Ok(output_path)
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

        let manifest = ImageManifest::from_resolved(&decl, &snaps, "amd64");
        assert_eq!(manifest.snaps.len(), 4);
        assert_eq!(manifest.snaps[0].role, "base");
        assert_eq!(manifest.snaps[1].role, "kernel");
        assert_eq!(manifest.snaps[2].role, "gadget");
        assert_eq!(manifest.snaps[3].role, "app");
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
}
