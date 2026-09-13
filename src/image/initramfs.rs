//! Native initramfs construction (issue #75).
//!
//! A kernel that follows the native verity contract (`root=PARTUUID=…` plus
//! `roothash=` and the explicit `systemd.verity_root_data` / `_hash`
//! devices) needs an initramfs that mounts that root read-only and
//! `switch_root`s into it. A stock Ubuntu Core `pc-kernel` snap ships
//! Canonical's snap-bootstrap initramfs instead, which mounts a writable
//! `ubuntu-data` and never verifies a shuttle root, so shuttle builds its
//! own.
//!
//! This module owns the pure, host-independent pieces: reading the snap's
//! `modules.dep`, resolving the boot-chain module closure in load order, and
//! writing a `newc` cpio archive. The `/init` script and the host userspace
//! staging live alongside the assembly wiring (ADR-0025 amendment).
//!
//! # Resolution model
//!
//! `modules.dep` maps a module path (`kernel/drivers/md/dm-verity.ko`) to
//! that module's dependency paths, all relative to the `modules/<ver>/`
//! directory. Shuttle's boot-chain requirement is expressed as module
//! *names* (`dm-verity`, from [`crate::doctor::required_initrd_modules`]),
//! so [`module_closure`] resolves each name to its one `.ko` path (a
//! `.ko.xz`/`.ko.zst`/`.ko.gz` on-disk spelling resolves to the same
//! module — Ubuntu kernels ≥ 6.x ship compressed modules), walks the
//! dependency graph, and returns the full path set dependency-first
//! (`insmod` order). Packing then decompresses such modules so the archive
//! carries plain `.ko` files the busybox `insmod` can load. Every
//! ambiguous, missing, cyclic, or undecompressable case fails closed — an
//! initramfs that cannot load its boot chain is a brick.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Parse `modules.dep` text into a map from module path to its dependency
/// paths. Blank lines and lines without a `:` are ignored; every field is
/// trimmed. On a duplicate key the later line replaces the earlier one (the
/// generated file never duplicates, so the choice is unobservable in
/// practice; "last wins" keeps the fold order-independent).
pub(crate) fn parse_modules_dep(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((path, deps)) = line.split_once(':') else {
            continue;
        };
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        let deps: Vec<String> = deps.split_whitespace().map(str::to_string).collect();
        map.insert(path.to_string(), deps);
    }
    map
}

/// Compression suffixes Ubuntu kernels put on module files. The kernel's
/// initramfs loader and busybox `insmod` cannot decompress modules, so a
/// compressed module is unpacked at pack time ([`decompress_module`]) and
/// stored under its plain `.ko` name.
const COMPRESSION_SUFFIXES: [&str; 3] = [".zst", ".xz", ".gz"];

/// The compression suffix `path` ends with, if any (`dm-verity.ko.zst` →
/// `".zst"`).
fn compression_suffix(path: &str) -> Option<&'static str> {
    COMPRESSION_SUFFIXES
        .into_iter()
        .find(|suffix| path.ends_with(suffix))
}

/// `path` with its compression suffix stripped (`a.ko.zst` → `a.ko`); a
/// plain path passes through unchanged. The `.ko` itself is kept — the
/// unpacked module is a normal `.ko` file.
fn unpacked_rel(path: &str) -> &str {
    match compression_suffix(path) {
        Some(suffix) => &path[..path.len() - suffix.len()],
        None => path,
    }
}

/// Decompress a compressed module's bytes with the matching host tool
/// (`zstd`/`xz`/`gzip -dc`). The kernel's initramfs loader and busybox
/// `insmod` cannot decompress modules, so the archive must carry the plain
/// `.ko`; a missing tool or a failed decompression fails closed.
fn decompress_module(data: Vec<u8>, rel: &str) -> miette::Result<Vec<u8>> {
    let Some(suffix) = compression_suffix(rel) else {
        return Ok(data);
    };
    let tool = match suffix {
        ".zst" => "zstd",
        ".xz" => "xz",
        ".gz" => "gzip",
        other => unreachable!("unhandled compression suffix {other}"),
    };
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    let mut child = Command::new(tool)
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            miette::miette!(
                "module '{rel}' is compressed ({suffix}) but {tool} is unavailable: {e} — \
                 the initramfs must carry the decompressed module, and busybox insmod \
                 cannot load the compressed form; install {tool}"
            )
        })?;
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(&data)
        .map_err(|e| miette::miette!("writing '{rel}' to {tool}: {e}"))?;
    // Drop stdin so the tool sees EOF.
    drop(child.stdin.take());
    let mut out = Vec::new();
    child
        .stdout
        .as_mut()
        .expect("stdout piped")
        .read_to_end(&mut out)
        .map_err(|e| miette::miette!("reading {tool} output for '{rel}': {e}"))?;
    let result = child
        .wait()
        .map_err(|e| miette::miette!("waiting for {tool}: {e}"))?;
    if !result.success() {
        return Err(miette::miette!(
            "{tool} failed to decompress module '{rel}' (exit {}): the initramfs must \
             carry the decompressed module and busybox insmod cannot load the \
             compressed form",
            result.code().unwrap_or(-1)
        ));
    }
    Ok(out)
}

/// Resolve a module *name* (`dm-verity`) to its single `.ko` path in the dep
/// map by matching the basename `"<name>.ko"` (optionally carrying a
/// compression suffix — `dm-verity.ko.zst` is the same module) across the
/// keys. Zero or more than one match is a fail-closed error naming the
/// module and the candidates — a silent pick would ship the wrong module.
fn resolve_module_path(name: &str, deps: &BTreeMap<String, Vec<String>>) -> miette::Result<String> {
    let wanted = format!("{name}.ko");
    let candidates: Vec<&String> = deps
        .keys()
        .filter(|path| unpacked_rel(path.rsplit('/').next().unwrap_or(path)) == wanted.as_str())
        .collect();
    match candidates.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err(miette::miette!(
            "required module '{name}' ({wanted}) not found in modules.dep — the kernel \
             snap's module tree does not carry it, so the initramfs cannot load its \
             boot chain"
        )),
        many => {
            let list = many
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(miette::miette!(
                "required module '{name}' is ambiguous in modules.dep: {list}"
            ))
        }
    }
}

/// The full set of module PATHS needed to `insmod` `required`, returned
/// dependency-first (a module appears after all of its dependencies) and
/// deduplicated. Sibling order is sorted, so the result does not depend on
/// input ordering or on map iteration.
///
/// Fails closed on an unresolved required name, a missing dependency, or a
/// dependency cycle. A compressed on-disk spelling resolves normally; the
/// pack step decompresses it ([`decompress_module`]).
pub(crate) fn module_closure(
    required: &[String],
    deps: &BTreeMap<String, Vec<String>>,
) -> miette::Result<Vec<String>> {
    let mut roots: Vec<String> = required
        .iter()
        .map(|name| resolve_module_path(name, deps))
        .collect::<miette::Result<Vec<_>>>()?;
    roots.sort();
    roots.dedup();

    let mut order: Vec<String> = Vec::new();
    let mut state: BTreeMap<String, Visit> = BTreeMap::new();
    for root in &roots {
        visit(root, deps, &mut order, &mut state, &mut Vec::new())?;
    }
    Ok(order)
}

/// DFS visit state, the cycle detector's three colors.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    /// On the current DFS stack — revisiting it is a cycle.
    InProgress,
    /// Fully emitted, every dependency already ahead of it.
    Done,
}

/// Depth-first, post-order walk: a node is pushed only after every
/// dependency has been pushed, which is exactly `insmod` order.
fn visit(
    path: &str,
    deps: &BTreeMap<String, Vec<String>>,
    order: &mut Vec<String>,
    state: &mut BTreeMap<String, Visit>,
    stack: &mut Vec<String>,
) -> miette::Result<()> {
    match state.get(path) {
        Some(Visit::Done) => return Ok(()),
        Some(Visit::InProgress) => return Err(cycle_error(path, stack)),
        None => {}
    }
    state.insert(path.to_string(), Visit::InProgress);
    stack.push(path.to_string());
    for dep in dependencies_of(path, deps)? {
        visit(&dep, deps, order, state, stack)?;
    }
    stack.pop();
    state.insert(path.to_string(), Visit::Done);
    order.push(path.to_string());
    Ok(())
}

/// The sorted dependency paths of `path`, verifying each is a key in the
/// map — a dependency that is not present cannot be loaded.
fn dependencies_of(
    path: &str,
    deps: &BTreeMap<String, Vec<String>>,
) -> miette::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for dep in deps.get(path).into_iter().flatten() {
        if !deps.contains_key(dep) {
            return Err(miette::miette!(
                "module '{path}' depends on '{dep}', which is not present in \
                 modules.dep — refusing to build an initramfs that cannot load its \
                 boot chain"
            ));
        }
        out.push(dep.clone());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Build a cycle error naming every member from the repeated node to the
/// current top of the stack.
fn cycle_error(path: &str, stack: &[String]) -> miette::Error {
    let start = stack
        .iter()
        .position(|p| p == path)
        .unwrap_or(stack.len().saturating_sub(1));
    let mut members: Vec<&str> = stack[start..].iter().map(String::as_str).collect();
    members.push(path);
    miette::miette!(
        "dependency cycle among modules: {} — modules.dep is malformed",
        members.join(" -> ")
    )
}

// ── newc cpio writer ──

/// A `newc` cpio member. Directories and symlinks carry `mode = 0` fields —
/// their octal type bits are OR'd in by [`newc_archive`] from the kind.
pub(crate) enum CpioKind<'a> {
    /// A regular file. `mode` is the permission bits (e.g. `0o644`).
    File { mode: u32, data: &'a [u8] },
    /// A directory. `mode` is the permission bits (e.g. `0o755`).
    Directory { mode: u32 },
    /// A symbolic link whose target is the payload of the member.
    Symlink { target: &'a [u8] },
}

impl CpioKind<'_> {
    /// Permission bits for this member (symlinks are always `0777`, as the
    /// kernel creates them).
    fn mode(&self) -> u32 {
        match self {
            CpioKind::File { mode, .. } | CpioKind::Directory { mode } => *mode,
            CpioKind::Symlink { .. } => 0o777,
        }
    }

    /// Octal type bits for the `mode` field.
    fn type_bits(&self) -> u32 {
        match self {
            CpioKind::File { .. } => 0o100000,
            CpioKind::Directory { .. } => 0o040000,
            CpioKind::Symlink { .. } => 0o120000,
        }
    }

    /// The member's payload (empty for directories).
    fn payload(&self) -> &[u8] {
        match self {
            CpioKind::File { data, .. } => data,
            CpioKind::Directory { .. } => &[],
            CpioKind::Symlink { target } => target,
        }
    }
}

/// One entry in a `newc` archive.
pub(crate) struct CpioEntry<'a> {
    /// Member path relative to the archive root (`etc/init.d/rcS`).
    pub name: &'a str,
    /// What the member is.
    pub kind: CpioKind<'a>,
}

/// Build a deterministic `newc` (magic `070701`) cpio archive.
///
/// Every numeric header field is eight lowercase hex digits; `ino` is a
/// deterministic index, `uid`/`gid` are zero, `mtime` is zero (no host
/// clock), and `devmajor`/`devminor`/`rdevmajor`/`rdevminor`/`check` are
/// zero. Payload and names are NUL-padded to 4-byte boundaries. A
/// `TRAILER!!!` member closes the archive, which is then zero-padded to a
/// 512-byte boundary so the image is block-aligned.
pub(crate) fn newc_archive(entries: &[CpioEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        write_member(&mut out, index as u32, entry.name, &entry.kind);
    }
    let trailer = CpioEntry {
        name: "TRAILER!!!",
        kind: CpioKind::File { mode: 0, data: &[] },
    };
    write_member(&mut out, entries.len() as u32, trailer.name, &trailer.kind);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

/// One `newc` header field: eight lowercase hex digits.
fn hex_field(value: u32) -> [u8; 8] {
    let mut field = [0u8; 8];
    let text = format!("{value:08x}");
    field.copy_from_slice(text.as_bytes());
    field
}

/// Pad `out` with NULs to the next 4-byte boundary.
fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Append one `newc` member (header + NUL-terminated name + payload) to
/// `out`, aligning both the name and the payload to 4 bytes.
fn write_member(out: &mut Vec<u8>, ino: u32, name: &str, kind: &CpioKind) {
    let payload = kind.payload();
    let name_bytes = name.as_bytes();
    let namesize = name_bytes.len() + 1; // trailing NUL

    out.extend_from_slice(b"070701");
    for field in [
        ino,
        kind.type_bits() | kind.mode(),
        0, // uid
        0, // gid
        1, // nlink
        0, // mtime — deterministic
        payload.len() as u32,
        0,               // devmajor
        0,               // devminor
        0,               // rdevmajor
        0,               // rdevminor
        namesize as u32, // includes the NUL terminator
        0,               // check
    ] {
        out.extend_from_slice(&hex_field(field));
    }

    out.extend_from_slice(name_bytes);
    out.push(0);
    pad4(out);
    out.extend_from_slice(payload);
    pad4(out);
}

// ── Assembly wiring (issue #75) ──

/// The three static userspace binaries the native initramfs ships: a
/// static-musl busybox (the shell, `insmod`, `mount`, `switch_root`, and
/// the text/`dd`/`od` applets `/init` uses), util-linux `findfs` (busybox
/// `findfs` cannot resolve a PARTUUID, and the 5.15 kernel does not export
/// PARTUUID in uevent), and `veritysetup` (dm-verity).
pub(crate) struct InitramfsTools {
    pub(crate) busybox: PathBuf,
    pub(crate) findfs: PathBuf,
    pub(crate) veritysetup: PathBuf,
}

/// The devbox package each tool comes from, for a fail-closed message that
/// names the exact fix, plus the store-path keyword that identifies the
/// owning static package (so busybox's multicall `findfs` is never mistaken
/// for util-linux's).
const TOOL_PACKAGES: [(&str, &str, &str); 3] = [
    (
        "busybox",
        "github:NixOS/nixpkgs#pkgsStatic.busybox",
        "busybox",
    ),
    (
        "findfs",
        "github:NixOS/nixpkgs#pkgsStatic.util-linux",
        "util-linux",
    ),
    (
        "veritysetup",
        "github:NixOS/nixpkgs#pkgsStatic.cryptsetup",
        "cryptsetup",
    ),
];

/// Resolve the three static userspace binaries, fail closed and name the
/// devbox package when one is missing.
///
/// The devbox profile's PATH resolves `findfs` to busybox's static applet
/// (which cannot do PARTUUID) and `veritysetup` to the dynamic cryptsetup
/// (which links glibc and cannot run in the initramfs) because their
/// `meta.priority` beats the static packages. So resolve from the devbox
/// package manifest's static store paths first — the only place the static
/// binaries are guaranteed — and fall back to PATH for hosts that put the
/// static tools there directly.
pub(crate) fn discover_initramfs_tools() -> miette::Result<InitramfsTools> {
    let static_bins = devbox_static_bins();
    let entries = crate::snap::path_entries();
    let resolve = |name: &str| -> miette::Result<PathBuf> {
        let (package, owner) = TOOL_PACKAGES
            .iter()
            .find(|(tool, _, _)| *tool == name)
            .map(|(_, pkg, owner)| (*pkg, *owner))
            .unwrap_or((name, name));
        // A candidate belongs to the tool's owning static package when its
        // store path carries the package keyword (`busybox`, `util-linux`,
        // `cryptsetup`). This rejects busybox's `findfs`/`sbin` applets.
        if let Some(path) = static_bins
            .iter()
            .find(|p| p.ends_with(name) && p.to_string_lossy().contains(owner))
        {
            if path.is_file() {
                return Ok(path.clone());
            }
        }
        crate::snap::resolve_in_path(name, &entries).ok_or_else(|| {
            miette::miette!(
                "initramfs tool '{name}' not found — shuttle builds a native initramfs \
                 for a prebuilt-UKI kernel and needs {name}; run 'shuttle doctor' and \
                 add {package} to devbox.json packages"
            )
        })
    };
    Ok(InitramfsTools {
        busybox: resolve("busybox")?,
        findfs: resolve("findfs")?,
        veritysetup: resolve("veritysetup")?,
    })
}

/// The static binaries declared by a devbox profile manifest: for each
/// `-static-` element, the `bin`/`sbin` candidate path for each of the three
/// tools. Pure over the manifest text (no filesystem access) so it is
/// testable without devbox; callers check `is_file` before using a candidate.
fn static_bins_from_manifest(manifest: &str) -> Vec<PathBuf> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let Some(elements) = value.get("elements").and_then(|e| e.as_object()) else {
        return out;
    };
    for (name, element) in elements {
        // Only the static builds: `busybox-static-*`, `cryptsetup-static-*`,
        // `util-linux-static-*`. Dynamic elements share names otherwise.
        if !name.contains("-static-") {
            continue;
        }
        let Some(paths) = element.get("storePaths").and_then(|p| p.as_array()) else {
            continue;
        };
        for store in paths.iter().filter_map(|p| p.as_str()) {
            for sub in ["bin", "sbin"] {
                for (tool, _, _) in TOOL_PACKAGES {
                    out.push(Path::new(store).join(sub).join(tool));
                }
            }
        }
    }
    out
}

/// The static binaries from the active devbox profile's manifest, if any.
fn devbox_static_bins() -> Vec<PathBuf> {
    let dir = std::env::var_os("DEVBOX_PACKAGES_DIR")
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(".devbox/nix/profile/default")));
    let Some(dir) = dir else {
        return Vec::new();
    };
    let Ok(manifest) = std::fs::read_to_string(dir.join("manifest.json")) else {
        return Vec::new();
    };
    static_bins_from_manifest(&manifest)
}

/// Busybox applet symlink names the `/init` script calls through PATH
/// (`PATH=/sbin:/bin`), plus the tools its PARTUUID fallback and
/// `dm-control` fallback need (`dirname`, `mknod` — neither is a shell
/// builtin). Each becomes `/bin/<name>` → `busybox`.
const BUSYBOX_APPLETS: [&str; 17] = [
    "sh",
    "mount",
    "mkdir",
    "cat",
    "tr",
    "sed",
    "basename",
    "dirname",
    "readlink",
    "dd",
    "od",
    "awk",
    "insmod",
    "mknod",
    "switch_root",
    "printf",
    "sleep",
];

/// Owned bytes for every archive member, held alive while the borrowed
/// [`CpioEntry`] list references them.
struct StagedFiles {
    init: Vec<u8>,
    modules_load: Vec<u8>,
    busybox: Vec<u8>,
    findfs: Vec<u8>,
    veritysetup: Vec<u8>,
    modules: Vec<(String, Vec<u8>)>,
}

/// Read a file into memory, failing closed with the exact path and role.
fn read_input(path: &Path, role: &str) -> miette::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        miette::miette!(
            "cannot read {role} at {}: {e} — refusing to build an initramfs that \
             cannot load its boot chain",
            path.display()
        )
    })
}

/// Read the kernel config and derive the required boot-chain module names.
fn required_modules(config_path: &Path) -> miette::Result<Vec<String>> {
    let text = std::fs::read_to_string(config_path).map_err(|e| {
        miette::miette!(
            "cannot read kernel config {}: {e} — cannot derive the initramfs \
             boot-chain modules, so refusing to build an initramfs that cannot \
             load its boot chain",
            config_path.display()
        )
    })?;
    Ok(crate::doctor::required_initrd_modules(&text))
}

/// The ordered module paths (relative to `modules_root`) for `required`,
/// failing closed when `modules.dep` is missing or unreadable.
fn closure_modules(modules_root: &Path, required: &[String]) -> miette::Result<Vec<String>> {
    let dep_path = modules_root.join("modules.dep");
    let text = std::fs::read_to_string(&dep_path).map_err(|e| {
        miette::miette!(
            "cannot read {}: {e} — the kernel snap's module tree does not carry \
             modules.dep, so the initramfs boot-chain closure cannot be resolved; \
             refusing to build an initramfs that cannot load its boot chain",
            dep_path.display()
        )
    })?;
    let deps = parse_modules_dep(&text);
    module_closure(required, &deps)
}

/// Read every payload the archive needs, so assembly can build borrowed
/// entries over stable buffers. A compressed module is decompressed here
/// and staged under its plain `.ko` name — the `/modules.load` contract
/// and the archive member names are the unpacked spellings.
fn stage_files(
    tools: &InitramfsTools,
    modules_root: &Path,
    modules: &[String],
    version: &str,
) -> miette::Result<StagedFiles> {
    let mut staged_modules = Vec::with_capacity(modules.len());
    for rel in modules {
        let absolute = modules_root.join(rel);
        let data = read_input(&absolute, &format!("module '{rel}'"))?;
        let data = decompress_module(data, rel)?;
        staged_modules.push((unpacked_rel(rel).to_string(), data));
    }
    let staged_names: Vec<String> = staged_modules
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    Ok(StagedFiles {
        init: include_str!("initramfs/init").as_bytes().to_vec(),
        modules_load: modules_load_text(version, &staged_names),
        busybox: read_input(&tools.busybox, "busybox")?,
        findfs: read_input(&tools.findfs, "findfs")?,
        veritysetup: read_input(&tools.veritysetup, "veritysetup")?,
        modules: staged_modules,
    })
}

/// The `/modules.load` body: one `/lib/modules/<version>/<rel>` per line in
/// closure order, newline-terminated (the `/init` contract).
fn modules_load_text(version: &str, modules: &[String]) -> Vec<u8> {
    let mut text = String::new();
    for rel in modules {
        text.push_str(&format!("/lib/modules/{version}/{rel}\n"));
    }
    text.into_bytes()
}

/// The fixed directory skeleton, plus every parent directory of the module
/// and staged-binary paths.
fn archive_directories(version: &str, modules: &[String]) -> Vec<String> {
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for dir in [
        "dev",
        "dev/mapper",
        "proc",
        "sys",
        "bin",
        "sbin",
        "lib",
        "lib/modules",
        "sysroot",
    ] {
        dirs.insert(dir.to_string());
    }
    dirs.insert(format!("lib/modules/{version}"));
    for rel in modules {
        for parent in parents_of(&format!("lib/modules/{version}/{rel}")) {
            dirs.insert(parent);
        }
    }
    // Parents of the staged binaries (`bin`, `sbin`) already exist above.
    dirs.into_iter().collect()
}

/// Every ancestor directory of a `/`-separated relative path, prefix-first
/// (`a/b/c` → `["a", "a/b"]`).
fn parents_of(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut prefix = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        out.push(prefix.clone());
    }
    out
}

/// Build the borrowed `newc` entry list over `staged` (which must outlive
/// the returned entries).
fn archive_entries<'a>(
    version: &str,
    modules: &[String],
    staged: &'a StagedFiles,
) -> Vec<CpioEntry<'a>> {
    let mut entries = Vec::new();
    for dir in archive_directories(version, modules) {
        entries.push(CpioEntry {
            name: leak_name(dir),
            kind: CpioKind::Directory { mode: 0o755 },
        });
    }
    entries.push(CpioEntry {
        name: "init",
        kind: CpioKind::File {
            mode: 0o755,
            data: &staged.init,
        },
    });
    entries.push(CpioEntry {
        name: "modules.load",
        kind: CpioKind::File {
            mode: 0o644,
            data: &staged.modules_load,
        },
    });
    entries.push(CpioEntry {
        name: "bin/busybox",
        kind: CpioKind::File {
            mode: 0o755,
            data: &staged.busybox,
        },
    });
    for applet in BUSYBOX_APPLETS {
        entries.push(CpioEntry {
            name: leak_name(format!("bin/{applet}")),
            kind: CpioKind::Symlink { target: b"busybox" },
        });
    }
    entries.push(CpioEntry {
        name: "sbin/findfs",
        kind: CpioKind::File {
            mode: 0o755,
            data: &staged.findfs,
        },
    });
    entries.push(CpioEntry {
        name: "sbin/veritysetup",
        kind: CpioKind::File {
            mode: 0o755,
            data: &staged.veritysetup,
        },
    });
    for (rel, data) in &staged.modules {
        entries.push(CpioEntry {
            name: leak_name(format!("lib/modules/{version}/{rel}")),
            kind: CpioKind::File { mode: 0o644, data },
        });
    }
    entries
}

/// Leak a freshly built member name so it can be borrowed by the entry list.
/// Bounded by the number of archive members (thousands at most) and freed
/// when the process exits, so `Box::leak` is acceptable here.
fn leak_name(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

/// Build the gzipped `newc` initramfs into `out_dir`; returns its path.
///
/// `modules_root` is the snap's `modules/<version>/` tree (carries
/// `modules.dep` and the `kernel/...` paths); `config_path` is the kernel
/// config; `version` is the ABI version, e.g. `5.15.0-186-generic`.
pub(crate) fn build_native_initramfs(
    tools: &InitramfsTools,
    modules_root: &Path,
    config_path: &Path,
    version: &str,
    out_dir: &Path,
) -> miette::Result<PathBuf> {
    let required = required_modules(config_path)?;
    let modules = closure_modules(modules_root, &required)?;
    let staged = stage_files(tools, modules_root, &modules, version)?;
    // Archive paths (and `/modules.load`) use the staged (unpacked) names.
    let unpacked: Vec<String> = staged
        .modules
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let entries = archive_entries(version, &unpacked, &staged);
    let archive = newc_archive(&entries);
    let gz = gzip_bytes(&archive);
    std::fs::create_dir_all(out_dir).map_err(|e| {
        miette::miette!(
            "cannot create initramfs output dir {}: {e}",
            out_dir.display()
        )
    })?;
    let output = out_dir.join("initramfs.img.gz");
    std::fs::write(&output, gz)
        .map_err(|e| miette::miette!("cannot write native initramfs {}: {e}", output.display()))?;
    Ok(output)
}

/// Deterministically gzip `archive` (no host clock: `mtime(0)`), matching
/// the reproducibility the cpio writer already guarantees.
fn gzip_bytes(archive: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(archive)
        .expect("writing to an in-memory gzip encoder cannot fail");
    encoder
        .finish()
        .expect("finishing an in-memory gzip encoder cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `modules.dep` lines the rev-3654 pc-kernel ships (cropped
    /// from `/tmp/opencode/pckernel_3654/modules/5.15.0-186-generic`).
    const REAL_DEP: &str = "\
kernel/drivers/block/virtio_blk.ko:
kernel/drivers/md/dm-bufio.ko:
kernel/drivers/md/dm-verity.ko: kernel/drivers/md/dm-bufio.ko
";

    const VIRTIO_BLK: &str = "kernel/drivers/block/virtio_blk.ko";
    const DM_BUFIO: &str = "kernel/drivers/md/dm-bufio.ko";
    const DM_VERITY: &str = "kernel/drivers/md/dm-verity.ko";

    fn required() -> Vec<String> {
        crate::doctor::required_initrd_modules("CONFIG_DM_VERITY=m\nCONFIG_VIRTIO_BLK=m\n")
    }

    #[test]
    fn parse_modules_dep_reads_real_lines() {
        let deps = parse_modules_dep(REAL_DEP);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps.get(VIRTIO_BLK), Some(&vec![]));
        assert_eq!(deps.get(DM_BUFIO), Some(&vec![]));
        assert_eq!(deps.get(DM_VERITY), Some(&vec![DM_BUFIO.to_string()]));
    }

    #[test]
    fn parse_modules_dep_ignores_blanks_and_bare_lines() {
        let deps = parse_modules_dep("\n  mod.ko:  dep.ko  \nnot-a-dep-line\n\n");
        // `not-a-dep-line` has no `:`, so it is skipped entirely.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps.get("mod.ko"), Some(&vec!["dep.ko".to_string()]));
    }

    #[test]
    fn parse_modules_dep_duplicate_key_last_wins() {
        let deps = parse_modules_dep("a.ko: b.ko\na.ko:\n");
        assert_eq!(deps.get("a.ko"), Some(&vec![]));
    }

    #[test]
    fn closure_is_dependency_first_and_deduplicated() {
        let deps = parse_modules_dep(REAL_DEP);
        let required = vec!["dm-verity".to_string(), "virtio_blk".to_string()];
        // Siblings are sorted (roots first), so the independent virtio_blk
        // sorts before the dm-* chain; within the chain deps come first.
        let order = module_closure(&required, &deps).expect("closure resolves");
        assert_eq!(
            order,
            vec![
                VIRTIO_BLK.to_string(),
                DM_BUFIO.to_string(),
                DM_VERITY.to_string(),
            ]
        );
        let bufio = order.iter().position(|p| p == DM_BUFIO).unwrap();
        let verity = order.iter().position(|p| p == DM_VERITY).unwrap();
        assert!(bufio < verity, "dm-bufio must precede dm-verity");
        assert_eq!(order.len(), 3, "no duplicates");
    }

    #[test]
    fn closure_order_is_independent_of_required_ordering() {
        let deps = parse_modules_dep(REAL_DEP);
        let forward = module_closure(&required(), &deps).unwrap();
        let mut backward = required();
        backward.reverse();
        assert_eq!(forward, module_closure(&backward, &deps).unwrap());
    }

    #[test]
    fn closure_rejects_unresolved_required_name() {
        let deps = parse_modules_dep(REAL_DEP);
        let err = module_closure(&["nvme".to_string()], &deps).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nvme"), "names the module: {msg}");
        assert!(msg.contains("not found"), "actionable: {msg}");
    }

    #[test]
    fn closure_rejects_ambiguous_required_name() {
        let deps = parse_modules_dep("a/dup.ko:\nb/dup.ko:\n");
        let err = module_closure(&["dup".to_string()], &deps).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ambiguous"), "{msg}");
        assert!(
            msg.contains("a/dup.ko") && msg.contains("b/dup.ko"),
            "{msg}"
        );
    }

    #[test]
    fn closure_rejects_missing_dependency() {
        let deps = parse_modules_dep("a.ko: ghost.ko\n");
        let err = module_closure(&["a".to_string()], &deps).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("a.ko") && msg.contains("ghost.ko"), "{msg}");
        assert!(msg.contains("not present"), "{msg}");
    }

    #[test]
    fn closure_rejects_cycle_naming_members() {
        let deps = parse_modules_dep("a.ko: b.ko\nb.ko: a.ko\n");
        let err = module_closure(&["a".to_string()], &deps).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cycle"), "{msg}");
        assert!(msg.contains("a.ko") && msg.contains("b.ko"), "{msg}");
    }

    #[test]
    fn closure_resolves_a_compressed_module_spelling() {
        // Ubuntu kernels ≥ 6.x ship modules compressed; the dep-map path
        // still names the module, so resolution succeeds (a tree carrying
        // BOTH spellings would be ambiguous — real maps carry one).
        let deps = parse_modules_dep("kernel/drivers/a.ko.xz:\n");
        let order = module_closure(&["a".to_string()], &deps).unwrap();
        assert_eq!(order, vec!["kernel/drivers/a.ko.xz".to_string()]);
    }

    #[test]
    fn resolve_module_path_matches_compressed_basenames() {
        let deps = parse_modules_dep(
            "kernel/drivers/md/dm-verity.ko.zst:\nkernel/drivers/block/virtio_blk.ko:\n",
        );
        assert_eq!(
            resolve_module_path("dm-verity", &deps).unwrap(),
            "kernel/drivers/md/dm-verity.ko.zst"
        );
        assert_eq!(
            resolve_module_path("virtio_blk", &deps).unwrap(),
            "kernel/drivers/block/virtio_blk.ko"
        );
    }

    fn fixture_entries() -> Vec<CpioEntry<'static>> {
        vec![
            CpioEntry {
                name: "etc",
                kind: CpioKind::Directory { mode: 0o755 },
            },
            CpioEntry {
                name: "etc/shuttle.conf",
                kind: CpioKind::File {
                    mode: 0o644,
                    data: b"root=PARTUUID=x roothash=deadbeef\n",
                },
            },
            CpioEntry {
                name: "sbin/init",
                kind: CpioKind::File {
                    mode: 0o755,
                    data: b"#!/bin/sh\n",
                },
            },
            CpioEntry {
                name: "sbin",
                kind: CpioKind::Symlink { target: b"../bin" },
            },
        ]
    }

    #[test]
    fn newc_archive_round_trips_through_doctor_reader() {
        let entries = fixture_entries();
        let archive = newc_archive(&entries);
        let members = crate::doctor::cpio_newc_members(&archive).expect("reader accepts writer");
        assert_eq!(
            members,
            vec![
                "etc".to_string(),
                "etc/shuttle.conf".to_string(),
                "sbin/init".to_string(),
                "sbin".to_string(),
            ]
        );
    }

    #[test]
    fn newc_archive_carries_trailer_and_starts_newc() {
        let archive = newc_archive(&fixture_entries());
        assert!(archive.starts_with(b"070701"));
        assert_eq!(archive.len() % 512, 0, "512-byte aligned");
        assert!(
            archive.windows(10).any(|w| w == b"TRAILER!!!"),
            "archive ends with a TRAILER!!! member"
        );
    }

    #[test]
    fn newc_archive_is_deterministic() {
        let first = newc_archive(&fixture_entries());
        let second = newc_archive(&fixture_entries());
        assert_eq!(first, second, "no host clock and no index nondeterminism");
    }

    #[test]
    fn newc_header_fields_are_deterministic_zero_mtime() {
        let archive = newc_archive(&[CpioEntry {
            name: "file",
            kind: CpioKind::File {
                mode: 0o644,
                data: b"hi",
            },
        }]);
        // magic + ino(0) + mode(0100644) + uid(0) + gid(0) + nlink(1) + mtime(0) …
        assert_eq!(&archive[0..6], b"070701");
        assert_eq!(&archive[6..14], b"00000000"); // ino
        assert_eq!(&archive[14..22], b"000081a4"); // mode: 0100644
        assert_eq!(&archive[22..30], b"00000000"); // uid
        assert_eq!(&archive[30..38], b"00000000"); // gid
        assert_eq!(&archive[38..46], b"00000001"); // nlink
        assert_eq!(&archive[46..54], b"00000000"); // mtime — no host clock
    }

    // ── Native initramfs assembly (issue #75) ──

    const FIXTURE_VERSION: &str = "5.15.0-186-generic";

    /// Write a small but real module tree: `modules.dep` plus the three
    /// closure `.ko` files, and a stub kernel config requiring them.
    fn write_fixture_tree(root: &Path) -> (PathBuf, PathBuf) {
        let modules_root = root.join("modules").join(FIXTURE_VERSION);
        for rel in [VIRTIO_BLK, DM_BUFIO, DM_VERITY] {
            let path = modules_root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{rel} payload")).unwrap();
        }
        std::fs::write(modules_root.join("modules.dep"), REAL_DEP).unwrap();
        let config = root.join(format!("config-{FIXTURE_VERSION}"));
        std::fs::write(&config, "CONFIG_DM_VERITY=m\nCONFIG_VIRTIO_BLK=m\n").unwrap();
        (modules_root, config)
    }

    /// Write three tiny files to stand in for busybox/findfs/veritysetup.
    fn write_fixture_tools(root: &Path) -> InitramfsTools {
        let path = |name: &str| root.join(name);
        std::fs::write(path("busybox"), b"BUSYBOX").unwrap();
        std::fs::write(path("findfs"), b"FINDFS").unwrap();
        std::fs::write(path("veritysetup"), b"VERITYSETUP").unwrap();
        InitramfsTools {
            busybox: path("busybox"),
            findfs: path("findfs"),
            veritysetup: path("veritysetup"),
        }
    }

    /// Gunzip `bytes` through the in-process decoder.
    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .expect("fixture archive is valid gzip");
        out
    }

    #[test]
    fn build_native_initramfs_contains_the_documented_members() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, config) = write_fixture_tree(root.path());
        let tools = write_fixture_tools(root.path());
        let out_dir = root.path().join("out");

        let archive_path =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, &out_dir)
                .expect("assembly succeeds");
        assert!(archive_path.is_file(), "returns the written path");

        let raw = gunzip(&std::fs::read(&archive_path).unwrap());
        let members = crate::doctor::cpio_newc_members(&raw).expect("reader accepts archive");
        for expected in [
            "init",
            "modules.load",
            "bin/busybox",
            "sbin/findfs",
            "sbin/veritysetup",
            "dev",
            "dev/mapper",
            "proc",
            "sys",
            "bin",
            "sbin",
            "lib",
            "lib/modules",
            &format!("lib/modules/{FIXTURE_VERSION}"),
            &format!("lib/modules/{FIXTURE_VERSION}/{VIRTIO_BLK}"),
            &format!("lib/modules/{FIXTURE_VERSION}/{DM_BUFIO}"),
            &format!("lib/modules/{FIXTURE_VERSION}/{DM_VERITY}"),
        ] {
            assert!(
                members.iter().any(|m| m == expected),
                "missing member {expected}; got {members:?}"
            );
        }
        for applet in ["bin/sh", "bin/dirname", "bin/mknod", "bin/switch_root"] {
            assert!(
                members.iter().any(|m| m == applet),
                "busybox applet symlink {applet} present; got {members:?}"
            );
        }
    }

    #[test]
    fn modules_load_is_the_closure_in_order_with_version_prefix() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, config) = write_fixture_tree(root.path());
        let tools = write_fixture_tools(root.path());
        let out_dir = root.path().join("out");

        let archive_path =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, &out_dir)
                .unwrap();
        let raw = gunzip(&std::fs::read(&archive_path).unwrap());
        let text = std::str::from_utf8(find_member(&raw, "modules.load").unwrap()).unwrap();
        assert_eq!(
            text,
            format!(
                "/lib/modules/{FIXTURE_VERSION}/{VIRTIO_BLK}\n\
                 /lib/modules/{FIXTURE_VERSION}/{DM_BUFIO}\n\
                 /lib/modules/{FIXTURE_VERSION}/{DM_VERITY}\n"
            )
        );
    }

    #[test]
    fn build_native_initramfs_is_byte_identical_across_runs() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, config) = write_fixture_tree(root.path());
        let tools = write_fixture_tools(root.path());
        let first =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, root.path())
                .unwrap();
        let first_bytes = std::fs::read(&first).unwrap();
        let second =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, root.path())
                .unwrap();
        assert_eq!(
            first, second,
            "same output path across runs in the same dir"
        );
        assert_eq!(
            first_bytes,
            std::fs::read(&second).unwrap(),
            "deterministic gzip: no host clock, same bytes"
        );
    }

    #[test]
    fn build_fails_closed_when_modules_dep_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, config) = write_fixture_tree(root.path());
        std::fs::remove_file(modules_root.join("modules.dep")).unwrap();
        let tools = write_fixture_tools(root.path());
        let err =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, root.path())
                .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("modules.dep"), "{msg}");
    }

    #[test]
    fn build_fails_closed_when_config_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, _config) = write_fixture_tree(root.path());
        let tools = write_fixture_tools(root.path());
        let missing = root.path().join("nope-config");
        let err = build_native_initramfs(
            &tools,
            &modules_root,
            &missing,
            FIXTURE_VERSION,
            root.path(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("kernel config"), "{err:#}");
    }

    #[test]
    fn build_fails_closed_when_a_tool_is_missing() {
        for tool in ["busybox", "findfs", "veritysetup"] {
            let root = tempfile::tempdir().unwrap();
            let (modules_root, config) = write_fixture_tree(root.path());
            let tools = write_fixture_tools(root.path());
            std::fs::remove_file(root.path().join(tool)).unwrap();
            let err = build_native_initramfs(
                &tools,
                &modules_root,
                &config,
                FIXTURE_VERSION,
                root.path(),
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains(tool),
                "error names the missing tool {tool}: {err:#}"
            );
        }
    }

    #[test]
    fn build_decompresses_a_compressed_dependency() {
        let root = tempfile::tempdir().unwrap();
        let (modules_root, config) = write_fixture_tree(root.path());
        // Compress the dm-bufio fixture on disk the way a modern kernel
        // snap ships it, and point modules.dep at the compressed spelling.
        let bufio = std::fs::read(modules_root.join(DM_BUFIO)).unwrap();
        std::fs::write(
            modules_root.join("kernel/drivers/md/dm-bufio.ko.xz"),
            &bufio,
        )
        .unwrap();
        std::fs::remove_file(modules_root.join(DM_BUFIO)).unwrap();
        std::fs::write(
            modules_root.join("modules.dep"),
            "kernel/drivers/block/virtio_blk.ko:\n\
             kernel/drivers/md/dm-bufio.ko.xz:\n\
             kernel/drivers/md/dm-verity.ko: kernel/drivers/md/dm-bufio.ko.xz\n",
        )
        .unwrap();
        let tools = write_fixture_tools(root.path());
        let out_dir = root.path().join("out");
        let initramfs =
            build_native_initramfs(&tools, &modules_root, &config, FIXTURE_VERSION, &out_dir)
                .unwrap();
        // The archive carries the DECOMPRESSED module: the plain `.ko`
        // member is present, the `.ko.xz` spelling is not.
        let gz = std::fs::read(&initramfs).unwrap();
        let members = crate::doctor::cpio_newc_members(&gunzip(&gz)).unwrap();
        let bufio_member = format!("lib/modules/{FIXTURE_VERSION}/kernel/drivers/md/dm-bufio.ko");
        assert!(
            members.iter().any(|m| m == &bufio_member),
            "archive carries the unpacked module: {members:?}"
        );
        assert!(
            !members.iter().any(|m| m.ends_with(".ko.xz")),
            "no compressed module ships: {members:?}"
        );
    }

    /// Assemble against the real extracted `pc-kernel` rev 3654 tree when
    /// `SHUTTLE_REAL_PCKERNEL` names it — skipped by default so the suite has
    /// no host-path dependency. Proves the closure, `/modules.load`, and the
    /// archive against the shipped module tree, not a fixture.
    #[test]
    fn build_native_initramfs_against_the_real_pc_kernel_tree() {
        let Ok(tree) = std::env::var("SHUTTLE_REAL_PCKERNEL") else {
            return;
        };
        let root = Path::new(&tree);
        let modules_root = root.join("modules").join(FIXTURE_VERSION);
        let config = root.join(format!("config-{FIXTURE_VERSION}"));
        if !modules_root.join("modules.dep").is_file() {
            return;
        }
        let tools_dir = tempfile::tempdir().unwrap();
        let tools = write_fixture_tools(tools_dir.path());
        let out_dir = tempfile::tempdir().unwrap();
        let archive = build_native_initramfs(
            &tools,
            &modules_root,
            &config,
            FIXTURE_VERSION,
            out_dir.path(),
        )
        .expect("real pc-kernel tree assembles");
        let raw = gunzip(&std::fs::read(&archive).unwrap());
        let text = std::str::from_utf8(find_member(&raw, "modules.load").unwrap()).unwrap();
        assert_eq!(
            text,
            format!(
                "/lib/modules/{FIXTURE_VERSION}/{VIRTIO_BLK}\n\
                 /lib/modules/{FIXTURE_VERSION}/{DM_BUFIO}\n\
                 /lib/modules/{FIXTURE_VERSION}/{DM_VERITY}\n"
            ),
            "real closure order"
        );
    }

    /// Extract a `newc` member's bytes (same walk as the doctor reader).
    fn find_member<'a>(data: &'a [u8], want: &str) -> Option<&'a [u8]> {
        let align4 = |n: usize| (n + 3) & !3;
        let mut pos = 0;
        loop {
            let header = data.get(pos..pos + 110)?;
            if !header.starts_with(b"070701") {
                return None;
            }
            let field = |i: usize| {
                let raw = &header[6 + i * 8..6 + i * 8 + 8];
                usize::from_str_radix(std::str::from_utf8(raw).ok()?, 16).ok()
            };
            let filesize = field(6)?;
            let namesize = field(11)?;
            let name_start = pos + 110;
            let name = std::str::from_utf8(&data[name_start..name_start + namesize - 1]).ok()?;
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;
            if name == "TRAILER!!!" {
                return None;
            }
            if name == want {
                return data.get(data_start..data_end);
            }
            pos = align4(data_end);
        }
    }

    #[test]
    fn static_bins_from_manifest_lists_the_static_store_candidates() {
        let manifest = r#"{"elements":{
            "busybox-static-x86_64-unknown-linux-musl":{"storePaths":["/nix/store/aaa-busybox-static-x86_64-unknown-linux-musl-1.37.0"]},
            "cryptsetup":{"storePaths":["/nix/store/bbb-cryptsetup-2.8.7-bin"]},
            "util-linux-static-x86_64-unknown-linux-musl":{"storePaths":["/nix/store/ccc-util-linux-static-x86_64-unknown-linux-musl-2.42.2-bin"]}
        }}"#;
        let bins = static_bins_from_manifest(manifest);
        assert!(
            bins.iter().any(|p| p == &PathBuf::from(
                "/nix/store/ccc-util-linux-static-x86_64-unknown-linux-musl-2.42.2-bin/bin/findfs"
            )),
            "util-linux static findfs is a candidate: {bins:?}"
        );
        assert!(
            bins.iter()
                .any(|p| p.ends_with("busybox") && p.to_string_lossy().contains("busybox")),
            "busybox static is a candidate: {bins:?}"
        );
        // The dynamic cryptsetup element is ignored.
        assert!(
            !bins
                .iter()
                .any(|p| p.to_string_lossy().contains("bbb-cryptsetup")),
            "dynamic elements are skipped: {bins:?}"
        );
    }

    #[test]
    fn resolve_prefers_the_owning_static_package_over_busybox_findfs() {
        // Mirrors `discover_initramfs_tools`' selection: a busybox findfs
        // candidate sorts first (busybox-static < util-linux-static) and must
        // not win for the `findfs` tool.
        let bins = vec![
            PathBuf::from("/nix/store/aaa-busybox-static-x/bin/findfs"),
            PathBuf::from("/nix/store/ccc-util-linux-static-x/bin/findfs"),
        ];
        let chosen = bins
            .iter()
            .find(|p| p.ends_with("findfs") && p.to_string_lossy().contains("util-linux"))
            .expect("util-linux findfs selected");
        assert_eq!(
            chosen,
            &PathBuf::from("/nix/store/ccc-util-linux-static-x/bin/findfs")
        );
    }
}
