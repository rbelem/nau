//! Post-build leak scan (ADR-0018 Decision 3, issue #22).
//!
//! After the build's staging completes, every produced file under `$STAGE`
//! is scanned for references that resolve only into build-only payloads —
//! entries visible at build time via `build_deps` (or a `requires` entry
//! that never entered the runtime closure) — or into the merged build
//! prefix ([`crate::snap::SANDBOX_BUILD_PREFIX`]). Policy is a hard build
//! error naming the leaking file, the soname/path, and the build-only entry
//! it resolves to; per-package `leaks_ok` keeps named exceptions greppable;
//! one success line keeps the check visible.
//!
//! ELFs are parsed structurally — `DT_NEEDED`, `DT_RUNPATH`/`DT_RPATH`,
//! and the `PT_INTERP` interpreter — with a minimal in-Rust reader over the
//! program headers (no new dependencies; the crate set is minimal by
//! project policy). A needed soname resolves cleanly when it matches a file
//! the package stages itself, a runtime-closure payload, or nothing at all
//! (system libraries such as glibc). It is a LEAK when its only match is a
//! build-only payload. Any RUNPATH/RPATH entry or interpreter pointing at
//! the merged build prefix is a leak outright — that path does not exist at
//! runtime (the live case: the nix gcc wrapper bakes
//! `RUNPATH=/shuttle-build-prefix/usr/lib` into produced binaries).
//!
//! Non-ELF files get a text scan for the prefix marker (the Nix-style
//! reference scan — catches `#!/...` shebangs and embedded paths); binary
//! non-ELFs are skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::output;
use crate::snap::SANDBOX_BUILD_PREFIX;

/// What the scan needs to resolve `DT_NEEDED` sonames: the file basenames
/// every build-visible payload carries, plus which payloads are
/// runtime-closure members.
#[derive(Debug, Clone, Default)]
pub struct PayloadListings {
    /// Package name → payload file basenames, for every payload the merged
    /// build prefix materialized (`requires` ∪ `build_deps`).
    pub payloads: BTreeMap<String, BTreeSet<String>>,
    /// The runtime-closure members among `payloads` (the package's
    /// transitive `requires`). Everything else in `payloads` is build-only.
    pub runtime: BTreeSet<String>,
}

/// Why a detected reference is a leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakKind {
    /// `DT_NEEDED` soname resolving ONLY into this build-only payload.
    Needed { entry: String },
    /// RUNPATH/RPATH entry pointing into the merged build prefix.
    Runpath,
    /// ELF interpreter (PT_INTERP) pointing into the merged build prefix.
    Interpreter,
    /// Text file referencing the merged build prefix.
    Text,
}

/// One detected build-only reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    /// The staged file carrying the reference (relative to the stage root).
    pub file: String,
    /// The offending string: a `DT_NEEDED` soname, a RUNPATH entry, the
    /// interpreter path, or the raw prefix marker found in a text file.
    /// This is what a `leaks_ok` entry must match exactly.
    pub reference: String,
    pub kind: LeakKind,
}

impl Leak {
    /// The one-line failure description for the build error.
    fn describe(&self) -> String {
        let file = &self.file;
        match &self.kind {
            LeakKind::Needed { entry } => format!(
                "build-only leak in '{file}': DT_NEEDED '{r}' resolves only into \
                 build-only payload '{entry}' — list it in `requires`, ship the \
                 library, or silence with leaks_ok",
                r = self.reference
            ),
            LeakKind::Runpath => format!(
                "build-only leak in '{file}': RUNPATH entry '{r}' points into the \
                 merged build prefix, which does not exist at runtime — rebuild with \
                 a runtime-visible path or silence with leaks_ok",
                r = self.reference
            ),
            LeakKind::Interpreter => format!(
                "build-only leak in '{file}': ELF interpreter '{r}' points into the \
                 merged build prefix — rebuild with a runtime-visible interpreter or \
                 silence with leaks_ok",
                r = self.reference
            ),
            LeakKind::Text => format!(
                "build-only leak in '{file}': text references the merged build prefix \
                 ('{r}') — fix the embedded path or silence with leaks_ok",
                r = self.reference
            ),
        }
    }
}

/// What one stage scan observed.
#[derive(Debug, Default)]
pub struct ScanReport {
    /// ELF files inspected.
    pub elfs: usize,
    /// All regular files inspected (ELFs included).
    pub files: usize,
    /// Build-only references that fail the build.
    pub leaks: Vec<Leak>,
    /// Hits silenced by a `leaks_ok` entry (visibly logged).
    pub silenced: Vec<Leak>,
}

impl ScanReport {
    /// Log silenced entries visibly, emit the one success line on a clean
    /// scan, and turn any leak into a hard build error (ADR-0018 Decision 3).
    pub fn enforce(self) -> miette::Result<()> {
        for leak in &self.silenced {
            output::warn(format!(
                "leak scan: silenced '{}' in {} (leaks_ok)",
                leak.reference, leak.file
            ));
        }
        if !self.leaks.is_empty() {
            let details: Vec<String> = self.leaks.iter().map(|l| l.describe()).collect();
            return Err(miette::miette!(
                "leak scan found {} build-only reference(s):\n{}",
                self.leaks.len(),
                details.join("\n")
            ));
        }
        output::status(format!(
            "leak scan: {} ELFs, {} files, {} build-only refs",
            self.elfs,
            self.files,
            self.leaks.len()
        ));
        Ok(())
    }
}

/// Scan every produced file under `stage` (ADR-0018 Decision 3).
///
/// `leaks_ok` entries silence hits whose [`Leak::reference`] matches
/// exactly. The report is inert until [`ScanReport::enforce`] turns it
/// into logs/errors.
pub fn scan_stage(
    stage: &Path,
    listings: &PayloadListings,
    leaks_ok: &[String],
) -> miette::Result<ScanReport> {
    // Pass 1: collect regular files (no symlink following) and the stage's
    // own basenames — a package's own shared libraries resolve its own
    // DT_NEEDED entries.
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut own_basenames: BTreeSet<String> = BTreeSet::new();
    collect_files(stage, stage, &mut files, &mut own_basenames)?;

    let mut report = ScanReport {
        files: files.len(),
        ..ScanReport::default()
    };
    for (path, rel) in &files {
        scan_file(path, rel, &own_basenames, listings, leaks_ok, &mut report)?;
    }
    Ok(report)
}

/// Depth-first collection of regular files below `dir` (symlinks are never
/// followed — the stage tree is what the package staged).
fn collect_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(std::path::PathBuf, String)>,
    basenames: &mut BTreeSet<String>,
) -> miette::Result<()> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| miette::miette!("leak scan: reading {dir:?}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| miette::miette!("leak scan: reading {dir:?}: {e}"))?;
        let path = entry.path();
        // File type without following symlinks.
        let ft = entry
            .file_type()
            .map_err(|e| miette::miette!("leak scan: reading {dir:?}: {e}"))?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if ft.is_dir() {
            collect_files(root, &path, files, basenames)?;
        } else if ft.is_file() {
            if let Some(name) = path.file_name() {
                basenames.insert(name.to_string_lossy().into_owned());
            }
            files.push((path, rel));
        }
    }
    Ok(())
}

/// Scan one staged file: ELFs structurally, non-ELF text by marker.
fn scan_file(
    path: &Path,
    rel: &str,
    own: &BTreeSet<String>,
    listings: &PayloadListings,
    leaks_ok: &[String],
    report: &mut ScanReport,
) -> miette::Result<()> {
    let mut file =
        std::fs::File::open(path).map_err(|e| miette::miette!("leak scan: opening {rel}: {e}"))?;
    let mut magic = [0u8; 4];
    let n = read_up_to(&mut file, &mut magic)
        .map_err(|e| miette::miette!("leak scan: reading {rel}: {e}"))?;
    if n == 4 && magic == *b"\x7fELF" {
        report.elfs += 1;
        scan_elf(&mut file, rel, own, listings, leaks_ok, report);
    } else if n == 4 {
        // Not an ELF (magic already consumed) — text scan from here on.
        scan_text_from(&mut file, magic.to_vec(), rel, leaks_ok, report);
    } else {
        // Empty or tiny file — nothing to scan.
    }
    Ok(())
}

/// Read up to `buf.len()` bytes, tolerating short reads at EOF.
fn read_up_to(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

// ── ELF structured scan ──

fn scan_elf(
    file: &mut std::fs::File,
    rel: &str,
    own: &BTreeSet<String>,
    listings: &PayloadListings,
    leaks_ok: &[String],
    report: &mut ScanReport,
) {
    let Some(dynamic) = parse_elf_dynamic(file) else {
        return; // static binary or malformed — nothing checkable, never fail on parser limits
    };
    // Rewind: the text fallback never runs for ELFs, but the interpreter
    // read below seeks; parse_elf_dynamic owns its own cursor.
    for soname in &dynamic.needed {
        if let Some(entry) = resolve_needed(soname, own, listings) {
            record(
                Leak {
                    file: rel.to_string(),
                    reference: soname.clone(),
                    kind: LeakKind::Needed { entry },
                },
                leaks_ok,
                report,
            );
        }
    }
    for entry in &dynamic.runpath_entries {
        if entry.contains(SANDBOX_BUILD_PREFIX) {
            record(
                Leak {
                    file: rel.to_string(),
                    reference: entry.clone(),
                    kind: LeakKind::Runpath,
                },
                leaks_ok,
                report,
            );
        }
    }
    if let Some(interp) = &dynamic.interp {
        if interp.contains(SANDBOX_BUILD_PREFIX) {
            record(
                Leak {
                    file: rel.to_string(),
                    reference: interp.clone(),
                    kind: LeakKind::Interpreter,
                },
                leaks_ok,
                report,
            );
        }
    }
}

/// Classify a DT_NEEDED soname. `Err(entry)` names the build-only payload
/// it resolves into; `Ok(())` means own-stage, runtime-closure, or system
/// (nothing build-only) — all acceptable.
fn resolve_needed(
    soname: &str,
    own: &BTreeSet<String>,
    listings: &PayloadListings,
) -> Option<String> {
    if own.contains(soname) {
        return None;
    }
    let mut in_runtime = false;
    let mut build_only: Option<String> = None;
    for (pkg, files) in &listings.payloads {
        if files.contains(soname) {
            if listings.runtime.contains(pkg) {
                in_runtime = true;
            } else {
                build_only = Some(pkg.clone());
            }
        }
    }
    // Runtime presence wins: a payload shipped by a `requires` entry is
    // exactly where a legitimate dependency should resolve.
    if in_runtime {
        return None;
    }
    build_only
}

/// Silencing gate: exact match on [`Leak::reference`] against `leaks_ok`.
fn record(leak: Leak, leaks_ok: &[String], report: &mut ScanReport) {
    if leaks_ok.iter().any(|ok| ok == &leak.reference) {
        report.silenced.push(leak);
    } else {
        report.leaks.push(leak);
    }
}

// ── Text (Nix-style reference) scan ──

const CHUNK: usize = 64 * 1024;

/// Stream-scan a non-ELF file for the build-prefix marker. Files carrying a
/// NUL byte are binary and skipped (per Decision 3 the text scan covers
/// scripts and configs, not binaries). Chunked with overlap so a marker
/// spanning a read boundary cannot hide.
fn scan_text_from(
    file: &mut std::fs::File,
    mut carry: Vec<u8>,
    rel: &str,
    leaks_ok: &[String],
    report: &mut ScanReport,
) {
    let marker = SANDBOX_BUILD_PREFIX.as_bytes();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let n = match read_up_to(file, &mut chunk) {
            Ok(n) => n,
            Err(_) => return, // unreadable tail — not a scan failure
        };
        if n == 0 {
            return;
        }
        let window: Vec<u8> = carry.iter().chain(&chunk[..n]).copied().collect();
        if window.contains(&0u8) {
            return; // binary — skipped by policy
        }
        if contains_slice(&window, marker) {
            record(
                Leak {
                    file: rel.to_string(),
                    reference: SANDBOX_BUILD_PREFIX.to_string(),
                    kind: LeakKind::Text,
                },
                leaks_ok,
                report,
            );
            return;
        }
        // Carry the tail so a split marker is still seen next round.
        let keep = marker.len().saturating_sub(1);
        carry = if n >= keep {
            chunk[n - keep..n].to_vec()
        } else {
            carry.extend_from_slice(&chunk[..n]);
            carry.split_off(carry.len() - keep.min(carry.len()))
        };
        if n < CHUNK {
            return; // EOF
        }
    }
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Minimal ELF dynamic-section reader ──

/// The dynamic info the scan checks, extracted from program headers only
/// (robust for stripped section-less binaries). `None` = nothing checkable.
#[derive(Debug, Default)]
struct DynamicInfo {
    needed: Vec<String>,
    /// RUNPATH + RPATH entries, colon-split (ld.so search-list semantics).
    runpath_entries: Vec<String>,
    interp: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Elf32,
    Elf64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Le,
    Be,
}

// Dynamic tags the scan consumes.
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

// Program header types.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

/// Sanity caps so a corrupt header can never drive a huge allocation.
const MAX_PHNUM: usize = 4096;
const MAX_SEGMENT: usize = 8 * 1024 * 1024;

fn parse_elf_dynamic(file: &mut std::fs::File) -> Option<DynamicInfo> {
    // Read the fixed-size ELF header (64 bytes covers both class layouts).
    let mut header = [0u8; 64];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut header).ok()?;
    if &header[..4] != b"\x7fELF" {
        return None;
    }
    let class = match header[4] {
        1 => Class::Elf32,
        2 => Class::Elf64,
        _ => return None,
    };
    let order = match header[5] {
        1 => ByteOrder::Le,
        2 => ByteOrder::Be,
        _ => return None,
    };

    let (e_phoff, e_phentsize, e_phnum) = match class {
        Class::Elf64 => (
            read_u64(&header, 0x20, order)?,
            read_u16(&header, 0x36, order)? as usize,
            read_u16(&header, 0x38, order)? as usize,
        ),
        Class::Elf32 => (
            u64::from(read_u32(&header, 0x1C, order)?),
            read_u16(&header, 0x2A, order)? as usize,
            read_u16(&header, 0x2C, order)? as usize,
        ),
    };
    let min_entsize = match class {
        Class::Elf64 => 56,
        Class::Elf32 => 32,
    };
    if e_phnum == 0 || e_phnum > MAX_PHNUM || e_phentsize < min_entsize {
        return None;
    }

    // Read the whole program-header table once.
    file.seek(SeekFrom::Start(e_phoff)).ok()?;
    let table_len = e_phnum
        .checked_mul(e_phentsize)
        .filter(|len| *len <= MAX_SEGMENT)?;
    let mut table = vec![0u8; table_len];
    file.read_exact(&mut table).ok()?;

    // Segment widths (p_offset, p_vaddr, p_filesz field offsets).
    let (off_at, vaddr_at, filesz_at) = match class {
        // p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) …
        Class::Elf64 => (0x08usize, 0x10usize, 0x20usize),
        // p_type(4) p_offset(4) p_vaddr(4) p_paddr(4) p_filesz(4) …
        Class::Elf32 => (0x04usize, 0x08usize, 0x10usize),
    };

    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (offset, vaddr, filesz)
    let mut dynamic: Option<(u64, u64)> = None; // (offset, filesz)
    let mut interp: Option<String> = None;
    for i in 0..e_phnum {
        let base = i * e_phentsize;
        let p_type = match class {
            Class::Elf64 => u64::from(read_u32(&table, base, order)?),
            Class::Elf32 => u64::from(read_u32(&table, base, order)?),
        };
        let p_offset = read_width(&table, base + off_at, class, order)?;
        let p_vaddr = read_width(&table, base + vaddr_at, class, order)?;
        let p_filesz = read_width(&table, base + filesz_at, class, order)?;
        if p_filesz > MAX_SEGMENT as u64 {
            continue;
        }
        match p_type as u32 {
            PT_LOAD => loads.push((p_offset, p_vaddr, p_filesz)),
            PT_DYNAMIC => dynamic = Some((p_offset, p_filesz)),
            PT_INTERP => {
                let bytes = read_at(file, p_offset, p_filesz.min(4096) as usize)?;
                interp = c_string(&bytes).map(str::to_string);
            }
            _ => {}
        }
    }

    let Some((dyn_off, dyn_len)) = dynamic else {
        return Some(DynamicInfo {
            interp,
            ..DynamicInfo::default()
        }); // static: nothing dynamic
    };
    let bytes = read_at(file, dyn_off, dyn_len as usize)?;
    let ent = match class {
        Class::Elf64 => 16usize,
        Class::Elf32 => 8usize,
    };

    let mut needed_offsets: Vec<u64> = Vec::new();
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: u64 = 0;
    let mut runpath_offsets: Vec<u64> = Vec::new();
    let mut i = 0;
    while i + ent <= bytes.len() {
        let tag = read_width(&bytes, i, class, order)?;
        if tag == DT_NULL {
            break;
        }
        let val = read_width(&bytes, i + ent / 2, class, order)?;
        match tag {
            DT_NEEDED => needed_offsets.push(val),
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_STRSZ => strsz = val,
            DT_RPATH | DT_RUNPATH => runpath_offsets.push(val),
            _ => {}
        }
        i += ent;
    }

    // Map the string-table virtual address to a file offset via PT_LOAD.
    let strtab_off = strtab_vaddr.and_then(|vaddr| vaddr_to_offset(vaddr, &loads))?;
    if strsz == 0 || strsz > MAX_SEGMENT as u64 {
        return None;
    }
    let strtab = read_at(file, strtab_off, strsz as usize)?;

    let str_at = |off: u64| -> Option<String> {
        let start = usize::try_from(off).ok()?;
        c_string(strtab.get(start..)?).map(str::to_string)
    };

    let needed = needed_offsets
        .iter()
        .filter_map(|off| str_at(*off))
        .collect();
    let runpath_entries: Vec<String> = runpath_offsets
        .iter()
        .filter_map(|off| str_at(*off))
        .flat_map(|list| {
            list.split(':')
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();

    Some(DynamicInfo {
        needed,
        runpath_entries,
        interp,
    })
}

/// Map a virtual address to a file offset through the PT_LOAD segments.
fn vaddr_to_offset(vaddr: u64, loads: &[(u64, u64, u64)]) -> Option<u64> {
    loads
        .iter()
        .find(|(_, pvaddr, pfilesz)| vaddr >= *pvaddr && vaddr < pvaddr.saturating_add(*pfilesz))
        .map(|(poffset, pvaddr, _)| poffset + (vaddr - pvaddr))
}

/// NUL-terminated string from the front of `bytes`.
fn c_string(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).ok()
}

fn read_width(b: &[u8], off: usize, class: Class, order: ByteOrder) -> Option<u64> {
    match class {
        Class::Elf64 => read_u64(b, off, order),
        Class::Elf32 => read_u32(b, off, order).map(u64::from),
    }
}

fn read_u16(b: &[u8], off: usize, order: ByteOrder) -> Option<u16> {
    let raw = b.get(off..off + 2)?;
    Some(match order {
        ByteOrder::Le => u16::from_le_bytes(raw.try_into().ok()?),
        ByteOrder::Be => u16::from_be_bytes(raw.try_into().ok()?),
    })
}

fn read_u32(b: &[u8], off: usize, order: ByteOrder) -> Option<u32> {
    let raw = b.get(off..off + 4)?;
    Some(match order {
        ByteOrder::Le => u32::from_le_bytes(raw.try_into().ok()?),
        ByteOrder::Be => u32::from_be_bytes(raw.try_into().ok()?),
    })
}

fn read_u64(b: &[u8], off: usize, order: ByteOrder) -> Option<u64> {
    let raw = b.get(off..off + 8)?;
    Some(match order {
        ByteOrder::Le => u64::from_le_bytes(raw.try_into().ok()?),
        ByteOrder::Be => u64::from_be_bytes(raw.try_into().ok()?),
    })
}

fn read_at(file: &mut std::fs::File, offset: u64, len: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn stage_file(stage: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = stage.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        p
    }

    // ── Synthetic ELF band ──

    /// A hand-built 64-bit little-endian ELF with one PT_LOAD covering the
    /// whole file (identity file→vaddr mapping), one PT_DYNAMIC carrying
    /// DT_STRTAB/DT_STRSZ/DT_NEEDED/DT_RUNPATH, and an optional PT_INTERP.
    /// Used to exercise the parser + resolution without a compiler.
    fn elf64_fixture(needed: &[&str], runpath: Option<&str>, interp: Option<&str>) -> Vec<u8> {
        use std::io::Write as _;

        let ehdr = 64u64;
        let phnum = 2 + interp.is_some() as u64; // LOAD + DYNAMIC (+ INTERP)
        let phentsize = 56u64;
        let phoff = ehdr;

        // String table content.
        let mut strtab: Vec<u8> = vec![0u8]; // index 0 = ""
        let mut needed_offsets = Vec::new();
        for s in needed {
            needed_offsets.push(strtab.len() as u64);
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
        }
        let mut runpath_offset = None;
        if let Some(rp) = runpath {
            runpath_offset = Some(strtab.len() as u64);
            strtab.extend_from_slice(rp.as_bytes());
            strtab.push(0);
        }
        let strsz = strtab.len() as u64;

        // Interp string sits in its own PT_INTERP segment (separate bytes).
        let interp_seg = interp.map(|s| {
            let mut v = s.as_bytes().to_vec();
            v.push(0);
            v
        });

        // Dynamic entries (count them first so the string table offset is
        // exact: right after the dynamic table).
        let dyn_entries = 2 + needed.len() + runpath_offset.is_some() as usize + 1; // STRTAB, STRSZ, NEEDED…, [RUNPATH], NULL
        let dyn_len = (dyn_entries * 16) as u64;
        let dyn_off = phoff + phnum * phentsize;
        let interp_off = dyn_off + dyn_len;

        let mut dyn_bytes = Vec::new();
        let mut push = |tag: u64, val: u64| {
            dyn_bytes.write_all(&tag.to_le_bytes()).unwrap();
            dyn_bytes.write_all(&val.to_le_bytes()).unwrap();
        };
        // The string table goes after the (optional) interp segment.
        let strtab_off = interp_off + interp_seg.as_ref().map(|s| s.len() as u64).unwrap_or(0);
        push(DT_STRTAB, strtab_off);
        push(DT_STRSZ, strsz);
        for off in &needed_offsets {
            push(DT_NEEDED, *off);
        }
        if let Some(off) = runpath_offset {
            push(DT_RUNPATH, off);
        }
        push(DT_NULL, 0);
        debug_assert_eq!(dyn_bytes.len() as u64, dyn_len);

        let total = strtab_off + strsz;
        let mut out = vec![0u8; total as usize];

        // e_ident.
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little-endian
        out[6] = 1; // EV_CURRENT
                    // e_phoff (0x20), e_phentsize (0x36), e_phnum (0x38).
        out[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
        out[0x36..0x38].copy_from_slice(&(phentsize as u16).to_le_bytes());
        out[0x38..0x3A].copy_from_slice(&(phnum as u16).to_le_bytes());

        // PT_LOAD covering the whole file (identity mapping).
        let mut phdr = |base: u64,
                        p_type: u32,
                        p_offset: u64,
                        p_vaddr: u64,
                        p_filesz: u64,
                        p_align: u64,
                        flags: u32| {
            let b = base as usize;
            out[b..b + 4].copy_from_slice(&p_type.to_le_bytes());
            out[b + 4..b + 8].copy_from_slice(&flags.to_le_bytes());
            out[b + 8..b + 16].copy_from_slice(&p_offset.to_le_bytes());
            out[b + 16..b + 24].copy_from_slice(&p_vaddr.to_le_bytes());
            out[b + 24..b + 32].copy_from_slice(&(0u64).to_le_bytes()); // p_paddr
            out[b + 32..b + 40].copy_from_slice(&p_filesz.to_le_bytes());
            out[b + 40..b + 48].copy_from_slice(&p_filesz.to_le_bytes()); // p_memsz
            out[b + 48..b + 56].copy_from_slice(&p_align.to_le_bytes());
        };
        phdr(phoff, PT_LOAD, 0, 0, total, 0x1000, 5);
        phdr(phoff + 56, PT_DYNAMIC, dyn_off, dyn_off, dyn_len, 8, 4);
        if interp_seg.is_some() {
            let iseg = interp_seg.as_ref().unwrap();
            // INTERP segment placed right after the dynamic table.
            phdr(
                phoff + 112,
                PT_INTERP,
                interp_off,
                interp_off,
                iseg.len() as u64,
                1,
                4,
            );
            let start = interp_off as usize;
            out[start..start + iseg.len()].copy_from_slice(iseg);
        }

        // Dynamic bytes (placed right after phdrs).
        out[dyn_off as usize..(dyn_off + dyn_len) as usize].copy_from_slice(&dyn_bytes);
        // String table.
        out[strtab_off as usize..(strtab_off + strsz) as usize].copy_from_slice(&strtab);
        out
    }

    fn write_elf(dir: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        stage_file(dir, rel, bytes)
    }

    #[test]
    fn elf64_parser_extracts_needed_runpath_interp() {
        let bytes = elf64_fixture(
            &["libc.so.6", "libfoo.so.1"],
            Some("/shuttle-build-prefix/usr/lib"),
            Some("/lib64/ld-linux-x86-64.so.2"),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = write_elf(dir.path(), "bin/app", &bytes);
        let mut f = std::fs::File::open(&path).unwrap();
        let dyni = parse_elf_dynamic(&mut f).unwrap();
        assert_eq!(dyni.needed, vec!["libc.so.6", "libfoo.so.1"]);
        assert_eq!(dyni.runpath_entries, vec!["/shuttle-build-prefix/usr/lib"]);
        assert_eq!(dyni.interp.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
    }

    #[test]
    fn elf64_parser_no_interp_rpath_only() {
        let bytes = elf64_fixture(&["libm.so.6"], Some("/usr/lib"), None);
        let dir = tempfile::tempdir().unwrap();
        let path = write_elf(dir.path(), "bin/t", &bytes);
        let mut f = std::fs::File::open(&path).unwrap();
        let dyni = parse_elf_dynamic(&mut f).unwrap();
        assert_eq!(dyni.needed, vec!["libm.so.6"]);
        assert_eq!(dyni.runpath_entries, vec!["/usr/lib"]);
        assert_eq!(dyni.interp, None);
    }

    #[test]
    fn elf64_parser_rejects_non_elf_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_elf(dir.path(), "t", b"#!/bin/sh\n");
        let mut f = std::fs::File::open(&path).unwrap();
        assert!(parse_elf_dynamic(&mut f).is_none());
    }

    // ── Resolution band ──

    fn listings(payloads: &[(&str, &[&str])], runtime: &[&str]) -> PayloadListings {
        let mut l = PayloadListings::default();
        for (pkg, files) in payloads {
            let set = files.iter().map(|f| f.to_string()).collect();
            l.payloads.insert(pkg.to_string(), set);
        }
        l.runtime = runtime.iter().map(|s| s.to_string()).collect();
        l
    }

    #[test]
    fn needed_resolves_own_stage_library() {
        let mut own = BTreeSet::new();
        own.insert("libapp.so.1".to_string());
        let l = listings(&[("buildtool", &["libbuild.so.1"])], &[]);
        assert_eq!(resolve_needed("libapp.so.1", &own, &l), None);
    }

    #[test]
    fn needed_resolves_runtime_closure_library() {
        let mut own = BTreeSet::new();
        let l = listings(
            &[
                ("ncurses", &["libncurses.so.6"]),
                ("mktool", &["libmkt.so.0"]),
            ],
            &["ncurses"],
        );
        assert_eq!(resolve_needed("libncurses.so.6", &own, &l), None);
    }

    #[test]
    fn needed_resolves_system_library() {
        let mut own = BTreeSet::new();
        let l = listings(&[("ncurses", &["libncurses.so.6"])], &["ncurses"]);
        assert_eq!(resolve_needed("libc.so.6", &own, &l), None);
    }

    #[test]
    fn needed_flags_build_only_payload() {
        let mut own = BTreeSet::new();
        let l = listings(
            &[
                ("ncurses", &["libncurses.so.6"]),
                ("devlib", &["libdev.so.1"]),
            ],
            &["ncurses"],
        );
        assert_eq!(
            resolve_needed("libdev.so.1", &own, &l),
            Some("devlib".to_string())
        );
    }

    #[test]
    fn runtime_presence_wins_over_build_only() {
        // A lib present in both a runtime and a build-only payload resolves.
        let mut own = BTreeSet::new();
        let l = listings(
            &[
                ("ncurses", &["libncurses.so.6"]),
                ("ncurses-dev", &["libncurses.so.6"]),
            ],
            &["ncurses"],
        );
        assert_eq!(resolve_needed("libncurses.so.6", &own, &l), None);
    }

    #[test]
    fn record_silences_exact_reference() {
        let leak = Leak {
            file: "bin/app".into(),
            reference: "libdev.so.1".into(),
            kind: LeakKind::Needed {
                entry: "devlib".into(),
            },
        };
        let mut report = ScanReport::default();
        record(leak.clone(), &["libdev.so.1".to_string()], &mut report);
        assert_eq!(report.silenced.len(), 1);
        assert!(report.leaks.is_empty());

        let mut report2 = ScanReport::default();
        record(leak, &[], &mut report2);
        assert_eq!(report2.leaks.len(), 1);
        assert!(report2.silenced.is_empty());
    }

    // ── Text / stage scan band ──

    #[test]
    fn stage_scan_finds_prefix_in_text_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "bin/run",
            b"#!/bin/sh\nexec /shuttle-build-prefix/usr/bin/x\n",
        );
        stage_file(dir.path(), "lib/x.so", b"\x7fELF\x02\x01\x01rest"); // looks like ELF, no phdrs → parser None
        stage_file(dir.path(), "data.bin", b"\x00\x01\x02");
        let l = PayloadListings::default();
        let report = scan_stage(dir.path(), &l, &[]).unwrap();
        assert_eq!(report.files, 3);
        assert_eq!(report.elfs, 1);
        assert_eq!(report.leaks.len(), 1);
        assert_eq!(report.leaks[0].file, "bin/run");
        assert_eq!(report.leaks[0].kind, LeakKind::Text);
    }

    #[test]
    fn stage_scan_silences_with_exact_reference() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "bin/run",
            b"#!/bin/sh\n/shuttle-build-prefix/usr/bin/x\n",
        );
        let l = PayloadListings::default();
        let report = scan_stage(dir.path(), &l, &["/shuttle-build-prefix".to_string()]).unwrap();
        assert_eq!(report.leaks.len(), 0);
        assert_eq!(report.silenced.len(), 1);
    }

    #[test]
    fn silence_requires_exact_match_not_contains() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(
            dir.path(),
            "bin/run",
            b"#!/bin/sh\n/shuttle-build-prefix/usr/bin/x\n",
        );
        let l = PayloadListings::default();
        // A substring entry does NOT silence the full-prefix marker.
        let report = scan_stage(dir.path(), &l, &["/shuttle-build-prefix/us".to_string()]).unwrap();
        assert_eq!(report.leaks.len(), 1);
        assert!(report.silenced.is_empty());
    }

    #[test]
    fn binary_non_elf_skipped() {
        let dir = tempfile::tempdir().unwrap();
        stage_file(dir.path(), "img.png", b"\x89PNG\r\n\x1a\n\x00blah");
        let l = PayloadListings::default();
        let report = scan_stage(dir.path(), &l, &[]).unwrap();
        assert_eq!(report.leaks.len(), 0);
    }

    #[test]
    fn enforce_emits_success_line_on_clean_scan() {
        let report = ScanReport {
            elfs: 2,
            files: 5,
            ..ScanReport::default()
        };
        assert!(report.enforce().is_ok());
        // Silence path logs + returns Ok.
        let report = ScanReport {
            silenced: vec![Leak {
                file: "bin/app".into(),
                reference: "libdev.so.1".into(),
                kind: LeakKind::Needed {
                    entry: "devlib".into(),
                },
            }],
            ..ScanReport::default()
        };
        assert!(report.enforce().is_ok());
    }

    #[test]
    fn enforce_fails_on_leak() {
        let report = ScanReport {
            elfs: 1,
            files: 1,
            leaks: vec![Leak {
                file: "bin/app".into(),
                reference: "libdev.so.1".into(),
                kind: LeakKind::Needed {
                    entry: "devlib".into(),
                },
            }],
            ..ScanReport::default()
        };
        let err = report.enforce().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("bin/app"), "{msg}");
        assert!(msg.contains("libdev.so.1"), "{msg}");
        assert!(msg.contains("devlib"), "{msg}");
    }
}
