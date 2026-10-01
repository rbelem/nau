//! In-process source-archive extraction (issue #170 seam).
//!
//! Extracted from the chart's pkg_source (pre-PR-2 down-move, ADR-0053):
//! pure archive I/O + tool resolution, no chart vocabulary.

use std::path::Path;

// ── In-process tarball extraction (issue #170 seam; moved from root snap.rs, #326) ──

/// Find the single top-level directory in a path (the source root
/// after extracting a tarball). If there's more than one entry or
/// no entry, returns None.
/// Extract one source archive into `dest` (issue #170).
///
/// Tarballs are unpacked IN-PROCESS with the `tar` crate (the same seam
/// `dep_fetch` uses for npm closures): gzip via `flate2`, xz via `xz2`,
/// plain tar raw. Extraction must never depend on whatever `tar` binary
/// the caller's PATH carries — pod builds run inside user environments
/// (`nau run --pod …`) whose PATH may shadow GNU tar with an
/// implementation that cannot read the archives real recipes pin
/// (observed: busybox tar rejects the rust dist tarball's 128 MiB
/// LZMA2 dictionary with an instant "corrupted data / short read",
/// while the SHA-256 of the same bytes verified clean).
///
/// Permissions, symlinks, and hardlinks are preserved; `unpack` refuses
/// path-escaping entries, so this is also the safer extractor. Archives
/// in formats the crates do not cover (bz2, zst, …) fall back to the
/// external `tar` spawn — the pre-#170 behavior for those extensions.
pub fn extract_tarball(archive: &Path, dest: &Path) -> miette::Result<()> {
    let filename = archive.to_string_lossy();
    let result = if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        let file = std::fs::File::open(archive)
            .map_err(|e| miette::miette!("opening {}: {e}", archive.display()))?;
        unpack_tar(flate2::read::GzDecoder::new(file), dest)
    } else if filename.ends_with(".tar.xz") {
        let file = std::fs::File::open(archive)
            .map_err(|e| miette::miette!("opening {}: {e}", archive.display()))?;
        unpack_tar(xz2::read::XzDecoder::new(file), dest)
    } else if filename.ends_with(".tar") {
        let file = std::fs::File::open(archive)
            .map_err(|e| miette::miette!("opening {}: {e}", archive.display()))?;
        unpack_tar(file, dest)
    } else {
        extract_tarball_external(archive, dest)
    };
    result.map_err(|e| miette::miette!("extracting {}: {e}", archive.display()))
}

/// Decode `reader` as a tar archive and unpack it into `dest`.
fn unpack_tar<R: std::io::Read>(reader: R, dest: &Path) -> std::io::Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.unpack(dest)
}

/// The external-`tar` fallback for formats the in-process crates do not
/// cover. Same spawn the pre-#170 code used for every archive.
fn extract_tarball_external(archive: &Path, dest: &Path) -> std::io::Result<()> {
    let tar = tar_tool().map_err(|e| std::io::Error::other(e.to_string()))?;
    let status = std::process::Command::new(&tar)
        .arg("xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("tar exited with {}", status)))
    }
}

/// The `tar` binary through the tools module: the external fallback only
/// fires for formats the in-process crates do not cover, so plain
/// resolution (PATH-first with the provisioned fallback) matches the
/// root snap.rs `floor_tool` contract this code was moved from.
fn tar_tool() -> miette::Result<std::path::PathBuf> {
    let resolved = crate::tools::resolve(crate::tools::ToolName::Tar)
        .map_err(|e| miette::miette!("resolve {Tar}: {e}", Tar = crate::tools::ToolName::Tar))?;
    Ok(match resolved {
        crate::tools::ResolvedTool::Provisioned { path, .. }
        | crate::tools::ResolvedTool::Path { path, .. } => path,
    })
}
