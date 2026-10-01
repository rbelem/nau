//! Generic `PATH` search mechanism (issue #326 PR 3 down-move).
//!
//! Splitting the process `PATH` into entries and resolving an executable
//! by name against them is host mechanism, not domain logic — every
//! domain (build sandbox, image toolchain probes, the doctor) resolves
//! tools the same way, so the seam lives in the non-domain leaf
//! ([`crate::tools`] provisioning sits beside it).

use std::path::PathBuf;

/// The process PATH split into absolute directory entries. Relative and
/// empty entries are dropped — the sandbox only ever mirrors absolute host
/// paths.
pub fn path_entries() -> Vec<PathBuf> {
    std::env::var("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|e| e.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// First existing, executable match for `name` in `entries` (PATH order —
/// the same resolution `sh` performs).
pub fn resolve_in_path(name: &str, entries: &[PathBuf]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    entries
        .iter()
        .map(|entry| entry.join(name))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_exec(dir: &std::path::Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn resolve_in_path_follows_path_order_and_checks_exec() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_exec(first.path(), "tool-probe");
        let entries = vec![second.path().to_path_buf(), first.path().to_path_buf()];
        assert_eq!(
            resolve_in_path("tool-probe", &entries),
            Some(first.path().join("tool-probe"))
        );
        // A non-executable file is not resolved.
        std::fs::write(first.path().join("plain"), "").unwrap();
        assert_eq!(resolve_in_path("plain", &entries), None);
        assert_eq!(resolve_in_path("absent", &entries), None);
    }
}
