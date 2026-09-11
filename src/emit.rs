//! Emission seam — writing systemd units and staged data files into the
//! staged image rootfs (issue #67).
//!
//! Every producer that materializes a boot-time artifact into the image
//! — the app-runtime emitter here, and the #59 state partition, #60
//! activation, #62 sysupdate and #63 bless-boot work — writes through
//! these functions, so "create the dir, write the text, enable the unit"
//! has one implementation and one error shape instead of four divergent
//! copies.
//!
//! These are pure filesystem writes over `root: &Path`: no global state,
//! no process spawning. Domain vocabulary: *emitted* units written at
//! build time into the staged rootfs — data, not a shipped daemon
//! (ADR-0011 §5).

use std::path::Path;

use miette::{IntoDiagnostic, WrapErr};

/// Write `contents` to `root/rel_path`, creating any missing parent
/// directories. The bytes are written verbatim — no newline
/// normalization, so a unit body is the exact value its renderer
/// produced.
fn write_file(root: &Path, rel_path: &Path, contents: &str, kind: &str) -> miette::Result<()> {
    let dest = root.join(rel_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&dest, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("{kind} {}", dest.display()))
}

/// Write a systemd unit into the staged rootfs.
///
/// `rel_path` is root-relative (e.g.
/// `usr/lib/systemd/system/foo.service`). Missing parent directories are
/// created.
pub fn write_unit(root: &Path, rel_path: &Path, text: &str) -> miette::Result<()> {
    write_file(root, rel_path, text, "writing unit")
}

/// Enable a unit by symlinking it into
/// `etc/systemd/system/<target>.wants/<unit_name>`.
///
/// The symlink is relative (`../<unit_name>`) so the staged rootfs stays
/// relocatable, matching the in-tree form `systemctl enable` produces.
pub fn enable_unit(root: &Path, target: &str, unit_name: &str) -> miette::Result<()> {
    link_unit_into(root, target, "wants", unit_name)
}

/// Pull a unit into a target with a strong dependency by symlinking it into
/// `etc/systemd/system/<target>.requires/<unit_name>`.
///
/// This is the on-disk form of systemd's `RequiredBy=<target>` (equivalently
/// `Requires=` from the target): a failing unit blocks the target instead of
/// merely being wanted by it. Same relative-symlink shape as
/// [`enable_unit`], which is the `.wants/` case.
pub fn require_unit(root: &Path, target: &str, unit_name: &str) -> miette::Result<()> {
    link_unit_into(root, target, "requires", unit_name)
}

/// Shared body of [`enable_unit`] and [`require_unit`]: symlink `unit_name`
/// into `etc/systemd/system/<target>.<kind>/`, relative so the staged rootfs
/// stays relocatable (matching `systemctl enable`/`require`).
fn link_unit_into(root: &Path, target: &str, kind: &str, unit_name: &str) -> miette::Result<()> {
    let link = root
        .join("etc/systemd/system")
        .join(format!("{target}.{kind}"))
        .join(unit_name);
    let parent = link.parent().expect("enablement link has a parent");
    std::fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("creating {}", parent.display()))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(format!("../{unit_name}"), &link)
        .into_diagnostic()
        .wrap_err_with(|| format!("linking {}", link.display()))?;
    Ok(())
}

/// Write a non-unit staged artifact (`fstab`, `tmpfiles.d`, `modeenv`,
/// …) into the staged rootfs, sharing [`write_unit`]'s parent-directory
/// creation and error handling.
pub fn write_staged_file(root: &Path, rel_path: &Path, contents: &str) -> miette::Result<()> {
    write_file(root, rel_path, contents, "writing staged file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A representative emitted unit body, pinned byte-for-byte. Mirrors
    /// the `render_unit` golden test in `units.rs`.
    const GOLDEN_UNIT: &str = "\
[Unit]
Description=shuttle: demo (srv)

[Service]
Type=exec
ExecStart=/usr/bin/demo-srv
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
";

    #[test]
    fn write_unit_creates_nested_parents_and_writes_exact_text() {
        let root = tempfile::tempdir().unwrap();
        let rel = Path::new("usr/lib/systemd/system/demo-srv.service");
        write_unit(root.path(), rel, GOLDEN_UNIT).unwrap();

        let dest = root.path().join(rel);
        assert!(dest.is_file(), "unit written at {}", dest.display());
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap(),
            GOLDEN_UNIT,
            "write_unit must not transform the body"
        );
        assert!(
            root.path().join("usr/lib/systemd/system").is_dir(),
            "nested parent directories created"
        );
    }

    #[test]
    fn enable_unit_creates_correct_relative_symlink() {
        let root = tempfile::tempdir().unwrap();
        enable_unit(root.path(), "multi-user.target", "demo-srv.service").unwrap();

        let link = root
            .path()
            .join("etc/systemd/system/multi-user.target.wants/demo-srv.service");
        let meta = std::fs::symlink_metadata(&link)
            .unwrap_or_else(|e| panic!("enablement link missing at {}: {e}", link.display()));
        assert!(meta.file_type().is_symlink(), "enablement is a symlink");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from("../demo-srv.service"),
            "relative symlink target"
        );
    }

    #[test]
    fn require_unit_creates_correct_relative_symlink() {
        // The `.requires/` form of enablement (systemd `RequiredBy=`): a
        // failing unit blocks the target instead of merely being wanted.
        let root = tempfile::tempdir().unwrap();
        require_unit(
            root.path(),
            "boot-complete.target",
            "shuttle-boot-health.service",
        )
        .unwrap();

        let link = root
            .path()
            .join("etc/systemd/system/boot-complete.target.requires/shuttle-boot-health.service");
        let meta = std::fs::symlink_metadata(&link)
            .unwrap_or_else(|e| panic!("requires link missing at {}: {e}", link.display()));
        assert!(meta.file_type().is_symlink(), "requirement is a symlink");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            PathBuf::from("../shuttle-boot-health.service"),
            "relative symlink target"
        );
        assert!(
            !root
                .path()
                .join("etc/systemd/system/boot-complete.target.wants")
                .exists(),
            "require_unit writes requires, not wants"
        );
    }

    #[test]
    fn write_staged_file_writes_exact_contents() {
        let root = tempfile::tempdir().unwrap();
        let rel = Path::new("etc/fstab");
        let fstab = "UUID=abcd-ef01 / ext4 defaults 0 1\n";
        write_staged_file(root.path(), rel, fstab).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.path().join(rel)).unwrap(),
            fstab
        );
    }
}
