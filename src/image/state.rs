//! Persistent state partition role + the mutable-`/var` split (ADR-0023).
//!
//! ADR-0023 makes "what survives an A/B flip" answerable from the
//! partition table: the persistent state — the shuttle store
//! (`/var/lib/shuttle`) and extension links (`/var/lib/extensions`) —
//! lives on a declared `role = "state"` partition mounted at `/var/lib`,
//! while `/var` itself is volatile (tmpfs + `systemd-tmpfiles`).
//!
//! The role is the runtime concept, not a per-base spelling:
//! - native images declare `role = "state"` directly;
//! - Ubuntu Core images keep their existing UC `system-data` role, which
//!   describes the same partition (the `ubuntu-data` writable already
//!   holds `/var` on UC).
//!
//! # Fail-closed trigger
//!
//! Like `disk.ab`, the split is opt-in: an image that declares no state
//! role — and declares no `update_source` — is byte-comparable to before
//! this change. The split activates when the image either
//!
//! 1. declares `role = "state"` (or is a UC image declaring
//!    `system-data`), or
//! 2. declares `update_source` — the runtime store is the update surface
//!    (ADR-0011 step (d), ADR-0012 §2), so an update-signing image with no
//!    state partition would lose every installed package on the first
//!    A/B flip.
//!
//! Once active, a missing state partition is a build error, never a
//! silent boot failure: the state paths (`/var/lib/shuttle`,
//! `/var/lib/extensions`) have nowhere to live.

use std::path::Path;

use super::*;

/// Gadget role name for the persistent state partition on native images
/// (ADR-0023). UC bases keep their existing `system-data` role; both map
/// to the same runtime concept.
pub(crate) const ROLE_STATE: &str = "state";

/// fstab path inside the staged rootfs.
pub(crate) const FSTAB_PATH: &str = "etc/fstab";

/// tmpfiles.d file that creates the state directories at boot.
pub(crate) const STATE_TMPFILES_PATH: &str = "usr/lib/tmpfiles.d/shuttle-state.conf";

/// tmpfiles.d file that materializes the volatile `/var` skeleton.
pub(crate) const VAR_TMPFILES_PATH: &str = "usr/lib/tmpfiles.d/shuttle-var.conf";

/// Mount point of the persistent state partition (ADR-0023 §2).
pub(crate) const STATE_MOUNT: &str = "/var/lib";

/// Mount point of the volatile tmpfs (the `/var` skeleton top).
pub(crate) const VAR_MOUNT: &str = "/var";

/// The always-present state directories, created at boot by tmpfiles —
/// the shuttle store ([`crate::runtime::DEFAULT_STATE_DIR`]) and the
/// sysext link directory ([`crate::runtime::DEFAULT_EXTENSIONS_LINK_DIR`]).
pub(crate) fn state_dirs() -> [&'static str; 2] {
    [
        crate::runtime::DEFAULT_STATE_DIR,
        crate::runtime::DEFAULT_EXTENSIONS_LINK_DIR,
    ]
}

/// The volatile `/var` skeleton tmpfs subdirectories (ADR-0023 §2):
/// `run`, `tmp`, `cache`, `log` — none of it survives a flip.
pub(crate) fn volatile_var_dirs() -> [&'static str; 4] {
    ["/var/run", "/var/tmp", "/var/cache", "/var/log"]
}

/// True when `role` names the native state role.
pub(crate) fn is_state_role(role: &str) -> bool {
    role == ROLE_STATE
}

/// True when a partition is the one the state role selects: the native
/// `role = "state"`, or the UC `system-data` role (which describes the
/// same persistent partition). Everything else — including the
/// root/ESP/swap — is not state.
pub(crate) fn is_state_partition(part: &Partition) -> bool {
    is_state_role(&part.role) || partition_uc_role(part) == Some(crate::uc::ROLE_DATA)
}

/// Does the image ask for the state partition + `/var` split?
///
/// True when a partition is role-marked state OR the image declares an
/// update source (the runtime store update surface). A plain native image
/// with neither keeps its historical layout byte-for-byte (ADR-0023).
pub(crate) fn needs_state_split(image: &ImageDeclaration, layout: &DiskLayout) -> bool {
    layout.partitions.iter().any(is_state_partition) || image.update_source.is_some()
}

/// Does the image emit the systemd-sysupdate transfer definitions **and**
/// their trigger units?
///
/// Both require an A/B disk and a declared `update_source`: a single-slot
/// layout has no slot to flip to, and a local-source transfer would carry
/// no verification — unverifiable update config is never emitted or
/// triggered silently (ADR-0011 step (d), ADR-0024 §2). One predicate
/// drives the transfer files and the timer/service pair so they cannot
/// drift apart.
pub(crate) fn emits_sysupdate(image: &ImageDeclaration, layout: &DiskLayout) -> bool {
    layout.ab && image.update_source.is_some()
}

/// The `/var` split, resolved against the effective partition table
/// before anything is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateSplit {
    /// GPT PARTLABEL of the state partition (`ubuntu-data` on UC, the
    /// declared name on native images).
    pub(crate) partlabel: String,
    /// Label of the root subvolume the split's tmpfs shadows: non-empty
    /// when a declared partition mounts a path under `/var`, so the
    /// `tmpfs /var` mount is scoped (`x-systemd.requires-mounts-for=`)
    /// to avoid shadowing it.
    pub(crate) var_submount_partlabel: String,
}

/// The declared partition that mounts a path under `/var` — the
/// `tmpfs /var` mount must require it, because systemd orders only a
/// parent mount after its declared children (ordering between siblings
/// is otherwise undefined, and the state partition itself mounts at
/// `/var/lib`).
fn var_submount(layout: &DiskLayout) -> Option<&Partition> {
    layout
        .partitions
        .iter()
        .find(|p| p.mount.starts_with("/var/") && p.mount != STATE_MOUNT)
}

/// Resolve the state split for an image whose `needs_state_split` is
/// true. Fails closed when the state partition is absent — the state
/// paths would otherwise be swallowed by the read-only verity root and
/// disappear on the first A/B flip.
pub(crate) fn resolve_state_split(
    image: &ImageDeclaration,
    layout: &DiskLayout,
) -> miette::Result<StateSplit> {
    let Some(part) = layout.partitions.iter().find(|p| is_state_partition(p)) else {
        let reason = if image.update_source.is_some() {
            "declares update_source (the runtime store is an update surface)"
        } else {
            "declares a non-UC \"state\" partition role"
        };
        return Err(miette::miette!(
            "image '{name}' {reason} but the disk layout declares no state partition — \
             the shuttle store ({state}) and extension links ({ext}) would live inside the \
             read-only verity root and be destroyed by the first A/B flip. Declare a \
             partition with role = \"state\" (sized once — partition layouts are hard to \
             change after deploy; ADR-0023)",
            name = image.name,
            state = crate::runtime::DEFAULT_STATE_DIR,
            ext = crate::runtime::DEFAULT_EXTENSIONS_LINK_DIR,
        ));
    };
    Ok(StateSplit {
        partlabel: part.name.clone(),
        var_submount_partlabel: var_submount(layout)
            .map(|p| p.name.clone())
            .unwrap_or_default(),
    })
}

/// fstab-option spelling of the "mount this after <partlabel>" dependency
/// systemd honors on fstab mounts (`x-systemd.requires-mounts-for=`).
pub(crate) fn requires_mounts_for_option(partlabel: &str) -> String {
    format!("x-systemd.requires-mounts-for=/dev/disk/by-partlabel/{partlabel}")
}

/// The state paragraph of `etc/fstab` — the persistent state mount plus
/// the volatile `/var` tmpfs — as individual lines, NO header.
///
/// This is the single renderer of the state lines; [`super::fstab_content`]
/// emits the one file-level header and appends these. Kept separate so the
/// declared-mount renderer can compose the file without a second header.
///
/// The persistent state partition mounts at `/var/lib`; `/var` itself is a
/// tmpfs so cache/log/tmp never grow the persistent surface (ADR-0023 §2).
/// Both carry `nofail` when declared `x-systemd.requires-mounts-for`, so a
/// bad state partition cannot wedge early boot in the emergency shell.
pub(crate) fn state_fstab_lines(split: &StateSplit) -> Vec<String> {
    let mut state_opts = String::from("defaults,nofail");
    if !split.var_submount_partlabel.is_empty() {
        state_opts.push(',');
        state_opts.push_str(&requires_mounts_for_option(&split.var_submount_partlabel));
    }
    vec![
        "# The persistent state partition (ADR-0023): survives A/B flips, never verity-hashed."
            .to_string(),
        format!(
            "PARTLABEL={} {} auto {}",
            split.partlabel, STATE_MOUNT, state_opts
        ),
        "# /var is volatile: the skeleton is tmpfs, scratch state is tmpfiles (ADR-0023 §2)."
            .to_string(),
        format!("tmpfs {VAR_MOUNT} tmpfs mode=0755,nosuid,nodev"),
    ]
}

/// `usr/lib/tmpfiles.d/shuttle-state.conf` — create the state directories
/// on the mounted state partition at boot, including the mount point
/// itself so the tmpfs/partition hierarchy is complete.
pub(crate) fn state_tmpfiles_content() -> String {
    let mut out = String::from("# Generated by shuttle — do not edit.\n");
    out.push_str(&format!("d {} 0755 root root -\n", STATE_MOUNT));
    for dir in state_dirs() {
        out.push_str(&format!("d {dir} 0755 root root -\n"));
    }
    out
}

/// `usr/lib/tmpfiles.d/shuttle-var.conf` — materialize the volatile `/var`
/// skeleton (`run`, `tmp`, `cache`, `log`) on the tmpfs at boot, plus
/// `extra` declared mount points that live under `/var` and are shadowed
/// by the tmpfs mount. The latter must be created at boot because a
/// build-time mkdir would be hidden by the tmpfs.
pub(crate) fn var_tmpfiles_content_with(extra: &[String]) -> String {
    let mut out = String::from("# Generated by shuttle — do not edit.\n");
    out.push_str(&format!("d {} 0755 root root -\n", VAR_MOUNT));
    for dir in volatile_var_dirs() {
        out.push_str(&format!("d {dir} 0755 root root -\n"));
    }
    for dir in extra {
        out.push_str(&format!("d {dir} 0755 root root -\n"));
    }
    out
}

// ── Boot-time generation activation (ADR-0023 §4, #60) ──

/// Unit filename of the boot-time activation oneshot.
pub(crate) const ACTIVATE_UNIT_NAME: &str = "shuttle-runtime-activate.service";

/// Unit path inside the staged rootfs (`usr/lib/systemd/system/`).
pub(crate) const ACTIVATE_UNIT_PATH: &str =
    "usr/lib/systemd/system/shuttle-runtime-activate.service";

/// ExecStart program for the activation oneshot.
///
/// The repo's on-device convention is a bare `shuttle` resolved from
/// PATH — the confined-app launcher emits `exec shuttle run` (see
/// [`crate::snap`] `emit_confined_launcher`), and no in-tree code ships
/// the binary at a fixed image path. systemd resolves a bare ExecStart
/// name through the fixed search path
/// (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), so
/// the assumption is: **the image ships the shuttle binary in one of
/// those directories** (e.g. `/usr/bin/shuttle`). If the binary lands
/// elsewhere the unit is inert — the exact trap ADR-0024 warns about —
/// so this constant is the single place to change when the image build
/// gains a definitive install path.
pub(crate) const ACTIVATE_EXEC: &str = "shuttle runtime activate";

/// Render the boot-time activation oneshot (ADR-0023 §4). It is
/// `Type=oneshot` with `RemainAfterExit=yes`, so the activation is a
/// single boot step systemd considers done once it exits. It is ordered
/// after the persistent state mount so the store is available when
/// activation runs, and enabled into `multi-user.target` via
/// [`crate::emit::enable_unit`].
pub(crate) fn activate_unit_content() -> String {
    format!(
        "# Generated by shuttle — do not edit.\n\
         [Unit]\n\
         Description=shuttle: activate the current runtime generation\n\
         # The store lives on the persistent state partition (ADR-0023);\n\
         # wait for its mount before touching generations.\n\
         After=local-fs.target\n\
         RequiresMountsFor={STATE_MOUNT}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         # Idempotent and boot-safe: a cold store is a no-op and a\n\
         # half-written journal is discarded (see activate_current).\n\
         ExecStart={ACTIVATE_EXEC}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Emit the boot-time activation oneshot + its `multi-user.target`
/// enablement into the staged rootfs. Gated identically to the state
/// split ([`needs_state_split`]): activation only matters when the store
/// lives on the state partition, so an image with no state role must not
/// gain the unit (that would be a boot regression).
pub(crate) fn emit_runtime_activate_unit(root: &Path) -> miette::Result<()> {
    crate::emit::write_unit(
        root,
        Path::new(ACTIVATE_UNIT_PATH),
        &activate_unit_content(),
    )?;
    crate::emit::enable_unit(root, "multi-user.target", ACTIVATE_UNIT_NAME)?;
    eprintln!("  ✓ {ACTIVATE_UNIT_NAME} emitted (boot-time generation activation)");
    Ok(())
}
