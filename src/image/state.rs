//! Persistent state partition role + the mutable-`/var` split (ADR-0023).
//!
//! ADR-0023 makes "what survives an A/B flip" answerable from the
//! partition table: the persistent state — the nau store
//! (`/var/lib/nau`) and extension links (`/var/lib/extensions`) —
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
//! silent boot failure: the state paths (`/var/lib/nau`,
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
pub(crate) const STATE_TMPFILES_PATH: &str = "usr/lib/tmpfiles.d/nau-state.conf";

/// tmpfiles.d file that materializes the volatile `/var` skeleton.
pub(crate) const VAR_TMPFILES_PATH: &str = "usr/lib/tmpfiles.d/nau-var.conf";

/// Mount point of the persistent state partition (ADR-0023 §2).
pub(crate) const STATE_MOUNT: &str = "/var/lib";

/// Mount point of the volatile tmpfs (the `/var` skeleton top).
pub(crate) const VAR_MOUNT: &str = "/var";

/// The always-present state directories, created at boot by tmpfiles —
/// the nau store ([`crate::runtime::DEFAULT_STATE_DIR`]) and the
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
/// `role = "state"`, or the UC `system-data` / `system-save` roles (which
/// describe the same class of boot-populated writable — snapd seeds
/// `ubuntu-data` and maintains `ubuntu-save` itself; the build formats
/// both empty). Everything else — including the root/ESP/swap — is not
/// state.
pub(crate) fn is_state_partition(part: &Partition) -> bool {
    is_state_role(&part.role)
        || matches!(
            partition_uc_role(part),
            Some(crate::uc::ROLE_DATA) | Some(crate::uc::ROLE_SAVE)
        )
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

/// WHY the build will not emit sysupdate transfers/units, when it will
/// not — the loud mirror of [`emits_sysupdate`], one message source so
/// the two skip shapes cannot drift apart (#293 item 6). `None` when the
/// build emits them. Both mirror shapes PRINT; neither is silent:
///
/// - A/B without `update_source`: nothing declared, nothing lost — the
///   slots stay twin-ready, the skip is informational.
/// - `update_source` without A/B: a declared update channel that can
///   never deliver (no slot to flip to) — declared intent silently inert
///   before #293 named it.
pub(crate) fn sysupdate_skip_reason(
    image: &ImageDeclaration,
    layout: &DiskLayout,
) -> Option<&'static str> {
    if emits_sysupdate(image, layout) {
        None
    } else if layout.ab {
        Some(
            "disk.ab = true without update_source — sysupdate transfer files \
             skipped (a local-source transfer carries no verification)",
        )
    } else if image.update_source.is_some() {
        Some(
            "update_source declared but disk.ab = false — a single-slot disk \
             has no slot to flip to, so the declared update channel is INERT: \
             no sysupdate transfer files or trigger units are emitted. Declare \
             disk.ab = true or drop update_source (#293)",
        )
    } else {
        None
    }
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
    /// Whether the state filesystem supports first-boot growth: the
    /// fstab state line then carries `x-systemd.growfs`, so
    /// systemd-growfs sizes the filesystem to the (grown) partition at
    /// mount time (#264). UC data partitions are `false` — snapd owns
    /// their growth.
    pub(crate) growfs: bool,
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
             the nau store ({state}) and extension links ({ext}) would live inside the \
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
        growfs: state_fs_growable(part),
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
/// On a growable state filesystem the state line additionally carries
/// `x-systemd.growfs` (#264): systemd-growfs sizes the filesystem to the
/// partition at mount time — the partition side is grown on first boot by
/// [`STATE_GROW_UNIT_NAME`], ordered before this mount.
pub(crate) fn state_fstab_lines(split: &StateSplit) -> Vec<String> {
    let mut state_opts = String::from("defaults,nofail");
    if split.growfs {
        state_opts.push_str(",x-systemd.growfs");
    }
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

/// `usr/lib/tmpfiles.d/nau-state.conf` — create the state directories
/// on the mounted state partition at boot, including the mount point
/// itself so the tmpfs/partition hierarchy is complete.
pub(crate) fn state_tmpfiles_content() -> String {
    let mut out = String::from("# Generated by nau — do not edit.\n");
    out.push_str(&format!("d {} 0755 root root -\n", STATE_MOUNT));
    for dir in state_dirs() {
        out.push_str(&format!("d {dir} 0755 root root -\n"));
    }
    out
}

/// `usr/lib/tmpfiles.d/nau-var.conf` — materialize the volatile `/var`
/// skeleton (`run`, `tmp`, `cache`, `log`) on the tmpfs at boot, plus
/// `extra` declared mount points that live under `/var` and are shadowed
/// by the tmpfs mount. The latter must be created at boot because a
/// build-time mkdir would be hidden by the tmpfs.
pub(crate) fn var_tmpfiles_content_with(extra: &[String]) -> String {
    let mut out = String::from("# Generated by nau — do not edit.\n");
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
pub(crate) const ACTIVATE_UNIT_NAME: &str = "nau-runtime-activate.service";

/// Unit path inside the staged rootfs (`usr/lib/systemd/system/`).
pub(crate) const ACTIVATE_UNIT_PATH: &str = "usr/lib/systemd/system/nau-runtime-activate.service";

/// ExecStart program for the activation oneshot.
///
/// Pinned absolutely to `/{NAU_BIN_PATH}` (i.e. `/usr/bin/nau`,
/// issue #81): the image build embeds the nau binary at that exact
/// path (see [`super::staging::embed_nau_binary`]), so the exec target
/// exists in every image the build produces — inside the dm-verity-hashed
/// tree, no PATH lookup. A test asserts the absolute prefix and the staged
/// path cannot drift apart.
pub(crate) const ACTIVATE_EXEC: &str = "/usr/bin/nau runtime activate";

/// Render the boot-time activation oneshot (ADR-0023 §4). It is
/// `Type=oneshot` with `RemainAfterExit=yes`, so the activation is a
/// single boot step systemd considers done once it exits. It is ordered
/// after the persistent state mount so the store is available when
/// activation runs, and enabled into `multi-user.target` via
/// [`crate::emit::enable_unit`].
pub(crate) fn activate_unit_content() -> String {
    format!(
        "# Generated by nau — do not edit.\n\
         [Unit]\n\
         Description=nau: activate the current runtime generation\n\
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

// ── First-boot state-partition growth (ADR-0044 D2, #264) ──

/// GPT type GUID marking the state partition growable. The Discoverable
/// Partitions Specification defines no state-partition type, so this is a
/// nau-private GUID (minted once, source-pinned): the build stamps it
/// onto the state partition (`sfdisk --part-type`) and the emitted repart
/// definition matches its partition by exactly this type — systemd-repart
/// matches existing partitions to definitions by type UUID alone
/// (repart.d(5)), so a DPS-generic type would match the wrong partition
/// (in a non-A/B image the verity root carries the same generic type).
/// No other partition in a nau image carries this GUID, so the match
/// is exact by construction.
pub(crate) const STATE_TYPE_GUID: &str = "cd0f7aae-5570-4511-8dd4-182a4d25c72e";

/// repart definition drop-in staged into the rootfs (guest path
/// `/usr/lib/repart.d/`). Written before the rootfs is hashed, so
/// dm-verity covers the growth contract like every other boot artifact.
pub(crate) const REPART_DEFINITION_PATH: &str = "usr/lib/repart.d/40-nau-state.conf";

/// Unit filename of the first-boot growth oneshot.
pub(crate) const STATE_GROW_UNIT_NAME: &str = "nau-state-grow.service";

/// Unit path inside the staged rootfs (`usr/lib/systemd/system/`).
pub(crate) const STATE_GROW_UNIT_PATH: &str = "usr/lib/systemd/system/nau-state-grow.service";

/// fstab-derived mount unit of [`STATE_MOUNT`] — the systemd-escaped unit
/// name systemd generates from the `etc/fstab` state line. The growth
/// unit orders itself before it so the partition is grown before
/// `systemd-growfs` sizes the filesystem at mount time.
pub(crate) const STATE_GROW_MOUNT_UNIT: &str = "var-lib.mount";

/// Filesystem types systemd-growfs can grow online — the state
/// filesystems first-boot growth applies to. Anything else keeps the
/// historical fixed-size behavior (growth of the partition without the
/// filesystem would strand the extra space inside the partition).
const GROWABLE_STATE_FS: [&str; 3] = ["ext4", "btrfs", "xfs"];

/// The systemd-repart binary the growth unit execs. Upstream installs it
/// as a public program (`/usr/bin/`), unlike the libexec daemons.
const REPART_BIN: &str = "/usr/bin/systemd-repart";

/// True when `part` is a NATIVE state partition whose filesystem first
/// boot can grow. UC `system-data`/`system-save` partitions are excluded:
/// snapd owns their growth story, and stamping nau's type GUID onto
/// them would fight the gadget.
pub(crate) fn state_fs_growable(part: &Partition) -> bool {
    is_state_role(&part.role) && GROWABLE_STATE_FS.contains(&part.fs.as_str())
}

/// The first-boot growth target resolved from the layout: the state
/// partition's 1-based GPT partition number plus its PARTLABEL. `None`
/// unless the table is GPT (repart.d is GPT-only per repart.d(5)) and a
/// native state partition carries a growable filesystem.
pub(crate) fn repart_growth_target(layout: &DiskLayout) -> Option<StateGrowth> {
    if layout.label != "gpt" {
        return None;
    }
    layout.partitions.iter().enumerate().find_map(|(i, part)| {
        state_fs_growable(part).then(|| StateGrowth {
            partno: i + 1,
            partlabel: part.name.clone(),
        })
    })
}

/// The state partition's first-boot growth mark: the 1-based GPT
/// partition number the type GUID is stamped onto, and the PARTLABEL the
/// first-boot unit resolves the whole disk from.
pub(crate) struct StateGrowth {
    pub(crate) partno: usize,
    pub(crate) partlabel: String,
}

/// Explain (never silently skip) why a layout with a native state
/// partition does not get first-boot growth. Called only when
/// [`repart_growth_target`] returned `None`; images with no native state
/// partition stay silent — no state partition, nothing to grow, and the
/// byte-comparable doctrine forbids new noise on plain images.
fn log_growth_skipped(layout: &DiskLayout) {
    let Some(part) = layout.partitions.iter().find(|p| is_state_role(&p.role)) else {
        return;
    };
    if layout.label != "gpt" {
        eprintln!(
            "  ℹ state partition '{}' on a '{}' table — first-boot growth needs GPT \
             (repart.d(5) is GPT-only); the state partition stays fixed-size",
            part.name, layout.label
        );
    } else {
        eprintln!(
            "  ℹ state partition '{}' uses filesystem '{}' — first-boot growth needs \
             one of {GROWABLE_STATE_FS:?} (systemd-growfs); the state partition stays \
             fixed-size",
            part.name, part.fs
        );
    }
}

/// The charset the growth unit's `sh -c` resolver can reference safely:
/// the PARTLABEL is embedded in a single-quoted ExecStart, so anything
/// outside `[A-Za-z0-9._-]` (a quote would break out of the quoting; a
/// space would split the device path) is refused at build time — the
/// same fail-closed shape as a declared `files[].dest`.
fn validated_growth_partlabel(partlabel: &str) -> miette::Result<()> {
    let ok = partlabel
        .strip_prefix(|c: char| c.is_ascii_alphanumeric())
        .is_some_and(|rest| {
            rest.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        });
    if ok {
        Ok(())
    } else {
        Err(miette::miette!(
            "state partition name {partlabel:?} cannot carry first-boot growth: the \
             PARTLABEL is embedded in the growth unit's shell resolver, so only \
             [A-Za-z0-9][A-Za-z0-9._-]* names are supported — rename the partition \
             or drop role = \"state\""
        ))
    }
}

/// Emit the first-boot growth artifacts into the staged rootfs: the
/// repart definition that marks the state partition growable and the
/// oneshot that runs systemd-repart before the state mount. Gated on a
/// resolvable growth target; a layout with a native state partition that
/// cannot carry growth gets a named note instead (never silence).
pub(crate) fn emit_state_growth(root: &Path, layout: &DiskLayout) -> miette::Result<()> {
    let Some(growth) = repart_growth_target(layout) else {
        log_growth_skipped(layout);
        return Ok(());
    };
    validated_growth_partlabel(&growth.partlabel)?;
    crate::emit::write_staged_file(
        root,
        Path::new(REPART_DEFINITION_PATH),
        &state_repart_definition(),
    )?;
    crate::emit::write_unit(
        root,
        Path::new(STATE_GROW_UNIT_PATH),
        &state_grow_unit(&growth),
    )?;
    crate::emit::enable_unit(root, "sysinit.target", STATE_GROW_UNIT_NAME)?;
    if growth.partno - 1 != layout.partitions.len() - 1 {
        eprintln!(
            "  ℹ state partition is not the last partition — first-boot growth stops \
             at the next partition (repart never moves partitions)"
        );
    }
    eprintln!(
        "  ✓ {STATE_GROW_UNIT_NAME} emitted (first-boot state growth: PARTLABEL={} \
         grows to fill the disk via systemd-repart)",
        growth.partlabel
    );
    Ok(())
}

/// The repart definition marking the state partition growable. No size
/// constraints: repart.d(5) defaults (10M minimum, no maximum, weight
/// 1000) are exactly the growth semantics wanted — grow into the free
/// space following the partition, stop at the next partition or the disk
/// end, and no-op once the table satisfies the definition.
pub(crate) fn state_repart_definition() -> String {
    let mut out = String::from("# Generated by nau — do not edit.\n");
    out.push_str("# First-boot state-partition growth (ADR-0044 D2, #264): systemd-repart\n");
    out.push_str("# matches the flashed state partition by its GPT type GUID and grows\n");
    out.push_str("# it into the free space following it (default sizing: 10M minimum, no\n");
    out.push_str("# maximum, weight 1000 — repart.d(5)), so a dd-flashed image takes\n");
    out.push_str("# possession of the rest of the disk on first boot. Idempotent: once\n");
    out.push_str("# the table satisfies the definition, repart no-ops.\n");
    out.push_str("#\n");
    out.push_str("# The filesystem inside is grown to match by systemd-growfs at mount\n");
    out.push_str("# time: etc/fstab carries x-systemd.growfs on the state line, and\n");
    out.push_str(&format!(
        "# {STATE_GROW_UNIT_NAME} orders the partition growth before the mount.\n"
    ));
    out.push_str("[Partition]\n");
    out.push_str("# Nau-private type GUID (the DPS defines no state-partition type).\n");
    out.push_str("# Stamped onto the state partition at build time; no other partition in\n");
    out.push_str("# a nau image carries it, so the match is exact. No Label=: repart\n");
    out.push_str("# uses it only when CREATING a partition, and a definition that fails\n");
    out.push_str("# to match must never mint a partition claiming the state PARTLABEL.\n");
    out.push_str(&format!("Type={STATE_TYPE_GUID}\n"));
    out
}

/// The `sh -c` script resolving the whole disk behind the state
/// partition. repart operates on a DISK, and the disk's device name is
/// not knowable at build time — but the state partition is, via its
/// stable by-partlabel symlink; the sysfs parent of that symlink's
/// target names the disk (`sda3` → `sda`, `nvme0n1p3` → `nvme0n1`).
/// No single quotes inside: the unit wraps this in `sh -c '…'`. No
/// `$VAR`/`${VAR}` references either — systemd expands those in
/// ExecStart= (systemd.service(5)) even inside quotes, before sh ever
/// sees them; `$(` command substitution is neither documented form and
/// passes through to sh untouched.
fn state_grow_exec(partlabel: &str) -> String {
    format!(
        "[ -e /dev/disk/by-partlabel/{partlabel} ] || {{ echo \"nau-state-grow: \
         no /dev/disk/by-partlabel/{partlabel}\"; exit 1; }}; \
         exec {REPART_BIN} --definitions=/{REPART_DEFINITION_PATH} \"/dev/$(basename \
         \"$(dirname \"$(readlink -f /sys/class/block/$(basename \"$(readlink -f \
         /dev/disk/by-partlabel/{partlabel})\")\")\")\")\""
    )
}

/// Render the first-boot growth oneshot. `DefaultDependencies=no` and an
/// explicit `Before=` on the state mount unit: a default-deps unit would
/// order after basic.target, which sits behind local-fs.target — too
/// late for the mount-time filesystem grow to see the grown partition.
/// Enabled into `sysinit.target` ([`emit_state_growth`]), where the
/// `Before=` carries the actual ordering.
pub(crate) fn state_grow_unit(growth: &StateGrowth) -> String {
    let mut out = String::from("# Generated by nau — do not edit.\n");
    out.push_str("[Unit]\n");
    out.push_str("Description=nau: grow the state partition to fill the disk (first boot)\n");
    out.push_str("Documentation=man:systemd-repart.service(8)\n");
    out.push_str("# Ordered BEFORE the state partition mounts: etc/fstab carries\n");
    out.push_str("# x-systemd.growfs on the state line and systemd-growfs sizes the\n");
    out.push_str("# filesystem to the partition at mount time — running after the mount\n");
    out.push_str("# would grow the partition too late for the filesystem to follow.\n");
    out.push_str("DefaultDependencies=no\n");
    out.push_str("After=systemd-udevd.service systemd-udev-trigger.service\n");
    out.push_str(&format!("Before=local-fs.target {STATE_GROW_MOUNT_UNIT}\n"));
    out.push_str("Conflicts=shutdown.target\n");
    out.push_str("Before=shutdown.target\n");
    out.push_str("# The repart definition emitted beside this unit is the whole feature;\n");
    out.push_str("# without it repart has nothing to match.\n");
    out.push_str(&format!("ConditionPathExists=/{REPART_DEFINITION_PATH}\n"));
    out.push('\n');
    out.push_str("[Service]\n");
    out.push_str("Type=oneshot\n");
    out.push_str("RemainAfterExit=yes\n");
    out.push_str("# repart operates on the WHOLE disk, not the state partition: the nested\n");
    out.push_str("# $() below walks by-partlabel → sysfs → parent disk. Written variable-free:\n");
    out.push_str("# systemd expands $VAR in ExecStart= (systemd.service(5)) before sh runs.\n");
    out.push_str(&format!(
        "ExecStart=/bin/sh -c '{}'\n",
        state_grow_exec(&growth.partlabel)
    ));
    out
}

/// The `sfdisk` argv stamping the growable type GUID onto the state
/// partition — the table-side half of the growth mark (the definition's
/// `Type=` is the other half; the two share [`STATE_TYPE_GUID`] so they
/// cannot drift). Pure so the argv is unit-testable without a runner,
/// mirroring [`super::parted_mkpart_args`].
pub(crate) fn state_growth_type_args(img_path: &Path, partno: usize) -> Vec<String> {
    vec![
        "sfdisk".to_string(),
        "--part-type".to_string(),
        img_path.to_string_lossy().into_owned(),
        partno.to_string(),
        STATE_TYPE_GUID.to_string(),
    ]
}

/// Stamp the growable type GUID onto the state partition's table entry.
/// Fail-open, never silent — the same posture as the A/B slot metadata
/// (a failed stamp degrades first-boot growth to a no-op with a spare
/// partition, it does not unboot anything), and the populate pre-flight
/// has already failed closed on a missing sfdisk by this point.
pub(crate) fn apply_state_growth_type(runner: &dyn CommandRunner, img_path: &Path, partno: usize) {
    let argv = state_growth_type_args(img_path, partno);
    if !runner.run(&argv).is_ok_and(|o| o.code == 0) {
        eprintln!(
            "  ⚠ sfdisk --part-type failed for partition {partno} ({STATE_TYPE_GUID}) — \
             first-boot state growth will not match its partition (fail-open: repart \
             would append a spare partition instead of growing)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(label: &str, parts: Vec<Partition>) -> DiskLayout {
        DiskLayout {
            label: label.into(),
            partitions: parts,
            swap: None,
            ab: false,
        }
    }

    fn part(name: &str, fs: &str, mount: &str, role: &str) -> Partition {
        Partition {
            name: name.into(),
            size: "256M".into(),
            fs: fs.into(),
            mount: mount.into(),
            options: vec![],
            role: role.into(),
        }
    }

    fn native_state_layout(label: &str, fs: &str) -> DiskLayout {
        layout(
            label,
            vec![
                part("UEFI", "vfat", "/boot/efi", ""),
                part("root", "ext4", "/", ""),
                part("state", fs, STATE_MOUNT, ROLE_STATE),
            ],
        )
    }

    #[test]
    fn growth_target_selects_the_native_state_partition() {
        let l = native_state_layout("gpt", "ext4");
        let growth = repart_growth_target(&l).expect("native ext4 state on GPT grows");
        assert_eq!(growth.partno, 3, "1-based GPT partition number");
        assert_eq!(growth.partlabel, "state");
    }

    #[test]
    fn growth_target_skips_uc_state_roles() {
        // system-data describes the same runtime concept, but snapd owns
        // UC growth — nau must not stamp its type GUID there.
        let l = layout(
            "gpt",
            vec![
                part("ubuntu-seed", "vfat", "/boot/efi", ""),
                part("writable", "ext4", "/var/lib", "system-data"),
            ],
        );
        assert!(
            repart_growth_target(&l).is_none(),
            "UC data partitions keep snapd's growth story"
        );
        assert!(!state_fs_growable(&l.partitions[1]));
    }

    // ── #293 item 6: the sysupdate skip shapes are named, never silent ──

    fn skip_reason(ab: bool, update_source: bool) -> Option<&'static str> {
        let mut image = crate::image::test_support::sample_image();
        image.update_source = update_source.then(|| "https://updates.example.com/os/".into());
        let mut l = native_state_layout("gpt", "ext4");
        l.ab = ab;
        sysupdate_skip_reason(&image, &l)
    }

    #[test]
    fn sysupdate_skip_reasons_cover_the_truth_table() {
        // The emitting shape: no reason, no print.
        assert!(skip_reason(true, true).is_none(), "emits ⇒ no skip");
        // The mirror shapes both PRINT — neither stays silent.
        let ab_only = skip_reason(true, false).expect("ab without source must print");
        assert!(
            ab_only.contains("without update_source"),
            "the ab-only skip names its cause: {ab_only}"
        );
        let source_only = skip_reason(false, true).expect("source without ab must print");
        assert!(
            source_only.contains("INERT") && source_only.contains("disk.ab = false"),
            "the source-only skip names the inert channel: {source_only}"
        );
        // Nothing declared, nothing skipped.
        assert!(skip_reason(false, false).is_none(), "plain image ⇒ silent");
    }

    #[test]
    fn sysupdate_skip_reason_agrees_with_the_emit_predicate() {
        // The helper is the mirror of emits_sysupdate: wherever something
        // IS declared (ab or source), exactly one of the two speaks.
        for ab in [true, false] {
            for source in [true, false] {
                let mut image = crate::image::test_support::sample_image();
                image.update_source = source.then(|| "https://u.example/".into());
                let mut l = native_state_layout("gpt", "ext4");
                l.ab = ab;
                if ab || source {
                    assert_eq!(
                        sysupdate_skip_reason(&image, &l).is_none(),
                        emits_sysupdate(&image, &l),
                        "mirror disagreement at ab={ab}, source={source}"
                    );
                } else {
                    // Nothing declared: nothing emitted, nothing printed.
                    assert!(sysupdate_skip_reason(&image, &l).is_none());
                    assert!(!emits_sysupdate(&image, &l));
                }
            }
        }
    }

    #[test]
    fn growth_target_requires_gpt() {
        let l = native_state_layout("mbr", "ext4");
        assert!(
            repart_growth_target(&l).is_none(),
            "repart.d(5) is GPT-only"
        );
    }

    #[test]
    fn growth_target_requires_a_growable_filesystem() {
        let l = native_state_layout("gpt", "vfat");
        assert!(
            repart_growth_target(&l).is_none(),
            "systemd-growfs cannot grow vfat — growth would strand the space"
        );
    }

    #[test]
    fn definition_type_is_the_stamped_type_guid() {
        // The definition's match key and the table stamp share one
        // constant — the two halves of the growth mark cannot drift.
        assert!(state_repart_definition().contains(&format!("Type={STATE_TYPE_GUID}")));
    }

    #[test]
    fn definition_pins_no_label() {
        // A definition carrying Label= would MINT a state-labeled
        // partition if it ever failed to match — shadowing the real one
        // in /dev/disk/by-partlabel. It must not carry one.
        assert!(
            !state_repart_definition().contains("\nLabel="),
            "unmatched definitions must not create state-labeled partitions"
        );
    }

    #[test]
    fn unit_orders_growth_before_the_state_mount() {
        let l = native_state_layout("gpt", "ext4");
        let unit = state_grow_unit(&repart_growth_target(&l).unwrap());
        assert!(
            unit.contains(&format!("Before=local-fs.target {STATE_GROW_MOUNT_UNIT}\n")),
            "the fstab mount unit of {STATE_MOUNT} must come after growth: {unit}"
        );
        assert!(
            unit.contains("DefaultDependencies=no"),
            "default deps would order the unit after basic.target — too late: {unit}"
        );
        assert!(
            unit.contains("After=systemd-udevd.service systemd-udev-trigger.service"),
            "the by-partlabel symlink needs coldplug done: {unit}"
        );
        assert!(
            unit.contains(&format!("ConditionPathExists=/{REPART_DEFINITION_PATH}")),
            "the emitted definition is the feature; guard the exec: {unit}"
        );
        assert!(unit.contains("Type=oneshot") && unit.contains("RemainAfterExit=yes"));
    }

    #[test]
    fn unit_exec_resolves_the_disk_and_runs_repart() {
        let l = native_state_layout("gpt", "ext4");
        let unit = state_grow_unit(&repart_growth_target(&l).unwrap());
        let exec = unit
            .lines()
            .find(|l| l.starts_with("ExecStart="))
            .expect("one ExecStart");
        assert!(exec.contains("/dev/disk/by-partlabel/state"), "{exec}");
        assert!(exec.contains("/sys/class/block/"), "{exec}");
        assert!(exec.contains(REPART_BIN), "{exec}");
        assert!(
            exec.contains(&format!("--definitions=/{REPART_DEFINITION_PATH}")),
            "explicit definitions dir — no stray /etc/repart.d input: {exec}"
        );
        // systemd expands $VAR/${VAR} in ExecStart= even inside quotes —
        // the script must carry no bare variable reference, or systemd
        // substitutes (unset → empty) before sh sees it.
        let bare_var = |c: char| c.is_ascii_alphanumeric() || c == '_';
        assert!(
            !exec.match_indices('$').any(|(i, _)| {
                exec[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c == '{' || bare_var(c))
            }),
            "no bare $-variable references (systemd eats them): {exec}"
        );
        assert!(!exec.contains('%'), "% is systemd specifier syntax: {exec}");
    }

    #[test]
    fn growth_partlabel_charset_is_enforced() {
        validated_growth_partlabel("state").unwrap();
        validated_growth_partlabel("nau_state-1.0").unwrap();
        for bad in ["state partition", "sta'te", "state;rm", "", "-leading"] {
            assert!(
                validated_growth_partlabel(bad).is_err(),
                "{bad:?} must be refused (sh -c embedding)"
            );
        }
    }

    #[test]
    fn sfdisk_args_carry_the_type_guid_and_partno() {
        let args = state_growth_type_args(Path::new("/tmp/disk.img"), 3);
        assert_eq!(args[0], "sfdisk");
        assert_eq!(args[1], "--part-type");
        assert_eq!(args[2], "/tmp/disk.img");
        assert_eq!(args[3], "3");
        assert_eq!(args[4], STATE_TYPE_GUID);
    }

    #[test]
    fn stamp_failure_is_fail_open_not_fatal() {
        struct Failing;
        impl crate::command::CommandRunner for Failing {
            fn run(&self, _argv: &[String]) -> std::io::Result<crate::command::RunnerOutput> {
                Err(std::io::Error::other("sfdisk vanished"))
            }
        }
        // Must not panic, must not error — the warning is the contract.
        apply_state_growth_type(&Failing, Path::new("/tmp/disk.img"), 2);
    }

    #[test]
    fn fstab_state_line_grows_only_when_the_split_says_so() {
        let grow = StateSplit {
            partlabel: "state".into(),
            var_submount_partlabel: String::new(),
            growfs: true,
        };
        let fixed = StateSplit {
            partlabel: "state".into(),
            var_submount_partlabel: String::new(),
            growfs: false,
        };
        assert!(
            state_fstab_lines(&grow)[1]
                .contains("PARTLABEL=state /var/lib auto defaults,nofail,x-systemd.growfs"),
            "growfs flag lands on the state line: {:?}",
            state_fstab_lines(&grow)
        );
        assert_eq!(
            state_fstab_lines(&fixed)[1],
            "PARTLABEL=state /var/lib auto defaults,nofail",
            "no growfs option without the flag (byte-stable)"
        );
    }
}
