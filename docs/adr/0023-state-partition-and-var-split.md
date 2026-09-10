# System state partition and mutable `/var` split

## Status

Accepted (2026-09-10). Extends ADR-0011 (runtime ownership, native target)
and ADR-0012 (file-level store, generations, two-axis updates). Grounded in
the production-delta grill session (2026-09-10).

## Context

ADR-0012 §2 fixed the shape — immutable verity base on axis 1, package store
on the state partition on axis 2 — but no image has ever declared where that
state partition lives. The gap map (2026-09-10) confirmed the concrete
absence:

- `image()` has no state/data partition for non-UC bases. `role` exists
  (`src/image.rs:124-130`) but is honored only for UC `coreN` bases;
  `examples/full-system/pc-rootfs/shuttle.lua:59-82` declares esp + root +
  swap only.
- `EVERYTHING` under `/var` — including `/var/lib/shuttle`
  (`DEFAULT_STATE_DIR`, `src/runtime.rs:94`) and `/var/lib/extensions`
  (`DEFAULT_EXTENSIONS_LINK_DIR`, `src/runtime.rs:97`) — currently lives
  inside the dm-verity read-only root, or nowhere.
- The image builder emits no `fstab`, no `tmpfiles.d`, no `.mount` unit
  (grep for `fstab|tmpfiles|/var` in `src/` is empty).
- `/etc` is baked into the hashed root (`etc/kernelcmdline`,
  `etc/sysctl.d/99-shuttle.conf`, `etc/shuttle/update-key.pub`,
  unit-enablement symlinks).

Without a state partition, an A/B flip changes the writable root wholesale and
every installed package, extension, and device identity is lost with it.

## Decision

1. **State is a declared partition with a role.** `image()` partition roles
   gain `state` for native images, alongside the existing UC
   `system-data` role. Both map to the same runtime concept: the persistent,
   never-verity-protected partition that survives A/B flips. On UC bases the
   existing `ubuntu-data` mapping stands; the native role is the new path.

2. **`/var/lib` is the state partition's mount point; `/var` itself is
   volatile.** The state partition holds only what must survive an update —
   the shuttle store (`/var/lib/shuttle`), extension links
   (`/var/lib/extensions`), machine identity, and anything else declared as
   persistent. The `/var` skeleton (`/var/tmp`, `/var/cache`, `/var/log`,
   `/var/run`) is tmpfs, populated by `systemd-tmpfiles` at boot. This keeps
   the state partition small and makes "what persists across an A/B flip"
   answerable from the partition table.

3. **`/etc` stays in the immutable hashed root; runtime overrides go
   through the state partition.** Generated defaults ship in the image (T6
   stage 1, `cross-distro-synthesis.md` §3 T6). Runtime overrides are
   `systemd-tmpfiles`/drop-in symlinks pointing into state — no 3-way merge
   engine, which stays deferred until hand-edited `/etc` proves a real
   workflow.

4. **Boot population is emitted data, not a daemon.** `systemd-tmpfiles`
   entries create the state directories; a generated
   `shuttle-runtime-activate.service` oneshot runs generation activation at
   boot. Both are emitted systemd units — ADR-0011 §5 (daemon law)
   unchanged.

## Alternatives considered

- **Mount the state partition at `/var` wholesale.** Rejected: drags
  disposable cache/log/tmp into the persistent surface, so the partition
  grows without bound and "persistent" stops meaning anything.
- **`/etc` as a sysext layer.** Rejected: the base-image sysext machinery is
  not built, and adding it to make `/etc` separately versioned solves a
  problem nobody has yet — the override path (3) covers the real need.
- **Keep `/var` inside the root and let each runtime command heal it.**
  Rejected: the current state. `RuntimeStore` docs already concede "every
  runtime command can heal" — meaning nothing is correct before the first
  CLI run, and an A/B flip destroys everything.

## Consequences

**Positive**: installed packages, extension links, and identity survive
atomic updates — the two-axis model becomes real rather than nominal; the
persistent surface is explicit and small.

**Negative**: the state partition size must be chosen at image-build time
(UC's gadget-refresh lesson: partition layouts are hard to change
post-deploy, so sizing policy must be documented, not inherited); the
state-split introduces a new failure mode where a state path is expected but
the partition is missing, which the builder must fail closed on.
