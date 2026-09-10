# Disposable-root updates: on-device sysupdate execution, try-boot, and key ceremony

## Status

Accepted (2026-09-10). Extends ADR-0011 (security stack, step (d) and (e)),
ADR-0012 (generations), and ADR-0023 (state partition). Grounded in the
production-delta grill session (2026-09-10).

## Context

ADR-0011 step (d) chose systemd-sysupdate for A/B updates and step (e) made a
key ceremony a Phase-24 deliverable. The code landed the **emission** half and
stopped:

- `write_sysupdate_transfers` emits three transfer files into
  `/usr/lib/sysupdate.d` (`50-root`, `50-verity`, `60-uki`), with
  `TriesLeft=3`/`TriesDone=0`, and a comment referencing
  `systemd-bless-boot.service` (`src/image.rs:2765-2899`, `:2876`).
- Nothing triggers sysupdate. Repo-wide, `sysupdate.timer|update-check|
  boot-count` appear only in those comments; `units.rs` emits app services and
  target-wants symlinks only.
- No boot-health unit, no try-boot counter handling, no revert path.
- `Keychain::load_dir`/`rotate`/`revoke`/`verify_keychain` exist in
  `src/sign.rs:164-330` but there is **no CLI surface** (`src/cli.rs`
  Commands enum has no key variant); rotation never promotes `secret-key.new`;
  revocation removes a local anchor file and never reaches a device.
- The transfer files are therefore inert configuration: emitted, never
  executed, unable to revert. That is the same class of failure as a kernel
  whose initrd lacks `virtio_blk` — config that looks correct and does nothing.

## Decision

1. **Initrd-module audit is a build-time hard gate.**
   `build_disk_image` inspects the resolved kernel's module tree and initrd
   and **fails the image build** unless the modules the boot chain requires
   (`virtio_blk`, `virtio_pci`, `dm_mod`, `dm-verity`, `ext4` — all `=m` on
   the audited kernels, ADR-0011 kernel-config audit) are present and reachable
   from the initrd. `doctor` may additionally warn, but the image build does
   not ship a kernel that cannot see its own disk. The required set is
   derived from the kernel config, not hardcoded.

2. **Sysupdate runs on systemd's own units, opt-in via `update_source`.**
   When `update_source` is set, the builder emits `systemd-sysupdate.timer` +
   `systemd-sysupdate.service` alongside the transfer files. `shuttle` ships
   no update daemon; this is ADR-0011 §5 (emitted units, not a privileged
   long-lived daemon) applied to updates. When `update_source` is unset, no
   timer is emitted — the existing "unverifiable update config is never
   emitted silently" rule extends to "never trigger silently".

3. **Try-boot and revert use the stock systemd boot-assessment machinery.**
   The builder emits `systemd-bless-boot.service` + `boot-complete.target`
   and a generated health-check unit that gates `boot-complete.target`.
   A boot that reaches userspace and passes the health check marks the
   generation good; a boot that never marks good exhausts `TriesLeft` and
   systemd-bless-boot reverts to the previous slot. No shuttle-owned boot
   logic, no boot script.

4. **Key ceremony ships as an operator CLI, and revocation reaches devices.**
   Add CLI surface over the existing primitives: keygen, rotate (minting and
   promoting `secret-key.new`), revoke. Images and updates carry the trusted
   key set; install/update refuse artifacts signed by a revoked key. A
   rotation whose new key has not been promoted is not trusted. Revocation
   that exists only as local anchor-file removal is not enforcement.

## Alternatives considered

- **Build-time warn only for initrd modules.** Rejected: the kernel↔base
  mismatch (ADR-0019) and the UC18-initrd finding both shipped as warnings
  nobody saw. A disk-invisible kernel is a brick; the gate is cheap because
  the required set is kernel-config-derivable.
- **Manual `shuttle update` command instead of a timer.** Not rejected
  outright — the CLI command remains useful — but a manual-only path means
  unattended devices never update, and the timer costs nothing beyond unit
  emission once `update_source` is set.
- **Shuttle-owned boot-good flag and revert script.** Rejected:
  `systemd-bless-boot` + `boot-complete.target` is the stock, tested
  mechanism, and it is what the existing code comments already pointed at.
  Reimplementing it trades a maintained upstream for a bespoke one.
- **Ship A/B flip without try-boot.** Rejected: a revert that cannot fire is
  the inert-config trap this ADR exists to close.

## Consequences

**Positive**: updates become real (triggered, health-gated, auto-reverting);
a bad update rolls back without an operator; key revocation has device-side
teeth; images that cannot boot are rejected at build time rather than at first
boot.

**Negative**: the build gate needs kernel-config parsing for arbitrary
shipped kernels (fails closed where the config is unavailable, which may
reject kernels that would in fact boot); the boot-health check must be
defined per image or auto-revert will never fire (a health check that never
passes is as broken as one that always does); the operator CLI widens the
key-ceremony surface ADR-0012 already flagged as security-critical.
