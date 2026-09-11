# Native initramfs construction: build our own when the payload ships a prebuilt UKI

## Status

Accepted (2026-09-11). Amends ADR-0011 (native boot contract) and complements
ADR-0025 (payload layout). Grounded in issue #75, the follow-up to #70, and a
working QEMU boot proof (2026-09-11).

## Context

ADR-0025 established that a prebuilt `kernel.efi` is disassembled (`.linux`,
`.initrd`) and re-assembled into shuttle's own UKI rather than adopted as-is. It
did not address what must live inside the initrd: the `.initrd` section was
treated as an opaque component and handed through.

The first real build with `pc-kernel` rev 3654 proved the remaining blocker. The
snap's `.initrd` is Canonical's **snap-bootstrap** userspace — it mounts a
writable `ubuntu-data` and never verifies a root device. It therefore cannot
honor shuttle's kernel command line (`root=PARTUUID=<u> roothash=<h>
systemd.verity_root_data=/dev/disk/by-partuuid/<u>
systemd.verity_root_hash=/dev/disk/by-partuuid/<u>`; see `verity_trailing` in
`src/image/verity.rs`), which is the integrity binding ADR-0025 exists to
protect. The ADR-0024 §1 initrd-module gate correctly failed the build for the
same reason: `CONFIG_DM_VERITY=m` on the audited kernel, but Canonical's initrd
carries no `dm-verity.ko` (it carries `dm-crypt.ko` instead).

The ADR-0011 kernel-config audit (2026-09-04) had already proven the shape of
the answer: a shuttle-assembled disk with a shuttle-built UKI booting to a
dm-verity-verified root, with busybox as PID 1 and systemd 261.1 running from
the verified device. That proof lived in throwaway `/tmp` scripts and was lost.
This ADR re-establishes the recipe in the repo. ADR-0011 §2 still defers Ubuntu
Core compatibility ("no compat code until a consumer exists"), and there is
still no UC-seed consumer.

## Decision

1. **shuttle builds its own initramfs whenever the boot assets come from a
   prebuilt `kernel.efi`.** Canonical's initrd is discarded; `kernel.efi`
   remains a `.linux` donor only. Kernel snaps using the raw convention — a real
   `vmlinuz` plus an `initrd` — keep their shipped initrd unchanged.

2. **The userspace is a hand-rolled POSIX `/init` script (busybox ash), not a
   systemd initramfs.** It mounts `/proc`, `/sys`, and `/dev` (devtmpfs),
   `insmod`s the boot-chain module closure in dependency order, resolves the GPT
   PARTUUID **without udev**, opens the dm-verity mapping, mounts the root
   read-only, and `switch_root`s into the verified root — the same sequence
   ADR-0011 recorded in the lost proof, now in-tree. The `veritysetup open`
   argument order settled empirically on cryptsetup 2.8.7 is `open
   <data_device> <name> <hash_device> [<root_hash>]`; the legacy `create
   <name> <data> <hash>` order is not accepted by `open`.

3. **The module closure is derived from the kernel config and ordered from the
   snap's `modules.dep`.** Every boot-chain requirement is a `CONFIG_*` symbol
   set `=m`; no module list is hardcoded. The build emits `/modules.load` (one
   module path per line, in load order) into the archive, and `/init` consumes
   it. For `pc-kernel` rev 3654 the closure is `virtio_blk.ko`, `dm-bufio.ko`,
   `dm-verity.ko`, in that order.

4. **The userspace is static musl.** Three single binaries are staged:
   `busybox`, `veritysetup` (cryptsetup), and `findfs` (util-linux). `findfs` is
   needed because busybox `findfs` cannot resolve `PARTUUID`, and the Ubuntu
   5.15 kernel does not export `PARTUUID` in `/sys/class/block/*/uevent` (it
   carries only `PARTN`/`PARTNAME`). util-linux `findfs`, which parses GPT via
   libblkid, is the primary path; a raw GPT partition-entry parse is the
   documented fallback.

5. **The archive is written in-process.** `newc` cpio is emitted in-process and
   gzipped in-process with a fixed zero mtime, so output is deterministic. No
   host `cpio`, `gzip`, or `zstd` subprocess is involved.

6. **The ADR-0024 §1 gate audits shuttle's own archive.** The same hard,
   fail-closed check now inspects the initramfs shuttle generates rather than a
   vendor initrd — aimed at the artifact actually shipped.

7. **Microcode is deliberately not reproduced.** Canonical's early-cpio
   microcode layer is omitted; microcode remains a per-image, per-firmware
   concern. This is a known limitation with a revisit trigger (below).

## Alternatives considered

- **Adopt Canonical's snap-bootstrap initrd as-is, or inject `dm-verity.ko`
  into it.** Rejected: snap-bootstrap still runs as the initramfs init, finds no
  modeenv or seed, and fails into `emergency.target` irreversibly; the injected
  module changes nothing. Injecting also means maintaining a diff against
  snapd-initramfs internals with no stability contract, redone per kernel
  revision.

- **A systemd-in-initramfs (systemd + udev + the initrd unit set), i.e.
  re-implementing `ubuntu-core-initramfs` minus snapd.** Rejected: tens of
  megabytes and a large moving surface for a boot contract that a ~170-line
  `/init` already satisfies.

- **A dynamic userspace with its library closure staged.** Rejected in favour of
  static: the `veritysetup` closure pulls glibc, libcryptsetup, libdevmapper,
  libblkid, libcrypto, libjson-c, and libudev (roughly 15.6 MB) plus a loader,
  versus ~9.7 MB of static single binaries, with fewer moving parts.

- **Teach `discover_kernel_version` or the payload locator a second location to
  dodge the initrd problem.** Rejected by ADR-0025 already; the booted runtime
  needs `/lib/modules/<ver>` regardless.

## Consequences

**Positive**: a stock Ubuntu Core kernel snap can finally build a bootable
shuttle image on the native path; the failure class moves from an unbootable
artifact at first boot to a build-time hard error; the ADR-0011 bootstrap recipe
is now in-tree and regression-tested instead of living in lost `/tmp` scripts.

**Negative**: shuttle now owns initramfs correctness for every kernel it ships
(module closure, load order, verity invocation) and gains host build
dependencies on static busybox, cryptsetup, and util-linux. The per-kernel
closure must be re-derived from each kernel config, so a kernel that makes the
root device or its filesystem modular in an unexpected way becomes a build-time
fail-closed rather than a silent brick.

**Revisit triggers**: if a UC-seed/GRUB consumer ever materializes, ADR-0025
already records adopt-as-is as the correct path for that target and this
machinery would not be used there. Microcode-in-initramfs can be revisited if a
target needs it.

**Open/untested**: the proof used a disk with separate data and hash partitions;
a combined single-partition layout is untested.

## Evidence

- QEMU serial log `/tmp/opencode/shuttle-init-tier2-proof.log` — the full boot:
  PARTUUID resolved, dm-verity opened, ext4 mounted read-only, `switch_root`
  reached the verified-root marker (`SHUTTLE-ROOTFS: boot chain complete`).
- QEMU serial log `/tmp/opencode/shuttle-init-tier1-proof.log` — the tier-1
  `/init` run up to module loading.
- Issue #75 (native initramfs construction) and the #70 build output, which
  surfaced the snap-bootstrap blocker.
