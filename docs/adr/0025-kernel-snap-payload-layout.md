# Kernel-snap payload layout: accept raw components and a prebuilt UKI

## Status

Accepted (2026-09-11). Amends ADR-0011 step (a) (boot-chain fix, UKI via
`ukify`). Grounded in the first end-to-end dogfood (2026-09-11), issue #70.

Amended 2026-09-14 (issue #87): the Raspberry Pi payload shape is a third
accepted layout, consumed by a second boot backend (`piboot`) — see the
amendment section at the end.

## Context

ADR-0011 step (a) defined the boot-chain fix — real kernel and loader entries
on the ESP, UKI via `ukify` so kernel params land — and with it an assumed
kernel-snap payload shape: `boot/vmlinuz-<ver>`, `boot/initrd.img-<ver>`, and
`lib/modules/<ver>/`. That convention was never checked against a real store
kernel snap.

The first end-to-end dogfood (2026-09-11, #70) built with the real `pc-kernel`
rev 3654 (track `22/stable`) and failed closed at staging: `no kernel module
tree (lib/modules/<version>) in the merged rootfs`. None of the assumed paths
exist. The snap ships:

- `kernel.efi` at the snap root — a prebuilt full systemd-stub UKI, with
  `.sdmagic`, `.sbat`, `.linux`, and `.initrd` PE sections;
- `modules/<kver>/kernel/...` — the module tree, under `modules/`, not
  `lib/modules/`;
- `modules/<kver>/initrd` — an empty *directory*, not the initramfs;
- `config-<kver>` and `System.map-<kver>` at the snap root;
- `firmware/` at the snap root.

On Ubuntu Core amd64 the real boot chain is UEFI → shim → GRUB →
`chainloader kernel.efi`. systemd-boot is not used there, and Canonical
assembles the UKI at kernel-snap build time and ships it as-is — the snap is
already the boot asset, not a set of components.

## Decision

1. **shuttle accepts both payload layouts.** When raw `vmlinuz`/`initrd` are
   present in the snap they are used directly, as today. When the payload
   instead ships a prebuilt UKI, shuttle extracts the `.linux` and `.initrd`
   PE sections with `objcopy` and re-assembles its own UKI with `ukify`.

2. **A prebuilt UKI is never adopted as the boot asset.** The snap's
   `kernel.efi` is a source of components, not the object installed on the ESP.

3. **The kernel version is the layout ABI string.** `modules/<kver>/` — the
   directory name, and what `uname -r` reports — is the version, not the snap
   `version:` field. That field is store packaging metadata and may differ,
   e.g. `5.15.0-186.196.1+535.309.01`. The extracted image's version banner is
   cross-checked against `kver` before the build proceeds.

4. **Staging normalizes the layout.** The staging copy maps snap-root
   `modules/` → rootfs `lib/modules/` and `firmware/` → `lib/firmware/`, so
   the booted runtime sees the conventional paths regardless of the snap's
   internal shape.

**Rationale (the decisive reason).** shuttle's per-image kernel command line —
`root=PARTUUID=<uuid>` and the dm-verity `shuttle.roothash=<hash>` — is the integrity
binding (ADR-0011 step (c); `VERIFY_ROOTHASH_SIG` is absent from the audited
kernels). It must live inside the signed UKI. Adopting `kernel.efi` as-is would
force that command line into bootloader-supplied `LoadOptions` on the mutable,
unsigned ESP — and systemd-stub ignores `LoadOptions` when a UKI carries an
embedded command line and Secure Boot is enabled. The adopt-as-is path is
therefore insecure today and breaks outright once UKI signing lands. Extraction
and re-assembly keep the cmdline where the signature covers it.

## Alternatives considered

- **Adopt `kernel.efi` as-is.** Rejected: it moves the integrity-binding
  cmdline onto an unsigned, mutable `LoadOptions` path (above), and it would
  additionally require a GRUB backend plus the snapd `grubenv` boot-variable
  protocol, both of which ADR-0011 already deferred.
- **Teach `discover_kernel_version` a second search location only
  (`modules/<kver>/`)** — the minimal fix (#70 item 2). Rejected as the whole
  answer: the booted runtime still needs `/lib/modules/<ver>`, so the mapping
  must happen regardless, and a single fail-closed discovery path — one payload
  located, one version derived, then normalized — is a safer invariant than two
  search locations that can disagree.

## Consequences

**Positive**: a stock Ubuntu Core kernel snap can finally build a shuttle image;
the layout mismatch moves from an unbootable artifact at first boot to a
build-time failure with a precise message.

**Negative**: shuttle rebuilds a UKI Canonical already assembled, discarding
upstream's tested embedded command line and any future Canonical signature
chain. The `.sbat` revocation metadata initially dropped here is now carried
verbatim into the rebuilt UKI instead (`objcopy` extraction alongside
`.linux`/`.initrd` and `ukify --sbat=@path`, issue #73; absent or malformed
upstream sections fail the build — a rebuilt UKI without its upstream's
revocation lineage could boot past revocations issued against the
original). The extraction path adds a hard runtime dependency on `objcopy`.
If the deferred UC-compatible (`uc-seed` / GRUB) profile (ADR-0011 §2) is ever
activated, adopt-as-is becomes the correct path for that target and this
extraction machinery is not used there — recorded here as an explicit decision
trigger for revisiting.

## Amendment (#87, 2026-09-14): the Pi payload shape and the piboot backend

### Context

The #74 sanity run measured the real `pi-kernel` 22/stable rev 1137 (arm64,
kver `5.15.0-1103-raspi`) and found a THIRD payload shape, outside both
layouts above:

- `kernel.img` at the snap root — a gzip-compressed ARM64 Image (uncompressed
  header starts with `MZ`: the EFI stub is compiled in, but the wrapper is
  not a PE object `ukify` can assemble);
- `initrd.img` at the snap root — a zstd-compressed initramfs (Canonical's
  snap-bootstrap);
- `modules/<kver>/` with `lib/modules → ../modules` and
  `lib/firmware → ../firmware` symlinks (the "double spelling"; staging's
  merge-overwrite walk is idempotent across both);
- `dtbs/broadcom/` + `dtbs/overlays/` (board device trees),
  `firmware/`, `config-<kver>`, `System.map-<kver>`; no `vmlinuz*`, no
  `kernel.efi`.

Raspberry Pi hardware runs no UEFI loader and no systemd-boot: the GPU
firmware (`bootcode.bin` → `start.elf` family) reads a FAT partition, honors
`config.txt`, loads the board DTB, decompresses gzip-wrapped kernel images
itself, and jumps to the kernel — the `piboot` scheme the pi gadget declares
(`bootloader: piboot` in its gadget.yaml). The measured pi gadget rev 132
(22/stable) makes the chain explicit in its own `boot-assets/config.txt`:

    [all]
    kernel=kernel.img
    cmdline=cmdline.txt
    initramfs initrd.img followkernel
    os_prefix=

The stock UC22 pi volume is MBR + four role partitions, with boot-assets on
`ubuntu-seed`; shuttle's simplified single-boot-partition shape needs none of
the seed model, only the firmware-visible content.

### Decision

1. **The Pi shape is a third accepted payload layout**, located as a
   `pi_raw` payload: `kernel.img`/`initrd.img` are used verbatim at their Pi
   spellings — never unwrapped, never re-assembled, never renamed at
   location time.

2. **`piboot` is the second implemented `bootloader.type`** (next to
   `systemd-boot`; the #71 fail-closed gate now carries two values). The
   payload↔bootloader pairing is enforced at staging: a Pi payload on a
   non-piboot image, and a non-Pi payload on a piboot image, are named
   build-time refusals — no boot chain is silently invented.

3. **The firmware partition is a staging contract**, derived from the
   gadget's own content spec (`boot-assets/ → /`, kernel DTBs → `/` and
   `/overlays`), in this order: kernel-snap board DTBs first
   (`dtbs/broadcom/` — measured; `dtbs/dtbs/broadcom/` accepted as the
   gadget.yaml spelling), then the gadget's `boot-assets/` VERBATIM
   (authoritative where names collide, mirroring the gadget's content
   ordering), then the payload under the names `config.txt` references
   (`kernel.img`, `initrd.img`). `cmdline.txt` is REWRITTEN: declared kernel
   params + `root=PARTUUID=<root>` — the Pi equivalent of the UKI-embedded
   cmdline. `config.txt` keeps every stock line except `initramfs`: the
   payload's initrd.img is Canonical's snap-bootstrap initramfs, which
   mounts a writable `ubuntu-data` and cannot honor a shuttle cmdline
   (the same reason ADR-0025's main text rejects adopting Canonical boot
   assets as-is). The one-line deviation is documented in a generated
   header comment on the file itself.

4. **The piboot build contract is fail-closed, statically audited:**
   - the declared disk is GPT (`root=PARTUUID` needs the read-back GPT
     PARTUUID; the Pi firmware reads GPT — the pi gadget's own TODO notes
     firmware support), with exactly one vfat partition (the firmware can
     read only FAT) and an ext4 root;
   - a gadget snap is declared (the boot-assets source) and its
     `boot-assets/` + the kernel's board DTBs exist — absence is a named
     build error;
   - the no-initramfs boot chain is audited from the kernel config
     (ADR-0024 §1's Pi analog): `CONFIG_EXT4_FS`, `CONFIG_MMC`,
     `CONFIG_MMC_BLOCK` must be `=y` — without an initramfs nothing loads
     modules or runs userspace before the root mount. Measured on the real
     rev 1137 config: all three are `=y`.

5. **Named scope limits — what is NOT assessed on Pi:**
   - **No dm-verity.** The raspi kernel builds `CONFIG_DM_VERITY=m`; the
     mapping needs an initramfs to load the module and run `veritysetup`,
     and shuttle's native initramfs binaries (#75) are host-static, not
     arm64. The piboot root is a plain ext4 partition; the build log states
     this. A `known_good_verity_kernel` allowlist entry for raspi kernels is
     deliberately NOT added: nothing consumes it on this backend.
   - **No boot assessment.** try-boot/revert (ADR-0024 §3) is a systemd-boot
     protocol — boot counters in UKI filenames, `LoaderBootCountPath`,
     `systemd-bless-boot`. The Pi's native analog (`config.txt tryboot` +
     `autoboot.txt` boot_partition= selection, Pi 4 EEPROM bootloader) would
     need per-slot boot partitions each carrying their slot's
     kernel.img/cmdline.txt, plus a health-gated autoboot.txt bless.
     `disk.ab = true` and `update_source` are therefore REFUSED for piboot
     (the emitted sysupdate transfers are the systemd-boot UKI protocol —
     EFI/Linux UKIs and x86-64 partition type GUIDs) rather than shipped
     inert. That refusal is the scope statement: on Pi, factory boot is
     verified; try-boot/revert is future work.

### Alternatives considered

- **Decompress `kernel.img` and boot a UEFI chain.** Rejected: unwrapping
  the payload mutates it (#70's rule: components, never rewrites), and a
  Pi UEFI surface (edk2/RPi firmware or u-boot-as-UEFI) is an extra boot
  component the gadget does not ship — a chain shuttle would have to
  vendor and verify.
- **Adopt Canonical's snap-bootstrap initramfs as the pi initrd.** Rejected
  for the same reason as the main text's adopt-as-is rejection: it mounts a
  writable `ubuntu-data` and ignores the declared cmdline — the integrity
  binding would be inert. The initramfs line is dropped instead; a future
  arm64 native initramfs (#75 cross-compiled) would restore it and carry
  dm-verity with it.
- **Map A/B onto `tryboot` now.** Rejected for this ticket: unverifiable on
  the available hardware/QEMU (raspi3b has no EEPROM tryboot; QEMU's
  raspi machines emulate no firmware at all), so shipping it would be
  exactly the unverifiable boot config shuttle refuses to emit.

### Consequences

**Positive**: a real Raspberry Pi image builds end to end — firmware blobs,
kernel payload, board DTBs, and the declared cmdline land on a FAT
partition the Pi firmware actually consumes; every input is verified at
build time and every gap is a named refusal.

**Negative**: the Pi image boots without dm-verity and without boot
assessment — a weaker integrity/rollback story than the amd64 UKI chain,
documented here as scope rather than hidden. `initrd.img` is staged
(unreferenced) so the payload stays complete on the firmware partition; a
stock-UC-shaped boot could re-enable the `initramfs` line manually.

### Proof level achieved (#87, 2026-09-14)

Build-level and firmware-visible-layout proof, with a partial boot-level
proof — on an x86_64 host with no arm64 hardware:

- **Build**: `shuttle image --file examples/full-system/pi-rootfs/shuttle.lua
  --arch arm64` goes green end to end against the REAL store snaps
  (core22 rev 2956, pi-kernel rev 1137, pi rev 132, snapd rev 27740,
  network-manager rev 953) → `ubuntu-core-pi_22.04_arm64.img` (5636 MB);
  both populate gates (root + firmware partition) are fail-closed —
  measured: a too-small root fails the build loudly.
- **Firmware-visible layout** (offset inspection, no loop device): GPT
  partitions `esp`(p1, vfat)/`root`(p2, ext4)/swap(p3); cmdline.txt on the
  FAT carries the declared params + `root=PARTUUID=` matching p2's read-back
  UUID exactly; config.txt = gadget's with the `initramfs` line dropped and
  the generated header; kernel.img/initrd.img byte-identical (sha256) to the
  snap payload; firmware blobs (bootcode.bin, start*/fixup* families), 12
  board DTBs, overlays/ all present.
- **Boot-level (payload)**: the payload Image (after the gzip unwrap the
  firmware itself performs) boots under `qemu-system-aarch64 -M virt -cpu
  cortex-a53` (TCG) from the banner through driver init to the VFS
  root-lookup — the staged kernel is a live, booting arm64 kernel. The
  audited config carries `CONFIG_CMDLINE_FROM_BOOTLOADER=y` (the
  firmware-provided cmdline protocol this backend depends on) and
  `CONFIG_EFI_PARTITION=y` (PARTUUID root resolution).
- **The named gap**: full-firmware boot proof needs REAL Pi hardware.
  QEMU does not emulate the VideoCore firmware (start.elf/config.txt —
  the very boot component this backend stages), and on the emulated
  `-M raspi3b` board this kernel goes silent before console init (no
  serial, no guest errors), so the emulator cannot close the chain.

**Manual boot recipe** (real Pi 3B/4, SD with the image flashed):

1. `dd` the image to the SD card; `_partx` sees `p1` (firmware, FAT32) and
   `p2` (root, ext4).
2. Serial console on GPIO 14/15 (`console=serial0,115200` is in
   cmdline.txt; add `enable_uart=1` — already in the gadget's config.txt).
3. Power on: the Pi firmware runs bootcode.bin → start.elf from p1,
   applies config.txt, decompresses kernel.img, applies the board DTB +
   overlays, passes cmdline.txt as the kernel cmdline, and jumps to the
   kernel with `root=PARTUUID=` resolving p2 (GPT-aware firmware; Pi 3
   firmware 2017+ / any Pi 4).
4. Expected: kernel mounts p2 (ext4, built-in) and boots the core22
   rootfs; snapd initializes from the seeded snaps (the / snap directory
   carries base/kernel/gadget/snapd/NM).
