# Kernel-snap payload layout: accept raw components and a prebuilt UKI

## Status

Accepted (2026-09-11). Amends ADR-0011 step (a) (boot-chain fix, UKI via
`ukify`). Grounded in the first end-to-end dogfood (2026-09-11), issue #70.

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
`root=PARTUUID=<uuid>` and the dm-verity `roothash=<hash>` — is the integrity
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
upstream's tested embedded command line, its `.sbat` revocation metadata, and
any future Canonical signature chain (the dropped `.sbat` is tracked
separately). The extraction path adds a hard runtime dependency on `objcopy`.
If the deferred UC-compatible (`uc-seed` / GRUB) profile (ADR-0011 §2) is ever
activated, adopt-as-is becomes the correct path for that target and this
extraction machinery is not used there — recorded here as an explicit decision
trigger for revisiting.
