# shuttle owns the system runtime; native snapd-free image target

## Status

Accepted (2026-08-31). Grounded in `.planning/cross-distro-synthesis.md` (rev 2/3) and a three-seat council review with fresh local-code and 2024-2026 ecosystem research.

## Context

shuttle assembles bootable images from snaps. Three decisions were open: who owns day-2 (updates/rollback), which image target (snapd-compatible Ubuntu Core-style vs snapd-free native), and what "do not lose security features" binds.

Verified starting point (council-verified, file:line): today's images have **zero** security guarantees — `build_disk_image` copies the rootfs onto a mutable btrfs/ext4 partition (`src/image.rs:992-995`), the ESP gets no kernel and no loader entries (images likely cannot boot), declared kernel params reach nothing, and app snaps are copied as inert squashfs blobs that nothing mounts or executes. Research findings: snapd-only capabilities are dynamic interface composition, snap-level D-Bus mediation, per-app home remapping, and strict confinement on Ubuntu's out-of-tree AppArmor patches; boot trust, image integrity, and trusted A/B updates are fully achievable snapd-free (UKI + systemd-measure PCR, dm-verity, systemd-sysupdate, systemd-cryptenroll) — the same mechanisms Ubuntu Core uses, kernel-enforced instead of daemon-enforced.

## Decision

1. **shuttle owns the runtime**: updates, rollback, installs, and health are shuttle's job (the distro, ShuttleOS), not snapd's and not an admin's.
2. **Native snapd-free image target.** Ubuntu-Core-compatibility is a *gated future profile*, not a roadmap item: the Phase-23 manifest IR stays target-agnostic (`target = native | uc-seed` chosen at assembly, never at eval); no compat code until a consumer exists. The hybrid (native base + snapd as bare confinement enforcer) is rejected: two runtime owners split update trust and undermine image integrity with mutable snapd state.
3. **Security values call**: parity or better with Ubuntu Core on **boot trust, image integrity, and update trust**. Per-app confinement is delivered as build-time systemd directives translated from snap metadata (one profile taxonomy) with an explicit build-time lint when `confinement: strict` cannot be honored; snapd's dynamic strict confinement (interfaces, D-Bus mediation, home remap) is formally not delivered.
4. **Security stack, in build order**: (a) boot-chain fix — real kernel + loader entries on the ESP, UKI via `ukify` so kernel params land (correctness gate, needed under every answer); (b) snap-revision assertion verification at resolve time — the current sha3-384 Store pin is TOFU (hash taken from the same API response as the URL); (c) dm-verity over the squashfs root partition with roothash in the signed UKI cmdline (kernel config check for `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` on shipped kernels; fallback: roothash bound via UKI/PCR); (d) updates via **systemd-sysupdate** — A/B partitions, GPG-verified manifests, tries-left boot assessment — with the signed Phase-23 image manifest as the model-assertion analog; (e) a key ceremony (generation, rotation, revocation) as a first-class Phase-24 deliverable; (f) **Phase 24a, app execution** — extract/merge app payloads and emit hardened units (`SystemCallFilter`, `ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet`, `PrivateUsers`), plugs → directives with explicit warn-and-drop; shoot-built packages only; (g) the confinement lint from (3).
5. **Daemon law** (amends synthesis §4): no privileged long-lived daemon ships. Runtime features are emitted systemd units/timers plus short-lived shuttle commands (sysupdate is systemd's own machinery and complies).
6. **Deferred**: composefs for the base image, SELinux, remote attestation, RAUC, bootc, delta transport, Flatpak (documentation only).

## Alternatives considered

- **Ubuntu Core-compatible target (b)**: contradicts (1) — snapd owns the UC runtime; imports the assertion bureaucracy and store dependency; requires Ubuntu-patched kernels for strict confinement.
- **Hybrid**: worst ledger — classic-mode confinement (weaker, still needs Ubuntu patches) plus mutable snapd state plus a split update trust domain.
- **Builder-only forever**: reopens later at higher cost; rejected in favor of owning the stack.

## Consequences

**Positive**: parity-or-better with UC on integrity, boot, and update trust, kernel-enforced; one coherent trust domain; all machinery is stock systemd/kernel — no daemons, offline-first preserved.

**Negative**: dynamic per-app confinement (interfaces, D-Bus mediation, home remap) is genuinely absent — GUI apps wanting snap-strict semantics have no native answer; self-managed keys concentrate trust in the key ceremony (mitigated by (4e)); shipped kernels must be audited for the dm-verity signature config; images from before this ADR could not boot or run apps — no migration path is owed.

---

## Kernel-config audit (closed 2026-09-04)

Supersedes the standing "remaining open" item ("shipped kernels must be audited for the dm-verity signature config") and the Context caveat *"images likely cannot boot"* — Superseded 2026-09-04: a shuttle-assembled disk with a shuttle-built UKI booted to a dm-verity-verified root, and userspace (busybox PID1 and systemd 261.1) ran **from** the verified device (QEMU missions, evidence `/tmp/opencode/shuttle-verity/` and `/tmp/opencode/shuttle-userspace/`, 2026-09-04).

Config source: nix kernel 6.18.45 build config, `/nix/store/qb1vm5aig0w3vp40bs508aif5fjqhky2-linux-6.18.45-dev/lib/modules/6.18.45/build/.config` (modules output `/nix/store/nggv3k0czjx0x245gsmbijnwvy1p0yyn-linux-6.18.45-modules`). Behavioral confirmation from `/tmp/opencode/shuttle-verity/logs/boot.log`.

| Option | Status | Evidence |
|---|---|---|
| `CONFIG_VIRTIO_BLK` | `=m` (module) | `.config`; guest: `virtio_blk virtio1: [vda] …` (boot.log:412) |
| `CONFIG_VIRTIO_PCI` | `=m` (module) | `.config`; guest insmod + `/proc/modules` Live (boot.log:402-411) |
| `CONFIG_DM_VERITY` | `=m` (module) | `.config`; guest `veritysetup status`: `type: VERITY / status: verified` (boot.log:462-463) |
| `CONFIG_BLK_DEV_DM` (dm-mod) | `=m` (module) | `.config`; `/proc/modules` `dm_mod … Live` (boot.log:430) |
| `CONFIG_EXT4_FS` | `=m` (module) | `.config`; verified root mounted ext4 ro (boot.log:447) |
| `CONFIG_CRYPTO_SHA256` | `=y` (built-in) | `.config`; dmesg `verity: sha256 using "sha256-lib"` (boot.log:445) |
| `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG` | **not set (absent)** | `.config`: `# CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG is not set` |

**VERIFY_ROOTHASH_SIG consequence**: the kernel performs no roothash signature verification against the system keyring — the signature-enforcement path of step (c) is unavailable on this kernel. Per the ADR's declared fallback, roothash trust binds via the signed UKI cmdline only; enabling signature enforcement would require a rebuilt kernel with this option (and provisioned keyring keys).

**Module-in-initrd requirement**: virtio block/PCI, dm-mod, dm-verity, and ext4 are all `=m`, so every shipped kernel image must carry these modules in its initrd — a bare kernel + busybox initrd cannot even see the disk (the disk-mission no-vda finding: no `vda` until `virtio_blk` is loaded). The proven recipe ships the flat dep closures (13 modules for this kernel) and insmods them in dependency order from `/init`. `doctor`'s kernel audit treats `CONFIG_DM_VERITY=m` kernels with boot proof as confirmed (`ConfirmedByProof`), not Unconfirmed.
