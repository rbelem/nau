# Ubuntu Core — Research Synthesis

**Date:** 2026-08-30
**Scope:** How Ubuntu Core works (runtime) and how it is built (image assembly).
**Detailed briefs:**

- `.planning/ubuntu-core-runtime-brief.md` — runtime architecture, boot chain, A/B updates, security, assertions, snapd internals (563 lines, 24 sources)
- `.planning/ubuntu-core-build-brief.md` — ubuntu-image pipeline, gadget.yaml schema, model assertion signing, store interaction, offline builds (757 lines, 17 sources)

---

## TL;DR

An Ubuntu Core system is a **set of squashfs snaps assembled at boot**, not a
traditional rootfs. Its content is declared by a **signed model assertion**;
images are produced by **ubuntu-image** from that assertion plus a **gadget
snap**. The whole pipeline is deterministic data assembly: assertions + partition
layout + snap fetch — no compilation of the OS itself.

---

## 1. Runtime model

### Snap-based OS composition

| Snap type | Role | Examples |
|---|---|---|
| base | The rootfs contents, mounted as squashfs at `/` by `snap-bootstrap` | `core24`, `core26` |
| kernel | Kernel + modules + initramfs, per-device | `pc-kernel` |
| gadget | Partition layout (`gadget.yaml`) + bootloader binaries (shim, GRUB/U-Boot) | `pc` |
| snapd | snapd itself, refreshable independently of the base | `snapd` |
| app | User software, strictly confined | any |

- Everything immutable lives in squashfs under `/snap/<name>/<rev>`; `/snap/<name>/current` symlinks to the active revision.
- Mutable state is confined to `writable` areas backed by the `ubuntu-data` partition (`/var/lib/snapd`, per-user data, system configurations).
- Only snapd, the kernel, gadget, and base run **unconfined**; all app snaps run in strict confinement (AppArmor + seccomp + namespaces + cgroups).

### Boot chain

```
firmware → shim (SecureBoot) → GRUB / U-Boot → kernel → initramfs
        → snap-bootstrap (mounts base snap as root) → snapd (userspace init)
```

- Bootloader environment variables (`snap_mode`, `snap_try_kernel`, `snap_try_kernel_revert`) direct snapd's boot logic; U-Boot and GRUB both integrate with snapd's boot-assets management.
- Four boot modes: **run**, **install** (first boot seeding), **recover** (repair from ubuntu-seed), **factory-reset**.

### Transactional updates (A/B with try-boot)

1. `snapd` refreshes kernel/base/gadget/snapd into a candidate slot.
2. Bootloader env set to `snap_mode=try` with fallback pointers intact.
3. Reboot into candidate. If snapd doesn't confirm health within the boot budget, the bootloader reverts automatically.
4. Gadget boot assets update with edition-based preserve semantics; app snaps revert transactionally via `snap revert`.

### Device identity and policy

- **Model assertion** (signed by brand-id key): declares series, architecture, grade, and the exact kernel/base/gadget/snaps the device must run. The image is a consequence of the model, not vice versa.
- **Serial assertion**: issued on first boot, binds device serial to the brand store.
- **Remodeling** (changing the model) is constrained and requires specific assertions.
- UC24+ full-disk encryption: `grade: signed` + `storage: encrypt`, TPM 2.0-sealed LUKS keys, recovery keys via recover mode.

---

## 2. Build model

### ubuntu-image pipeline (snap mode, 10 internal stages)

```
prepare_image → load model assertion → resolve gadget snap
  → load gadget.yaml → fetch snaps (store REST API by snap-id+revision, or local --snap)
  → build seed tree (/var/lib/snapd/seed: snaps + assertion chain)
  → create GPT partitions per gadget.yaml (ubuntu-seed vfat, ubuntu-boot, ubuntu-data ext4, ubuntu-save)
  → copy boot assets (shim, grub) → mkfs → write disk image (.img/.raw)
```

- Internally delegates snap fetching/validation to snapd's `image.Prepare()` and `seedwriter.Writer`.
- `--snap ./local.snap` injects local snaps and forces `dangerous` grade models.
- **No true offline mode exists**; offline-ish builds require local snaps for every snap in the model.

### gadget.yaml (the partition contract)

- `volumes` → disk geometry, partition table, bootloader (grub / u-boot / lk).
- `structures` → partitions with roles: `mbr`, `system-boot` (kernel+boot assets), `system-data` (writable), `system-seed` (implied), `system-save` (recovery state, UC20+), plus `esp`.
- Filesystem labels snapd expects: `ubuntu-seed`, `ubuntu-boot`, `ubuntu-data`, `ubuntu-save`.
- `update:` semantics per structure control how refreshes mutate partitions; content copied from the gadget snap's dirs (`grub/`, `u-boot/`...).
- Gotcha: "same GUID, different roles" pattern; vfat for seed/boot (readable by bootloader), ext4 for data; seed partition must be sized with headroom for remodeling.

### Model assertion (minimal working set)

Required fields: `type: model`, `series: 16|24|26`, `brand-id`, `model`, `architecture`, `grade` (`signed|dangerous`), plus snap references: `core` (base), `kernel`, `gadget`, and optional `required-snaps`. UC24+ adds `components`. Workflow: `snap create-key` → `snap sign model.assert model.assertion` → `ubuntu-image snap model.assertion`.

---

## 3. Implications for shoot

1. **Image assembly is data assembly.** The pipeline (assertions + gadget.yaml + snap fetch + partition layout) matches shoot's existing shape: Lua-declared data → deterministic artifacts. No compiler-in-the-loop.
2. **`src/image.rs` slot already exists** in `docs/gap-analysis-snapcraft-nix.md` (§ "Image assembly": base + kernel + gadget + extras, GPT/ESP/bootloader). This research defines what that module must produce: a seed tree + gadget.yaml-driven partition layout, not a rootfs build.
3. **A minimal shoot image target** would mirror ubuntu-image's output, not reimplement snapd: seed dir layout, correct fs labels, boot assets copied from a gadget snap, and a signed (or dangerous-grade) model assertion.
4. **Read before designing that phase:** build brief §1 (pipeline), §2 (gadget.yaml), §8 (gotchas — root requirement, vfat constraints, seed sizing); runtime brief §2 (boot chain — what the bootloader must be able to load), §6 (seed layout).

---

## 4. Open questions for later reports to resolve

- Version target: core24 vs core26 seed format differences (UC26 specifics — e.g. Python removal from the base — noted in runtime brief gotchas).
- Whether shoot targets `grade: dangerous` local images only, or signed flows with a self-managed brand store.
- Cross-arch story (amd64 first vs arm64/Pi from the start).
