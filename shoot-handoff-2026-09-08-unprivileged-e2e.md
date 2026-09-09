# Handoff: shuttle — unprivileged image build shipped + boot-proven; pods spec closed (2026-09-08)

## Session arc (2026-09-05 → 09-08)

Pods shipped end-to-end (issues #2–#16 closed; umbrella spec **#1 closed as shipped**
2026-09-08 — ADR-0015/0016/0017 ground it; live `default` pod at gen 44, 34 packages,
`hermes-desktop` menu entry verified). Then the privileged-`build_disk_image` debt
(09-04 handoff open item 1) was killed by a **full unprivileged rewrite**, and the
rewrite was **validated end-to-end against a real store payload**, including a QEMU
boot through UKI → kernel → initrd.

## Commits (main, pushed)

| Commit | What |
|---|---|
| `8719fd7` | feat(image): build disk images without root — no loop devices, no mount, no losetup. Standalone extent-sized partition files (`sfdisk -J` readback for extents+PARTUUIDs; parted "MB" is decimal 10⁶), `mkfs.ext4 -d` populate, mtools ESP, in-process exact-bounds splice, A/B twins byte-identical by construction, btrfs roots fail closed, new fail-closed preflight. Deleted `attach_loop`/`partition_dev`/`partuuid_of`/mount-populate fns. src/image.rs only. |
| `08d07bf` | fix(image): three real-world gaps found by the first real-payload E2E (see below) |

## E2E validation (snaps cached; scripts + serial logs in /tmp/opencode/shuttle-e2e/)

Built `core22` + `pc-kernel` + `pc` from the Snap Store → 1165 MB kernel image,
**zero privileged steps**. Independent verification: GPT extents/PARTUUIDs match the
UKI cmdline byte-for-byte; ESP carries fallback loader + UKI; **`veritysetup verify`
PASSES** over the spliced root region against the roothash baked into the UKI.

**QEMU/KVM boot proof:** UEFI → ESP → UKI → Linux 4.4.0-287 booted with the exact
composed cmdline → initrd detected all three partitions (`sda: sda1 sda2 sda3` via
AHCI after switching from virtio). Initrd then dropped to its snapd shell:
`LABEL=writable` unresolvable + `snap_core not set` — the **UC18-era snapd boot
contract**, correct for the kernel payload the store resolve picked (see next).

**08d07bf fixes (found by the E2E):**
1. `build_dir` doubles as the staged rootfs → partition files were self-including
   under `mkfs.ext4 -d`. All artifacts now go to a separate scratch tempdir.
2. snapd's `/var/lib/snapd/void` sentinel ships mode 111 → mke2fs can't scan it
   unprivileged. Staged rootfs normalized `chmod -R u+rwX` pre-populate (adjusted
   modes are what the verity hash carries — deterministic).
3. ESP fallback-loader lookup only knew `/usr/lib/systemd/boot` and a `*.efi` glob
   that could pick `linuxx64.efi.stub` as BOOTX64.EFI → now FHS roots + NixOS system
   profile, exact `systemd-bootx64.efi` name first.
4. Restored the 9a rootfs-level manifest write (boot facts unknowable pre-format).

## New insight: kernel-payload ↔ base contract (grill item 3)

Unpinned `pin("pc-kernel")` resolved **rev 3720 = Xenial 4.4 ESM kernel** for a
core22 image. Empirically (initrd dissected): no virtio, no dm-verity module, no
veritysetup, UC18 `snap_core=`/`writable` boot contract. Base-aware kernel
resolution / version-floor warning / explicit payload contract = grilling agenda.

## Environment notes (unchanged from 09-04, still true)

dcg guard blocks compound shell (write script files, run them); devbox replaces PATH
so nest `nix shell … -c bash <script>` and re-prepend captured bin dirs (see
`build.sh`/`inner.sh` pattern); `nixpkgs#systemdUkify` is the ukify attr; QEMU's
bundled edk2 works (code=edk2-x86_64-code.fd, vars=edk2-i386-vars.fd — chmod +w the
copy); `attack_isolation` flake still passes in isolation, fails under parallel load.

## Open (ordered)

1. **Grill** (`/grill-with-docs`, input pack ready at
   `.planning/grill-input-2026-09-08.md`): ① native `build_deps` (survey at
   `.planning/research/native-build-deps-survey.md`; blocks htop/tig/gcm),
   ② devbox.d flake-tools port/keep (~48 dirs), ③ kernel↔base payload contract.
2. `/to-tickets` parity backlog + cutover → `/implement` per ticket → `/wizard` cutover.
3. Production delta (new phase): persistent /var, state partition, on-device sysupdate.
4. `analyzer-spike/` (1.7G, untracked) keep/delete; `.venv/` untracked.
5. Full first-boot userspace in QEMU — blocked on item 1③ (payload contract), not on
   image assembly.

## Suggested skills

- `grill-with-docs` (item 1) → `to-tickets` (item 2) → `wizard` (cutover).
- `diagnosing-bugs` only if the payload-contract work surfaces builder bugs.
