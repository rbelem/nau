# #80 — execute systemd-sysupdate end to end (QEMU network + a second, genuinely different generation)

This directory holds the harness that executes `systemd-sysupdate` **in a
guest**, end to end: a gen-1 device is built, booted once (it fetches the
payload over QEMU SLIRP networking and installs generation 2 into the
`_empty` slot), then booted again so the counted UKI (`+3-0` → `+2-1`) is
observed on the ESP through a real update — not a hand-planted UKI.

## Contents

| file | purpose |
| --- | --- |
| `gen1.lua` | the factory device: A/B disk (slot B ships `_empty`-labeled), `update_source` pointed at `http://10.0.2.2:8123/` (QEMU SLIRP's alias for the host loopback), the sysupdate service pulled into the first boot via `systemd.wants=` |
| `gen2.lua` | the update payload build: version 2.0, health gate `/bin/false` so the counted UKI is never blessed — the `+3-0` → `+2-1` decrement stays observable |
| `gen2-bless.lua` | same payload with health gate `/bin/true`: the boot-complete.target ceremony runs and the counter suffix is shed (bless path) |
| `proof/` | per-generation proof oneshots (`shuttle-80-proof.service` echoes the generation into the boot), the clean-poweroff oneshot, the `/etc/generation` marker, the journald console drop-in |
| `prepare.sh` | stages the guest sysupdate tooling, builds all three images, extracts the payload artifacts (`root_@v_@u.img`, `verity-hash_@v_@u.img`, `<name>_@v.efi`) plus `SHA256SUMS` from the payload build's slot A |
| `tools/` | `http-fetch`: a ~200-line Rust stand-in for `systemd-pull` (see "Why a fetcher stand-in" below) |
| `local/` | (gitignored) populated by `prepare.sh`: the anchored fetcher binary and payload-tooling copies |

## Why the base rootfs needs staged tooling

The Ubuntu Core 22 base ships no `systemd-sysupdate` (added in systemd 256;
the base has 249) and no libcurl/libfdisk for it. `prepare.sh` therefore
copies the host's systemd 261 `systemd-sysupdate` binary plus
`libsystemd-shared-261.so` into the image, anchored to the guest loader
(`/lib64/ld-linux-x86-64.so.2`); the binary's highest GLIBC symbol
requirement is 2.34 and the guest's glibc is 2.35. systemd-pull itself is
replaced by `tools/`'s ~200-line HTTP fetcher because the real puller
dlopens libcurl (whose closure needs glibc ≥ 2.36 for
`GLIBC_ABI_GNU2_TLS`); the fetcher speaks exactly enough HTTP for the
plain-file payload server.

## The transfer contract (what makes the installed slot bootable)

The emitted transfers name artifacts `root_@v_@u.img` /
`verity-hash_@v_@u.img`: the `@u` wildcard encodes the GPT PARTUUID that
sysupdate assigns to the written slot (`PartitionUUID=` semantics,
sysupdate.d(5) Example 1). The payload build derives both GUIDs from its
dm-verity roothash (`generation_guids_from_roothash`), pins them onto its
own slot A, and bakes the same GUIDs into the UKI cmdline — so the UKI
installs onto the slot sysupdate prepared, whichever physical slot that is.
Factory slot B carries the literal `_empty` label (the DPS marker
sysupdate treats as a writable slot); the running version (`%A`) is
protected and is never recycled.

## Reproduce

```sh
# 0. prerequisites: devbox shell (cargo, patchelf, sfdisk, mtools, debugfs,
#    e2fsprogs), a package-index.json with core22 pins (repo root)
devbox run -- bash prepare.sh                 # builds gen1 + gen2 + gen2b and extracts payloads

# 1. serve the gen-2 payload (host loopback; the guest reaches it as 10.0.2.2)
cd "$WORK/payload-gen2" && python3 -m http.server 8123 --bind 127.0.0.1 &

# 2. phase A — first gen-1 boot performs the in-guest update
cp "$WORK/images/gen1/shuttle-80_1.0_amd64.img" "$WORK/live/live1.img"
devbox run -- target/debug/shuttle test "$WORK/live/live1.img" --runs 1 --timeout 1500 \
    --log "$WORK/evidence/A-update.serial.log" \
    --require "Finished shuttle: apply systemd-sysupdate A/B updates" \
    --require "Reached target Multi-User System" \
    --require "payload proof: generation 1" \
    --qemu-arg=-nic --qemu-arg user,model=virtio-net-pci

# 3. phase B — two counted boots: the ESP shows +3-0 then +2-1
devbox run -- target/debug/shuttle test "$WORK/live/live1.img" --runs 2 \
    --expect-counter-seq "3-0,2-1" --timeout 300 \
    --log "$WORK/evidence/B1-counting.serial.log" \
    --require "payload proof: generation 2" \
    --require "Reached target Multi-User System" \
    --qemu-arg=-nic --qemu-arg user,model=virtio-net-pci
```

`sequence.json` in the phase-B run directory is the machine-checked
counter evidence; the per-boot `*.esp.txt` listings are the ESP evidence
for the tries suffix (`shuttle-80_2.0+3-0.efi` installed by sysupdate,
`+2-1` after the loader's counted rename).

## Product changes this proof required (all in `src/`, unit-tested)

1. **Executable transfer files** (`src/image/boot.rs`): the emitted
   transfers previously used `Path=%v/root.img` (`%v` is the kernel
   release specifier, not the update version), a nonexistent
   `Path=in-places`, no `[Source] MatchPattern=`, and a `{name}_empty`
   pattern arm that is not the DPS `_empty` marker — none of which a real
   systemd-sysupdate accepts. They now carry a base-URL `Path=`,
   `@v`/`@u` source patterns, `Path=auto`, and root-relative
   `/boot/EFI/Linux` for the UKI (avoids the guest's `$BOOT` discovery).
2. **DPS slot identity** (`src/image/verity.rs`, `src/image/mod.rs`): the
   slot-A data/hash partition GUIDs are derived from the dm-verity
   roothash and pinned via `sfdisk --part-uuid`, and the same GUIDs ride
   the transfer `@u` wildcards — so one UKI boots both the built image
   and the update-installed slot.
3. **Factory slot B labeled `_empty`** (`src/image/verity.rs`): the
   running version is protected (`ProtectVersion=%A`), so a version-
   labeled clone in slot B would leave the first update no writable slot.
   The byte-identical clone content stays; only the label says "unused".
4. **`files =` image DSL** (`src/dsl/init.lua`, `src/image/mod.rs`,
   `src/lua.rs`, `src/image/staging.rs`): stage extra host files into the
   rootfs before it is hashed (needed for the sysupdate tooling the base
   lacks).
5. **`shuttle test --qemu-arg`** (`src/cli.rs`, `src/main.rs`,
   `src/boot_test.rs`): pass-through QEMU argv tokens, used for guest
   networking (`--qemu-arg=-nic --qemu-arg user,model=virtio-net-pci`).

## Evidence

The runs archive serial logs, per-boot ESP listings and `sequence.json`
under `~/.cache/shuttle-80/evidence/` (paths printed by the commands
above), plus a post-mortem (`sfdisk -J` + `debugfs`) proving slot A holds
generation 1 and slot B generation 2 with the payload-derived PARTUUIDs.

## #86 — a killed install strands the target slot (reproduce + recover)

A sysupdate install killed mid-transaction leaves the target slot
unusable, and systemd 249 has no `vacuum` verb to clear it: the NEXT
update refuses (`Selected update '2.0' is already acquired and partially
installed. Vacuum it to try installing again.`) — a clean #63 fallback
device becomes permanently stuck on one generation.

**Measured strand signature** (kill during the 50-verity transfer, after
50-root finalized): slot B root carries the FINAL `2.0` label + `@u`
PARTUUID but a masked placeholder TYPE GUID; the hash slot carries the
final label, a masked type and a random PARTUUID (`@u` never ran); the
ESP has no 2.0 UKI. Masked types make both partitions invisible to
`MatchPartitionType` AND they do not read `_empty` — no writable target.

**The invariant** (`shuttle runtime recover-slots`,
`src/slot_recovery.rs`): a slot label is valid only while its UKI was
fully written (structurally: a PE whose section table fits the file) and
the update was declared installed. Label-without-bootable-UKI ⇒ stranded
⇒ restore the flavor type (where masked) + relabel `_empty`. The running
version (`%A`) is never touched; nothing is reclaimed unless the running
version's own UKI is present (the sentinel proving the ESP listing is
real); every other odd state surfaces as a named anomaly, never an
action. The emitted `shuttle-slot-recovery.service` oneshot runs this at
boot, `Before=systemd-sysupdate.service`, on the same gate as the
transfers.

**Reproduce** (S = control `gen1-strand.lua`, recovery masked via
`systemd.mask=`; R = treatment `gen1.lua`; both images carry the #86
unit; the payload is unchanged, served from `~/.cache/shuttle-80`):

```sh
# 0. build + stage (prepare.sh builds gen1-strand too; the payload from
#    the #80 wave is reused as-is)
export SHUTTLE_80_WORK="$HOME/.cache/shuttle-86"
devbox run -- bash prepare.sh

# 1. S1/R1 — strand creation: serve the payload with the throttling
#    server; the guest's verity-hash fetch dies (EAGAIN on the delayed
#    body) AFTER the root transfer finalized
python3 tools/strand-server.py ~/.cache/shuttle-80/payload-gen2 8123 &
devbox run -- target/debug/shuttle test "$WORK/images/<S-or-R>/shuttle-80_1.0_amd64.img" \
    --runs 1 --timeout 900 --log "$WORK/evidence86/<phase>.serial.log" \
    --require "payload proof: generation 1" \
    --qemu-arg=-nic --qemu-arg user,model=virtio-net-pci
#    → sfdisk -J: partitions 5/6 masked types + 2.0 labels; ESP: no 2.0 UKI

# 2. S2 — the native re-run (unthrottled `python3 -m http.server`): the
#    update refuses; `systemd-sysupdate list` assesses 2.0 as
#    `current+partial` and 1.0 as `protected`. Stuck forever.
# 3. R2 — the recovery boot (unthrottled server): the oneshot relabels
#    both halves `_empty` (serial lines `slot-recovery: relabeled ...`),
#    the SAME update transaction then finishes
#    ("Finished shuttle: apply systemd-sysupdate A/B updates") and the
#    ESP gains shuttle-80_2.0+3-0.efi.
```

Evidence: `~/.cache/shuttle-86/evidence86/` — per-phase serial logs,
`*-partitions.json` GPT dumps and `*-esp-listing.txt` (S1 strand state,
S2 refusal, R2 relabel+retype+success).

**Proof-harness plumbing note**: the build-host embed of `/usr/bin/shuttle`
(#81) needs glibc ≥ 2.38 and could never exec on the core22 guest
(measured: `GLIBC_2.39 not found` — the #80 logs show the same for the
activate oneshot). Both gen1 lulas therefore stage a guest-runnable copy
(`local/nix/shuttle-guest`: the same build with RUNPATH into the nix
glibc/gcc dirs already staged for the sysupdate tooling). Product images
keep the #81 embed untouched.
