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
