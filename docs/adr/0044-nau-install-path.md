# ADR-0044: Nau bare-metal install — flashed mission images

## Status

Proposed. Drafted 2026-09-27 by a planning session from a four-seat council
review (all four seats: install = write the built image; installer never
builds, never signs). Awaiting operator ratification. Implementation tickets
are gated on ratification.

## Context

Nau is the immutable, verity-protected A/B distribution shuttle assembles
(ADR-0011/0012/0023/0024). The image machinery is complete and deterministic
(#48): `shuttle image` emits a whole-disk GPT artifact — ESP with a UKI
(ADR-0019/0025/0026/0027), two verity-protected root slots, the hash
partitions, and the state partition — assembled unprivileged from plain files
(`src/image/`: `partition.rs`, `verity.rs`, `boot.rs`, `state.rs`). The QEMU
boot-and-assert harness (#50) boots it; the image ships `/usr/bin/shuttle`
(#81); sysupdate transfers carry the A/B update path (ADR-0024).

What does not exist is the install story: no decision on how a person puts
Nau on hardware, no per-mission publication channel, no verification path for
a flashed device. "Installer" in the glossary means the on-device package
operation (ADR-0012/0035) — a different concept; this ADR mints the
install-path vocabulary deliberately (see D6).

The constraint that decides everything: the verity superblock UUID and salt
are derived from the rootfs content, the root/hash GPT GUIDs are derived from
the roothash (`src/image/verity.rs`), and the verity args are baked into the
UKI cmdline at build time (`src/image/boot.rs`). These are mutually consistent
only inside one built `.img`. Any code that lays out partitions or re-derives
a roothash at install time re-opens build-time signing custody — either the
update signing key ships on install media, or devices boot locally-signed
roots and the verified-boot chain (ADR-0011/0024) is dead on arrival.

## Decision

1. **Install = write the built whole-disk `.img` to the target disk.** The
   Fedora IoT/Raw model. Install copies bytes; it never lays out partitions,
   never re-derives a roothash, never signs. The artifact is the installer.
2. **Whole-disk only for 1.0; fixed build-time geometry.** No dual-boot, no
   install-time resizing. The sized-once state partition (ADR-0023) grows to
   fill the disk on first boot via systemd-repart — its own ticket, QEMU-gated.
3. **Cassini target matrix: x86_64 UEFI and Raspberry Pi.** Both boot backends
   exist (systemd-boot and piboot, `src/image/mod.rs`); the Pi is the native
   flash case.
4. **Trust is established at download, not on the device.** A flashed device
   cannot verify its own medium. Each mission publishes the `.img`, a
   `SHA256SUMS`, and the signed image manifest. `shuttle verify-image --device
   /dev/disk/by-id/...` — read-only, unprivileged — proves a written target
   still matches the signed manifest. This verb is the entire 1.0 installer
   surface inside shuttle; the write itself stays documented `dd`.
5. **Publication rides the ADR-0033 Decision 10 static export tree**, named
   `nau-<mission>-<version>-<arch>.img` (ADR-0013 vocabulary). `update_source`
   baked into a released image points at the same lane: install and update are
   one story, and flashing is conceptually "slot A from a local file".
6. **Destructive-write safety.** Devices are named by `/dev/disk/by-id` (or
   serial), never raw `sdX`; targets that are mounted, smaller than the image,
   or carry a recognizable foreign signature are refused without an explicit
   override; confirmations print the resolved device's model and serial
   (the ADR-0032 D5 norm: documented, never silent).
7. **Secure Boot is out of scope for Cassini, recorded here.** UKIs are signed
   at build time under the ADR-0024 ceremony; no on-device signing path exists
   at any point.
8. **Release images for 1.0 are built by one trusted machine** — not the
   worker farm and not hosted CI — with `SOURCE_DATE_EPOCH` pinned and the
   `examples/rebuild-compare.sh` byte-identity check run before signing. The
   farm's fabrication hazard (ADR-0040 D7) is an accepted interim risk for dev
   builds, not a release gate. ADR-0040's determinism cross-check, mechanized,
   is the future admission ticket for farm-built release inputs.

## Alternatives considered

- **Live ISO with an interactive installer.** Rejected for 1.0: a second
  artifact class (live rootfs, ISO pipeline, partitioner UX) that re-runs the
  build-time pipeline against arbitrary hardware, and drags in the signing
  custody problem Decision 1 rules out. It is also a strict superset: a future
  live installer can lay out partitions and then byte-copy this same image;
  nothing built for the flash path is throwaway.
- **Netinstall driven by shuttle.** Rejected: needs a bootable medium to run
  shuttle from (chicken-and-egg), and moves first-boot trust distribution onto
  the network, against the ADR-0033 D7 posture that anchors travel out-of-band
  — a flashed image bakes its trust set; a netinstall device has none yet.

## Consequences

**Positive**: zero new privileged surface (ADR-0035's helper is untouched);
the QEMU-verified artifact is exactly what ships; verification and publication
reuse the ADR-0033 export lane; install, update, and rollback share one
mechanism.

**Negative**: whole-disk, no dual-boot, fixed geometry, and a documented `dd`
as the write step — accepted scope for an operator-and-enthusiast 1.0, stated
here rather than discovered later.

**Neutral**: CONTEXT.md gains *mission image*, *flash*, and *verify-image*
terms when this ADR is ratified (avoid: installer, flasher, ISO for this
path); release media naming enters the mission checklist.

## Revisit triggers

- Sustained demand for dual-boot or install-time partitioning — reopen as the
  live-installer ADR (layout + byte-copy of the same artifact, no re-derive).
- Image size making whole-disk flash wasteful — a `shuttle image write`
  re-layout that reuses `partition.rs`/`verity.rs` and stamps the derived
  GUIDs, booting the same prebuilt UKI.
- ADR-0040 build attestation landing — farm-built package closures become
  admissible release inputs behind the mechanized determinism gate.

## References

- ADR-0011 (runtime ownership), ADR-0012 (store/generations), ADR-0013 (Nau,
  mission naming), ADR-0023 (state partition), ADR-0024 (A/B updates and key
  ceremony), ADR-0032 D5 (documented destructive steps), ADR-0033 D10 (export
  tree), ADR-0040 D7 (worker fabrication hazard).
- Issues: first-boot state growth, `shuttle verify-image`,
  `shuttle image --release` (filed 2026-09-27), ratification ticket.
