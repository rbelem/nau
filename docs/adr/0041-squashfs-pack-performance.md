# zstd snap packing: default compression, explicit level, 1M blocks

## Status

Proposed (2026-09-22), amended the same day after council review. Extends
ADR-0005 (mksquashfs subprocess for snap packaging). The evidence table and
ticket breakdown live in `.planning/squashfs-performance-plan.md`.

## Context

`build_snap` (src/snap.rs:4240-4269) is the only production pack site. It
shells out to `mksquashfs <build_dir> <out>.snap -noappend -comp
<compression> -all-root`, where `compression` defaults to `xz` and the DSL
restricts it to `xz` or `lzo` (src/dsl/init.lua:174-184). No block size, no
compression level, no reader or processor knobs are passed. Every `shuttle
build`, `pod sync`, `pod add`, and `pod rebuild` pays this pack cost, and
`MAX_PARALLEL_BUILD_WORKERS = 3` (src/build_sched.rs:31-35) multiplies its
RAM and I/O footprint across workers.

xz is the slowest common SquashFS compressor. mksquashfs defaults to 128K
blocks, which is what `build_snap` runs today. On a 26.6 GB, 614k-file
benchmark tree that baseline packs in about 223 s (ratio 2.84). zstd level 6
at 1M blocks packs the same tree in about 42 s (ratio 2.69): roughly 5.3x
faster for about 5.5% larger images. Block size is the bigger lever and the
two must be chosen together: level 3 at 512K is about 40 s at ratio 2.55,
level 9 at 1M costs about 54 s for almost no size gain, and mksquashfs' own
zstd default level is 15, which lands near 138 s. So both the level and the
block size have to be explicit. zstd decode speed is largely level
insensitive, so the level choice does not cost mount-time read performance,
and zstd decodes several times faster than xz.

Reproducibility is already native: `SOURCE_DATE_EPOCH` (mksquashfs 4.4+)
plus `POD_BUILD_EPOCH` (src/pod.rs:4288-4298) make identical trees produce
identical bytes, and the payload cache keys on that. Compressor output is
deterministic for a fixed input, level, and compressor-library version. The
compressor library was already part of this implicit toolchain (liblzma for
xz); it is not a new class of dependency.

Runtime compatibility is not a blocker on the pack side. snapd reads zstd
SquashFS since 2.38 (2019). Shuttle's own install path reads payloads
through unsquashfs, which needs a squashfs-tools build with zstd enabled.
That is standard on Debian 12+, Ubuntu 22.04+, Fedora, Arch, and NixOS. A
tools build without zstd fails at pack time with `Compressor not supported`.
The unpack side needs its own check: a zstd payload can reach a machine that
never packed it, through sideload (ADR-0037) or a shared pod store.

squashfs-tools 4.7 (June 2025) parallelized the reader stage
(`-small-readers`, `-block-readers`) and eliminated a fragment-packing
stall, together worth 20% to more than 10x on I/O-bound packs for any
compressor. Distro availability in late 2026 is still uneven, so it cannot
be a hard requirement yet. `install.sh` checks tool presence only (lines
76-96) and `doctor` advisory-checks the version by substring
(src/doctor.rs:1063-1080). That substring check misreports today: it calls
4.7 "untested" and reports ok for pre-4.4 tools that lack
`SOURCE_DATE_EPOCH`.

## Decision

1. The default snap compression changes from xz to zstd, packed with
   explicit `-b 1M -Xcompression-level 6`. The new argv applies to the zstd
   default path only. An explicit `compression = "xz"` keeps today's argv
   unchanged, because the published numbers show 1M blocks regress xz pack
   time by about 16% (258 s vs 223 s at the 128K default).
2. The DSL `compression` field accepts `zstd`, `xz`, and `lzo`. A new
   optional integer field `compression_level` is validated at the DSL
   boundary: allowed for zstd (1-22) and lzo (1-9), rejected for xz, whose
   mksquashfs wrapper does not implement `-Xcompression-level`. The Rust
   parser stops accepting arbitrary compression strings (src/snap.rs:1697).
3. zstd support is probed before the pack. The probe resolves mksquashfs
   through the same PATH mechanism the pack uses, runs one tiny pack with
   the requested level, and caches per resolved binary path. Without zstd,
   the pack fails closed with an actionable error that names
   `compression = "xz"` as the escape. No silent fallback: payload
   sha3-384 pins are the idempotency guarantee (src/pod.rs:4283-4288), and
   a silent compressor switch would change pins across machines for
   identical declarations.
4. `doctor` parses the version numerically and advises 4.7 or newer for
   parallel readers. This fixes the live misreport described above. Doctor
   additionally checks unsquashfs zstd read support, since sideloaded
   payloads can reach machines that never packed them. Checks stay
   advisory and `install.sh` stays presence-only.
5. The rollout is gated on measurement, evaluated per tree profile: at
   least 2x pack speedup and at most 10% image-size regression against the
   xz 128K baseline. The harness must reproduce the production argv
   byte-for-byte, measure the 3-concurrent-pack shape, and report unpack
   and read-side numbers without gating on them initially.

## Alternatives considered

- **squashfs-tools-ng** (`tar2sqfs`, `sqfstar`): slower than mksquashfs on
  the same tree (122 s vs 47 s, upstream issue #30), and shuttle already
  stages a plain tree, so its streaming design buys nothing here. Rejected.
- **backhand** (Rust SquashFS writer): would drop the external binary
  dependency, but it is single-image and single-thread oriented and loses
  to mksquashfs' thread pool. Rejected for now; revisit only if removing
  the squashfs-tools dependency becomes a goal.
- **Vendoring squashfs-tools 4.7.4**: deferred. The doctor advice covers
  the gap; snapd's own snap already bundles 4.7.4 as precedent if pod
  builds stay I/O-bound.
- **`-no-fragments`**: helps launch time, costs image size, and pack time
  is not fragment-bound. Not taken. The harness read-side numbers will
  show whether fragment packing interacts with 1M blocks before anyone
  revisits this.
- **lzo as default**: strictly dominated by zstd (similar speed, worse
  ratio). It stays selectable and never becomes the default.
- **gzip in the DSL**: dropped. The evidence table shows gzip strictly
  dominated by zstd on both axes; adding it would be speculative
  flexibility.

## Consequences

Positive: roughly 5.3x faster packs on the default path at about 5.5%
larger images. zstd's lower per-thread memory use reduces RAM pressure
across the 3 build workers compared with xz dictionaries. Knobs become
explicit, the version advisory becomes actionable, and doctor stops
misreporting 4.7.

Negative: payload bytes change once per machine as new sha3-384 values
land, and mixed old/new shuttle fleets hold both variants under different
hashes. Cross-machine pin identity now requires the same squashfs-tools and
libzstd on every machine that rebuilds or pins a pod, and machines using
the xz escape pin differently from zstd machines. Both behaviors are the
correct fail-closed outcome, but they can surface as pin mismatches across
a fleet. The zstd level 6 images are about 5.5% larger on the benchmark
tree, and content-dependent gaps can be wider in either direction.

Neutral: xz remains for size-critical snaps. Snaps intended for Snap Store
upload, where download size reaches end users, should pin
`compression = "xz"`. 1M blocks amplify small random reads on mounted
images; shuttle consumes payloads by unsquashfs extraction, where block
size is neutral to positive, but the harness reports read-side numbers so
the tradeoff stays visible.
