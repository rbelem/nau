# SquashFS pack performance plan

Date: 2026-09-22, amended after council review the same day. Decision
record: `docs/adr/0041-squashfs-pack-performance.md`.

## Goal

Cut the time shuttle spends packing SquashFS payloads, and measure the
unpack side, without breaking reproducibility, pod install fail-closed
behavior, or snapd compatibility.

## Current state

| Concern | Today | Where |
|---|---|---|
| Pack invocation | `mksquashfs <dir> <out>.snap -noappend -comp xz -all-root` (+ `-no-progress` under parallel dep builds) | src/snap.rs:4240-4269 |
| Default compressor | xz (slowest common option) | src/snap.rs:4242 |
| DSL values | `xz`, `lzo` only | src/dsl/init.lua:174-184, parsed at src/snap.rs:1697 |
| Block size, level, readers | not passed; mksquashfs defaults to 128K blocks | src/snap.rs:4243-4254 |
| Version gate | presence-only in install.sh:76-96; advisory substring check in doctor that misreports 4.7 and false-ok's pre-4.4 | src/doctor.rs:1063-1080 |
| Reproducibility | `SOURCE_DATE_EPOCH` native (4.4+), `POD_BUILD_EPOCH=946684800` | src/pod.rs:4288-4298 |
| Unpack cost | dep payloads re-unpacked on every merged-prefix build, no cache | src/build_prefix.rs:146-167 |
| Concurrency | 3 parallel build workers, RAM and I/O multiply | src/build_sched.rs:31-35 |

## Evidence

Benchmark tree: 26.6 GB, 614k files
([baryluk's squashfs benchmarks](https://gist.github.com/baryluk/70a99b5f26df4671378dd05afef97fce)).
Pack side:

| Config | Time | Ratio |
|---|---|---|
| xz, 128K (mksquashfs default; today's baseline) | ~223 s | 2.84 |
| xz, 1M | ~258 s | 3.02 |
| zstd 15, 256K (mksquashfs zstd default) | ~138 s | 2.74 |
| zstd 6, 1M | ~42 s | 2.69 |
| zstd 6, 256K | ~43 s | 2.59 |
| zstd 6, 512K | ~42 s | 2.64 |
| zstd 3, 512K | ~40 s | 2.55 |
| gzip 1, 512K | ~42 s | 2.34 |
| lz4, 512K | ~41 s | 1.96 |

Unpack side, same source: xz 256K about 31 s, zstd 6 1M about 27 s.
Decompression is I/O-bound end to end, so the zstd switch speeds unpack by
only about 15% wall clock. The compressor change does not fix the
merged-prefix unpack cost on its own.

Supporting facts:

- squashfs-tools 4.7 (June 2025) added parallel readers and removed a
  fragment-packing stall, together 20% to more than 10x on I/O-bound packs
  for any compressor
  ([release notes](https://lkml.org/lkml/2025/6/3/1214),
  [Phoronix](https://www.phoronix.com/news/SquashFS-Tools-4.7)). Older
  releases read from a single thread, the dominant bottleneck there.
- squashfs-tools-ng `tar2sqfs` is slower than mksquashfs on the same
  tree (122 s vs 47 s, [issue #30](https://github.com/AgentD/squashfs-tools-ng/issues/30)).
- snapd reads zstd SquashFS since 2.38 (2019).
- Canonical bundles squashfs-tools 4.7.4 inside snapd's own snap.
- `-Xcompression-level` is implemented for the gzip, lzo, and zstd
  wrappers in squashfs-tools, not for xz. Ranges differ (zstd 1-22,
  gzip and lzo 1-9).

## Work breakdown

Order: harness first, doctor bug fix immediately (standalone), unpack
spike early, compressor change gated on the harness.

1. Benchmark harness plus xz baseline (#152). Amended scope: baseline must
   reproduce production argv exactly (xz at the 128K default) and
   byte-match an unmodified `shuttle build` output; matrix covers the
   block-size and level curve; runs the 3-concurrent-pack shape; benches
   at least two tree profiles (source-heavy, media or already-compressed
   heavy) plus one real shuttle payload; reports unpack and read-side
   numbers per config.
2. Doctor numeric version parse, 4.7 advice, unsquashfs zstd check (#155).
   This is a live bug fix: the substring check misreports 4.7 and
   false-ok's pre-4.4 tools. No dependencies; lands in parallel with
   #152.
3. Unpack spike (#156). Runs immediately after #152. The decompression
   numbers show the compressor switch does not subsume it. Measures both
   the xz baseline images and, once available, the zstd images.
4. zstd default with explicit level 6 and 1M blocks on the zstd path, DSL
   `compression_level` knob with per-compressor validation, zstd support
   probe (#154). Gated by #152 per tree profile. Absorbs the former #153:
   unconditional `-b 1M` fails its own gate on the xz path (about 16%
   pack-time regression), so block size travels with the zstd default.
5. Former #153 is closed as superseded by #154.

Gates from ADR-0041 decision 5: at least 2x pack speedup and at most 10%
image-size regression per tree profile. Read-side and unpack numbers are
reported, not gated, until measured.

## Rejected and deferred options

- squashfs-tools-ng: rejected (slower, no streaming need).
- backhand: rejected for now; revisit only if dropping the external
  squashfs-tools dependency becomes a goal.
- Vendoring squashfs-tools 4.7.4: deferred; doctor advice covers the gap.
- `-no-fragments`: not taken; read-side numbers will inform any revisit.
- lzo as default: rejected (dominated by zstd).
- gzip in the DSL: rejected (dominated by zstd on both axes; speculative
  flexibility).

## Open questions

- Whether pod store blobs are ever served over the network (src/serve.rs),
  which would turn the 5.5% size cost into a recurring bandwidth cost.
  One quantification, then close or act on it.
