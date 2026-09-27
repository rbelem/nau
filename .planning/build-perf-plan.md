# Build performance plan

Date: 2026-09-27. v3 — council review round 2 complete (4/4
agree-with-changes, corrections folded); Jev review of this version
follows. Produced by the build-slowness investigation (three read-only
lanes), corrected by a four-seat council review, amended with field
evidence from sibling agent sessions over herdr, then re-corrected by the
second council round. Companion docs: `.planning/remote-cache-plan.md`
(networked cache), `.planning/squashfs-performance-plan.md` (pack work,
partially landed). Feeds tickets; changes no code by itself.

## Goal

Cut the daily `shuttle build --all` loop and single-package rebuilds, in
that order, without breaking reproducibility (byte-identical artifacts,
sha3-384 pins), snapd compatibility, or ADR-0039's offline sandbox.
Success is measured against the #152 benchmark harness plus live profiles
of both real loops, not against intuition.

## Verified findings

Citations re-verified by the second council round against the tree of
2026-09-27 (one drift found and fixed: the 1115 lookup site no longer
exists). Labels: read (code), measured (harness/docs numbers), field
(observed in live agent sessions 2026-09-27).

| # | Finding | Where | Cost shape | Label |
|---|---|---|---|---|
| 1 | Top-level outputs never read from nor written to the build cache. Deps skip rebuilds via `in_output.exists()`; named outputs repay gcc/glibc and full packs daily | src/main.rs:1396-1481 (`build_one_arch`, no `cache.lookup`, no `cache.store`); lookups 612/946 and stores 991/1336 are dep-only; dep skip main.rs:938 | dominant, daily | read |
| 2 | Merged prefix rebuilt per package per arch: unsquashfs every dep payload + full `fs::copy` + wrapper rewrite, no cache, tempdir per call | src/build_prefix.rs:124-142, 157-179, 761, 140 (fail-closed guards 218-223) | large on cache-miss builds; shrinks after fix 1 | read |
| 3 | Closure/eval storm: quadratic subprocess evals, multiplicative with full-tree re-hash of pinned inputs; extra walks at main.rs:851, 1065, leak_scan.rs:156 | src/main.rs:1085-1099, 589-599; src/deps.rs:248; src/isolate.rs:485; src/pkg_source.rs:841-860 | grows with index size; becomes the daily floor after fix 1 | read |
| 4 | Source tarballs never cached; curl into fresh tempdir per build; the sha256 pin is pre-known only for warm-lockfile pinned sources | src/snap.rs:4881-4896, 4905; src/main.rs:1494-1503 | network round-trip per recipe per build | read |
| 5 | mksquashfs never receives `-processors`; pinned 4.7.5 floor tools support parallel readers (zero `processors` hits in src/; the probe argv at snap.rs:4510-4518 is intentionally untouched) | src/snap.rs:4678; recipes/tools/pins.conf:23 | one line against the measured 42 s pack, every cache-miss | read |
| 6 | Cache governance: activates unconditionally under `--all` (not opt-in), default root, prune fires only when `--cache-max-size` was passed — unbounded growth; leaked build tempdirs and per-lane `target/` trees compound it | src/main.rs:776; src/cache.rs:423-429 (prune gated on `max_size`) | disk exhaustion; ENOSPC presents as link failures, not disk errors | read + field |
| 7 | Existence-only lookups serve truncated or stale bytes — three independent instances of one defect class: (a) the pkgs cache (existence-only lookup cache.rs:377, plain `fs::copy` store :412); (b) the pod downloads dir, which is WEAKER: keyed on `name_version_arch` with no closure key at all plus a `force_build` bypass (src/pod.rs:5949-5956); (c) build.rs's cmake sentinel extraction (stale headers after a vendored-source bump) | src/cache.rs:365-382; src/pod.rs:5938-5957; field: ~63 GB leaked `/tmp/.tmpXXXXXX` from Sep 19-27; truncated python snap from a two-sync race | correctness gate, not polish | read + field |
| 8 | Leak scan: serial full-stage walk per real build | src/leak_scan.rs:171-191 | vanishes on cache-hit days after fix 1 | read |
| 9 | Parts serial inside a package; stage-merge ADR never written; worker pool default 3 but `workers.local_jobs` raises it with zero code — note `pool_budget` is consulted only on the dep phase (main.rs:1188), so this knob does not touch pod sync at all | src/snap.rs:5643; docs/adr/0022; src/build_sched.rs:45, 113-120, 39-44 | differentiation, not parity | read |
| 10 | gcc/glibc multi-hour source builds by policy (no deb ingestion) | docs/adr/0021; docs/agents/devbox-deprecation-plan.md | one-time if the cache persists; otherwise daily | recorded |
| 11 | Pack cost already fixed: zstd 6 / 1M = 42 s vs xz 223 s on 26.6 GB (~5.3x, 5.5% larger) | docs/adr/0041 | done; relevant only on cache-miss | measured |

Gotchas carried from review: the default `./stage` flock refuses a second
concurrent process (`LOCK_EX|LOCK_NB`, src/snap.rs:3137-3145, taken once
per process at :3180-3191) — it does not queue, and it does not stop
in-process packs from multiplying; adopt-info and store snaps are never
cacheable (src/cache.rs:365-402) and become the residual daily cost after
fix 1; the v4 key omits compression/env/toolchain (arch lives in the
filename, cache.rs:376) and post-ADR-0041 a v4-keyed lookup can serve
stale xz artifacts.

## Ordered plan

Reconciled by two council rounds (round 2: 4/4 agree-with-changes) and
amended with field evidence. Each item names its acceptance check.

0. **Now, zero code.** Raise `workers.local_jobs` in `shuttle.lua`.
   Correct mechanism notes from review: the flock is inter-process only,
   so raising the pool puts N mksquashfs in flight inside one process —
   the 16 s ↔ 66 s swing in the field evidence is exactly this shape.
   The knob acts on the dep phase only (`pool_budget` at main.rs:1188).
   Gate on RAM and I/O headroom (build_sched.rs:39-44's stated reason),
   not disk headroom alone.
   Acceptance: dep-phase wall clock drops with no thrash; pack wall clock
   on the pinned harness does not regress.
0b. **Scratch hygiene (field-driven, rescoped by council round 2).**
   Facts first: `tempfile::tempdir` already deletes on Drop (pod.rs:5859)
   — the leaks are SIGKILL/timeout paths where Drop never runs, so a
   startup sweep IS the mechanism, not "cleanup-on-drop plus a sweep."
   Scope: sweep only shuttle-owned temp-name prefixes, gated on age plus
   liveness (pid-stamp or store lock), never payload names; the pod
   downloads dir is a cache, not scratch — it gets repair-via-digest in
   item 1a, never deletion-by-pattern. One-time operator cleanup of the
   ~63 GB of leaked `/tmp/.tmpXXXXXX` trees (decision pending in the
   sibling session). Scratch relocation (out of `/tmp`): measure before
   defaulting — the headroom preflight must cover the destination
   partition (root 92%, /home 90%), and disk-bound scratch may slow
   builds. Gate scripts fail loud on low disk before linking (ENOSPC at
   `ld.bfd` presented as a code failure three times in one day).
   Acceptance: a SIGKILLed build leaves no shuttle-owned tempdir behind;
   no sweep ever deletes a live build's scratch or a downloads-dir
   payload; gate scripts refuse to start under headroom thresholds.
1a. **v5 closure key + top-level store/serve, atomic (perf half).**
   Key = `SnapMeta::build_input_digest` (src/snap.rs:791 — the honest
   superset ADR-0040 D6 names, covering layout, hooks, apps, icon,
   SOURCE_DATE_EPOCH, compression) + resolved tool/packer identity +
   vendored-source identity (the vendored Luau tarball hash — analyzer
   objects drifted from mlua-sys and changed build outcomes with
   identical recipes) + an explicit plain-vs-pod flavor field (pod builds
   bake store paths into wrappers, pod.rs:5869-5871 — interchangeability
   must be decided, not assumed). HOST compiler identity is NOT a key
   field: the nix-gcc-wrapper incident (host 15.2.0 compiled a pod build
   instead of pinned 14.2) is a root-cause bug — pod builds must not pick
   host cc, fixed fail-closed as its own ticket in this wave; host
   identity is a verification assert via rebuild-compare across machines,
   not a namespace field (keying it would make cross-machine hits near
   zero and kill the fleet cache). Arch stays filename-level. Store via
   temp-then-rename; lookup validates size/digest. Retention: prune runs
   on the daily path, excluding in-flight scratch. Dep reuse unifies
   through the key; the pod downloads dir gets a real closure key, atomic
   store, and digest-validated reuse in this same wave (mandatory — its
   defects are field-proven twice in one week; `force_build` remains the
   drift escape). Acceptance: one v4 invalidation warm-up; a no-change
   daily loop skips build+pack for every cacheable output in both loops;
   SIGKILLed builds never serve truncated bytes; same key across days on
   one machine, different key across the gcc 14.2 ↔ 15.2.0 swap
   (toolchain-identity stability test).
1b. **CacheManifest sidecar (wire half — ADR-0043-gated).** The sidecar
   lands in schema-canonical form, unsigned locally, signed only at
   publish. This is the remote-cache plan's artifact, not a perf fix;
   it rides separately so the perf wave never blocks on the ADR.
2. **Tarball cache by pre-known sha256**
   (`~/.cache/shuttle/src/<sha256>`), with the same atomic
   temp-then-rename + digest-on-read treatment — a partial fetch under a
   final digest name would poison every later build. Scope carve-out from
   review: zero-network acceptance holds for PINNED sources with a warm
   lockfile (283 URL-tarball sources across 239 recipes); floating and
   `Unverified` sources re-resolve by design (issue #175) — caching them
   would freeze them by TOFU.
2b. **Harness pre-gate (before item 3).** Pin `-processors` in the #152
   bench; pack numbers are otherwise noise (identical configs swung
   16 s ↔ 66 s wall when mksquashfs ran beside four compiling lanes).
   Acceptance: two consecutive harness runs on an unchanged tree agree.
3. **Profile gate.** Live profiles of both loops — plain `shuttle build
   --all` AND the pod sync the operator actually runs daily — after item
   1a: residual time split (eval storm / prefix materialization / pack /
   leak scan / fetch), the adopt-info/store snap share, and cache
   persistence across days. Arbitrates the size of items 4-6.
   Scheduling note from synthesis: if item 5's byte-neutrality proof
   passes early, land item 5 before this gate so pack numbers reflect
   the final pipeline; otherwise item 5 rides the v5 wave and this gate
   runs after it.
4. **Eval memoization slice.** Per-invocation memo of `load_meta` /
   `build_closure` and `content_hash` for pinned inputs; sweep the extra
   walk sites. Escalate to structural flattening only if the profile says
   the storm still dominates. Acceptance: eval-spawn count drops from
   quadratic to linear in the profile.
5. **`-processors` for mksquashfs.** One line, argv at src/snap.rs:4678.
   Acceptance: pack wall-clock on the pinned harness improves or matches,
   AND byte-neutrality is proven via `examples/rebuild-compare.sh` before
   merge — if parallelism is not byte-neutral, this lands together with
   the v5 key, never before it.
6. **Merged-prefix work, measure-first.** Cheap slice: reflink /
   `copy_file_range` in `merge_tree` (check build-host CoW support
   first). Full unpack cache (spike #156) only if still hot, keyed on
   payload set + declared `requires` + wrapper-rewrite inputs.
   Acceptance: measured prefix time after item 1a justifies whatever
   lands.
7. **Later, gated.** Leak-scan parallelization (matters only on cache-miss
   builds); distributed workers T4-T5 (ADR-0040-gated; pays only while
   toolchain bumps are frequent).

## Measurement gates

- Pre-gate (item 2b): `-processors` pinned in the harness before the
  profile gate runs.
- Harness: #152 (`291eb8c`), tree 26.6 GB / 614k files; re-run per change
  with `-processors` pinned.
- Live loops: instrumented `shuttle build --all` and pod sync before item
  1a and after each item; log per-phase wall clock. Timing anchor from
  the field: a warm single-package rebuild (opencode-bin, 80 MB fetch +
  81 MB mksquashfs) takes about 2-3 minutes today.
- Reproducibility: `examples/rebuild-compare.sh` byte-identity on a sample
  package after any key or packer change (explicitly includes the
  `-processors` change).

## Field evidence (herdr sync, 2026-09-27)

Two sibling agent sessions reviewed the draft; their corrections are
folded above. Raw observations:

- ~63 GB of shuttle-pattern build tempdirs (`/tmp/.tmpXXXXXX`) accumulated
  Sep 19-27; /tmp at 93% through the period. No build was running — the
  trees are leaks from killed/interrupted builds. Attribution correction
  from the pod-sync session: /tmp sat at ~93% with zero mksquashfs I/O
  errors; the reproducible corruption was a concurrent-download race in
  the pod downloads dir, not disk pressure. The disk-pressure claim in
  the first draft is withdrawn; the leak itself is confirmed by both
  sessions.
- Per-lane `cargo target/` trees grew 8-15 GB each across five parallel
  worktree lanes and filled /home to 100% mid-gate; ENOSPC surfaced as
  `ld.bfd: No space left on device` link failures and cost a full
  misdiagnosis cycle each time.
- Concurrent pod syncs raced one python snap download; the loser unpacked
  a truncated file (mksquashfs "invalid superblock"), and a toolchain-gcc
  recipe edit stayed invisible behind the filename-presence cache until a
  hand-delete. A 10-minute foreground timeout killed a sync mid-download
  and left a truncated artifact, detected fail-late at unpack.
- A pod build compiled google-benchmark with the host's nix gcc wrapper
  (15.2.0) instead of the pod's pinned gcc 14.2 payload; a host channel
  bump broke previously-green recipes (`-pedantic-errors` vs UAPI
  headers). Council round-2 framing: this is a sandbox toolchain-leak bug
  to fix fail-closed, not a key field.
- Host disk at draft time: root 92% used, /home 90% (df, pane p0).
- Citation freshness: line numbers verified against the tree by both
  council rounds; sibling sessions report same-day drift
  (#190/#191/#239/#243; ADR-0040's own evidence cites build_sched.rs:36
  for the constant now at :45). Refresh every citation before it becomes
  a ticket instruction.
