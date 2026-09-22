# Coverage

Unit-test coverage status, measured with `cargo-llvm-cov` (0.8.7, pinned in
`devbox.json`). This file records the baseline, the working command, the
weak-file table that decides a future CI gate floor, and the test-wave plan.

## Working coverage command

`cargo-llvm-cov` needs `llvm-tools-preview`, which rustup-managed toolchains
get for free. The devbox-pinned nix `rustc` has no rustup, so the LLVM tools
come from nixpkgs and are passed through the env vars `cargo-llvm-cov`
documents for exactly this case:

```bash
# One-time (session-local): LLVM 21 tools matching rustc 1.97.1's LLVM
nix build github:NixOS/nixpkgs/nixos-26.05#llvm --out-link /tmp/opencode/llvm-link

# Baseline/after-wave measurement (~12 min cold, ~2 min warm)
env -u LD_LIBRARY_PATH \
  LLVM_COV=/tmp/opencode/llvm-link/bin/llvm-cov \
  LLVM_PROFDATA=/tmp/opencode/llvm-link/bin/llvm-profdata \
  devbox run -- bash -c 'SHUTTLE_SYSTEMD=off cargo llvm-cov --workspace --all-targets --locked'

# Per-file uncovered line numbers, without re-running tests (fast):
env -u LD_LIBRARY_PATH LLVM_COV=… LLVM_PROFDATA=… \
  devbox run -- cargo llvm-cov report --text --show-missing-lines --output-path /tmp/opencode/cov-missing.txt
```

Notes:

- `--summary` and `--llvm-path` are **not** valid flags of this
  cargo-llvm-cov version; the `LLVM_COV`/`LLVM_PROFDATA` env vars are its
  supported seam (its own error message names them).
- Tests run offline (`SHUTTLE_SYSTEMD=off`), same as the `check` gate.

## Baseline (2026-09-22, commit ef63400 + doc worktree edits)

| Metric | Value |
| --- | --- |
| Line coverage | **85.98%** (8527 / 60836 missed) |
| Function coverage | 78.14% (1275 / 5833 missed) |
| Region coverage | 85.99% |
| Tests | 1366 lib unit tests + 30 integration suites, all green |

## Worst-covered src/ files (baseline)

Sorted by line coverage. "Hard" = coverage is structurally bounded (spawns
host tools, binds real sockets, or is the bin entrypoint); "testable" =
pure logic or the module already has an injectable seam.

| File | Exec lines | Missed | Line % | Note |
| --- | --- | --- | --- | --- |
| src/main.rs | 3232 | 1827 | 43.47% | Hard — bin entrypoint: arg-parse → subcommand dispatch, every real-exec side; the logic behind it lives in `cli.rs` (tested via lib) |
| src/output.rs | 146 | 82 | 43.84% | Testable — mode/quiet statics, JSON accumulators, progress-bar constructors; pure |
| src/isolate.rs | 1055 | 484 | 54.12% | Mostly hard — bwrap/unshare/namespace exec glue; some pure helpers testable |
| src/store.rs | 244 | 94 | 61.48% | Testable — full `CommandRunner` injection; query/resolve/download/verify |
| src/discovery.rs | 251 | 74 | 70.52% | Mostly hard — `announce`/`browse` bind real mDNS sockets; peer-table helpers already tested |
| src/command.rs | 18 | 5 | 72.22% | Hard — `RealRunner` *is* the real subprocess exec |
| src/image/partition.rs | 1499 | 405 | 72.98% | Split — sgdisk/parted/mkfs exec = hard; `sfdisk -J`/`sgdisk` output parsing = testable |
| src/assert.rs | 644 | 167 | 74.07% | Testable — PGP verify/sign round-trips against the vendored trust anchor; fixture-heavy |
| src/image/boot.rs | 799 | 173 | 78.35% | Hard — boot image assembly shelling out to host tools |
| src/image/staging.rs | 1786 | 386 | 78.39% | Mostly hard — staging exec glue; `base_track`/`channel_on_track` parsers testable |
| src/slot_recovery.rs | 675 | 144 | 78.67% | Split — `os_release_field`, `image_name_from_root_transfer`, `parse_partno` pure; recovery exec hard |
| src/pkg_source.rs | 1258 | 234 | 81.40% | Split — local path resolution testable; `github:` inputs fetch from the network |
| src/confine.rs | 567 | 99 | 82.54% | Testable — bwrap arg assembly, apparmor profile render are pure |
| src/index.rs | 494 | 84 | 83.00% | Mostly testable — `resolve_all` hits the live store (not injectable today); lookup/serde/DSL seam testable |
| src/deps.rs | 327 | 53 | 83.79% | Testable — pure graph logic; `format_tree`, `load_meta` paths untested |
| src/image/verity.rs | 427 | 62 | 85.48% | Split — veritysetup exec hard; trailer/roothash math testable |
| src/cache.rs | 936 | 130 | 86.11% | Testable — store cache on tempdirs |
| src/dep_fetch.rs | 2187 | 282 | 87.11% | Split — registry HTTP fetched via loopback fixtures in tests/; unit-testable parsing remains |
| src/desktop.rs | 602 | 75 | 87.54% | Testable — desktop-file assembly |
| src/boot_test.rs | 1460 | 177 | 87.88% | Hard — itself a test file (qemu boot rounds) |
| src/pod.rs | 3196 | 386 | 87.92% | Mostly hard — pod lifecycle exec; env/merge helpers testable |
| src/uc.rs | 942 | 99 | 89.49% | Testable — UC seed/model assembly |
| src/snap.rs | 8527 | 888 | 89.59% | Testable — the DSL surface; 192 existing tests, long tail remains |
| src/build_prefix.rs | 953 | 97 | 89.82% | Testable — prefix merge logic |
| src/image/initramfs.rs | 894 | 88 | 90.16% | Mostly hard — initramfs assembly with host tools |

## Partition — test-wave clusters

Four clusters of related weak files, ordered by (testable uncovered lines).
Wave 1 attacks the biggest first.

### Cluster A — artifact resolution & dependency graph (wave 1)

- **Files**: `store.rs` (61.5%), `index.rs` (83.0%), `deps.rs` (83.8%)
- **Baseline**: 231 uncovered lines, ~all testable
- **Plan**:
  - `store.rs`: `env_snap_id` parsing (comma/whitespace/empty/name-miss),
    `query_info_with` error paths (curl spawn failure, non-zero exit, bad
    JSON), `resolve_with` via a scripted fake runner (channel "track/risk"
    vs bare-risk parsing, no-matching-entry, revision-mismatch,
    sha3-mismatch, assertion-network downgrade for explicit pins vs hard
    failure), `download` already-cached short-circuit + curl failure +
    success, `verify` mismatch error shape, `fetch` end-to-end.
  - `deps.rs`: `resolve_deps` recursive traversal + visited dedup +
    alias canonicalization, `format_tree`/`print_tree_node` rendering,
    `load_meta` all three `PkgResult` branches, `recipe_dir` both shapes.
  - `index.rs`: `lua_index_entry` happy path + not-found error,
    `StoreRef` serde default channel, `entry_to_snap_meta` unpinned-source
    (`Unverified`) branch, `find_by_name_or_alias`.
  - Out of scope without a production change: `PackageIndex::resolve_all`
    (calls the non-injectable `StoreClient::resolve` — flagged, not
    refactored).

### Cluster B — confinement & sandbox assembly

- **Files**: `confine.rs` (82.5%), `isolate.rs` (54.1%), `command.rs` (72.2%)
- **Baseline**: ~588 uncovered lines, ~95 testable (rest is real
  namespace/exec work)
- **Plan**: `resolve_command_in` search semantics, `overlay_pod_env_with`
  merge rules, `apply_backend_options`, the `bind_*` bwrap-arg builders
  (assert on `Command::get_args()`), `profile_name`/
  `render_apparmor_profile` goldens; `isolate.rs` pure helpers only.

### Cluster C — output/CLI surfaces

- **Files**: `output.rs` (43.8%), `discovery.rs` (70.5%), `emit.rs` (92.8%)
- **Baseline**: ~163 uncovered lines, most testable except
  `announce`/`browse` (real sockets)
- **Plan**: quiet-build gating of `spinner`/`progress_bar`, JSON
  record/flush round-trips per command + non-JSON no-op + unknown-command
  branch (global statics serialized under a test mutex), serde shapes
  (`skip_serializing_if` fields); `host_of`/`upsert_unique` IP-ranking
  edge cases not already covered.

### Cluster D — image-adjacent parsing & slot recovery

- **Files**: `slot_recovery.rs` (78.7%), `image/partition.rs` (73.0%),
  `image/verity.rs` (85.5%), `image/state.rs` (99.1%)
- **Baseline**: ~611 uncovered lines, ~half testable (pure parsers and
  fake-runner-drivable logic)
- **Plan**: `os_release_field`, `image_name_from_root_transfer`,
  `parse_partno`, `gather_ukis` on a tempdir ESP; partition-table JSON
  parsing (`sfdisk -J` shapes), verity trailer math; reclaim flow through
  the existing fake tools.

## Wave log

| Wave | Clusters | Commit(s) | Line coverage | Δ |
| --- | --- | --- | --- | --- |
| baseline | — | — | 85.98% | — |
