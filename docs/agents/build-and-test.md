# Build & Test

## Environment

The toolchain is pinned in `devbox.json` — rustc, clippy, and rustfmt 1.97.1,
cargo, plus the Linux tools the build and test suite exercise (`squashfs-tools`,
`bubblewrap`, `patchelf`, `gnumake`, `flex`/`bison`, `lua54`, …).

The login shell is already devbox-free: it sources the pod shellenv
(`~/.bashrc.d/90-shuttle.sh`), and the pod env exports the farm's loader-lib
`LD_LIBRARY_PATH`. That leak breaks devbox's own node (`node: symbol lookup
error`), so every devbox runner is invoked with `env -u LD_LIBRARY_PATH`.

Related leak: the farm's ld-wrapper can resolve even the *system* `curl` to a
pod's libcurl (`…/generations/<n>/ld-wrappers/.../libcurl.so.4`), which may
ship no CA bundle — a host-side HTTPS fetch then fails TLS despite a clean
PATH (the #130 bug, live on the host until the pod syncs a fixed generation).
Before trusting a fetch's TLS result here, export the host bundle:
`export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`. Transient `x509`
failures from `gh`/watchers get an immediate retry/re-arm, not dismissal.

| Task | Command | Expands to |
| --- | --- | --- |
| Debug build | `env -u LD_LIBRARY_PATH devbox run -- build` | `cargo build` |
| All tests | `env -u LD_LIBRARY_PATH devbox run -- test` | `cargo test` |
| Lint | `env -u LD_LIBRARY_PATH devbox run -- clippy` | `cargo clippy -- -D warnings` |
| Format | `env -u LD_LIBRARY_PATH devbox run -- fmt` | `cargo fmt` |
| Format check | `env -u LD_LIBRARY_PATH devbox run -- fmt-check` | `cargo fmt --check` |
| Full gate | `env -u LD_LIBRARY_PATH devbox run -- check` | test + clippy + fmt-check |
| Lint (pod gate) | `shuttle run --pod gate -- cargo clippy -- -D warnings` | pod-side clippy |
| Format check (pod gate) | `shuttle run --pod gate -- cargo fmt --check` | pod-side rustfmt |

`env -u LD_LIBRARY_PATH devbox run -- check` is the definition of green;
`clippy` treats warnings as errors. The two pod-gate rows are the ratified
substitute for the lint axes — same verdicts as the devbox pin (evidence in
the endgame section below).

### Devbox-free endgame (target state)

The gate is meant to move off devbox onto `shuttle run -- <cmd…>` (issue
#102): exec any command with a reconciled pod's env overlaid — farm-first
PATH plus the pod's declared vars, no sandbox, transparent exec. The command
form is real, and as of the ratification it carries the lint axes (clippy,
fmt) as the verified substitute; the test axis is not yet pod-carried.
Directionality is fixed: the pod payload follows the devbox pin — the pod
never leads it. When the switch happens, the pod becomes the single
canonical gate, and rustfmt/clippy output drifts between versions, so the
pin is the contract on whichever side carries it.

Two blockers, precisely:

1. ~~**Pin.**~~ **CLOSED in round 8.** rust.lua briefly pinned 1.98.1 and had to pin
   1.97.1: rust.lua is a FETCH recipe (upstream static tarballs), so 1.97.1 was
   always fetchable — it was devbox's nixpkgs that could not resolve 1.98.x
   (1.97.1 was the newest resolvable there), which is why the two sides could
   not converge from the devbox side. Caveat: the devbox flake inputs now
   track nixos-unstable, so re-check 1.98.x resolvability there before
   treating the pin as immovable; any move stays a forward-only ratchet
   commit. Re-probed 2026-09-23: still not resolvable — `rustfmt@1.98.1`
   and the 1.98.0 quartet all fail with `package not found`, and
   `devbox search --show-all` tops out at 1.97.1.
2. ~~**Exposure.**~~ **CLOSED at the farm layer (round 7, commit
   45cabf9):** the farm bin set now emits a shim for every bare
   `cargo-*` sibling recorded beside a declared `cargo` app, so
   `cargo clippy`/`cargo fmt` resolve inside `shuttle run` with no
   payload rebuild; proven pod-side in round 7 (`cargo clippy
   -- -D warnings` exit 0). The payload keeps shipping both binaries;
   the apps-map route (declaring `cargo-clippy`/`cargo-fmt` apps)
   remains an alternative, not a blocker.

Ratchet rule: once the pod is the gate, the pin moves forward only, via
a dedicated bump commit that lands the forward-fixes first (the code
changes the newer clippy demands) — never port an older toolchain into a
newer gate to un-block a lane.

Flip trigger — switch when any of: nixpkgs carries 1.98.x; clippy drift
grows beyond a handful of diagnostics; or CI runs the pod gate. Both
blockers are now closed: exposure at the farm layer (round 7) and the
pin itself (round 8 — the gate pod carries rust 1.97.1, and pod-side
clippy/fmt verdicts match the devbox pin exactly).

**Ratified (post-round-8 rerun on the daily host):** the pod gate is the
verified substitute for the lint axes — `shuttle run --pod gate -- cargo
clippy -- -D warnings` (≈1m25s warm vs devbox's ≈15s; the accepted cost of
the flip) and `… cargo fmt --check` both passed with verdicts matching the
devbox pin, re-confirmed after the five-lane merge of 2026-09-23. The
evidence is single-host and warm-cache: re-verify per host and cold cache
before leaning on the substitution elsewhere. The test axis is NOT
ratified: a full pod-side
`cargo test` on the daily host fails where devbox passes, on build-host
tools the gate pod does not ship — observed: `patchelf` (image staging
path) and the mksquashfs-backed snap-build tests — plus one xz
decompress failure under the pod env (suspected loader-lib leak, #130
class; confirm before closing the axis). Until the gate pod declares
those tools (recipe-layer provisioning, the general shape of gate-pod
gap 3), the test axis stays devbox-side: `devbox run -- check` remains
the full gate, and the pod gate substitutes for clippy/fmt only.

### `devbox run` semantics

`devbox run <script>` starts a devbox shell (pinned packages on PATH,
`init_hook` applied) and runs the script inside it; `devbox run --
<cmd>` runs a one-off command the same way. The command travels in the
`DEVBOX_RUN_CMD` env var and the generated wrapper evals it unquoted,
so a quoting-sensitive inline payload (`devbox run -- bash -c '…'`)
gets re-parsed and loses its quoting. Put nontrivial scripts in a file
(`devbox run -- bash script.sh`) or a `devbox.json` script, and set
one-off variables with `--env`/`--env-file`.

## Pre-migration sweep: `return false` in pointer returns (#208)

Before each migration rebuild — every recipe port and every upstream
version bump through the pool — re-run the gcc-14 `int-conversion`
sweep over embedded C sources, patches, and snippets:

```bash
grep -rniE 'return *(false|FALSE)' pkgs/
```

Baseline 2026-09-25: zero live hits (the two known occurrences are fix
artifacts — the `less` sed-patch at `pkgs/l/less.lua:39` and tig's
`-Wno-error=int-conversion` downgrade at `pkgs/t/tig.lua`). Recipes
fetch upstream sources at build time, so this in-repo grep cannot see
everything: treat any `-Werror=int-conversion` build failure in a pod
build log as a sighting of this class. The fix is the tig/less
pattern — sed-patch to `return NULL` when the function returns a
pointer, or a scoped `-Wno-error=int-conversion` downgrade when the
return type is a boolean-ish integer (`NCURSES_BOOL`, `TRUE`/`FALSE`
unions) — never a blanket `-w`.

## Test layout

- **Unit tests** live in `src/` next to the code they cover, in `#[cfg(test)]`
  modules (Rust convention).
- **Integration tests** live in `tests/` and drive the built binary and library
  end to end. Groups present today: `eval_*` (DSL evaluation and parity),
  `pod_*` (confinement, overlay, install, deps, desktop, wrapper, native ELF,
  loads, portable, build prefix), `attack_isolation`, `inputs_lock`,
  `leak_scan`, and `check_cmd`.
- Fixtures needed by integration tests live in `tests/fixtures/`; DSL parity
  cases live in `tests/parity/`.
- Tests run offline. Where a registry or proxy is required (dependency-fetch
  tests), the suite uses loopback fixtures under `tests/fixtures/` — no
  external service or network access.
- **Asserting on rendered stderr:** errors render through `miette`, which
  wraps captured stderr at 80 columns with `│` gutters. Integration tests must
  assert short per-line fragments (`"held package 'zgotmp'"`,
  `"dependency closure"`), never a phrase long enough to straddle a wrap
  boundary — a `contains()` on a split phrase fails even though the exact
  sentence was printed.
- **Gated tests skip silently.** `gated_test!` early-returns with an eprintln
  when its tool is absent (issue #134 tracks a fail-loud canary). A green
  local run proves nothing for gated tests: when a PR's proof rests on them,
  grep the CI run log for their `... ok` lines and do not merge on a run
  where they were skipped.
