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

`env -u LD_LIBRARY_PATH devbox run -- check` is the definition of green;
`clippy` treats warnings as errors.

### Devbox-free endgame (target state)

The gate is meant to move off devbox onto `shuttle run -- <cmd…>` (issue
#102): exec any command with a reconciled pod's env overlaid — farm-first
PATH plus the pod's declared vars, no sandbox, transparent exec. The command
form is real, but it cannot carry this repo's gate yet. Directionality is
fixed: the pod payload follows the devbox pin — the pod never leads it.
When the switch happens, the pod becomes the single canonical gate, and
rustfmt/clippy output drifts between versions, so the pin is the contract
on whichever side carries it.

Two blockers, precisely:

1. **Pin.** `pkgs/r/rust.lua` pins 1.98.1 and must pin 1.97.1. rust.lua
   is a FETCH recipe (upstream static tarballs), so 1.97.1 is fetchable —
   it is devbox's nixpkgs that cannot resolve 1.98.x (1.97.1 is the
   newest resolvable there), which is why the two sides cannot converge
   from the devbox side.
2. **Exposure.** rust.lua's apps map must declare `cargo-clippy` and
   `cargo-fmt`. The payload already ships both binaries; the existing
   `clippy` app exposes the entry point under the wrong name for cargo's
   `cargo-<sub>` PATH discovery, so `cargo clippy`/`cargo fmt` die with
   `no such command` (round 6 of the gate-pod log).

Ratchet rule: once the pod is the gate, the pin moves forward only, via
a dedicated bump commit that lands the forward-fixes first (the code
changes the newer clippy demands) — never port an older toolchain into a
newer gate to un-block a lane.

Flip trigger — switch when any of: nixpkgs carries 1.98.x; clippy drift
grows beyond a handful of diagnostics; or CI runs the pod gate. Until
then, round 6's negative verdict stands: the pod lint axis cannot replace
the devbox gate, and the devbox command above remains the verified gate.

### `devbox run` semantics

`devbox run <script>` starts a devbox shell (pinned packages on PATH,
`init_hook` applied) and runs the script inside it; `devbox run --
<cmd>` runs a one-off command the same way. The command travels in the
`DEVBOX_RUN_CMD` env var and the generated wrapper evals it unquoted,
so a quoting-sensitive inline payload (`devbox run -- bash -c '…'`)
gets re-parsed and loses its quoting. Put nontrivial scripts in a file
(`devbox run -- bash script.sh`) or a `devbox.json` script, and set
one-off variables with `--env`/`--env-file`.

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
