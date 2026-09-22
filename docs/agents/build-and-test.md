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
form is real, but it cannot carry this repo's gate yet:

- The daily pod ships a rust toolchain, but 1.98.1 — not the pinned 1.97.1
  (devbox's nixpkgs pin cannot resolve 1.98.x; 1.97.1 is the newest
  resolvable). rustfmt/clippy output drifts between versions, so the pin is
  the contract.
- `check` is a devbox script name, not a farm binary — `shuttle run -- check`
  has nothing to resolve until the pod ships the pinned toolchain and a gate
  wrapper (or the gate is spelled as explicit `shuttle run -- cargo …`
  commands).

Prerequisite for the switch: the pod/pool must carry the pinned toolchain
(cargo/rustc/clippy/rustfmt 1.97.1) — pod 1.98.1 still drifts from the pin,
and devbox cannot resolve 1.98.x yet. Until then, the devbox command above
remains the verified gate.

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
