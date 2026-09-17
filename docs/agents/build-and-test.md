# Build & Test

## Environment

The toolchain is pinned in `devbox.json` — rustc, clippy, and rustfmt 1.95,
cargo, plus the Linux tools the build and test suite exercise (`squashfs-tools`,
`bubblewrap`, `patchelf`, `gnumake`, `flex`/`bison`, `lua54`, …). Run everything
through devbox so the pinned versions are used.

| Task | Command | Expands to |
| --- | --- | --- |
| Debug build | `devbox run -- build` | `cargo build` |
| All tests | `devbox run -- test` | `cargo test` |
| Lint | `devbox run -- clippy` | `cargo clippy -- -D warnings` |
| Format | `devbox run -- fmt` | `cargo fmt` |
| Format check | `devbox run -- fmt-check` | `cargo fmt --check` |
| Full gate | `devbox run -- check` | test + clippy + fmt-check |

`devbox run -- check` is the definition of green; `clippy` treats warnings as errors.

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
