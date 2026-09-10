# Project Context

**shuttle** — a Rust CLI that builds Snap packages from Lua declarations,
replacing Snapcraft's YAML with a programmable, composable Lua DSL. Inspired by
Nix's declarative reproducibility and Neovim's Lua-based configurability.

- **Former name:** *shoot* (renamed 2026-08, ADR-0013). The checkout directory
  may still be named `shoot/`; the project and remote are `rbelem/shuttle`.
- **Core value:** define any Snap package with a single Lua file — packaged,
  composable, version-controllable.

## Constraints

- **Language:** Rust stable only — no nightly features. Edition 2021.
- **Platform:** Linux only (snaps target Linux; `mksquashfs` and `bubblewrap`
  are Linux-native).
- **Output:** standard `.snap` files compatible with `snapd`.
- **License:** GPL-3.0-only (`LICENSE`).

## Stack

- CLI: `clap` (derive) + `clap_complete`; diagnostics: `miette`.
- Lua/Luau evaluation: `mlua` (`luau` feature); Rust-side definition parsing:
  `full_moon` (`luau` feature).
- Serialization: `serde`, `serde_json`, `serde_yaml`, `toml`.
- Dependency fetching: `flate2`, `tar`, `zip`. Assertions/crypto: `pgp`,
  `ed25519-dalek`, `sha2`, `sha3`.
- `build.rs` compiles a vendored Luau analyzer from `shim/`.
- Toolchain and native build tools are pinned in `devbox.json`.

## Where things live

- `src/` — the CLI and library.
- `tests/` — integration tests.
- `pkgs/` — package definitions; `examples/` — sample projects.
- `docs/` — ADRs and research; `CONTEXT.md` — domain glossary.
