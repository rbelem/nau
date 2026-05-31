# shoot

Build Snap packages from Lua declarations.

Inspired by Nix's declarative reproducibility and Neovim's Lua-based
configurability. Define any Snap package with a simple Lua file — no Snapcraft
YAML needed. Pins all inputs by content hash for reproducible builds.

## Quickstart

```bash
# Build a snap from source
shoot build --file examples/jq-from-source/shoot.lua

# Build a system image from pinned snaps
shoot image --file shoot.lua --source-date-epoch 0
```

## Dev Environment (devbox)

```bash
devbox run -- build        # debug build
devbox run -- test         # all tests
devbox run -- clippy       # clippy (warnings are errors)
devbox run -- fmt-check    # formatting check
devbox run -- check        # full check (test + clippy + fmt)
```

## Project State

- **Phase 1**: CLI scaffold + mlua eval — ✓
- **Phase 2**: snap()/app() globals with validation — ✓
- **Phase 3-5**: structs + YAML + SquashFS packaging — ✓
- **Phase 6**: multi-arch builds — ✓
- **Phase 7**: composable DSL (merge + require) — ✓
- **Phase 8**: output selection — ✓
- **Source pinning**: SHA-256 verification + lockfile — ✓
- **Snap pinning**: store API, download, sha3-384 verify — ✓
- **Image assembly**: compose snaps into reproducible rootfs — ✓
- **CI/CD**: GitHub Actions with devbox — ✓

See `CONTEXT.md`, `docs/adr/`, and `.planning/` for architecture docs.
