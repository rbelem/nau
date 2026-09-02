# shuttle

Build Snap packages from Lua declarations.

Inspired by Nix's declarative reproducibility and Neovim's Lua-based
configurability. Define any Snap package with a simple Lua file — no Snapcraft
YAML needed. Pins all inputs by content hash for reproducible builds.

## Quickstart

```bash
# Build a snap from source
shuttle build --file examples/jq-from-source/shuttle.lua

# Build a system image from pinned snaps
shuttle image --file shuttle.lua --source-date-epoch 0
```

## Dev Environment (devbox)

```bash
devbox run -- build        # debug build
devbox run -- test         # all tests
devbox run -- clippy       # clippy (warnings are errors)
devbox run -- fmt-check    # formatting check
devbox run -- check        # full check (test + clippy + fmt)
```

## Networking

The build sandbox has **no network** (it unshares the network namespace):
build commands cannot download anything. Fetch sources up front via the
definition's `source` / `inputs` instead.

Also disable build-time downloads — e.g. for CMake, pass
`-DBUILD_TESTING=OFF` so FetchContent doesn't try to clone test
dependencies at build time. When a build command fails and its output
looks like a download attempt (curl/wget/fetch/clone/download), shuttle
prints a best-effort no-network hint; the match is advisory, not exact.

## Porting a single `build` to `parts`

Commands in `parts` each run in a **fresh work directory**; `$SRC` points
at the shared source checkout. A command that ran at the source root under
a single `build` must target it explicitly in a part:

| single `build`              | `parts` form                    |
| --------------------------- | ------------------------------- |
| `./configure --prefix=/usr` | `$SRC/configure --prefix=/usr`  |
| `make`                      | `make -C $SRC`                  |

See `pkgs/b/bzip2.lua` for a real three-part example — every command uses
`make -C $SRC` and installs into the shared `$STAGE`.

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

See `CONTEXT.md` (domain glossary) and `docs/adr/` (architecture decisions) for docs.
