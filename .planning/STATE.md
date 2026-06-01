# STATE.md

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-06-01)
See: `.planning/ROADMAP.md` (updated 2026-06-01)
See: `.planning/REQUIREMENTS.md` (updated 2026-06-01)

**Core value:** Define any Snap package with a simple Lua file — no Snapcraft YAML needed.
**Current focus:** Extending examples/ for agent-driven system building

## Current Phase

**Phase:** Beyond MVP — Image Assembly & System Building
**Status:** 12/12 phases complete
**Started:** 2026-05-16
**Plan:** All MVP phases done. See ROADMAP.md for Beyond MVP phases.

## Progress

**Phases:** 12/12 complete
**Requirements:** 17/17 v1 requirements complete

## Test Count

**93 tests passing**, clippy clean, fmt clean

## Project Stats

- **105 packages** in `pkgs/` (Ubuntu-style pool layout)
- **4 examples** in `examples/` (system-base, pc-rootfs, pi-rootfs)
- **DSL extensions:** `type`, `requires`, `aliases` fields
- **Dependency resolution:** `shoot deps` + `shoot build --order`
- **Image assembly:** `shoot image` with GPT disk, kernel params, bootloader
- **Package index:** `package-index.json` with store pins and alias resolution

## Recent Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-16 | Standalone tool (not Snapcraft preprocessor) | Must generate `.snap` without Snapcraft dependency |
| 2026-05-16 | `mlua` for embedded Lua | Safe, maintained, Lua 5.4 support |
| 2026-05-16 | Nix + Neovim inspired DSL | Combines composability with ergonomic Lua tables |
| 2026-05-16 | Vertical MVP phases | Each phase delivers end-to-end user capability |
| 2026-05-16 | Multi-output flakes architecture | One `shoot.lua` can declare multiple snaps |
| 2026-05-31 | Ubuntu pool layout for packages | First-letter flat namespace (like archive.ubuntu.com) |
| 2026-06-01 | Decompose core22 into individual packages | Explicit dependency tracking vs monolithic base |
| 2026-06-01 | GNU target triplet for toolchain naming | Standard convention: `<compiler>-<libc>-<arch>` |
| 2026-06-01 | `type` field on snap() | Distinguish source/meta/store packages |
| 2026-06-01 | `requires` + `aliases` fields | Declare dependencies and alternative names |

## Blockers

None currently.

---

*Last updated: 2026-06-01 — full project state audit*
