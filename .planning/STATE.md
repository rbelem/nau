# STATE.md

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-05-16 after initialization)

**Core value:** Define any Snap package with a simple Lua file — no Snapcraft YAML needed.
**Current focus:** Phase 1 — Hello, shoot

## Current Phase

**Phase:** 1 — Hello, shoot
**Status:** Pending (next to execute)
**Started:** —
**Plan:** —

## Progress

**Phases:** 0/8 complete
**Requirements:** 0/17 complete

## Recent Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-16 | Standalone tool (not Snapcraft preprocessor) | Must generate `.snap` without Snapcraft dependency |
| 2026-05-16 | `mlua` for embedded Lua | Safe, maintained, Lua 5.4 support |
| 2026-05-16 | Nix + Neovim inspired DSL | Combines composability with ergonomic Lua tables |
| 2026-05-16 | Vertical MVP phases | Each phase delivers end-to-end user capability |
| 2026-05-16 | Multi-output flakes architecture | One `shoot.lua` can declare multiple snaps |

## Blockers

None currently.

## Notes

- GSD research subagents not installed — roadmap generated inline
- Research agents (`gsd-project-researcher`, `gsd-research-synthesizer`, `gsd-roadmapper`) can be installed with `npx get-shit-done-cc@latest --global`
- Model profile: inherit (current session model)
- All v1 requirements mapped across 8 phases

---

*Last updated: 2026-05-16 after initialization audit*
