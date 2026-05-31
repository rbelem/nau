# shoot

## What This Is

A Rust CLI tool that builds Snap packages from Lua declarations. Inspired by Nix's declarative reproducibility and Neovim's Lua-based configurability, `shoot` replaces Snapcraft's YAML with a programmable, composable Lua DSL. Single snaps first — growing toward full Ubuntu Core image assembly.

## Core Value

Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

## Requirements

### Validated

(None yet — ship to validate)

### Active

17 v1 requirements across 5 categories, documented in [`REQUIREMENTS.md`](REQUIREMENTS.md):

- **CLI** (4) — `shoot build shoot.lua`, `--file`, `--arch`, `--output`
- **Lua DSL** (5) — mlua eval, Neovim-style tables, multi-output flakes, composable patterns, error messages
- **Metadata** (3) — Rust structs for Snap format, YAML generation, multi-arch metadata
- **Build** (3) — directory assembly, mksquashfs, multi-arch builds
- **Validation** (2) — config validation, clear error guidance

### Out of Scope

- Ubuntu Core image assembly — v1 is single-snap packaging only
- macOS or Windows snap building — Linux-only for v1
- Snapcraft interop as preprocessor — standalone only
- Nightly Rust features — stable-only constraint

## Context

- User maintains snaps today and hits the limits of YAML: no conditionals, loops, or composability
- Looking for a Devbox-like experience: declare intent in config, tool handles the complexity
- Nix (reproducibility, derivations) + Neovim (Lua tables as config) = design north star
- CLI modeled after `nix build`: standard `shoot.lua` in current dir, `shoot build [output]` for specific outputs
- Multi-output architecture: one `shoot.lua` can declare multiple snaps (different apps, different archs), like Nix flakes
- The Snap format itself is well-understood: `meta/snap.yaml` layout, SquashFS packaging, slot/plug permissions
- Rust is the right fit for a CLI that embeds a Lua runtime and does filesystem operations

## Constraints

- **Language**: Rust stable only — no nightly features
- **Platform**: Linux (snaps target Linux; `mksquashfs` is Linux-native)
- **Output**: Standard `.snap` format compatible with `snapd`
- **License**: GPL v3 (inherited from project)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Standalone tool (not preprocessor) | Must generate `.snap` without Snapcraft dependency | Accepted — standalone CLI, no Snapcraft dependency |
| `mlua` for embedded Lua | Safe, maintained, Lua 5.4 support | Accepted — Lua 5.4 via `mlua` |
| `mksquashfs` command for packaging | Stable, proven, avoids reimplementing SquashFS | Accepted — shell out to `mksquashfs` at build step |
| Nix + Neovim inspired DSL | Combines composability (Nix) with ergonomic Lua (Neovim) | Data-description Lua (ADR-0001) — Lua syntax, return-table contract, side-effect-free evaluation |
| Rust stable only | Avoids nightly churn, matches project convention | Enforced — no nightly features |
| Single-snap v1, system images later | Manageable scope; system images add model assertions, gadget snaps | Scoped to single snaps for v1 only |
| Nix flake CLI design | `shoot build` reads `shoot.lua` from current dir, like `nix build` reads `flake.nix` | Accepted — `shoot build shoot.lua` with `--file` override |
| Multi-output flake architecture | One `shoot.lua` declares multiple snaps (multiple outputs), like Nix flake outputs | Table-of-outputs from day one (ADR-0003) — `shoot.lua` always returns `{ default = {...} }` |
| Lua DSL as schema source of truth | `snap()` validates types/fields at eval time, Rust is passive consumer (ADR-0002) | Accepted — no dual validation, Lua errors are user-facing |
| Injected globals return values | `snap(...)` returns validated table; `return` is the contract, not global mutation (ADR-0004) | Accepted — Nix-style return values, testable without CLI |
| Structured error reporting from day one | Lua errors wrapped with file/line via mlua; Rust errors via miette | Accepted — miette for Rust errors, Lua stack traces preserved |
| Binary staging model | `--stage` takes directory path (default `./stage/`), flat copy into snap assembly | Accepted — single stagedir in v1, composable deferred to Phase 7 |
| System dependency model | `mksquashfs` checked at build step, not upfront; graceful degradation if `snapd` absent | Accepted — checked at use time, no hard startup failures |
| Interface validation | Cached interface list from `snapd`, injected as Lua globals | Accepted — warnings on unknown interfaces, not errors |
| Vertical MVP phase structure | Each phase delivers an end-to-end user capability, not horizontal layers | Accepted — vertical slices |
| Interactive workflow mode | Manual approval at each step (YOLO disabled) | Accepted — GSD interactive mode |

---

*Last updated: 2026-05-31 — Key Decisions filled from ADR-0001–0004 and CONTEXT.md*

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state
