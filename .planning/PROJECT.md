# shoot

## What This Is

A Rust CLI tool that builds Snap packages from Lua declarations. Inspired by Nix's declarative reproducibility and Neovim's Lua-based configurability, `shoot` replaces Snapcraft's YAML with a programmable, composable Lua DSL. Single snaps first — growing toward full Ubuntu Core image assembly.

## Core Value

Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] **REQ-CLI-01**: CLI accepts a Lua file input and optional output flags via `clap`
- [ ] **REQ-LUA-01**: Embedded Lua (`mlua`) evaluates the config file with injected globals
- [ ] **REQ-LUA-02**: Lua DSL supports table-based declarations (Neovim-style) for app metadata, permissions, apps
- [ ] **REQ-LUA-03**: Lua DSL supports composable/functional patterns (Nix-inspired) — overrides, imports
- [ ] **REQ-META-01**: Tool maps processed Lua values to Rust structs matching the Snap package format
- [ ] **REQ-META-02**: Tool generates `meta/snap.yaml` from the struct data
- [ ] **REQ-BUILD-01**: Tool assembles the snap directory structure and runs `mksquashfs` to produce `.snap`
- [ ] **REQ-VALID-01**: Tool validates the Lua config and reports clear errors for missing/invalid fields

### Out of Scope

- Ubuntu Core image assembly — v1 is single-snap packaging only
- macOS or Windows snap building — Linux-only for v1
- Snapcraft interop as preprocessor — standalone only
- Nightly Rust features — stable-only constraint

## Context

- User maintains snaps today and hits the limits of YAML: no conditionals, loops, or composability
- Looking for a Devbox-like experience: declare intent in config, tool handles the complexity
- Nix (reproducibility, derivations) + Neovim (Lua tables as config) = design north star
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
| Standalone tool (not preprocessor) | Must generate `.snap` without Snapcraft dependency | — Pending |
| `mlua` for embedded Lua | Safe, maintained, Lua 5.4 support | — Pending |
| `mksquashfs` command for packaging | Stable, proven, avoids reimplementing SquashFS | — Pending |
| Nix + Neovim inspired DSL | Combines composability (Nix) with ergonomic Lua (Neovim) | — Pending |
| Rust stable only | Avoids nightly churn, matches project convention | — Pending |
| Single-snap v1, system images later | Manageable scope; system images add model assertions, gadget snaps | — Pending |

---

*Last updated: 2026-05-16 after initialization*

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
