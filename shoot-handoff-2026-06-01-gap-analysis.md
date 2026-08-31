# Handoff: shoot — competitive gap analysis done, next: Phase 15 implementation

## Session Scope

Competitive gap analysis of shoot vs Snapcraft and Nix/NixOS. Produced a structured gap document and updated the roadmap with 8 new phases. No code changes.

## What's Done

### Research (parallel @librarian + codegraph self-explore)

1. **Snapcraft ecosystem research** — full plugin list (35+), snapcraft.yaml schema, parts lifecycle, build providers (LXD/Multipass/Launchpad), extensions (GNOME/KDE/Flutter/ROS), assertions/signing, Store publishing, known pain points
2. **Nix/NixOS patterns research** — flake inputs/lockfile architecture, module system (options/mkIf/mkMerge/mkForce), derivation model, content-addressed store, cross-compilation (pkgsCross), CI/CD patterns, known pain points
3. **Codebase mapping** — current SnapMeta struct fields, DSL functions, CLI commands, build pipeline, image assembly, package index, lockfile format, store client

### Artifacts Produced

| Artifact | Path | Purpose |
|----------|------|---------|
| Gap analysis | `docs/gap-analysis-snapcraft-nix.md` (513 lines) | Comprehensive comparison with 8 Snapcraft gaps, 6 Nix gaps, 8-phase roadmap | |
| Roadmap update | `.planning/archive/ROADMAP.md` | 8 new phases (15-22) appended with success criteria |

### Build Health

- **Pre-existing failure**: `mlua-sys` crate fails to build (missing system Lua library). Unrelated to this session (only .md files changed).
- Last known passing commit: `92d207a` (121 tests, clippy clean, fmt clean)

## Key Findings

### Top 3 gaps (by priority)

1. **Input lockfile** (CRITICAL) — shoot's Nix-inspired package inputs (`github:user/repo`) have no lockfile. Builds are NOT reproducible across time. `shoot.lock` exists for source hashes and snap pins but not for input revisions. See §4.1 of gap analysis.

2. **snap.yaml completeness** (HIGH) — Missing fields: `layout` (bind mounts), `hooks` (install/configure/refresh), typed plugs/slots (content interfaces), global `environment`, `icon`, `compression`, `type`, `adopt-info`. See §3.3 of gap analysis.

3. **Plugin system** (HIGH) — Snapcraft has 35+ language plugins. shoot has `build = "shell-command"` only. Start with `cargo` and `make` plugins. See §3.1 of gap analysis.

### Recommended next phase: Phase 15 — Complete snap.yaml Coverage

Lowest effort, highest user value. Can be done in a single focused session.

**Target fields to add** (in priority order):
1. `layout` — bind, bind-file, symlink, tmpfs
2. `hooks` — install, configure, pre/post-refresh, remove
3. Typed plugs/slots — interface key, attributes, content tags
4. Global `environment` — per-snap env vars

**Files to edit:**
- `src/dsl/init.lua` — add field validation for each new field
- `src/snap.rs` — add fields to SnapMeta, SnapApp, add Layout/Hook structs
- `src/lua.rs` — extract new fields from Lua tables
- `src/image.rs` — no changes likely

## Redactions

None.

## Suggested Skills for Next Session

1. **`oracle`** — If starting Phase 15, the struct design for `layout` (four variant types), `hooks` (named scripts), and typed plugs/slots needs architectural review. The serialization approach (serde with custom serializers for Layout variants) could benefit from oracle-level review before implementation.

2. **`librarian`** — If researching Nix lockfile format or Snap Store API details for Phase 16 (input lockfile) or Phase 20 (CI/CD). Also useful if implementing `layout` and needing to verify the exact snap.yaml schema for bind/bind-file/symlink/tmpfs.

3. **`fixer`** — Once the structs and DSL validation are designed for Phase 15, the actual field additions across 3-4 files (dsl/init.lua, snap.rs, lua.rs) can be dispatched as a bounded implementation task to @fixer.

4. **`caveman`** — When reviewing research results or navigating large source files, caveman mode cuts token overhead during debugging or structural exploration.

5. **`gsd-execute-phase`** — If following the GSD workflow, use `/gsd-execute-phase` with the phase number for structured execution with atomic commits and checkpoint protocols.
