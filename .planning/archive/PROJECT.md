# shoot

## What This Is

A Rust CLI tool that builds Snap packages from Lua declarations. Inspired by Nix's declarative reproducibility and Neovim's Lua-based configurability, `shoot` replaces Snapcraft's YAML with a programmable, composable Lua DSL.

**Phase:** Post-MVP. All 17 v1 requirements shipped. Extended with image assembly, package index, toolchain management, and dependency resolution.

## Core Value

Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

## Architecture Overview

```
shoot build shoot.lua     → produces .snap snap packages from source
shoot image shoot.lua     → produces bootable .img disk images
shoot index               → manage package-index.json (add, list, resolve)
shoot deps                → resolve dependency trees (requires fields)
shoot doctor              → check system readiness
```

### Package Index

`pkgs/` — 105 package definitions following Ubuntu pool convention:
- Flat by-name: `pkgs/<first-letter>/<name>/shoot.lua`
- Types: `source` (build from tarball), `meta` (declares deps only), `store` (from Snap Store)
- Each declares `requires` (build dependencies) and `aliases` (alternative names)

### Examples

`examples/` — composable system images:
- `system-base/`: minimal QEMU/KVM rootfs (11 essential packages)
- `pc-rootfs/`: x86_64 with btrfs + lxd
- `pi-rootfs/`: Raspberry Pi with ext4

### Toolchains

Standard GNU triplet naming: `toolchain-<compiler>-<libc>-<arch>`
- `toolchain-gcc-gnu-x86_64` (aliases: `toolchain-x86_64`, `toolchain`)
- `toolchain-clang-gnu-x86_64` (alias: `toolchain-clang-glibc-x86_64`)
- `build-deps` (alias: `build-essential`)

## Requirements

All 17 v1 requirements implemented. See `.planning/REQUIREMENTS.md`.

### Validated

| # | Requirement | Verified |
|---|-------------|----------|
| CLI-01 | `shoot` reads `shoot.lua` from current dir | 93 tests |
| CLI-02 | `shoot build` triggers build pipeline | Integration tests |
| CLI-04 | `--output` flag | CLI tests |
| LUA-01 | `mlua` with injected globals | DSL eval tests |
| LUA-02 | Neovim-style tables | Validation tests |
| LUA-03 | Multi-output structure | Image + build tests |
| LUA-04 | Composable patterns | merge/require tests |
| LUA-05 | Clear error messages | Error path tests |
| VAL-01 | Config validation | Validation tests |
| VAL-02 | Clear error guidance | Error message tests |
| META-01 | Rust structs for Snap format | Round-trip tests |
| META-02 | YAML generation | YAML output tests |
| BUILD-01 | Snap directory assembly | unsquashfs verification |
| BUILD-02 | `mksquashfs` packaging | .snap file tests |

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Standalone tool (not preprocessor) | Must generate `.snap` without Snapcraft dependency | Accepted — standalone CLI |
| `mlua` for embedded Lua | Safe, maintained, Lua 5.4 support | Accepted — Lua 5.4 via `mlua` |
| `mksquashfs` command for packaging | Stable, proven, avoids reimplementing SquashFS | Accepted |
| Nix + Neovim inspired DSL | Combines composability with ergonomic Lua tables | Data-description Lua (ADR-0001) |
| Rust stable only | Avoids nightly churn | Enforced |
| Multi-output flakes architecture | One `shoot.lua` declares multiple snaps | Table-of-outputs (ADR-0003) |
| Ubuntu pool package layout | Flat by-name, first-letter subdirs | `pkgs/<letter>/<name>/shoot.lua` |
| GNU target triplet toolchain naming | Standard convention | `toolchain-<compiler>-<libc>-<arch>` |
| `type`, `requires`, `aliases` fields | Self-describing packages | Source/meta/store distinction |

### Out of Scope

- macOS or Windows snap building — Linux-only
- Snapcraft interop as preprocessor — standalone only
- Nightly Rust features — stable-only constraint
- Package signing / store publishing — requires snapd infrastructure

## Constraints

- **Language**: Rust stable only
- **Platform**: Linux (`mksquashfs` is Linux-native)
- **Output**: `.snap` packages compatible with `snapd`, `.img` disk images
- **License**: GPL v3

---

*Last updated: 2026-06-01 — architecture update after post-MVP extensions*
