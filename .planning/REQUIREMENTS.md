# Requirements: shoot

**Defined:** 2026-05-16
**Core Value:** Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

## v1 Requirements — All Done

All 17 v1 requirements are implemented and tested.

### CLI

- [x] **CLI-01**: `shoot` reads `shoot.lua` from current dir (or `--file` override)
- [x] **CLI-02**: `shoot build` command triggers the build pipeline
- [x] **CLI-03**: `--arch` flag for multi-arch builds
- [x] **CLI-04**: `--output` flag for custom output path

### Lua DSL

- [x] **LUA-01**: Embedded `mlua` evaluates `shoot.lua` with injected globals for snap declarations
- [x] **LUA-02**: Table-based declarations for snap metadata, apps, permissions (Neovim-style)
- [x] **LUA-03**: Multi-output structure — declare multiple snaps per file (Nix flake-style)
- [x] **LUA-04**: Composable patterns — imports, overrides, functions (Nix-inspired)
- [x] **LUA-05**: Clear error messages for invalid or missing fields

### Metadata

- [x] **META-01**: Map processed Lua values to Rust structs matching Snap package format
- [x] **META-02**: Generate `meta/snap.yaml` from struct data
- [x] **META-03**: Support multi-arch metadata in output declarations

### Build

- [x] **BUILD-01**: Assemble snap directory structure with binaries and `meta/`
- [x] **BUILD-02**: Run `mksquashfs` to produce `[name]_[version]_[arch].snap`
- [x] **BUILD-03**: Build for multiple architectures from one config

### Validation

- [x] **VAL-01**: Validate Lua config structure before building
- [x] **VAL-02**: Report missing required fields with clear guidance

## Additional Capabilities (Beyond v1)

| Feature | Status | Notes |
|---------|--------|-------|
| Image assembly (bootable disk images) | ✅ | GPT partitions, bootloader, kernel params |
| Package index (package-index.json) | ✅ | Store resolution, pin management, aliases |
| 105 base system packages | ✅ | Source definitions in `pkgs/` |
| Toolchain meta-packages | ✅ | GCC + Clang with GNU target triplet naming |
| DSL `type`, `requires`, `aliases` | ✅ | Self-describing packages |
| Dependency resolution | ✅ | `shoot deps` + `shoot build --order` |
| Snap Store client | ✅ | Query, download, sha3-384 verify |
| Lockfile | ✅ | Source and snap pinning for reproducibility |
| System readiness checks | ✅ | `shoot doctor` |
| CI/CD (GitHub Actions + devbox) | ✅ | Build, test, clippy, fmt |

## Out of Scope

| Feature | Reason |
|---------|--------|
| macOS / Windows builds | Snaps target Linux; `mksquashfs` is Linux-native |
| Snapcraft preprocessor mode | Standalone tool — generates `.snap` directly |
| Nightly Rust features | Stable-only constraint |
| GUI / visual tooling | CLI-only |
| LSP / editor integration | Deferred |
| Package signing | Requires snapd infrastructure |
| Remote store publishing | Requires Snap Store developer account |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | Phase 1 | Done ✓ |
| CLI-02 | Phase 1/8 | Done ✓ |
| CLI-03 | Phase 1/6 | Done ✓ |
| CLI-04 | Phase 1 | Done ✓ |
| LUA-01 | Phase 1 | Done ✓ |
| LUA-02 | Phase 2 | Done ✓ |
| LUA-03 | Phase 8 | Done ✓ |
| LUA-04 | Phase 7 | Done ✓ |
| LUA-05 | Phase 2 | Done ✓ |
| META-01 | Phase 3 | Done ✓ |
| META-02 | Phase 4 | Done ✓ |
| META-03 | Phase 4/6 | Done ✓ |
| BUILD-01 | Phase 5 | Done ✓ |
| BUILD-02 | Phase 5 | Done ✓ |
| BUILD-03 | Phase 6 | Done ✓ |
| VAL-01 | Phase 2 | Done ✓ |
| VAL-02 | Phase 2 | Done ✓ |

**Coverage:**
- v1 requirements: 17/17 Done ✓

---

*Requirements defined: 2026-05-16*
*Last updated: 2026-06-01 — all 17 requirements Done*
