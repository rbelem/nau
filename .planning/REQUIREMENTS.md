# Requirements: shoot

**Defined:** 2026-05-16
**Core Value:** Define any Snap package with a simple Lua file — no Snapcraft YAML needed. Packaged, composable, version-controllable.

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### CLI

- [ ] **CLI-01**: `shoot` reads `shoot.lua` from current dir (or `--file` override)
- [ ] **CLI-02**: `shoot build` command triggers the build pipeline
- [ ] **CLI-03**: `--arch` flag for multi-arch builds
- [ ] **CLI-04**: `--output` flag for custom output path

### Lua DSL

- [ ] **LUA-01**: Embedded `mlua` evaluates `shoot.lua` with injected globals for snap declarations
- [ ] **LUA-02**: Table-based declarations for snap metadata, apps, permissions (Neovim-style)
- [ ] **LUA-03**: Multi-output structure — declare multiple snaps per file (Nix flake-style)
- [ ] **LUA-04**: Composable patterns — imports, overrides, functions (Nix-inspired)
- [ ] **LUA-05**: Clear error messages for invalid or missing fields

### Metadata

- [ ] **META-01**: Map processed Lua values to Rust structs matching Snap package format
- [ ] **META-02**: Generate `meta/snap.yaml` from struct data
- [ ] **META-03**: Support multi-arch metadata in output declarations

### Build

- [ ] **BUILD-01**: Assemble snap directory structure with binaries and `meta/`
- [ ] **BUILD-02**: Run `mksquashfs` to produce `[name]_[version]_[arch].snap`
- [ ] **BUILD-03**: Build for multiple architectures from one config

### Validation

- [ ] **VAL-01**: Validate Lua config structure before building
- [ ] **VAL-02**: Report missing required fields with clear guidance

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### System Images

- **SYS-01**: Build Ubuntu Core images (model assertions, gadget snaps)
- **SYS-02**: Image assembly pipeline (replacing `ubuntu-image`)

### Ecosystem

- **ECO-01**: Package registry / sharing composable modules
- **ECO-02**: IDE / editor support (LSP, syntax highlighting)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Ubuntu Core image assembly | v1 is single-snap packaging only; system images add model assertions, gadget snaps |
| macOS / Windows builds | Snaps target Linux; `mksquashfs` is Linux-native |
| Snapcraft preprocessor mode | Standalone tool — generates `.snap` directly |
| Nightly Rust features | Stable-only constraint |
| GUI / visual tooling | CLI-only for v1 |
| LSP / editor integration | Deferred to v2+ |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | — | Pending |
| CLI-02 | — | Pending |
| CLI-03 | — | Pending |
| CLI-04 | — | Pending |
| LUA-01 | — | Pending |
| LUA-02 | — | Pending |
| LUA-03 | — | Pending |
| LUA-04 | — | Pending |
| LUA-05 | — | Pending |
| META-01 | — | Pending |
| META-02 | — | Pending |
| META-03 | — | Pending |
| BUILD-01 | — | Pending |
| BUILD-02 | — | Pending |
| BUILD-03 | — | Pending |
| VAL-01 | — | Pending |
| VAL-02 | — | Pending |

**Coverage:**
- v1 requirements: 17 total
- Mapped to phases: 0
- Unmapped: 17 ⚠️

---
*Requirements defined: 2026-05-16*
*Last updated: 2026-05-16 after initial definition*
