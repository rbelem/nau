# Roadmap: shoot

**Defined:** 2026-05-16
**Granularity:** Fine (8 phases)
**Mode:** Vertical MVP — each phase delivers an end-to-end user capability

## Phase 1: Hello, shoot
**Goal:** Rust project scaffold with CLI skeleton and basic Lua evaluation
**Mode:** mvp
**Success Criteria:**
1. User can run `shoot build shoot.lua` and see parsed config printed to stdout
2. CLI handles `--file`, `--arch`, `--output` flags
3. `mlua` initializes and evaluates a simple Lua config
4. Tests pass for CLI parsing and Lua evaluation

**Requirements:** CLI-01, CLI-02, CLI-03, CLI-04, LUA-01

---

## Phase 2: Lua DSL Schema
**Goal:** Define the Lua table structure for a single snap declaration with validation
**Mode:** mvp
**Success Criteria:**
1. User writes Neovim-style Lua tables for name, version, summary, description, apps, plugs, slots
2. Tool validates required fields and reports clear errors for missing/invalid values
3. Tool validates field types (string, table, etc.)
4. Tests cover valid configs, invalid configs, and edge cases

**Requirements:** LUA-02, LUA-05, VAL-01, VAL-02

---

## Phase 3: Snap Metadata Mapping
**Goal:** Map validated Lua values to Rust structs matching the Snap package format
**Mode:** mvp
**Success Criteria:**
1. Rust structs cover all standard Snap metadata fields (name, version, apps, plugs, slots, etc.)
2. Lua tables → Rust structs conversion is complete and correct
3. Structs handle optional fields gracefully (defaults or None)
4. Tests cover round-trip Lua → struct data integrity

**Requirements:** META-01

---

## Phase 4: YAML Generation
**Goal:** Generate valid `meta/snap.yaml` from Rust structs
**Mode:** mvp
**Success Criteria:**
1. `meta/snap.yaml` is written to a temp directory with correct Snapcraft-compatible structure
2. YAML output matches the Snap package schema (snapd can parse it)
3. Tool handles edge cases: empty app list, no plugs, no slots
4. Tests validate generated YAML against expected format

**Requirements:** META-02, META-03 (arch field in YAML)

---

## Phase 5: Snap Assembly + SquashFS
**Goal:** Full pipeline — Lua config → `.snap` package
**Mode:** mvp
**Success Criteria:**
1. Tool assembles the snap directory: binaries/ under root, `meta/snap.yaml` in place
2. `mksquashfs` produces a valid `.snap` file
3. Output filename follows `[name]_[version]_[arch].snap` convention
4. `--output` flag controls output path
5. Tests: generated `.snap` can be inspected with `unsquashfs`

**Requirements:** BUILD-01, BUILD-02

---

## Phase 6: Multi-Architecture Builds
**Goal:** Build snaps for multiple architectures from one config
**Mode:** mvp
**Success Criteria:**
1. `--arch` flag filters or iterates over declared architectures
2. Lua DSL supports per-arch overrides in app definitions
3. Each arch build generates correct arch-specific metadata
4. Tests: build for amd64 and arm64 from same config

**Requirements:** CLI-03, META-03, BUILD-03

---

## Phase 7: Composable DSL — Imports & Overrides
**Goal:** Nix-inspired composability: import modules and override configs
**Mode:** mvp
**Success Criteria:**
1. Lua `require`/import loads shared config modules (e.g., `common.lua`)
2. Override semantics allow merging base configs with per-snap overrides
3. Modules can define reusable app templates, plug sets, slot configurations
4. Tests: compositional patterns produce expected merged configs

**Requirements:** LUA-04

---

## Phase 8: Batch Builds & Output Naming
**Goal:** Build all outputs from a multi-output `shoot.lua` with correct file naming
**Mode:** mvp
**Success Criteria:**
1. `shoot build` (no args) builds all declared outputs in sequence
2. Output files follow `[name]_[version]_[arch].snap` naming per output
3. `--output` flag works for single-output builds, auto-names for batch builds
4. Tests: batch build produces all correct `.snap` files

**Requirements:** LUA-03 (designed in Phase 1), CLI-02

---

## Coverage

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | Phase 1 | Pending |
| CLI-02 | Phase 1 | Pending |
| CLI-03 | Phase 1/6 | Pending |
| CLI-04 | Phase 1 | Pending |
| LUA-01 | Phase 1 | Pending |
| LUA-02 | Phase 2 | Pending |
| LUA-03 | Phase 1 | Pending |
| LUA-04 | Phase 7 | Pending |
| LUA-05 | Phase 2 | Pending |
| META-01 | Phase 3 | Pending |
| META-02 | Phase 4 | Pending |
| META-03 | Phase 4/6 | Pending |
| BUILD-01 | Phase 5 | Pending |
| BUILD-02 | Phase 5 | Pending |
| BUILD-03 | Phase 6 | Pending |
| VAL-01 | Phase 2 | Pending |
| VAL-02 | Phase 2 | Pending |

**All 17 v1 requirements mapped ✓**

---

*Last updated: 2026-05-16 after initial definition*
