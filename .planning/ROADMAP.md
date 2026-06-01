# Roadmap: shoot

**Defined:** 2026-05-16
**Granularity:** Fine (8 phases, later extended)
**Mode:** Vertical MVP — each phase delivers an end-to-end user capability

## Phase 1: Hello, shoot
**Status:** ✅ Complete
**Goal:** Rust project scaffold with CLI skeleton and basic Lua evaluation
**Mode:** mvp
**Success Criteria:**
1. ✅ User can run `shoot build shoot.lua` and see parsed config printed to stdout
2. ✅ CLI handles `--file`, `--arch`, `--output` flags
3. ✅ `mlua` initializes and evaluates a simple Lua config
4. ✅ Tests pass for CLI parsing and Lua evaluation

**Requirements:** CLI-01, CLI-02, CLI-03, CLI-04, LUA-01

---

## Phase 2: Lua DSL Schema
**Status:** ✅ Complete
**Goal:** Define the Lua table structure for a single snap declaration with validation
**Mode:** mvp
**Success Criteria:**
1. ✅ User writes Neovim-style Lua tables for name, version, summary, description, apps, plugs, slots
2. ✅ Tool validates required fields and reports clear errors for missing/invalid values
3. ✅ Tool validates field types (string, table, etc.)
4. ✅ Tests cover valid configs, invalid configs, and edge cases

**Requirements:** LUA-02, LUA-05, VAL-01, VAL-02

---

## Phase 3: Snap Metadata Mapping
**Status:** ✅ Complete
**Goal:** Map validated Lua values to Rust structs matching the Snap package format
**Mode:** mvp
**Success Criteria:**
1. ✅ Rust structs cover all standard Snap metadata fields (name, version, apps, plugs, slots, etc.)
2. ✅ Lua tables → Rust structs conversion is complete and correct
3. ✅ Structs handle optional fields gracefully (defaults or None)
4. ✅ Tests cover round-trip Lua → struct data integrity

**Requirements:** META-01

---

## Phase 4: YAML Generation
**Status:** ✅ Complete
**Goal:** Generate valid `meta/snap.yaml` from Rust structs
**Mode:** mvp
**Success Criteria:**
1. ✅ `meta/snap.yaml` is written to a temp directory with correct Snapcraft-compatible structure
2. ✅ YAML output matches the Snap package schema (snapd can parse it)
3. ✅ Tool handles edge cases: empty app list, no plugs, no slots
4. ✅ Tests validate generated YAML against expected format

**Requirements:** META-02, META-03 (arch field in YAML)

---

## Phase 5: Snap Assembly + SquashFS
**Status:** ✅ Complete
**Goal:** Full pipeline — Lua config → `.snap` package
**Mode:** mvp
**Success Criteria:**
1. ✅ Tool assembles the snap directory: binaries/ under root, `meta/snap.yaml` in place
2. ✅ `mksquashfs` produces a valid `.snap` file
3. ✅ Output filename follows `[name]_[version]_[arch].snap` convention
4. ✅ `--output` flag controls output path
5. ✅ Tests: generated `.snap` can be inspected with `unsquashfs`

**Requirements:** BUILD-01, BUILD-02

---

## Phase 6: Multi-Architecture Builds
**Status:** ✅ Complete
**Goal:** Build snaps for multiple architectures from one config
**Mode:** mvp
**Success Criteria:**
1. ✅ `--arch` flag filters or iterates over declared architectures
2. ✅ Lua DSL supports per-arch overrides in app definitions
3. ✅ Each arch build generates correct arch-specific metadata
4. ✅ Tests: build for amd64 and arm64 from same config

**Requirements:** CLI-03, META-03, BUILD-03

---

## Phase 7: Composable DSL — Imports & Overrides
**Status:** ✅ Complete
**Goal:** Nix-inspired composability: import modules and override configs
**Mode:** mvp
**Success Criteria:**
1. ✅ Lua `require`/import loads shared config modules (e.g., `common.lua`)
2. ✅ Override semantics allow merging base configs with per-snap overrides
3. ✅ Modules can define reusable app templates, plug sets, slot configurations
4. ✅ Tests: compositional patterns produce expected merged configs

**Requirements:** LUA-04

---

## Phase 8: Batch Builds & Output Naming
**Status:** ✅ Complete
**Goal:** Build all outputs from a multi-output `shoot.lua` with correct file naming
**Mode:** mvp
**Success Criteria:**
1. ✅ `shoot build` (no args) builds all declared outputs in sequence
2. ✅ Output files follow `[name]_[version]_[arch].snap` naming per output
3. ✅ `--output` flag works for single-output builds, auto-names for batch builds
4. ✅ Tests: batch build produces all correct `.snap` files

**Requirements:** LUA-03 (designed in Phase 1), CLI-02

---

## Beyond MVP — Image Assembly & System Building

The original 8-phase roadmap covered single-snap packaging. The following
extensions were added after MVP completion:

### Image Assembly (Phase 9 — ✅ Complete)
**Goal:** Bootable disk images from multiple snaps
**Features:**
- ✅ `image()` DSL function: compose base, kernel, gadget, and extra snaps
- ✅ GPT disk layout with configurable partitions (ESP + root + swap)
- ✅ Kernel parameters, modules, modprobe config via `merge()` with pin tables
- ✅ Bootloader configuration (systemd-boot, grub)
- ✅ sysctl kernel tuning
- ✅ `shoot image` CLI command
- ✅ Full disk image creation: parted + mkfs + loopback + bootloader install

### Package Index (Phase 10 — ✅ Complete)
**Goal:** Canonical package registry for snap definitions
**Features:**
- ✅ `pkgs/` directory with Ubuntu pool convention (flat by-name, first-letter subdirs)
- ✅ `package-index.json` with pre-resolved pins
- ✅ `index()` DSL function for named lookups
- ✅ `shoot index list`, `add`, `resolve` subcommands
- ✅ Alias resolution (`find_by_name_or_alias`)
- ✅ Fallback from store → index in image builder

### Base System Packages (Phase 11 — ✅ Complete)
**Goal:** Decompose core22 into individual source packages
**Features:**
- ✅ 105 packages in `pkgs/` covering all system dependencies
- ✅ Source-based build scripts with real upstream URLs
- ✅ Build tools: make, autotools, pkg-config, texinfo, gettext
- ✅ GCC toolchain: binutils, gmp, mpfr, mpc, isl, gcc
- ✅ LLVM/Clang toolchain: cmake, ninja, llvm, clang, lld, compiler-rt, libc++
- ✅ Meta-packages: toolchain-gcc-gnu-x86_64, toolchain-clang-gnu-x86_64, build-deps
- ✅ `type` field: source / meta / store
- ✅ `requires` field for build dependency declarations
- ✅ `aliases` field for alternative names

### Tooling (Phase 12 — ✅ Complete)
**Features:**
- ✅ `shoot deps` subcommand: dependency tree resolution
- ✅ `shoot build --order`: print build order without building
- ✅ `shoot doctor`: system readiness checks

---

## Coverage

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

**All 17 v1 requirements Done ✓**

---

*Last updated: 2026-06-01 — fully updated to reflect actual project state*

## Status Key

- **Pending** — Not started
- **In Progress** — Actively being worked on
- **Complete** — Delivered, tests pass, documented
