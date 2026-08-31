# Competitive Gap Analysis: shuttle vs Snapcraft & Nix

**Date:** 2026-06-01
**Author:** AI-assisted research (Snapcraft docs, Nix docs, shuttle codebase mapping)

---

## 1. Executive Summary

shuttle is a Rust CLI that builds Snap packages from Lua declarations. It has
completed an 8-phase MVP (single-snap packaging) plus 6 extension phases
(image assembly, package index, toolchain bootstrap, cross-compilation, etc.).
121 tests pass, clippy clean.

This document systematically compares shuttle against **Snapcraft** (the
established Python Snap builder) and **Nix/NixOS** (the declarative build &
deployment reference) to identify gaps, opportunities, and priorities.

**Key finding:** shuttle is strongest where Snapcraft is weakest (Lua
composability, cross-compilation, self-contained binary) and weakest where
Snapcraft is strongest (plugin ecosystem, remote builds, Store integration).
Against Nix, shuttle's input system is on the right track but lacks lockfile
pinning and a module system.

---

## 2. shuttle Current Capabilities (Codebase Map)

| Area | Capability | Code Location |
|------|-----------|---------------|
| **DSL** | `snap()`, `app()`, `image()`, `pin()`, `merge()`, `index()` | `src/dsl/init.lua` |
| **Snap metadata** | name, version, summary, description, license, source, grade, confinement, architectures, build, type, aliases, requires, target, toolchain, inputs, apps | `src/snap.rs` (SnapMeta) |
| **Snap apps** | command, daemon, plugs, slots, environment | `src/snap.rs` (SnapApp) |
| **Build** | Source download (curl) → extract (tar) → shell build → mksquashfs pack | `src/snap.rs` |
| **Sandbox** | bubblewrap isolation (unshare user/pid/ipc/net, ro-bind system paths) | `src/snap.rs` |
| **Cross-compilation** | `--target` flag, CC/CXX/LD/AR env vars, sysroot mount, CONFIGURE_TARGET | `src/snap.rs` |
| **Image assembly** | Multi-snap rootfs images (base + kernel + gadget + extras), disk images (GPT partitions, ESP, bootloader) | `src/image.rs` |
| **Package index** | `package-index.json`, `index()` DSL, store resolution | `src/index.rs` |
| **Package inputs** | `github:user/repo[/branch]` and `path:/local/dir`, cache at `~/.cache/shuttle/inputs/` | `src/pkg_source.rs` |
| **Lockfile** | `shuttle.lock` — source hash pinning + snap revision/checksum pinning | `src/lock.rs` |
| **Binary cache** | `~/.cache/shuttle/pkgs/`, SHA-256 keyed, LRU pruning | `src/cache.rs` |
| **Dependencies** | `requires` field, topological resolution, `--order`, `--tree`, `--flat` | `src/deps.rs` |
| **Toolchain** | GCC/LLVM bootstrap packages, meta-package orchestrator, `toolchain` field | `pkgs/` |
| **CLI** | build, image, deps, search, doctor, completion, cache, index subcommands | `src/cli.rs` |
| **Store client** | Snap Store resolution + download + sha3-384 verification | `src/store.rs` |
| **JSON output** | Machine-readable build results | `src/output.rs` |

---

## 3. Gap Analysis: shuttle vs Snapcraft

### 3.1 Plugin System — CRITICAL GAP

**Snapcraft:** 35+ plugins (autotools, cmake, meson, rust, python, go, node,
dotnet, flutter, etc.). Each plugin knows how to configure, build, stage, and
prime a specific language/build system. Custom plugins are deprecated (core22+)
in favor of `plugin: nil` + scriptlets.

**shuttle:** No plugin system. Everything is `build = "shell-command"` with
`$SRC`, `$STAGE` env vars. This works for simple cases but misses:
- Language-specific dependency management (cargo fetch, pip install)
- Build system integration (cmake --build with correct flags)
- Cross-compilation per plugin (rust cross-target, python cross-build)
- Stage/prime file filtering (what gets included in the snap)

**Priority:** HIGH
**Effort:** Large (new module: `src/plugin/` with per-plugin types)
**Path:** Start with `cargo` and `make` plugins, then autotools + cmake

### 3.2 Parts Lifecycle — CRITICAL GAP

**Snapcraft:** Four-step lifecycle per part: `pull → build → stage → prime`.
Parts have `after:` ordering. The `stage/` directory merges outputs from all
parts. The `prime/` directory filters staged files per-snap. File-set filtering
(`stage-files`, `prime-files`) controls what lands where.

**shuttle:** Single build command per snap, no parts. Dependencies are
external snaps (via `requires`), not co-packaged build units. No staging
merge from multiple parts.

**Priority:** HIGH
**Effort:** Large (requires refactoring build pipeline into stages)
**Path:** Phase A — add multi-part support to the DSL (`part()` function).
Phase B — implement stage/prime lifecycle with merge semantics.

### 3.3 snap.yaml Coverage — MEDIUM GAP

**Snapcraft snapcraft.yaml fields shuttle does NOT support:**

| Field | Importance | Notes |
|-------|-----------|-------|
| `layout` | HIGH | Bind mounts, symlinks, tmpfs for FHS compat |
| `hooks` | HIGH | install, configure, pre-refresh, post-refresh scripts |
| `plugs` (typed) | MEDIUM | shuttle supports string arrays but not typed plug definitions |
| `slots` (typed) | MEDIUM | Same — string arrays only, not typed with interface/attributes |
| `environment` (global) | MEDIUM | Per-app env exists, global env missing |
| `system-usernames` | LOW | Daemon user configuration |
| `assumes` | LOW | Minimum snapd version assertions |
| `compression` | LOW | xz vs lzo |
| `type` | LOW | app/base/gadget/kernel/snapd |
| `epoch` | LOW | Data compatibility epochs |
| `lint` | LOW | Linter configuration |
| `package-repositories` | MEDIUM | APT repo configuration for stage-packages |
| `build-base` | MEDIUM | Separate build environment base |
| `icon` | MEDIUM | Snap icon |
| `adopt-info` | MEDIUM | Inherit metadata from part |
| `passthrough` | LOW | Raw pass-through to snap.yaml |

**Priority:** MEDIUM-HIGH
**Effort:** Small-Medium per field (DSL validation + Rust struct + YAML
serialization). Priority order: layout, hooks, typed plugs/slots, environment.

### 3.4 Build Environment Management — MEDIUM GAP

**Snapcraft:** LXD containers and Multipass VMs as build providers. Clean-room
builds with `--use-lxd` or `--destructive-mode`. Parallel builds via multiple
containers.

**shuttle:** bubblewrap sandbox only. Host-based with namespace isolation.
No container/VM build providers. No parallel builds.

**Priority:** MEDIUM
**Effort:** Medium (LXD API integration for ephemeral containers)
**Path:** Add `--use-lxd` flag using LXD Go/REST API via command-line.
Parallelism follows from multi-part support.

### 3.5 Remote Build & Publishing — MEDIUM GAP

**Snapcraft:** `snapcraft remote-build` uses Launchpad CI for multi-arch
builds. `snapcraft upload --release <channel>` publishes to Snap Store.
Progressive releases, tracks, channels.

**shuttle:** No remote build. No Store publishing. `shuttle build` is local-only.
Store integration is read-only (resolution + download for image assembly).

**Priority:** MEDIUM
**Effort:** Large (Launchpad API is custom, Snap Store assertions are complex)
**Path:** Consider simpler: GitHub Actions integration first (artifact upload),
then Snap Store CLI upload via snapcraft's own tools, then native integration.

### 3.6 Extensions — LOW-MEDIUM GAP

**Snapcraft:** GNOME, KDE, Flutter, ROS extensions pre-configure build/runtime
environment. `snapcraft expand-extensions` shows the expanded YAML.

**shuttle:** No extension system. Equivalent: Lua modules + merge() pattern.
Users can `require("desktop")` and `merge(base, desktop)` — this is arguably
more flexible than Snapcraft extensions but requires manual authoring.

**Priority:** LOW (Lua composability already solves this)
**Effort:** Minimal (add workspace/desktop templates to pkgs/lib/)

### 3.7 Content Interfaces & Layouts — MEDIUM GAP

**Snapcraft:** Content interface providers/consumers share directories between
snaps. Layout declarations bind-mount snap-internal paths to host locations.

**shuttle:** Has `plugs` and `slots` as string arrays but no typed content
interface definitions. No `layout` DSL at all.

**Priority:** MEDIUM-HIGH (content sharing is core to the snap ecosystem)
**Effort:** Medium per feature

### 3.8 Known Snapcraft Pain Points (shuttle advantages)

| Snapcraft Pain Point | shuttle Advantage |
|---------------------|-----------------|
| YAML complexity + multiple base versions | Single Lua DSL, one base target |
| Cryptic Pydantic validation errors | Lua stack traces + Rust type safety |
| Plugin option inconsistency | Homogeneous Lua table syntax |
| Slow build iteration | Rust binary, fast startup |
| Python performance | Rust performance |
| Multiple base syntaxes (core18/20/22/24) | Single canonical DSL |
| Steep learning curve | Lua is familiar to many devs |

---

## 4. Gap Analysis: shuttle vs Nix/NixOS

### 4.1 Lockfile for Inputs — CRITICAL GAP

**Nix:** `flake.lock` pins every input to a specific revision with content
hashes (`narHash`). Transitive locking — indirect dependencies are also pinned.
`nix flake update` updates specific inputs. `follows` prevents duplication.

**shuttle:** Package inputs (`github:user/repo[/branch]`) have a local cache
but **no lockfile**. `shuttle index update` re-fetches the default input but
doesn't pin revisions. This means builds are NOT reproducible across time.

**Priority:** CRITICAL
**Effort:** Medium (extend `shuttle.lock` with input entries, add `--update`
flag to update specific inputs, add `follows`-like dependency propagation)

### 4.2 Module System — MEDIUM-HIGH GAP

**NixOS:** Powerfully composable module system with option declarations,
types, `mkIf`/`mkMerge`/`mkForce` priorities, submodules, import composition.
The `evalModules` function handles configuration merging declaratively.

**shuttle:** Lua `merge()` function handles shallow/deep merging but has no
option declaration system, no type checking beyond ad-hoc validation, no
conditional enabling (`mkIf` equivalent), no override priorities.

**Priority:** MEDIUM-HIGH (positions shuttle for declarative system assembly)
**Effort:** Large (new subsystem: option declaration + type system + merge)
**Path:** Borrow from NixOS: `option { type = "string", default = "x" }`,
`config = mkIf(condition, { ... })`. Full scope is Phases 6-7 material.

### 4.3 Content-Addressed Store — MEDIUM GAP

**Nix:** `/nix/store/<hash>-<name>-<version>` — immutable, content-addressed,
GC-rooted. Hash encodes all build inputs (source + dependencies + build
script). This enables binary caching, reproducibility, and safe GC.

**shuttle:** Binary cache at `~/.cache/shuttle/pkgs/` is SHA-256 keyed by source
tarball, NOT by full build input. Cache entries can be stale if dependencies
change without source change. GC is manual (LRU time-based, not reference-
counted).

**Priority:** MEDIUM
**Effort:** Medium-Large (content addressing requires full input enumeration)
**Path:** Add build input hashing to cache keys. Add reference tracking.

### 4.4 Flake Registry — LOW GAP

**Nix:** Global registry resolves short names (e.g. `nixpkgs` →
`github:NixOS/nixpkgs/nixos-unstable`). Can be overridden in `nix.conf`.

**shuttle:** Package index (`package-index.json`) serves a similar role but
only covers snap definitions, not input sources. No registry for package
inputs.

**Priority:** LOW
**Effort:** Small (add registry URL resolution to `pkg_source.rs`)

### 4.5 Closure Analysis — LOW GAP

**Nix:** `nix why-depends` shows why a package depends on something. `nix
store --query --requisites` lists full closure. Tree visualization.

**shuttle:** `shuttle deps` shows direct + transitive dependencies. `--tree` and
`--flat` output modes exist. JSON output for tooling. This is actually
relatively mature for the current scope.

**Priority:** LOW (already functional)

### 4.6 Nix Pain Points (shuttle advantages)

| Nix Pain Point | shuttle Advantage |
|----------------|-----------------|
| Custom functional language | Lua — familiar to many |
| FHS incompatibility | Snap packages use FHS — no compat layer needed |
| Cryptic error messages | Lua stack traces + Rust errors |
| Disk space bloat | Simple cache with max-size enforcement |
| Steep learning curve | Simple Lua DSL ~50 lines of init |
| Build debugging difficulty | Direct shell commands, no derivation abstraction |

---

## 5. Phased Roadmap (Next 8 Phases)

### Phase 15: Complete snap.yaml Coverage
**Goal:** Support all commonly-used snap.yaml fields
**Effort:** Medium
**Tasks:**
1. Add `layout` DSL + struct + YAML — bind/bind-file/symlink/tmpfs
2. Add `hooks` DSL + struct + YAML (install, configure, pre/post-refresh, remove)
3. Add typed plugs/slots with interface, attributes, content tags
4. Add global `environment` field
5. Add `icon` support (copy into meta/)
6. Add `compression` field (xz/lzo)
7. Add `type` field (app/base/gadget/kernel/snapd) — partially exists
8. Add `adopt-info` pattern

**DSL example:**
```lua
snap {
    name = "my-app",
    version = "1.0",
    layout = {
        ["/etc/myapp.conf"] = { bind_file = "$SNAP_DATA/etc/myapp.conf" },
        ["/var/run/myapp"] = { symlink = "$SNAP_COMMON/run" },
    },
    hooks = {
        configure = "scripts/configure.sh",
        install = "scripts/install.sh",
    },
    plugs = {
        network = { interface = "network" },
        shared-data = {
            interface = "content",
            content = "my-content",
            target = "$SNAP/data",
            default_provider = "producer",
        },
    },
}
```

### Phase 16: Package Inputs Lockfile
**Goal:** Reproducible builds from locked input revisions
**Effort:** Medium
**Tasks:**
1. Extend `shuttle.lock` format with `inputs` section (name → { url, rev, narHash })
2. `shuttle build --lock` or implicit locking when building with inputs
3. `shuttle build --update <input>` to refresh a specific input
4. `shuttle lock` subcommand — generate/update lockfile without building
5. Use locked revisions in pkg_source resolution (fail if missing)
6. Add `--offline` mode that uses only cached/locked inputs

**Lockfile format addition:**
```json
{
  "version": 1,
  "inputs": {
    "packages": {
      "url": "github:rbelem/shuttle/main",
      "rev": "abcdef1234567890",
      "narHash": "sha256-..."
    }
  },
  "sources": {},
  "snaps": {}
}
```

### Phase 17: Plugin System (MVP)
**Goal:** Language/build-system plugins beyond raw shell commands
**Effort:** Large
**Tasks:**
1. Design plugin trait in Rust: `pull()`, `build()`, `stage()`, `prime()`
2. Implement `MakePlugin` (autotools-style: configure/make/make install)
3. Implement `CargoPlugin` (cargo build + binary discovery)
4. Add `plugin` + `plugin-opts` fields to snap() DSL
5. Auto-detect plugin from project structure (Cargo.toml → cargo, Makefile → make)
6. Part-level `after` ordering for multi-part builds

**DSL example:**
```lua
snap {
    name = "my-rust-app",
    version = "1.0",
    plugin = "cargo",
    source = "https://github.com/user/repo/archive/v1.0.tar.gz",
    plugin_opts = {
        features = { "default" },
        release = true,
    },
    apps = {
        my-app = app { command = "bin/my-app" },
    },
}
```

### Phase 18: Multi-Part Builds
**Goal:** Assemble a single snap from multiple build parts
**Effort:** Large
**Tasks:**
1. Add `parts` table to snap() DSL (parallel to list of parts)
2. Implement stage/prime lifecycle merge semantics
3. Implement `after` ordering between parts
4. Part-level file filtering (`stage-files`, `prime-files`, `stage-excludes`)
5. Parallel part building when dependencies allow
6. Build provider abstraction (host, LXD, multipass)
7. Add `--use-lxd` flag for containerized builds

**DSL example:**
```lua
snap {
    name = "full-stack-app",
    version = "1.0",
    parts = {
        backend = part {
            plugin = "cargo",
            source = "https://github.com/user/backend.git",
            after = { "libs" },
            stage_files = { "bin/*" },
        },
        frontend = part {
            plugin = "npm",
            source = "https://github.com/user/frontend.git",
            after = { "libs" },
            prime_files = { "www/*" },
        },
        libs = part {
            plugin = "make",
            source = "https://github.com/user/libs.git",
        },
    },
}
```

### Phase 19: Content/Layout Interfaces
**Goal:** Content-sharing between snaps + filesystem layouts
**Effort:** Medium
**Tasks:**
1. Typed content interface declarations (slots + plugs with interface key)
2. Layout bind-mount/symlink/tmpfs generation
3. Content interface auto-connection hints
4. `default-provider` in DSL

### Phase 20: CI/CD Integration
**Goal:** Build snaps in CI pipelines
**Effort:** Medium
**Tasks:**
1. GitHub Action: `rbelem/shuttle-action` (install shuttle, build, output .snap)
2. `shuttle github-action` subcommand to generate CI workflow
3. `shuttle upload` — upload to Snap Store (via snapcraft's store API)
4. `shuttle release --channel` — release to channels

### Phase 21: NixOS-Inspired Module System
**Goal:** Declarative system assembly with typed options
**Effort:** Large
**Tasks:**
1. Lua `option()` function: declare typed options with defaults
2. `mkIf(condition, config)` for conditional snap inclusion
3. `mkMerge(list)` and `mkForce(value)` for override priorities
4. Recursive module evaluation (evalModules equivalent)
5. Snap option libraries (networking, desktop, server profiles)
6. Full Ubuntu Core image definition from modular Lua

**DSL example:**
```lua
-- modules/desktop.lua
return {
    options = {
        desktop = {
            greeter = option { type = "string", default = "gdm" },
        },
    },
    config = mkIf(config.desktop.enabled, {
        snaps = {
            gnome-desktop = pin("gnome-3-38-2004-sdk"),
            pulseaudio = pin("pulseaudio"),
        },
    }),
}
```

### Phase 22: Content-Addressed Store
**Goal:** Nix-style content-addressed build cache for full reproducibility
**Effort:** Large
**Tasks:**
1. Hash-address build outputs by (source_hash + dep_hashes + build_script_hash)
2. GC using reference counting (Nix-style reachability from roots)
3. `nix-store --query --requisites` equivalent for snaps
4. Binary cache export/import for air-gapped builds
5. `shuttle store --serve` — local binary cache HTTP endpoint

---

## 6. Priority Matrix

| Phase | Impact | Effort | Risk | Priority Score |
|-------|--------|--------|------|----------------|
| **15: snap.yaml coverage** | High | Medium | Low | ★★★★★ |
| **16: Inputs lockfile** | High | Medium | Low | ★★★★★ |
| **17: Plugin MVP (cargo/make)** | High | Large | Medium | ★★★★☆ |
| **18: Multi-part builds** | High | Large | High | ★★★★☆ |
| **19: Content/layout** | Medium | Medium | Low | ★★★☆☆ |
| **20: CI/CD** | Medium | Medium | Low | ★★★☆☆ |
| **21: NixOS module system** | Medium | Large | High | ★★☆☆☆ |
| **22: Content-addressed store** | Medium | Large | High | ★★☆☆☆ |

**Recommended sequence:**
1. **Phase 15** (snap.yaml completion) — quick wins, low risk, high user value
2. **Phase 16** (input lockfile) — fixes reproducibility, prerequisite for
   production use
3. **Phase 17** (plugins) — unlocks real-world language build workflows
4. **Phase 18** (multi-part) — enables complex snaps, parallels phases 17
5. **Phase 19/20** (content interfaces + CI/CD) — ecosystem integration
6. **Phase 21/22** (module system + content addressing) — advanced features

---

## 7. Competitive Positioning

### Where shuttle wins TODAY:
- **Lua config vs YAML**: Composability, merging, require(), conditionals
- **Cross-compilation**: Built-in `--target` flag, bubblewrap sandbox
- **Self-contained binary**: Single Rust binary, no Python dependency
- **Image assembly**: Full disk image creation from multiple snaps
- **Package index + inputs**: Nix-inspired runtime package resolution

### Where shuttle needs to catch up:
- **Plugins**: Must implement 4-5 language plugins to be credible
- **snap.yaml completeness**: Must cover layout, hooks, typed plugs/slots
- **Lockfile reproducibility**: Must pin input revisions
- **Multi-part builds**: Single-part snaps are limiting

### Differentiation strategy:
1. **Lua DSL as moat** — Snapcraft's YAML is painful; shuttle's Lua is the
   core value proposition
2. **Cross-compilation first** — Snapcraft cross-compilation is complex;
   shuttle makes it first-class with `--target`
3. **Ubuntu Core image builder** — shuttle's image assembly is something
   Snapcraft doesn't do directly (snapcraft doesn't build Ubuntu Core images)
4. **Nix-inspired architecture** — lockfile + inputs + module system =
   Nix-level reproducibility without Nix's complexity
5. **Rust performance** — fast CLI, fast builds, no Python overhead

---

## 8. References

- Snapcraft docs: https://documentation.ubuntu.com/snapcraft/latest/
- Snapcraft plugins: https://documentation.ubuntu.com/snapcraft/latest/reference/plugins/
- Snapcraft parts lifecycle: https://documentation.ubuntu.com/snapcraft/latest/explanation/parts-lifecycle/
- Nix flakes: https://nix.dev/manual/nix/2.18/command-ref/new-cli/nix3-flake.html
- NixOS modules: https://nlewo.github.io/nixos-manual-sphinx/development/writing-modules.xml.html
- Nix derivations: https://nix.dev/manual/nix/latest/language/derivations
- shuttle codebase: `src/` modules as of commit 92d207a
- shuttle roadmap: `.planning/archive/ROADMAP.md`
