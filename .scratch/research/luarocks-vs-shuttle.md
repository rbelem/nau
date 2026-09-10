# LuaRocks vs Shuttle — what the existing Lua package manager ecosystem implies for shuttle's design

*Cited research brief · Sep 2026 · shuttle = Rust CLI that builds Snaps from Lua declarations*

---

## 1. LuaRocks architecture

**Rockspec = a Lua file returning tables.** The manifest is literally a Lua source file whose top-level assignment populates plain data tables: `package`, `version`, `description`, `dependencies`, `build`, `source`, `test` [1]. There is no DSL grammar to parse — `luarocks` loads the file with Lua itself and inspects the resulting tables. Version strings are "X.Y.Z-rev" (e.g. `"2.0.1-1"`); dependency constraints are strings using Lua relational operators plus RubyGems' pessimistic `~>` [1].

**Build backends.** `build.type` selects a backend: `builtin` (direct copy for pure-Lua or simple C modules, with a `build.modules` map of sources, libraries, defines, incdirs), `make` (variables passed into a Makefile pass), `cmake`, `command` (raw `build_command`/`install_command` shell strings), and `none`. Backends are also **pluggable as rocks themselves** — e.g. the community `luarocks-build-xmake` backend [2] and `luarocks-build-builtin-with-command` [3]. A rockspec can even **embed unified-diff patches inline** as strings [1].

**Dependency model.** Three tiers [1][4]:
- `dependencies` — other rocks, resolved from rocks trees at install time.
- `external_dependencies` — C libraries, detected by probing for header/library *filenames* on pre-configured search paths (e.g. `EXPAT = { header = "expat.h" }`), exporting `KEY_DIR/_INCDIR/_LIBDIR` variables to build rules [1]. This is a *probe-and-fail* model: LuaRocks never downloads or builds C libs; it demands the OS provide them [4].
- `build_dependencies` / `test_dependencies` (since 3.0) for build/test-time-only rocks [1]. The special dependency `"lua"` constrains the Lua interpreter version [1].

**Install model.** Rocks install into **rocks trees** (`~/.luarocks`, `/usr/local`, …) — a versioned directory layout of Lua modules and native `.so` files — not into any OS package database. Dependency resolution modes (`one`/`all`/`order`/`none`) control which trees count [4]. The public repository (luarocks.org) serves manifest + source rocks; it is a registry of rockspecs, not of built binaries (binary rocks exist but the default flow builds from `source.url`) [1].

**Lockfiles (late addition, partial).** LuaRocks long had no lockfile story; modern versions (3.x, `luarocks init` projects) write a `luarocks.lock` file pinning resolved dependency versions, and `luarocks build` will honor it if present [5]. It pins versions, not source hashes or build environment.

## 2. The precedent angle: "package declarations as Lua" has shipped since ~2007

LuaRocks (described academically as "a declarative and extensible package management system for Lua", SBLP 2013 [6]) proved at 18+ years of ecosystem scale that a **manifest can be a real Lua file evaluated to pure data tables** and that this is ergonomic and greppable-diffable.

What it got right:
- **Convention: data, not code.** The rockspec format *documents* the tables as the contract [1]; authors write `package = "LuaSocket"` etc. Compute is confined to a few sanctioned spots (`build.type = "command"` strings, embedded patches). The 99% case is pure declarative tables.
- **Extensibility via the same mechanism:** build backends, test backends and upload tools are themselves Lua modules loadable as rocks [2][3] — the tool bootstraps its own plugin system on its own package ecosystem.
- **Multi-DSL authorship comfort:** Lua's table syntax reads like config while allowing loops/conditionals where genuinely needed (e.g. per-platform tables, `platform_overrides` [1]).

Problems it hit (instructive for shuttle):
- **Arbitrary code execution is intrinsic.** The `command` backend "execut[es] arbitrary shell during luarocks install … with no allowlist over which rocks may do so" [7]; rockspecs are Lua programs, so even "parsing" one executes attacker-controlled code. LuaRocks accepts this because it's a developer tool running as the user; a **builder** (like shuttle) evaluating untrusted manifests has a different threat model.
- **Non-hermetic builds.** `builtin`/`make`/`cmake` invoke whatever compiler/make is on `$PATH`; `external_dependencies` are resolved by *scanning the host filesystem* for headers [1][4]. Two machines produce different rocks. Reproducibility was never a design goal.

## 3. Non-goals / limits of LuaRocks relevant to shuttle

- **No sandbox, no hermeticity**: build steps run unsandboxed against host toolchain and host C libs [1][7].
- **Not system packaging**: installs into a Lua rocks tree, invisible to the OS, no services, no confinement, no cross-distro guarantee [4]. Conversely snapd has no notion of rocks.
- **Weak lock/repro story**: `luarocks.lock` pins resolved versions only, and only in `luarocks init` project workflows; no source hash pinning of `source.url` beyond optional MD5 of tarballs [1][5].
- **Native deps outsourced to the OS** (probe-headers model) — the exact problem snaps solve with `stage-packages` [1][4].

## 4. Interop options for shuttle

**(a) Shuttle consuming rockspecs.** Snapcraft today has **no Lua/LuaRocks plugin** — the official plugin list covers .NET, Cargo, Go, npm, Poetry, Python, Ruby, uv, etc., with no `lua` entry [8]. Snap packagers shipping Lua apps fall back to generic parts: `make`/`autotools`/`cmake` plugins or `override-build:` scriptlets that hand-run `luarocks make`/`luarocks install --tree=$SNAPCRAFT_PART_INSTALL` (override scriptlets are the documented escape hatch for non-plugin flows [9]), plus `build-packages: [lua5.x, luarocks]`. So there is a **real gap**: shuttle could parse rockspecs (as pure data — but note parsing requires evaluating Lua, e.g. via a sandboxed `mlua`/`hlua` with a restricted environment) and translate `dependencies` → snap parts, `external_dependencies` → `stage-packages`. Community overlap evidence: `snaphelpers` is a rock on LuaRocks specifically "for interfacing with the snap subsystem from within a snap" [10] — Lua devs are already snapping things by hand.

**(b) LuaRocks modules as shuttle's plugin system.** LuaRocks proved a tool can eat its own dog food (backends are rocks [2][3]). Shuttle could adopt the same shape: DSL extension hooks implemented as Lua modules resolvable via a vendored/bundled luarocks, giving free ecosystem distribution. Risk: pulling in LuaRocks' "manifests are programs" execution semantics; shuttle would need its own restricted module environment (no `io`/`os` in plugin sandbox unless explicitly granted).

**(c) Layering — complementary, not competing.** LuaRocks manages *Lua modules into a Lua runtime tree*; shuttle manages *OS applications into squashfs snaps* [4] vs snapd model. They occupy disjoint layers; the natural composition is shuttle orchestrating luarocks inside a part's build (like snapcraft's cargo plugin wraps cargo). There's even historical precedent of system packagers consuming rockspecs rather than replacing them — Fedora's Lua packaging draft explicitly planned "generating spec files from .rockspec specifications" [11].

## Sources

[1] Rockspec format — luarocks/luarocks docs (raw.githubusercontent.com/luarocks/luarocks/master/docs/rockspec_format.md)
[2] luarocks-build-xmake announcement — tboox.org/2021/01/22/luarocks-build-xmake-v1.0/
[3] luarocks-build-builtin-with-command — luarocks.org/modules/leso-kn/luarocks-build-builtin-with-command
[4] Dependencies (deps modes, external deps probing) — raw.githubusercontent.com/luarocks/luarocks/master/docs/dependencies.md
[5] `luarocks.lock` deplock files — luarocks/luarocks `src/luarocks/deplocks.lua`, `src/luarocks/deps.lua`, `spec/make_spec.lua` (github.com/luarocks/luarocks)
[6] "LuaRocks — a declarative and extensible package management system for Lua", Hisham Muhammad et al., SBLP 2013 — inf.puc-rio.br/~roberto/docs/sblp2013-2.pdf
[7] Nesbitt, "Install-script allowlists" (2026-06-05) — nesbitt.io/2026/06/05/install-script-allowlists.html
[8] Snapcraft plugins index (no Lua/LuaRocks plugin) — snapcraft.io/docs/snapcraft-plugins
[9] Snapcraft build overrides (`override-build` escape hatch) — documentation.ubuntu.com/snapcraft/8.14/explanation/build-overrides/
[10] snaphelpers rock — luarocks.org/modules/nuccitheboss/snaphelpers
[11] Fedora PackagingDrafts/Lua — fedoraproject.org/wiki/PackagingDrafts/Lua

*Note:* GitHub wiki pages and some luarocks.org doc URLs were login-walled/404 during research; the luarocks/luarocks repo `docs/*.md` files were used as the primary source instead (same content, canonical home).

---

## Feeds the grilling

1. **Shuttle's Lua evaluation is LuaRocks' biggest security lesson inverted**: rockspecs are programs, and parsing = executing. Will shuttle evaluate user manifests in a sandboxed Lua (mlua, restricted env, no `io`/`os`) — and are "pure data tables" a *verified* property or just a convention you enforce by lint?
2. LuaRocks confined compute to sanctioned escape hatches (`command` backend, embedded patches) and got 18 years of mileage. Will shuttle's DSL have explicit escape hatches (arbitrary shell in a part), or does snap-style `override-build` creep undermine the "declarative Lua" pitch?
3. LuaRocks' build backends are plugins distributed *as rocks*. Should shuttle's build/profile/DSL extensions be Lua modules loadable from luarocks — and if so, in what trust domain, since plugin code runs on the host at build time?
4. LuaRocks only grew lockfiles (~3.x, version-pins only) and still isn't hermetic — it delegates C libs to the OS. Snaps already solve the C-lib layer with `stage-packages`; is shuttle's reproducibility story then "translate rockspec `external_dependencies` → `stage-packages`", and does that translation have a deterministic mapping for the probe-by-header model?
5. Is rockspec **ingestion** a v1 feature, a plugin, or explicitly out of scope? If in scope: who evaluates the rockspec (shuttle's embedded Lua) and how do you handle rockspecs whose `build.type = "command"` is arbitrary shell — copy verbatim into a part (Snapcraft-equivalent trust) or refuse?
6. Snapcraft ships no Lua plugin [8]. Is shuttle's actual beachhead "the missing Lua plugin for the Snap world" (i.e., compete with *nothing*) — and if snapcraft later grows an official lua/luarocks plugin, what is shuttle's remaining reason to exist? (Presumably: full-image ShuttleOS assembly, which snapcraft can't do.)
7. LuaRocks' dep constraints live in strings (`"lfs >= 1.0, < 2.0"`); snapcraft's are YAML maps. Does shuttle adopt LuaRocks' constraint-string syntax, invent its own table-based form, or delegate resolution entirely to an embedded luarocks invocation?
8. Manifest-as-code means manifests can compute `version` from `git describe` etc. — convenient but kills diffability and cacheability. Does shuttle require manifests to be *statically analyzable* (pure data, cache-friendly) and how do you prove it?
