# Lua Build Systems vs Shuttle — What Transfers to a Snap Packager

Research brief · shuttle (Rust CLI building Snap packages from Lua declarations) · Sep 2026

Question: build systems based on Lua vs Shuttle. Would anything from a build system help shuttle be a better package manager and handle building packages better?

---

## 1. The Lua-based build-system landscape

### XMake — the closest full analog (build engine + package manager + Lua DSL)

- **Positioning**: "Xmake = Build backend + Project Generator + Package Manager + [Remote|Distributed] Build + Cache… Xmake ≈ Make/Ninja + CMake/Meson + Vcpkg/Conan + distcc + ccache/sccache" [1].
- **Both layers are Lua.** The project manifest (`xmake.lua`, declarative `target()`/`add_requires()` DSL) *and* every package recipe (`xmake-repo` entries with `package("zlib") … on_install("linux", function (package) … end)`) are Lua executed at load/build time [2][3]. This is exactly the shape shuttle is contemplating: a Lua manifest that references packages whose build logic is also Lua.
- **Targets/dependencies**: targets declare files + kind; `add_requires("tbox 1.6.*")` + `add_packages("tbox")` wires a dependency into a target with automatic linkdirs/includeirs; semver ranges, optional deps, per-platform `on_install("linux", …)` dispatch, config inheritance down the dep chain (e.g. `vs_runtime` MD inherited by transitive deps) [3].
- **Reproducibility story (partial)**: every version pinned in the repo has a sha256 [3]; a `xmake-requires.lock` lockfile (v2.5.7+, npm/cargo-lock-style) pins versions + repo commits [3]; `{verify = false}` is explicitly flagged as a security risk [3].
- **Caching**: built-in local C/C++ content-based build cache, plus **remote cache similar to Mozilla's sccache** [4]. Parallel compilation and "optimized dependency analysis" are headline features [5].
- **Sandboxing story: essentially none.** XMake docs warn not to install/run as root "because this is very insecure" [6] — the risk model acknowledged is filesystem damage, not manifest code execution. `on_install` recipes call `os.vrun("./config …")`, `make`, `os.cp`, etc. — full host access from Lua [3]. There is a Lua *syntax* sandbox (xmake patches its embedded Lua with restricted/patched stdlib, per its implementation), but it is about providing a consistent API surface, not a security boundary. In practice the model is **trusted user**: any `xmake.lua` you build from runs arbitrary code on your machine, same as a Makefile or CMake script.

### Premake5 — generation-over-building

- Premake "reads a scripted definition of a software project and … uses it to generate project files for toolsets like Visual Studio, Xcode, or GNU Make" [7]. Lua defines workspaces/projects/filters; actions emit `.sln`/Makefiles/Ninja files.
- **Why generation instead of building**: the value proposition is letting developers use the IDE/toolset they prefer — "Maximize your potential audience by allowing developers to use the platforms and toolsets they prefer", "Keep builds in sync across toolsets by generating project from the Premake scripts on demand" [7]. Premake deliberately owns *project description*, not *build execution*: incremental scheduling, toolchains, caching all remain the delegated backend's job.
- **Limit that puts on it**: no dependency DAG control over compilation, no caching, no package management of its own — a Premake script is a frontend; correctness and performance belong to MSBuild/Make/Ninja. This is the "thin Lua frontend" end of the spectrum.
- Premake also advertises its full Lua environment for "automation of complex configuration tasks" — again, unrestricted Lua, trusted-user model [7].

### Others, one line each

- **LuaRocks `builtin` build mode**: a Lua `rockspec` can drive the built-in `make`-like build with simple module tables — Lua as declarative description with imperative escape hatch; LR is a *package* manager first, so it's actually the nearest *packaging* precedent for shuttle's Lua-manifest idea.
- **Lake**: a small Lua-based make-like (ant-flavored); niche, mostly historical.

## 2. Which build-system mechanics transfer to a snap packager

| Feature | Does a snap packager need it? | What snapcraft/craft-parts does today | Cost to own |
|---|---|---|---|
| **Dependency DAG** | Yes — snapcraft *parts* already form a DAG via `after:` | Craft-parts processes parts through a **PULL → OVERLAY → BUILD → STAGE → PRIME** lifecycle [8]; execution order follows part dependencies; parts are built **sequentially** — parallelism exists only *inside* one part's build via `CRAFT_PARALLEL_BUILD_COUNT` (a per-part job count, not across parts) [8][9] | Medium: a topological scheduler + per-part state dirs. This is the single clearest win — inter-part parallelism is absent in craft-parts |
| **Rebuild-only-changed** | Yes (a full rebuild per tweak is the classic snapcraft pain) | Craft-parts does have per-step caches: the pull step "places them [sources] into a **package cache**", parts have cache state keyed by a **cache version / part properties hash**, so a part whose declared properties didn't change skips its step; `snapcraft clean <part> --unpatch` and `--step` exist for surgical invalidation [8][10] | Medium-high: content hashing of declared inputs (part spec + scriptlets + files) is the hard part; hashing the *recipe text* is the 80% solution |
| **Artifact / build caching** | Only at part granularity today | No inter-part build cache, no remote cache; a shared per-machine packages cache covers *pulled sources*, not build outputs [8] | High to do well (remote cache like sccache needs content-addressed storage + trust model); local part-output cache is moderate |
| **Toolchain detection** | Partially — snaps pin to a base (core22/24), so toolchain comes from the base/staged snaps, not the host | Plugins (autotools, cmake, …) assume the right tools in the build env; less detection needed than a generic build system | Low — mostly already solved by base snaps |
| **Hermetic environments** | Yes in spirit — reproducibility is a snap selling point | Builds run in managed instances/chroots managed by craft-application, but *inside* the build env there is no hermeticity: scriptlets have network and full env, PATH/flags are merely *conventions* injected by craft-parts [8] | Very high if done properly (that's a Nix/Bazel project); documented middle ground: record env + hash inputs |

**Bottom line of this section**: the two mechanics worth stealing are (a) topological scheduling to parallelize *across parts* (craft-parts today doesn't), and (b) content-hash-keyed part caches keyed on the Lua manifest, to skip unchanged parts (craft-parts has the concept — part properties hash + cache version [10] — and it proves the design works in a snap packager).

## 3. Security / manifest-eval angle

Three evaluation models exist among the systems compared:

- **Unrestricted Lua at load** (XMake, Premake, LuaRocks `on_build` hooks): any manifest/recipe runs arbitrary code with user privileges. Mitigation in practice: none technical — trusted-user model; docs only warn against running *as root* [6][7].
- **Non-Turing-complete DSL** (Meson): "The main design principle of Meson is that the definition language is not Turing complete. Any change that would make Meson Turing complete is automatically rejected" [11]; rationale: no infinite loops/undecidable behavior, easier reasoning and IDE integration [11][12]. Note the *stated* motivation is consistency/analyzability, not sandboxing — a non-Turing-complete language is still not safe to evaluate from an untrusted source.
- **Sandboxed/special-purpose evaluation** (Nix): the Nix expression language is pure/lazy and evaluation has no arbitrary side effects; builds can be sandboxed (no network, isolated FS). That's why `nixpkgs` can be reviewed as data rather than as programs.

**Implication for shuttle**: if shuttle keeps Lua (per the project charter — "Neovim's Lua-based configurability"), it inherits the XMake/Premake trusted-user model: *a shuttle manifest is code, treat it like a Makefile*. Two practical mitigations that Lua ecosystems actually use, without abandoning Lua:

1. **Restrict what the Lua environment exposes** (XMake-style patched stdlib): allow the DSL calls, expose a narrow `os`/`io` subset, no `require` of arbitrary modules during *evaluation*; defer all side-effectful work to explicitly declared build hooks.
2. **Keep evaluation pure, execution explicit**: manifest evaluation computes a *plan* (parts, sources, hashes — the data a lockfile needs); anything that runs commands happens in declared hook functions executed during build, ideally logged and hash-recorded. This is exactly the line Nix draws with pure evaluation + sandboxed derivations, achievable in spirit with Lua discipline.

Also relevant from XMake: integrity is enforced at the *source* level (sha256 per version, `{verify = false}` opt-out labeled a risk [3]) — a pattern a snap packager should copy since snap store review won't save you from a tampered tarball.

## 4. Verdict material — where's the line?

- **Premake's position**: scope = project description + generate; deliberately never builds. Proof that a thin Lua frontend is a coherent scope — but shuttle must build (packing requires running builds), so this is a counter-model, not a template.
- **XMake's position**: it *is* everything — build + generator + package manager + distributed build + cache [1]. That scope is achievable but note the cost: XMake is a large, years-old C+Lua codebase. For shuttle, XMake is a *feature map*, not a codebase to mirror.
- **Craft-parts' position**: it exists as a *library* extracted from snapcraft (LifecycleManager takes parts dicts [8]) — Canonical's own answer to "the packager is a build orchestrator" is to isolate that orchestrator behind an API. Shuttle's equivalent would be: the Lua layer produces a parts plan; a small DAG executor + cache layer consumes it. That keeps shuttle a packager that *packs well* without becoming a build system.
- **The line**: borrow **scheduling** (topological DAG with per-part parallelism), **invalidation** (content/property hashing → skip unchanged parts, like craft-parts' cache-version [10]), and **integrity** (source hashes + lockfile [3]). Do *not* borrow: language-level hermeticity ambitions, remote compilation caches, toolchain management — those are build-system problems that the base snap + declared plugins already mostly solve, and owning them is the "become XMake" trap.

## Sources

[1] docs.xmake.io index — "Xmake = Build backend + Project Generator + Package Manager + [Remote|Distributed] Build + Cache" (via search snippet)
[2] https://github.com/xmake-io/xmake — cross-platform build utility based on Lua
[3] https://xmake.io/guide/package-management/using-official-packages.html — add_requires/add_packages, sha256 per version, verify=false risk, lockfile `package.requires_lock`, `on_install` recipes with `os.vrun`
[4] https://xmake.io/guide/extras/build-cache.html — built-in local cache; remote cache "similar to Mozilla's sccache" (via search snippet)
[5] https://xmake.io/ — "built-in caching, parallel compilation, optimized dependency analysis"
[6] https://xmake.io/guide/quick-start.html — "not recommended for root installation, because this is very insecure"
[7] https://premake.github.io/docs/What-Is-Premake — generation model, toolset-neutrality rationale, "complete Lua scripting environment"
[8] https://documentation.ubuntu.com/craft-parts/latest/reference/parts_steps/ — PULL/OVERLAY/BUILD/STAGE/PRIME, CRAFT_PARALLEL_BUILD_COUNT, injected PATH/flags, LifecycleManager
[9] https://github.com/canonical/craft-application/issues/180 — parallel build count is per-build jobs, craft-parts default 1 (via search snippet)
[10] https://craft-parts.readthedocs.io/en/latest/explanation/parts.html — pull step package cache, step lifecycle (via search snippet; page moved to documentation.ubuntu.com)
[11] https://mesonbuild.com/Contributing.html — "the definition language is not Turing complete. Any change that would make Meson Turing complete is automatically rejected" (via search snippet)
[12] https://mesonbuild.com/Syntax.html — no user-defined functions; rationale: reasoning + IDE integration (via search snippet)

---

## Feeds the grilling

1. Shuttle's Lua manifest will be executable code. Which evaluation model — full Lua (XMake/Premake trusted-user), restricted sandboxed Lua (patched stdlib, pure-eval-plan + explicit hooks), or a Meson-style non-Turing-complete subset? Pick one and defend it against "a snap manifest is fetched from the internet and run as root-adjacent code."
2. Craft-parts already has part-property hashing + cache-versioning but builds parts sequentially. Does shuttle commit to inter-part parallel builds on day one, or is that scope creep for v1?
3. If manifests can compute (loops, functions), what exactly does a shuttle lockfile pin — resolved values only, or evaluation output hashes — and is a Lua manifest even reproducible enough to lock?
4. Content-hash invalidation needs a definition of "inputs": manifest text + scriptlets + source hash — is that enough, or do injected env (like craft-parts' PATH/CFLAGS conventions) count?
5. XMake needed a lockfile, per-version sha256, and still ships `{verify = false}`. What is shuttle's integrity floor — is unsigned-source building allowed at all?
6. Where's shuttle's Premake-line? Is there anything shuttle deliberately refuses to do that Premake refuses (i.e., no toolchain/cache ownership), and is that written down as a non-goal?
7. Should shuttle's Lua layer produce a *plan* (data) that a separate executor consumes — the craft-parts LifecycleManager split — so the packager never becomes the build system by accident?
8. Base snaps already pin the toolchain; does shuttle need toolchain detection at all, and what breaks (e.g., cross-compiling to Ubuntu Core images) if it relies purely on bases?
