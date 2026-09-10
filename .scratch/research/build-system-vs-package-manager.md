# Should shuttle become a general-purpose build system (à la Meson)?

Research brief — Sept 2026. Question: would turning **shuttle** (Rust CLI that builds Snap packages from Lua declarations) into a general-purpose build system like Meson make it *more consistent* and a *stronger package manager*?

**Short answer: No.** The evidence points the other way: build systems and package managers solve different problems, every successful convergence (Nix, Cargo) won by owning the *dependency graph*, not by becoming a general compiler orchestrator. Meson itself explicitly refuses to be a general-purpose language or a packaging tool. Shuttle's value is the layer *above* the build system — exactly where Snapcraft already places it.

---

## 1. Meson's scope: build only, deliberately

- Meson self-describes as "an open source build system meant to be both extremely fast and as user friendly as possible" — nothing about packaging or distribution. Its design goal: "every moment a developer spends writing or debugging build definitions is a second wasted." ([mesonbuild.com](https://mesonbuild.com/))
- Its DSL is **deliberately non-Turing-complete**: "build definitions in a very readable and user friendly non-Turing complete DSL." ([mesonbuild.com](https://mesonbuild.com/)) The FAQ states Meson's "design is focused on solving specific problems rather than providing a general purpose language to write complex code solutions in build files." ([mesonbuild.com/FAQ](https://mesonbuild.com/FAQ.html))
  - This is the exact inverse of shuttle's Lua DSL: Lua *is* Turing-complete. Shuttle's differentiator vs Snapcraft YAML is programmability — which is a packaging-DSL feature, not a build-system feature.
- Meson's core features are compiler orchestration, incremental builds, cross-compilation, and a "dependency provider that works together with distro packages" — i.e., it *consumes* distro package managers rather than replacing them ([mesonbuild.com](https://mesonbuild.com/)).
- Meson enforces declarative discipline (e.g., no wildcard globbing of sources, because "this cannot be made both reliable and fast") ([FAQ](https://mesonbuild.com/FAQ.html)) — a constraint philosophy that only makes sense for source→binary compilation, not for assembling a squashfs package from arbitrary parts.

## 2. Build system ↔ distro packaging: the standard layering

Every major distro treats the build system as a replaceable engine underneath packaging metadata:

- Debian/`debhelper` and RPM specs invoke whatever build system the upstream uses (`%meson_build`, `%meson_install` macros exist in Fedora rpm macros; `dh` sequences call `meson` for meson.build projects).
- **Snapcraft does exactly this**: the `meson` plugin "configures projects using Meson and builds them using Ninja," then installs outputs into `$CRAFT_PART_INSTALL`. Declaring `meson` as a `build-package` is all the integration needed ([docs.snapcraft.io meson plugin](https://docs.snapcraft.io/meson-plugin), [snapcraft.io/docs/meson-plugin](https://snapcraft.io/docs/meson-plugin)). Equivalent plugins exist for cmake, autotools, make, cargo, python, etc.
- The lesson: **the packaging layer stays small and stable precisely because it delegates builds via plugins.** If shuttle became a build system, it would compete with Meson/Ninja/CMake at their strongest game (fast incremental rebuilds, dependency scanning, compiler abstractions) while abandoning the game where it has no incumbent competitor (Lua-declared snaps).

## 3. Precedents of convergence — and why they won

| System | Converged? | Why it worked / what it cost |
|---|---|---|
| **Nix** | build + pkg mgr + language | Wins on reproducibility: "a build process will only find resources that have been declared explicitly as dependencies… If it builds, you will know you've provided a complete declaration" ([nixos.org/guides/how-nix-works](https://nixos.org/guides/how-nix-works)). Cost: a bespoke functional language (Nix expressions) and its own store/isolation model. Even Nix is *not* a build system — Tweag: "Nix in its current form is designed to support the package management use case, not the build system use case" (no incremental rebuilds), which is why people bolt Bazel on ([tweag.io, 2018](https://www.tweag.io/blog/2018-03-15-bazel-nix/)). |
| **Bazel** | build + remote artifact mgmt | Hermeticity at the build layer; deliberately **not** a package manager for distribution. Its reproducibility claims come from sandboxing + declared inputs — a huge infrastructure investment (remote caches, execution). |
| **Cargo** | build + pkg mgr | "Cargo downloads your Rust package's dependencies, compiles your packages, makes distributable packages, and uploads them to crates.io" ([Cargo Book](https://doc.rust-lang.org/cargo/)). But it only works because **one language, one build graph, one registry**. Cargo explicitly does not attempt to be a general C/C++/anything build system. |
| **Conan / vcpkg** | pkg mgr driving builds | They *delegate* builds to CMake/Meson/autotools recipes rather than owning compilation — the same layering as Snapcraft plugins. |

**Pattern:** convergence succeeds when there is a single unified dependency graph to own (one language ecosystem, or a whole-system store). Convergence as "do both jobs with one tool" has no successful precedent; the successful projects each picked which half they were.

## 4. What "consistency" actually means here

- Nix/Bazel-style consistency comes from **hermeticity** (builds see only declared inputs), not from owning a build DSL. Nix gets it via sandboxing and the store; Bazel via action sandboxing ([how-nix-works](https://nixos.org/guides/how-nix-works)).
- Snapcraft-style consistency comes from **isolation at build time** (clean build environments, staged dependencies) while delegating compilation to whatever the part needs.
- Shuttle currently can get the Snapcraft-style consistency for free by delegating to existing build systems inside its Lua parts. Becoming a build system wouldn't add hermeticity unless shuttle also builds sandboxes, input hashing, and a content-addressed store — i.e., re-implementing Nix, a multi-year effort orthogonal to "build Snap packages from Lua."

## 5. Assessment for shuttle

1. **Meson comparison is a category error.** Meson produces *build instructions*; shuttle produces *packages*. Different artifacts, different invariants. Meson explicitly stays non-Turing-complete for reliability; shuttle's Lua DSL is a packaging flexibility play, and that's fine — packaging (unlike incremental compilation) tolerates Turing-complete DSLs because it runs once per build, not per keystroke.
2. **The strong move is the one Snapcraft validates:** pluggable build backends (`plugin: meson`, `plugin: cargo`, …) beneath a stable declarative package layer. Shuttle could offer better ergonomics than YAML *without* owning compilation.
3. **If consistency is the goal, the lever is hermetic input capture, not build ownership** — e.g., declaring build deps in Lua and checking them, rather than a from-scratch build engine.
4. **Scope risk:** a general build system means incremental-build graphs, compiler detection, cross-compilation, IDE integration — the entire reason Meson is ~100k+ lines of Python with a decade of hardening. It would swamp a project whose roadmap goal is Snap packages → Ubuntu Core image assembly.

---

## Feeds the grilling

1. **What does "consistency" concretely mean for shuttle?** Bit-identical `.snap` outputs? Same inputs → same dependency resolution? Which failure does today's design have that a build system would fix — and can you name a real incident?
2. **If hermeticity is the goal, why is owning compilation the lever?** Snap gets reproducibility from clean build environments while delegating to meson/cmake. Why would shuttle doing both layers beat shuttle enforcing the environment layer?
3. **Would shuttle-meson compete on incremental build speed?** Meson's core design point is sub-second no-op builds on 10k-file trees ([FAQ](https://mesonbuild.com/FAQ.html)). Is shuttle prepared to win that engineering race — or will users just run meson directly?
4. **Does a Turing-complete Lua DSL at the build layer break the guarantees you want?** Meson banned a general-purpose language on purpose. If shuttle's build definitions can execute arbitrary Lua, what stops unreproducible builds by construction?
5. **Which precedent does shuttle follow: Cargo (one language, one graph) or Snapcraft (plugins)?** Shuttle has neither a single language graph nor (today) a plugin system. What is the unifying dependency graph that justifies convergence in shuttle's case?
6. **What happens to the Ubuntu Core endgame?** The roadmap's destination is image assembly. Does a build-system pivot serve image assembly at all, or does it defer ShuttleOS by years of build-engine work?
7. **Who is the user of shuttle-as-build-system?** Upstream projects (who already chose meson/cmake) or assemblers (who consume built artifacts)? A tool can't be primary for both.
8. **What is the migration story?** If shuttle keeps Snap output and adds build orchestration, is that actually "becoming Meson" — or just adding a `plugin:` keyword, which costs ~1% of the pivot and captures most of the benefit?
