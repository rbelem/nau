# Build dependencies: sandbox-scoped `build_deps`, merged-prefix visibility, leak scan

## Status

Accepted (2026-09-08). Grounded in a `/grill-with-docs` session and a cross-distro survey
(`.planning/research/native-build-deps-survey.md`: Debian, RPM/Fedora, Arch, Alpine, Void,
Gentoo, Nix, conda — primary sources cited there).

## Context

`requires` conflated two things: what a build links against and what ships in the runtime
closure. Two failures follow. First, the build sandbox (ADR-0004) is hermetic — `env_clear`
plus bubblewrap binds hide the host — and binds only the interpreted-package dependency
closure of ADR-0017 at `/shuttle-deps`; pool `requires` payloads are never visible at build
time, so a source build cannot find headers or link libraries (empirically: `htop` declares
`requires = { "glibc", "ncurses" }` and its `./configure` finds no ncurses). Second, the
plugin mechanism contributes toolchains as `requires` (the cargo plugin pulls the rust
toolchain package), leaking whole toolchains into runtime closures and pods.

## Decision

1. **Split.** `requires` means runtime dependencies (what enters the pod/generation closure).
   A new `build_deps` string array means build-time-only dependencies — mounted into the
   build sandbox for the build, never present in the runtime closure. This mirrors the
   universal distro split (Debian `Build-Depends`/`Depends`, RPM `BuildRequires`/`Requires`,
   Gentoo `DEPEND`/`RDEPEND`, Nix `buildInputs`/runtime closure, conda `build`/`run`).
   A package that links a library at build time lists it in **both** fields — the explicit
   duplication that Gentoo and conda normalize.

2. **Visibility: merged prefix.** Build-time payloads (`build_deps`, plus the build-time view
   of `requires`) materialize into one `/usr`-like tree ro-bound into the sandbox, so
   `./configure`, `pkg-config`, and compilers consume them unmodified. Per-package
   directories with hand-rolled `-I`/`-L` flags are rejected; environment-minimal buildroots
   with a consumable prefix are the norm in every surveyed system (Alpine abuild even uses
   bubblewrap itself).

3. **Enforcement: leak scan, hard error.** After packaging, shuttle scans every produced
   ELF (`DT_NEEDED`, `DT_RUNPATH`/`DT_RPATH`, interpreter) plus scripts/text for references
   that resolve only into build-only store entries, and fails the build on a hit. Policy:
   hard error by default (the conda overlinking / Nix `disallowedReferences` model — every
   surveyed system that made this lint-only, notably Arch, tolerates leakage); per-package
   `leaks_ok` escape hatch keeps exceptions greppable; one success log line
   (`leak scan: N ELFs, 0 build-only refs`) keeps the check visible.

4. **Reproducibility.** `build_deps` participate in the recipe hash (changed build deps force
   a rebuild) and are pinned in `shuttle.lock` — the lockfile IS the pin record (ADR-0017
   Decision 5).

5. **Toolchain migration follows.** Land the mechanism + leak scan first; then migrate
   plugin-provided toolchains (cargo → rust toolchain) from `requires` to `build_deps` as
   the first customer — shrinking runtime closures and pods.

6. **Deferred:** a `check_deps` third axis (Arch `checkdepends`, Gentoo `BDEPEND`, Nix
   `checkInputs`) waits until a test phase exists. A `host_deps` split (Nix three-platform
   model) waits until cross-compilation of packages (beyond the existing `target` sysroot
   mount) is real; the field name is chosen to survive that retrofit.

## Alternatives considered

- **`requires` stays build-visible AND runtime, with `build_only` for tools.** Rejected:
  keeps the conflation that broke builds, and toolchain leak semantics stay ambiguous.
- **Leak scan as warning only.** Rejected: the Arch/namcap model demonstrably leaks; a
  shipped warning becomes a permanent compatibility constraint.
- **Implicit host toolchain (Debian `build-essential` model).** Rejected: explicit beats
  implicit for reproducibility; the survey flags implicitness as Debian's known wart.

## Consequences

**Positive**: source builds can finally consume pool libraries (htop, tig, git-credential-
manager unblock); runtime closures and pods stop carrying toolchains; build environments
are minimal and reproducible; leak detection matches the strictest industry precedent.

**Negative**: two lists per linking package (explicit duplication — the accepted norm);
the leak scan has known blind spots (dlopened plugins, data files consumed at build time)
covered only by the escape hatch; merged-prefix materialization adds build-setup work per
build; a future cross-compilation story will need the `host_deps` retrofit.
