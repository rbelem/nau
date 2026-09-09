# Survey: Build-time vs Runtime Dependency Separation in Established Package Managers

Research brief for shuttle's `build_deps` design. (Regenerated 2026-09-08 — original session brief was lost with a tmp reclaim.)

---

## 1. Debian: Build-Depends vs Depends

**(a) Declaration.** Debian splits dependencies by *metadata level*, not content: source packages (debian/control) carry `Build-Depends`, `Build-Depends-Indep` (arch:all-only, e.g. docs tooling), and `Build-Depends-Arch`; binary packages carry `Depends`, `Recommends`, etc. (Debian Policy ch. 7). Build profiles (`<pkg profile:nobuild>`) further scope builds.

**(b) Enforcement.** The policy text is declarative, but enforcement is structural: **buildds (autobuilders) install only Build-Depends before running debian/rules** — so a `Depends` that's actually needed at compile time simply breaks the build on the clean autobuilder. `dpkg-depcheck`/`apt-get build-dep` and lintian (e.g. checks for missing build deps on shared library builds) help lint this. CI (ci.debian.net / Salsa pipelines) builds in minimal schroots.

**(c) Leak prevention.** The key trick is the **-dev package split**: every shared library ships two binary packages — `libfoo1` (runtime: the .so.N and nothing else) and `libfoo-dev` (headers, unversioned `.so` symlink, `.a`, pkg-config files, static libs). Because a compiled binary's `Depends` are auto-generated via shlibs machinery (`dpkg-shlibdeps` → `${shlibs:Depends}`) from the ELF `DT_NEEDED` entries against **versioned sonames**, the -dev package only enters build-time. Since the -dev package is never installed on end-user systems, leak is prevented socially/architecturally: `Depends: libfoo-dev` is a lintian-classed packaging bug, not a hard error.

**Multiarch:** `libfoo-dev` is `Multi-Arch: same` on its build arch while `libfoo1` may be installed for foreign arches; headers live in `/usr/include/<triplet>/` (e.g. `/usr/include/x86_64-linux-gnu/`) so cross builds coexist (Debian Policy 11.1, Ubuntu multiarch spec).

**(d) Build tools.** Compilers come via `build-essential` (implicit, not declared); `pkg-config` and codegen tools are explicitly `Build-Depends`. Notably policy requires them for the `clean` target too — even cleaning needs declared build tools.

## 2. RPM/Fedora: BuildRequires vs Requires

**(a) Declaration.** Spec files: `BuildRequires: ncurses-devel` in the header block; `Requires:` (or `Requires(hint):`) on the binary subpackages. Weak deps (`Suggests`, `Recommends`) exist but are orthogonal.

**(b) Enforcement.** Fedora builds happen in **Koji/Mock with an empty buildroot**: mock installs *only* the declared BuildRequires plus `@buildsys-build` into a chroot. Any undeclared-but-needed file → build failure ("file not found", "pkg-config not found"). So the split is enforced by **environment minimality**, not linting. `rpmlint` additionally flags wrong-dependency patterns (e.g., `devel-dependency` — a non-devel package requiring a -devel package is an rpmlint error).

**(c) Leak prevention.** Same -devel split as Debian: `ncurses-libs` vs `ncurses-devel`. Two extra RPM-specific mechanisms:
- **`%files` segmentation** — each subpackage lists exactly the files it owns; a header landing in `%files -n libfoo-libs` is caught by "file listed twice" or unpackaged-files build errors. Build artifacts physically staged into `%{buildroot}`; the packaging step *selects* files into subpackages.
- **Automatic dependency generation**: `find-requires`/`auto-provides` scripts (rpm 4.15+: `Dependency generators`) scan produced ELFs for `DT_NEEDED` and rewrite them into soname `Requires: libncurses.so.6`. So runtime deps are *derived from produced ELF content*, not hand-declared — exactly the ldd-walk model under consideration for shuttle. Builds fail on `unresolved` auto-requires by default (mock policy).

**(d)** No static `%_host` build-tool concept; compilers are ordinary `BuildRequires: gcc`. Note `%buildroot` isolation: builds see an *empty* staged root, so "what the build sees" and "what the package ships" are forcibly separate.

## 3. Arch: depends / makedepends / checkdepends / optdepends

**(a) Declaration.** PKGBUILD arrays:
```sh
depends=('glibc')          # runtime
makedepends=('cmake')      # build-time, build host
checkdepends=('python-pytest')  # only for check()
optdepends=('foo: bar')    # optional runtime
```
Officially documented in `PKGBUILD(5)` / Arch wiki PKGBUILD page.

**(b) Enforcement.** `makechrootpkg` (from devtools) builds in a clean chroot containing `base-devel` + depends + makedepends + checkdepends (with `namcap`, a lint tool, flagging suspicious dependency classification — e.g., namcap warns when a package linked against a library doesn't depend on it). Arch's **official repos build in clean chroots** (though the split is only as strict as the maintainer's declaration; base-devel presence masks some tool deps — an intentional pragmatic choice).

**(c) Leak prevention.** Arch is the weakest of the set: there's no per-file ownership *split* within one package — `pacman` tracks the file list, and a header accidentally in `package()` output just ships. Enforcement is namcap lint + the -split convention (`foo` and `foo-dev`-equivalent: Arch ships headers *inside* the main package for most libs, only splitting where size demands, e.g. `linux-api-headers`). No closure computation — pacman just records `depends`.

**(d)** Notable: `checkdepends` is a third axis — deps needed only for the test phase. Relevant to shuttle if a test phase is ever added: tests are build-host-only.

## 4. Alpine: APKBUILD makedepends + -dev subpackages

**(a) Declaration.** APKBUILD: `depends=`, `makedepends=`, `checkdepends=` (same triad as Arch, syntax shell arrays, per `APKBUILD Reference` wiki page). Subpackage splits declared via `subpackages="htop-dev htop-doc"` and per-subpackage control functions / `default_dev`.

**(b) Enforcement.** `abuild` builds in a **bubblewrap/mkinitfs-based sandboxed chroot** (`abuild -r` with `USE_CCACHE`, controlled by `/etc/abuild.conf`) containing only base + makedepends/checkdepends/depends. Notable: **Alpine's build isolation is also bubblewrap**, the same tool as shuttle's.

**(c) Leak prevention.** Alpine's `-dev` split is the most aggressive in any distro: `abuild`'s `default_dev` *automatically* extracts headers, `.so` symlinks, `.pc`, and static libs into `foo-dev`, and `default_dbg` into `-dbg`. Crucially, abuild has a **verification pass**: after packaging it checks every produced file is owned by exactly one subpackage and errors on untracked files ("could not find required file" / unversioned-so errors). Runtime `depends` are auto-computed from `DT_NEEDED` scanning (so:soname → owning package lookup against the APK index, "so:*" virtual providers) — same derive-from-ELF model as RPM. `apk` resolves these strictly; a header-only dep cannot enter the runtime graph because it never ships in the runtime subpackage.

**(d)** `-dev` packages *do* get built and published, so the split is "separate artifact" not "ephemeral". `depends_dev` handles the rare case where another package's build needs libfoo headers+libs transitively (`makedepends="libfoo-dev"` pulls its `depends_dev`).

## 5. Void: xbps-src

**(a) Declaration.** In `srcpkgs/<pkg>/template` (shell): `hostmakedepends=` (tools that run on the **build host**, i.e. native), `makedepends=` (libraries for the **target** platform), `checkdepends=`, `depends=` (runtime). (Void Handbook, "Packaging" chapter.) For native builds hostmakedepends and makedepends both install into the masterdir; for cross builds hostmakedepends install natively while makedepends go into the target `destdir` sysroot.

**(b) Enforcement.** `xbps-src` builds in a chroot masterdir (controlled, with mount points to host caches) — environment-minimality enforcement like Arch/Alpine.

**(c) Leak prevention.** Like Arch: xbps files list + `xbps-query --repository ... -f`; there's a `pkg-config`/shlib detection hook (`void-packages/common/environment/setup/shlib_provides.sh`) that scans produced ELFs to compute **shlib-requires/shlib-provides**, and xbps can resolve `soname` dependencies at install time. `-devel` subpackages (`subpackages="foo-devel"`) split headers manually via per-subpackage `foo-devel_package()` functions; wrong placement is caught by linting (`xbps-lint` / the common scripts) but the regime is linter-not-error mostly.

**(d)** Void's **host vs target build-dependency split** is the cleanest non-Nix articulation of the concept Gentoo calls BDEPEND — see §7 for why this maps well onto shuttle.

## 6. Gentoo: DEPEND / RDEPEND / BDEPEND

**(a) Declaration.** Ebuilds (Gentoo Development Guide, "Dependencies"):
```bash
DEPEND=">=sys-libs/ncurses-6:0="   # compiled against, build time
RDEPEND=">=sys-libs/ncurses-6:0="  # runtime
BDEPEND="virtual/pkgconfig"        # build-time tool running on the *build host*
PDEPEND="..."                      # post-install (cycle-breaker)
IDEPEND="..."                      # needed at install time of the binary pkg
```
`BDEPEND` (EAPI 7) exists precisely because DEPEND is "needed to build **for** the target" while BDEPEND is "needed to run **on** the build machine" — under native builds they collapse; under cross-compilation (and Portage's "binary host" mode) they diverge. Gentoo's migration from crossdev-style hackery to BDEPEND is documented in the EAPI-7 spec and devmanual.

**(b) Enforcement.** Ebuild metadata (`metadata.xml`-adjacent dependency cache) is computed at ebuild commit time by repoman/pkgdev/pkgcheck linting; the dep graph is resolved by Portage before the build starts, inside its sandbox (Portage's `sandbox` LD_PRELOAD + `FEATURES=userfetch/usersandbox` — again a filesystem-view isolation). pkgcheck (modern linter) flags unsorted deps, missing slot ops, and DEPEND/RDEPEND mismatches.

**(c) Leak prevention.** Two-phase install: build into `${D}` (image dir), then `merge` only copies files from `${D}`. Since DEPEND packages aren't recorded in the binary package's runtime deps (`xpak` metadata carries only RDEPEND), leak is prevented by **what's recorded in the produced artifact's metadata** — exactly shuttle's model with a manifest. A build tool installed for DEPEND never appears in RDEPEND unless the ebuild author copies it, and pkgcheck/repcicd lint the diff. Slot/subslot operators (`>=foo-1:2=`) tie rebuilds to ABI, functionally the soname equivalent.

**(d)** `virtual/pkgconfig` idiom: build tools are their own package atoms with explicit classification; `DEPEND="${RDEPEND}"` idiom shows DEPEND ⊇ RDEPEND is the common case (shuttle: current world).

## 7. Nix: nativeBuildInputs / buildInputs / strictDeps

**(a) Declaration.** nixpkgs cross-compilation manual (chap. "Platform parameters"): every build has three platforms — **build** (where the build runs), **host** (where it will run), **target** (what it builds code for, rarely used). Then:
```nix
nativeBuildInputs = [ pkg-config meson ];  # deps for the BUILD platform (run there)
buildInputs          = [ zlib ];           # deps for the HOST platform (linked against)
checkInputs / disallowedReferences …
strictDeps = true;
```
`strictDeps = true` makes the split enforced: nativeBuildInputs go only into native build environment, buildInputs only into the host-side env, so a native tool accidentally in buildInputs *fails or is absent* rather than silently working.

**(b) Enforcement.** Three layers:
1. **Sandbox**: the Nix build daemon runs derivations in a bubblewrap-like isolated namespace; only the *input closure paths* of the derivation are visible (bind-mounted read-only), plus `$NIX_BUILD_TOP`. **The host system is invisible** — implicit system deps are impossible by construction. This is the strongest possible enforcement and the one shuttle's bwrap sandbox already gestures toward.
2. **Closure computation**: a derivation's outPath hash is a function of its explicit input closure. Runtime closure is then computed *downward*: `nix-store -q --references <output>` scans the actual output store paths for embedded store-path references (Nix rewrites the `/nix/store/hash-name` strings inside binaries — the "shredding/grafting" of store paths, plus runtime deps found by scanning binary contents for store path strings).
3. **Strictness flags**: `strictDeps`, `disallowedReferences`/`disallowedRequisites` (fails the build if output references a disallowed store path — e.g., you can declare `disallowedReferences = [ gcc ]`), and `allowedReferences` for whitelist mode.

**(c) Leak prevention.** Fundamentally: the runtime closure is *derived by scanning the produced output* for references to input store paths. A build-only input either (i) never gets its store path string into the output bytes (typical for compilers) or (ii) does — and then the leak is detectable and blockable by `disallowedReferences`. There's no -dev split at all; the *whole* of zlib exists as one store path and being in buildInputs vs runtime closure is determined by content, not declaration.

**(d)** Build-tool ecosystem: `nativeBuildInputs` carries compilers, pkg-config, codegen tools; `pkg-config` is wrapped (`PKG_CONFIG_HOOKS`) so it only searches `buildInputs` of the current derivation — preventing cross leakage of .pc files. `checkInputs` is the Arch/Gentoo-style third axis (test-time only).

## 8. Conda: build / host / run

**(a) Declaration.** `meta.yaml`:
```yaml
requirements:
  build: [cmake, pkg-config]   # runs on the BUILD machine
  host: [zlib, ncurses]        # the build TARGET environment (linking, headers)
  run: [zlib >=1.2]            # runtime
```
(conda-build docs, "Defining metadata — Requirements section".) The build/host/run split mirrors Nix's three-platform model exactly — conda adopted it for cross-compilation support.

**(b) Enforcement.** Each phase runs with **only its declared prefix on the environment path**: build phase sees `$BUILD_PREFIX` (build tools), host phase sees `$HOST_PREFIX` (libraries+headers being linked against), and a done output cannot depend on anything not in build/host/run. Conda-build's sanity checks verify: no requirement missing from the final output's dependency listing, no non-run requirement leaking into the package's bin/lib. Linters: `conda-build` itself errors on e.g. "run requirements not satisfied at runtime" heuristics and on pinning violations.

**(c) Leak prevention.** The **host/build prefix separation is physical**: libraries installed to `$PREFIX` (host) vs tools in `$BUILD_PREFIX`; a build-time tool whose binaries get accidentally copied into `$PREFIX/bin` **does** ship — conda-build's `binaries_have_prefix` / overlinking checks catch this. Conda-build 3 added **overlinking/overdepending detection**: it ldds every produced ELF, resolves each `DT_NEEDED` against host-prefix libraries, and errors on linking against libraries not declared in host/run (overlinking) or on run-deps that nothing links against (overdepending). This is precisely the "post-build leak scan" model — implemented as a **build-time error**, not CI-only.

**(d)** `pkg-config` is installed into build prefix with a wrapper that filters `.pc` search to host prefix (again the wrapped-pkg-config pattern).

---

## Synthesis: design guidance for shuttle `build_deps`

### The pattern space (what everyone converges on)

Every mature system expresses the same three-way distinction, with different vocabulary:

| Axis | shuttle-relevant question | Examples |
|---|---|---|
| **build-host tools** | things that must *run* inside the sandbox to produce output | Nix `nativeBuildInputs`, Gentoo `BDEPEND`, conda `build`, Void `hostmakedepends` |
| **build-target libs** | things linked against / headers consumed | Nix `buildInputs`, Gentoo `DEPEND`, Debian `-dev`, conda `host` |
| **runtime** | things the produced files actually load at run time | everything's `depends`/`RDEPEND`/`run` |

For shuttle today (native-only builds, no cross-compilation), build-host tools and build-target libs collapse — so **one new field, `build_deps`, is the right granularity now**. Design the *metadata* with an eye to a later `host_deps` split (Gentoo/Nix/conda all had to retrofit it; the field name `build_deps` matches "runs during build" semantics and stays correct if cross comes later).

### Where the split is enforced, ranked by strength

1. **Sandbox invisibility (Nix, Debian buildds, Fedora mock, Alpine abuild):** the build environment contains only what's declared. Undeclared build deps break the build. This is the only enforcement that never rots. **Shuttle's bwrap sandbox already gives this** — build deps are extra bind-mounts/overlay entries into the sandbox; runtime deps are absent from the sandbox unless declared. Use it.
2. **Derived-from-output dependencies (RPM auto-requires, Alpine so:* scanning, conda overlinking check, Nix reference scanning):** runtime deps are computed by scanning the produced files, not trusted from the manifest. This is the correct default for shuttle: the manifest's `deps` field should be a *floor*, and the ELF walk the *truth*.
3. **Linters (namcap, rpmlint, pkgcheck, xbps-lint):** catch author mistakes but tolerate drift. Use as warnings only.
4. **Manual -dev splits:** not applicable — shuttle's file-level CA store doesn't publish distro-style -dev subpackages; unnecessary, because sandbox + output-scan replaces their function.

### Recommended architecture

**Declaration** (Lua pkgs/ file):
```lua
build_deps = { "pkgconf", "ncurses" },   -- present only inside the build sandbox
deps = { "musl" },                        -- runtime manifest, closure inputs
```
Semantics: `build_deps` entries are fetched into the store as usual, mounted into the bwrap overlay (read-only) at build time, and **recorded in the build recipe's hash** (so a change in build deps changes the output hash — reproducibility requires this, matching Nix derivation inputs) but **never appear in the package manifest's runtime `deps`**.

**Leak scan — yes, but make it the primary, not a backstop.** The proposed post-build walk is validated by industry precedent: it is essentially RPM's `find-requires` + conda-build's overlinking check + Nix reference scanning combined. Recommended shape:
- For each produced ELF (walk output tree, `ELF magic` + `readelf -d`-equivalent `DT_NEEDED` / `DT_RPATH` / interpreter), resolve each needed soname and each `RPATH`/`RUNPATH` entry against the store entries that were mounted as build-only.
- Also scan plain-text/script outputs for build-only store paths (cheap string scan — Nix's trick; catches `#!/store/...-gcc` shebangs and embedded paths).
- **Resolution rule matters:** resolve sonames via each store entry's *provided* sonames (RPM/Alpine "provides" model), so the check is "does any produced file depend on something that only exists in a build-only entry," not on host paths. Check `DT_RUNPATH`/`DT_RPATH` pointing at build-only mounts too — headers don't show up in ldd but a stale `-L/store/...-ncurses` baked into the runpath does.

**Failure policy — hard error, with an escape hatch:**
- Default: **hard error** (conda-build's overlinking model). Rationale: silent leakage is precisely the bug class this feature exists to kill, and a warning that ships in a release becomes a permanent compatibility constraint. Every system that made this a lint (Arch) ended up with leakage; every system that made it a build error (Fedora mock unresolved requires, conda overlinking, Nix `disallowedReferences`) has a clean property.
- Provide `leaks_ok = { "..." }` (or `build_deps_no_leak_check = ["ncurses"]`) as a per-package, **linting-visible** escape hatch — matching Nix `disallowedReferences` inverted, and making the exceptions greppable/auditable.
- Emit the scan results into the build log on success too (one line: "leak scan: 14 ELFs, 0 build-only refs"), so the check is visible and debuggable when it *does* fail.

**Build-time-only tools:** treat compilers/pkgconf/codegen as ordinary store entries in `build_deps` — no special casing (Debian's implicit `build-essential` is a known wart; explicit beats implicit for reproducibility). Consider eventually a `check_deps` (Arch/Gentoo/Nix `checkInputs` precedent) if shuttle adds a test phase — same sandbox scoping, discarded with build deps.

**One caution:** the leak scan as sole enforcement has a blind spot shared with conda's — **runtime-optional and dlopened plugins** (Nix's `dlopen` deps problem) and pure-data consumption of build-time files (e.g., generated tables copied into output). Don't try to solve these statically; the escape hatch + string scan covers the practical cases.

### Sources

- Debian Policy Manual, ch. 7 (Relationships between packages) & ch. 5 — https://www.debian.org/doc/debian-policy/ch-relationships.html
- Debian New Maintainers' Guide, ch. 4 — https://www.debian.org/doc/manuals/maint-guide/dreq.en.html
- Debian Wiki, BuildProfileSpec — https://wiki.debian.org/BuildProfileSpec
- RPM upstream docs, dependencies & dependency generators — https://rpm-software-management.github.io/rpm/manual/dependencies.html
- Fedora Packaging Guidelines — https://docs.fedoraproject.org/en-US/packaging-guidelines/
- Arch PKGBUILD(5) — https://man.archlinux.org/man/PKGBUILD.5
- Alpine APKBUILD Reference — https://wiki.alpinelinux.org/wiki/APKBUILD_Reference
- Void Handbook, Packaging (templates, hostmakedepends) — https://docs.voidlinux.org/xbps/repositories/manual.html
- Gentoo Development Guide, Dependencies — https://devmanual.gentoo.org/general-concepts/dependencies/
- Gentoo EAPI-7 spec (BDEPEND) — https://projects.gentoo.org/pms/7/pms.html
- Nixpkgs manual, Cross-compilation & platform parameters — https://nixos.org/manual/nixpkgs/stable/#chap-cross-compilation ; nix.dev cross-compilation tutorial — https://nix.dev/tutorials/cross-compilation.html
- Nix manual, reference scanning / disallowedReferences — https://nixos.org/manual/nix/stable/language/derivations
- conda-build docs, Defining metadata (build/host/run) — https://docs.conda.io/projects/conda-build/en/latest/resources/define-metadata.html
