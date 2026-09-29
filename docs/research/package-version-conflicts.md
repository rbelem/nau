# Same package, different versions: coexistence strategies across packaging systems

Research pass (2026-09-27) feeding the version-conflict design work (ADR-0043
direction). Question: how do existing systems let the same package coexist at
different versions on one system — at build time (shared/merged prefix) and at
runtime (user profile / environment)? Official docs preferred as sources.

## 1. Nix / Nixpkgs

- **Mechanism**: content-addressed store paths (`/nix/store/<hash>-name-version`),
  immutable. Two versions are two different store paths; no shared prefix exists
  at store level.
- **Build time**: `stdenv` merges `buildInputs`/`nativeBuildInputs` into one
  prefix (buildEnv-style symlink forest). Identical paths across inputs collide
  and abort the build unless `meta.priority` disambiguates. Propagation is
  explicit (`propagatedBuildInputs`); per-input compiler wrappers
  (`NIX_CFLAGS_COMPILE`) supplement the merged tree.
- **Runtime**: profiles = generation symlink farms (`~/.nix-profile`). Two
  versions of one package install fine (distinct derivations); `bin/` name
  collisions fail unless `meta.priority` is set (`nix-env --set-flag priority`).
- **Multiple outputs** (`out`, `dev`, `lib`, `bin`, …) move headers out of
  runtime closures and reduce `include/` collisions between build inputs.
- Sources: <https://nix.dev/manual/nix/stable/command-ref/nix-env/set-flag.html>,
  <https://nixos.org/manual/nixpkgs/stable/#multiple-output>

## 2. Guix

- Same store + profile/generation model as Nix (`/gnu/store`,
  `~/.guix-profile`). Two versions coexist by referring to versioned package
  variables in a manifest (`python-3.10`, `python-3.11`).
- **Search paths** are declared per package; `guix package --search-paths`
  emits only the exports the current profile needs.
- **Grafts**: security fixes applied by rewriting references inside
  already-built dependents (store-path substitution), so a fixed lib coexists
  with the unfixed one without rebuilding the world.
- Sources: <https://guix.gnu.org/manual/en/html_node/Invoking-guix-package.html>,
  <https://guix.gnu.org/manual/en/html_node/Grafts.html>,
  <https://guix.gnu.org/manual/en/html_node/Search-Paths.html>

## 3. Snap / snapd

- **Parallel installs with instance keys** (snapd ≥ 2.38, still documented as
  experimental): `snap install foo_bar` — instance name `<snap-name>_<key>`;
  the key must be lowercase, must not start with a digit. Each instance is
  fully isolated: own services, config, data dirs, interface connections.
- **Within one snap**: app names are the exposed command names; two apps
  cannot share one name inside a single snap.
- Docs label parallel installs experimental while production use is common
  (e.g. `chromium_x`) — docs-vs-practice divergence.
- Sources: <https://snapcraft.io/docs/explanation/how-snaps-work/parallel-installs/>,
  <https://forum.snapcraft.io/t/parallel-snap-installs/5763>

## 4. Flatpak

- **Runtimes + branches**: the version dimension is the branch
  (`org.freedesktop.Platform//24.08`); branches coexist as separate OSTree
  refs over a content-addressed object store.
- **Extensions** mount at per-branch paths (`/usr/lib/extensions/...`), so
  inter-branch collision cannot happen.
- **Exported commands** are the reverse-DNS app ID
  (`/var/lib/flatpak/exports/bin/<app-id>`), never a bare `foo` — collision
  is designed out by namespace, and isolation replaces merging per sandbox.
- Sources: <https://docs.flatpak.org/en/latest/conventions.html>,
  <https://docs.flatpak.org/en/latest/flatpak-command-reference.html>

## 5. Conda / mamba

- **Environments are prefixes**; packages hardlink/copy from a central cache
  keyed by name-version-build string (e.g. `numpy-1.26.4-py312h..._0`). An env
  links exactly one build; the cache holds many.
- **Transactions check file collisions at link time** (two packages providing
  the same file in one env → error), though historical clobbering behavior is
  under-documented relative to how often it bites.
- **conda-build prefix replacement** (consonance/CB3): the build-prefix path
  string is replaced with a placeholder at package time and substituted at
  install time; binaries smaller than the placeholder path break.
- **Pinning** (`run_exports`, `pin_compatible`, env pinning files) constrains
  which versions the solver picks, not how they coexist physically.
- Sources: <https://docs.conda.io/projects/conda/en/latest/user-guide/concepts/environments.html>,
  <https://docs.conda.io/projects/conda-build/en/latest/resources/commands/conda-build.html>,
  <https://mamba.readthedocs.io/>

## 6. Homebrew

- **Keg architecture**: one keg directory per version under `Cellar`; exactly
  one version is linked into the shared prefix via symlinks. `brew link`
  refuses on conflict; `--overwrite` is explicitly user-brokered.
- **Versioned formulae** (`node@22`) are distinct package names; both can be
  linked at once under their own names.
- **keg-only** formulae are never linked; dependents reference them by stable
  `opt` path (`$(brew --prefix openssl@1.1)/lib`) — the answer to soname
  interleaving without a merged prefix.
- Sources: <https://docs.brew.sh/Formula-Cookbook>, <https://docs.brew.sh/FAQ>

## 7. Debian / dpkg / apt / alternatives

- One filesystem namespace, one version per package name: dpkg refuses
  otherwise. Coexistence is achieved by **different package names**
  (`libssl3` vs `libssl1.1`, `gcc-12`/`gcc-13`, the `foo22` convention) plus
  **virtual packages with `Provides:`**, including versioned provides, so a
  renamed package can satisfy a dependency version.
- **Multi-arch** coexistence (`:amd64`/`:i386`) uses multiarch-suffixed
  library paths — the path-namespace trick.
- **Alternatives system** (`update-alternatives`) dispatches genuinely
  interchangeable commands (`java`, `editor`) by priority symlink.
- Sources: <https://www.debian.org/doc/debian-policy/ch-relationships.html>,
  <https://wiki.debian.org/Multiarch/>,
  <https://man7.org/linux/man-pages/man8/update-alternatives.8.html>

## 8. RPM

- **`installonlypkgs`** (kernels, `kernel-modules*`) is the only sanctioned
  same-name multi-version case — a dnf config list with
  `installonly_limit` (default 3), not a general mechanism.
- File conflicts between packages error by default; kernel modules avoid
  collision via per-version paths (`/lib/modules/<kver>/`).
- Sources: <https://dnf.readthedocs.io/en/latest/conf_ref.html#installonlypkgs>,
  <https://rpm-software-management.github.io/>

## 9. Gentoo SLOT — the canonical slots design

- Each ebuild declares `SLOT`; the same package with different SLOTs installs
  in parallel into distinct sub-paths. One SLOT is "active" for revdep
  rebuilds; several are installable.
- **Sub-slots** (`1/abc`) track ABI: a soname bump bumps the sub-slot, and
  **slot-operator deps** (`dev-lang/python:3.11=`) trigger dependent rebuilds
  keyed on slot identity.
- Tradeoff: slots are manually authored per package — powerful, but the
  metadata burden lands on maintainers.
- Sources: <https://devmanual.gentoo.org/general-concepts/slots/index.html>,
  <https://wiki.gentoo.org/wiki/Slotting>

## 10. Language ecosystems

- **Cargo**: the resolver allows semver-compatible duplicates
  (`serde 1.0.1` and `1.0.9` in one graph); semver-incompatible versions
  always coexist. Identity is the unit key `(crate, version, source,
  features)`, not a path.
  <https://doc.rust-lang.org/cargo/reference/resolver.html>
- **pnpm**: `node_modules/.pnpm/<name>@<version>/` content store with a
  symlinked top level — structurally the Nix profile pattern.
  <https://pnpm.io/symlinked-node-modules-structure>
- **uv/Poetry**: venv = isolated prefix per project; uv caches wheels
  content-addressed and hardlinks into venvs.
- **asdf/mise**: per-directory version files + shims dispatching per cwd.
  <https://mise.jdx.dev/>, <https://asdf-vm.com/>

## 11. ELF-level reality

- **soname discipline** is the loader's coexistence mechanism:
  `libssl.so.1.1` and `libssl.so.3` are different DSOs and coexist trivially.
  Two libs sharing a soname but differing in ABI is the pathological case.
- **RUNPATH/RPATH + `$ORIGIN`**: binaries resolve libs relative to their own
  directory; DT_RUNPATH is not transitive (RPATH is) — a classic nested-
  wrapper gotcha.
- **Wrapper dispatch**: `bin/foo` is a script exporting
  `LD_LIBRARY_PATH`/module dirs and exec'ing `bin/foo.real`. Ubiquitous;
  costs an exec hop and risks env leakage to children.
- Sources: <https://man7.org/linux/man-pages/man8/ld.so.8.html>,
  <https://man7.org/linux/man-pages/man1/ld.1.html>,
  <https://www.debian.org/doc/debian-policy/ch-sharedlibs.html>

## 12. Nix profile dispatch details

- Profile assembly is a symlink farm with collision detection: two packages
  providing `bin/ld` abort unless `meta.priority` resolves it (lower wins;
  equal priority hard-fails; default 5).
- NixOS resolves wrapper collisions in module space (`hiPrio`/`lowPrio`,
  `withPackages` building one merged interpreter env per expression); two
  such envs coexist as distinct store paths.
- Sources: <https://nixos.org/manual/nixpkgs/stable/#fun-lib-lowPrio>,
  <https://nixos.org/manual/nixos/stable/options>

## Synthesis: the six design primitives

1. **Content-addressed store + profile symlink farm with priority** (Nix,
   Guix, pnpm). Build-time conflict impossible by construction; runtime
   merging is explicit and collision-checked. Cost: relocation everywhere and
   a priority/collision policy at profile assembly.
2. **Name suffixing / slots / versioned names** (Gentoo SLOT, Debian `foo22`,
   Homebrew `node@22`, output splits). Coexistence by distinct identity in
   one namespace. Cost: metadata burden on packagers; a dispatch/default
   layer is still needed.
3. **Soname/ABI discipline** (ELF, Debian policy, Gentoo sub-slots). Runtime
   interleaving is solved when ABI identity is encoded in the filename.
   Only covers ELF DSOs; soname bumps force rebuild bookkeeping.
4. **Instance keys / artifact namespace scoping** (snapd instance keys,
   Flatpak app IDs, image tags). Exported names derive from the keyed
   identity, so dispatch collisions cannot happen. Cost: instances must
   tolerate running alongside themselves (per-instance state/config).
5. **Env-per-selection** (conda envs, venvs, Flatpak sandboxes). Never merge;
   each selection gets a prefix; "the system" is the active env. Cost: disk
   (mitigated by hardlink caches) and switch friction.
6. **Wrapper dispatch / shims** (asdf/mise, ELF wrapper scripts,
   update-alternatives, keg links). One PATH entry, per-invocation
   resolution. Cost: exec hop, env-leak risk, surprising resolution rules.

## Relevance to nau

Nau already has primitive 1's store (content-addressed, per-build). The
hard problems live at two seams: the merged build prefix (where Nix's own
implementation also collides and aborts unless priority disambiguates) and
the flat farm (where ADR-0015 already mandates loud, never-silent collision
handling). For Lua-declared packages, name suffixing (primitive 2) plus
soname discipline (primitive 3) plus the existing build-time wrapper pass
(ADR-0015 D8 / ADR-0034) cover the observed cases without new machinery.
