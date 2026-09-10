# shuttle

A Rust CLI that builds Snap packages from Lua declarations — like Nix for Snapcraft. Formerly named *shoot* (renamed 2026-08, ADR-0013).

## Language

**Snap**: A self-contained Linux application package (`.snap` file) installable by `snapd`.
_Avoid_: AppImage, Flatpak, container image

**shuttle.lua**: The entry-point configuration file. Returns a table of named snap outputs.
_Avoid_: config file, manifest, snapcraft.yaml

**Snap output**: One named snap declaration inside a `shuttle.lua`. Single-snap projects use the `default` key; multi-output projects name them (`server`, `cli`).
_Avoid_: target, artifact, build product

**Package**: A static snap definition — either single-file (`pkgs/<letter>/<name>.lua`) or directory (`pkgs/<letter>/<name>/init.lua`).
_Avoid_: recipe, formula, formula file

**Package type**: `source` (build from upstream tarball), `meta` (dependency group, no build), `store` (pulled from Snap Store, no local source).

**Input**: A package source declaration, inspired by Nix flake inputs. URL schemes: `github:user/repo[/branch]` (shallow-cloned to `~/.cache/shuttle/inputs/`) or `path:/local/dir` (local filesystem). Declared as a Lua global before the return statement in `shuttle.lua`, or per-snap via `inputs` on a `snap()` declaration. If no inputs are declared, a default `github:rbelem/shuttle/main` is used at runtime.
_Avoid_: registry, flake, source declaration

**Toolchain**: A meta-package (`type = "meta"`) that aggregates compiler, linker, and runtime libraries needed to build source packages. Named by GNU triplet: `toolchain-<compiler>-<libc>-<arch>`.

**Stage**: The temporary directory where built binaries are installed during a snap build (`$STAGE` env var). Contents are copied into the snap root before SquashFS packaging.
_Avoid_: destdir, install prefix, output dir

**Build sandbox**: A bubblewrap-isolated environment where source builds execute. Provides read-only system paths, private `/tmp`, and `$STAGE`/`$SRC` env vars.
_Avoid_: container, chroot, jail

**Bootstrap**: The 3-stage process of building a compiler toolchain from a host compiler: stage0 (minimal C-only cross-compiler) → stage1 (full C/C++ cross-compiler) → stage2 (verification rebuild).
_Avoid_: cross-compile setup, toolchain init

**Package index**: The `package-index.json` file mapping snap names to store pins or source definitions. Queried by the `index()` DSL function.
_Avoid_: registry, catalog, database

**Requires**: A package's runtime dependencies, declared as a string array in the `snap()` table. Everything listed enters the runtime closure (pod/generation) transitively; resolved by `shuttle deps` and `shuttle build --all`. A package that links a library at build time lists it here *and* in `build_deps` — the explicit-duplication norm (Gentoo DEPEND/RDEPEND, conda host/run).
_Avoid_: depends, deps, links, build dependencies

**Build dependency**: A package's build-time-only dependencies, declared as `build_deps` in the `snap()` table. Visible inside the build sandbox for the duration of the build; never enters the runtime closure. Compilers, pkg-config, codegen tools, and build-time-only libraries are build dependencies (ADR-0018).
_Avoid_: makedepends, nativeBuildInputs, build requires

**Aliases**: Alternative names a package is known by. Toolchain `toolchain-gcc-gnu-x86_64` has aliases `toolchain-x86_64` and `toolchain`.

**Target**: The cross-compilation GNU triplet (e.g. `x86_64-linux-gnu`, `aarch64-linux-gnu`). When set, the build sandbox exports `CC=<target>-gcc`, `CXX=<target>-g++`, etc.

**Image**: A bootable disk image (`.img`) assembled from multiple snaps — base, kernel, gadget, and application snaps. Declared via the `image()` DSL function.

**ShuttleOS**: The Linux distribution assembled by shuttle — an immutable verity-protected base updated via A/B, plus a content-addressed package store on the state partition (ADR-0011/0012).
_Avoid_: shoot distro, shuttle distro

**Store**: The content-addressed, file-level repository of package content — local build cache (`~/.cache/shuttle/`) and on-device under the state partition. Packages are signed manifests of store file hashes, not monolithic blobs (ADR-0012).
_Avoid_: cache, registry, spool

**Generation**: A pinned selection of base-image version + package set + configuration that boots as one unit. Rollback means booting a previous generation; GC is rooted at generations (ADR-0012).
_Avoid_: profile, snapshot, deployment

**State partition**: The persistent, non-verity partition that survives A/B flips — mounted at `/var/lib`, holding the store, extension links, and device identity. Everything else under `/var` is volatile (tmpfs + tmpfiles). Declared as a partition with `role = "state"` (native) or `"system-data"` (UC). (ADR-0023)
_Avoid_: data partition, writable partition, persistent volume

**Boot assessment**: The try-boot mechanism that marks a booted generation good via `boot-complete.target` and reverts after `TriesLeft` is exhausted. Stock systemd (`systemd-bless-boot`), not shuttle-owned logic. (ADR-0024)
_Avoid_: health check, boot verification, watchdog

**Key ceremony**: Generating, rotating (minting and promoting a new key), and revoking signing keys, plus distributing the trusted key set to devices so revoked keys are refused at install/update time. (ADR-0024)
_Avoid_: key management, PKI

**Image manifest**: The flat, serializable, signed result of evaluating `image()` — partitions, UKI/roothash digests, package lists. The shuttle-side analog of a model assertion (ADR-0011).
_Avoid_: model assertion, lockfile (the lockfile pins *inputs*; the manifest describes the *system*)

**Install**: An on-device operation that adds a package to the store and the current generation without mutating the base (`shuttle install`, ADR-0012).
_Avoid_: snap install, layering

**Pod**: A named user-level package selection owned by one user; the small shuttle served by the system mothership. Each pod has its own packages, overlays, lockfile, and generation chain; rollback switches that pod only.
_Avoid_: global, profile, environment

**Pod generation**: A pinned selection of one pod's packages + overlays + loaded pods at one point in time. Rollback switches that pod's `current` link only; it never reboots or touches system generations.
_Avoid_: system generation, snapshot

**Overlay**: An inline, code-only patch to an existing package declaration inside `pod.lua`, layered over `pkgs/` and loaded pods. Later layers win; upstream files are never modified.
_Avoid_: fork, shadow file, patch file

**Confinement**: The runtime isolation level of an installed package/app. Two levels: `unconfined` (runs directly on the host with the user's privileges — the default for simple CLIs) and `confined` (wrapped in a bubblewrap/AppArmor-seccomp sandbox with declared grants — for GUI apps and services). Distinct from the build-time *build sandbox*.
_Avoid_: strict, classic, full, sandboxed

**Grants**: Declared resource access a `confined` app requests (filesystem paths, network, sockets, devices) — the shared vocabulary any confinement backend honors. A package may add a non-portable `backend_options` sub-table for backend-specific raw flags beyond the shared vocabulary.
_Avoid_: interfaces, permissions, capabilities

## Flagged ambiguities

- **"Build"** can mean: (a) the `shuttle build` CLI command, (b) a source package's compile step (`snap { build = "..." }`), or (c) the build sandbox environment. Use "build command", "build script", and "build sandbox" respectively.
- **"Sandbox"** can mean: (a) the build-time *build sandbox* (bubblewrap, ADR-0004), or (b) runtime *confinement* (level applied to the installed app). They are different axes; use "build sandbox" and "confinement" to disambiguate.
- **"Package"** can refer to a Lua declaration in `pkgs/` or to the Snap Store concept of a snap. Use "package index entry" or "store snap" to disambiguate.

## Example dialogue

**Dev**: I want to add a new source package. Do I just drop a `.lua` file in `pkgs/`?

**Domain expert**: Yes. Drop `pkgs/f/foo.lua` with a `snap()` declaration. Set `type = "source"`, add its upstream tarball URL and build script, and declare its `requires` — at minimum `{ "glibc" }`.

**Dev**: What if foo needs a cross-compiler? Do I need to configure that separately?

**Domain expert**: Add `target = "aarch64-linux-gnu"` to the snap declaration. The build sandbox will set `CC=aarch64-linux-gnu-gcc`, etc. If foo needs the full toolchain, add `"toolchain"` to its requires — it resolves to `toolchain-gcc-gnu-x86_64`.

**Dev**: And if I want to produce two snaps with different configs?

**Domain expert**: Return a table with two keys: `{ server = snap { ... }, foo = snap { ... } }`. Use `merge(require("base"), { name = "foo", ... })` to avoid repeating shared fields.

**Dev**: How do I build an entire system image from these?

**Domain expert**: Write an `image()` declaration with a base snap, kernel, gadget, and any extra snaps. `shuttle image shuttle.lua` resolves everything from the Snap Store, extracts the base as a rootfs, merges kernel modules, and packs the result into a SquashFS `.img`.

**Dev**: The default input fetches from `github:rbelem/shuttle/main`. Can I use a different repo?

**Domain expert**: Set a global `inputs` table at the top of your `shuttle.lua`:
```lua
inputs = {
    mypkgs = { url = "github:myorg/mypackages/main" },
}
```
Packages are resolved from your input's `pkgs/` directory. You can also use a local path:
```lua
inputs = {
    localpkgs = { url = "path:/home/me/custom-pkgs" },
}
```
Per-snap inputs work the same way, declared inside a `snap()` table.

**Dev**: What if I don't have a `shuttle.lua` at all?

**Domain expert**: `shuttle build hello` auto-fetches the default input (`github:rbelem/shuttle/main`) on first run. It's cached in `~/.cache/shuttle/inputs/`. Run `shuttle index update` to refresh.
