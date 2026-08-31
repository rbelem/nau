# shuttle

A Rust CLI that builds Snap packages from Lua declarations — like Nix for Snapcraft. Formerly named *shoot* (renamed 2026-08, ADR-0010).

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

**Requires**: A snap's build dependencies, declared as a string array in the `snap()` table. Resolved transitively by `shuttle deps` and `shuttle build --all`.
_Avoid_: depends, deps, links

**Aliases**: Alternative names a package is known by. Toolchain `toolchain-gcc-gnu-x86_64` has aliases `toolchain-x86_64` and `toolchain`.

**Target**: The cross-compilation GNU triplet (e.g. `x86_64-linux-gnu`, `aarch64-linux-gnu`). When set, the build sandbox exports `CC=<target>-gcc`, `CXX=<target>-g++`, etc.

**Image**: A bootable disk image (`.img`) assembled from multiple snaps — base, kernel, gadget, and application snaps. Declared via the `image()` DSL function.

**ShuttleOS**: The Linux distribution assembled by shuttle — an immutable verity-protected base updated via A/B, plus a content-addressed package store on the state partition (ADR-0011/0012).
_Avoid_: shoot distro, shuttle distro

**Store**: The content-addressed, file-level repository of package content — local build cache (`~/.cache/shuttle/`) and on-device under the state partition. Packages are signed manifests of store file hashes, not monolithic blobs (ADR-0012).
_Avoid_: cache, registry, spool

**Generation**: A pinned selection of base-image version + package set + configuration that boots as one unit. Rollback means booting a previous generation; GC is rooted at generations (ADR-0012).
_Avoid_: profile, snapshot, deployment

**Image manifest**: The flat, serializable, signed result of evaluating `image()` — partitions, UKI/roothash digests, package lists. The shoot-side analog of a model assertion (ADR-0011).
_Avoid_: model assertion, lockfile (the lockfile pins *inputs*; the manifest describes the *system*)

**Install**: An on-device operation that adds a package to the store and the current generation without mutating the base (`shuttle install`, ADR-0012).
_Avoid_: snap install, layering

## Flagged ambiguities

- **"Build"** can mean: (a) the `shuttle build` CLI command, (b) a source package's compile step (`snap { build = "..." }`), or (c) the build sandbox environment. Use "build command", "build script", and "build sandbox" respectively.
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
