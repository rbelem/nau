# Package Manager Binary Exposure on PATH — Primary-Source Research

> **Purpose**: feed a council review on whether shuttle's pod farm should use SHIMs, direct
> SYMLINKs, or PATH-prefixing — matching how devbox/snap/others actually do it.
> **Date**: 2026-09-05
> **Method**: direct source inspection of jetify-com/devbox (Git, main branch) + established
> documented behavior of nix/guix/snapd/Homebrew/asdf/mise/npm/pipx/cargo/go.

## Big picture: two distinct layers

Most confusion about "shim vs symlink" conflates two layers. Separate them:

- **Layer 1 — package-manager exposure**: how the PM makes a package's `bin/` appear on PATH.
  This is unambiguously *either* (a) a PATH-prefix of a dir of **direct symlinks** into a
  content-addressed store (nix, guix, Homebrew Cellar), *or* (b) a dir of **shim stubs**
  (asdf, mise), *or* (c) a PATH-prefix of the package's **own bin dir** with no link at all
  (npm global via symlinks, cargo/go install copying the binary).
- **Layer 2 — whether the package's own binary is a wrapper script**. Relates to the
  builder, not the PM. Nixpkgs' `makeWrapper`/`wrapProgram` produces wrapper *scripts*
  as the package's `bin/<tool>` in the store (e.g. wrapped `python`, `node`, `${libc}`
  wrappers). These are NOT PM shims — they are the package's own entrypoint.

## Devbox — the user is right to check, but the answer is: NO SHIMS

Source-verified in jetify-com/devbox (main):

- `internal/devbox/global.go` `GlobalDataPath()` → `xdg.DataSubpath("devbox/global/default")`
  = `~/.local/share/devbox/global/default`. A `current` symlink points at it (line 37).
- `internal/devbox/nixprofile.go` `syncNixProfileFromFlake` → diffs `buildInputs` (from
  `nix print-dev-env`) against the nix profile's `manifest.json`, then
  `nix.ProfileInstall`/`nix.ProfileRemove` into the profile dir (lines 64, 69).
- `internal/nix/nix.go` `ProfileBinPath(projectDir)` → `<projectDir>/.devbox/nix/profile/default/bin`
  (line 165). This is a **nix profile** — a directory of **direct symlinks** into `/nix/store`.
- That `bin/` dir is exposed by **prepending it to PATH** via `eval "$(devbox global shellenv)"`.
  No shim stub is ever written by devbox.

**The only place devbox source says "shim"** is `internal/plugin/info.go` `printCreateFiles`
(line 111) — a doc label for *helper files a plugin's `create_files` emits* (env vars, init
hooks), NOT binary stubs. And `internal/nix/shim.go` is a Go compat re-export, unrelated.

> **Conclusion: devbox global uses NO shims.** It is PATH-prefix + nix-profile symlinks into
> the store. The earlier research (devbox-global-internals.md) was correct.

## Snap — neither plain symlink nor a classic shim

- `/snap/bin/<app>` is a **symlink** to `/usr/bin/snap` (the snap launcher binary), placed
  there by `snapd`. `snapd` also honors `snap alias` for alternate names on the same
  mechanism. `/snap/bin` is on PATH via distro setup.
- Running `/snap/bin/<app>` → execs `/usr/bin/snap`, which resolves the name, sets up
  confinement (snap-confine/mount namespace/AppArmor interfaces), and execs the app inside
  its squashfs.
- So: **one symlink + a single shared launcher**. NOT one shim per app, NOT a direct
  symlink to the app binary. It's a "launcher symlink" model.
- The binary you get is **confined** — the launch cost includes confinement setup per
  invocation.

## Guix / Nix (nix3-profile) — direct symlinks, no shims

- `nix profile install` builds a profile dir where `bin/<tool>` is a **direct symlink** into
  `/nix/store/<hash>-<pkg>/bin/<tool>`. Paths are store-path-referenced; generations are
  symlink-swapped. No shim stubs. Confirmed by the nix manual (nix3-profile) and the
  `manifest.json` elements `storePaths` model.
- **Layer-2 nuance**: `buildEnv` and `makeWrapper` can make the *store package's own*
  `bin/<tool>` a wrapper *script* (e.g. wrapped interpreters, `${libc}` wrappers). These are
  builder artifacts, not PM profile shims. At the profile layer exposure is always a
  **symlink**.

## Other package managers

| PM | Layer-1 mechanism | Shim? | Notes (source) |
|----|-------------------|-------|----------------|
| **Homebrew** | PATH-prefix of `bin/` of **symlinks** into Cellar (`brew link`) | No | `opt/<formula>/bin/<tool>` symlinks; no wrapper stubs |
| **asdf** | `~/.asdf/shims/<tool>` — **shim stubs** | **Yes** | Classic shim model; each shim `exec`s the runtime/plugin shim |
| **mise / rtx** | `~/.local/share/mise/shims/<tool>` — shim stubs | **Yes** | Shim execs the mise-resolved version |
| **nix-darwin / nix-env** | profile `bin/` symlinks into store | No | Same as nix3-profile |
| **Flatpak** | `/var/lib/flatpak/exports/bin/<app>` (or `~/.local/share/flatpak/exports/bin`) wrappers that `flatpak run` | Partial | Launcher wrappers, not per-app shims |
| **npm global** | `bin/` **symlinks** into `node_modules/.bin` | No | `npm -g` symlinks package bin into `$(prefix)/bin` |
| **pipx** | per-app venv, `bin/` **symlinks** | No | `~/.local/bin/<app>` → venv bin |
| **cargo install** | **direct binary** copied into `~/.cargo/bin` | No | No link layer at all |
| **go install** | **direct binary** in `GOBIN` | No | No link layer at all |

### Reading the table

- **Shim camp**: asdf, mise (per-version shims for runtime version switching).
- **Symlink camp**: nix, guix, Homebrew, npm, pipx, devbox (via nix profile).
- **Direct-binary camp**: cargo, go.
- **Launcher-symlink camp**: snap (one `/usr/bin/snap` symlink per app + confinement).

## Implications for shuttle pods

The shuttle pod farm currently exposes `current/bin/<tool>` as **direct symlinks** into the
store (like nix/guix/devbox). This matches the devbox/nix model exactly:

- No shim-stub indirection (asdf/mise style) — you'd lose the direct link and pay a
  fork+resolve per invocation; `which <tool>` would lie.
- No launcher-symlink (snap style) — pods are unconfined dev tools, not confined snaps; a
  snap-style runner adds per-invocation confinement cost with no benefit.
- PATH access is a single prepend of the pod farm's `current/bin` (mirroring devbox's
  `shellenv` PATH-prefix), or the user links that dir into `~/.local/bin` once.

**Empirical confirmation** (the decisive case): the devbox global profile's bin dir was
inspected directly — **every** entry is a symlink into `/nix/store`. E.g.:

```
.../profile/default/bin/zg -> /nix/store/ygd0npbnfbbgx3mvp2a3ba27ppr549kv-zg-0.2.1/bin/zg
```

The `zg` binary is a *wrapper script* — but it sits at the **store package layer**
(`buildNpmPackage`/`makeWrapper` artifact), NOT the profile layer. Its body is:

```sh
#! /nix/store/...-bash-5.3p15/bin/bash -e
exec "/nix/store/...-nodejs-22.23.2/bin/node"  /nix/store/...-zg-0.2.1/lib/.../cli/index.js "$@"
```

This is a single `exec` (no lingering fork), present because `zg` is a Node script with no
standalone ELF. Native tools in the same profile (`atuin`, `bun`, `bw`) are direct symlinks
to ELF binaries with no wrapper. So:

- **Farm layer = direct symlinks** (devbox-parity, proven).
- **Store package layer = build-time wrapper allowed** for interpreter-based packages
  (the `makeWrapper` analogy). Shuttle's pod build path should support emitting a
  `$STAGE/bin/<tool>` launcher that `exec`s the interpreter + script path, so the farm
  symlink points at that wrapper.

**Decided**: keep direct symlinks at the farm layer; the pod feature's package-build story
must support build-time wrapper generation for interpreter-based packages (the `zg` case),
so a scripting-language tool in a pod works without changing the farm model.

## Sources

- jetify-com/devbox source (Git, main): `internal/devbox/global.go`,
  `internal/devbox/nixprofile.go`, `internal/nix/nix.go` (`ProfileBinPath`),
  `internal/plugin/info.go`.
- Nix manual — nix3-profile (profile of symlinks, generations, GC roots).
- Guix manual — profiles are symlinks into `/gnu/store`.
- snapd: `/snap/bin/<app> -> /usr/bin/snap`, `snap run`, `snap alias`.
- Homebrew `brew link` / `opt/<formula>/bin` symlinks.
- asdf, mise per-version shims (`~/.asdf/shims`, `~/.local/share/mise/shims`).
- npm global bin symlinks; pipx venv bin symlinks; cargo/go direct binaries.
