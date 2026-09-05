# Devbox Global Internals — Primary Source Research

> **Purpose**: Feed for `/grill-with-docs` session on adding devbox-global-like user package management to shuttle.
> **Date**: 2026-09-04
> **Sources**: jetify-com/devbox source (main branch, Go), Nix 2.x official docs, Jetify docs.

---

## 1. Nix Profiles — the substrate devbox builds on

### 1.1 What a nix profile is

A **profile** is a versioned directory of symlinks into the Nix store (`/nix/store/`). Each installed package contributes its `bin/`, `lib/`, `share/`, etc. as symlinks. The profile directory is the "union" of all installed packages' outputs. [^nix-profile-man]

[^nix-profile-man]: https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-profile — "A Nix profile is a set of packages that can be installed and upgraded independently from each other. Nix profiles are versioned, allowing them to be rolled back easily."

### 1.2 Filesystem layout

```
~/.local/state/nix/profiles/profile              → profile-7-link     (symlink, "current")
~/.local/state/nix/profiles/profile-7-link       → /nix/store/...-profile  (symlink to store path)
~/.local/state/nix/profiles/profile-6-link       → /nix/store/...-profile  (previous generation)
~/.local/state/nix/profiles/profile-5-link       → /nix/store/...-profile  (older generation)
```

Each store path contains:
```
/nix/store/...-profile/
├── bin/
│   ├── rg        → /nix/store/...-ripgrep-14.1.1/bin/rg
│   ├── go        → /nix/store/...-go-1.22.5/bin/go
│   └── ...
├── share/        → (merged share dirs from all packages)
└── manifest.json → (nix profile metadata — see §1.4)
``` [^nix-profile-man]

The default profile path for regular users is `$XDG_STATE_HOME/nix/profiles/profile` (typically `~/.local/state/nix/profiles/profile`). [^nix-profile-man]

When `use-xdg-base-directories` is set, the user-visible link is `~/.nix-profile` → `$XDG_STATE_HOME/nix/profile`. The Nix installer prepends `~/.nix-profile/bin` to `PATH`. [^nix-profile-man]

### 1.3 Generations and rollback

Each `nix profile install` or `nix profile remove` creates a new generation (N suffix in `profile-N-link`). The `profile` symlink atomically switches to the new generation-link. Previous generation-links are GC roots — they prevent the store paths from being garbage-collected until the generation is explicitly removed. [^nix-profile-man]

Key commands:
- `nix profile install --profile <path> <installable>` — adds package, bumps generation
- `nix profile remove --profile <path> <name-or-index>` — removes, bumps generation
- `nix profile rollback --profile <path>` — reverts `profile` symlink to previous generation
- `nix profile list --profile <path>` — lists installed packages (JSON since nix 2.17)
- `nix profile wipe-history --profile <path>` — deletes non-current generation-links (frees GC roots)
- `nix profile history --profile <path>` — shows all generation versions

**Important**: Once `nix profile` is used on a profile, `nix-env` cannot operate on it (one-way migration). [^nix-profile-man]

### 1.4 Profile manifest format

Each generation's store path contains `manifest.json` (used by `nix profile` >= 2.17) or `manifest.nix` (legacy `nix-env`). [^nix-profile-man]

Modern manifest.json (nix >= 2.20):
```json
{
  "elements": {
    "ripgrep": {
      "active": true,
      "attrPath": "legacyPackages.x86_64-linux.ripgrep",
      "originalUrl": "github:NixOS/nixpkgs/...",
      "priority": 5,
      "storePaths": ["/nix/store/...-ripgrep-14.1.1"],
      "url": "github:NixOS/nixpkgs/..."
    }
  },
  "version": 2
}
``` [^devbox-nixprofile]

Legacy manifest.json (nix < 2.20): uses `elements` as an array with numeric indices instead of named keys. [^devbox-nixprofile]

[^devbox-nixprofile]: jetify-com/devbox `internal/nix/nixprofile/profile.go` — ProfileListItems handles both modern (elements as map, nix >= 2.20) and legacy (elements as array, nix < 2.20) JSON formats.

### 1.5 GC roots

Each generation-link is a GC root. The Nix garbage collector (`nix store gc`) will not delete store paths reachable from any live root. Devbox's `wipeProfileHistory()` explicitly removes non-current generation-links to release their GC roots. [^devbox-nixprofile-sync]

[^devbox-nixprofile-sync]: jetify-com/devbox `internal/devbox/nixprofile.go` — `wipeProfileHistory()` removes all entries in the profile directory except "default" and the current generation-link.

---

## 2. Flake Inputs — devbox.json → flake.nix translation

### 2.1 Overview

Devbox translates a `devbox.json` into a Nix flake (`flake.nix`) inside the project's `.devbox/gen/flake/` directory. The flake is the "compilation target" — Nix evaluates it to produce a `devShells.<system>.default` derivation containing all declared packages as `buildInputs`. [^devbox-generate]

[^devbox-generate]: jetify-com/devbox `internal/shellgen/generate.go` — `GenerateForPrintEnv()` creates flake.nix, shell.nix, scripts, and .gitignore inside the project dir.

### 2.2 The flake.nix template

From `internal/shellgen/tmpl/flake.nix.tmpl`:

```nix
{
  description = "A devbox shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/<commit-hash>";  # from lockfile's Stdenv()
    # one input per unique flake source:
    <flakeInputName>.url = "<resolved-url>";
  };
  outputs = { self, nixpkgs, ... }:
    let pkgs = nixpkgs.legacyPackages.<system>; in {
      devShells.<system>.default = pkgs.mkShell {
        buildInputs = [
          # for each package: either fetchClosure (cached) or attr-path reference
          (builtins.trace "downloading <pkg>" (builtins.fetchClosure { ... }))
        ];
      };
    };
}
``` [^devbox-flake-tmpl]

[^devbox-flake-tmpl]: jetify-com/devbox `internal/shellgen/tmpl/flake.nix.tmpl` — the full template with fetchClosure optimization, flake input handling, and symlinkJoin for multi-output flakes.

### 2.3 How devbox.json packages become flake inputs

The `flakeInputs()` function (in `internal/shellgen/flake_plan.go`) groups packages by their flake source (e.g., all packages from the same nixpkgs commit become one input). Each unique flake URL gets a named input in the flake. [^devbox-flake-plan]

[^devbox-flake-plan]: jetify-com/devbox `internal/shellgen/flake_plan.go` — `newFlakePlan()` creates the plan from installable packages, fills NarInfo cache, and calls `flakeInputs()`.

Package resolution chain:
1. `devbox.json` lists `"packages": ["ripgrep@14.1", "go@1.22"]`
2. Devbox queries its search index to map `ripgrep@14.1` → specific nixpkgs commit + attribute path
3. The resolved info goes into `devbox.lock` (see §2.4)
4. The flake template references the locked nixpkgs commit and attribute path

### 2.4 devbox.lock pinning

`devbox.lock` is the lockfile that pins exact versions. Structure:

```json
{
  "lockfile_version": "1",
  "packages": {
    "ripgrep@14.1": {
      "resolved": "github:NixOS/nixpkgs/<commit>#legacyPackages.x86_64-linux.ripgrep",
      "source": "devbox-search",
      "version": "14.1.0",
      "systems": {
        "x86_64-linux": {
          "outputs": [
            { "name": "out", "path": "/nix/store/...-ripgrep-14.1.0", "default": true }
          ]
        }
      }
    }
  }
}
``` [^devbox-lock]

[^devbox-lock]: jetify-com/devbox `internal/lock/package.go` — `Package` struct with `Resolved`, `Source`, `Version`, `Systems` (keyed by system, containing `Outputs` with store paths). Legacy format used `StorePath` instead of `Outputs`.

Key lockfile behaviors:
- **Version**: `"1"` (current)
- **Stdenv pinning**: The nixpkgs flake is itself a locked package in the lockfile (the `Stdenv()` method resolves it). [^devbox-lockfile]
- **Dirty detection**: Compares JSON hash of in-memory vs on-disk lockfile. Saves only when dirty. [^devbox-lockfile]
- **State hash file**: `.devbox/state.json` tracks config_hash, lock_file_hash, nix_profile_manifest_hash, nix_print_dev_env_hash, devbox_version, is_fish. Used to skip re-computation when nothing changed. [^devbox-statehash]

[^devbox-lockfile]: jetify-com/devbox `internal/lock/lockfile.go` — `GetFile()`, `Save()`, `isDirty()`, `IsUpToDateAndInstalled()`, `Tidy()`.

[^devbox-statehash]: jetify-com/devbox `internal/lock/statehash.go` — `stateHashFile` struct, `UpdateAndSaveStateHashFile()`, `isStateUpToDate()`.

### 2.5 Input URL forms

Devbox supports several flake reference forms:

| Form | Example | Source |
|------|---------|--------|
| Versioned devbox package | `ripgrep@14.1` | Devbox search index → nixpkgs commit |
| Unversioned devbox package | `ripgrep` | Devbox search index → latest |
| GitHub flake | `github:owner/repo/rev` | Direct flake reference |
| Path flake | `path:./my-flake#name` | Local filesystem |
| Legacy Nix attr path | `go_1_22` (no @) | Current nixpkgs from Stdenv |

From `devpkg/flake_installable.go` and `devconfig/`:

Flake references go through `FlakeInstallable()` which parses the URL, determines the `Ref` (flake source), `AttrPath` (package attribute), and `Outputs`. [^devbox-config]

[^devbox-config]: jetify-com/devbox `internal/devconfig/` — config file handling, and `internal/devpkg/` for package resolution.

### 2.6 Where devbox global stores its project

```go
// internal/devbox/global.go
func GlobalDataPath() (string, error) {
    path := xdg.DataSubpath(filepath.Join("devbox/global", currentGlobalProfile))
    // currentGlobalProfile = "default"
    // ...
    currentPath := xdg.DataSubpath("devbox/global/current")
    os.Symlink(nixProfilePath, currentPath)
    return path, nil
}
```

With XDG defaults: [^devbox-global]

| Path | Content |
|------|---------|
| `~/.local/share/devbox/global/default/` | The "project directory" — contains devbox.json, devbox.lock, .devbox/ |
| `~/.local/share/devbox/global/current` | Symlink → `default/` (future: switchable profiles) |
| `~/.local/share/devbox/global/default/devbox.json` | Global package declarations |
| `~/.local/share/devbox/global/default/devbox.lock` | Resolved versions |
| `~/.local/share/devbox/global/default/.devbox/` | Generated flake, state.json, nix profile |

[^devbox-global]: jetify-com/devbox `internal/devbox/global.go` — `GlobalDataPath()` uses `xdg.DataSubpath("devbox/global/default")` which resolves to `~/.local/share/devbox/global/default` via `XDG_DATA_HOME` or `~/.local/share`.

The XDG resolution comes from `internal/xdg/xdg.go`: `dataDir()` returns `$XDG_DATA_HOME` or `~/.local/share`. [^devbox-xdg]

[^devbox-xdg]: jetify-com/devbox `internal/xdg/xdg.go` — `DataSubpath()`, `ConfigSubpath()`, `CacheSubpath()`, `StateSubpath()` using env vars with fallback defaults.

---

## 3. PATH Linking — how binaries land on PATH

### 3.1 The nix profile bin directory

The Nix profile at `~/.local/state/nix/profiles/profile` contains a `bin/` directory with symlinks to each installed package's binaries. Nix itself does NOT automatically add this to PATH — the Nix installer's shell init hook does: [^nix-profile-man]

```bash
# Typical addition in ~/.bashrc (added by nix installer):
export PATH="$HOME/.nix-profile/bin:$PATH"
```

### 3.2 Devbox's PATH mechanism — `devbox global shellenv`

Devbox's approach is **not** static symlinks into `~/.local/bin/`. Instead, it uses **environment manipulation via `devbox global shellenv`** which must be eval'd in the user's shell RC file. [^devbox-global-cli]

[^devbox-global-cli]: jetify-com/devbox `internal/boxcli/global.go` — `ensureGlobalEnvEnabled()` warns if the global environment is not activated and instructs users to add `eval "$(devbox global shellenv)"` to their shell rcfile.

The recommended shell integration:

```bash
# ~/.bashrc or ~/.zshrc
eval "$(devbox global shellenv)"

# For nushell: see NUSHELL.md
```

When `devbox global shellenv` runs, it: [^devbox-envexports]

1. Calls `d.ensureStateIsUpToDateAndComputeEnv()` — verifies flake/nix profile are current, computes full environment
2. Returns `export KEY="VALUE";` statements for all environment variables (from plugins, devbox.json env, nix print-dev-env)
3. **Prepends the nix profile's `bin/` directory to `PATH`** — this is the critical step that makes installed binaries available
4. Appends a `devbox refresh` alias (for live-reloading the environment)
5. Optionally sources init hooks

[^devbox-envexports]: jetify-com/devbox `internal/devbox/devbox.go` — `EnvExports()` calls `ensureStateIsUpToDateAndComputeEnv()` then `exportify()` to produce shell-compatible export statements.

### 3.3 PATH stack architecture

Devbox uses a **PATH stack** mechanism (in `internal/devbox/envpath/`) to support nested devbox environments. Each project gets a unique hash (`ProjectDirHash()`). The PATH is constructed as a stack: [^devbox-envvars]

- Global shellenv prepends global profile bin dir
- Project-level `devbox shell` prepends project profile bin dir
- Nested shells stack, so project bins take precedence over global bins

The `IsEnvEnabled()` method checks whether the current shell's PATH stack contains the project's hash — used to differentiate "inside a devbox shell" from "bare shell." [^devbox-envvars]

[^devbox-envvars]: jetify-com/devbox `internal/devbox/envvars.go` — `IsEnvEnabled()` creates a fake env and checks the PATH stack for the project hash. `SkipInitHookEnvName()` uses the hash as a sentinel.

### 3.4 Per-shell integration

Devbox supports:
- **Bash/Zsh**: `eval "$(devbox global shellenv)"` in `~/.bashrc` / `~/.zshrc`
- **Fish**: Uses a different shellrc template (`shellrc_fish.tmpl`)
- **Nushell**: Separate integration via `$env.KEY = "value"` syntax (handled by `exportifyNushell()`) [^devbox-envexports]

### 3.5 No `~/.local/bin` shims

Unlike Homebrew or asdf, devbox does **not** create shim executables in `~/.local/bin/`. All binary access goes through the nix profile's `bin/` directory, which is prepended to PATH by the shellenv hook. This means:

- If shellenv is not evaluated, binaries are not on PATH
- There is no "shim" layer — binaries are direct symlinks to the Nix store
- The profile bin dir takes precedence over system binaries (it's prepended)

---

## 4. Lifecycle Commands — `devbox global` subcommands

### 4.1 Command routing

`devbox global` is implemented in `internal/boxcli/global.go` as a parent command that delegates to existing subcommands (add, remove, list, etc.) with the `--config` flag automatically set to the global data path. [^devbox-global-cli]

```go
func globalCmd() *cobra.Command {
    globalCmd := &cobra.Command{}
    persistentPreRunE := setGlobalConfigForDelegatedCommands(globalCmd)
    *globalCmd = cobra.Command{
        Use:                "global",
        Short:              "Manage global devbox packages",
        PersistentPreRunE:  persistentPreRunE,
        PersistentPostRunE: ensureGlobalEnvEnabled,
    }
    addCommandAndHideConfigFlag(globalCmd, addCmd())
    addCommandAndHideConfigFlag(globalCmd, removeCmd())
    addCommandAndHideConfigFlag(globalCmd, listCmd())
    addCommandAndHideConfigFlag(globalCmd, updateCmd())
    addCommandAndHideConfigFlag(globalCmd, pullCmd())
    addCommandAndHideConfigFlag(globalCmd, pushCmd())
    addCommandAndHideConfigFlag(globalCmd, shellEnvCmd(...))
    // ... run, install, path, services
    return globalCmd
}
```

The key insight: `devbox global add X` is identical to `devbox add X --config ~/.local/share/devbox/global/default/`. The "global" is just a different project directory. [^devbox-global-cli]

### 4.2 `devbox global add <pkg>[@version]`

1. Resolves package name via devbox search index (maps `pkg@version` to nixpkgs commit + attr path)
2. Validates the package exists (falls back to legacy nix attr path if not in search)
3. Adds to `devbox.json` (`cfg.PackageMutator().Add()`)
4. Calls `ensureStateIsUpToDate(ctx, install)` which:
   - Regenerates `flake.nix` in `.devbox/gen/flake/`
   - Runs `nix build` (or `nix print-dev-env`) to build/fetch packages
   - Runs `nix profile install --profile <path>` to add to the nix profile
   - Updates `devbox.lock` with resolved versions and store paths
   - Updates `.devbox/state.json` with new hashes [^devbox-packages]

[^devbox-packages]: jetify-com/devbox `internal/devbox/packages.go` — `Add()` method: validates, mutates config, ensures state, saves config.

### 4.3 `devbox global remove <pkg>`

1. Finds package in config by canonical name
2. Removes from `devbox.json` via `cfg.PackageMutator().Remove()`
3. Calls `plugin.Remove()` to clean up plugin files
4. Calls `ensureStateIsUpToDate(ctx, uninstall)` which:
   - Diffs the flake's `buildInputs` against the current nix profile
   - Runs `nix profile remove --profile <path>` for removed store paths
   - Runs `nix profile install` for any newly-needed paths (usually none)
   - Cleans up lockfile (`lockfile.Tidy()`) [^devbox-packages]

### 4.4 `devbox global list`

Delegates to the existing `listCmd()` which reads `devbox.json` and prints the configured packages with their resolved versions from the lockfile. [^devbox-global-cli]

### 4.5 `devbox global update`

Updates packages to newest versions matching their version constraints: [^devbox-update]

- `pkg@latest` → newest available
- `pkg@20` → newest `>=20.0.0, <21.0.0`
- No version → treated as `@latest`

Calls `Outdated()` to detect version drift, then `Add()` + `Remove()` for each changed package. [^devbox-packages]

[^devbox-update]: Jetify docs — "Whenever you run devbox update, packages will be updated to their newest versions that matches your criteria."

### 4.6 `devbox global shellenv`

Outputs shell export statements to activate the global devbox environment. Behavior:

1. Ensures state is up to date (same as install)
2. Computes full environment (plugins, env vars, nix print-dev-env output)
3. Outputs `export KEY="VALUE";` for all vars
4. Optionally runs init hooks (`--run-hooks` flag)
5. Appends `devbox refresh` alias for live-reload

This is the command users eval in their shell RC. It is the **sole mechanism** for making global packages available — there are no systemd services, no daemon, no file watchers. [^devbox-envexports]

### 4.7 `devbox global pull` / `devbox global push`

Delegates to `pullbox` — a sync mechanism for sharing devbox configurations. `Pull` fetches a `devbox.json` from a URL or Jetify Cloud; `Push` uploads the current config. This is for config sharing, not binary distribution. [^devbox-pushpull]

[^devbox-pushpull]: jetify-com/devbox `internal/devbox/pushpull.go` — delegates to `pullbox.New(d, opts).Pull(ctx)` / `.Push(ctx)`.

### 4.8 File layout summary

```
~/.local/share/devbox/global/           # XDG_DATA_HOME/devbox/global/
├── current → default                   # symlink to active profile
└── default/                            # the global "project"
    ├── devbox.json                     # package declarations
    ├── devbox.lock                     # pinned resolutions
    └── .devbox/
        ├── gen/
        │   └── flake/
        │       ├── flake.nix           # generated Nix flake
        │       ├── flake.lock          # Nix flake lock (auto-generated)
        │       └── .gitignore
        ├── state.json                  # state hashes for idempotency
        └── nix/
            └── profile/
                └── default             # nix profile symlink
                    → profile-N-link → /nix/store/...-profile/
                        ├── bin/        # merged bin dirs (the PATH target)
                        ├── share/
                        └── manifest.json
```

Note: the nix profile lives **inside** the devbox project directory (`.devbox/nix/profile/default`), NOT in the standard `~/.local/state/nix/profiles/` location. This is devbox-specific — it keeps the profile isolated per-project. The `ProfilePath` constant in devbox source is `.devbox/nix/profile/default`. [^nix-constant]

[^nix-constant]: jetify-com/devbox `internal/nix/nix.go` — `const ProfilePath = ".devbox/nix/profile/default"` and `ProfileBinPath()` returns `<projectDir>/.devbox/nix/profile/default/bin`.

---

## 5. Concept Mapping: Devbox → Shuttle

| Devbox Concept | Implementation | shuttle Analog (existing) | Notes |
|---|---|---|---|
| **devbox.json** | JSON list of package names + versions | `shuttle.lua` snap() declarations | shuttle uses Lua DSL; devbox uses JSON |
| **devbox.lock** | Pinned resolution: commit + store path per system | Lockfile (pins *inputs*, not the system) | Both are version-controlled, checked in |
| **Nix profile** (`.devbox/nix/profile/default`) | Versioned symlink dir to /nix/store entries | **Store** (file-level content-addressed, ADR-0012) | Fundamental difference: nix is store-path-level; shuttle is file-level CAS |
| **Generations** (`profile-N-link`) | Atomic symlink switch, GC roots | **Generation** (ADR-0012) — base + packages + config, one bootable unit | Similar concept! Both pin a selection and enable rollback. Shuttle generations are broader (system-level, not just packages) |
| **nix profile install/remove** | Add/remove store paths from profile | **Install** (ADR-0012) — add package to store + generation | shuttle install is file-level, manifest-based; nix profile is store-path-level |
| **flake.nix** (generated) | Nix expression referencing inputs + packages | `shuttle.lua` evaluation → snap manifests | Both are "declarations that get evaluated to produce artifacts" |
| **flake inputs** (`nixpkgs.url = ...`) | Pinned upstream sources | **Inputs** (CONTEXT.md) — `github:user/repo/branch`, `path:/local` | Very similar concept! Both shallow-clone or reference external package sources |
| **Global data path** (`~/.local/share/devbox/global/`) | Project directory for global packages | *No existing analog* | shuttle has no "global user profile" concept yet |
| **Package index** (devbox search) | Maps `name@version` → nixpkgs commit + attr | **Package index** (`package-index.json`) — maps snap names to store pins | Both are name→source resolution layers |
| **nix store** (`/nix/store/`) | Content-addressed store of build outputs | **Store** (ADR-0012) — file-level CAS on state partition | shuttle's store is more granular (files, not derivations) |
| **shellenv** | Export PATH + env vars to activate packages | *No existing analog* | shuttle operates at image build time, not shell-session time |
| **Plugins** | Auto-generated config for complex packages (nginx, postgres) | *No existing analog yet* | shuttle has `type = "meta"` but no plugin system |
| **runx** | Non-nix binary packages (runtime executables) | **Store snaps** (`type = "store"`) — pulled from Snap Store | Both handle "just download a binary" case |

### Key structural differences

1. **Granularity**: Nix profiles operate on store paths (entire package outputs); shuttle's store is file-level content-addressed. A devbox profile is a flat union of package bin/lib/share dirs; a shuttle generation is a system image.

2. **Activation model**: Devbox activates per-shell-session via `eval $(shellenv)`; shuttle activates at boot (generation = system state). There is no "per-terminal session" concept in shuttle.

3. **Scope**: Devbox global manages user-level development tools (ripgrep, go, node); shuttle manages system-level packages (kernel, systemd, application snaps) assembled into bootable images.

4. **Rollback**: Both support rollback, but shuttle's rollback is boot-time (switch generations via systemd-boot/sysupdate); devbox's rollback is profile-time (`nix profile rollback` changes the symlink).

5. **No daemon**: Both avoid long-running daemons — devbox uses shell hooks; shuttle uses systemd units.

---

## 6. Open Questions for the Grill

### 6.1 Should shuttle have a "global user profile" at all?

shuttle currently operates at image-assembly time. A devbox-global-like feature would mean shuttle also manages *per-user* development tools on the host machine (not inside the image). This is a scope expansion from "image builder" to "user package manager." Does this fit the project's identity?

### 6.2 What would the "profile" be?

Devbox's profile is a nix profile (symlinks to /nix/store). Shuttle's store is file-level CAS. If shuttle manages user packages, would it:
- (a) Use its own store + manifest system (like ADR-0012, but for user-level)?
- (b) Generate nix profiles (leveraging the existing nix ecosystem)?
- (c) Use snap packages only (install snaps into a user-level snapd)?

### 6.3 Lua DSL vs JSON for user config?

Devbox uses `devbox.json`. Shuttle uses Lua. Would a global user config be `shuttle.lua` in `~/.config/shuttle/`? What's the minimal Lua shape for "give me these packages on PATH"?

### 6.4 PATH activation model?

Devbox requires `eval "$(devbox global shellenv)"` in the shell RC. Shuttle has no equivalent. Options:
- (a) Shell hook (like devbox) — requires shell integration per user
- (b) Static symlinks in `~/.local/bin/` — simpler, no shell setup, but no version isolation
- (c) systemd user units / generators — fits shuttle's "no daemon, emit systemd" philosophy but doesn't solve PATH

### 6.5 How do generations work across two axes?

ADR-0012 defines generations as "base-image + packages + config = bootable unit." If shuttle also has a user-level profile, do user packages become a third axis? Or do they fold into the generation manifest? How does rollback work when the user has installed tools that the base image doesn't know about?

### 6.6 Content-addressing vs store-path addressing?

Nix profiles reference store paths (`/nix/store/abc123-ripgrep-14.1/`). Shuttle's store is file-level CAS. If shuttle manages user packages, does it still use file-level CAS? Or does it switch to package-level for user-facing management (simpler mental model, matches devbox/nix-env)?

### 6.7 What about development vs production?

Devbox global is explicitly for **development tools** (compiler, linter, formatter). Shuttle's ADR-0012 install is for **production packages** on deployed systems. Should shuttle distinguish these two modes? Or unify them?

### 6.8 Snap Store integration?

shuttle already has `type = "store"` packages that pull from the Snap Store. Could "global user packages" simply be snap installs into a user-level snapd? This avoids building a new package management layer but couples to snapd.

---

## Sources

| Source | URL / Location | Accessed |
|--------|---------------|----------|
| Nix profile docs | https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-profile | 2026-09-04 |
| Devbox global.go (source) | `jetify-com/devbox/internal/devbox/global.go` (main branch) | 2026-09-04 |
| Devbox nixprofile.go (source) | `jetify-com/devbox/internal/devbox/nixprofile.go` (main branch) | 2026-09-04 |
| Devbox packages.go (source) | `jetify-com/devbox/internal/devbox/packages.go` (main branch) | 2026-09-04 |
| Devbox global CLI | `jetify-com/devbox/internal/boxcli/global.go` (main branch) | 2026-09-04 |
| Devbox lock/lockfile.go | `jetify-com/devbox/internal/lock/lockfile.go` (main branch) | 2026-09-04 |
| Devbox lock/package.go | `jetify-com/devbox/internal/lock/package.go` (main branch) | 2026-09-04 |
| Devbox lock/statehash.go | `jetify-com/devbox/internal/lock/statehash.go` (main branch) | 2026-09-04 |
| Devbox xdg.go | `jetify-com/devbox/internal/xdg/xdg.go` (main branch) | 2026-09-04 |
| Devbox envvars.go | `jetify-com/devbox/internal/devbox/envvars.go` (main branch) | 2026-09-04 |
| Devbox nix/profiles.go | `jetify-com/devbox/internal/nix/profiles.go` (main branch) | 2026-09-04 |
| Devbox shellgen/flake.go | `jetify-com/devbox/internal/shellgen/generate.go` (main branch) | 2026-09-04 |
| Devbox flake template | `jetify-com/devbox/internal/shellgen/tmpl/flake.nix.tmpl` (main branch) | 2026-09-04 |
| Devbox flake_plan.go | `jetify-com/devbox/internal/shellgen/flake_plan.go` (main branch) | 2026-09-04 |
| Jetify docs: configuration | https://www.jetify.com/docs/devbox/configuration/ | 2026-09-04 |
| Jetify docs: pinning packages | https://www.jetify.com/docs/devbox/guides/pinning-packages | 2026-09-04 |
| Jetify docs: devbox overview | https://www.jetify.com/docs/devbox/ | 2026-09-04 |
| Devbox nixprofile/profile.go | `jetify-com/devbox/internal/nix/nixprofile/profile.go` (main branch) | 2026-09-04 |
| Devbox nix/nix.go | `jetify-com/devbox/internal/nix/nix.go` (main branch) | 2026-09-04 |
