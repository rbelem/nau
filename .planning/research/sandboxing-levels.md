# Sandboxing Levels for Shuttle Pods — Primary-Source Research

> **Purpose**: feed a design decision on defining LEVELS of sandboxing for shuttle pods.
> The owner wants three precisely-named levels: (1) none, (2) "like nix", (3) "like snap/Flatpak".
> **Date**: 2026-09-05
> **Method**: direct primary-source inspection (nix manual, snapcraft confinement docs,
> Flatpak sandbox-permissions docs) + shuttle's own build sandbox code.
> **Note**: the librarian lane was billing-blocked; this was written from primary
> documentation fetched directly.

## The core distinction people conflate

There are TWO independent axes that look like one "sandbox level":

- **Build sandbox (compile-time)**: confines the *builder* while it produces the artifact.
  nix, snapcraft (for build parts), and shuttle's bubblewrap build sandbox all do this.
  It protects the host from a malicious/mistaken build, and (for nix) makes the build
  reproducible. It says NOTHING about what the *installed app* can do when run.
- **Runtime confinement (run-time)**: confines the *installed app* while the user runs it.
  nix does **NOT** do this (a nix profile tool runs unconfined on the host). snap `strict`
  and Flatpak DO (AppArmor/seccomp/namespaces, a `snap run`/`flatpak run` interposing
  launcher).

The owner's three levels map to the RUNTIME axis (the build sandbox already exists in
shuttle). Name them on the runtime axis.

## Comparison table (runtime confinement)

| Level | Mechanism | Runtime confinement | Compatibility | Per-invocation cost | Example |
|-------|-----------|---------------------|---------------|---------------------|---------|
| **None** | none — binary execs directly | none (full user privileges, full FS, full net) | max — everything works, unconfined | zero | `nix profile` tool (jq typing from a nix profile), Homebrew, cargo-installed |
| **Nix-like** | none at runtime; store/content-addressed + **build** sandbox only | none at runtime (build + store integrity only) | max (identical to None at runtime) | zero (plus build-time sandbox cost) | any `nix profile install` — the store guarantees integrity, the profile is a symlink |
| **Snap strict / Flatpak** | AppArmor/seccomp/mount+net namespaces via `snap run`/`flatpak run` | read-only host root, private /tmp, no net by default, no device nodes, limited syscalls, no host processes | **broken for many dev tools** — need interfaces/portals/filesystem grants | high — namespace + confinement setup per invocation | vlc (snap strict), a Flatpak GUI app |

## Per-level primary-source detail

### Level 1 — None (baseline)
An installed binary is a symlink/direct copy and execs directly. No namespace, no policy,
no launcher. Equivalent to `nix profile` *runtime* behavior and to Homebrew/cargo/go
installs. Max compatibility; no confinement of the running app. The host is the boundary.

### Level 2 — "Like nix"
nix confines at **build** time (sandboxed derivations: namespaces, no network, restricted
store) and guarantees **store integrity** (content-addressed, immutable, GC-rooted), but a
`nix profile`-installed tool runs **unconfined on the host** — it is a symlink to a store
path, executed directly. nix's security model is "reproducible, immutable build + store",
*not* "confined runtime." [^nix-conf]

[^nix-conf]: Nix manual — `sandbox = true` (default on Linux) restricts *builders*; the
`allow-new-privileges` doc explicitly notes sandboxed *builds* can't setuid. Nothing confines
the *running* artifact. nix3-profile = a directory of symlinks into /nix/store.

Shuttle's **build sandbox** (bubblewrap, `src/snap.rs` `run_bwrapped`: `--unshare-user/pid/ipc/net`,
read-only FHS roots via `SANDBOX_RO_ROOTS`, private /tmp, no network) is already "nix-like"
at the build axis. So shuttle Level 2 = build-sandbox + store integrity, unconfined runtime
— which is what the pod farm already does once #10 (hermetic sandbox + runtime-lib wrapper)
lands: reproducible store-backed content, direct-symlink farm, unconfined execution.

### Level 3 — "Like snap strict / Flatpak" (runtime-confined)
snap strict: AppArmor + seccomp + mount/net namespaces; app has no access to files/net/
processes/devices except via declared **interfaces**; run via `snap run <app>` which sets up
confinement then execs. `classic` = no confinement (manual approval); `devmode` = strict with
full access + debug output (development only). [^snap-conf]

[^snap-conf]: snapcraft.io/docs/snap-confinement — strict/classic/devmode; strict uses
AppArmor, seccomp, namespaces; strict snaps must declare interfaces to access resources.

Flatpak: bubblewrap (`bwrap`). Default denies host files (except runtime, app, `~/.var/app`),
network, device nodes, other processes, session D-Bus names, and most syscalls; grants are
added via `finish-args` (`--filesystem=`, `--socket=`, `--share=network`, `--device=`) and
user-consented **portals** (file chooser, URI open, print, notifications). Run via
`flatpak run`. [^flatpak-conf]

[^flatpak-conf]: docs.flatpak.org/en/latest/sandbox-permissions.html — flatpak isolates via
bubblewrap; default denies host FS/net/devices/processes; `--filesystem`/`--socket`/
`--share`/`--device` grants and portals restore access.

## The cost surface (why you cannot put dev CLIs in strict)

- **Compatibility**: `jq`, `rg`, `git`, `go`, `cargo` need host FS (HOME, /tmp, project dirs),
  network (fetch deps), and often `$SSH_AUTH_SOCK` / `$XDG_RUNTIME_DIR`. Under strict they
  break unless you grant `--filesystem=home`, `--share=network`, sockets — at which point
  the confinement is mostly cosmetic for a dev tool.
- **Per-invocation overhead**: `snap run`/`flatpak run` set up namespaces + policy each launch.
  For short-lived CLIs run in hot loops, that overhead is real and annoying.
- **What strict is actually for**: GUI apps with hostile/dynamic content and untrusted code
  (browsers, media players, office suites), and background services with privileged access.
  Dev tools are the *user* running trusted code — strict buys little and costs a lot.

## Recommended taxonomy for shuttle

Name the levels on the **runtime** axis, distinct from the existing "build sandbox" term
(which stays as-is in CONTEXT.md):

1. **Unconfined** — the installed tool runs directly on the host with the user's privileges.
   Default for dev CLIs. (The pod farm's current model; matches nix/Homebrew/cargo runtime.)
2. **Store-isolated** (the "like nix" level) — the runtime app is unconfined, but the
   artifact is a content-addressed, immutable, GC-rooted store entry with a hermetic,
   reproducible build. Integrity yes; runtime confinement no. (Shuttle's build sandbox +
   store + farm, once #10 lands.)
3. **Confined** (the "like snap/Flatpak" level) — the running app is wrapped in a
   namespace/AppArmor/seccomp sandbox with declared interfaces/grants, launched via a
   `shuttle run`-style interposing launcher. For GUI apps and privileged services; NOT the
   default for dev CLIs.

A package's `confinement` field would pick the level (like snap's strict/classic), defaulting
to `unconfined`/`store-isolated` for dev tools and opting into `confined` for GUI/services.

## Open questions for the grill / council

1. Name the three levels — `unconfined` / `store-isolated` / `confined`? Or a different set?
2. Is `store-isolated` worth being a distinct *runtime* level, or is it really just "build
   + store guarantee" (axis-1) with `unconfined` runtime? (I lean: name it, because the
   hermetic-build + store-integrity guarantee is a real, sellable property even at
   unconfined runtime.)
3. For `confined`: does shuttle use bubblewrap (like Flatpak, already the build tool) or
   AppArmor/seccomp (like snap)? bubblewrap reuses the existing dependency; AppArmor is
   stronger for hostile code but kernel+policy heavy.
4. What grants/interfaces surface does `confined` expose (filesystem, network, devices,
   sockets, portals)? Mirror snap interfaces or Flatpak finish-args?
5. Which real tools go `confined` in v1 — GUI apps only? Or never until a real need?

## Sources

- Nix manual — nix.conf / sandbox (build-time only), nix3-profile (symlink store, no runtime
  confinement). https://nixos.org/manual/nix/stable/command-ref/conf-file.html
- snapcraft.io/docs/snap-confinement — strict/classic/devmode, AppArmor/seccomp/namespaces,
  interfaces. https://snapcraft.io/docs/snap-confinement
- Flatpak sandbox-permissions — bubblewrap isolation, default denies, finish-args grants,
  portals. https://docs.flatpak.org/en/latest/sandbox-permissions.html
- Shuttle build sandbox — `src/snap.rs` `run_bwrapped`, `SANDBOX_RO_ROOTS`, ADR-0004.
