# Pod runtime confinement: two levels, shared grants, pluggable backends

## Status

Accepted (2026-09-05). Grounded in a `/grill-with-docs` session on sandboxing levels, primary-source research (`.planning/research/sandboxing-levels.md`: nix build-only integrity, snap `strict`/`classic`/`devmode`, Flatpak bubblewrap + portals), and the pod feature (ADR-0015). Naming invariant per ADR-0013. `Confinement`, `Grants`, and build-sandbox-vs-confinement disambiguation added to `CONTEXT.md`.

## Context

The pod feature (ADR-0015) exposes user-level tools through a symlink farm of direct symlinks into the content-addressed store. The owner wants to define **levels of sandboxing** for the tools a pod installs. A conflation had to be resolved first: the term "sandbox" currently means the **build sandbox** (bubblewrap, ADR-0004) that confines the *builder* at compile time — a different axis from confining the *installed app* at runtime.

Primary-source facts (research file): **nix** confines the *build* (sandboxed derivations, immutable store) but a `nix profile` tool runs **unconfined** on the host — its security model is reproducible/integrity, not runtime confinement. **snap** `strict` confines the *running app* (AppArmor + seccomp + namespaces via a `snap run` launcher) with declared *interfaces*; `classic` = no confinement, `devmode` = dev-only. **Flatpak** confines runtime via bubblewrap (`bwrap`) with default denies + `--filesystem`/`--socket`/`--share`/`--device` grants and user-consented *portals*.

Decision split: dev CLIs (jq, rg, git, go) simply cannot run under strict confinement without broad grants that make it cosmetic — and pay a per-invocation namespace cost in hot loops. GUI apps and background services are where confinement genuinely helps. So a two-level runtime model, distinct from the build sandbox.

## Decision

1. **Two runtime confinement levels, on the runtime axis only** (the build sandbox stays a separate, always-on axis):
   - **`unconfined`** — the installed app runs directly on the host with the user's privileges. Default for simple CLIs. (This is the pod farm's existing model: direct symlink, no launcher.) The content-addressed store + hermetic build remain the "nix-like" integrity guarantee, but the runtime is not confined.
   - **`confined`** — the installed app runs inside a namespace/AppArmor/seccomp sandbox with declared grants, launched via a `shuttle run <app>` interposing launcher. For GUI apps and services.

2. **`store-isolated` is NOT a third runtime level.** It is a property of `unconfined` (build sandbox + immutable store integrity). Two runtime levels only.

3. **One shared grants vocabulary, a `backend` selector, both honor it.** The common grants are the portable contract; a backend keyword (`bwrap` or `apparmor`) selects the enforcement mechanism. The same `grants` declaration is the source of truth — bwrap implements it via `--bind`/`--ro-bind`/`--unshare-net`/`--socket`/`--device`, AppArmor via profile rules and syscall filters. This makes the backends interchangeable for anything expressible in the shared vocabulary.

4. **A non-portable `backend_options` finetune escape hatch.** A package may add a sub-table of backend-specific raw flags (e.g. `backend_options = { bwrap = {...} }` or `{ apparmor = {...} }`) for needs beyond the shared vocabulary. These are documented as non-portable: switching backends loses the raw bits (warned). Shared grants remain the portability contract; `backend_options` is the explicit escape hatch.

5. **Grants vocabulary** (the shared contract, mirroring Flatpak finish-args simplified into Lua):
   ```lua
   confined = {
     backend = "bwrap",        -- or "apparmor"
     filesystem = { "read", "write" },
     network = false,
     sockets = { "ssh-auth", "wayland", "x11" },
     devices = { "dri", "input" },
     backend_options = { /* backend-specific raw flags */ },
   }
   ```

6. **Defaults by package type.** A simple CLI `snap()`/`app()` defaults to `unconfined`; a GUI app (`terminal = false` / a `desktop` app) or a service defaults to `confined`. The package author declares it; the pod can override per-package via `pod.lua` (mirroring the overlay layering).

7. **The `shuttle run <app>` launcher.** For `confined`, the farm `current/bin/<app>` symlinks to a wrapper that invokes `shuttle run <app>`, which sets up the sandbox then execs the app — transparent to the user (no new mental model, `which`/PATH stay truthful). `shuttle run` is also the future home for env hooks.

8. **Fail closed if a confinement backend is unavailable.** A `confined` app must NOT silently run unconfined on a host where bwrap (unprivileged userns) or AppArmor is unavailable — it fails with a clear error. A per-pod `confinement = "unconfined"` override is the explicit, user-acknowledged escape hatch.

## Alternatives considered

- **Three levels (`unconfined` / `store-isolated` / `confined`).** Rejected: `store-isolated` has an unconfined runtime identical to `unconfined`; its distinguishing property is the build sandbox + store integrity, which is the build/storage axis, not a distinct runtime level.
- **Snap-style `strict`/`classic`/`devmode`.** Rejected: no clean "nix-like" intermediate; `devmode` is a dev-only mode, not a shipping level.
- **Two independent, non-interchangeable confinement models.** Rejected: defeats the owner's requirement that the backends work together/interchange.
- **Strictly-portable only (no raw escape hatch).** Rejected: contradicts the owner's finetune requirement.
- **Always-layered (bwrap + AppArmor together on every confined app).** Rejected: more complex than needed; the backend selector keeps the mechanism per-host/per-package.

## Consequences

**Positive**: one declarative grants contract honored by either backend (portable confinement); the "nix-like" integrity guarantee is preserved under `unconfined` without runtime cost; dev CLIs stay fast and compatible; GUI/services can be genuinely confined; `shuttle run` keeps `which` truthful; fail-closed means no silent privilege weakening.

**Negative**: two enforcement mechanisms to maintain; `backend_options` raw flags are inherently non-portable (documented, warned); `confined` costs a namespace setup per invocation (acceptable for GUI/services, wrong for hot CLI loops); unprivileged-userns/AppArmor availability varies by host (fail-closed surfaces it); AppArmor policy profiles are more work than bwrap flags for the same grants. The next step is an implementation ticket for the `confined` backend + `shuttle run`, after the runtime-lib wrapper (#10) which is already merged.
