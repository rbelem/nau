# Pods: user-level package management, pod generations, and the symlink farm

## Status

Accepted (2026-09-05). Grounded in a `/grill-with-docs` session (parent issue #1), a primary-source research pass on devbox internals (`.planning/research/devbox-global-internals.md`), a three-seat council review on binary exposure (`.planning/research/package-manager-bin-exposure.md`), and the two-axis store/generations ADR (ADR-0012). Naming invariant per ADR-0013 applies throughout.

## Context

ADR-0012 defined two update axes: an immutable dm-verity base and a package store on the state partition, with **system generations** pinning base-version + package set + configuration as one *bootable* selection. That model is correct for the deployed system (ShuttleOS), but it does not cover the host machine a developer works on. Today a shuttle developer still needs a second stack — devbox + nix — to manage their own user-level tools (ripgrep, jq, compilers, GUI apps). Two package worlds means two config languages, two lockfiles, two stores, two mental models.

The owner's requirement: shuttle is the backend, and it replaces devbox + nix for user-level package management. GUI applications installed as user packages must also reach the desktop applications menu via freedesktop `.desktop` entries.

A design tension had to be resolved: ADR-0012's `Install` and `Generation` are *bootable-system* concepts. Stuffing host dev tools into the same manifest would couple `shuttle rollback` (a reboot) to "drop my tools." The resolution is a **separate, host-side user-level chain** — pods — reusing the store but not the bootable generation semantics.

## Decision

1. **Pods.** A **pod** is a named user-level package selection owned by one user — the small shuttle served by the system mothership. A user may have multiple pods (`work`, `home`). The system image is the mothership; the pod is the small vessel. CLI, per ADR-0013, never uses the word "global": the command group is `shuttle pod`.

2. **CLI shape is `shuttle pod [--name <name>] <verb>`.** The `--name` flag precedes the verb; omitted it targets the `default` pod (devbox-global parity). Verbs: `add`, `remove`, `list`, `update`, `rollback`, `sync`, `gc`. The command group mirrors the existing runtime command group (install/remove/upgrade/rollback/gc lifecycle) and reuses the existing runtime store pointed at the pod state directory — no forked store.

3. **Pod generations are a SEPARATE chain from system generations.** A **pod generation** pins one pod's packages + overlays + loaded pods at a point in time. `shuttle pod rollback` flips that pod's `current` link only; it never reboots and never touches system generations. GC is rooted at pod generation links; system generations are never eligible. Reusing `Generator` semantics wholesale is rejected because it would couple a reboot to a dev-tool revert.

4. **Declaration is a `pod()` Lua global, code-only, in a single file per pod.** The agreed schema:

   ```lua
   pod {
     loads = { "base" },
     packages = { "jq", "ripgrep@14" },
     overlay = { jq = { version = "1.8", build = "..." } },
   }
   ```

   Imperative verbs rewrite this declaration file (add/remove/edit), so the declarative file stays the single source of truth.

5. **Layering order inside one pod:** shared package collection < loaded pods (in listed order) < own `packages` < inline `overlay`. Later wins; upstream files are never modified; overlays live in the pod's own config so pods cannot leak into each other. Composition is live-following in v1 (a pod resolves its loaded pods' current generations; cross-pod generation pins are deferred). Load chains resolve transitively; cycles (self-load included) are a hard error at evaluation time, named in full.

6. **Conflict policy.** Cross-layer binary override (loading pod over loaded pod) warns naming winner and loser; a same-precedence binary collision within one pod is a hard error; both evaluate at mutation *and* activation time — no silent shadowing path. Desktop application-ID collisions follow the same rule. The collision classifier is one shared mechanism, not per-domain.

7. **Activation: the farm is a directory of DIRECT SYMLINKS, no shims.** Each pod generation exposes `current/bin/<tool>` as direct symlinks into the content-addressed store, reachable by a single PATH prepend (or a one-time link into `~/.local/bin`). No shell RC integration in v1. This is the devbox/nix model, verified in source *and* empirically (every entry in a real devbox global profile `bin/` is a symlink into `/nix/store`). asdf/mise-style shims are rejected: they solve per-invocation version dispatch, which shuttle solves at activation with the atomic `current` flip; shims would add a fork + argv mangling per call and break `which <tool>` / `/proc/self/exe` truthfulness. Snap-style launcher symlinks (`/snap/bin/<app> -> /usr/bin/snap`) are rejected: they exist for confinement, and pods are unconfined host tools.

8. **Build-time wrappers, not farm wrappers.** A package whose real entrypoint is not a standalone ELF (a Node/Python/other-interpreter CLI, e.g. a `zg`-like tool) is handled by authoring a launcher wrapper into the **store package at build time** (the nix `makeWrapper`/`wrapProgram` analogy), so the farm `current/bin/<tool>` symlink points at a working wrapper. The wrapper is a single `exec` (`exec "$interpreter" "$script" "$@"`), baked into the store payload — never added by the farm emitter or any runtime step. Native-ELF packages get no wrapper. (Tracked as issue #9.)

9. **Desktop integration is user-level and generation-versioned.** GUI entries are generated from each package's `apps` metadata into the user's applications directory, with `Exec` rewritten to the pod farm paths and icons linked alongside; entries are part of the pod generation so removal and rollback add, revert, or withdraw launchers atomically. Never writes outside user directories; no privilege escalation. Consuming `apps` metadata for pods requires un-rejecting desktop-related fields on the pod evaluation path.

10. **Reuse, don't fork.** Pods reuse the content-addressed file store, signed manifests, GC-rooting, and lockfile machinery (ADR-0012). The only net-new module is the farm/launcher emitter. No devbox/nix import path, no daemon, no file watcher, no systemd user units for activation.

## Alternatives considered

- **Reuse system generations with a host axis.** Rejected: ADR-0012 generations are *bootable* selections; folding host tools in would couple `shuttle rollback` (reboot) to dev-tool reverts and muddy the two-axis contract.
- **Wrap devbox/nix.** Rejected: drags in the nix daemon + binary-cache trust model (ADR-0012 moved away from it) and splits the supply chain in two.
- **Shims (asdf/mise style).** Rejected (council 3/3): solves per-invocation version dispatch shuttle already handles at activation; costs a fork per call; lies to `which`/`/proc/self/exe`.
- **Snap-style launcher symlinks.** Rejected: exists for confinement; pods are unconfined.

## Consequences

**Positive**: one stack replaces devbox + nix; host tools and system packages share one store and one lockfile philosophy; pod rollback/GC are cheap and never disturb the bootable system; GUI apps reach the desktop menu; devbox-parity activation without shim cost.

**Negative**: two update chains must stay coherent (system generations vs pod generations) — they are deliberately separate contracts, so no cross-referencing manifests are required today; interpreter-based packages need build-time authors to emit a wrapper (#9); a pod's `PATH` prepend is manual (no shellenv hook in v1); cross-pod pins are deferred (live-following only). The hosting project keeps the naming invariant (no "global" in CLI/config).
