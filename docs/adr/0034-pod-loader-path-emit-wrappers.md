# The pod loader path: emit-time LD wrappers replace the shellenv export

## Status

Accepted (2026-09-19). Amends ADR-0028 (pod loader path shellenv seam):
Decision 1's transport — the shellenv `LD_LIBRARY_PATH` export — is
superseded by emit-time per-app wrappers. The Decision's three hard
requirements are re-derived, not dropped. Grounded in issue #110.

## Context

ADR-0028 scoped the loader seam to the pod's activation surface: the
shellenv exported one generation-scoped `LD_LIBRARY_PATH` whose entries
threaded through the `current` link. In the field (2026-09-19, the daily
pod) the export failed its own third requirement — "must not pollute the
ambient environment beyond the pod's own activation surface" — because an
environment variable IS ambient by construction. Every child of the
hosting shell inherited the pod's extension libraries, and binaries that
dynamically link the same sonames broke in the pod's presence:

- host `curl` (and the pod's own `curl` when the host list was empty)
  loaded the pod's libcurl and failed TLS verification;
- a nix-store `git-remote-https` loaded the pod's libcurl and failed
  certificate checks (`unable to get local issuer certificate`);
- `node` loaded the pod's libsqlite3 and died on a missing symbol
  (`sqlite3session_attach`), taking `devbox run` down with it;
- the host `less` printed a loader warning on every `git log`.

The failure is structural, not tunable: any env var visible to the shell
is visible to everything the shell runs, so "scoped to pod processes"
cannot hold at the env layer.

## Decision

1. **The seam moves into the emit.** `farm::emit` writes a per-app LD
   wrapper into `generations/<n>/ld-wrappers/<app>` for every app (and
   service binary) of a package that contributes loader-lib dirs. The
   script sets `LD_LIBRARY_PATH` to the generation's recorded loader-lib
   dirs — the exact list ADR-0028's `loader-libs` file already recorded,
   in the same layer-first order — resolved generation-relative through
   the wrapper's own location (`$d/../extensions/...`), then execs the
   app's normal entry target (assembly leaf, confined launcher, or store
   blob). The farm entry for such an app points at the wrapper.

2. **SET, never compose-prepend.** The old shellenv composed with
   `${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}`; inside a pod process that
   would still mix ambient entries ahead of the pod's list. The wrapper
   assigns outright: a pod process sees the pod's libraries, and
   whatever the caller's environment carried stops at the wrapper.

3. **The shellenv export is withdrawn.** `pod shellenv` renders the
   farm-first `PATH` prepend plus the declared env (ADR-0030) — no
   `LD_LIBRARY_PATH`. `shuttle run`'s arbitrary-command overlay drops
   the loader-lib prepend for the same reason: an arbitrary command is
   not a pod process. `shuttle run` of a farm binary inherits the
   wrapper's scope through the farm entry it resolves.

4. **The three ADR-0028 requirements re-derived.** (a) Rollback safety:
   the wrapper lives inside the generation and resolves its lib dirs
   relative to itself, so the `current` flip re-scopes every path
   atomically exactly as before; the wrapper area is reset on every
   emit, so a re-emit of a lib-less generation withdraws stale wrappers
   alongside the stale `loader-libs` list. (b) No cross-pod leak: the
   dirs are per-generation and per-pod by construction. (c) No ambient
   pollution: nothing is exported at all — strictly stronger than the
   env form, which polluted by default.

5. **Farm-entry shape follows the confined-launcher precedent (ticket
   #11), not the issue #3 bare-blob rule.** Issue #3's "direct links, no
   shims" already yielded for confined apps, whose farm entries point at
   a `shuttle run` launcher wrapper. A libs-carrying app has the same
   justification: the bare blob cannot work at all without its
   generation's libraries. `which` stays truthful — the wrapper is
   named for the app and execs it transparently.

## Consequences

**Positive.** Host toolchains (nix git, node via devbox, system curl)
work inside a pod shell again. Pod binaries get exactly their
generation's libraries with no ambient interference. Rollback semantics
are preserved without re-eval. The `loader-libs` record keeps both its
consumers: the wrappers and `shuttle run`'s declared-app sandbox.

**Negative.** One extra `exec` hop for wrapped binaries (a shell exec,
no copy). Farm entries for libs-carrying apps are no longer direct store
links, so tooling that assumed blob-addressed farm targets must read the
wrapper (or `entry_target_rel`) instead. Generations gain an
`ld-wrappers/` directory (GC-scoped like everything else in the
generation).

## Migration

`pod sync`/`rebuild` re-emit and write wrappers; an already-eval'd shell
that still carries the old export from a pre-#110 rc keeps it until the
next login, where the shellenv simply stops emitting it. The
`examples/cutover/verify-sweep.sh` gates remain the acceptance proof:
every daily tool resolves and runs from the farm, and the environment is
now pod-free as well as devbox-free.

## References

ADR-0028 (the superseded transport, and the three hard requirements
re-derived here); issue #110 (field report: curl SSL, git push,
remote-https); issue #89 (the loader-libs record); ticket #11 (the
wrapper-at-farm-entry precedent); `docs/t13-cutover-checklist.md` §5.7
(the seam's original landing note).
