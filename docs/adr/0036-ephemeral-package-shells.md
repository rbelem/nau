# ADR-0036: Ephemeral package shells — `shuttle shell`

Status: Draft (design doc; the implementation is not scheduled in this
document). Council-reviewed 2026-09-21 (two-seat consensus; both seats
picked Option A, both rejected Option B, both kept nix as the documented
bridge for the cases A serves worst). §5 amended 2026-09-22 by
ADR-0038 contract 7.

## Context

Retiring devbox-global removes the last ephemeral profile surface on the
host. Pods are declarative and persistent: trying one binary means
`shuttle pod add`, a sync, a generation, and a removal later. The
retirement was accepted partly because nix itself stays on NixOS hosts,
so `nix shell nixpkgs#ffmpeg -c …` keeps working. That is a bridge, not
a design: it splits the package world into two stores, two GCs, two
philosophies, and it does not exist on non-nix distros (#98–#100).

The recurring shapes the surface must serve:

- **One-shot binaries**: `ffmpeg` in a pipe, `openfortivpn` under sudo,
  a formatter inside a script. Nothing should outlive the invocation.
- **Throwaway environments**: a shell whose PATH has one extra tool, for
  debugging, without touching `pod.lua`.

`shuttle run -- <cmd…>` (#102) already owns env overlay; what it cannot
do is bring packages that the pod does not declare.

## Decision

`shuttle shell [<pod flags>] <pkg>… [-- <cmd…>]` (Option A): resolve and
build the named pool packages into the content-addressed store reusing
the pod build machinery, assemble a throwaway farm, and exec the command
with the #102 env overlay (farm-first PATH, ADR-0028 loader seam,
declared env from the target pod). No pod mutation, no lockfile entry,
no generation, no `shuttle.lock` record.

- **Option B (scratch pod) rejected**: generation + rollback machinery
  buys nothing for a use case whose defining property is disposability,
  and it pollutes `pod list` with pseudo-pods.
- **Option C (nix bridge) retained, scoped**: heavy trees and privileged
  one-shots stay on nix until shuttle can serve them (below). The ADR
  says this explicitly so the bridge does not silently become permanent
  — and so nobody expects `shuttle shell ffmpeg` to beat a nix binary
  cache on day one.

## Design contract

1. **Store home is pod-scoped** (`--pod`/`--root`, mirroring `run`).
   Ephemeral blobs land in the named pod's store and that pod's `gc`
   governs them. No dedicated ephemeral store; cross-pod blob sharing
   remains future work (ADR-0033 direction).
2. **A session root guards the exec lifetime.** "Unrooted, reclaimed by
   the next gc" is wrong as stated: gc is mark-sweep over generation
   manifests, so an unrooted blob is sweepable *while the command runs*,
   and farm symlinks make a mid-exec sweep kill every later subprocess.
   `shell` takes a build/exec lock shared with gc and holds a temporary
   root (a store-roots entry) for the duration; crash-orphaned roots are
   reclaimed by the next gc after an age floor. After exit, the entry is
   unrooted and the next gc reclaims it — the nix-shell gcroot shape.
3. **Concurrent invocations serialize** on the same lock (two `shuttle
   shell ffmpeg` at once must not race the build or the farm).
4. **Farm assembly goes through the emit/wrapper path** (ADR-0034), not
   raw symlinks: farm entries are loader-seamed per ADR-0028/ADR-0034,
   and a raw-symlink throwaway farm would regress exactly the dynamic
   linking cases the wrappers fixed.
5. **Shadowing is ephemeral-first, and said so.** The throwaway farm
   precedes the pod farm on PATH for the invocation — that is the
   feature (`shuttle shell jq -- bash` gets the ephemeral jq). The
   declared-app confinement rule of `run` does not apply: `shell` never
   sandboxes (fail-open, same as the #102 command half). (Amended by
   ADR-0038 contract 7: in a pod whose isolation level is not `host`,
   `shell` inherits the pod boundary; the fail-open rule names `host`
   pods only.)
6. **The bare form is reserved**: `shuttle shell <pkg>…` without `--`
   will exec an interactive shell with the overlay once implemented;
   tonight's contract only fixes the name, not the semantics.

## Consequences

**Positive**

- The nix-shell shape exists natively; throwaway intent never touches
  `pod.lua`, the lockfile, or generations.
- Build/cache machinery, toolchain pins, and offline vendoring are
  reused, not forked.
- The store stays the single content address space; gc discipline is
  the pod's, with one explicit root rule.

**Negative**

- **No binary cache for shuttle content.** A cold `shuttle shell
  ffmpeg` is a multi-hour build; `nix shell nixpkgs#ffmpeg` is minutes
  from cache. Until ADR-0033-style peer sharing or an attic-like blob
  cache exists, the documented answer for heavy trees is the nix bridge.
  The man page and `--help` must say this to avoid a broken-first-
  impression loop.
- **Privileged one-shots stay out of scope**: ADR-0035's privilege
  boundary is the install-time rename; there is no run-time privilege
  path. `sudo nix shell nixpkgs#openfortivpn -c …` remains the bridge
  for the root/VPN class. Recorded here so the question stops recurring.

## References

- #102 (`run --` env overlay, the shell of this contract), ADR-0028
  (shellenv/loader seam), ADR-0034 (emit wrappers), ADR-0033 (peer
  package sharing — the cache-shaped mitigation), ADR-0035 (privileged
  install path), t13 checklist §5.1/§5.5 (the retirement that created
  the gap).
