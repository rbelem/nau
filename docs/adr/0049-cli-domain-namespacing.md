# ADR-0049: CLI domain namespacing

## Status

Accepted. Ratified 2026-09-30 by the operator after the four-seat council
review of the binary-split plan (#312–#320). The split plan pinned
"`nau <subcommand>` UX immutable" as a SPLIT-SCOPING decision; the operator
elected to reshape the surface before the split machinery lands instead, so
the tracer and every later contract test pin the final spellings. This ADR
supersedes that invariant and re-pins it post-reshape.

Amended 2026-09-30 (naming council, 4 seats): `farm` → **`pool`** —
ADR-0040 does NOT name the worker domain `farm`; it says the opposite
("*naming respects CONTEXT.md: `farm` stays the pod bin farm (src/farm.rs)*"
and rejects `farm {}` config naming), and `farm` sits on CONTEXT.md's
Worker avoid-list. The worker domain takes ADR-0040's own title noun,
`pool` ("an SSH-driven build pool with no daemons"). The `trust` tree is
flattened to two levels, and the onboard-binary target is named
`nau-mothership` (ratified in ADR-0050).

## Context

The CLI grew to 26 top-level verbs plus 4 hidden internal workers, all in
one flat `Command` enum. The domains already existed implicitly — `pod` and
`runtime` are namespaced today, the cloud fleet is called "build farm" by
its own ADR-0040 while the command says `workers`, and the definition/build
lifecycle (check, eval, lock, lint, audit, index, deps) shares one grammar.
The flat surface hides those seams; the split plan made them load-bearing
(the onboard allowlist is exactly the pod+runtime domains). Reshaping
mid-split would churn the tracer's contract tests, so the reshape lands
first, expand–contract.

## Decision

1. **Ten domain namespaces** (table below). Domain nouns: `chart` (define &
   resolve), `build`, `image`, `ship` (distribute), `peer` (LAN sharing),
   `pod`, `runtime`, `trust` (ceremony), `pool` (was `workers` — ADR-0040's
   own title noun; `farm` is REJECTED, it stays the pod bin farm,
   `src/farm.rs`), and `doctor` (domain of one, stays flat). `completion`
   is tooling, not a domain — stays top-level.

   | Domain | Commands |
   |---|---|
   | `nau chart` | check, eval, eval-worker, check-worker, lock, lint, audit, search, index, deps |
   | `nau build` | snap, cache |
   | `nau image` | build, test, verify |
   | `nau ship` | push, pull |
   | `nau peer` | serve, browse, export |
   | `nau pod` | add, declare, remove, sync, list, update, rebuild, refresh, rollback, gc, shellenv, secrets, run |
   | `nau runtime` | install, remove, upgrade, rollback, gc, activate, recover-slots |
   | `nau trust` | keygen, rotate, promote, revoke, list, verify — flattened two-level; `--ca` scopes the host-CA halves (`nau trust keygen --ca`, `nau trust list --ca`) |
   | `nau pool` | provision, destroy, burst, down, issue, publish, pickup, probe, job |
   | `nau doctor` | (the verb itself) |

   Nesting rule: two levels, three where a verb group already exists
   (`chart index update`; precedent `pod secrets refresh`).

5. **Extensibility — external subcommands (git's `git-<cmd>` mechanism).**
   An UNKNOWN verb falls through to an executable `nau-<verb>`: resolved
   sibling-of-`current_exe` first, then PATH — never via an environment
   override (the isolation posture: no env-influenced lookup, for nau's own
   workers or anyone else's). Known verbs — including the hidden legacy
   spellings and the internal `__*` workers — always match their real clap
   variants first; the external path only ever sees names nau does not
   know. Verb names must match `[a-z][a-z0-9-]*` (git's own charset rule:
   no dots, no leading dashes, no path separators — no path tricks). argv
   is forwarded verbatim, stdio inherited, exit code propagated. This is a
   DISPATCH contract, not a code split: nau's own code remains one binary
   (per ADR-0050); third parties — and pods, whose bin farms land on PATH
   via `pod shellenv` — extend the CLI by shipping `nau-<verb>`
   executables, exactly as `git-credential-*` extends git.

2. **The hidden internal commands are revealed and integrated:**
   `__eval-worker` → `chart eval-worker`, `__check-worker` → `chart
   check-worker`, `__worker-cap` → `pool probe`, `__worker-job` → `pool
   job`. Help text marks them advanced — invoked by nau itself.

3. **Migration is expand–contract.** (a) The domain namespaces land BESIDE
   the legacy spellings; every old spelling stays a working hidden alias —
   nothing breaks. (b) Load-bearing contracts migrate in gate-green
   batches: the wrapped-build parser accepts `nau build snap`, completion
   generation emits the tree, the 20+ integration test invocations and the
   docs move. (c) After a deprecation window the aliases emit named
   deprecation warnings, then are removed.

4. **The pool rename is wire-visible.** The coordinator invokes workers BY
   NAME over SSH, so `__worker-cap`/`__worker-job` → `pool probe`/`pool
   job` changes the remote protocol surface. Bump
   `WORKER_PROTOCOL_VERSION` and roll coordinator + workers in lockstep —
   the burst provision→teardown lifecycle makes fleet rollover cheap.

## Security

- The eval/check containment invariant is about DISCOVERY, not visibility.
  `chart eval-worker` / `chart check-worker` remain self-re-exec'd via
  `current_exe()` with NO env override and NO PATH fallback (the isolation
  ruling stands untouched); this ADR changes only their clap visibility.
- Boot units are untouched: `runtime activate` / `recover-slots` keep their
  exact argv; the pinned ExecStart constants and the staged-path drift pin
  are unaffected.
- No EXEC_PATH-style discovery is introduced by or alongside this ADR.

## Migration map

- **Expand** — namespaces + hidden aliases (additive; legacy help output
  unchanged).
- **Migrate** — wrapped-build spellings, completion, tests, docs; blocked
  by expand + the layering un-inversion (#313), so the motion happens once
  on the final tree.
- **Contract** — deprecation warnings, then alias removal after the window.
- The split tracer (#314) is additionally blocked by the migrate step, so
  every split contract test pins the post-reshape spellings.

## Consequences

**Positive:** a discoverable two-level surface; the split plan's domain
seams map 1:1 onto namespaces (pod + runtime = the onboard allowlist;
chart + build = the heavy host side; ship + peer = the thin
verify-and-transport layer both sides need); `pool` is ADR-0040's own
vocabulary, and the trust flatten removes the only three-level surprise
before the tracer pins spellings.

**Negative:** the hot path (`nau build` → `nau build snap`) rewrites muscle
memory, docs, and CI invocations; hidden aliases must be maintained for the
window; completion output changes for every shell.

**Rejected names** (one-line reasons, so they stay rejected):
`helm` (Helm, the k8s package manager), `cargo` (Rust's own — doubly fatal
in a Rust project), `node` (Node.js; also names the local instance, not the
far one), `harbor` (CNCF Harbor), `manifest` (the project already has image
manifests, job manifests, and signed store manifests), `port` (self-collides
with `nau://host:port`), `fleet` (Rancher Fleet; JetBrains Fleet), `quay`
(Quay.io), `jetty` (Java Jetty).

**Onboard binary name:** the slim device artifact's cargo `[[bin]]` target
is `nau-mothership` — the glossary's own term (a pod is "the small nau
served by the system mothership"). The INSTALLED filename is immutable
`/usr/bin/nau` (the staged-path and ExecStart pins stand); a
`nau-mothership` debug hardlink is permitted for log attribution.
Ratified in ADR-0050.

## References

- Binary-split council plan and tickets #312–#320 (the immutability
  invariant this ADR supersedes and re-pins)
- ADR-0010 (eval containment), ADR-0033 (peer sharing), ADR-0040
  (distributed build workers — the `pool` vocabulary and the prior ruling
  that `farm` stays the pod bin farm), and the worker-discovery ruling in
  the isolation module
- ADR-0047 precedent for ratified-decision-before-machinery status
