# ADR-0051: Crate modularity along domain seams

## Status

Accepted. Ratified 2026-09-30 by the operator: the goal of the original
"split like git" request is **modularity, extensibility, and
maintainability** — explicitly not binary size (ADR-0050 measured that gate
NO-GO). One shipped binary stands; the modularity is delivered as an
internal crate workspace along ADR-0049's domain seams.

## Context

ADR-0050 closed the second-artifact split on measurement. The operator then
re-framed the goal: git's maintainability comes from its internal structure,
not from being many programs — and the same holds here. ADR-0049's domain
namespaces are already the map of the codebase; what they lack is
*enforcement*: modules inside one crate can reach into each other, so the
domain walls are conventions. A cargo workspace turns each domain into a
crate whose boundaries the compiler enforces — illegal dependencies stop
compiling, compile/clippy granularity follows domains, and the dependency
graph documents the architecture.

## Decision

1. **One shipped binary, unchanged.** The root package keeps the `nau` bin,
   the hidden `__*` worker verbs, and the integration tests (the
   `CARGO_BIN_EXE_nau` contract is load-bearing). External `nau-<verb>`
   executables remain third-party extensions (ADR-0049 Decision 5), never
   in-tree artifacts.
2. **The lib splits into domain crates** along ADR-0049's ten domains:
   `nau-core` (shared types, store, sign, manifest IR — the spine),
   `nau-chart`, `nau-build` (the vendored analyzer + `build.rs` live here
   and ONLY here), `nau-image`, `nau-ship`, `nau-peer`, `nau-pod`,
   `nau-runtime`, `nau-trust`, `nau-pool`.
3. **Dependency direction:** domain crates may depend on `nau-core`; never
   sideways; the root package depends on everything. If two domains need to
   talk, the shared vocabulary moves DOWN into `nau-core` — never a
   sideway edge.
4. **Sequencing (the seam-first ruling):** #313 (layering un-inversion) →
   the module seams (#316, #317) → the workspace skeleton, then per-domain
   crate extraction ONE crate per PR, `scripts/gate.sh` green every step.
5. **Gate-day budget:** the workspace lands with a dedicated pass for
   `deny.toml [graph]`, the Cargo.lock CI assertion, `build.rs`
   vendored-tarball paths, and devbox — in that pass, not scattered.

## Consequences

**Positive:** enforced domain walls (illegal imports stop compiling);
per-domain iteration without rebuilding the analyzer or the whole graph;
the dependency graph becomes architecture documentation; future extension
is a new crate, not a new top-level verb.

**Negative:** workspace churn lands once (deny.toml, lockfile assertion,
vendored paths, devbox); 56 modules move over several PRs before the payoff
completes; intermediate states must keep both grammars of ADR-0049 working.

## References

- ADR-0049 (domain namespaces — the map), ADR-0050 (single binary stands)
- #313 (layering un-inversion), #316/#317 (module seams), and the
  binary-split tickets #314–#320 this track supersedes
