# Build execution model: packages parallel, parts serial; stage-merge is the gate

## Status

Accepted (2026-09-09). Recorded by a council review of the gap analysis
(2026-09-09). Extends ADR-0004 (build sandbox), ADR-0014 (plugin registry),
and ADR-0018 (build_deps). Naming invariant per ADR-0013 applies.

## Context

The gap analysis flagged "inter-part parallelism" as a v1 deferral
(`src/snap.rs`: *"Run named parts sequentially in dependency order (v1 — no
parallelism)"*). The council corrected two facts about that framing:

1. **The named blocker was wrong.** "PATH is process-global" is
   `#[cfg(test)]`-scoped (the test harness serializes E2E builds that stub
   host tools). The real build path already computes `path_dirs` locally and
   hands them to the child via `env_clear` + explicit `PATH`; it is
   parallel-safe with respect to PATH.
2. **The hard blocker is semantic, not environmental.** Parts *share `$STAGE`
   and the whole build tree by design* — the integration point. Two parts
   writing the same stage path race. Resolving that is a stage-merge semantics
   decision, not a thread pool.

Separately, inter-**package** parallelism is a different and cheaper win: 191
`pkgs/` entries, a Kahn topological sort already exists, and each package
build is isolated in its own tempdir.

## Decision

1. **Parts stay serial in v1.** Inter-part parallelism is explicitly **not**
   enabled and is **gated behind a stage-merge ADR**. The shared `$STAGE`
   contract must first define: whether parts get private stage subtrees merged
   in a fixed order, or a declared merge policy per stage path, or something
   else. Until that ADR exists, no inter-part threading.
2. **Process-global state migrates into an explicit `BuildContext`.** The
   blocker for *any* parallelism is the process-global surface: `set_var`
   of `SOURCE_DATE_EPOCH` and `SHUTTLE_ARCH`, the `output` mode statics, and
   the `pkg_source` global inputs. These move into a context object threaded
   through the build before parallelism is attempted.
3. **Inter-package parallelism is the first target.** Once `BuildContext`
   lands, build ready nodes of the existing package topological order
   concurrently (thread-per-ready-node or a bounded pool). Each package build
   keeps its own tempdir stage; there is no shared-stage contract to settle at
   the package level. Tracked as its own ticket.
4. **No remote build farm, no remote cache, no substituters.** Unchanged from
   ADR-0011's daemon law and the single-machine trust domain. Parallelism is
   local only.

## Alternatives considered

- **Enable inter-part parallelism now with a lock per stage path.** Rejected:
  a lock is a merge policy by accident; the shared-stage contract must be
  designed, not emergent. Silent ordering dependence is worse than
  sequential builds.
- **Skip inter-package and go straight to inter-part.** Rejected: inter-part
  is blocked on the stage-merge ADR, while inter-package is unblocked modulo
  `BuildContext` and covers the larger workload.
- **Adopt a remote/execution cache to get parallelism "for free".** Rejected:
  out of scope (daemon law, single-machine trust domain); remote caches are a
  recorded non-adoption.

## Consequences

**Positive**: the build-execution boundary is now explicit; the parallelism
work has a defined prerequisite (`BuildContext`) and a defined gate
(stage-merge ADR); the wrong blocker ("PATH") is corrected on the record so
future work does not chase it.

**Negative**: parts remain serial until the stage-merge ADR is written and
accepted — a correctness-over-speed choice, deliberate. Inter-package
parallelism is deferred behind `BuildContext`, so no speedup lands in this
milestone.

**Neutral**: craft-parts is also sequential across parts, so inter-part
parallelism remains a differentiation opportunity rather than parity debt.
