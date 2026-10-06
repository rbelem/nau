# Research: Meta Rebalancer for Nau's Farm Placement

**Date:** 2026-10-06
**Status:** Complete — evaluated, not adopted
**Context:** Meta open-sourced Rebalancer, an assignment-problem solver
(blog 2026-09-21, OSDI'24 paper). Question: does it improve how nau places
farm build jobs onto workers?

---

## What Rebalancer Is

- C++ core with a Python DSL (`rebalancer` on PyPI), Apache-2.0, active
  upstream (`facebook/rebalancer`).
- Solves "assign objects to bins under constraints and objectives."
- Two solvers: an optimal MIP path (Xpress, Gurobi, HiGHS) and a parallel
  local search over an expression graph.
- Built for hyperscale. The blog reports P99 solve time of 12 seconds at
  265k objects and 3.2k bins, and roughly 40 million problems solved per
  day at Meta (shard placement, service placement, traffic routing).

## Nau's Assignment Surface

- `crates/nau-pool/src/build_sched.rs` (header, lines 31-41) schedules the
  ready set of the dependency graph across the coordinator's slots and one
  SSH channel per declared worker.
- Placement preference is capability match, then a member already holding
  the node's known dependency closure (a warm store saves a payload ship,
  issues #303 and #309), then ready-set order.
- Scale is small. `MAX_PARALLEL_BUILD_WORKERS` defaults to 3, and
  `tests/build_sched_executors.rs` exercises pool budgets of 6 and 11.

## Verdict: Not a Fit

| Dimension | Rebalancer | Nau's scheduler |
|---|---|---|
| Scale | 265k objects, 3.2k bins | Tens of jobs, 11 slots at most in the tests |
| Problem shape | One static assignment pass | Dynamic ready set under DAG precedence |
| Failure handling | Not modeled | Stop-the-world, re-dispatch on worker loss (ADR-0040 Amendment 1) |
| Dependency cost | C++ core, Python bindings | Rust CLI with offline bwrap-sandboxed builds |
| Payoff at nau's size | None measurable | Greedy with the preference order is near optimal |

The shape mismatch decides it. Nau's hard parts are precedence ordering,
failure semantics, and warm-store placement. Rebalancer models none of
them. Using it would mean snapshotting each ready set as a fresh problem
while still owning all the DAG machinery. Integration would pull a Python
runtime or a C++ dependency into a sandboxed offline build path.

## Worth Stealing

Rebalancer ships Explorer, a debug UI that shows which constraints bind and
why an object landed in one bin and not another. The cheap nau version is a
view over `render_farm_timings` that explains why a job went to a given
worker: payload shipped versus warm hit, capability fit, ready-set order.

## Revisit When

The pool becomes a shared multi-tenant farm with dozens of workers and
capacity dimensions (RAM, disk, arch). Then an assignment formulation earns
its keep. Prefer a small local-search heuristic in Rust or a HiGHS Rust
binding over this library.

## Sources

- Blog: https://engineering.fb.com/2026/09/21/open-source/rebalancer-generic-high-performance-library-assignment-problems/
- Repo: https://github.com/facebook/rebalancer
- Paper: "Optimizing Resource Allocation in Hyperscale Datacenters" (OSDI'24),
  https://www.usenix.org/system/files/osdi24-kumar.pdf
