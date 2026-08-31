# Package-definition language: Nickel (typed config language, replacing data-description Lua)

## Status

Proposed. Ratification is gated on the spike acceptance criteria in §Decision 8 — mark `Accepted` only after every gate passes; a failed gate triggers the Luau fallback tripwire (§Decision 9). Supersedes ADR-0002.

## Context

shoot's package definitions were a data-description Lua DSL (ADR-0002): `snap()` validates its argument table and returns it; Rust extracts pre-validated fields via `SnapMeta::from_lua_table`. That design assumed human authors and first-party files.

The operating premise changed: definitions will be written primarily by LLMs, released continuously, with minimal human review, and will arrive from outside the repository (user-submitted packages, agent-authored third-party definitions). Under that threat model, AI-authored definitions are untrusted input to the **eval step**, which runs in the host process *before* the bubblewrap sandbox ever engages. The runtime guarantees (sandbox, content-addressed store, input locking) protect builds — they do not protect evaluation.

The current Lua architecture fails that premise in three ways:

1. **Sandbox is a denylist over a C API.** mlua's sandboxing works by denying stdlib symbols; omissions are escapes, and omissions are what unreviewed codegen produces.
2. **No type enforcement at the boundary.** Lua has no static types; `snap()` checks fields ad hoc, and a malformed definition surfaces as a Lua-level error — or silently: `src/lua.rs` drops broken outputs at three call sites (`:70`, `:121`, `:201` in `evaluate_images`). These bugs are to be fixed or explicitly accepted before migration starts; they strengthen the removal case either way.
3. **The AI feedback loop is unpowered.** The decisive property for AI-authored code is a cheap, deterministic post-generation validation gate with machine-readable, spanned diagnostics. Lua offers none natively.

A re-evaluation was run from scratch (research: `docs/nix-language-design-lessons.md`, `docs/agents/research-scripting-languages.md`, `docs/nickel-vs-starlark.md`, `docs/lua-dialects.md`). Two findings framed it: reproducibility is a runtime property, not a language property (20 years of Nix history — the language needs only deterministic, side-effect-free evaluation of definitions); and the AI-age levers are safety-by-construction at eval, typing as the check gate, and structured diagnostics for the generate→check→fix loop.

### Relationship to the cited research

Both research documents concluded, under the *old* premise (human authors, first-party files), that the Lua architecture was consensus-aligned and that laziness and Nickel-style machinery should be avoided (`nix-language-design-lessons.md` §5.3/§7; `research-scripting-languages.md` recommends Starlark). This ADR overturns those conclusions because the premise they rested on is gone: untrusted, machine-authored input moves the safety requirement from the build (where bubblewrap already enforces it) to evaluation (where nothing currently does). The type-boundary reversal follows from the premise shift; the laziness acceptance does not — it is a deliberate trade recorded in §Decision 5.

### Scoring worksheet

Six axes, 1–5 each. Training-corpus familiarity was excluded by decision (the AI-authoring surface is the schema plus the check loop, not the language); ecosystem maturity was excluded on the commitment to build shoot's own linter/LSP tooling.

| Candidate | Declarative | Determinism | Untrusted safety | Rust embed | Validation loop | Static typing | Σ |
|---|---|---|---|---|---|---|---|
| **Nickel** | 5 | 5 | 5 | 4 | 5 | 4 | **28** |
| Starlark | 5 | 5 | 5 | 4 | 4 | 2 | **25** |
| Luau (mlua) | 4 | 4 | 5 | 4 | 4 | 4 | **25** |
| Rhai | 4 | 4 | 4 | 5 | 4 | 2 | 23 |
| Teal | 5 | 4 | 2 | 3 | 2 | 3 | 19 |
| TypeScriptToLua | 3 | 3 | 2 | 2 | 4 | 5 | 19 |
| Lua 5.4 (mlua) | 4 | 3 | 3 | 5 | 2 | 1 | 18 |
| Python (PyO3) | 3 | 1 | 1 | 4 | 4 | 2 | 15 |

A census of further Lua dialects (Titan, Astro, Pluto, Fennel, MoonScript, YueScript, Clue, NattLua, Fuse, Erde, Urn — `docs/lua-dialects.md`) produced nothing above Luau. A custom DSL was rejected: it would require building parser, evaluator, type system, and diagnostics — the components that are precisely the leverage points — and contradicts the Nix-history lesson against owning a language that needs rewriting.

### Honest statement of the deciding margins

- **On untrusted-code safety alone, Starlark is the stronger choice**: eager evaluation, termination by construction, parse-time dialect pinning, and Buck2-scale untrusted-eval precedent. Nickel's safety advantage is confined to "no I/O expressible"; its AST-level construct filtering (§Decision 6) is itself a hand-rolled denylist, one level up.
- **This decision therefore rests on typing and diagnostics**, not on the safety axis: runtime-enforced contracts at the definition, spanned contract-aware failures, JSON diagnostics out of the box, and serde extraction. Luau ties Starlark while preserving the Lua corpus and tooling; it loses on check-time-only typing (erased at runtime) and a C++ toolchain dependency.

## Decision

1. **Adopt Nickel** as the package-definition language, embedded as a library. Crate target: evaluate **`nickel-lang-core` 0.18.0** and **`nickel-lang` 2.2.0** (the stable-interface crate) in the spike and pin one. Note: the `nickel` crate on crates.io is an abandoned web framework — never a candidate. Pin the minor version, record it in the lockfile, and upgrade only deliberately at release boundaries (0.x churn is real for embedders).
2. **Enforce the schema with contracts applied by shoot's prelude.** Definitions are authored untyped; Nickel's static checker is partial and falls back to runtime contracts. Shoot wraps every definition value in a contract that validates the package schema at evaluation — the enforcement point is shoot's wrap, never the author's annotation. The differentiator is **spanned, contract-aware failure reporting** (errors that point at the offending definition), not uniquely-enforced static typing.
3. **Extract via serde.** Define Rust structs mirroring the package schema and convert the evaluated value into `PackageDef`/`SnapMeta` via the crate's serde path. **The extraction API sketch from the head-to-head (`eval_deep(...).to_serde()`) is unverified until compile-tested in the spike** — exact surface differs between `nickel-lang-core` and `nickel-lang`. `SnapMeta` and everything downstream (store, cache, lockfile, image assembly) are unchanged; the extraction seam keeps the swap reversible. Also compile-verify that JSON-formatted diagnostics are reachable from the public API (`ErrorFormat::Json` has been an internal/reexported path at times).
4. **Build the AI loop as `shoot check`:** parse + eval + validate, emitting JSON diagnostics (`{span, expected, actual, suggestion}`) for agent feedback. Target <100ms per check **including the isolation overhead from (5)** — measured, not assumed, in the spike. Diagnostic output is an injection channel into agent contexts: cap message sizes and treat diagnostic text as data, never instructions.
5. **Bound evaluation with process isolation — this is the only real termination bound.** Cyclic thunks (`{ a = b, b = a }`) diverge with no loop construct; Nickel has no public resource-limit API, and a watchdog thread cannot safely cancel in-process eval. Therefore: untrusted definitions are evaluated in a **short-lived subprocess** with a wall-clock timeout (default 5s, configurable) and a memory rlimit applied in the child before eval; results or diagnostics cross back as serialized data. **Boundary rule:** the child gets no direct filesystem or store access — every import and `index()` resolution crosses the process boundary as a request to the parent (the IPC protocol is a spike deliverable; its per-resolution latency counts against the check budget). If spawn overhead breaks the latency budget, fall back to a persistent worker pool with crash-restart — still process-isolated, never in-process. Blackholing covers syntactic `let`-cycles only, not generated recursion or memory growth — it is never relied on as a bound.
6. **Pin the dialect by AST filtering** (reject non-declarative constructs after parse). This is **dialect pinning only** — a configuration statement about what the DSL accepts. It is not a termination or safety mechanism (see 5). File the upstream dialect-configuration feature request before the spike; the answer may change this decision point.
7. **Keep host functions for resolution, and harden them.** `index()` and input resolution remain Rust callbacks — they are file-I/O-capable surfaces exposed to untrusted eval and must be bounded (path traversal is the known risk). Imports resolve through the lockfile-controlled store resolver, never the filesystem at large; the spike must prove import interception is achievable (Nickel's import resolution is plain file I/O).
8. **Spike acceptance criteria — all gates must pass to mark this ADR `Accepted`:**
   - Adversarial suite: infinite thunk, deep recursion, huge literal, contract violation — each contained by the subprocess bounds (killed < 5s, memory under rlimit), host unaffected.
   - Golden-output parity: the three spike packages (`hello`, `jq`, `system-base`) extract identically to the Lua path.
   - Latency: `shoot check` <100ms demonstrated, subprocess overhead included.
   - Imports: resolvable **only** through the store-backed resolver; direct filesystem imports rejected. **Cross-boundary proof:** at least one import and one `index()` call resolved through the subprocess boundary via the IPC path from §Decision 5, with per-resolution latency measured against the check budget.
   - Diagnostics: JSON shape validated against a schema; `ErrorFormat::Json` (or equivalent) confirmed reachable from the pinned crate.
   - Crate: embed target chosen between `nickel-lang-core`/`nickel-lang`, version pinned, API surface compile-proven.
   Keep the adversarial suite as a permanent fuzz corpus.
9. **Fallback tripwire:** any failed gate, or spike-found blocks that make contract wrapping or import interception infeasible, triggers the **Luau path** (mlua + `luau` feature, vendored build, `--!strict` checker as library, Rust tooling stack: full-moon/selene/StyLua). Git-tag the pre-migration state; keep `from_lua_table` compilable until the migration gate passes.
10. **Runtime work is unchanged and proceeds regardless** (language-independent): input lockfile pinning revisions (CRITICAL gap), full-input content hashing, bubblewrap sandbox.

### Migration

1. Spike per §Decision 8 (three packages: `hello`; `jq` — exercises the library layer; `system-base` — exercises `merge`/`pin`/`index`).
2. Re-express `src/dsl/init.lua` — the DSL prelude (`snap()`, `merge()`, `pin()`, `index()`) — as Nickel contracts + stdlib functions. **This is the largest single work item** and precedes any definition porting.
3. Port `pkgs/lib/` (`cli`, `daemon`, `desktop`): these are parameterized constructors with overrides-merging — a real port to Nickel functions with merge priorities, **not a codemod**.
4. Codemod the 112 leaf definitions (data literals map directly; `merge()` maps to Nickel merge).
5. **Dual-eval consistency gate:** evaluate all 112 definitions through both Lua and Nickel paths and diff extracted `SnapMeta`. The gate must pass **before** deleting mlua; `from_lua_table` stays compilable until then.

### Alternatives considered

- **Starlark** (`starlark-rust`, 25): the safety pick — eager, termination by construction, parse-time dialect pinning, Buck2/Aspect production precedent. Rejected as primary because the DSL surface is dynamically typed (the schema gate stays host-side), value extraction is manual field-by-field, and diagnostics must be built from parse errors. Revisit if definitions ever need real scripting.
- **Luau via mlua** (25): designated fallback (§Decision 9). Smallest migration, sandboxing designed for untrusted scripts, `--!strict` gradual typing, first-class Rust tooling stack. Loses on check-time-only typing (erased at runtime — no boundary enforcement) and a vendored C++ toolchain dependency.
- **Rhai** (23): pure Rust, safe defaults — under-powered for composition, no static typing.
- **Teal / TypeScriptToLua** (19): check-time typing behind external toolchain binaries (`tl`, Node.js); no runtime enforcement.
- **Python (PyO3)** (15): unsandboxable for untrusted code.
- **Custom DSL** (25 nominal): rejected — parser, evaluator, type system, and diagnostics would all be self-built; those are the leverage points, and the Nix-history lesson warns against owning a language that needs rewriting.
- **Lua 5.4 via mlua** (18, incumbent): the denylist sandbox, absent type gate, and the three silent-drop call sites are the reasons for this ADR. (The earlier "broken build" argument is retracted: `mlua 0.10` with `features = ["lua54"]` lacking `vendored` is an environment issue fixable with one flag.)

## Consequences

### Positive

- Schema violations fail at the definition with contract-aware, spanned, machine-readable errors — the AI validation loop gets its gate from the language layer, with shoot's contract wrap as the enforcement point.
- Serde-based extraction replaces field-by-field table walking; `SnapMeta` and everything downstream stay untouched.
- JSON diagnostics exist at the source; `shoot check` becomes thin.
- First-class merging (with defaults and priorities) replaces the `merge()` shim.
- Pure Rust, no C FFI — eliminates the mlua-sys/pkg-config dependency class entirely.
- No I/O expressible in the language; evaluation is deterministic and subprocess-bounded.

### Negative

- **Lazy-by-default evaluation is accepted deliberately**: no typed alternative is eager (this reverses the Nix-history guidance, which was written under the trusted-author premise); it is mitigated by `eval_deep` + subprocess bounding, at the cost of a worker-process architecture the Lua path did not need.
- No dialect-pinning API upstream — AST filtering is a stopgap we maintain until the feature request lands.
- Nickel's ecosystem and community are small; the AI tooling layer (linter, LSP extensions, editor integration) is ours to build, on top of NLS as the fork base.
- The 112 existing definitions and their authors must move from Lua to `.ncl` syntax; the prelude and library layer require real ports, not mechanical translation.

### Neutral

- LLM corpus familiarity was excluded from the decision by design; the AI-authoring surface is the schema (as contracts + generated reference docs) plus the `shoot check` loop, which is language-independent.
- Migration is gated, reversible, and touches every package definition; the spike gates it and the consistency gate proves it.
- Organist (Nickel's Nix-tooling embed) is Tweag-internal — treated as a design reference, not independent validation.
