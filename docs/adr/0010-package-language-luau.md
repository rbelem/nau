# Package-definition language: Luau (typed Lua via mlua), superseding the Nickel decision

## Status

Accepted (2026-08-31, owner decision). Supersedes [ADR-0009](0009-package-language-nickel.md), which remains the record of the Nickel evaluation and spike. Project renamed shoot → shuttle.

## Context

ADR-0009 evaluated the package-definition language from scratch for AI-authored, untrusted definitions and accepted Nickel after a spike passed all six gates (`spike/REPORT.md`: `nickel-lang-core =0.18.0`, golden parity 0 diffs, adversarial containment, 51ms median check, IPC-only imports). Luau was the designated fallback (25/30 on the six-axis scoring, tied with Starlark).

The owner has chosen the Luau path. The deciding factors, consistent with the recorded evidence:

1. **Corpus and prelude continuity.** The 112 definitions, `pkgs/lib/` constructors, and the `src/dsl/init.lua` prelude are Lua; Luau keeps them (near-)unchanged. Nickel required a full `.ncl` migration including a from-scratch prelude re-expression — the largest single work item in the ADR-0009 migration plan.
2. **Rust tooling exists today.** full-moon (lossless parser), selene (linter), StyLua (formatter), and mlua's `luau` backend all support Luau first-class — the "we build our own tooling" commitment starts from working foundations instead of a fork of NLS.
3. **Sandboxing designed for untrusted scripts.** Luau ships a reduced stdlib (no `io`, no `os.execute`, no `debug`) as the default build — a smaller denylist surface than Lua 5.4's, though still denylist-class rather than Nickel's nothing-to-express class.
4. **Native Rust callbacks.** `index()` and host functions register directly through mlua — no data-splice workaround.

Accepted trade-offs (from the recorded evidence, `docs/agents/research-scripting-languages.md`):

- **Types are check-time-only.** Luau's `--!strict` analyzer erases types at runtime; enforcement of the package schema happens in Rust at the extraction boundary. The AI gate is the checker + host validation loop, not language-enforced contracts.
- **Vendored C++ toolchain dependency** (`luau0-src`, ~30-60s first build; no system-Lua/pkg-config dependency).
- **Luau's new type solver is still stabilizing** upstream; pin and upgrade deliberately.
- **Standalone `require` needs a custom resolver** (Roblox asset semantics don't apply).

## Decision

1. **Adopt Luau** as the definition language via mlua's `luau` feature (vendored). Definitions stay `.lua` in Luau syntax.
2. **Checker as a library gate.** Run Luau's analyzer programmatically in `--!strict` mode as the first stage of `shoot check`; map its structured errors (locations, messages) to the same JSON diagnostic shape specified in ADR-0009 Decision 8 (`{span, expected, actual, suggestion}`), capped in size, treated as data (injection rule carries over).
3. **Schema enforcement in Rust.** Preserve the ADR-0002 data-description pattern: `snap()` remains a validating table pass-through; all field validation happens at the Rust extraction boundary with named errors. No silent drops (the three `src/lua.rs` call sites are already fixed to warn-and-continue; they now also gain validation reporting).
4. **Eval bounding carried over from ADR-0009 Decision 5, unchanged:** untrusted definitions evaluate in a short-lived subprocess with wall-clock timeout (5s default) and memory rlimit; results and diagnostics cross as serialized data; the child gets no filesystem or store access. First line of defense is Luau's reduced stdlib; process bounds are the real guarantee. Use Luau's VM interrupt hook for cooperative abort inside the budget when available through mlua.
5. **Imports through a custom resolver only.** mlua's Luau `require` is configured with a module resolver backed by the lockfile-controlled store; direct filesystem `require` is rejected. The cross-boundary proof from the ADR-0009 spike gates applies as-is.
6. **`index()` as a native mlua Rust callback**, hardened against path traversal (carried from ADR-0009 AM8).
7. **Runtime work unchanged** (language-independent): input lockfile (shipped, `f2f87e1`), full-input content hashing, bubblewrap sandbox.
8. **Spike gates carry over as migration acceptance criteria**, adapted: adversarial suite (thunk, deep recursion, huge literal, contract violation → containment <5s under rlimits), golden parity (all 112 definitions extract identically Luau-vs-current-Lua-5.4 through the dual-eval gate before the old backend is removed), latency (<100ms incl. subprocess), resolver-only imports, JSON diagnostics schema. Port the adversarial sources from `spike/src/gates.rs` as the fuzz corpus seed.
9. **Archive the Nickel spike** (`spike/`) as research; it is not deleted — the gate harness structure and the IPC/subprocess design (`spike/src/isolate.rs`) are the implementation reference for items 4-5.

### Migration

1. Swap mlua backend `lua54` → `luau` (vendored) behind a feature flag; keep both backends compilable during transition.
2. Verify corpus compatibility (Luau is 5.1-derived; confirm no 5.2+-only syntax in `pkgs/` and the prelude — the dual-eval gate catches any drift).
3. Add the analyzer gate + Rust-side schema validation + JSON diagnostics to `shoot check`.
4. Wire the custom require resolver + subprocess isolation; run the adapted gate suite.
5. Dual-eval consistency gate over all 112 definitions; then remove the `lua54` backend.

### Alternatives

- **Nickel** (`nickel-lang-core =0.18.0`): spike-proven (all gates passed) and the stronger typing story (runtime contracts, spanned failures). Superseded by owner decision in favor of corpus continuity and the existing Rust tooling stack. The spike remains the reference for the subprocess/IPC isolation design.
- **Starlark** (`starlark-rust`): the safety pick (eager, termination by construction); loses on typing and diagnostics-vs-effort. Unchanged from ADR-0009.
- **Lua 5.4 via mlua** (incumbent): the status quo this ADR upgrades — same language family without the analyzer, the reduced stdlib, or the Luau tooling stack.

## Consequences

### Positive

- Zero-syntax-change migration for definitions and prelude; the 112-file corpus, `pkgs/lib/`, and `src/dsl/init.lua` carry over (subject to the parity gate).
- `shoot check` gains a real type gate (`--!strict`) plus Rust-side schema validation with named errors.
- Reduced-stdlib Luau VM shrinks the eval-sandbox denylist surface.
- Native Rust callbacks for `index()`/host functions (no data splicing).
- First-class Rust tooling: full-moon AST for the linter/LSP work, selene, StyLua.
- No system-Lua dependency either way (vendored builds for both backends).

### Negative

- Types are check-time-only; runtime enforcement of the schema is Rust's job, permanently. The "gate by construction" property ADR-0009 bought with Nickel is traded away.
- Vendored C++ toolchain in the build (~30-60s cold compile).
- Luau's type solver is mid-rewrite upstream; expect analyzer behavior changes across pins.
- Standalone `require` configuration is our code (Roblox semantics don't transfer).
- Luau is 5.1-derived: no integer division (`//`), no `goto`, no 5.4 integer subtype — corpus and any new prelude code must stay within the subset (parity gate enforces).

### Neutral

- The threat model, subprocess isolation design, injection rules for diagnostics, and the runtime reproducibility work are unchanged from ADR-0009 — only the language layer swapped.
- Both spikes (Nickel, and this Luau migration) feed the same fuzz corpus.
