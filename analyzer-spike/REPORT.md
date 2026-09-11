# Luau analyzer-as-library spike — report

**Date:** 2026-09-01
**Scope:** standalone crate at `analyzer-spike/` (own `Cargo.toml`, own lockfile; root `src/`, `Cargo.toml`, `docs/`, `.planning/`, `spike/` untouched; nothing committed).
**Verdict up front: FEASIBLE.** `--!strict` checking of a definition source runs programmatically from Rust with fully structured results (1-based spans + message), in-process, at **~1.35 ms cold / 30–120 µs warm** — 2 orders of magnitude under the 100 ms `shoot check` budget. Recommendation for the `shoot check` analyzer slot: **link `Luau.Analysis` behind the `cc`-based build proven here** (details and conditions below).

Run everything with:

```bash
cd analyzer-spike
cargo run --release            # cases a/b/c/d/e + latency table
cargo test --release           # 5 tests, incl. case (b) structured-diagnostic assertion
```

---

## 1. The question, answered

| Question | Answer |
|---|---|
| Can Luau's type analyzer run as a library from Rust? | **Yes.** C++ `extern "C"` shim over `Luau::Frontend`, compiled+linked statically via the `cc` crate. |
| Structured results? | **Yes.** `Vec<Diagnostic{begin_line, begin_col, end_line, end_col, message}>`; spans 1-based (end col exclusive, same convention `luau-analyze` prints); message is `Luau::toString(TypeError)` — multi-line but already JSON-escaped cleanly. Parse errors also come back as structured diagnostics ("Expected '}' (to close '{' at line 3), got <eof>" at a span). |
| Cost? | 206 LOC C++ shim + 136 LOC build.rs; 121 C++ TUs (120 upstream + shim); +2 m06 s cold release build; pinned tarball (1.8 MB) vendored in the crate. See §5 for production cost. |

## 2. What got built

```
analyzer-spike/
├── Cargo.toml            # build-deps only: cc (parallel), flate2, tar — no runtime deps
├── build.rs              # extracts tarball → OUT_DIR, parses upstream Sources.cmake,
│                         # compiles Ast+Config+EqSat+Analysis+Compiler+VM (120 .cpp) + shim
├── luau-0.663.tar.gz     # vendored upstream source (single auditable file, 1.8 MB)
├── shim/shuttle_shim.cpp # 206 LOC extern "C" bridge (the only code we own in C++)
└── src/{lib,main}.rs     # safe wrapper (Checker, check_once, Diagnostic) + spike harness
```

**Key deviation from the task's step-1 expectation:** `luau0-src` 0.12.3+luau663 (the crate mlua uses) vendors **only `Ast`, `CodeGen`, `Compiler`, `Custom`, `VM` — no `Luau.Analysis`**. There is no prebuilt crate exposing the analyzer. This spike therefore compiles the analyzer from the upstream `luau-lang/luau` tarball at tag **0.663** (the exact version `luau0-src` 0.12.3 pins), so a future mlua link would be version- and ABI-consistent (same `LUAI_MAXCSTACK`/`LUA_VECTOR_SIZE` defines).

The shim mirrors `CLI/src/Analyze.cpp` (luau-analyze) exactly:

```cpp
// mode has no FrontendOptions field in 0.663 — it flows through ConfigResolver
checker->configResolver.defaultConfig.mode = Mode::Strict;
Frontend frontend(&fileResolver, &configResolver, options);   // retainFullTypeGraphs=false
Luau::registerBuiltinGlobals(frontend, frontend.globals);     // once per checker
Luau::freeze(frontend.globals.globalTypes);
CheckResult cr = frontend.check(moduleName);                  // errors + lint + timeoutHits
```

Two access patterns, both measured: `check_once` (fresh Frontend per check — the subprocess model of ADR-0010 Decision 4) and `Checker::new` + reuse (worker model — Frontend + frozen builtin globals survive across checks).

## 3. Measured results (release build, 12-core linux)

| Case | Result |
|---|---|
| (a) clean typed definition | **0 diagnostics** |
| (b) `snap { name = 42 }` vs `{ name: string, version: string }` | **1 structured diagnostic** at 7:6–7:36: `'{ name: number, … }' could not be converted into '{\| name: string, … \|}' … Property 'name' is not compatible. Type 'number' could not be converted into 'string'` — mapped to `{span, message}` JSON (ADR-0009 Decision-8 shape; `expected`/`actual` ride inside `message`) |
| (b2) same source, non-strict | Same error — correct 0.663 semantics: explicitly annotated parameters are enforced in both modes |
| (d) syntax error | Structured: `4:1-4:0 Expected '}' (to close '{' at line 3), got <eof>` |
| (e1) `require("shuttle-prelude")` + valid definition, **typed prelude seeded as a module** | **0 diagnostics** — require resolution + cross-module type inference work with only `FileResolver::resolveModule` + `readSource` wired |
| (e2) same, but `name = 42` | Caught **through the module boundary**: `could not be converted into 'SnapMeta'` (the exported type alias flows) |
| (c1) `pkgs/h/hello.lua` raw | `11:15 Unknown global 'snap'`, `39:21 Unknown global 'app'` — exactly the unbound-prelude surface |
| (c2) `pkgs/j/jq/init.lua` raw | `Unknown require` (lib not seeded) + `Unknown global 'snap'`, `'merge'` — as predicted, requires need resolution wiring |

**Latency (release, median of n):**

| Path | Cold (fresh Frontend) | Warm (reused Frontend) |
|---|---|---|
| Clean typed definition (10 lines) | **1 349 µs** (n=20) | **30 µs** (n=50) |
| `pkgs/h/hello.lua` (44 lines) | — | 83 µs |
| `pkgs/j/jq/init.lua` (43 lines, require trace) | — | 118 µs |
| Prelude-wired definition (cross-module) | — | 55 µs |

Debug build latencies: cold ~7 ms, warm <0.5 ms — release is the honest production configuration (matches the Nickel spike's finding).

## 4. `require` / prelude: how resolution works, what shuttle must implement

- **Resolution hook:** `FileResolver` gets two calls: `readSource(name)` (load a module's text) and `resolveModule(context, expr)` (map a `require` argument expression to a module name). Both are pure virtual; the shim implements them over an in-memory `HashMap<ModuleName, String>` — the exact seam where shuttle's lockfile-store resolver goes. `ConfigResolver::getConfig(name)` carries the per-module mode (strict) and can later carry lint config.
- **Flow proof (e1/e2):** a seeded typed prelude module + a definition that `require`s it type-checks cleanly, and errors on the definition side carry the prelude's exported types (`SnapMeta`) in messages. No `loadDefinitionFile` needed for the gate; it remains the richer option if typed *globals* (bare `snap`, `merge`, `app` without `require`) are wanted instead — that is how Roblox Studio injects definitions.
- **Unresolved requires** produce `Unknown require: <path>` (or "unsupported path" when the tracer can't resolve the expression) — i.e. the gate fails *closed* on unseeded requires. Good for untrusted definitions.
- **Gotchas found (each cost a debugging round):**
  1. **`--!strict`/`--!nonstrict` hot-comments in the source override the ConfigResolver default** (`Frontend::parse` → `parseMode(hotcomments)`). An AI-authored definition could downgrade the gate with one comment line. Production must strip/reject mode hot-comments in the check stage (also true of `luau-analyze`).
  2. `SourceCode::Type::Script` makes a module **un-requirable** ("Module is not a ModuleScript") — required modules must be typed `Module`.
  3. Rust `&str` → C `const char*` without NUL termination: the shim reads module *names* as C strings, so adjacent string literals got swallowed into the key (lookup silently failed). Fix: names cross as `CString`; sources are length-delimited.
  4. `Analysis/src/TypeFunction.cpp` uses `compileOrThrow`/`BytecodeBuilder`/`lua_*`, which drags `Luau.Compiler` + `Luau.VM` into the link even for pure typechecking (that's why CMake lists them as private deps).
  5. Upstream 0.663 relies on transitive `<cstdint>` inclusions that newer gcc rejects (e.g. `TypedAllocator.cpp` `uintptr_t`); fixed with `-include cstdint` on all TUs — expect to re-check on Luau bumps.
  6. `cc::Build::cargo_metadata(false)` silently suppresses `cargo:rustc-link-lib` emission — copy-pasting it from luau0-src's lib cost one broken-link round-trip.

## 5. Integration cost for production (honest numbers)

| Item | Measured | Notes |
|---|---|---|
| C++ code shuttle would own | **206 LOC shim** | The only first-party C++; everything else is upstream verbatim |
| C++ TUs compiled | **121** (Ast 9, Config 2, EqSat 2, Analysis 64, Compiler 10, VM 33, shim 1) | Source lists read from upstream `Sources.cmake` at build time — no hand-maintained list |
| Cold build delta | **+2 m06 s release / +54 s debug**, one-time, cached in `target/` | vs. mlua+luau0-src baseline (~30–60 s for VM+Compiler per ADR-0010): roughly +3× on cold builds; incremental Rust-only rebuilds stay ~2–5 s. CI is where this lands — cache `target/` or the cc object dir |
| Vendored payload | 1.8 MB tarball in-tree | Expands to ~6 MB in `OUT_DIR` at build time |
| Rust surface | 265 LOC wrapper, zero new runtime deps | `Diagnostic` mapping is trivial; `Checker` is `!Send` (Frontend is single-threaded) — one per subprocess/thread |
| Shim maintenance | Low | Surface = 8 functions over a 4-type concept (checker/seed/check/result). Real risk is upstream API churn, not breadth |
| Luau version pin | **0.663** (`luau0-src 0.12.3+luau663` pins the same VM) | The new type solver was mid-rewrite upstream in this era; pin and upgrade deliberately (ADR-0010 trade-off, unchanged). Bumps need re-verification of: mode-in-ConfigResolver, require tracing flags, `<cstdint>`-style include strictness |
| What's *not* wired yet (deliberately) | Lint (`runLintChecks=false`), cancellation/time limits (`moduleTimeLimitSec`), typed globals via `loadDefinitionFile`, multi-threaded `checkQueuedModules` | All are existing upstream capabilities, none load-bearing for the Decision-2 gate |

## 6. Recommendation for `shoot check`

**Adopt this binding as the Decision-2 "checker as a library gate."** Concretely:

1. Move `analyzer-spike/` → a `shoot-luau-analysis` build-tree crate (same `build.rs` + shim; the harness `main.rs` and vendored tarball stay, the spike tests become the seed of the checker's test suite).
2. Gate shape: `strict` checker + in-memory seeded modules = prelude (typed, as in case e) + `pkgs/lib` templates + the definition; map `Diagnostic` → ADR-0009 Decision-8 JSON (`{span{begin,end}, message}`), cap count/size, treat as data.
3. **Reject mode hot-comments** in the check stage (strip or hard-error) — the checker's strictness is a host decision, not an author flag (§4.1).
4. Requires resolve **only** through the store-backed `FileResolver` — same firewall argument as the Nickel spike's import gate; unseeded names fail closed with spanned diagnostics (proven in case c2).
5. Latency is a non-issue: even the subprocess model (cold 1.35 ms/check) sits far under the 100 ms budget; the warm path (~100 µs) makes a persistent worker optional, not required.
6. Keep the pinned tarball + `Sources.cmake`-driven build; treat Luau bumps as release-boundary work with the §4 gotcha list as the regression checklist.
