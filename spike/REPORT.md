# ADR-0009 Nickel embed spike — report

**Date:** 2026-08-30
**Scope:** standalone crate at `spike/` (own `Cargo.toml`, own lockfile; root untouched, nothing committed).
**Verdict up front: all six Decision-8 gates PASS. Recommendation: proceed toward `Accepted`.**

Run everything with:

```bash
cd spike && cargo run --release -- all   # subcommands: bakeoff contracts parity adversarial imports latency
```

---

## 1. Crate bake-off (Decision 1) — **CHOSEN: `nickel-lang-core` 0.18.0, pinned `=0.18.0`**

Both candidates were added, compiled and exercised (both are present in `spike/Cargo.toml`; they
coexist — `nickel-lang` is a thin stable wrapper over `nickel-lang-core` of the same workspace).

| Capability needed by shoot | `nickel-lang` 2.2.0 (stable) | `nickel-lang-core` 0.18.0 |
|---|---|---|
| Eval a source string | ✅ `Context::eval_deep` (verified at runtime) | ✅ `ProgramBuilder::…build::<CacheImpl>()` + `eval_full_for_export` |
| serde extraction | ✅ `Expr::to_serde::<T>()` (verified: `Point { x: 1.5, name: "probe" }`) | ✅ `serde_json::Value::deserialize(NickelValue)` (`NickelValue: serde::Deserializer`) |
| JSON diagnostics | ✅ `Error::format(&mut buf, ErrorFormat::Json)` (verified, parses as JSON) | ✅ `error::report` module — but see gotcha (b) below |
| Host data / host functions | ❌ **not exposed** (no `add_source`, no `extend_env`, no AST access) | ✅ `ProgramBuilder::add_source_string` + `not_exported` host-owned inputs |
| Custom import resolution | ❌ only `with_added_import_paths` (filesystem search) | ✅ `%inmem_src%:` in-memory import channel (`cache::IN_MEMORY_SOURCE_PATH_PREFIX`) |
| AST-level access (Decision 6) | ❌ | ✅ `program.parse()` / `nickel_lang_parser::traverse` (available; not needed — see §5) |

The stable crate is genuinely nice for the "three calls" MVP the comparison doc sketched —
`Context::new() / eval_deep() / to_serde()` all compile and run exactly as documented there.
But the doc's low-level sketch (`VmContext::with_extend_env(vec![...])`,
`nickel_value_from_rust_fn`) is **verified inaccurate in its exact form**: `with_extend_env` does
exist on `VmContext`, but there is **no public API in either crate to register a Rust function as
a Nickel-callable callback** (no custom primops; `ForeignId` is a bare `u64`). Host involvement is
data-in and data-out around eval.

**Why core wins:** everything the security gates need (in-memory imports, host-owned index data,
pre-eval source access) is only public in `nickel-lang-core`. Version pinned `=0.18.0` in
`spike/Cargo.toml`; lockfile records `nickel-lang-core 0.18.0` + `nickel-lang 2.2.0`.

---

## 2. Gate results (Decision 8) — measured, release build

| Gate | Result | Measured evidence |
|---|---|---|
| Adversarial: infinite thunk | **PASS** | contained in **26 ms**; Nickel's blackhole detection self-aborts (`infinite recursion` diagnostic) — the subprocess was never even needed for this case, matching Decision 5's "blackholing covers syntactic let-cycles" |
| Adversarial: deep recursion | **PASS** | generated unbounded recursion (`f f 100000000` self-application idiom): VM heap grew to **466 MB RSS**, died at **exit 101** (alloc failure) at **785 ms**, well under `RLIMIT_AS=512MB` wall |
| Adversarial: huge literal | **PASS** | exponential string doubling (32 lines of source → 2^32 bytes of eval): **SIGABRT at 959 ms**, RSS peak 506 MB — allocation failure at the AS cap |
| Adversarial: contract violation | **PASS** | contained in 26 ms, structured JSON diagnostic returned |
| — host unaffected | **PASS** | parent served every case and printed the summary line after the suite |
| Golden parity (3 packages) | **PASS** | `hello`, `jq` (require+merge composition), `system-base` (pin/merge/index): **0 field-level diffs** Lua-vs-Nickel through the subprocess IPC path |
| Latency `shoot check` | **PASS** | median **51 ms** wall including subprocess spawn+IPC (eval-only 24.6 ms). Debug build: 101 ms (would FAIL — release is the honest production configuration). In-process median 9.2 ms; per-eval isolation overhead ≈ 42 ms, inside the Decision-5 fallback budget |
| Imports | **PASS** | `import "lib.ncl"` + `index()` resolved **only** through the IPC channel (per-resolution: 0.03–0.04 ms warm, 2.5 ms cold). Direct imports (`/etc/passwd`, existing-file canary, `../` traversal) → rewritten to unseeded `%inmem_src%:` names → **rejected with spanned diagnostics; the raw path never reaches the filesystem** (evidence: error text contains `%inmem_src%:/etc/passwd`, not `/etc/passwd`) |
| Diagnostics | **PASS** | JSON diagnostics captured from the pinned crate, mapped to a schema (`{severity, message, span{byte/line/col}, expected, actual, suggestion}`) and serde-validated; `expected`/`actual` are real source snippets (`expected="String"`, `actual="42"`) |
| Crate | **PASS** | `nickel-lang-core` pinned `=0.18.0`; API surface compile-proven and exercised (§3) |

**20/20 checks PASS, 0 FAIL** (`cargo run --release -- all` prints each individually).

IPC protocol (Decision 5 deliverable): newline-delimited JSON over the child's stdio —
child → `{"req":"Source","name":"lib.ncl"}` / `{"req":"Index"}`; parent answers
`{"ok":true,"content":…}` after applying the import-rewrite policy. All eval inputs (prelude,
index, definition, lib) cross the boundary; the child opens no project files (its cwd is an empty
temp dir).

---

## 3. The API surface that actually worked (real code, not sketch)

### Evaluation + serde extraction (Decision 3)

```rust
use nickel_lang_core::{eval::cache::CacheImpl, program::ProgramBuilder};

let mut program = ProgramBuilder::new()
    .add_source_string(prelude_src, "prelude.ncl")            // host wrap, in-memory seed
    .add_source_string(wrap_definition(pkg_src), "jq.ncl")    // main program
    .build::<CacheImpl>()?;
let nv = program.eval_full_for_export()?;                     // drops `not_exported` fields
let value: serde_json::Value = serde_json::Value::deserialize(nv)?;  // NickelValue: Deserializer
```

The host wrap (`wrap_definition`) — the Decision-2 enforcement point:

```rust
format!("let {{ {PRELUDE_BINDINGS}, .. }} = import \"%inmem_src%:prelude.ncl\" in\n{pkg_src}")
// PRELUDE_BINDINGS = "snap, merge, pin, index, app, image"
```

### JSON diagnostics

```rust
use nickel_lang_core::error::{report::DiagnosticsWrapper, IntoDiagnostics};

let diagnostics = err.into_diagnostics(&mut files);
let json = serde_json::to_string(&DiagnosticsWrapper::from(diagnostics))?;
```

⚠️ **Gotcha verified in 0.18.0:** `report::report_with(w, files, err, ErrorFormat::Json)` **ignores
the writer and dumps to stderr** for every format except `Text`. Serialize `DiagnosticsWrapper`
yourself (as above). Labels serialize as `range:{start,end}` (byte offsets) + `file_id`; line/col
via `files.location(file_id, byte_idx)`; `FileId` has no public constructor — round-trip it
through its serde impl.

### Import interception (Decision 5/7) — the filesystem firewall

```rust
// parent-side, before any source crosses the boundary:
src.replace_all(/(import\s+)"((?:[^"\\]|\\.)*)"/, …"%inmem_src%:$2"…)
```

Every `import "<path>"` becomes `import "%inmem_src%:<path>"`. The resolver
(`SourceCache::get_or_add_file`) checks the in-memory table first and **only** falls back to real
file I/O for non-matching paths — and since the rewritten path *is* the inmem name, a direct
author import can never touch the filesystem: unseeded names fail with
`import of %inmem_src%:/etc/passwd failed: could not find import`. The parent (store) seeds only
store-owned names; `prelude.ncl`/`index-data` are host material, `lib.ncl` is store content.
Author syntax stays clean (`import "lib.ncl"`, `import "shoot-prelude"` as a host alias).

### Host functions (Decision 7)

No Rust-callback registration exists in either crate (the doc's `nickel_value_from_rust_fn` is
fiction at 0.18.0/2.2.0). What works, and satisfies the boundary rule:

- **`index()`** — the host flattens `package-index.json` to a record and splices it into the
  prelude as `index_data | not_exported = {...}`; prelude `index = fun n => insert "name" n
  index_data."%{n}"` (with a custom contract for the not-found blame). In the subprocess the index
  crosses the IPC pipe per-request. Lazy per-name resolution would need an upstream hook; batched
  resolution measured at 0.03 ms.
- **All other DSL functions are pure Nickel** in the prelude (contracts + shims), so no host
  callbacks are actually required by the three golden packages.

---

## 4. Golden parity notes

- All three packages extract byte-identical JSON (modulo numeric form, below) through the
  subprocess path.
- `description` strings: Lua `[[…]]` skips the first newline only; the `.ncl` ports use explicit
  escapes to reproduce exact bytes. Worth an authoring-guideline note in production.
- **Numeric seam finding:** Nickel numbers deserialize as floats (`1` → `1.0` in JSON). Numerically
  equal, and the parity diff normalizes via f64 comparison — but `SnapMeta` extraction must coerce
  explicitly (e.g. `revision` fields).
- Parity ran through the full production shape: subprocess + IPC imports + IPC index.

## 5. Spike-found gotchas (each cost a debugging round; all are real API behavior)

1. **`merge` operands are independent worlds.** The synthesized multi-input
   `merge (import a) (import b)` evaluates each import separately — fields of one are *unbound*
   inside the other. The wrap must bind the prelude lexically (`let { snap, … } = import …`).
2. **`{ name = name }` is a blackhole.** Record fields are in recursive scope, so a field
   definition shadows an outer parameter of the same name. Prelude parameters are now
   `pin_name`/`index_name`.
3. **`%record/insert%` is add-only** ("tried to extend a record with the field a, but it already
   exists") — remove-then-insert for overwrite; hence the prelude's custom `merge`.
4. **`report_with(.., ErrorFormat::Json)` writes to stderr**, not the given writer.
5. **`let` is non-recursive** — adversarial recursion needs the self-application idiom.
6. **Destructuring patterns are closed** without `..`.
7. **Nickel self-detects thunk cycles** (`{ a = b, b = a }` → `infinite recursion` diagnostic in
   26 ms): blackholing is real, as Decision 5 anticipated; process bounding is still mandatory for
   generated recursion/memory growth (proven by the two cases that only die at the rlimit).

---

## 6. Recommendation

**Proceed toward `Accepted`** — every Decision-8 gate passes on the pinned crate, and the two
mechanisms the ADR flagged as risky (contract wrap with spanned diagnostics; import interception
with cross-boundary proof) work with the *unmodified* public API of `nickel-lang-core 0.18.0`.

Conditions/notes for the migration plan (none are tripwires):

1. **Pin `nickel-lang-core =0.18.0`** and treat 0.x bumps as release-boundary work (per Decision 1).
2. **Budget `shoot check` as release-build only** (~50 ms incl. isolation; ~9 ms without). If the
   100 ms budget ever gets tight, Decision 5's persistent-worker fallback has headroom (isolation
   overhead ≈ 42 ms/eval is the only cost).
3. **Host-function shape:** ADR-0007-era expectations of Rust callbacks inside eval are not
   implementable on the public API; `index()` as host-materialized data crossing the boundary is
   the working pattern (arguably stronger: the child provably gets no filesystem or store access).
4. **Import rewrite is regex-based in the spike** (safe for the DSL grammar — imports are literal
   strings — but production should move it to the AST pass via `nickel_lang_parser::traverse`,
   which is already a public dependency path).
5. Keep the adversarial sources in `spike/src/gates.rs` as the permanent fuzz corpus seed
   (per Decision 8).
