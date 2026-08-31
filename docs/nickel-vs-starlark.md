# Nickel vs Starlark for Shoot DSL

Head-to-head comparison across 10 dimensions for embedding a declarative
package-definition DSL in a Rust host with AI tooling.

**Date:** 2026-08-30  
**Libraries:** `nickel-lang-core` 0.18.0 (133K downloads, MIT) vs `starlark` 0.14.2 (4.7M downloads, Apache-2.0)

---

## 1. Crate Reality

| | Nickel | Starlark |
|---|---|---|
| **Crate** | `nickel-lang-core` | `starlark` |
| **Version** | 0.18.0 | 0.14.2 |
| **Downloads** | 133K total | 4.7M total |
| **License** | MIT | Apache-2.0 |
| **Versions** | 23 | 21 |
| **High-level API** | `nickel` crate (stable, wraps core) | `starlark` crate (unified entry) |
| **Ecosystem** | Organist (Nix tooling mgmt), Nickel LSP (NLS) | Buck2 (Meta's build system) |

**Verdict:** Starlark has 35x more downloads and is battle-tested at Meta scale.
Nickel is younger but has a clean core/high-level split and active development.

---

## 2. Embed API

### Nickel

```rust
use nickel_lang::Context;

let mut ctx = Context::new();
let expr = ctx.eval_deep(r#"
  {
    name = "my-snap",
    version = "1.0",
    build = { 
      inputs = ["gcc", "make"],
      script = "make install",
    },
  }
"#)?;
// expr.as_record() → Record with field access
let name = expr.as_record().unwrap()
    .value_by_name("name").unwrap()
    .as_str().unwrap(); // "my-snap"
```

Low-level (core crate):
```rust
use nickel_lang_core::{
    eval::{VirtualMachine, VmContext, cache::CacheImpl},
    eval::value::NickelValue,
    cache::CacheHub,
    identifier::Ident,
};

let mut vm_ctxt = VmContext::new(cache, std::io::sink(), NullReporter {})
    .with_extend_env(vec![
        (Ident::new("host_func"), nickel_value_from_rust_fn),
    ]);
let vm = VirtualMachine::new(&mut vm_ctxt);
let result = vm.eval_full(prepared_value)?;
```

### Starlark

```rust
use starlark::environment::{Globals, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{Dialect, parse};

let dialect = Dialect {
    enable_def: true,
    enable_lambda: true,
    enable_load: true,    // for imports
    ..Dialect::standard()
};

let globals = Globals::standard();
let module = Module::new();

let ast = parse("my.snap", &dialect, source)?;
let mut eval = Evaluator::new(&module);
let value = eval.eval_module(&ast, &globals)?;

// Extract to Rust via starlark values or serde
```

**Verdict:** Nickel's high-level `Context` is simpler (eval + to_serde).
Starlark requires manual dialect/globals/module/eval setup but is more explicit.

---

## 3. Evaluation Control

### Nickel
- **Full evaluation:** `ctx.eval_deep(src)` — evaluates everything
- **Shallow evaluation:** `ctx.eval_shallow(src)` — WHNF only, then step further
- **Record spine:** `prog.eval_record_spine()` — recursive record structure
- **Field targeting:** `prog.field = FieldPath::parse("build.inputs")` — evaluate one field
- **Timeout/step limits:** Not built into the public API; the abstract machine
  has no documented step counter or resource limit mechanism

### Starlark
- **One-shot:** `eval.eval_module(ast, globals)` — full evaluation
- **Dialect flags:** `Dialect` struct controls what constructs are available
  at parse time (def, lambda, load, types, f-strings, while)
- **Timeout:** Buck2 wraps Starlark in a sandbox with resource limits;
  `starlark-rust` itself does not expose a step counter in the public API
- **Environment isolation:** `Globals::standard()` + custom `Module` per eval

**Verdict:** Both lack built-in step/resource limits in the public API. Nickel
has finer-grained evaluation modes (shallow vs deep vs record spine). Starlark's
dialect control is compile-time (parse-time) which is cleaner for pinning.

---

## 4. Value Extraction (NickelValue ↔ Rust types)

### Nickel

```rust
// Via high-level nickel crate
let expr = ctx.eval_deep("{ x = 42, y = \"hello\" }").unwrap();
let x: i64 = expr.as_record().unwrap()
    .value_by_name("x").unwrap().as_i64().unwrap();

// Via serde (powerful)
#[derive(serde::Deserialize)]
struct PackageDef { name: String, version: String }

let pkg: PackageDef = ctx.eval_deep(src)?.to_serde().unwrap();

// Direct value type inspection
expr.is_null()
expr.as_bool() -> Option<bool>
expr.as_str() -> Option<&str>
expr.as_number() -> Option<Number>
expr.as_record() -> Option<Record>
expr.as_array() -> Option<Array>
expr.as_enum_tag() -> Option<&str>
expr.as_enum_variant() -> Option<(&str, Expr)>
```

### Starlark

```rust
use starlark::values::Value;

match value.to_str() {
    Ok(s) => { /* string */ },
    Err(_) => {},
}
match value.is_none() {
    true => { /* null */ },
    _ => {},
}
// Starlark values are not easily convertible to Rust structs
// No built-in serde support
// Manual extraction: value.at(&Value::new("field")) for record access
```

**Verdict:** Nickel wins decisively. `Expr::to_serde()` gives you typed Rust
structs directly from Nickel values. Starlark has no serde integration — you
must manually extract each value with runtime type checks.

---

## 5. Diagnostics / LSP Support

### Nickel

```rust
// Error types with source spans
enum EvalErrorKind {
    MissingFieldDef { .. },
    TypecheckError { .. },
    ImportError { .. },
    InternalError(String),
    // ... 20+ variants
}

// Error reporting to strings, JSON, YAML, TOML
err.format(&mut out, ErrorFormat::Json)?;  // machine-readable
err.format(&mut out, ErrorFormat::AnsiText)?;  // human-readable

// Source position tracking
struct PosTable;  // maps position indices to spans
struct Files;     // codespan-compatible file database

// LSP (NLS)
lsp/nls/ crate — full Language Server Protocol implementation
```

### Starlark

```rust
use starlark::analysis::{EvalMessage, LintMessage, EvalSeverity};

// Pre-defined lints with severity levels
enum EvalSeverity { Warning, Error }

struct LintMessage {
    message: String,
    span: Span,
    severity: EvalSeverity,
}

// Source positions
struct CodeMap;  // maps FileId → source content
struct Pos { line: u32, column: u32 }
struct Span { low: Pos, high: Pos }

// No built-in LSP — Buck2 has its own IDE integration
```

**Verdict:** Nickel has a more mature diagnostics story: `ErrorFormat::Json`
for machine-readable output, codespan integration, and an actual LSP (NLS).
Starlark has good source tracking and lint infrastructure but no LSP.

---

## 6. Dialect Pinning

### Nickel

No `Dialect` struct. Nickel's language features are fixed per version.
To restrict what users can do, you'd need to:
- Parse-then-filter the AST (manual)
- Use `not_exported` fields for internal-only values
- Restrict imports via `import_paths` configuration

### Starlark

```rust
Dialect {
    enable_def: true,        // allow def statements
    enable_lambda: true,     // allow lambda expressions
    enable_load: true,       // allow load() imports
    enable_types: false,     // no type annotations
    enable_f_strings: false, // no f-strings
    enable_while: false,     // no while loops
    ..Dialect::standard()
}
```

Compile-time control over which language constructs exist. A user who
writes `while True: pass` gets a parse error, not a runtime error.

**Verdict:** Starlark wins. The `Dialect` struct is exactly what shoot needs
to enforce "no loops, no FFI, only declarative package definitions" at parse
time. Nickel has no equivalent.

---

## 7. Laziness

### Nickel

- **Lazy by default.** Values are computed on-demand.
- `eval_shallow` returns WHNF with unevaluated sub-terms.
- `eval_deep` forces full evaluation.
- Closure representation: `Term::Closure` wraps a term + environment.
- Good for: merge semantics, optional fields, config composition.

### Starlark

- **Eager evaluation.** All values are computed immediately.
- No lazy/thunk representation.
- Good for: predictable execution, no hidden computation costs.
- Bad for: config composition patterns (every merge forces evaluation).

**Verdict:** For a package-definition DSL where users write declarative
configs that compose via merge, Nickel's laziness is natural. For shoot,
which needs `shoot check` to validate without building, Nickel's lazy
evaluation means you can inspect config structure without triggering
expensive build steps. Starlark's eagerness would require guard patterns.

---

## 8. Real Embedders

### Nickel
- **Organist** (github.com/nickel-lang/organist): Uses Nickel to manage
  Nix-based development tooling. Embeds Nickel as the config language for
  declaring project dependencies, build steps, etc.
- **Nickel CLI**: The reference implementation, embeds core as a library.
- **NLS**: Language server, embeds core for IDE features.

### Starlark
- **Buck2** (Meta): The primary embedder. Billions of lines of Starlark
  executed daily. Full sandbox, caching, parallel execution.
- **Please** (thought-machine): Build system using Starlark.
- **proto Starlark** (various): Custom dialects for specific domains.

**Verdict:** Buck2 proves Starlark can handle massive scale. Organist
is a closer analog to shoot — it embeds Nickel for the same "declarative
config" use case. Both have real production embedders.

---

## 9. Loading / Module Systems

### Nickel

```rust
// Import resolution
ctx.with_added_import_paths(vec![
    "/my/lib/path".into(),
]);

// In Nickel code:
// let lib = import "my-lib.ncl" in ...
// import can resolve relative to the importing file

// Virtual imports (for embedding)
// Via extend_env: host-injected values visible to Nickel code
// Via CacheHub::add_source: add synthetic sources that Nickel can import
```

- `import` resolves files relative to the importing file
- Fallback search paths via `with_added_import_paths`
- Virtual imports via `CacheHub::add_source(SourcePath::Generated(...), ...)`
- No lockfile mechanism — import resolution is straightforward file I/O

### Starlark

```rust
// In Starlark code:
// load("helper.bzl", "some_func", "SOME_CONST")

// Enable in dialect
Dialect { enable_load: true, .. }

// Custom loaders via Evaluator::set_import_resolver(...)
```

- `load()` pulls specific symbols from other `.bzl` files
- No relative import by default — must configure resolver
- Buck2 has a sophisticated import system with cell/module/package hierarchy

**Verdict:** Nickel's import system is simpler and sufficient for shoot.
The `extend_env` mechanism allows host code to inject functions/values
that Nickel code can use without `import`. Starlark's `load()` is more
structured but requires resolver setup.

---

## 10. Killer Test: `shoot check` Validation Loop

The core use case: user writes a Lua-like package definition, shoot
evaluates it, extracts the result, validates it, and returns machine-readable
diagnostics.

### Nickel Implementation

```rust
use nickel_lang::Context;
use serde::Deserialize;

#[derive(Deserialize)]
struct PackageDef {
    name: String,
    version: String,
    build: BuildDef,
}

#[derive(Deserialize)]
struct BuildDef {
    inputs: Vec<String>,
    script: String,
}

fn shoot_check(source: &str) -> Result<PackageDef, Vec<Diagnostic>> {
    let mut ctx = Context::new();
    let result = ctx.eval_deep(source);
    
    match result {
        Ok(expr) => match expr.to_serde::<PackageDef>() {
            Ok(pkg) => Ok(pkg),
            Err(e) => Err(vec![Diagnostic::error(
                &format!("Invalid package definition: {}", e)
            )]),
        },
        Err(e) => {
            let mut diagnostics = Vec::new();
            let mut out = Vec::new();
            e.format(&mut out, ErrorFormat::Json)?;
            // Parse JSON diagnostics
            diagnostics.push(/* ... */);
            Err(diagnostics)
        }
    }
}

// Usage
let result = shoot_check(r#"
  {
    name = "my-snap",
    version = "1.0",
    build = {
      inputs = ["gcc", "make"],
      script = "make install",
    },
  }
"#);
```

**Why it works:**
1. `eval_deep` gives full evaluation
2. `to_serde` converts directly to typed Rust structs — zero manual extraction
3. Error format JSON produces machine-readable diagnostics
4. Laziness means you could add `eval_shallow` for partial validation

### Starlark Implementation

```rust
use starlark::environment::{Globals, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{Dialect, parse};

fn shoot_check(source: &str) -> Result<PackageDef, Vec<Diagnostic>> {
    let dialect = Dialect {
        enable_def: true,
        enable_lambda: false,    // no lambdas in package defs
        enable_load: false,      // no imports
        enable_types: false,
        enable_f_strings: false,
        enable_while: false,
        ..Dialect::standard()
    };
    
    let globals = Globals::standard();
    let module = Module::new();
    
    match parse("shoot.snap", &dialect, source) {
        Ok(ast) => {
            let mut eval = Evaluator::new(&module);
            match eval.eval_module(&ast, &globals) {
                Ok(value) => {
                    // Manual extraction — no serde support
                    let name = value.at(&Value::new("name"))
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| vec![Diagnostic::error("missing 'name'")])?;
                    let version = value.at(&Value::new("version"))
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| vec![Diagnostic::error("missing 'version'")])?;
                    // ... more manual extraction
                    
                    Ok(PackageDef { name, version, /* ... */ })
                }
                Err(e) => Err(vec![Diagnostic::error(&e.to_string())]),
            }
        }
        Err(e) => Err(vec![Diagnostic::error(&e.to_string())]),
    }
}
```

**Why it's harder:**
1. No serde integration — manual extraction for every field
2. No `Dialect` equivalent in Nickel, but Starlark's is cleaner for restriction
3. Error messages are strings, not structured diagnostics
4. Must handle each value type manually

---

## Summary Scorecard

| Dimension | Nickel | Starlark | Winner |
|---|---|---|---|
| 1. Crate Reality | 133K dl, active | 4.7M dl, Buck2 | **Starlark** |
| 2. Embed API | Simple `Context` | Manual setup | **Nickel** |
| 3. Evaluation Control | Shallow/deep/spine | One-shot + dialect | **Nickel** |
| 4. Value Extraction | `to_serde()` | Manual | **Nickel** |
| 5. Diagnostics | JSON/YAML/TOML + LSP | Lint messages | **Nickel** |
| 6. Dialect Pinning | None | `Dialect` struct | **Starlark** |
| 7. Laziness | Lazy by default | Eager | **Nickel** |
| 8. Real Embedders | Organist | Buck2 | **Tie** |
| 9. Loading/Modules | Simple imports | `load()` + resolver | **Nickel** |
| 10. Killer Test | Clean serde path | Manual extraction | **Nickel** |

**Overall: Nickel 7 — Starlark 2 — Tie 1**

---

## Recommendation for Shoot

**Nickel is the better choice.** Here's why:

1. **Serde integration is killer.** The `to_serde()` path means shoot can
   define Rust structs matching the expected package schema and get validated
   conversion for free. With Starlark, you'd build a manual extraction layer
   that's error-prone and tedious to maintain.

2. **Diagnostics are production-ready.** `ErrorFormat::Json` gives you
   machine-readable errors out of the box — exactly what `shoot check` needs.
   Starlark requires parsing error strings.

3. **Laziness matches the DSL.** Package definitions are declarative configs.
   Users write `build.script = "make install"` and shouldn't need to think
   about evaluation order. Nickel's laziness makes this natural.

4. **The high-level `Context` API is simple.** Three calls: `new()`,
   `eval_deep()`, `to_serde()`. That's the entire embedding surface for
   shoot's MVP.

5. **The dialect gap is solvable.** Nickel lacks Starlark's `Dialect` struct,
   but shoot can enforce restrictions via:
   - AST filtering post-parse (reject `while`, `for`, etc.)
   - Restricted imports (don't add dangerous paths to `import_paths`)
   - Contract-based validation (tag the result type)

### What Nickel Needs to Add

To close the gap with Starlark on dialect pinning, Nickel should add:
```rust
Dialect {
    enable_imports: false,
    enable_functions: true,
    enable_merge: true,
    ..Dialect::standard()
}
```

This is a feature request, not a blocker. The current workaround (AST
filtering) is sufficient for shoot's MVP.

### Migration Path

1. **MVP:** Use `nickel` crate with `Context::eval_deep` + `to_serde`
2. **Linter:** Use Nickel's `ErrorFormat::Json` for diagnostics
3. **LSP:** Integrate NLS or build custom using `nickel-lang-core` APIs
4. **Dialect:** Add AST-level restrictions for unsafe constructs
