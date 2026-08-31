# Language Design Lessons from the Nix/Guix Family

**Date:** 2026-08-29  
**Status:** Research report — informs shuttle's Lua DSL evolution decisions  
**Sources:** Nix manual, Lix project, Nickel blog/docs, Starlark spec, Dhall design docs, Pkl docs, Guix papers, arXiv literature review (Zwinger 2026)

---

## 1. Executive Summary

Twenty years of Nix language design reveal a clear pattern: **reproducibility is a runtime property, not a language property.** Nix's strict functional expression language does not inherently produce reproducible builds — the daemon, content-addressed store, fixed-output derivations, and source filtering do. The language is merely a string-context bridge between human intent and the store.

This report surveys Nix, Lix, Tvix, Nickel, Starlark, CUE, Dhall, Pkl, and Guix/Guile to extract what a package manager's configuration language should borrow and what it should avoid. The core finding for shuttle: **Lua's simplicity is an asset, not a liability**, provided shuttle enforces the right runtime constraints (sandboxing, content hashing, input locking) rather than trying to make the language itself guarantee reproducibility.

---

## 2. The Nix Expression Language: What Went Wrong

### 2.1 Dynamic Typing Without Escape Hatches

Nix is dynamically typed with no gradual typing path. Type errors surface at evaluation time deep in attribute chains, producing inscrutable error messages. The community has documented this extensively (CuBeRJAN/nix-problems, Zwinger 2026).

**Lesson for shuttle:** Lua is also dynamically typed, but shuttle's DSL is data-description (ADR-0002: `snap()` validates its argument table and returns it unchanged). The Rust side (`SnapMeta::from_lua_table`) provides the type boundary. This is the right architecture — don't add a type system to Lua; keep the type boundary at the Rust Lua-table extraction layer.

### 2.2 Laziness as a Footgun

Nix uses lazy evaluation by default. This enables elegant infinite structures but creates:
- Incomplete attribute errors that are hard to trace back to the offending expression
- Memory leaks from thunks that hold references to large data structures
- Debugging difficulty — you can't step through evaluation order

Tvix (Google/TVL's Rust rewrite) explicitly dropped lazy trees from CppNix's implementation. Lix has also deferred lazy trees and plans a "functionally equivalent replacement."

**Lesson for shuttle:** Lua's eager evaluation is the right default for a build DSL. Build configurations should be evaluated once, completely, and predictably. Lazy evaluation adds complexity without benefit for data-description languages.

### 2.3 The `with` Scoping Problem

Nix's `with` attribute set destructuring introduces names into scope without explicit binding, creating name shadowing and making it impossible to determine where a name came from by reading the code.

**Lesson for shuttle:** Lua's `local` scoping and `require()` module system are already clean. Don't introduce `with`-like shortcuts that pollute scope.

### 2.4 Evaluation Performance

Nix evaluation is notoriously slow for large expressions (Nixpkgs is ~80K packages). The evaluator rewrites (Tvix, Lix) have made incremental progress: Lix reports 8-20% faster than CppNix 2.18. Tvix targets a complete Rust rewrite with incremental evaluation.

Nickel has seen ~10x performance improvement since 1.0 through a bytecode interpreter and other optimizations.

**Lesson for shuttle:** Lua is already fast (LuaJIT is among the fastest scripting runtimes). mlua provides Rust-side integration. shuttle's DSL is small (a few hundred lines of Lua at most), so eval performance is a non-issue. Don't optimize for scale you don't have.

### 2.5 No Standard Library Versioning

Nixpkgs grows ~50K lines/month. There's no mechanism to version or freeze the standard library independently of the language. Lix is addressing this with "a robust language versioning system" that allows evolution "without sacrificing backwards-compatibility or correctness."

**Lesson for shuttle:** shuttle's Lua standard library is minimal and defined in `src/dsl/init.lua`. The package inputs system (`github:user/repo[/branch]`) already provides versioning at the input level. No additional mechanism needed.

---

## 3. The Evaluator Crisis: Three Rewrites

### 3.1 Tvix (Rust rewrite by TVL/Google)

- Complete Rust rewrite of the Nix evaluator and store
- Targets incremental evaluation and caching
- Dropped lazy trees from CppNix
- Focuses on correctness and performance

### 3.2 Lix (community fork of CppNix)

- Forked at CppNix 2.18, focused on stability and evolution
- "A language with room to grow" — plans for language versioning
- Deprecating legacy features and misfeatures
- REPL improvements, better error messages
- Plans for gradual Rust introduction

### 3.3 Key Insight

Three independent groups (CppNix upstream, Tvix, Lix) are all wrestling with the same problems: evaluation performance, language evolution, and backward compatibility. This confirms that Nix's language design has fundamental scalability issues that can't be patched incrementally.

**Lesson for shuttle:** Avoid building a language that needs rewriting. Lua is stable, fast, and has decades of embedded use. The DSL layer on top should be small enough to rewrite if needed, but the base language won't need it.

---

## 4. Alternative Approaches

### 4.1 Nickel — The "Nix Language Done Right" (Tweag)

Nickel was explicitly designed as "an evolution of the Nix language." Key design decisions:

- **Gradual typing:** Types are optional, enforced at boundaries between typed and untyped code via contracts
- **Merging:** Records can be merged with associated metadata (documentation, defaults, types, contracts). This is Nickel's answer to NixOS modules
- **Design by contract:** Contracts are runtime assertions inserted at type boundaries
- **Algebraic data types** (since v1.5): enum variants with payloads, pattern matching
- **No string contexts:** Nickel doesn't have Nix's string-context mechanism for tracking provenance — this is handled by the package manager layer instead

**Status (2026):** Stable at 1.0+, active development. 86 contributors, ~5000 commits. Package management added in v1.11. Nix compatibility is experimental. Language server with contract-aware diagnostics.

**Lesson for shuttle:** Nickel's merging model (`mkMerge`, `mkIf`, `mkForce` equivalents) is powerful for modular configuration but requires a custom language. shuttle's Lua `merge()` function is simpler but sufficient for Snap packaging. If shuttle ever needs NixOS-level modularity, Nickel's design is the reference — but Lua + Rust-side module resolution is a viable middle ground.

### 4.2 Guix/Guile — The Two-Tier Approach

Guix uses Guile Scheme (a full general-purpose Lisp) as its configuration language. The 2013 paper "Functional Package Management with Guix" explains the rationale:

- **Two-tier programming:** A domain-specific EDSL (package definitions, system configurations) embedded within a general-purpose language
- **No custom language needed:** Guile provides macros, modules, types, testing — everything a package ecosystem needs
- **Full Lisp power:** Users can write arbitrary code in package definitions
- **Tradeoff:** Less hermetic than Nix. Guix builds are reproducible because of the store, not the language

**Lesson for shuttle:** Lua occupies a similar position to Guile — it's a general-purpose language used as an EDSL host. shuttle should embrace this: let users write normal Lua code (loops, conditionals, functions) and provide DSL functions (`snap()`, `merge()`, `pin()`) as the domain-specific layer. Don't try to make Lua hermetic; make the build sandbox hermetic.

### 4.3 Starlark — Determinism by Restriction

Starlark (Bazel's language) is a restricted Python subset designed for determinism:

- **No recursion, no unbounded loops** — guarantees termination
- **Frozen modules** — imported modules are immutable
- **No side effects** — no file I/O, no network access
- **Deterministic** — same file + same interpreter = same result

**However:** Buck2 (Meta's build system) uses Starlark but **allows recursion**, contradicting the core Starlark constraint. This shows that even the creators of Starlark found the restrictions too limiting in practice.

**Lesson for shuttle:** Determinism constraints in the language are the wrong place to enforce build reproducibility. Buck2's relaxation of Starlark's recursion ban proves the community will work around language restrictions. Enforce determinism at the runtime level (sandbox, content hashing, input locking) rather than the language level.

### 4.4 CUE — Unification-Based Configuration

CUE uses a constraint-based unification model where values are refined through unification:

- **Schema is data:** Types and values are the same concept
- **Closed structs:** Can't add fields to a struct after definition
- **Merging via unification:** Configurations compose by unifying constraints

**Status (2026):** In maintenance mode. The unification model is elegant but the learning curve is steep and the community has not grown as hoped.

**Lesson for shuttle:** CUE's unification model is too complex for package management. The merge semantics should be simple table merging, not constraint unification.

### 4.5 Dhall — Totality by Design

Dhall guarantees that all programs terminate (total language):

- **No general recursion** — functions must be structurally recursive
- **No Text comparison** — forces structured representations
- **No floating-point arithmetic** — avoids imprecision
- **Strongly typed** — promotes "invalid states unrepresentable"

**Status (2026):** Declining adoption. The totality guarantees are too restrictive for practical configuration. The author has stepped back from active development.

**Lesson for shuttle:** Totality guarantees are overkill for a build DSL. Users should be able to write loops and conditionals freely. Termination is guaranteed by the runtime (process timeout), not the language.

### 4.6 Pkl — Apple's Configuration Language

Pkl (Apple, 2024) takes a different approach:

- **Typed schemas** with validation (`Int(this > 1000)`)
- **Code generation** for Java, Kotlin, Swift, Go
- **Multi-format output** (JSON, YAML, property lists)
- **IDE integration** with language server
- **Embeddable** as a library in application code

**Lesson for shuttle:** Pkl's schema-with-validation pattern is interesting but its focus is application configuration, not build systems. The code generation approach (schema → typed classes) is relevant if shuttle ever needs to generate snap.yaml from Lua, but the current approach (Lua → Rust struct → YAML) already achieves this.

---

## 5. Cross-Cutting Analysis: Where Does Reproducibility Come From?

### 5.1 The Central Insight

Nix's reproducibility comes from the **runtime**, not the language:

| Reproducibility Mechanism | Layer | Language Dependency |
|--------------------------|-------|-------------------|
| Content-addressed store (`/nix/store/<hash>-name`) | Runtime | None |
| Fixed-output derivations (network access with hash check) | Runtime | String contexts bridge to store |
| Sandboxed builds (bubblewrap/namespaces) | Runtime | None |
| Source filtering (`.gitignore`-like) | Runtime | None |
| Daemon (serialization of builds) | Runtime | None |
| Input locking (`flake.lock`) | Tooling | None |

The Nix expression language's only contribution to reproducibility is **string contexts** — a mechanism where a string like `"${foo}/bin/bar"` carries provenance information (which derivation produced the path). This is a clever bridge between the language and the store, but it's not what makes builds reproducible.

### 5.2 What This Means for Language Design

A package manager's configuration language does **not** need to be:
- Purely functional (Guix proves this with Guile Scheme)
- Lazily evaluated (Nix's laziness causes more problems than it solves)
- Hermetic (Starlark's restrictions are bypassed by Buck2)
- Total (Dhall's totality is too restrictive)
- Typed (Nickel's gradual typing is nice but not required)

A package manager's configuration language **should** be:
- Easy to read and write (Lua excels here)
- Composable (table merging, modules, `require()`)
- Evaluated deterministically (eager evaluation, no side effects in DSL)
- Fast to evaluate (Lua/LuaJIT is fast)

The reproducibility guarantees should come from:
- Build sandboxing (bubblewrap, already implemented in shuttle)
- Content-addressed caching (SHA-256 keyed, needs full input hashing)
- Input locking (lockfile pinning revisions)
- Source filtering (exclude `.git`, build artifacts)

### 5.3 shuttle's Architecture Is Correct

shuttle's current design aligns with this insight:
- **Lua DSL** = data-description (ADR-0002), not hermetic computation
- **Rust host** = type safety, performance, sandbox management
- **bubblewrap sandbox** = hermetic builds
- **Package inputs** = Nix-style flake inputs (needs lockfile — identified as CRITICAL gap)
- **Binary cache** = SHA-256 keyed (needs full input hashing for correctness)

---

## 6. Comparison Table

| Property | Nix | Nickel | Starlark | Guix/Guile | CUE | Dhall | Pkl | shuttle (Lua) |
|----------|-----|--------|----------|------------|-----|-------|-----|-------------|
| **Type system** | Dynamic, untyped | Gradual (types + contracts) | Dynamic, untyped | Dynamic (Lisp) | Structural (unification) | Strong, static | Strong, typed schemas | Dynamic (Lua) |
| **Evaluation** | Lazy | Lazy (with contract boundaries) | Eager | Eager (Scheme) | Eager | Eager | Eager | Eager |
| **Purity enforcement** | Pure (no I/O in expressions) | Pure by default | Pure (no I/O, no recursion) | Impure (full Scheme) | Pure | Pure (total) | Pure | Pure in DSL, impure host |
| **Termination guarantee** | No (lazy cycles) | No | Yes (no recursion) | No (full Scheme) | No | Yes (structural recursion) | No | No |
| **Determinism** | Language-weak, runtime-strong | Language-weak, runtime-strong | Language-strong | Runtime-strong | Language-strong | Language-strong | Language-strong | Runtime-strong |
| **Merging/composability** | Attribute set overlay | First-class merge with metadata | Dict update | Lisp macros + modules | Unification | Import + let-bindings | Module system | Lua table merge |
| **Error messages** | Poor (improving in Lix) | Good (contract-aware LSP) | Good | Scheme-level | Good | Good | Excellent (IDE + LSP) | Lua stack traces + Rust errors |
| **Eval performance** | Slow (improving) | 10x faster since 1.0 | Fast (frozen) | Fast (Guile) | Moderate | Slow (type-checking) | Fast | Fast (LuaJIT) |
| **Ecosystem size** | Nixpkgs (~100K packages) | Small (experimental) | Bazel ecosystem | GNU ecosystem | Small | Small | Growing (Apple) | Tiny (Snap packages) |
| **Learnability** | Steep (unique language) | Moderate (Nix-like + types) | Easy (Python subset) | Steep (Lisp) | Steep (unification) | Moderate (Haskell-like) | Easy (config-like) | Easy (Lua) |
| **Embeddability** | Standalone | Library (Rust/Python/C/Go) | Library (Go, Rust, Java) | Standalone | Library (Go) | Library (Haskell) | Library (JVM/Swift/Go) | Library (mlua in Rust) |
| **Active development** | Yes (CppNix + Lix + Tvix) | Yes (Tweag) | Yes (Bazel) | Yes (GNU) | Maintenance | Declining | Yes (Apple) | Yes (shuttle) |

---

## 7. Implications for shuttle's Lua DSL

### 7.1 What to Keep

1. **Eager evaluation** — Lua's default. Build configs should be evaluated once, completely, predictably.
2. **Data-description pattern** — `snap()` validates and returns. No hidden mutation. (ADR-0002 is correct.)
3. **Simple table merging** — `merge()` is sufficient. No need for Nickel-style metadata-aware merge.
4. **`require()` module system** — Lua's built-in is fine for sharing snap definitions.
5. **Rust-side type boundary** — `SnapMeta::from_lua_table` is the right place for validation.

### 7.2 What to Add (from other languages' lessons)

1. **Lockfile for inputs** (from Nix flakes) — CRITICAL gap already identified. Pin input revisions with content hashes.
2. **Content-addressed caching** (from Nix store) — Hash by full build inputs, not just source tarball.
3. **Build sandbox enforcement** (from Nix daemon + Starlark purity) — Already implemented via bubblewrap. Keep it.
4. **Schema-like validation** (from Pkl contracts) — Enhanced `snap()` validation with field type checking and defaults. Not a full type system, just better error messages.

### 7.3 What to Avoid

1. **Custom type system** — Don't build Nickel or Dhall into Lua. The Rust boundary handles types.
2. **Lazy evaluation** — Already avoided. Don't introduce it.
3. **Hermeticity at language level** — Don't restrict Lua like Starlark. Restrict the build sandbox instead.
4. **Complex merging semantics** — CUE's unification and Nickel's metadata-aware merge are overkill for Snap packaging.
5. **Totality guarantees** — Dhall proved this is too restrictive. Users need loops and conditionals.

### 7.4 Architecture Validation

shuttle's architecture (Lua DSL + Rust host + bubblewrap sandbox + content-addressed cache) is **aligned with the consensus** of 20 years of package manager language design:

- The language should be simple and familiar (Lua ✓)
- Reproducibility comes from the runtime (sandbox + store ✓)
- Type safety belongs at the host boundary (Rust ✓)
- Composition comes from the language's own features (Lua tables + require ✓)
- The DSL should be small and data-descriptive (snap() validates and returns ✓)

The remaining gaps (lockfile, full input hashing, plugin system) are **runtime/tooling gaps**, not language design gaps. This is the right place for them to be.

---

## 8. Sources

| Source | URL | Key Insight |
|--------|-----|-------------|
| Zwinger 2026 (arXiv:2604.11398) | https://arxiv.org/abs/2604.11398 | Literature review: Nix solves old problems but introduces new ones |
| Nix content-addressing docs | https://nix.dev/manual/nix/stable/store/derivation/outputs/content-address | Reproducibility is a store property, not a language property |
| Lix project | https://lix.systems/about/ | Language versioning, legacy deprecation, community governance |
| Nickel since 1.0 (Tweag) | https://www.tweag.io/blog/2026-02-19-nickel-since-1-0/ | ADTs, pattern matching, 10x perf improvement, package management |
| Nickel manual | https://nickel-lang.org/user-manual/introduction/ | Gradual typing, merging, design by contract |
| Starlark spec | https://github.com/bazelbuild/starlark/blob/master/spec.md | Deterministic subset of Python, no recursion |
| Dhall design choices | https://docs.dhall-lang.org/discussions/Design-choices.html | Totality, no Text comparison, associative operators |
| Pkl documentation | https://pkl-lang.org/index.html | Typed schemas, code generation, multi-format output |
| Guix paper (arXiv:1305.4584) | https://arxiv.org/abs/1305.4584 | Two-tier programming: EDSL within general-purpose language |
| CuBeRJAN/nix-problems | https://github.com/CuBeRJAN/nix-problems | Community-documented Nix language pain points |
