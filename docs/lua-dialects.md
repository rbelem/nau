# Lua Dialect Census (2024-2026)

Comprehensive survey of Lua dialects, variants, and superset languages for the **shoot** Rust CLI's package-definition DSL decision. Focus: anything beyond already-evaluated candidates (Lua 5.4, LuaJIT, Teal, Luau, Pallene, Ravi, Amulet, Candy, Nelua, TypeScriptToLua).

Date: 2026-08-30.

---

## 1. Live Dialects with Meaningful Activity

### Tier 1: Production-Ready / Significant Community

#### Fennel

| Attribute | Detail |
|-----------|--------|
| **What** | Lisp that compiles to Lua. Full Lua interop, zero-overhead compilation, compile-time macros. |
| **Typing** | None. No type system. `fennel-ls` provides editor diagnostics but no static type checking (by design — types would require whole-program analysis + metatable understanding). |
| **Compile target** | Lua source code. Single `.fnl` file is the entire compiler. |
| **Embed from Rust** | Self-hosted compiler in Lua/Fennel. Could embed via mlua, or shell to `fennel --compile`. No Rust library. |
| **Maintenance** | Very active. Moved off GitHub to SourceHut (`sr.ht/~technomancy/fennel`). 2.6k GitHub stars (mirror). Annual community surveys (2023-2025). In Debian main. |
| **Community** | ~200 survey respondents (2025). Active IRC/Matrix chat. Used in Neovim ecosystem (Fennel plugins), LÖVE2D games, TIC-80 fantasy consoles. |
| **Verdict** | **Wrong shape for shoot.** Lisp syntax is hostile to AI-authored package defs. No types = no validation loop value. Great for game scripting, not declarative config. |

#### MoonScript

| Attribute | Detail |
|-----------|--------|
| **What** | Indentation-based language (CoffeeScript-inspired) that compiles to Lua. |
| **Typing** | None. Dynamic only. |
| **Compile target** | Lua 5.1+ source code. |
| **Embed from Rust** | Self-hosted in MoonScript itself. Parser uses C native module (`pgen`). No Rust library. |
| **Maintenance** | **Stagnant.** Last meaningful release 0.5.0 (2019-ish). GitHub mirror still exists but development has effectively halted. Creator (leafo) focused on other projects. |
| **Community** | Declining. Used historically in Lapis web framework and itch.io. |
| **Verdict** | **Dead for new projects.** YueScript is its successor. No types, no activity. Skip. |

#### YueScript

| Attribute | Detail |
|-----------|--------|
| **What** | MoonScript descendant, modernized codebase. Adds macros, pipe operator, existential operator, export syntax. |
| **Typing** | None. Dynamic only. |
| **Compile target** | Lua 5.1-5.5 source code. `--target` flag selects version. |
| **Embed from Rust** | Written in C++17. Can build as shared library (`yue.so`) or CLI binary. Could call via FFI from Rust. No Rust native binding. |
| **Maintenance** | **Active.** Maintained by IppClub/Dora SSR game engine team. Regular releases. 2025-2026 commits. |
| **Community** | Small but dedicated. Discord community. |
| **Verdict** | **Wrong shape.** No types, syntax is niche. Good for MoonScript migration, not for declarative DSLs. |

#### Pluto

| Attribute | Detail |
|-----------|--------|
| **What** | Lua 5.5 superset. Adds switch/case, ternary, compound operators, `class` keyword, enhanced stdlib. |
| **Typing** | **None.** No static typing, no gradual typing, no type annotations. Pure syntactic sugar over Lua. |
| **Compile target** | Lua 5.5 bytecode (mostly compatible). Some features generate non-standard bytecode. |
| **Embed from Rust** | Written in C (fork of Lua C source). Custom VM. Could embed via C FFI. No Rust bindings. |
| **Maintenance** | **Active.** ~372 GitHub stars. Rebases regularly with upstream Lua 5.5. Active development 2024-2026. |
| **Community** | Small but growing. "Dropped into large communities without breaking scripts." |
| **Verdict** | **Interesting but no types.** Good for Lua ergonomics (switch/case would be nice for package defs) but provides zero validation value. Breaking-change philosophy (new keywords) is a risk. Not above Luau. |

#### Clue

| Attribute | Detail |
|-----------|--------|
| **What** | C/Rust-like syntax that compiles to any Lua version. Brace-delimited blocks, `//` comments, `match` expressions, metatable syntax sugar. |
| **Typing** | **None** currently. Type system planned for v4.0. |
| **Compile target** | Lua source code (any version via flags). |
| **Embed from Rust** | **Written in Rust!** Available as `clue` crate on crates.io. Can embed as library or CLI. Uses mlua for `--execute` mode. |
| **Maintenance** | **Active.** Regular releases. Rust-native. |
| **Community** | Small. Discord server. |
| **Verdict** | **Rust-native is a plus**, but no types yet. Type system is future-tense. If v4 ships types, could be interesting — but that's speculative. Not ready now. |

#### Lus

| Attribute | Detail |
|-----------|--------|
| **What** | "Sovereign" Lua 5.5 superset with its own runtime and standard library. |
| **Typing** | Unclear from docs. Appears to be dynamically typed. |
| **Compile target** | **Own bytecode / own runtime.** Not compatible with stock Lua VM. |
| **Embed from Rust** | Monorepo with own runtime. Would need C FFI integration. |
| **Maintenance** | Early stage. Small community. |
| **Community** | Minimal. |
| **Verdict** | **"Sovereign" = breaks Lua ecosystem compatibility.** Own runtime means no standard Lua tooling works. Wrong direction for shoot. |

---

### Tier 2: Niche but Active

#### NattLua

| Attribute | Detail |
|-----------|--------|
| **What** | LuaJIT with an optional type system. "A typed version of Lua a bit similar to TypeScript." |
| **Typing** | **Optional/gradual.** Types can be omitted. When present, checked at analysis time (not runtime). Type functions, analyzer functions, literal types, range types, union types, pattern-matched string types. Very expressive. |
| **Compile target** | LuaJIT source (transpiles back to Lua). Type annotations stripped in output. |
| **Embed from Rust** | Written in Lua/LuaJIT. Has its own LSP (for VSCode). No Rust library. |
| **Maintenance** | **Active.** Ongoing development. TypeScript port exists (`nattlua-ts`). |
| **Community** | Very small. Niche tooling for advanced users. |
| **Verdict** | **Most interesting typing model in this census.** Literal types, range types, type functions are powerful. But: LuaJIT-only (not Lua 5.4/5.5), self-hosted in Lua (no Rust embed path), very small community. The type system ideas are worth stealing for shoot's validation layer, but NattLua itself doesn't fit. |

#### Fuse

| Attribute | Detail |
|-----------|--------|
| **What** | "A gradually typed dialect of Lua written in Rust." Targets Lua, LuaJIT, Luau. Inspired by TypeScript/JS, Scala/Java, Rust ownership. |
| **Typing** | **Gradual/static.** Immutable by default, optional `mut`. Exhaustive pattern matching. Optional types (no nil). Ownership system (simplified Rust borrow checker). |
| **Compile target** | Lua source (multiple versions), LuaJIT bytecode, Luau bytecode. |
| **Embed from Rust** | **Written in Rust!** Compiler is a Rust binary/library. Multi-target output. |
| **Maintenance** | **Very early.** Version sub-0.1. "NOT ready for production." 15-16 GitHub stars. |
| **Community** | Effectively none yet. |
| **Verdict** | **Most promising candidate on paper** — Rust-native, gradual types, multi-target. But version sub-0.1 means it's years from production. If it matures, it could be the answer. For now, not viable. **Watch list.** |

#### Titan

| Attribute | Detail |
|-----------|--------|
| **What** | System programming language from PUC-Rio LabLua (same team as Lua itself). Statically typed, compiles to C. |
| **Typing** | **Static.** Full type system with modules, records, arrays. Check-time enforcement. |
| **Compile target** | **C code** (then compiled to native). Not Lua bytecode. |
| **Embed from Rust** | Written in Lua (compiler front-end) + C (back-end). Could embed via C FFI. No Rust bindings. |
| **Maintenance** | **Effectively dead.** Last activity 2020-2021. Superseded by Pallene (which we already evaluated). GitHub repo exists but no meaningful commits in years. |
| **Community** | Zero. Academic project concluded. |
| **Verdict** | **Dead.** Pallene is its successor (already excluded). Skip. |

#### Erde

| Attribute | Detail |
|-----------|--------|
| **What** | Go/Rust-like syntax transpiler to Lua. Symbol-favored syntax (`{}`, `=>`, `match`). |
| **Typing** | None. |
| **Compile target** | Lua source code. |
| **Embed from Rust** | Written in Lua. No Rust bindings. |
| **Maintenance** | **Low activity.** Website exists but development appears slow. |
| **Community** | Very small. |
| **Verdict** | **No types, no Rust embed, low activity.** Skip. |

#### LunarML

| Attribute | Detail |
|-----------|--------|
| **What** | Standard ML compiler that produces Lua (or JavaScript). Full SML '97 with modules. |
| **Typing** | **Static** (full ML type system). But it's SML, not Lua. |
| **Compile target** | Lua 5.3/5.4/LuaJIT source code. |
| **Embed from Rust** | Written in Standard ML. No Rust bindings. |
| **Maintenance** | **Active.** Presented at ML Workshop 2025. Regular releases. |
| **Community** | ML academic community. Very niche. |
| **Verdict** | **Wrong language entirely.** It's SML, not a Lua dialect. Interesting that it compiles to Lua, but irrelevant for shoot. |

#### Clue (revisit — more detail)

Already covered above. Key fact: **only Rust-native compiler in this census** besides Fuse.

---

### Tier 3: Dead / Dormant (for completeness)

| Dialect | Status | Notes |
|---------|--------|-------|
| **Urn** | Dormant. GitLab repo last active ~2020. No releases since. Lisp→Lua, self-hosted in Urn itself. | Dead. |
| **Lumen** | Dead. GitHub archived. Lisp→Lua. | Dead. |
| **Hua** | Dead. Lisp→Lua. | Dead. |
| **l2l** | Dead. Lisp→Lua. | Dead. |
| **Kailua** | Archived. Typed Lua (earlier than Teal). | Dead. |
| **Tua** | Dead. Typed Lua. | Dead. |
| **Wu** | Unmaintained. Rust-like syntax→Lua. | Dead. |
| **Hypatia** | Dormant. ML-like→Lua. | Dead. |
| **Candran** | Unmaintained. Lua preprocessor. | Dead. |
| **gijit** | Unmaintained. Go→LuaJIT. | Dead. |
| **Brat** | Dead. Uses MoonJIT. | Dead. |

---

## 2. Rust-Native Lua Tooling Ecosystem

This is the ecosystem we'd build shoot's validation/LSP layer on top of.

### full-moon (Rust Lua Parser)

| Attribute | Detail |
|-----------|--------|
| **What** | Lossless parser for Lua. Preserves comments, whitespace, style. AST round-trips perfectly. |
| **Lua versions** | **5.1, 5.2, 5.3, 5.4, Luau** (via feature flags: `lua52`, `lua53`, `lua54`, `luau`). Also `luajit` and `cfxlua` (CFX/FiveM dialect). |
| **Crates** | `full-moon` on crates.io. Latest 2.1.1. |
| **API** | `LuaVersion` struct controls which version to parse. Feature flags cascade (`lua54` enables `lua53`+`lua52`). |
| **Luau support** | Full Luau support including type annotations, string interpolation. Module named `luau` (was `types`, renamed). |
| **Lua 5.5 support** | **Not yet.** No `lua55` feature flag as of 2.1.1. |
| **Used by** | StyLua (formatter), selene (linter), luau-language-server. |
| **Verdict** | **Foundation of the Rust Lua tooling stack.** Our linter and LSP would build on this. Missing Lua 5.5 is a gap but 5.4 coverage is excellent. |

### selene (Rust Lua Linter)

| Attribute | Detail |
|-----------|--------|
| **What** | Blazing-fast Lua linter written in Rust. Built on full-moon. |
| **Lua versions** | Lua 5.1 (default), with support for other versions via configuration. Luau support built-in (Roblox-oriented). |
| **Features** | Stdlib definitions, unused variable detection, shadowing warnings, custom lint rules via TOML config. |
| **Crates** | `selene` and `selene-lib` on crates.io. |
| **VSCode** | Extension available. |
| **Luau** | Yes, first-class Luau support (created by same author as full-moon, Kampfkarren). |
| **Verdict** | **Best Rust linter for Lua.** Would be our linter foundation. Extensible via Lua-defined stdlib. Can target specific Lua versions. |

### StyLua (Rust Lua Formatter)

| Attribute | Detail |
|-----------|--------|
| **What** | Deterministic Lua code formatter. Inspired by Prettier. Built on full-moon. |
| **Lua versions** | 5.1, 5.2, 5.3, 5.4, LuaJIT, Luau. |
| **Crates** | `stylua` and `stylua_lib` on crates.io. Latest 2.5.2. |
| **API** | `format_ast()`, `format_code()` functions. `LuaVersion` enum. |
| **Config** | Column width, indent type, quote style, call paren style, etc. |
| **Verdict** | **Production-ready formatter.** Would enforce consistent style on AI-generated package defs. |

### lua-language-server (LuaLS)

| Attribute | Detail |
|-----------|--------|
| **What** | Full LSP implementation for Lua. ~1M VSCode installs. |
| **Language** | Written in **C++** (with Lua). Not Rust. |
| **Features** | Diagnostics, completion, hover, goto definition, find references, code actions, formatting, type checking (via EmmyLua annotations). |
| **Typing** | Supports EmmyLua-style type annotations for gradual type checking. v3.0.0+ changed annotation syntax (no longer cross-compatible with EmmyLua). |
| **Luau** | Separate fork/project: `luau-language-server`. |
| **Verdict** | **Most mature Lua LSP.** C++ implementation, not Rust. Could use as reference or shell to it. For a pure-Rust stack, we'd need to build LSP on full-moon + custom analysis. |

### Other Rust Lua Crates

| Crate | Purpose | Notes |
|-------|---------|-------|
| `mlua` | High-level Lua bindings for Rust | Supports Lua 5.1-5.5, LuaJIT, Luau. async/await. Primary embed path for any Lua engine in Rust. |
| `rlua` | Older Lua bindings (archived) | Predecessor to mlua. Don't use. |
| `lua-src-rs` | Lua C source bundled for Rust builds | Builds Lua 5.1-5.5 from source during `cargo build`. Used by mlua. |
| `luaparse-rs` | Lua parser (port of luaparse.js) | Supports Luau, Lua51-54. Alternative to full-moon. Less mature. |

---

## 3. Scoring: Does Any New Dialect Beat Luau?

Our ranking axes (max 30):
1. **Declarative** (5) — natural for config/definitions
2. **Determinism** (5) — reproducible builds, no hidden state
3. **Untrusted safety** (5) — sandboxed execution, no escapes
4. **Rust embed** (5) — native Rust integration path
5. **Validation loop** (5) — type checker / linter for error detection
6. **Static typing** (5) — compile-time or check-time type enforcement

### Luau baseline: 25/30

| Axis | Score | Notes |
|------|-------|-------|
| Declarative | 4 | Verbose but works for config |
| Determinism | 5 | No randomness in type system |
| Untrusted safety | 4 | Sandboxing via Roblox model |
| Rust embed | 3 | mlua Luau support exists |
| Validation loop | 4 | Luau's own type checker + linter |
| Static typing | 5 | Gradual, strong when annotations present |

### New dialect candidates scored:

#### NattLua: ~16/30

| Axis | Score | Notes |
|------|-------|-------|
| Declarative | 3 | Lua syntax, no DSL sugar |
| Determinism | 5 | Type analysis is deterministic |
| Untrusted safety | 2 | LuaJIT-only, no sandbox story |
| Rust embed | 1 | Self-hosted in Lua, no Rust path |
| Validation loop | 3 | Has type checker but niche tooling |
| Static typing | 2 | Optional/gradual, very expressive but non-standard |
| **Total** | **16** | Interesting type ideas, but LuaJIT-only + no Rust embed kills it |

#### Fuse: ~20/30 (theoretical)

| Axis | Score | Notes |
|------|-------|-------|
| Declarative | 4 | Clean syntax, could work for config |
| Determinism | 5 | Static analysis |
| Untrusted safety | 3 | Ownership model helps, but sub-0.1 |
| Rust embed | 5 | Written in Rust, native compiler |
| Validation loop | 3 | Type system exists but immature |
| Static typing | 4 | Gradual, Rust-inspired ownership |
| **Total** | **20** | Would be ~23-24 if mature. **Watch list.** |

#### Pluto: ~17/30

| Axis | Score | Notes |
|------|-------|-------|
| Declarative | 4 | Switch/case is nice, but no DSL features |
| Determinism | 5 | Deterministic |
| Untrusted safety | 2 | C VM, no sandbox story |
| Rust embed | 2 | C FFI possible but not native |
| Validation loop | 2 | No type checker, no linter |
| Static typing | 1 | Zero typing capability |
| **Total** | **17** | Syntactic sugar only, no validation value |

#### Clue: ~16/30

| Axis | Score | Notes |
|------|-------|-------|
| Declarative | 3 | C/Rust syntax, not config-friendly |
| Determinism | 5 | Deterministic compilation |
| Untrusted safety | 2 | Compiles to Lua, no sandbox |
| Rust embed | 4 | Written in Rust, usable as library |
| Validation loop | 1 | No type system yet |
| Static typing | 1 | Planned for v4.0, doesn't exist |
| **Total** | **16** | Rust-native is a plus, but no types = no value |

---

## 4. Conclusion

**No new dialect discovered in this census beats Luau (25/30).**

The closest theoretical candidate is **Fuse** (written in Rust, gradual types, ownership model) but it's version sub-0.1 and years from production readiness. **NattLua** has the most interesting type system ideas (literal types, range types, type functions) but is LuaJIT-only with no Rust embed path.

### Key findings:

1. **Fuse is the only Rust-native typed Lua dialect.** It's the most promising long-term candidate but not viable today.
2. **NattLua's type system is the most sophisticated** in the Lua ecosystem — worth studying for validation loop design, even if we don't use NattLua itself.
3. **Pluto is the most active Lua superset** (~372 stars, rebasing on Lua 5.5) but has zero typing capability.
4. **Fennel is the most popular Lua-adjacent language** (2.6k stars) but Lisp syntax disqualifies it for AI-authored config.
5. **The Rust Lua tooling stack (full-moon + selene + StyLua) is mature** and covers Lua 5.1-5.4 + Luau. Missing Lua 5.5 support is a gap.
6. **mlua** supports Lua 5.1-5.5 + Luau, making it the universal Rust embed path.

### Recommendation:

**Stick with Luau as the primary candidate.** The Rust tooling ecosystem (full-moon, selene, StyLua, mlua) has first-class Luau support. No alternative dialect offers a better combination of typing, safety, Rust embed, and validation tooling.

If Fuse matures (v1.0+), revisit — it could potentially score 23-24/30 and might edge out Luau on the Rust embed axis.

---

## Appendix: Star Counts & Activity Summary (August 2026)

| Dialect | GitHub Stars | Last Active | Language | Typing |
|---------|-------------|-------------|----------|--------|
| **Fennel** | ~2,600 | Active (SourceHut) | Lua/Fennel | None |
| **Pluto** | ~372 | Active (2024-2026) | C (Lua fork) | None |
| **YueScript** | ~300+ | Active (2024-2026) | C++17 | None |
| **MoonScript** | ~4,000+ | Stagnant (2019) | MoonScript/Lua | None |
| **Clue** | ~200+ | Active (2024-2026) | **Rust** | None (v4.0) |
| **NattLua** | ~150+ | Active (2024-2026) | Lua/LuaJIT | Optional/gradual |
| **Fuse** | ~15 | Early (sub-0.1) | **Rust** | Gradual/static |
| **Erde** | ~100+ | Low activity | Lua | None |
| **Lus** | ~50+ | Early | Own runtime | Unclear |
| **LunarML** | ~100+ | Active (2025) | SML | Static (ML) |
| **Urn** | ~200+ | Dormant (~2020) | Urn/Lua | None |
| **Titan** | ~150+ | Dead (~2020) | Lua/C | Static |
