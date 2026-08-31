# Research: Embeddable Scripting Languages for Shuttle

**Date:** 2026-08-29
**Status:** Complete
**Context:** Evaluating scripting language options for Shuttle, which currently uses Lua via `mlua`. Key concern is sandboxing for untrusted/AI-generated code.

---

## Requirements Recap

1. **Sandboxed execution** — untrusted / AI-generated code must not escape
2. **Deterministic / pure evaluation** — reproducible builds
3. **Rust embedding** — solid `unsafe`-free crate, good ergonomics
4. **Metaprogramming** — Lua-style table DSLs or equivalent for declarative package builds
5. **Performance** — fast startup, low memory for one-shot evaluations

---

## Assessment Table

| Language | Rust Crate | Maturity | Sandboxing | Determinism | Performance | Maintenance (2025-2026) | Shuttle Fit |
|---|---|---|---|---|---|---|---|
| **Starlark** | `starlark-rust` | Production (Buck2, Aspect CLI) | ✅ Built-in, Rust-native | ✅ By design | Fast (compiled) | **Active** — Buck2 drives it | ★★★★★ |
| **Nickel** | `nickel-lang` (Rust lib) | Production (Tweag, ~4.1k★) | ⚠️ N/A (pure config, no I/O) | ✅ By design | Fast (compiled) | **Active** — commercial backing | ★★★★☆ |
| **piccolo** | `piccolo` (pure Rust Lua) | Experimental (~700★) | ✅ Design goal — `UserData` + `Context` isolation | ✅ No FFI | Fast | **Active** — maintained | ★★★☆☆ |
| **Lua 5.4** | `mlua` (C API) | Production (Neovim) | ⚠️ Bolt-on — loadlib, FFI, os/io/math.random exposed | ⚠️ Requires denylisting | Very fast (C Lua) | **Active** — maintained | ★★★☆☆ |
| **Boa** | `boa_engine` (pure Rust) | Production (18k★) | ⚠️ Denylisting — no I/O by default, but no hard sandbox | ⚠️ JS has non-determinism (Date, Math.random) | Fast | **Active** — very active | ★★★☆☆ |
| **Rhai** | `rhai` (pure Rust) | Production (4k★) | ✅ Sandboxed by default (no I/O, no FS) | ⚠️ No random/file access, but no proof of determinism | Moderate (interpreted) | **Active** — maintained | ★★★☆☆ |
| **mruby** | `mruby` (C, Rust binding needed) | Production | ⚠️ Similar to Lua — FFI, loadlib | ⚠️ Requires denylisting | Fast | **Active** (Sonic Pi, mruby-CLI) | ★★☆☆☆ |
| **Janet** | None — C only | Production | ⚠️ C FFI risk | ⚠️ Requires denylisting | Fast | **Active** — niche community | ★☆☆☆☆ |
| **LuaJIT** | `luajit` (C) | Production (Neovim) | ⚠️ Same as Lua + JIT escape | ⚠️ JIT non-determinism | **Fastest** | ⚠️ **Semi-dormant** — no releases since 2023 | ★☆☆☆☆ |
| **Gluon** | `gluon` | 2.1k★ | ✅ Pure Rust, no FFI | ✅ Designed for embedding | Moderate | ⚠️ **Low activity** | ★★☆☆☆ |
| **Mun** | `mun_runtime` | Pre-release | ⚠️ Uses LLVM — large attack surface | ⚠️ Unknown | Fast (JIT) | ⚠️ **Low activity** | ★☆☆☆☆ |
| **Wren** | C only | Production | ✅ Sandboxed (no FFI) | ✅ Designed for embedding | Moderate | ⚠️ **C only** — no Rust embedding | ★☆☆☆☆ |
| **Pallene** | None | Research | N/A (compiled Lua) | N/A | Fast | ⚠️ **Dormant** — research project | ★☆☆☆☆ |
| **Teal** | None | Niche | N/A (type checker over Lua) | N/A | Same as Lua | ⚠️ **Low activity** | ★☆☆☆☆ |

---

## Detailed Findings

### 🏆 Starlark-rust (strongest recommendation)

**What it is:** A Rust implementation of Starlark (Google's Python dialect for build rules). Buck2 (Meta's build system) and Aspect CLI both embed it.

**Sandboxing:**
- **No file I/O, no network, no process execution** — by design
- No dynamic imports, no `eval()`, no `exec()`
- Global interpreter lock prevents side effects between evaluations
- Deterministic iteration order (hash randomization disabled by default)
- Pure data in → pure data out — exactly what Shuttle needs

**Precedent:**
- Buck2: Meta's production build system, millions of builds/day
- Aspect CLI: `aspect-build/aspect-cli` uses `starlark-rust` for build rules
- Many Google-internal build systems

**Ergonomics:**
- Python-like syntax — familiar to most developers
- Records (structs), lists, dicts, functions, comprehensions
- `load()` for modular imports (controlled by host)
- Strong typing with `type()` checks and `provider` pattern

**Fit for Shuttle:**
```python
# snap.star — equivalent of current snap.lua
def snap():
    return Snap(
        name = "my-app",
        version = "1.0",
        summary = "My app",
        description = "Longer description",
        apps = {
            "my-app": App(
                command = "bin/my-app",
                plugs = ["network", "desktop"],
            ),
        },
        parts = [
            Part(
                plugin = "npm",
                source = ".",
                build_snaps = ["node/20/stable"],
            ),
        ],
    )
```

**Concern:** Starlark is more restrictive than Lua — no metatables, no runtime code generation. This is a *feature* for security but limits DSL flexibility. Shuttle's current Lua DSL relies on `__index` metamethods for convenience (`snap apps.myapp.plugs`), which Starlark can't do — you'd use explicit function calls instead.

---

### 🥈 Nickel

**What it is:** A Rust-native configuration language from Tweag. "Nix done right" — typed, with contract system, merging, and lazy evaluation.

**Sandboxing:** Not needed — Nickel is a pure configuration language with no I/O capability by design.

**Determinism:** Guaranteed — no randomness, no time, no external state.

**Fit for Shuttle:**
```nickel
{
  snap = {
    name = "my-app",
    version = "1.0",
    apps."my-app" = {
      command = "bin/my-app",
      plugs = ["network", "desktop"],
    },
    parts = [{
      plugin = "npm",
      source = ".",
    }],
  },
}
```

**Concern:** Nickel is designed for *configuration*, not *imperative build logic*. If Shuttle needs conditional logic, loops over fetched data, or complex part assembly, Nickel may be too restrictive. Also, Nickel's Rust embedding (`nickel-lang` crate) is newer and less battle-tested than `starlark-rust`.

---

### 🥉 piccolo (pure-Rust Lua)

**What it is:** A pure-Rust Lua 5.4 implementation with explicit sandboxing as a design goal.

**Sandboxing:**
- No C FFI — eliminates the primary Lua sandboxing weakness
- `Context`-based isolation: each execution context gets its own memory space
- `UserData` for controlled host-object exposure
- Can deny `require`, `dofile`, `loadfile` at the registry level

**Determinism:** Achievable — no C FFI means no `math.random` from liblua, and you can hook or remove any non-deterministic stdlib function.

**Concern:** Still experimental (~700★). May have performance gaps vs C Lua. Fewer eyeballs = more risk. If Shuttle needs production reliability *now*, piccolo is premature.

---

### Lua via mlua (current)

**Why re-evaluate:** mlua sandboxing is a denylist approach against a C API with a large attack surface. Every new `require` or FFI call is a potential escape. For *untrusted* code (AI-generated, user-submitted), this is a losing game — you're always one missed denylist entry away from a sandbox escape.

**When to keep Lua/mlua:**
- If the code is *trusted* (Shuttle's own DSL, reviewed package definitions)
- If metaprogramming flexibility (metatables, `__index`) is non-negotiable
- If Lua ecosystem libraries (luarocks) add value

**When to switch:**
- If untrusted code execution is a real requirement
- If build reproducibility is non-negotiable
- If you want a language where the *default* is safe, not one where safety is a denylist

---

### Notable Dismissals

- **LuaJIT**: Semi-dormant (no releases since 2023, no Lua 5.4). JIT adds non-determinism. Not worth the risk for new projects.
- **Rhai**: Good sandboxing story, but interpreted (slower) and less mature than Starlark. No major production embedder.
- **Boa**: Large and active, but JavaScript has inherent non-determinism (`Date`, `Math.random`, `performance.now`). No hard sandbox mode.
- **mruby**: Similar weaknesses to Lua (C FFI, loadlib). Extra complexity for no gain over Lua.
- **Janet, Gluon, Mun, Wren, Pallene, Teal**: Insufficient ecosystem, C-only, dormant, or too niche.

---

## Decision Matrix

| If your priority is... | Choose |
|---|---|
| **Maximum security + determinism** | Starlark-rust |
| **Purpose-built config (no build logic)** | Nickel |
| **Lua syntax with better sandbox** | piccolo (risky today, promising) |
| **Lua ecosystem + flexibility** | Keep mlua (but accept sandboxing limits) |
| **JavaScript familiarity** | Boa (accept non-determinism) |

---

## Recommendation

**For Shuttle's use case (declarative Snap package builds, potentially AI-generated code):**

**Starlark-rust** is the strongest choice. It's:
- Battle-tested in Buck2 (Meta's production build system)
- Designed for exactly this: sandboxed, deterministic, embedded build rules
- Python-like syntax (familiar to most developers)
- Pure Rust — no C FFI, no FFI sandboxing concerns

**Trade-off:** Starlark is more restrictive than Lua. You lose metatables and runtime code generation. For Shuttle's DSL, this means:
- Explicit function calls instead of `__index` magic
- No runtime metaprogramming (but Starlark has `load()` for controlled imports)
- Records instead of dynamic tables

**If metaprogramming flexibility is non-negotiable**, keep mlua but plan for a denylist-review process.

**If you want to stay in the Lua family** but improve sandboxing, piccolo is worth tracking — but it's not production-ready today.

---

## References

- [starlark-rust GitHub](https://github.com/facebookexperimental/starlark-rust) — Buck2's Starlark implementation
- [Aspect CLI](https://github.com/aspect-build/aspect-cli) — uses `starlark-rust` for build rules
- [Nickel language](https://github.com/nickel-lang/nickel) — Rust-native config language
- [piccolo GitHub](https://github.com kyren/piccolo) — pure-Rust Lua with sandboxing
- [mlua GitHub](https://github.com/mlua-rs/mlua) — current Lua embedding (for reference)
- [Buck2 Starlark docs](https://buck2.build/docs/) — production precedent
