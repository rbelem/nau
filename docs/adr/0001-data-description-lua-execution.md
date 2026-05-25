# Data-description Lua execution model

`shoot.lua` is evaluated as a data-description language, not a scripting environment. The Lua runtime evaluates a `shoot.lua` that returns a well-structured table. Users can use loops, conditionals, and helper functions to construct configs, but the evaluation is deterministic and side-effect-free — any ordering of independent declarations produces the same result.

Status: accepted

## Considered Options

- **Full scripting (Neovim-style)** — `shoot.lua` can execute arbitrary Lua, read files, make network calls, mutate state during config evaluation. Closest to what "write Lua" intuitively means. Risks non-deterministic builds, harder to validate, and users could write configs that work only in certain environments.
- **Lazy Nix-style DSL** — Attribute sets with `mkDefault`/`mkForce` semantics, pure, declarative. Most predictable but also farthest from what existing Snap users know (YAML). The learning curve would be steep — users need to learn a custom DSL on top of Lua.
- **Data-description Lua (chosen)** — Lua syntax, but the contract is "return a table." Users get the expressiveness they lack in YAML (conditionals, loops, imports) without the complexity of a lazily-evaluated DSL. The Lua runtime is the parser; the output is the table.

## Consequences

- Validation can be pure: parse the returned table, check required fields, report errors — no need to simulate an evaluation environment.
- `mlua` integration is straightforward: call `chunk.eval::<Value>()`, extract the table, map it to Rust structs.
- Users coming from Snapcraft YAML have a gentler learning curve: the mental model is "like YAML but with functions."
- Future multi-output flakes are natural: the Lua returns a table of output tables, not a single config.
