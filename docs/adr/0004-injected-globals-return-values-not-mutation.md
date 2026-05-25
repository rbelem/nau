# Injected globals return values, don't mutate state

`snap(...)` and other injected globals return validated tables. The user assembles the output table explicitly and returns it from `shoot.lua` with a `return` statement. Rust reads the return value of the evaluated chunk — it does not inspect mutable globals.

Status: accepted

## Considered Options

- **Mutation (Neovim-style)** — `snap "myapp" { ... }` mutates an internal `_outputs` table in the Lua registry. Rust reads the global after eval. Simpler for users (just declare), but opaque: where does the data go? Imports can't easily inspect or transform outputs. Testing requires evaluating the whole script and checking globals.

- **Return value (Nix-style, chosen)** — `snap(...)` returns a validated table. `return { default = snap("myapp", {...}), cli = snap("cli", {...}) }` is the contract. Explicit, composable, testable in Lua. Imports become `local common = require("./common.lua"); return common.extend(...)`. Rust calls `chunk.eval::<Table>()` and gets the output directly.

## Consequences

- `mlua` integration is `chunk.eval::<Value>()` on the compiled chunk — no global state to sync.
- Users must write `return ...` in every `shoot.lua`. This is natural for anyone who's written Lua before.
- Phase 7 composability works without special syntax: `require` returns a table, you merge tables, done.
- Testability: you can `dofile("shoot.lua")` and assert on the returned table without `shoot` CLI.
