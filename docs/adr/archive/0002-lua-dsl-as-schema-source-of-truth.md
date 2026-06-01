# Lua DSL as schema source of truth

The schema for snap declarations lives in injected Lua functions (`snap`, `app`, etc.), not in Rust structs. These functions validate their arguments (types, required fields, field relationships) during Lua evaluation. Rust receives pre-validated tables and is a passive consumer — no struct-level validation beyond what Lua already checked.

Status: accepted

## Considered Options

- **Rust structs as source of truth (Snapcraft-like)** — Define Snap metadata as Rust structs with validation. `mlua` extracts values from Lua tables, then Rust validates types and fields. Errors come from the mapping layer. Single place for typed validation, but users never see Lua stack traces for field errors — they get Rust error messages instead. Adding a field requires a Rust code change.

- **Lua DSL as source of truth (Nix-like, chosen)** — Injected Lua functions validate at eval time. `snap(...)` checks required fields and types inside Lua, throws Lua errors users can trace. Rust receives structurally validated data. Adding a field is one change in Lua validation helpers. Follows the Nix model where `mkDerivation` IS the schema, not an external type definition.

## Consequences

- Lua evaluation phase is also validation phase — no second pass needed in Rust.
- Error messages for malformed configs come from Lua stack traces, which users of a Lua-based tool will find natural.
- The Lua sandbox is self-documenting: a user can inspect injected globals to discover available fields.
- Rust structs remain simple data holders (`#[derive(Deserialize)]` style, possibly with Serde).
- The injected validation helpers must be tested separately from the Rust codebase's tests.
