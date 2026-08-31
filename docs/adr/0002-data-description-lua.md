# Data-description Lua DSL (not imperative config)

> **Status: Superseded by [ADR-0009](0009-package-language-nickel.md)** (package-definition language: Nickel). Retained for rationale on the data-description pattern, which carries over.

The Lua DSL is purely data-description: `snap()` validates its argument table and returns it unchanged. There is no hidden mutation, no builder pattern, no intermediate objects. This is deliberate: it keeps Lua the schema source of truth (per ADR-0002) and makes Rust a passive consumer — `SnapMeta::from_lua_table` simply extracts pre-validated fields. The alternative (imperative Snapcraft-style YAML or a builder API) would split validation authority between Lua and Rust.

Rejected alternatives: TOML/YAML (too rigid, no composability), Rust builder pattern in Lua (duplicated validation), embedded DSL via macros (opaque error messages).
