# `shoot.lua` returns a table of named outputs

The Lua DSL always returns a table of named outputs, not a single snap declaration. A single-snap config returns a table with one entry (`{ default = { ... } }`). A multi-output config returns multiple entries (`{ server = { ... }, cli = { ... } }`). `shoot build` builds all outputs; `shoot build <name>` builds one specific output.

Status: accepted

## Considered Options

- **Single-snap return (Snapcraft-like)** — `shoot.lua` declares one snap. Multi-output is added later by wrapping it in a list syntax. Simpler to start, but Phase 8 becomes a refactor of the return contract, breaking existing configs.

- **Table-of-outputs from day one (Nix flakes-like, chosen)** — The return type is always a table. Single-snap is a natural special case. No breaking change when multi-output lands — the CLI arg `shoot build <output>` just starts working.

## Consequences

- Phase 1's Lua evaluation must handle a table-of-tables, not a single table.
- Phase 8 is eliminated as a rewrite phase; the remaining work is CLI arg dispatch and output naming.
- The roadmap should be updated: Phase 8 shrinks to "output selection CLI + naming" or gets absorbed into Phase 1/5.
- Users coming from Snapcraft YAML need to understand the table-of-outputs concept from day one, even if they only declare one snap.
