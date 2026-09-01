# Built-in builder plugin registry (parts gain `plugin`)

## Status

Accepted (2026-09-01)

## Context

Definitions build with raw shell commands (`build = "..."`, now per-part since multi-part landed). Real-world language builds need canned builders: the gap analysis requires 4-5 language plugins for credibility, and hand-writing autotools/cargo/cmake incantations for every package is the failure mode Snapcraft's plugins exist to prevent.

Constraints that shape the design:

- Builds run in the bubblewrap sandbox; plugins must not weaken it.
- The binary cache keys on the parts spec; plugin identity + options must fold into that key or cache correctness breaks.
- Definitions are AI-authored and untrusted at eval; plugin options are definition data and must be validated at a boundary.
- Lua tables are unordered; everything order-sensitive was settled by ADR-0009-era multi-part work (`after` edges, name tie-break).

## Decision

1. **Built-in Rust plugin registry, v1.** Plugins are compiled into shuttle: initial set `cargo`, `make`, `cmake`, `autotools`. A part selects one with `plugin = "<name>"` plus a per-plugin options table. No dynamic plugin loading: external-executable plugins (`shuttle-plugin-*` on PATH) were considered and deferred — they add discovery, versioning, and an untrusted-execution surface that v1 does not need; revisit only if third-party builders are actually requested.
2. **`build` and `plugin` are mutually exclusive per part** (a plugin IS the build); `after` ordering and shared `$STAGE` semantics are identical for plugin parts.
3. **Plugin schemas are Rust's boundary.** Each plugin declares its options (required/optional, types) and validates them in Rust — per the boundary-discipline rule, `snap()` in Lua checks only that `plugin` is a known name and options are a table; deep option validation lives with the plugin implementation, producing named errors ("cargo: option 'channel' must be a string").
4. **Expansion is declarative.** A plugin expands to a `BuildPlan { commands, env, extra_requires }` consumed by the existing `run_parts` machinery — a plugin cannot execute arbitrary logic at build time beyond the commands it emits. Plugins may append to the snap's `requires` (e.g. `cargo` pulls the rust toolchain package) so the sandbox stays hermetic and the lockfile/cache see the full closure.
5. **Cache keying**: the canonical parts JSON (already hashed) gains plugin name, plugin version, and the canonical options map. Changing an option invalidates the cache; identical options keep it warm.
6. **Per-plugin scope (v1)**: each plugin's option set is intentionally minimal (e.g. `make`: `target`, `makefile`; `cargo`: `channel`; `cmake`: `generator`, `defines`; `autotools`: `args`) — grow by demand, not speculation.

## Consequences

### Positive

- Real language workflows with one-line parts; consistent validation errors; sandbox and cache semantics preserved by construction.
- Plugin additions are shuttle releases, which is acceptable while the registry is small and curated.

### Negative

- New builders require a shuttle release (the deferred external-plugin mechanism is the escape hatch, deliberately unpaved).
- Plugin option schemas are a public-ish surface to keep stable once packages depend on them.

### Neutral

- Per-part `source`/inputs remain future work (shared `$SRC` today), independent of the plugin mechanism.
