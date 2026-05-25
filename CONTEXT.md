# shoot

A Rust CLI tool that builds Snap packages from Lua declarations. Replaces Snapcraft's YAML with a programmable, composable Lua DSL.

## Language

**snap**:
A self-contained Linux package format (.snap file) containing one or more apps, metadata, and permissions. The build artifact of `shoot`.
_Avoid_: Package, bundle

**snap declaration**:
The Lua block inside `shoot.lua` that describes a single snap. Contains name, version, summary, description, apps, plugs, and slots.

**app**:
An executable entry point within a snap, defined in `meta/snap.yaml`. A snap can declare multiple apps. Not the entire application — just the command the system runs to start it.
_Avoid_: Binary, program (when referring to the entry point)

**output**:
A named snap declaration in a multi-output `shoot.lua`. Like Nix flake outputs, one config can declare multiple snaps under different output names.

**shoot.lua**:
The root Lua config file. `shoot build` reads it from the current directory by default (or `--file` override). Defines one or more snap declarations.

**Shootfile**:
Alternative name for `shoot.lua`. Not the primary name — included for recognition.

**Lua for data description, not scripting**:
`shoot.lua` is evaluated as a data-description language. The script returns a well-structured table — you can use loops, conditionals, and helper functions in Lua, but the result is deterministic and side-effect-free. This gives users Lua's expressiveness (unlike Snapcraft YAML) while keeping evaluation predictable (Nix-like).
_Avoid_: Imperative scripting, side effects during config evaluation

**Library dependency model**: Snaps bundle their own dependencies. There is no global shared library store (unlike Nix). When a snap needs a shared library, the user stages it alongside the binaries under `--stage`. For sharing libraries between installed snaps, use the Snap content interface (slot/plug) — a producer snap exposes `$SNAP/lib` as a slot, a consumer snap mounts it at `$SNAP/extra-libs`. This is orthogonal to the build-time staging model; `shoot` just generates the correct entries in `meta/snap.yaml` when the DSL declares `plugs`/`slots`.
_Avoid_: Expecting shoot to resolve library dependencies, shared system library directories

**Schema is Lua-defined, not Rust-defined**:
The DSL **is** the schema. Injected Lua globals (`snap`, `app`, etc.) validate their arguments at evaluation time — types, required fields, relationships. Rust receives pre-validated data with no struct-level validation. This mirrors Nix: `mkDerivation` is the schema, not an external type definition.
_Avoid_: Dual validation (Lua + Rust), Rust structs as source of truth

**CLI flag discipline**:
CLI flags are added only in the phase that gives them behavior. `--arch` waits until Phase 6 (multi-arch). `--output` (output path) waits until Phase 5 (snap assembly). Output selection in Phase 8 uses a positional arg: `shoot build <output-name>`, not `--output`.
_Avoid_: Stub flags with no behavior

**Binary staging**:
For v1, `--stage` takes a directory path (default `./stage/`). Binaries and libraries are copied from there into the snap assembly. Composability (stage as a merge of multiple sources from imported modules) is deferred to Phase 7 when the composable DSL lands.
_Avoid_: Build-time dependency resolution, stagedir as a list in v1

**Structured error reporting from day one**:
Lua errors from injected globals are wrapped with file/line context from `mlua`. Rust errors use `miette` or `color-eyre` for rich diagnostics. Both produce the same format: `[ERROR] shoot.lua:12:3: missing required field 'name'`. No separate error-polish phase — the error UX is part of each phase from the start.
_Avoid_: println errors, deferring error UX to later

**Injected globals return values, not mutate state**:
`snap(...)` returns a validated table. The user assembles outputs explicitly and returns them from `shoot.lua`. This is Nix-style: `stdenv.mkDerivation` returns a derivation, `flake.nix` returns outputs. Makes composability natural (imports return tables you can merge), and `return` is the single contract point between Lua and Rust.
_Avoid_: Mutation-based registration, implicit output collection

**Outputs as first-class concept**:
`shoot.lua` always returns a table of named outputs. Single-snap configs return `{ default = { ... } }`. Multi-output configs return `{ server = { ... }, cli = { ... } }`. `shoot build` builds all; `shoot build <name>` builds one. Designed from day one (ADR-0003) — no Phase 8 retrofit needed.
_Avoid_: Single-value return type, late addition of multi-output

**Phase 3 scope**:
Phase 3 (Snap Metadata Mapping) is scoped to defining Rust structs (`SnapMetadata`, `SnapApp`, etc.) and testing the extraction contract. The actual mapping from Lua tables to structs is trivial (field extraction from pre-validated data) — the value of the phase is getting the type definitions right, not the conversion logic.

**System dependency model**:
Dependencies are checked at use time, not upfront. `mksquashfs` is only checked when the build reaches the packaging step — `shoot build --dry-run` and validation work without it. `shoot doctor` gives proactive system readiness (checks for `mksquashfs`, `snap`, etc.). If `snap` CLI is absent, interface validation is silently skipped.
_Avoid_: Hard startup failures for missing tools, requiring snapd on cross-compile hosts

**Composable DSL scope (Phase 7)**:
Phase 7 adds a single `merge(base, overrides)` injected global for recursive deep merge of config tables. No priority system (`mkDefault`/`mkForce`) — Snap configs have shallow override depth (apps, plugs), not nested option trees. `require` + `merge` covers composability.
_Avoid_: Nix priority system, custom DSL for overrides

**Test strategy**:
Lua validation tests are inline in Rust via `mlua`. Rust tests inject the same globals, evaluate Lua snippets, and assert on returned tables. One test runner (`cargo test`), unified CI. Integration tests spawn `shoot build` and validate the output `.snap` with `unsquashfs`.
_Avoid_: Separate test frameworks, dual test infrastructure

**Interface validation from snapd**:
Plug and slot interface names are validated against a cached snapshot from `snapd`. On first `shoot build`, Rust runs `snap interface --all`, parses the interface names, and caches them in `~/.cache/shoot/interfaces.json`. The interface list is injected into Lua globals. Unknown names produce a warning (not error) — the build proceeds. If `snap` CLI isn't available, validation is skipped (graceful degradation for cross-compile hosts). `shoot build --refresh-interfaces` forces a re-fetch.
_Avoid_: Hardcoded interface lists, hard errors on unknown interfaces, build failures when snapd is absent

## Example dialogue

> **Dev:** I want to build my app as a snap.
> **Expert:** Start by creating a `shoot.lua`. Declare a snap with name, version, and the apps you want.
> **Dev:** I have a web server and a cron job — should I put them in one snap or two?
> **Expert:** Either works. If they share lifecycle, put both apps in one snap. If they need to update independently, declare two outputs in your `shoot.lua` and build each separately.
> **Dev:** So I'd do `shoot build server` and `shoot build cron`?
> **Expert:** Yes, or `shoot build` with no args builds all outputs.
