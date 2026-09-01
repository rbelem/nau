-- shuttle typed prelude — analyzer definition file (Luau Mode::Definition).
--
-- Loaded via Frontend::loadDefinitionFile by the check stage so that the
-- globals the eval prelude injects at runtime (src/dsl/init.lua: snap,
-- merge, pin, index, app, image) are *bound globals* for the analyzer.
-- Without this, every corpus definition would fail the gate with
-- "Unknown global 'snap'" — the unbound-prelude surface the spike measured
-- (analyzer-spike/REPORT.md §3, case c1).
--
-- Deliberately LOOSE parameter/result types (`any`): schema strictness lives
-- in the Rust-side validation (ADR-0010 Decision 3 — snap() is a validating
-- pass-through, all field validation happens at the extraction boundary).
-- A strict SnapMeta table type here would make the analyzer stage reject
-- `snap { name = 42 }` with a Luau message before the eval stage reports its
-- named schema error, reordering (and duplicating) the diagnostic stream.
-- What the strict-mode gate still catches on definitions: syntax errors,
-- misspelled globals, unknown locals, annotated type errors, and type errors
-- that flow across require() module boundaries.
--
-- Trailing optional parameters (`any?`) mirror the runtime DSL: pin() and
-- merge() are legal with fewer arguments, snap()/app()/index()/image() are
-- not.

declare snap: (meta: any) -> any
declare merge: (base: any?, overrides: any?) -> any
declare pin: (name: any, opts: any?) -> any
declare index: (name: any) -> any
declare app: (opts: any) -> any
declare image: (opts: any) -> any
