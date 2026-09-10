# Planning & Docs

## Planning

Planning uses the **grill-with-docs** format (`/grill-with-docs`): a relentless
interview that resolves open questions and records decisions as ADRs and
glossary entries as they are settled. It is the only planning workflow here —
do not introduce a separate phase-execution workflow.

- **`.planning/`** — active planning inputs: `research/`,
  `cross-distro-synthesis.md`, `grill-input-*.md`.
- **`.planning/archive/`** — historical, superseded planning: `PROJECT.md`,
  `ROADMAP.md`, `REQUIREMENTS.md`, `STATE.md`. Read for history only; it does
  not describe the current state.

## Documentation

- **`CONTEXT.md`** (repo root) — the domain glossary: canonical terms, their
  definitions, avoided synonyms, and flagged ambiguities. Read it before naming
  domain concepts, and use its vocabulary in issue titles, refactors, test
  names, and docs.
- **`docs/adr/`** — architecture decision records, numbered `NNNN-slug.md`.
  Read the ADRs touching an area before changing it. If a change contradicts an
  ADR, surface the conflict explicitly instead of silently overriding it.
  Superseded ADRs move to `docs/adr/archive/`.
- This is a single-context repo: one `CONTEXT.md` plus `docs/adr/` at the root.
  See [domain guidance](domain.md) for how these are consumed.
