# Project rename: shuttle → nau (CLI merges with the distro name)

## Status

Accepted (2026-09-28). Owner-initiated. Amends ADR-0013 Decision 1: the CLI, binary,
crate, and project name are now **nau** — the same name the 0013 amendment already gave
the distro. Supersedes the 0013 clause "no `nau` binary exists (naming invariant)":
that invariant governed distro tooling, and the CLI now deliberately occupies it.

## Context

ADR-0013 split the brand to dodge two verified collisions: crates.io `shuttle` (awslabs)
and shuttle.dev's `shuttle` binary on PATH, which mutually block `cargo install`. The
split bought a clean CLI name at the cost of what 0013 itself recorded as a "permanent
distribution tax" — cargo-install conflicts and permanently dominated search. The
benefit half of the trade then collapsed when the distro became **Nau** (0013 amendment,
2026-09-20): the project now carries two names where one would do, and the surviving
distro name already passed the owner's constraints (one syllable, /naw/ across
PT/EN/DE/ES/IT, the ναῦς/navis lineage). Renaming the CLI onto the distro name keeps
the tax's resolution and drops the second name entirely.

Collision posture for `nau` as the CLI name (all findings inherited from the 0013
sweep, 2026-09-20): crates.io `nau` is held by a dormant ~85-download hobby crate — the
same accepted tax class 0013 recorded for the distro (`nauos` tooling namespace stands
for distro-side crates; the CLI crate rides bare `nau`). No OS product, distro, or
active software brand named Nau exists; "nau linux" search is empty. Unexamined:
English/PT dictionary-word search noise for generic "nau" queries. That gap lands
under the 0013 trademark pre-release gate, which stays blocking for any public release
and now covers the CLI name; the gate re-verifies the crates.io `nau` holder at run time.

## Decision

1. CLI, binary, crate, and project name: **nau** (lowercase on disk, prose "Nau" shared
   with the distro). Canonical surfaces move in the same wave: `nau` binary, `nau.lua` /
   `nau.lock` inputs, `nau-prelude` runtime, `NAU_*` env vars, `~/.cache/nau/`,
   `~/.local/share/nau/` state, `DEFAULT_INPUT_URL = github:rbelem/nau/main`.
2. Clean break per 0013 Decision 2 — no compat shims, no `shuttle` binary alias, no
   old-path fallbacks. On-disk state under the old paths is inert: caches are
   regenerable and pod state re-syncs; nothing migrates.
3. GitHub repo renamed `rbelem/shuttle` → `rbelem/nau` (GitHub redirects old URLs
   indefinitely; local remotes updated) — same mechanics as 0013 Decision 3.
4. The `install.sh` 3-key alias `stl` survives, repointed: `ln -sfn nau "$BIN_DIR/stl"`.
   Its reason to exist (shortening a 7-letter name) is gone with a 3-letter binary; the
   alias is owner muscle memory and may be dropped later without an ADR.
5. Naming invariant (0013 Decision 5) retained verbatim: paths on disk carry the name,
   domain concepts never do, digests and stored metadata never embed it, the DSL stays
   name-free.
6. Historical-artifact freeze, 0013 Decision 4 policy extended to this rename:
   `docs/adr/*` (all of them — records of decisions made under the names they used),
   `.planning/archive/`, `.planning/research/`, `.planning/grill-input-*`,
   `.scratch/`, `shoot-handoff-*` / `handoff-*` files, `.opencode/`. Everything else
   tracked is renamed mechanically (content sed over the three case forms plus `git mv`
   for paths carrying the name), with the full gate as the behavior pin.
7. Vendored Luau tarballs and the Luau shim keep their upstream shape; only our shim
   filename moves (`shim/nau_shim.cpp`, referenced by `build.rs` and `src/analysis.rs`).

## Alternatives considered

- **Keep the split** (CLI shuttle, distro Nau) — preserves install-URL stability for
  zero existing users at the price of the recorded distribution tax forever. Rejected:
  the tax was 0013's own negative consequence, and the owner initiated the merge.
- **blastoff and other fresh CLI names** — 0013's council #1 resurfaces with every
  rename; rejected again for the same reason: the owner wants the one-name family.

## Consequences

**Positive**: one name across CLI and distro; the cargo-install collision 0013 accepted
as permanent dissolves (nothing else installs a `nau` binary of consequence); naming
invariant keeps this the cheap rename it was (constants + paths + docs).

**Negative**: crates.io bare `nau` remains occupied by the dormant hobby crate — the
future CLI crate publication needs either a name claim/negotiation or the `nau-os`/
`nauos` namespace, decided at the trademark gate. Historical docs and ADRs read through
the mapping chain shoot → shuttle (ADR-0013) → nau (this ADR). Local hosts that ran the
old binary see old-path state go cold (`~/.cache/shuttle/`, `~/.local/share/shuttle/`);
a stale `~/.local/bin/shuttle` + `stl` symlink pair needs one reinstall to follow.

## References

- ADR-0013 (project rename shoot → shuttle; distro named Nau; the collision sweep and
  the naming invariant this ADR inherits and extends)
- Rename execution: codemod over tracked files with the freeze set, then the full gate
  (`scripts/gate.sh`) as the before/after behavior pin; commits mirror the 0013 pair
  (`refactor: rename project …`, `docs: record rename (ADR-…)`).
