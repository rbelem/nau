# Project rename: shoot → shuttle (CLI), distro named ShuttleOS

## Status

Accepted (2026-08-31). Supersedes the project name "shoot" everywhere except historical artifacts.

## Context

Owner-initiated rename at the cheapest possible moment (pre-1.0, zero users, immediately before the design-reset ADRs). Council review was unanimous that "shuttle" carries a real cost, with verified facts:

- crates.io `shuttle` is held by awslabs (concurrency-testing library, 5.2M downloads).
- shuttle.dev (Rust deployment platform) ships a binary literally named `shuttle` on PATH; `cargo install` hard-errors on duplicate binary names, so installs mutually block.
- "shuttle rust/cli" search is permanently dominated by shuttle.dev.
- Suffix escape hatches (e.g. crate `shuttle-distro`) do not fix the PATH collision.

The owner chose the two-name split with eyes open: **`shuttle` = the package manager / CLI; ShuttleOS = the distro it assembles.** Follow-up deep search found nothing disqualifying for ShuttleOS: the GitHub org `shuttleos` is claimed but stale (one kernel repo, 2022), `shuttleos.com` is an unrelated Brazilian transport service, `shuttleos.dev/.org/.io` are available, crates.io `shuttle-os`/`shuttleos` are free, and Shuttle PC holds no ShuttleOS product or trademark.

## Decision

1. CLI, binary, crate-namespace root, and project name: **shuttle**. Distro name: **ShuttleOS** (prose only; no code or format surface carries it).
2. Clean break — no compat shims, no old-name fallbacks: `shuttle.lua`, `shuttle.lock`, `~/.cache/shuttle/`, `DEFAULT_INPUT_URL = github:rbelem/shuttle/main`, `99-shuttle.conf`, `shuttle-prelude`.
3. GitHub repo renamed to `rbelem/shuttle` (GitHub redirects old URLs indefinitely); local remotes updated.
4. Historical artifacts stay untouched: `docs/adr/0001-0009`, `.planning/` archives, handoff files, `.opencode/` scaffolding.
5. **Naming invariant** (binding on all future work): paths on disk carry the name (`~/.cache/shuttle/`); domain concepts never do ("the store", "generations" — never "shuttle-store"); digests and stored metadata never embed the name (format-version numbers instead); the DSL stays name-free (`snap()`, `image()`, `merge()`, `pin()`, `index()`).

## Alternatives considered

- **blastoff** — council's unanimous #1 (free on crates.io, clean search). Rejected by owner in favor of the ShuttleOS/shuttle split.
- **Keep shoot** — zero cost, but forfeits the reset moment; rejected.
- **padshot / sling** — semantically thin / noisy; dominated.

## Consequences

**Positive**: one coherent brand family (shuttle builds ShuttleOS); rename landed before ADR-0011/0012 so they are born with the final name; naming invariant makes any future rename O(constants + docs).

**Negative**: accepted, permanent distribution tax — `cargo install` conflicts with cargo-shuttle's binary and "shuttle rust" search favors shuttle.dev. Future crates.io publication will need a suffixed crate name (`shuttle-os` / `shuttleos` are free).
