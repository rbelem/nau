# Project rename: shoot → shuttle (CLI), distro named Nau

## Status

Accepted (2026-08-31). Supersedes the project name "shoot" everywhere except historical artifacts.
Amended (2026-09-20, twice): distro renamed ShuttleOS → Cassini → **Nau**; releases now carry mission names, Cassini first. Owner constraints: no "OS" suffix; pronounceable in every major language (PT/EN/FR/DE/IT/JP/CN).

## Context

Owner-initiated rename at the cheapest possible moment (pre-1.0, zero users, immediately before the design-reset ADRs). Council review was unanimous that "shuttle" carries a real cost, with verified facts:

- crates.io `shuttle` is held by awslabs (concurrency-testing library, 5.2M downloads).
- shuttle.dev (Rust deployment platform) ships a binary literally named `shuttle` on PATH; `cargo install` hard-errors on duplicate binary names, so installs mutually block.
- "shuttle rust/cli" search is permanently dominated by shuttle.dev.
- Suffix escape hatches (e.g. crate `shuttle-distro`) do not fix the PATH collision.

The owner chose the two-name split with eyes open: **`shuttle` = the package manager / CLI; ShuttleOS = the distro it assembles.** Follow-up deep search found nothing disqualifying for ShuttleOS: the GitHub org `shuttleos` is claimed but stale (one kernel repo, 2022), `shuttleos.com` is an unrelated Brazilian transport service, `shuttleos.dev/.org/.io` are available, crates.io `shuttle-os`/`shuttleos` are free, and Shuttle PC holds no ShuttleOS product or trademark.

Amendment (2026-09-20): the distro name went ShuttleOS → Cassini → **Nau** through a ten-round collision sweep (86 candidates; blocking findings for Orbit, Ground Control, Tranquility, Juno, Altair, Aurora, Sputnik, Vostok, Atlantis, Arrakis, Rama, Lyra, Selene, Canopus, Alhena, Mizar, Aldebaran, Hamal, Vela, Tucana, Mariner, Janus, Rigil, Kodiak, Mojave, Naos, Arca). **Nau** won on owner preference plus evidence: one syllable, /naw/ in PT/EN/DE/ES/IT, katakana ナウ, Mandarin "nao", the ancestral ship word — Greek ναῦς, Latin navis — that lives inside "astronaut" (star-sailor). No OS product, distro, or active software brand named Nau exists; "nau linux" search is empty. Known accepted quirk: French reads "au" as /o/ ("no"), same class as the city Pau and Bauhaus; documented pronunciation guide ships with the brand. Architecture: the distro is the ship, releases are missions — 1.0 "Cassini", then Buran, Venera, Telstar, Leonov, Skylab, Soyuz, Zond, Lunik, Anik, Telesto, Mintaka, Ankaa. Feasibility conditions: claim github.com/nau-os (the `nauos` org is a squatted-empty 2022 shell), register nauos.dev and nau-os.dev while free, publish any Rust tooling as `nau-os`/`nauos` (crates.io `nau` is held by a dormant 85-download hobby crate).

## Decision

1. CLI, binary, crate-namespace root, and project name: **shuttle**. Distro name: **Nau** (amended 2026-09-20 from ShuttleOS via Cassini; owner constraints: no "OS" suffix, cross-language pronounceability, short). Release codenames are mission names, Cassini first. Canonical forms, one per surface: prose "Nau"; `NAME="Nau"`, `PRETTY_NAME="Nau 1.0 (Cassini)"`; org github.com/nau-os (contingency getnau → nau-linux; the squatted `nauos` org is never chased); domain nauos.dev (contingency nau-os.dev → naulinux.org); crates `nauos` (bare `nau` is never used); no `nau` binary exists (naming invariant). Pronunciation guide ships with the brand docs (per-language table incl. the accepted French /no/ reading). Trademark pre-release gate, blocking: re-run the name-collision sweep, confirm no Class 9 NAU software filings, verify claimed handles/domains match this matrix; any hit escalates to the owner before release.
2. Clean break — no compat shims, no old-name fallbacks: `shuttle.lua`, `shuttle.lock`, `~/.cache/shuttle/`, `DEFAULT_INPUT_URL = github:rbelem/shuttle/main`, `99-shuttle.conf`, `shuttle-prelude`.
3. GitHub repo renamed to `rbelem/shuttle` (GitHub redirects old URLs indefinitely); local remotes updated.
4. Historical artifacts stay untouched: `docs/adr/0001-0009`, `.planning/` archives, handoff files, `.opencode/` scaffolding.
5. **Naming invariant** (binding on all future work): paths on disk carry the name (`~/.cache/shuttle/`); domain concepts never do ("the store", "generations" — never "shuttle-store"); digests and stored metadata never embed the name (format-version numbers instead); the DSL stays name-free (`snap()`, `image()`, `merge()`, `pin()`, `index()`).

## Alternatives considered

- **blastoff** — council's unanimous #1 for the CLI (free on crates.io, clean search). Rejected by owner in favor of the ShuttleOS/shuttle split.
- **Keep shoot** — zero cost, but forfeits the reset moment; rejected.
- **padshot / sling** — semantically thin / noisy; dominated.
- **ShuttleOS → Cassini → Nau** (amendment path): ShuttleOS carried the banned "OS" suffix; Cassini was the owner's release-name pick, demoted to the 1.0 codename; Nau won on owner preference plus evidence.
- Amendment-round candidates (2026-09-20 sweep): **Orbit** (blocking: orbit-os.org is an active embedded Linux with the same A/B-update concept), **Ground Control** (blocking: active MDM company + LaunchDarkly product), **Tranquility** (blocking: tranquilityos.com is a live commercial "AI OS"), **Spaceport** (clean but bare crate `spaceport` taken; weaker phonetic consistency), **Blastoff** (clean everywhere, but reads as an event, not a place to live), **Alcantara** (clean, but the Italian fabric company owns adjacent mindshare).
- Later-round finalists (2026-09-20, same day): **Jezero** (clean; Mars crater, "lake"; owner: "good, not there"), **Naos** (owner favorite; BLOCKED by two existing OS projects + OS-adjacent crate + squatted domains), **Nave** (minor; runner-up; Italian ship + cathedral nave), **Falua** (clean; presidential barge), **Safina / Jangada / Canoa / Fragata / Karaka / Uru / Nostromo / Sulaco / Yamato / Daedalus / Roc / Stargazer / Baikonur / Omelek / Mahia / Andoya / Kiruna / Naro** (minor-tier; full findings in the 2026-09-20 sweep log).

## Consequences

**Positive**: one coherent brand family (shuttle builds Nau; Nau launches Cassini); rename landed before ADR-0011/0012 so they are born with the final name; naming invariant makes any future rename O(constants + docs).

**Negative**: accepted, permanent distribution tax — `cargo install` conflicts with cargo-shuttle's binary and "shuttle rust" search favors shuttle.dev. Future crates.io publication will need a suffixed crate name (`shuttle-os` / `shuttleos` are free).
