# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

One pipeline, two halves; the flow between them is the product (confirmed in the init interview, 2026-10-17).

- **Package builders** — developers who declare snaps, images, and pods in Lua and run nau builds. Situation: a terminal in their repo, driven by `nau.lua` and `pkgs/`; job: reproduce a package or a whole image without hand-written Snapcraft YAML.
- **Nau operators** — people who assemble, flash, boot, and run Nau systems, pods, and lanes. Situation: a machine or a small fleet; job: keep it on a known-good generation with verifiable trust and a rollback that always exists.

The halves feed each other: a builder's package enters a store, an operator's generation pins it, a release ships both to the download lane.

## Product Purpose

nau is a Rust CLI that builds Snap packages and bootable images from Lua declarations — "like Nix for Snapcraft" (`CONTEXT.md`), with Nix's declarative reproducibility and Neovim's Lua-based configurability (README). It assembles **Nau**: an immutable, verity-protected A/B Linux distribution whose releases are missions (ADR-0011/0012). The `www` surface is the family's front door: what Nau is, the mission roster, the download lane, and the verification walkthrough.

Success is the release-to-flash trust chain working end to end: Cassini (mission 1.0) published; a user flashing a mission image and proving it with `verify-image`; updates arriving A/B from the same lane. Current state: Cassini is "preparing for publication" — the download links 404 until it lands (`www/` copy).

## Positioning

One declaration path — `nau.lua` plus `pkgs/` — produces snaps, images, pods, and services, with inputs pinned by content hash and a lockfile (README, `CONTEXT.md`). One name spans the assembler (nau) and the ship it assembles (Nau); releases are missions sharing one vocabulary, one signed manifest, one trust chain (ADR-0013, ADR-0031, ADR-0044). The claim holds because the pieces are one system: the DSL, the store, the A/B update, and the release lanes are designed together — a neighboring product cannot truthfully copy one piece without the others.

## Operating Context

- **Repo-centric workflow**: `nau.lua` entry files; `pkgs/` package definitions; devbox-pinned Rust toolchain; `scripts/gate.sh` as the behavior pin; heavy compiles run on worker pools, never the workstation (AGENTS.md).
- **Trust rituals**: key ceremony; signed image manifests; `SHA256SUMS` + detached OpenPGP signature; flash by `/dev/disk/by-id/`; `nau verify-image` before first boot (ADR-0024, ADR-0044, `docs/nau-ops-runbook.md`).
- **Release rituals**: missions — 1.0 "Cassini", then Buran, Venera, Telstar, Leonov, Skylab, Soyuz, Zond, Lunik, Anik, Telesto, Mintaka, Ankaa (ADR-0013); one version, target matrix, and signed manifest per mission.
- **Lanes**: `www` / `download` / `cache` under `nau.rclb.dev` — static-only, no auth, no API, no state — expected to be served by a Nau deployment itself (ADR-0046). `rclb.dev` names stay canonical until the brand domains are registered after the trademark gate (ADR-0013 amendment).
- **Docs as evidence**: `CONTEXT.md` (domain glossary), `docs/adr/` (decision records), `docs/nau-ops-runbook.md` (execution pack), `.planning/` (plans).

## Capabilities and Constraints

- Confirmed functionality: builds `source`, `meta`, and `store` packages; snaps (SquashFS) and bootable images; system generations; pods (per-user selections, per-pod rollback); node/peer sharing over mDNS with signed-manifest verification; SSH-driven worker pool; content-addressed store (ADR-0033, ADR-0040, ADR-0012).
- GPL-3.0-only; Linux first (any distro, NixOS, WSL2); macOS unsupported today (README).
- The public web surface is static files: zero JavaScript, strict CSP (`script-src 'none'`), self-hosted fonts, no third-party requests (`www/DEPLOYMENT.md`).
- Explicitly undecided: the trademark pre-release gate (blocking for any public release under the name); brand-domain registration (`nauos.dev`, `github.com/nau-os`) deferred; crates.io `nau` claim undecided (ADR-0013 amendment, ADR-0031).

## Brand Commitments

- **Name**: `nau` lowercase on disk; prose "Nau" shared with the distro (ADR-0031). One syllable, /naw/ across PT/EN/DE/ES/IT; katakana ナウ; Mandarin "nao"; French /no/ is an accepted, documented quirk (ADR-0013).
- **Ship metaphor**: the distro is the ship; releases are missions; etymology ναῦς / navis — the root inside "astronaut" (ADR-0013). Mission names ship with the brand.
- **Naming invariant** (binding on all future work): paths on disk carry the name; domain concepts never do; digests and stored metadata never embed it; the DSL stays name-free (ADR-0013 D5, ADR-0031 D5).

## Evidence on Hand

Real: the repository and its ADR record; the two live `www` pages (`www/index.html`, `www/download.html`); `CONTEXT.md`; the runbook; `.planning/` plans; CI gates. Absent, and never to be fabricated: testimonials, user quotes, benchmarks, press coverage, adoption numbers, pricing. The distro is unreleased — every artifact claim must stay tied to real release state.

## Product Principles

1. **One pipeline, one name.** Builders and operators share one vocabulary and one story; design work never splits them into separate products.
2. **Declared, not managed.** Everything durable — packages, images, pods, services — is a declaration; verbs act on declarations instead of becoming admin surfaces (ADR-0032).
3. **Trust travels with the bytes.** Pin, sign, and verify at every boundary: download, flash, boot, update (ADR-0024, ADR-0033, ADR-0044).
4. **Tell the truth about state.** No fake artifacts, no invented links; the surface says what is released and what is still on the pad.
5. **Reproducibility by construction.** Content-hash pinning, lockfiles, pinned epochs — the same inputs rebuild the same bytes (README; pinned-epoch gate).
