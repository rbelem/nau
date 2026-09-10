# No `stage-packages` / `.deb` ingestion — snap content is source-built or store-pinned

## Status

Accepted (2026-09-09). Recorded by a council review of the gap analysis
(`.scratch/research/*`, 2026-09-09). Extends ADR-0012 (file-level
content-addressed store), ADR-0017 (dependency fetch), and ADR-0018
(build_deps split, leak scan). Naming invariant per ADR-0013 applies.

## Context

Snapcraft's single biggest ecosystem lever is `stage-packages`: it pulls
prebuilt Ubuntu-archive `.deb` payloads into a part's stage directory without
building them. Shuttle has no analog — packages come from `source` builds out
of `pkgs/` or from store-pinned snaps, plus ecosystem dependency closures
(npm/pip/cargo/go, ADR-0017).

This was previously *silent* rather than decided. The council review named it:
an unrecorded omission is a future accidental re-introduction, so it must be
recorded as a decision — adopting it, or refusing it on the record.

## Decision

**Refuse `stage-packages` / `.deb` ingestion. Record it as an explicit
non-adoption.**

1. **No Ubuntu-archive `.deb` payload path.** Shuttle does not download,
   extract, or stage `.deb` files to satisfy package content.
2. **Libraries are pool packages, built or store-pinned.** A library a source
   package links against is a `pkgs/` package (source-built) or a store-pinned
   snap, declared in `requires` (runtime) and/or `build_deps` (build-time,
   ADR-0018).
3. **Toolchains are pool packages.** Compilers and build tools come from
   `toolchain-*` meta-packages and plugin-contributed `build_deps`, never from
   archive `.deb` staging.
4. **Dependency closures stay ecosystem resolvers.** npm/pip/cargo/go closures
   (ADR-0017) are content-hashed and lockfile-pinned; they are the only
   non-store ingestion path, and they are already covered by the closure-hash
   and offline-mount guarantees.

## Alternatives considered

- **Adopt `stage-packages` for ecosystem parity.** Rejected: it reintroduces
  un-hashed, host-archive-dependent content — exactly what the leak scan
  (ADR-0018) and the file-level content-addressed store (ADR-0012) exist to
  eliminate. A staged `.deb` payload is not content-addressed by shuttle, not
  lockfile-pinned, and varies with the archive snapshot at build time.
- **Adopt it behind a flag.** Rejected: a flag makes it a permanent
  compatibility surface; every consumer would key cache behaviour on whether
  it was set. No consumer exists, so the flag is speculative.
- **Adopt it only for store-pinned equivalents.** Rejected: store snaps already
  provide that path with revision pins and sha3-384 content hashes — reusing
  it is better than a second, weaker ingestion mechanism.

## Consequences

**Positive**: one coherent ingestion model (source-built or store-pinned, plus
hash-pinned ecosystem closures); content-addressing and lockfile pinning hold
across the whole package graph; no second supply chain to audit.

**Negative**: packages that exist only as Ubuntu-archive `.deb` payloads and
have no reasonable source build must be either source-built in `pkgs/`,
store-pinned, or explicitly out of scope — the "grab the distro's build"
convenience is genuinely unavailable. This is the accepted cost, consistent
with shuttle's source-first package model.

**Neutral**: `snapcraft.yaml` conversion tooling (if ever built) must flag
`stage-packages` as unsupported rather than silently dropping it.
