# ADR-0043: remote build cache — a cache content type over the ADR-0033 lanes

## Status

Proposed. Drafted 2026-09-27 from `.planning/remote-cache-plan.md` v3
(four-seat council review round 2: agree-with-changes ×4, corrections
folded; key scoping resolved by the operator the same day). Requirement
from the operator: the build cache must be reachable over HTTPS from the
internet and over P2P, with P2P used mostly on the local network. First
lane: `https://cache.zet.rclb.dev/shuttle-cache/`
(`.planning/server-infra-plan.md`).

## Context

The build cache is closure-keyed, immutable, local-only (`~/.cache/
shuttle/pkgs`, v4 key, existence-only lookup), and its consumer is the
build path (`ensure_dep_payload`, and its pod twin
`ensure_pod_dep_payload`) — not the pod store. No lane carries it: the
ADR-0033 manifest is name/version/revision-keyed with install metadata,
a different content class. The clause to reverse originates in ADR-0022
Decision 4 ("no remote build farm, no remote cache, no substituters")
and is preserved by ADR-0040 Decision 1.

This ADR changes one thing about the model: the cache becomes a second
signed content type riding the existing four ADR-0033 lanes. Not a new
lane, not a substituter service, not a new trust machinery.

## Decision

1. **CacheManifest** — a signed canonical-JSON kind beside
   PackageManifest, same machinery (`src/sign.rs`). Fields: closure key
   (the v5 hash, build-perf item 1a), target arch, human summary
   (name/version/recipe), blob sha256, blob size, packer identity
   (mksquashfs binary + compression + level), signer key id + ed25519
   signature. Identity is the closure key; entries are immutable, so
   revision/freshness and a downgrade gate are absent by construction.
2. **Two rules close what immutability opens.** Equivocation: two validly
   signed manifests for one closure key with different blob digests have
   no revision to order them — the consumer refuses the key on any signed
   conflict, fail-closed. Store-under-local-digest: artifacts are stored
   under the digest the consumer computes itself, never a remote-declared
   one (hash-then-store).
3. **Consumer seam**: `ensure_dep_payload` and `ensure_pod_dep_payload`
   gain the same fetch order — local cache, then configured lanes (LAN
   peers via browse/origin, HTTPS mirrors), then build. Leaving the pod
   path out would let a fleet share the cache while every pod still
   builds its own closure members. The pod downloads dir joins in the
   item-1a wave: it first needs the real closure key (today it has
   none); `force_build` remains the drift escape. Fetch is host-side
   only, before the sandbox (ADR-0039 untouched), through the curl
   convention with bounded timeouts — and lanes inherit the recorded
   clean-env trap: fetch TLS fails behind the pod's leaked
   `LD_LIBRARY_PATH`.
4. **Publish seam**: `shuttle serve` and `shuttle export` gain the cache
   content type; a cache export tree is servable by any web server
   exactly like Decision 10. Minting point: **sign at publish time**
   (serve/export), matching ADR-0033 D2 — signing at build time would
   land D2's deferred follow-up and put operator keys on build machines.
   The build-perf item-1b local sidecar stays schema-canonical and
   unsigned. Persisting `serve` remains a declared pod service
   (ADR-0032); no new daemon (ADR-0011 D5).
5. **Trust**: signature over manifest, digest over blob, fail-closed,
   strict-set with revocation; revocation is checked against current
   lists on local reuse, not only at ingest, so a later revocation
   un-poisons cached entries. Anchors travel out-of-band (D7). Wire
   grammar: D4 is amended with `GET /cache/<key>.json` (the
   `[a-z0-9-]` grammar of `manifests/<pkg>` cannot hold a 64-hex key)
   and a `cache/` export subtree; `/blobs` is NOT widened to build
   artifacts — cache and store blobs stay disjoint namespaces until
   build-time minting exists (open call 4, 4/4).
6. **Lanes are configured, never discovered into trust.** Builds consume
   cache lanes only when `shuttle.lua` declares them, mirroring
   `node {}.peers`. LAN-auto consumption defaults off — rejected 4/4
   because it widens a compromised key's blast radius from pulled
   packages to every build input, breaks the "absent key = zero
   behavior change" posture, and repeats the implicit-seed pattern
   ADR-0033 rejected; even enabled it would refuse unsigned entries.
   Discovery is never trust (D3). WAN confidentiality rides TLS from
   the web server; LAN stays cleartext with the recorded accepted loss
   (Decision 8). Anchors never ride the wire.
7. **Supersession, precisely scoped.** This ADR satisfies ADR-0040 D1 —
   result sharing still rides ADR-0033's lanes; it is a new content
   type, not a new lane and not a substituter. It reverses the
   preserved ADR-0022 D4 cache half. It reverses ADR-0040 D6's
   separate-namespace protection: worker job-manifest identity and
   cache identity converge on the v5 key, with D7's fabrication-hazard
   controls kept intact and applied to cache entries (determinism
   cross-checks remain the interim control).
8. **Key scoping: flat trust set for v1** (operator, 2026-09-27). The
   scoped `cache-signer` role fires on whichever comes first: a second
   signer key, or the cache serving installable payloads.
   `examples/rebuild-compare.sh` spot-checks are the interim control.
9. **Retention precedes publishing.** The publisher is #270 (blobs-
   then-manifest, skip-existing blobs, unconditional manifest re-PUT
   with bytes-compare); the floor is the infra plan's two-tier age
   prune (manifests 30d, blobs 90d, prefix-scoped, under flock), with
   reference-scanned deletion as the upgrade. Published-tree hygiene
   follows Decision 10's ownership-marker semantics plus a cache-tree
   marker: a stale package manifest is harmful, a stale cache entry is
   inert (immutable, key-addressed, digest-checked) — mirror pruning is
   lazy, manifest-first, and never touches a foreign directory.

## Alternatives considered

- **LAN-auto consumption on by default.** Rejected 4/4 (open call 1).
- **Build-time minting** (sign during the build). Rejected for now: puts
  operator keys on build machines, lands D2's deferred follow-up; the
  publish-time mint covers v1.
- **S3 semantics in the consumer** (an S3 client reading a bucket).
  Rejected: the lane is a static tree over plain HTTPS — any web server
  serves it, the consumer rides curl, and storage stays untrusted by
  construction (this ADR's premise, confirmed by the infra work).

## Consequences

**Positive**: a fleet shares builds through the same signed-manifest
machinery users already trust; pods and host builds converge on one fetch
order; the first real lane costs one bucket and one Caddy vhost.

**Negative — named, not hidden**: the transitive amplifier. A poisoned
cache entry becomes a build input of every downstream package, so the
blast radius of one compromised key is the whole build graph. The flat
v1 trust set sharpens this; the interim controls are mandatory digest
validation, mandatory signatures, revocation-on-reuse, and the
rebuild-compare ritual. The ritual's soundness precondition —
full-pipeline build determinism — is gate-pinned
(`tests/payload_reproducibility.rs` for packing,
`tests/payload_reproducibility_build.rs` for the full build_snap
pipeline; the A2 serialization bistability was root-caused and fixed in
c55bcef). Per-lane compression forks the namespace
explicitly (compression is inside the v5 key): each (closure,
compression) pair is a distinct valid entry — pin one compression per
lane role (zstd for LAN; xz or higher zstd for WAN) rather than leaving
per-blob discretion.

## Revisit triggers

- The cache-signer trigger (second signer key, or installable payloads
  in the cache).
- Build-time minting, if provenance pressure demands it.
- Blob dedup across content types, behind separate endpoints.
- LAN-auto consumption: stays rejected absent a trust-model change.

## References

ADR-0022 D4 (superseded cache half), ADR-0033 D2/D3/D4/D7/D8/D10 (the
lanes this rides), ADR-0040 D1/D6/D7 (preserved clause, reversed
namespace separation, fabrication controls), ADR-0024 (key ceremony,
revocation), ADR-0039 (offline sandbox boundary), ADR-0011 D5 (no new
daemon), ADR-0032 (declared services), ADR-0044 (mission images are a
different lane; Snap Store and OCI untouched; `.snap` stays the export
format only). `.planning/remote-cache-plan.md` (the reviewed source),
`.planning/server-infra-plan.md` (the first lane), `.planning/
build-perf-plan.md` items 1a/1b (the key and the sidecar). Issues #253
(this ADR), #270 (the publisher).
