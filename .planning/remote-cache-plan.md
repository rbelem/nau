# Remote cache plan (HTTPS + LAN P2P)

Date: 2026-09-27. v3 — council review round 2 complete (4/4
agree-with-changes, corrections folded); Jev review of this version
follows. Requirement from the operator, 2026-09-27: the build cache must
be reachable over HTTPS from the internet and over P2P, with P2P used
mostly on the local network. This plan feeds ADR-0043; it changes no code
by itself. Companion: `.planning/build-perf-plan.md` (whose item 1a
builds the artifact this plan puts on the wire; item 1b is the sidecar
this plan defines).

## Current state

| Concern | Today | Where |
|---|---|---|
| LAN P2P lane | `shuttle serve` (GET /info, /manifests/<pkg>, /blobs/<sha256>, port 7780) + mDNS announce/browse; `shuttle pull shuttle://host[:port]/<pkg>` verifies fail-closed (ed25519, revoked-first, strict-set) then hash-checks blobs | docs/adr/0033 Decisions 3-7; src/serve.rs; src/pull_peer.rs; src/discovery.rs |
| Internet lane | Static export tree (`index.json`, `manifests/`, `blobs/`) served by any web server; `pull https://...` same verification; TLS belongs to the web server | docs/adr/0033 Decision 10; src/export.rs |
| Content format | Signed canonical-JSON PackageManifest (name/version/revision/files/install metadata/signer) + sha256-addressed blobs | docs/adr/0033 Decision 2; src/pkg_manifest.rs |
| Trust | ADR-0024 ceremony; anchor sources union (device baked + operator keychain); revocation; no TOFU; key distribution out-of-band | docs/adr/0033 Decision 7 |
| Build cache | Local-only, closure-keyed dirs under `~/.cache/shuttle/pkgs`, v4 key, existence-only lookup, plain-copy store | src/cache.rs; build-perf-plan item 1a upgrades this |
| Pod downloads dir | Existence-only cache, WEAKER than the pool cache: keyed on `name_version_arch` with no closure key, plus a `force_build` bypass | src/pod.rs:5938-5957, downloads dir at :5860; field-confirmed 2026-09-27 |
| Recorded constraint | The clause to reverse originates in ADR-0022 Decision 4 ("no remote build farm, no remote cache, no substituters") and is PRESERVED by ADR-0040 Decision 1:89-92 ("no remote cache, no substituters, no new content lane; result sharing stays on ADR-0033's lanes"). ADR-0040 D6 also deliberately kept worker job-manifest identity separate from the `v4:` cache namespace, and D7 records the fabrication-hazard controls | docs/adr/0022 D4; docs/adr/0040 D1, D6, D7 |

## The gap

No lane carries the build cache. The ADR-0033 manifest is
name/version/revision-keyed with install metadata; the build cache is
closure-keyed and immutable, and its consumer is the build path
(`ensure_dep_payload`, src/main.rs:925, and its pod twin
`ensure_pod_dep_payload`, src/pod.rs:5938), not the pod store. Serving it
means one new content TYPE over the existing lanes (not a new lane), two
seam extensions, and the reversal of one preserved clause.

## Design

**One seam, one new artifact** (subtract-before-you-add: every transport,
discovery, and verification decision below is already reviewed in
ADR-0033).

1. **CacheManifest** — a signed canonical-JSON kind beside
   PackageManifest, same machinery (src/sign.rs). Fields: closure key
   (the v5 hash), target arch, human summary (name/version/recipe),
   blob sha256, blob size (precedent: ADR-0040 D6's `{sha256, size,
   purpose}`), packer identity (mksquashfs binary + compression +
   level), signer key id + ed25519 signature. Identity is the closure
   key; entries are immutable, so revision/freshness and the downgrade
   gate are absent by construction — conditional on the rules below.
   Two council-mandated rules close the holes immutability opens:
   - **Equivocation rule.** Two validly signed manifests for one closure
     key with different blob digests have no revision to order them; the
     consumer refuses the key on any signed conflict, fail-closed.
   - **Store-under-local-digest.** Artifacts are stored under the
     digest the consumer computes itself, never under a
     remote-declared digest (hash-then-store).
2. **Consumer seam** — `ensure_dep_payload` (src/main.rs:925) AND the pod
   twin `ensure_pod_dep_payload` (src/pod.rs:5938) gain the same fetch
   order: local cache → configured lanes (LAN peers via browse/origin,
   HTTPS mirrors) → build. Leaving the pod path out would let a fleet
   share the build cache while every pod still builds its own closure
   members locally; the pod downloads dir first needs the real closure
   key from build-perf item 1a. Host-side only, before the sandbox:
   ADR-0039 untouched. Transport rides the curl convention (src/oci.rs
   bounded timeouts). Lane config must state the clean-env requirement:
   fetch() TLS fails behind the pod's leaked `LD_LIBRARY_PATH` (curl
   resolves the pod libcurl, whose CA bundle fails verification) — every
   network path in this plan inherits that trap.
3. **Publish seam** — `shuttle serve` and `shuttle export` gain the
   cache content type; a cache export tree is servable by any web server
   exactly like Decision 10. **Minting point (decided): sign at publish
   time** (serve/export), matching ADR-0033 D2's existing minting and
   its accepted provenance-move; signing at build time would land D2's
   explicitly-deferred build-time-minting follow-up and put operator
   keys on build machines. The local sidecar from build-perf item 1b is
   schema-canonical and unsigned; signing happens only where a key
   already lives. Persisting `serve` stays a declared pod service
   (ADR-0032); no new daemon (ADR-0011 Decision 5).
4. **Trust** — signature over manifest + digest over blob, fail-closed,
   strict-set with revocation, anchors out-of-band. Revocation is
   checked against current lists on local reuse (cheap), not only at
   ingest, so a later revocation un-poisons cached entries.
   Wire-grammar: ADR-0033 D4:141-147 reserves `manifests/<pkg>` for the
   `[a-z0-9-]` grammar — a 64-hex closure key does not fit, so ADR-0043
   amends D4 with a new path, `GET /cache/<key>.json`, and a `cache/`
   subtree in the export tree. Blob segments stay hex-addressed.
5. **Retention** — the unbounded-growth fix from build-perf item 1a is a
   prerequisite: one machine's cache serves a fleet, so prune/retention
   policy must exist before publishing. Field confirmation: single-machine
   retention is already broken — ENOSPC from build artifacts alone
   (per-lane `target/` trees filled /home to 100%) during the same week.

## ADR actions for ADR-0043

- **Supersede the preserved clause precisely:** ADR-0022 Decision 4's
  cache half, as preserved by ADR-0040 Decision 1. Frame it as
  SATISFYING ADR-0040 D1, not fighting it: result sharing still rides
  ADR-0033's lanes — this is a new content type over the existing four
  lanes, not a new lane and not a substituter service.
- **Ride the pre-sanctioned opening:** ADR-0040's own revisit trigger
  ("a `v5` key folding environment/layout/hooks/… into cache identity")
  explicitly anticipated and declined to smuggle this key work; ADR-0043
  cites it and also states the reversal of D6's separate-namespace
  protection (worker job-manifest identity vs cache identity) — with
  D7's fabrication-hazard controls (determinism cross-checks) kept
  intact and applied to cache entries.
- **Extend ADR-0033 scope explicitly:** CacheManifest as a second
  content type behind the same verification; D4 grammar amendment
  (`/cache/<key>.json`, `cache/` export subtree); D5 scope extension
  (serve/export beyond the pod store). Name what does NOT change: Snap
  Store and OCI lanes untouched; `.snap` stays the export format only
  (ADR-0012 D6). Note why D2's rejected "P2P over monolithic .snap"
  alternative does not apply: the cache blob is a build output, never
  installed — the packed snap IS the artifact, a different content
  class.
- **Confirm the operator call:** builds consume cache lanes only when
  configured (lanes declared in `shuttle.lua`, mirroring `node {}.peers`).
  No auto-discover-and-trust (council 4/4). LAN-auto consumption is a
  named alternative, defaulting off; even if enabled it would refuse
  unsigned entries — discovery is never trust (D3).

## Security deltas (cache-specific)

1. A poisoned cache entry poisons builds silently — and the consumer is
   `ensure_dep_payload`, so a poisoned entry becomes a build input of
   every downstream package: the blast radius is the whole build graph,
   not one package (the transitive amplifier; name it in the ADR).
   Digest validation is mandatory (build-perf item 1a's correctness
   gate); the signature is mandatory too, not optional.
2. Key soundness: peers serve artifacts to machines that did not build
   them, so the v5 key must capture everything the bytes depend on.
   Council round-2 correction (3/4 seats): key on the EFFECTIVE pinned
   toolchain and full build-input digest — NOT host compiler identity.
   The nix-gcc-wrapper incident (host 15.2.0 vs pinned 14.2) is a
   sandbox toolchain-leak bug to fix fail-closed, not a namespace field;
   keying host identity would make heterogeneous-fleet hits near zero
   and kill the operator's own requirement. Host identity survives as a
   verification assert (rebuild-compare across machines). Verified by
   `scripts/rebuild-compare.sh` + the #152 harness, not assumed.
3. Flat trust set sharpens: one compromised builder key poisons every
   peer's build inputs (transitively, per delta 1). Positions recorded
   for the ADR to settle — see open calls.
4. Inventory disclosure: `/info`-style endpoints now expose build recipe
   summaries, and the operator requirement puts cache trees on
   internet-facing HTTPS — `index.json` would publish them to anyone who
   can reach the mirror. Decide in the ADR: state the accepted exposure
   (D10's "no secrets by construction" argument covers manifests and
   blobs the operator chose to publish), or omit the index for cache
   trees. Carry over the loopback-default / explicit-bind posture.
5. WAN confidentiality comes free on the HTTPS lane (TLS from the web
   server); LAN stays cleartext with the recorded accepted loss
   (Decision 8). Do not put anchors on the wire.

## Bandwidth note (answers the squashfs plan's open question)

Cache blobs are the packed snaps themselves, already compressed —
transport compression wins nothing. ADR-0041's zstd default is ~5.5%
larger than xz; over WAN-heavy fleets that is recurring bytes. If it
matters: raise the zstd level for WAN-destined blobs, or pin
`compression = "xz"` for cache blobs intended to cross the internet.
Local-LAN peers keep zstd (faster packs, bigger blobs are free on LAN).
Wording corrected by council round 2: with compression inside the v5
key, per-lane compression choices fork the namespace EXPLICITLY — each
(closure, compression) pair is a distinct valid entry, and the cost is
duplicate storage per closure, not silent divergence. The ADR should
pin one compression per lane role (zstd for LAN, xz or higher-zstd for
WAN) rather than leaving per-blob discretion.

## Open calls

Positions from council round 2 (alpha/beta/gamma/delta), for ADR-0043 to
settle:

1. **Default posture: RESOLVED, config-gated (4/4).** LAN-auto widens a
   compromised-key blast radius from pulled packages to every build
   input, breaks the "absent `node {}` = zero behavior change" posture,
   and mirrors the implicit-seed-on-build pattern ADR-0033 rejected.
2. **Key scoping: UNRESOLVED, decide in the ADR.** Beta and alpha: flat
   set for v1 (scoping is an ADR-0024 ceremony redesign that does not
   exist; gate the lane on it and the feature dies), with a hard revisit
   trigger and `rebuild-compare.sh` determinism
   spot-checks as the interim control (mirroring ADR-0040 D7). Delta and
   gamma: a distinct key ROLE for cache artifacts from day one
   (`cache-signer`, a label plus its own anchor file — no new
   machinery), because cache compromise propagates into build outputs,
   a strictly larger blast radius than package installs. The middle
   option costs almost nothing and bounds the worst case; the flat
   option ships sooner. Council synthesis leans flat-for-v1 with the
   trigger condition spelled out: the scoping work fires on whichever
   comes first, a second signer or the cache serving installable
   payloads.
3. **Published-tree retention: RESOLVED in shape (4/4), details for the
   ADR.** Decision 10's `.shuttle-export` ownership-marker semantics
   verbatim, plus a cache-tree marker. Cache-specific asymmetry (delta):
   a stale package manifest is harmful (wrong version served), a stale
   cache entry is inert (immutable, key-addressed, digest-checked) — so
   mirror pruning can be lazy. Sweep order (gamma): delete manifest
   first, then zero-reference blobs; never prune a foreign directory.
4. **Blob dedup across content types: RESOLVED, disjoint namespaces v1
   (4/4).** Cache blobs are whole packed snaps; store blobs are
   individual files — nothing to dedup until build-time minting exists,
   and sharing storage entangles generation-rooted GC (ADR-0012) with
   cache LRU. Serving must not widen `/blobs` to build artifacts
   (grammar scope per content type). Revisit behind separate endpoints.
5. **Pod downloads dir: RESOLVED, adopt in the item-1a wave (4/4),**
   scoped out of the published cache namespace for v1 (gamma). It needs
   a real closure key first (today it has none); `force_build` remains
   the drift escape; leaving it existence-only while hardening its twin
   would leave a known-poisonable cache live on the operator's daily
   loop.

## Provenance

Drafted by the build-perf session (pane p12) from the operator's
requirement, reviewed in-place by sibling sessions pE (worktree/clone
lanes) and pZ (pod sync lane) over herdr on 2026-09-27; their corrections
are folded into the text above. Council round 2 (four seats,
agree-with-changes ×4) re-verified all citations and drove the v3
corrections: host-identity keying removed, item-1 split, minting point,
equivocation and revocation rules, D4 grammar amendment, ADR-0022/0040
supersession framing. Jev review of this version follows.
