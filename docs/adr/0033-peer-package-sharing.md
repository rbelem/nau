# Peer package sharing: masterless LAN-first P2P over the content store

## Status

Accepted (2026-09-19), revised same day after a two-seat council review. The
revision corrects the central premise (the signed package manifest is a new
artifact, not an existing one — see Decision 2), adds a normative wire
grammar to the serving surface (Decision 4), and tightens the verification,
freshness, and store-scope statements per the council findings. Revised
again the same day after snapd-distribution research: the sharing surface is
restated as named distribution lanes (Decision 9) and gains a static-HTTP
export lane servable by any web server (Decision 10). Extends ADR-0012
(file-level content store), ADR-0010 (Luau language), ADR-0024 (key
ceremony, trusted-key distribution), and ADR-0032 (declared pod services).
Adjacent to ADR-0012 Decision 7 (distribution rides OCI registries):
complementary lanes, no override — see Decision 9.

## Context

Three distribution paths exist today: the Snap Store (`.snap` export format,
standing project constraint), OCI registries (`shuttle push`/`pull`, ADR-0012
Decision 7 / Phase 25), and local rebuild. All three are wrong-shaped for the
common fleet case — a ShuttleOS image, a lab of dev machines, a classroom —
where several peers hold or need identical package content on one LAN and no
registry exists.

What the store already provides: sha256-addressed content blobs
(`src/runtime.rs` `blob_path`, layout `runtime.rs:7-16`,
`store/<aa>/<sha256>` per `farm.rs`), and the ed25519 signing +
trusted-key-verification machinery of the image path (`src/sign.rs`,
ADR-0024 ceremony). What it does **not** provide: a signed, per-package,
shareable manifest. The generation `manifest.json` records per-package file
hashes but is unsigned derived local state; `ImageManifest` signs image-level
eval output against sha3-384 Snap Store payload pins, not store blobs; the
`SignatureEnvelope` is a channel/batch envelope, not an artifact. The install
path is currently fail-open on unsigned manifests (note-and-proceed,
`SignatureEnvelope::default()` at every production call site). Sharing is
therefore not zero-new-format work; Decision 2 owns the one genuinely new
artifact.

Owner requirements from the grill:

1. P2P sharing of packages between shuttle machines.
2. All shuttle configuration stays in Lua (`shuttle.lua` configures all
   shuttle details, including sharing).
3. The "master" question, settled as Decision 1 below: there is none.
4. Plain HTTP sharing too: P2P is one way to move packages, a dumb static
   web server is another — and the way snapcraft/Ubuntu Core do it today
   should be supported.

How the snap world distributes today (verified against snapd source and
current docs, 2026-09): the Snap Store API is HTTPS-mandatory with an
assertion chain (account-key → snap-declaration → snap-revision; SHA3-384
blob integrity), and plain HTTP is never allowed — the base URL is
hardcoded, with no config key to downgrade. `snap install <URL>` does not
exist: snapd treats any argument containing `/` as a local path, so URL
install is a long-standing gap filled only by manual `wget` + `snap
install`. The sanctioned fleet/air-gap paths are heavyweight: the
`snap-store-proxy` snap is deprecated in favor of `enterprise-store`
(offline mode exists, but requires TLS with its own CA distributed to
devices), and UC20+ seeding bakes snaps into the image via the model
assertion (store base URL is not a runtime setting; the model's `store`
header is the sanctioned redirect). The offline sideload flow —
`snap download` producing a `.snap` + `.assert` pair, installed after
`snap ack` — is the lightweight Canonical-sanctioned path. Nix and Guix
prove the model this ADR adopts for the missing lane: a bare static HTTP
directory (narinfo + nar blobs / guix publish) with ed25519 signatures
verified against out-of-band-distributed public keys; any web server
suffices, plain HTTP allowed.

## Decision

1. **Masterless. There is no network-level master role.** Authority comes
   from signing keys, not node roles: a peer accepts a package when its
   signed PackageManifest verifies against the local trusted-key set
   (Decision 7), regardless of which node served it. "Master" survives only
   as the *origin peer* — the first entry in `node {}.peers`, a default pull
   source exactly like a git remote named `origin`: a hint, never a
   privilege. The word *master* is avoided in code, docs, and CLI
   (CONTEXT.md: Node, Peer).

2. **The signed PackageManifest is the one new artifact, defined here.**
   What travels between peers is a PackageManifest plus the store blobs it
   references — never a monolithic `.snap` (that stays the Snap Store/OCI
   export format). Schema (canonical JSON, canonicalized and signed with the
   same machinery as the image manifest, `src/sign.rs`):

   - `name`, `version`, `revision` (monotonic per name; freshness policy in
     Decision 7), `target` (GNU triplet),
   - `files`: array of `{ path, sha256, executable }` — the store blob set,
   - `install`: the metadata recorded at install time today by parsing the
     payload's `snap.yaml` (`runtime.rs:174-200`) — apps, launchers,
     services, confinement — because a receiving peer must reconstruct an
     installable entry from the manifest alone, and file hashes alone cannot
     (council finding: metadata must travel, not be re-derived),
   - `signer` key id + ed25519 signature over the canonical bytes.

   **Minting**: shuttle mints and signs a PackageManifest whenever it writes
   a package into a pod store it manages — at build time and at peer-ingest
   time. Unsigned store entries are never served. Consequence: re-serving
   content originally pulled from the Snap Store re-signs it under the
   serving operator's key, moving provenance from snapd assertions to that
   key (accepted; the SLSA-lite provenance machinery in `sign.rs` may later
   bind original materials). This manifest is new code — schema, canonical
   bytes, minting hooks — and is the price of admission for the whole
   feature; "acceptance is free" was the council-rejected framing.

3. **LAN-first discovery; explicit addresses for WAN.** Serving nodes
   announce via mDNS (`_shuttle._tcp.local.`); `shuttle pull` can browse
   the LAN. WAN peers are addressed explicitly
   (`shuttle://host[:port]/<pkg>`) or reached over a VPN. No relay, no NAT
   traversal in v1. mDNS resolution is unauthenticated and raceable — it is
   discovery only, never trust (Decision 7).

4. **Transport: plain TCP, minimal HTTP/1.1 subset — with a normative wire
   grammar.** Read-only endpoints on one configurable port (default 7780,
   unprivileged): `GET /info`, `GET /manifests/<pkg>`, `GET /blobs/<sha256>`.
   The client side is not new code: peer `pull` rides the repo's one network
   convention, curl behind `CommandRunner` (`src/oci.rs`); only the server
   is genuinely new.

   **Wire grammar (normative — safety is conditional on it, not intrinsic
   to "read-only"):** a blob path segment is exactly 64 lowercase hex,
   resolved through the store's blob-path API, never a raw `join` — a naive
   join turns `GET /blobs/../../.config/shuttle/secret-key` into an
   unauthenticated arbitrary-file read of the signing key over plaintext
   HTTP (council exploit path). A package name is `[a-z0-9-]` (the
   ADR-0032 collision-classifier charset). Anything else is 404. Request
   line and headers are size-capped, every connection gets read/write
   timeouts and the server holds a connection-concurrency bound (the
   `oci.rs` bounded-timeout precedent) — a bare `TcpListener` has no
   slowloris defenses by default.

   Dependencies, stated honestly: the server is std-only; discovery adds
   **one new runtime crate** (`mdns-sd`, synchronous pure Rust) plus its
   transitive tree, to be enumerated from actual `cargo tree` output at
   implementation time and justified per the `Cargo.toml` norm. Fallback if
   the tree is judged too heavy: the subprocess convention
   (`avahi-browse`/`resolvectl`), mirroring curl. No tokio, no hyper, no
   libp2p, no BitTorrent.

5. **Verbs and scope: `shuttle serve` foreground; `pull` gains peer
   references; v1 scope is the pod store.** `shuttle serve` evaluates
   `node {}` from `shuttle.lua` and serves the invoking user's **pod store**
   — the store it can write unprivileged — until interrupted. `shuttle pull
   shuttle://host[:port]/<pkg>` verifies and stages the PackageManifest +
   missing blobs into the local pod store; installation is the existing pod
   workflow, not a pull side effect (a deliberate contrast with
   `pull --install`). Persistence is not a shuttle verb: keeping `serve`
   running is a declared pod service (`services = { … }` running
   `shuttle serve`), riding the ADR-0032 emitter machinery — declarative,
   never verb-managed, no built-in daemonization. Serving the **system**
   runtime store (`/var/lib/shuttle`, root-owned) on ShuttleOS devices is
   out of v1 scope: ADR-0032 services are user-level and pod-scoped, and a
   user unit cannot read the system store — that needs a system-scope
   service story and is recorded as a revisit trigger, not hand-waved.

6. **Config: a `node {}` declaration in `shuttle.lua`.** Evaluated in the
   same pass as the rest of the file and carried to Rust in the eval
   payload (today's eval yields image/snap outputs only — the payload gains
   a node field). The Lua-side validator joins the `snap()` / `app()` /
   `image()` validators in `dsl/init.lua` (the DSL exports
   `snap/app/image/index/fetch/pin/merge`; note `pod {}` is validated in
   Rust, `pod.rs` — not a precedent for this one). Language per ADR-0010
   (Luau); the Lua-DSL-as-schema principle traces to ADR-0002.

   ```lua
   node {
       name = "devbox",
       serve  = { address = "127.0.0.1:7780", announce = true },
       peers  = { "shuttle://nuci.local:7780" },  -- first entry = origin peer
   }
   ```

   The example binds loopback by default; `0.0.0.0` is an explicit choice
   the operator types, not a default (council note: `/info` publishes the
   package inventory to everyone who can reach the socket). Absent
   `node {}` means zero behavior change: no sockets, no discovery, no new
   processes. One file configures all shuttle details, build and share
   alike.

7. **Verification: fail-closed, strict-set, downgrade-refusing — a
   tightening of today's path.** Peer pull uses `verify_trust_set`
   semantics (revoked-first; the ANY-anchor `verify_keychain` is never
   acceptable on the peer path), consulting the anchor sources the runtime
   already consults: the device image-baked set (`/etc/shuttle/trusted-keys`
   + `revoked-keys`, ADR-0024) and the operator keychain
   (`~/.config/shuttle/keys/`). An unverified manifest is refused and named,
   never provisionally accepted, never TOFU. **This is stricter than both
   existing precedents** — the OCI path verifies self-consistency (opt-in
   `--expect`), and the runtime install path is fail-open on unsigned
   manifests today. The tightening is peer-lane-only in v1; extending
   fail-closed verification to the runtime install path is a recorded
   revisit trigger, not a silent scope grab. **Freshness**: a manifest whose
   revision is older than the installed one for that name is refused unless
   `--allow-downgrade` is explicit; where `shuttle.lock` pins exist, they
   bind, per the `pull --install` precedent.

   Anchor distribution is out-of-band, full stop: the key ceremony has no
   distribute verb today (`shuttle key` = keygen/rotate/promote/revoke/
   list/verify), and transporting anchors over the peer channel itself
   would invent TOFU over plaintext HTTP. A key-distribution mechanism is a
   revisit trigger, designed against that failure mode.

8. **Security posture notes.** The trust set is flat: any trusted key can
   sign any package name — no key→namespace scoping exists (inherent to
   ADR-0024; P2P broadens exposure versus the OCI path, where registry
   accounts namespace packages). TLS is rejected on the LAN path for
   integrity reasons (signatures + hashes suffice) but **confidentiality is
   genuinely lost**: package content and the `/info` inventory cross the
   LAN in cleartext; the VPN caveat covers WAN only. Recorded as accepted
   loss plus revisit triggers, not as a non-issue.

9. **Distribution lanes, named.** Shuttle moves packages over four lanes,
   each with different infrastructure needs and one shared content format
   (PackageManifest + content-addressed payloads where shuttle-native):

   | Lane | Transport | Infrastructure | Status |
   |---|---|---|---|
   | Snap Store | HTTPS + assertions | Canonical's (api.snapcraft.io) | Existing (`src/store.rs`, `pin()`, image builds) — the Ubuntu-native path, unchanged |
   | OCI registry | HTTPS/plain-HTTP registry | One registry host | Existing (`push`/`pull`, ADR-0012 Decision 7) — WAN/CI/archive |
   | Peer-to-peer | HTTP subset + mDNS | None (peers serve themselves) | This ADR — LAN/ad-hoc, `shuttle://` references |
   | Static HTTP | Any web server (nginx, S3, GitHub Pages) | A directory to upload | This ADR (Decision 10) — cold mirrors, DMZ/air-gap handoffs, `http(s)://` references |

   Surfaced explicitly against ADR-0012 Decision 7 ("distribution … rides
   ordinary OCI registries"): the peer and static lanes add coverage for
   the no-registry, no-network cases; nothing replaces that decision.
   Note the snap-world contrast: snapd cannot consume any of these lanes
   except the Snap Store itself (HTTPS + assertions only; no URL install),
   so the static and peer lanes are shuttle-to-shuttle by design —
   authority comes from the PackageManifest signature, not from snapd
   assertions. Content destined for stock snapd keeps riding the existing
   `.snap` export lane (plus `.assert` pairs where offline snapd install
   is the target).

10. **The static-HTTP lane: an export tree any web server can serve.**
    `shuttle export <dir>` writes the store's shareable content as a
    plain directory tree: `index.json` (the `/info` payload),
    `manifests/<pkg>.json` (signed PackageManifests), `blobs/<sha256>` —
    the same layout the serve endpoints expose, one-to-one, so
    `shuttle serve` is simply a dynamic view of the tree a mirror
    freezes. Uploading the directory to any static host publishes the
    content; no shuttle code runs server-side. `shuttle pull` accepts
    `https://mirror.example/shuttle/<pkg>` and plain `http://` references
    beside `shuttle://` peer references — same verification path as
    Decision 7 (signature first, then hash-checked blobs), independent of
    origin. This is the Nix/Guix pattern applied to the store (Context:
    static HTTP + offline ed25519 signing), and it fills the gap snapd
    never closed: URL-based install of verified packages from
    infrastructure that is just files. Serving a tree requires nothing of
    the server — no CGI, no TLS, no CA distribution — which is exactly
    what the snapd world's own air-gap paths fail to offer.

    ```bash
    shuttle export site/                     # freeze a shareable tree
    # upload site/ to any web host, then on any machine:
    shuttle pull https://mirror.example/shuttle/git
    ```

    Wire-grammar rules (Decision 4) apply to static pulls unchanged, with
    the client strictly requesting only well-formed names — the traversal
    hazard is a serve-side concern, and the export tree contains no
    secrets by construction (it is manifests and blobs the operator chose
    to publish).

## Alternatives considered

- **Declared hub role (`node { role = "hub" }`).** Rejected as a *role*:
  it creates a center of failure for pushes and drifts the design toward
  client/server. The legitimate need (a fleet rendezvous point) is met by
  `announce = true` plus naming the hub as every peer's origin.
- **Implicit seed-on-build (whoever builds publishes).** Rejected: sharing
  becomes ambient state no declaration describes — the exact defect
  ADR-0032 removed for services. Noisy on shared LANs, nothing to audit,
  nothing to turn off except not building.
- **BitTorrent / libp2p transport.** Rejected for v1: heavy dependency
  trees into a sync, vendored-dep-light codebase, and swarm dynamics are
  unnecessary where one origin serves a handful of LAN peers. The
  manifest/blob seam keeps a torrent backend open as a later transport
  choice (Revisit triggers).
- **P2P over monolithic `.snap` files.** Rejected: contradicts the
  ADR-0012 native format, forfeits file-level dedup, and would make peers
  second-class compared to `shuttle install`.
- **LAN-local OCI registry (`registry:2` on one peer) instead of a peer
  protocol.** Rejected for v1: it works today with `push`/`pull` and zero
  new protocol code, but it reintroduces a service to operate (the thing
  the fleet case lacks), and it cannot express per-package discovery or
  pod-store staging. Recorded as the honest fallback if the peer lane
  stalls.
- **rsync/syncthing over content-addressed store directories with
  install-time gating.** Rejected: out-of-band sync of store internals
  bypasses manifest signing (trust becomes "whatever a peer's rsync
  delivered") and has no declared config surface.
- **Trust on first use (TOFU).** Rejected: silent trust acquisition
  contradicts the ADR-0024 posture where trust is always an explicit
  operator act (ceremony, promote, revoke).
- **TLS on the LAN path.** Rejected for v1: a certificate authority
  duplicates the key ceremony with worse tooling; signatures bind content
  to authority. Re-open for confidentiality, not integrity, per Decision 8.
- **Extend `push`/`pull` OCI verbs only (no peer lane).** Rejected: still
  requires a registry host, the exact infrastructure the fleet case lacks.
- **`.snap` + `.assert` pairs as the offline exchange format (the snapd
  sanctioned flow).** Rejected as shuttle's primary lane: it moves
  monolithic squashfs blobs (no dedup) and binds authority to snapd
  assertions rather than the ADR-0024 ceremony. Kept exactly where it
  belongs — the `.snap` export format stays the bridge to stock snapd
  installs, and `snap download`-style pairs remain the answer when the
  *consumer* is an unmodified snapd device.
- **enterprise-store (ex snap-store-proxy) as the fleet answer.** Rejected
  for v1: heavyweight (TLS with its own CA distributed to every device, a
  service to operate), and its authority model is Canonical's, not the
  local key ceremony. The peer + static lanes cover the same need with
  zero server infrastructure; the OCI lane covers the
  registry-shaped case.
- **Ride snapd's model-assertion `store` header to redirect devices.**
  Rejected: it is a ShuttleOS/image-build concern, not a sharing lane —
  and shuttle's own image path already pins store snaps via `pin()`
  (ADR-0019).

## Consequences

**Positive**: LAN fleets share verified package content with zero
infrastructure; dedup is free (blobs already content-addressed); the
PackageManifest gives the store its first per-package signed artifact, which
the runtime path may adopt later; no behavior change without `node {}`; all
sharing config stays in the one Lua file; the protocol is curl-debuggable on
both ends; the origin-peer idea gives fleets their hub without a role.

**Negative**: the PackageManifest is real new surface — schema, canonical
bytes, minting hooks at build and ingest, and a metadata-travel contract
that must track `snap.yaml`-derived install metadata as it evolves; two
transports to build and test (HTTP subset + mDNS), and mDNS availability
varies — corporate WLANs often filter multicast, where explicit peer
addresses degrade gracefully but discovery is absent; WAN peers need
explicit addresses or a VPN until relay/NAT traversal exists (deferred);
confidentiality on the LAN is forfeited (Decision 8); `/info` discloses the
pod inventory to anyone who can reach the socket, and the loopback default
trades convenience for that exposure; the v1 scope is pod stores only, so
the flagship ShuttleOS fleet case cannot serve its system store until a
system-scope service story exists; serving is unauthenticated — a peer
return for abuse (rate limiting) exists only as a trigger; and a flat trust
set means one compromised builder key can sign any package name.

## Revisit triggers

- The runtime install path's fail-open posture on unsigned manifests should
  converge with the peer lane's fail-closed rule — re-open when the
  minting hooks (Decision 2) exist on the runtime side.
- ShuttleOS fleet serving of the system store (`/var/lib/shuttle`) → needs
  a system-scope service story; re-opens with the ADR-0032 backend family.
- WAN swarm demand (many peers, one slow origin) → torrent backend behind
  the same manifest/blob seam.
- Peer sharing crosses untrusted networks without a VPN → TLS or a
  noise-pattern handshake, re-evaluated for confidentiality (Decision 8).
- Private packages or inventory privacy becomes a requirement →
  key-gated endpoints or discovery opt-outs on `/info`.
- Fleet key-distribution at scale → a signed key-set manifest mechanism,
  designed so anchors never ride the peer channel (Decision 7).
- Corporate WLANs with filtered multicast → unicast/DNS-SD discovery
  fallback.
- `serve` exposed beyond the LAN → rate limiting and abuse posture.
- A fleet genuinely wants push semantics (C2-style distribution) → re-open
  the hub-role alternative with the push-target obligations spelled out.

## Evidence

- Native store layout and sha256 blob addressing: `src/runtime.rs`
  (layout comment, `blob_path`), `src/farm.rs` (`store/<aa>/<sha256>`).
- **Absence** of a signed per-package manifest (the council's core
  finding): `ImageManifest` signs image-eval output with sha3-384 Snap
  Store pins (`src/manifest.rs`); the generation `manifest.json` with
  per-file sha256 records is unsigned (`src/runtime.rs`); `SignatureEnvelope`
  is a batch envelope; production call sites pass
  `SignatureEnvelope::default()` (`src/main.rs` push/pull paths).
- Fail-open install posture: unsigned manifests note-and-proceed
  (`src/runtime.rs` install path).
- Verifiers: strict `verify_trust_set` (revoked-first) vs ANY-anchor
  `verify_keychain` (`src/sign.rs`); anchor sources consulted at
  `src/runtime.rs` (device set + operator keychain); ceremony verbs
  (`src/cli.rs` `Key` subcommand) have no distribute/import.
- Fail-closed transfer precedent (partial): `src/cli.rs` `Push`/`Pull` —
  sha256-verified blobs, opt-in `--record`/`--expect` cross-check;
  `pull --install` lockfile pin-binding (`src/main.rs`).
- Network conventions: curl behind `CommandRunner` with bounded timeouts
  (`src/oci.rs`).
- Declarative persistence: ADR-0032 Decisions 2, 5, 8 (declared services
  through emitter backends; user-level scope; the reconcile tail owns
  activation); pod validation in Rust (`src/pod.rs` `evaluate_pod_source`).
- DSL validators and exports: `src/dsl/init.lua`
  (`snap`/`app`/`image`/`index`/`fetch`/`pin`/`merge`); language per
  ADR-0010; Lua-DSL-as-schema principle per ADR-0002.
- Snapd distribution research (2026-09, primary sources): store base URL
  hardcoded HTTPS in snapd (`store/store.go`; `Snap-Device-Series: 16` +
  device headers); assertion chain account-key → snap-declaration →
  snap-revision with SHA3-384 blob integrity; `snap install <URL>`
  unsupported — `isLocalContainer()` (`cmd/snapd/cli/cmd_snap_op.go`)
  treats any argument containing `/` as a local path; `snap-store-proxy`
  deprecated in favor of `enterprise-store` (offline mode, TLS with own
  CA via `core.store-certs.*`); UC20+ seeding via model assertion with
  the `store` header as the sanctioned store redirect; offline sideload
  = `snap download` pair + `snap ack` (no `--dangerous`), while
  `--dangerous` skips signature verification only.
- Static-HTTP precedent: Nix binary cache (`nix-cache-info`,
  `<hash>.narinfo` with ed25519 signatures, `/nar/` blobs; any static
  server; `trusted-public-keys` out-of-band) and `guix publish` (`-k`
  signing, unsigned-substitute rejection) — nixos.org and gnu.org
  manuals.
