# Build sandbox stays offline: no networked build mode

## Status

Accepted (2026-09-23). Two-seat council review on the #176 follow-up. Reaffirms
ADR-0004's offline build sandbox and ADR-0017's explicit rejection of networked
builds; extends ADR-0038's deny-by-default posture to the build axis.

## Context

Build sandboxes unshare the network (`--unshare-net`, ADR-0004): recipe SOURCE
fetches run host-side by design, and every sanctioned build-time input path —
`source`/`sources` (sha256-pinned), `deps` closures (ADR-0017), pod inputs — is
declared and content-pinned. #176 surfaced the consequence sharply: build-STEP
downloads (the uv/python recipe class fetching python-build-standalone inside
its build script) cannot work in sandboxes as-is, and the resolv.conf/hosts/CA
ro-binds plus the `CURL_CA_BUNDLE` default that landed in e10bc09 are
necessary-not-sufficient while `--unshare-net` holds. The follow-up decision:
either recipes with build-time downloads move those fetches into declared
sources, or a networked-sandbox mode is designed deliberately.

## Decision

1. **The build sandbox never gets a network.** `--unshare-net` is unconditional
   for every build step, in every mode. Degraded-direct execution (the
   bwrap-unavailable fallback, ADR-0004) runs with host network only because
   there is no boundary there; it is documented as a degradation, never a grant.

2. **Every byte a build consumes arrives via a declared fetch path** — host-side,
   content-pinned: `source`/`sources`, a `deps` closure (ADR-0017), or a pod
   input. A build script that downloads is a recipe defect. The fix is to
   express the download as a declared input or to extend the fetch machinery
   (a new resolver per ADR-0017's ecosystem-agnostic shape — e.g. a uv lock
   resolver is the sanctioned answer for the uv/python class), never to open
   the sandbox.

3. **The e10bc09 groundwork stays, scoped honestly.** The resolv.conf/hosts/CA
   binds and the never-clobber `CURL_CA_BUNDLE` default serve degraded-direct
   builds and any exec form where network legitimately exists; inside the bwrap
   sandbox they are inert. They are not a down payment on a networked mode.

4. **Sandbox loopback reachability is a non-goal.** Host-loopback-served input
   fixtures (dep_fetch loopback servers) serve the host-side fetch phase by
   design; builds have no reason to reach them.

5. **Escape valve for genuinely un-declarable dynamic fetches:** run the fetch
   as a `sandbox`-level pod exec with `network = true` (ADR-0038 — the user
   declares it), content-hash the output, and consume it as a declared source.
   Network lives where the user declared it; builds stay pure functions of
   hash-pinned inputs.

6. `warn_no_network_hint` remains the pointing finger; its text names
   `sources`/`deps` as the sanctioned paths.

## Alternatives considered

- **Deliberate networked build mode.** Rejected: a build runs arbitrary
  upstream build code, so network makes it an unpinned second-stage fetcher —
  whatever it lands in the `.snap` is absent from the lockfile's pin record
  (ADR-0017 D3/D5, ADR-0037 stop describing the payload). Already rejected
  outright in ADR-0017's Alternatives.
- **Per-recipe opt-in (`build_network = true`).** Rejected: a recipe-mediated
  trust inversion (third-party recipe code weakening every downstream
  consumer's posture), a two-tier reproducibility regime, and a permanent
  pressure valve. Nix's answer to the same pressure was the fixed-output
  derivation — pin the fetch, never free the network — and shuttle already has
  the FOD analog in `sources` + deps closures.

## Consequences

**Positive**: builds remain pure functions of hash-pinned inputs; the lockfile
fully describes every payload; posture stays coherent with ADR-0038's
deny-by-default; no new grant surface to audit.

**Negative**: recipe classes that download inside build steps must be rewritten
to declared inputs (recipe work, not code work — python/uv already comply);
growth lands as new host-side resolvers; authenticated registries remain a
host-side resolver concern.

## References

ADR-0004 (bubblewrap sandbox, offline), ADR-0017 (dependency fetch, offline
install, networked-build rejection), ADR-0038 (pod isolation, deny-by-default),
#176. ADR-0038 is pod isolation; the squashfs ADR renumbered to ADR-0041
(2026-09-26) after the tree briefly carried two 0038 files.
