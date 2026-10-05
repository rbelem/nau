# ADR-0055: Pool front — authenticated farm front and funnel lifecycle

## Status

Accepted (design), 2026-10-05. Produced from the 2026-10-05 incorporation
review (council round-2 verdicts + jev gates over the pod-services session's
productization scope). Implementation ticketed separately: the funnel
lifecycle ticket lands first (reachability precondition), the front verb
second.

## Context

The farm's publish/pickup path is currently assembled from operator-side
stopgaps: a hand-rolled `front.py` shim serving build-request publish and
artifact pickup, a manually managed tailscale funnel task, and manual token
files. Each piece works; the composition is where the week's evidence shows
failure:

- The shim lacked pin routes and single-shot curl handling — benchmark
  windows 1–3 burned on front defects before a build ever ran (window-4
  diagnosis), and the 0644 pin-install bug silently answered preflights with
  the distro mksquashfs.
- A half-dead `ssh -f -N -L` tunnel does not error; it hangs submits
  silently. The `ss -tln` pre-check is now skill law (nau-farm-ops), but the
  tunnel itself is still an unowned persistent process.
- The funnel is host-wide per host:port on this tailscale (AllowFunnel
  granularity): the public front had to move to 8443 so tailnet-only
  services kept 443. Nothing in nau owns that choice; it lives in session
  prose.
- `nau pool` today exposes only provision/destroy (`src/cli.rs` PoolCommand);
  there is no front verb. The POST-route machinery the front needs exists in
  `crates/nau-peer/src/serve.rs` (#328 scope, open).

This consolidates the operator seam named in ADR-0052's operational flow
(manual token + manual tunnels + ops-side shim) without touching ADR-0052's
settled scope: versions, build-requests, and server release remain that
ADR's; the front is a distinct surface over the same seams. Closed #306
(non-executable installs, single-shot curls) is the direct prior evidence
for this failure class.

## Decision

1. **nau owns the funnel lifecycle.** `nau pool provision` stands the
   tailscale funnel up (port 8443, the public front port) and
   `nau pool destroy` tears it down with the worker. No persistent manual
   funnel task. Provisioning already carries funnel URL plumbing
   (`provision/mod.rs` boot-scale funnel flaps); lifecycle ownership
   completes it.
2. **`nau pool front` replaces the shim.** One authenticated front serves:
   static files (the pins and artifacts the worker preflights against),
   build-request publish (POST route from nau-peer/serve), and artifact
   pickup — with the pin routes and multi-shot curl behavior the shim
   lacked.
3. **The public surface stays on its own port** (8443) and tailnet-only
   services keep 443 — encoding the AllowFunnel granularity as product
   behavior rather than operator folklore.
4. **Security stance:** the front is public-internet exposure by design
   (that is its job); bearer-token auth at the build-request seam (ADR-0052
   day-one model) applies to publish/pickup; static pin/artifact serving is
   unauthenticated read-only by choice — the bytes are hash-pinned
   consumers-side, so the trust anchor is the digest, not the transport.

## Consequences

**Positive.** The publish/pickup chain stops being session-assembled: every
piece is a verb with tests. Benchmark windows stop burning on front
defects. The funnel's half-dead failure mode becomes a provision/destroy
lifecycle problem nau can preflight, not a zombie CLI process an operator
must remember to check.

**Negative.** nau now operates a public-facing server surface — the failure
modes move from operator scripts into product code, where they are visible
and testable but also nau's to own (uptime, auth, port collisions with
hermes's tailnet-only 443). The `front.py` shim and the manual funnel task
must be retired in the same wave the verb lands, or two fronts drift.

## References

- [ADR-0052](0052-*.md) — versions / build-requests / server-release platform (seams this front consolidates; scope deliberately untouched)
- rbelem/nau#328 — `nau serve` POST routes (open; the front's publish route reuses this machinery)
- rbelem/nau#306 — closed; single-shot curl + non-executable install class
- nau-farm-ops skill — funnel port rule, tunnel pre-checks, the 8443/443 split
