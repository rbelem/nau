# ADR-0046: Nau hosts its own distribution surface

## Status

Accepted (2026-09-27, operator decisions in a grill session, recorded by a
planning session). Supersedes the hosting half of
`.planning/server-infra-plan.md` (the zet VPS was deleted the same day —
"dropped zet, I was not using it") and re-homes `.planning/
nau-infra-plan.md` onto the Nau deployment itself.

## Context

zеt — the single Hetzner VPS that was to host the shuttle build cache, the
Nau download/mirror lanes, and www — was deleted by the operator: it ran
services nothing was using yet. The distribution needs a home for
`www.nau.rclb.dev`, `download.nau.rclb.dev` (mission images + updates,
ADR-0044 D5) and `cache.nau.rclb.dev` (the ADR-0043 lane), plus an S3
backend for the build cache. The distro's first fully functional VM build
is the gating milestone for real deployments (operator rider on the
ADR-0044 ratification; ticket #277 holds the full-installer lane behind
the same milestone).

## Decision

1. **Nau replaces zet as the infrastructure host.** A small VPS
   (2 vCPU / 4 GB class is sufficient — the host serves cache and lanes;
   the workers do the compute), provider-agnostic: any cloud server whose
   rescue mode can write a disk image qualifies.
2. **Install = rescue + dd-flash of the x86_64 mission image** (ADR-0044
   flow). Boot rescue, write the image to `/dev/sda`, reboot into Nau.
   No installer code, no interactive path — this is the first live
   dogfood of flash → first boot → A/B updates on real hardware. It
   opens when the VM milestone passes; #277 (full installer) stays
   behind it.
3. **The distribution surface is served by Nau itself, as a pod.** One
   "lanes" pod on the host carries the static file service (www,
   download, cache trees) and the TLS terminator as declared pod
   services (ADR-0032). Every user request to `nau.rclb.dev` exercises
   the pod machinery — the distro hosts its own distribution surface.
4. **The build cache backend is rustfs as a pod on the same host**
   (ADR-0043's first lane). The provision script
   (`rustfs-provision-shuttle-cache.sh` in the zet repo, verified live
   before zet was dropped) is re-runnable against it unchanged; #270's
   real verification targets this pod.
5. **Trust inheritance is explicit: this host is a Nau device.** Its
   updates ride the same ADR-0024/0024-lane story as every installed
   machine — the #267 decision (update-signature gap, blocking for
   Cassini) therefore covers the infrastructure host first. A compromised
   lane host compromises nothing beyond itself (signatures verify
   fail-closed on consumers), but an unpatched one would eventually stop
   receiving missions.

## Consequences

**Positive**: maximal dogfood with a concrete deadline (the VM milestone
unblocks the installer lane AND this deployment); one small bill replaces
the zet setup; every infrastructure component (lanes, cache, updates)
runs as shipped packages, not hand-rolled host state; the zet-repo
scripts survive as the re-runnable artifact of everything learned.

**Negative**: the monitoring story died with zet and must be rebuilt
(kuma, the disk guard, the prune heartbeat receiver — all open); the
single small host is the availability domain for the lanes; and the
first deployment happens before an installer exists, so re-deployment
means re-flash.

**Neutral**: provider sizing may grow (cache growth is the only
pressure); the ADR-0033 LAN lane and the HTTPS lane coexist unchanged;
#271 (worker account isolation) is independent of this host and stands.

## Revisit triggers

- Cache growth pressuring the small host — evacuate to Hetzner Object
  Storage (`cache-evacuate.sh` runbook) or widen the VPS.
- A monitoring destination decision (where kuma-successor alerts go) —
  required before the prune heartbeat is meaningful.
- Any requirement for a second lane host — becomes the first real
  multi-node Nau fleet question.

## References

ADR-0013 (nau.rclb.dev as the operational home), ADR-0044 (mission
images, flash), ADR-0043 (the cache lane), ADR-0032 (declared pod
services), ADR-0024 (updates). `.planning/server-infra-plan.md` and
`.planning/nau-infra-plan.md` (superseded in part; the rustfs policy
dialect findings and provision script remain valid). Tickets: #270
(publisher; verification target), #274-#276 (lanes, re-homed), #277
(full installer, still gated), #267 (update trust, blocking for
Cassini).
