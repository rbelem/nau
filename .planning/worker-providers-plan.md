# Worker providers plan: classes, lifetime, OS, provider-agnostic contract

Date: 2026-09-27. Answers four operator questions: which providers and
machine classes, how long a builder lives, which OS until Nau can dogfood,
and how provider-agnosticism is preserved. Sources fetched 2026-09-27
(pricing pages, distro package indexes, official docs); unverified figures
are flagged inline. Feeds #194, #269, #271; amends nothing at the ADR
layer.

## 1. Providers and machine classes

**Primary: Hetzner Cloud — unchanged as first provider, but the SKU table
changed.** Hetzner renamed and repriced the cloud lineup effective
2026-06-15 (docs.hetzner.com price-adjustment notice): CX22 is now CX23,
CX32 → CX33, CX42 → CX43. Ticket #194's example `--type cx22` no longer
exists for new orders — SKUs must be pinned at implementation time, not
copied from the plan. Current hourly (excl. VAT, hourly-capped at the
monthly price, ideal for TTL-destroyed workers):

| Class | Hetzner SKU | vCPU/RAM/disk | €/hr | €/mo cap | Role |
|---|---|---|---|---|---|
| build-light | CX23 | 2/4/40 | 0.0088 | 5.49 | single-package bursts |
| build-default | CX33 | 4/8/80 | 0.0136 | 8.49 | daily loop, index runs |
| build-aarch64 | CAX11 / CAX21 | 2/4/40, 4/8/80 | 0.0096 / 0.0168 | 5.99 / 10.49 | arm64 targets |

Notes: IPv4 is a separately billed resource now (unit price unverified —
community ≈ €0.30/mo); 20TB traffic included; locations fsn1/nbg1/hel1 —
hel1 for cache locality with the zet VPS. Dedicated-vCPU CPX SKUs repriced
steeply (CPX22 €19.49/mo cap) and EU availability of the small CPX sizes is
unconfirmed — **not recommended for builders**; shared vCPU at 3× the
count is the better €/compile. Hetzner Cloud exposes **no nested KVM**
(official FAQ) — a future kvm-capable class needs dedicated root (Hetzner
Robot auction ≈ €40/mo flat, no hourly) or OVH Eco dedicated; deferred
until a package actually requires kvm (`__worker-cap` already probes for
it; admissible only when the pool needs it).

**Secondary (templates, not urgency):** Scaleway and OVH stay the #198 /
OVH template targets; per-SKU prices could not be verified from official
pages (JS consoles) — flag. OVH's 2026-10-01 model change splits storage
and IPv4 out of instance pricing, making its small compute noticeably
worse than Hetzner for workers (c3-4-flex ≈ €0.06/hr all-in vs CX33's
0.0136 + ~0.0004 IP). AWS/GCP/Azure are the wide-capacity burst tier:
GCP E2 spot (~$0.02/hr, per-second billing) is the cheapest hyperscaler
shape; Azure B-series burst credits make it wrong for sustained compile
saturation; AWS spot ballpark $0.025–0.06/hr for 2–4 vCPU (trackers, not
official pages — verify via spot advisor at implementation).

**Spot is gated, not banned.** ADR-0040 D4's stop-the-world with no retry
means one eviction fails an hours-long run, and spot's fixed 2-minute
notice cannot checkpoint a gcc stage. Spot-capable providers (#195) are
admissible only after the #268 failure-class split (worker loss
re-dispatches) lands, and only for lanes whose jobs tolerate eviction.
Until then: on-demand hourly only.

**Oracle free tier: not part of the pool.** Always-Free A1 is now 2
OCPU/12GB (reduced) and idle instances get reclaimed; a farm built on
free-tier goodwill is flaky by construction. Fine as a personal
experiment box; not a builder the operator depends on.

**Provider-agnostic contract** (unchanged by provider choice): the
Provisioner seam takes one provider module per cloud; the worker
admission test is `__worker-cap` (arch/nproc/ram/disk/bwrap/mksquashfs/
kvm — fail-closed, the real sandbox probe included); the TTL label
contract and host_key pin (ADR-0045) are provider-neutral; capability
classes are config (a `workers` entry's jobs + arch + the provider type),
never code. Any provider whose SKU passes the cap probe and honours the
label contract is admissible — that is the whole agnosticism story, and
it is why provider order is a cost decision, not an architecture one.

## 2. How long a builder runs

**Burst workers are destroyed by the run that rented them; TTL is the
failure backstop, not the lifecycle.** The provisioner's destroy verb (or
the end-of-run cleanup) tears the machine down on completion — success or
fail. The TTL label exists for the paths that leak: crashed workstation,
lost SSH path, killed coordinator. Defaults:

| Run type | Default TTL | Rationale |
|---|---|---|
| single-package burst | 4h | orders of magnitude over job wall clock |
| index / release run | 24h | toolchain stages run for hours; the run fans out per worker |
| any (marker-less) | sweep age floor | alert 48h, destroy 72h (already in #269) |

Worker TTLs must exceed the maximum job wall clock (decision 5 of
`server-infra-plan.md`), so a 24h TTL on an index run never kills a live
job mid-build. **Standing workers are an option, not the default.** A
full-month CX33 costs €8.49 and buys zero provisioning latency (~4 min,
cloud-init-dominated) for the daily loop. Start burst-only — the ADR's
stated demand is machines the operator already controls, and the LAN
covers the daily loop — and add one standing CX33 only if the
provisioning latency measurably hurts. The sweep applies to standing
workers too, but a standing worker's TTL label is refreshed by its
heartbeat (already the documented alternative to oversized TTLs).

## 3. Worker OS until Nau can dogfood

**The latest Ubuntu LTS (26.04 at decision time; the contract pins
"latest LTS", never a codename), stock provider image, with two tool
pins.** It is cloud-init-native on every provider (keeps #195-#198
mechanical), matches the zet standard, and — researched, not assumed —
bubblewrap works unprivileged out of the box on the AppArmor-restricted
lineage (23.10+ through 25.x; the cap probe re-verifies on whatever
boots). Keep the system hardening; do
NOT set `apparmor_restrict_unprivileged_userns=0`. `__worker-cap`'s real
sandbox probe is the admission gate: a worker whose userns is broken
fails preflight by design.

The two pins, both research-confirmed:

1. **squashfs-tools: build 4.7.x from source in the template.** 4.6.1 is
   what every stable distro ships (Ubuntu through 25.10, Debian 13,
   Fedora through 44); 4.7.x is packaged only in Fedora 45+/Rawhide.
   26.04's package version is unverified — the source-built pin makes
   the question moot. The doctor advises 4.7+
   (#155), and ADR-0041's zstd defaults make mksquashfs behavior part of
   artifact identity — a fleet must run one pinned mksquashfs. The build
   is a trivial `make` against lz4/zstd/xz; install to `/usr/local/bin`
   with the version recorded for the cap probe.
2. **bwrap + ca-certificates + curl from the distro**, no overlay needed.

The template stays provider-neutral (stock Ubuntu image + cloud-init), so
every provider module is a thin SKU mapping. **Dogfood path:** the worker
contract is exactly four things — sshd, the pinned shuttle binary,
bwrap working, the pinned mksquashfs — and `__worker-cap` verifies all of
them. When Nau can boot and carry that set, switching the fleet to Nau is
a template change (new image + same cloud-init), which is itself the
dogfood: the farm building the packages the farm runs on. Golden-image
choice (#271 ownership): snapshot per (OS, tool-pin) version, refreshed
on every pin bump — Hetzner bills snapshots per compressed GB-month
(unit price unverified, historically €0.012/GB-mo), which at template
scale is noise. `hcloud server create --label` is CLI-verified (the #269
pre-check stands).

## 4. Ticket actions

- **#194 (amend):** SKU examples are stale post-reprice — classes
  build-light (CX23) / build-default (CX33) / build-aarch64 (CAX11/21);
  jobs and RAM budget derive from the class (4 jobs / 8GB on
  build-default, 2 jobs / 4GB on build-light); TTL defaults 4h burst /
  24h index runs; template = stock Ubuntu 24.04 + source-built
  squashfs-tools 4.7.x + distro bwrap + cap probes.
- **#271 (amend):** placement hel1 stands; add snapshot ownership (per
  OS/tool-pin version, refreshed on bump) and the note that CPX dedicated
  SKUs are not builder candidates post-reprice.
- **#276 (new):** worker base template — the OS decision, the two tool
  pins, the cap-probe admission contract, snapshot-per-version lifecycle.
  Blocked by #194 (the template ships with the provisioner).
- **#195 (amend, on the parked lane):** spot admissibility gated on #268
  (worker-loss re-dispatch); until then on-demand hourly only.

## Sources and confidence

Fetched 2026-09-27: Hetzner price-adjustment notice, cloud FAQ (nested
virt: no), billing FAQ; Ubuntu Discourse userns restriction thread;
packages.ubuntu.com / packages.debian.org / fedoraproject squashfs-tools
indexes; Oracle free-tier docs; OVH pricing-update blog; AWS/GCP/Azure
pricing pages are JS consoles — hyperscaler figures are tracker-sourced
ballparks flagged for verification at implementation. Unverified: Hetzner
IPv4 and snapshot unit prices, Scaleway/OVH Eco per-SKU prices, Oracle
paid A1 rate, EU CPX small-size availability.
