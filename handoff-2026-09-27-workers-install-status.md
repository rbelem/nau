# Handoff 2026-09-27 — distributed workers + Nau install-path status

State of the two connected features: cloud build workers (ADR-0040) and the
Nau end-user install path (new ADR-0044). Written after a transcript recall,
live tracker verification, and a four-seat council review. Every claim below
was verified against the repo and GitHub on 2026-09-27.

## Capsule

- Workers (ADR-0040, Accepted): T0-T3 landed (#188, #189, #190/PR #239,
  #191/PR #245). Next: #192 (SshExecutor, T4), then #193 (coordinator, T5).
- Providers #194-#198 stay parked behind ADR-0045 (host-key provenance), now
  drafted: mint-and-inject over the provider API, never ssh-keyscan.
- Install path (ADR-0044, Proposed): dd-flash the whole-disk image; install
  copies, never builds or signs. Ratification gates its tickets.
- The workers plan had drifted from the ratified ADR (v4 keying, speed
  fields, T6 edge); resynced in this pass before any T4 dispatch.
- Release images for 1.0 come from one trusted machine, not the farm; (b)
  does not wait on (a).

## Thread status

- [merged #239] T2 BuildExecutor seam (#190, closed this pass).
- [merged #245] T3 hidden __worker-cap/__worker-job verbs (#191).
- [open #192] T4 SshExecutor + content sync — next dispatch; plan box now
  carries the D6 manifest-identity ingest rule and the host_key pin duty.
- [open #193] T5 coordinator integration, review-gated.
- [parked #194-#198] T6-T10 providers — gated on ADR-0045 ratification; T6
  also now depends on T5 (the plan's "T6 after T3" edge was stale).
- [open #253] ADR-0043 remote cache — plan committed (bad2aeb, pushed), ADR
  unwritten; land the D6 conformance fix before drafting it (its v5 key
  reverses ADR-0040 D6's separate-namespace protection; one clean invariant
  to reverse, not two).
- [proposed docs/adr/0044] Nau install path — awaiting ratification.
- [proposed docs/adr/0045] Worker host-key provenance — awaiting operator.

## Council verdicts (4 seats, unanimous unless noted)

1. T4 → T5 before any provider work; the plan's T6 edge re-pointed to T5.
2. Host-key provenance: coordinator mints the keypair at provision time and
   injects the private half via cloud-init over the authenticated provider
   API; public half pinned in the workers entry; ssh-keyscan never runs.
   Operator picks plain injection or the SSH-CA form at ratification. Seats
   split 2-2 on the default form; both are covered by ADR-0045.
3. Install = write the built whole-disk image (Fedora IoT model). "Re-signing
   verity roots" is a category error the ADR rules out: roothash, GPT GUIDs,
   and UKI cmdline are mutually derived at build time. verify-image is the
   only new verb; dd stays documented.
4. Release images: one trusted builder for 1.0 (farm fabrication hazard,
   ADR-0040 D7, is not a release gate); the farm's job is the daily ~190
   package loop. (b) has no hard dependency on (a).

## Tickets filed this pass

- #261 Ratify ADR-0044 (install path) — ready-for-human.
- #262 Ratify ADR-0045 (host-key provenance; un-parks #194) — ready-for-human.
- #263 os-release violates the ADR-0013 identity matrix (ID=shuttle in
  boot.rs) — ready-for-agent, small, blocking for any release.
- #264 First-boot state-partition growth (systemd-repart) — ready-for-agent.
- #265 shuttle verify-image — ready-for-agent, gated on ADR-0044.
- #266 shuttle image --release (deterministic mission media + SHA256SUMS +
  signed manifest + rebuild-compare ritual) — ready-for-agent, gated on
  ADR-0044.
- #267 Sysupdate Verify=no signature gap + ADR-0024 key-ceremony CLI —
  needs-triage (the "headline security story" gap; blocking-for-1.0 is the
  operator's call; council recommends closing it).
- #268 ADR-0040 amendment: split D4 failure classes (worker loss re-dispatches;
  stop-the-world only when no executor remains) — needs-triage; blocks T5
  design.

## Doc defects fixed this pass

- .planning/distributed-workers-plan.md resynced to ADR-0040 (ingest key,
  cut fields, T6 edge, host-key pin, resync banner).
- docs/adr/0035: "ShuttleOS image assembly runs as root" was false and used
  the retired name — now states the unprivileged reality.
- Both plans cited scripts/rebuild-compare.sh; the file is
  examples/rebuild-compare.sh.

## Next moves

1. Operator: ratify ADR-0045, pick injection vs CA form — un-parks #194.
2. Operator: ratify ADR-0044 — unblocks verify-image, image --release,
   first-boot growth.
3. Dispatch #192 (T4) against the resynced plan box.
4. Before drafting ADR-0043: settle the v5-vs-D6 key question in its open
   calls, so the cache lane reverses one clean invariant.
