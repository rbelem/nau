# Server infra plan: worker spin-up + S3 cache storage

Date: 2026-09-27. Researched against the zet cluster repo
(`~/Workspace/github.com/rbelem/zet`, private) and
`.planning/remote-cache-plan.md` v3. Oracle review folded same day
(anonymous-read gate promoted to step 0, retention measurement, sweep
hardening, omissions recorded). This plan moves no ADR clauses; it
provisions the infrastructure the cache lane (ADR-0043, #253) publishes to
and the workers lane (ADR-0045 gate, #194) will rent. The cache is untrusted
storage under ADR-0033 D10: every artifact carries its signature and digest;
the S3 layer can neither authenticate nor poison an entry that consumers
accept.

## Current state

| Concern | zet cluster today | Shuttle need |
|---|---|---|
| Compute | One Hetzner CX33 VPS `zet` (hel1, Ubuntu 24.04, k3s v1.36.3+k3s1, ~4Gi headroom) | Coordinator = the operator's build machine (ADR-0040 posture; no coordinator server). Workers = ephemeral Hetzner VMs, post-#262 |
| S3 | rustfs 1.0.0-rc.1 in ns `cache`, 20Gi local-path PVC, NodePort 30081, public vhost `cache.zet.rclb.dev` (Caddy TLS, wildcard via Cloudflare DNS-01) | A place to hold + serve the cache export tree (`cache/<key>.json`, `blobs/<sha256>`) over HTTPS |
| S3 consumer precedent | Attic binary cache reads/writes bucket `attic-cache`; bucket-scoped user via `scripts/rustfs-provision-attic.sh` (`mc`, creds written back to SM). All existing policies attach to authenticated users — nothing anonymous exists yet | Same shape: bucket + scoped user + public-read GETs |
| Secrets | Bitwarden SM; rendered on the workstation, applied to the VPS; no SM token on the VPS (`secrets-render`/`secrets-apply`) | New SM keys for the cache push user; nothing enters `shuttle.lua` |
| IaC | tofu: `hcloud_server.zet` + Cloudflare DNS (`tofu/dns.tf`); `hcloud_token` inside SM `TOFU_INPUTS` | Worker provisioning reuses the same token, via operator env only |
| Timers | Workstation systemd user timer (`update-timer.yml`, 05:30 daily); VPS timer (`attic-backup.yml`) | Cache prune timer on the VPS; worker TTL sweep timer on the workstation |
| Backups | rustfs data: none (only Attic SQLite) | Cache needs none — content-addressed, deterministic, rebuildable; loss is time, not data |

## Decisions

1. **Cache storage backend: rustfs on zet.** Over (a) Hetzner Object Storage
   and (b) plain disk behind Caddy. It reuses the canonical service pattern,
   the secrets flow, and a TLS front that already terminates in front of
   rustfs; attic proves the bucket-user-script shape. The cache is
   rebuildable, so the single-disk single-replica posture is acceptable in a
   way it would not be for primary data. Migration trigger: at ~60% bucket
   fill (measured, see decision 4) or repeated ENOSPC pressure on the shared
   disk, evaluate Hetzner Object Storage — the mc-based publish/serve flow is
   backend-agnostic and moves intact; the evaluation includes its monthly
   cost against the CX33's included traffic.
2. **Serving: the existing S3 path-style vhost, anonymous reads — gated on
   step 0.** The `cache.zet.rclb.dev` vhost already reverse-proxies rustfs,
   and path-style authenticated access is proven (attic). What is NOT proven
   is anonymous access: rustfs rc.1's support for MinIO-style anonymous
   bucket policy is the plan's load-bearing assumption. **Checklist step 0
   verifies it empirically** (curl an anonymous GET and ListObjects against a
   throwaway bucket) before the provision script is written. The policy must
   allow `GetObject` and **deny `ListBucket`** — MinIO's anonymous-download
   preset permits listing, which would re-open the inventory exposure
   decision 3 rejects; verify the policy shape, do not assume it. Pull-side
   semantics to record with it: a 403 on a missing key must be treated as
   not-found by consumers. **Fallback if anonymous policy is unsupported:**
   `mc mirror` the bucket to a directory and add a Caddy `file_server` block
   on the same vhost — still zero new DNS/TLS, same lane URL shape.
   The lane root for `shuttle.lua` is
   `https://cache.zet.rclb.dev/shuttle-cache/` (bucket prefix absorbed by
   the configurable base URL).
3. **Inventory exposure: no index for the cache bucket.** The cache plan's
   delta 4 offers "accepted exposure or omit the index". Decision: omit —
   `index.json` never publishes to `shuttle-cache`, and the bucket policy
   denies listing (decision 2). Keys are opaque closure hashes;
   CacheManifest contents (recipe summaries) are fetchable only by someone
   who already knows a key. Recorded as the accepted exposure. The
   credential shape has exactly two rungs: anonymous (GetObject on
   `shuttle-cache` only) and the push user (read/write/list/delete scoped to
   `shuttle-cache` only — delete and list are required by the manifest-first
   prune; no bucket-create, no admin, no other bucket). Nothing between
   them, no shared admin credential.
4. **Retention: weekly age-based prune on the VPS, with the trigger
   measured.** systemd timer + `mc`-driven sweep of `shuttle-cache`: objects
   older than 30 days are removed, manifest-first (`cache/<key>.json` deleted
   before its blobs) per the cache plan's open call 3 sweep order; never
   touches `attic-cache`. Age-only pruning on immutable blobs is
   landfill-safe: an orphaned blob after manifest deletion ages out within
   30 days, and concurrent publishes are never prune-eligible (Last-Modified
   is upload time). Two recorded consequences: re-publishing refreshes an
   entry's age, so an actively used entry whose publisher stops refreshing
   dies at 30 days — that is the intended policy, not an accident; and exact
   GC semantics (reference counting, LRU) stay an ADR-0043 call — the timer
   is the floor. The same timer logs `mc du` on the bucket and `df` on the
   data path every run: the 60% migration trigger in decision 1 is measured
   by this, or it is dead text.
5. **Workers: no new server.** The coordinator is the build machine; workers
   are ephemeral Hetzner VMs created by the #194 provisioner once ADR-0045 is
   ratified (#262). `hcloud_token` reaches the provisioner through the
   operator's environment (SM `TOFU_INPUTS`), never `shuttle.lua` — same
   rule as every other secret. Default burst shape cx22 (2 vCPU/4GB), x86_64,
   Ubuntu 24.04, TTL marker, host key minted and injected per ADR-0045; the
   cloud-init template spec belongs to #194. Worker TTLs must exceed the
   maximum job wall clock (or workers must heartbeat-refresh their TTL), so
   the sweep in decision 6 never kills a machine mid-job.
   **Standing worker on the zet VPS: rejected.** ~4Gi headroom shared with
   rustfs, attic, postgres, n8n, auth — farm builds would thrash the same
   disk the cache sits on. Revisit on a node upgrade or a second VPS.
6. **Worker safety net: TTL sweep timer on the workstation.** Daily systemd
   user timer: list Hetzner servers labeled `shuttle-worker`, destroy only on
   a three-condition match — the label AND a parseable TTL marker AND the
   TTL past due. Alert on any hcloud API failure: a silently skipped sweep
   is the exact failure this net exists to catch. Dry-run is the default
   mode for the first two weeks (log what it would destroy), then flips to
   enforce. Catches a crashed `workers destroy` or a lost SSH path before it
   becomes a bill.

## Recorded assumptions and positions

- **Consistency**: single-node rustfs is effectively strongly consistent;
  cache objects are immutable and the only overwrite is a re-publish of the
  same closure key. Read-after-write mirroring is therefore safe. Written
  down so a future clustered rustfs re-opens it deliberately.
- **rustfs upgrade path**: rc.1 digest-pinned now (checklist item 2); bumps
  follow the repo's dated-comment convention, and 1.0 final gets its own
  dated bump with a bucket-listing sanity check against both caches.
- **Abuse/rate limiting**: the cache bucket is public-read on a public vhost
  with no rate limiter. Accepted for now (blobs are large, keys unguessable,
  CX33 traffic is included); the explicit alternative is a Caddy
  `rate_limit` block on the vhost if traffic logs show draining. Revisit
  with the migration trigger.
- **Licensing**: blobs are GPL-3.0-built binaries served anonymously.
  Position recorded: the cache is a build-acceleration cache for the
  operator's own machines and their direct correspondents. shuttle is
  GPL-3.0-only with source in-repo, and the corresponding source for every
  blob is obtainable from the public repo by commit pin. If Nau images ever
  ship from this lane, re-run this analysis as part of the ADR-0044
  publication decision.

## zet-side execution checklist

No GitHub tracker for zet (private repo); this checklist is the ticket
queue. Order matters: step 0 gates the script's policy shape; the PVC bump
precedes the bucket filling.

0. **Anonymous-read gate.** Throwaway bucket + `mc anonymous set` (or raw
   policy JSON): curl an unauthenticated GET (expect 200) and an
   unauthenticated LIST (expect 403). Records the rustfs policy dialect and
   the 403-vs-404 behavior. If it fails, switch decision 2 to the documented
   fallback and re-point the lane root.
1. **Provision script** `scripts/rustfs-provision-shuttle-cache.sh` —
   model `rustfs-provision-attic.sh`: idempotent `mc` run against
   `https://cache.zet.rclb.dev` — a re-run converges from any partial state
   (bucket exists, user exists, policy half-applied are all sensed and
   completed, and the script fails loudly before the SM writeback if any
   step failed); bucket `shuttle-cache`; bucket-scoped user
   `shuttle-cache` with read/write/list/delete on that bucket only (the
   decision 3 credential shape; no bucket-create, no admin); anonymous
   policy per step 0 (GetObject yes, ListBucket no); creds written back to
   SM as `SHUTTLE_CACHE_S3_ACCESS_KEY` / `SHUTTLE_CACHE_S3_SECRET_KEY`.
2. **Digest-pin the rustfs image.** `rustfs/rustfs:1.0.0-rc.1` is the only
   non-digest-pinned image in the repo (repo convention). Pin to the rc.1
   digest with a dated comment.
3. **PVC headroom.** Bump `rustfs-data` 20Gi → 40Gi before the bucket starts
   filling, if the cx33 disk allows (verify `df` first — local-path on the
   single disk); record the measured 60% trigger in the PVC comment.
4. **Prune + measurement timer** `ansible/playbooks/cache-prune.yml` + timer
   — VPS-side, `attic-backup.yml` shape: weekly `mc rm --older-than 30d`
   manifest-first against `shuttle-cache`, plus `mc du` + `df` logged every
   run (the decision 1 trigger's data source), creds from the rendered
   Secret via `mc alias`, log to journal. Outcome signal: the timer pushes a
   heartbeat to the existing uptime-kuma on success, so a dead prune shows
   up as a missing heartbeat instead of a journal line nobody reads; the
   same run flags the log line when bucket fill crosses the 60% trigger.
5. **Deploy** via `scripts/deploy.sh` phases (secrets-render → secrets-apply
   → deploy); the checklist touches none of the tofu/DNS layers.

## shuttle-side tickets

- **New: worker TTL sweep timer (#269)** — workstation systemd user timer +
  `hcloud` sweep script (decision 6; three-condition match, alert on API
  failure, dry-run first). Money-bounded, shuttle-independent.
- Existing lanes this infra serves: #253 (ADR-0043 cache lane), build-perf
  item 1a (v5 key — the lane carries nothing real until it lands), #194
  (Provisioner + Hetzner, post-#262), #192 (carries the host_key pin
  mechanics).

## Sequencing

Step 0 and items 1-4 are content-agnostic — they serve a static tree
regardless of what fills it — so they land before the v5 key and ADR-0043;
step 0 gates item 1. The lane becomes useful when build-perf 1a + #253 land.
The PVC bump (item 3) precedes first publish. Worker provisioning waits for
#262 (your ratification), then #194; the TTL sweep timer should exist before
the first real provision, not after the first forgotten VM.

## Risks

- **Shared disk, single replica.** rustfs, attic, postgres, and the OS share
  one cx33 disk. A runaway cache competes with the Attic SQLite and the k3s
  PVCs. Mitigations: the prune + measurement timer, the PVC bump before
  filling, the 60% trigger, and the rebuildable-by-design posture. Measured:
  rustfs OOM-crashlooped at a 1Gi limit; the 2Gi limit and ~4Gi node
  headroom are real constraints, and a growing object count (many small
  manifests) is the thing to watch against that limit.
- **NodePort exposure** binds 0.0.0.0; ufw is the only gate (existing
  posture, unchanged here). The anonymous-read policy is scoped to
  `shuttle-cache` only — `attic-cache` stays credential-gated.
- **rustfs is an rc release** holding both caches. Acceptable while the
  cache is rebuildable; the Hetzner Object Storage migration path is the
  escape hatch and is preserved by the mc-based flow, with cost now part of
  its trigger evaluation.
- **TTL sweep deletes by three-condition match.** Label + parseable TTL
  marker + past due, grace rule from decision 5, dry-run default — the
  residual risk is a server that matches all three but is still wanted,
  which means the TTL was set wrong at provision time; that is a #194
  template bug, not a sweep bug.
