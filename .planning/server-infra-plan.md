# Server infra plan: worker spin-up + S3 cache storage

> **SUPERSEDED IN PART, 2026-09-27 (operator, evening): the zet VPS was
> deleted.** "I dropped zet, I was not using it. We will be deploying Nau
> in place." The zet checklist below is therefore history: steps 0-2 were
> executed and verified live (the rustfs policy dialect findings and the
> provision script `scripts/rustfs-provision-nau-cache.sh` in the zet
> repo remain valid and re-runnable against any MinIO-compatible target);
> steps 3-7 and all VPS-side artifacts (timers, monitors, mc) died with
> the server. The workers plan (classes, TTL, OS) is unaffected. The cache
> lane and the Nau domains re-home onto the Nau deployment itself — see
> `.planning/nau-infra-plan.md` and the ADR-0046 draft decision pending.

Date: 2026-09-27. v2 — four-seat council review folded (premise
corrections: local-path has no quota, no publisher exists yet, age-prune
kills hot blobs, the TTL sweep inverted the leak case, worker account
isolation was missing). Oracle round-1 corrections retained. This plan
moves no ADR clauses; it provisions the infrastructure the cache lane
(ADR-0043, #253) publishes to and the workers lane (ADR-0045 gate, #194)
will rent. The cache is untrusted storage under ADR-0033 D10: every
artifact carries its signature and digest; the S3 layer can neither
authenticate nor poison an entry that consumers accept.

## Current state

| Concern | zet cluster today | Nau need |
|---|---|---|
| Compute | One Hetzner CX33 VPS `zet` (hel1, Ubuntu 24.04, k3s v1.36.3+k3s1, ~4Gi headroom, one shared disk) | Coordinator = the operator's build machine (ADR-0040 posture; no coordinator server). Workers = ephemeral Hetzner VMs, post-#262 |
| S3 | rustfs 1.0.0-rc.1 in ns `cache`, 20Gi local-path PVC (no quota enforced — local-path is a hostPath dir), NodePort 30081, public vhost `cache.zet.rclb.dev` (Caddy TLS, wildcard via Cloudflare DNS-01) | A place to hold + serve the cache export tree (`cache/<key>.json`, `blobs/<sha256>`) over HTTPS |
| S3 consumer precedent | Attic binary cache reads/writes bucket `attic-cache` (authenticated, bucket-scoped user via `scripts/rustfs-provision-attic.sh`). Anonymous reads on this same rustfs+Caddy path have a recorded precedent: the legacy `devbox-nix-cache` bucket answered anonymous 200s before it was object-lock-frozen (`scripts/kuma/monitors.json:63-74`) | Same shape: bucket + scoped user + public-read GETs |
| Monitoring | uptime-kuma in ns `monitoring`, provisioned from `scripts/kuma/monitors.json` — zero push-type monitors, no notification channels configured; kuma runs on zet itself | Prune heartbeat + disk-guard alert need a provisioned push monitor and channel |
| Secrets | Bitwarden SM; rendered on the workstation, applied to the VPS; no SM token on the VPS (`secrets-render`/`secrets-apply`) | New SM keys for the cache push user; nothing enters `nau.lua` |
| IaC | tofu: `hcloud_server.zet` + Cloudflare DNS; `hcloud_token` in SM `TOFU_INPUTS` is the full-account token (owns zet, can touch DNS) | Worker provisioning must NOT reuse the full-account token — see decision 5 and #271 |
| Timers | Workstation systemd user timer (`update-timer.yml`); VPS timer (`attic-backup.yml`, `Persistent=true`) | Cache prune timer on the VPS; worker TTL sweep timer on the workstation |
| Backups | rustfs data: none (only Attic SQLite) | Cache needs none — content-addressed, deterministic, rebuildable; loss is time, not data |

## Decisions

1. **Cache storage backend: rustfs on zet.** Over (a) Hetzner Object
   Storage and (b) plain disk behind Caddy. It reuses the canonical service
   pattern, the secrets flow, and a TLS front that already terminates in
   front of rustfs; attic proves the bucket-user-script shape; the recorded
   anonymous precedent de-risks the serving path. The cache is rebuildable,
   so single-disk rc software is an acceptable tenant. **The migration
   trigger measures the disk, not the bucket**: local-path enforces no PVC
   quota, so the only real signal is `df` on the data path — below 10Gi
   free, publishing stops and the guard alert fires. `mc du` on the bucket
   is trend telemetry, not a trigger. The evacuation runbook
   (`scripts/cache-evacuate.sh`, mc mirror to Hetzner Object Storage) is
   written and tested while the bucket is empty, so the trigger is
   mechanical when it fires; its cost line is part of the runbook.
2. **Serving: the existing S3 path-style vhost, anonymous reads — gated on
   step 0.** Anonymous is the only model that adds no client code, no
   signing service (ADR-0011 D5 bars new daemons), and no secret in
   `nau.lua`; credentials would protect nothing confidential
   (signature+digest fail-closed verification is the security). Recorded
   precedent says anonymous GET already worked on this stack; the true
   step-0 unknowns are the policy dialect and persistence. Step 0 verifies,
   through the Caddy vhost (not the NodePort): anonymous GET 200; anonymous
   ListObjectsV2 denied; the MinIO preset trap (`download` = GetObject
   only; it is `public` that adds ListBucket — round 1's wording
   corrected); HEAD and Range; 403-vs-404 on a missing key; `attic-cache`
   still 403s anonymously (policy scoping); policy survives a rustfs pod
   restart; a large blob streamed to concurrent anonymous clients while
   watching rustfs RSS against the 2Gi limit; the console on 30082 still
   requires auth; and finally an end-to-end `nau pull` against a
   hand-published manifest+blob. **Fallback if anonymous is unsupported:**
   `mc mirror` to a directory + Caddy `file_server` on a new `handle`
   block of the same vhost. The fallback is correctness-equivalent
   (digest+sig make partial data a miss) but operationally worse: it
   doubles cache bytes on the scarce disk, adds a mirror-interval
   staleness window (a miss, never a wrong answer — cadence pinned at 5
   minutes if invoked), and re-tools the prune (`find -mtime`,
   `--remove`). The lane root for `nau.lua` is
   `https://cache.zet.rclb.dev/nau-cache/`.
3. **Inventory exposure: no index, two-rung credentials.** No `index.json`
   publishes to `nau-cache`; the bucket policy denies listing. Keys are
   opaque closure hashes. Exactly two rungs: anonymous (GetObject on
   `nau-cache` only) and the push user (read/write/list/delete on
   `nau-cache` only — delete and list exist for the prune; no
   bucket-create, no admin, no other bucket). Consumers treat 403 and 404
   identically as miss, and warn on consecutive 403s (a broken policy must
   not silently degrade every build to cold — consumer semantics belong to
   #253). If an inventory is ever wanted, it is a signed file the push user
   writes, never an S3 listing surface. **Workers need no cache
   credentials at all** (ADR-0040 D6: sources travel from the coordinator;
   workers never fetch upstream) — written down so nobody wires
   `NAU_CACHE_S3_*` onto a worker.
4. **Retention: a publisher, then two-tier age pruning, measured and
   heartbeated.** The plan v1 error: it provisioned a bucket nothing writes
   to. **The publish transport is its own ticket (#270)** — workstation-side
   uploader: blobs-then-manifest per entry, skip-if-exists blobs
   (content-addressed), unconditional manifest re-PUT with a bytes-compare
   before overwrite. Skipping existing blobs means re-publishing does NOT
   refresh blob age, so v1's "re-publishing refreshes an entry's age" was
   false for blobs. Prune is therefore two-tier and two-pass: manifests
   pruned at 30d, blobs at 90d, both prefix-scoped invocations
   (`cache/` then `blobs/` — a single bucket-wide `mc rm --older-than` is
   not manifest-first), under `flock` against concurrent publishes, with
   the run failing loudly before any heartbeat. Reference-scanned deletion
   (delete blobs no live manifest references) stays the ADR-0043 upgrade;
   two-tier age is the floor that keeps hot entries alive. The same timer
   logs `mc du` + `df` every run and **pushes a kuma heartbeat only on
   verified completion** — provisioned properly: a push monitor and a
   notification channel added to `scripts/kuma/monitors.json` (today:
   none exist), plus a workstation-side stale-heartbeat check, because
   kuma runs on zet and a node-level death kills the pruner and its
   witness together. The timer is `Persistent=true` (post-downtime
   catch-up). An object-lock/versioning guard is asserted before every
   prune (this rustfs already hosts one object-locked bucket; prune lives
   on DeleteObject).
5. **Workers: no new server, isolated account, colocated.** The coordinator
   is the build machine; workers are ephemeral Hetzner VMs created by the
   #194 provisioner once ADR-0045 is ratified (#262). **Workers get their
   own Hetzner project and a project-scoped API token in SM (#271)** —
   reusing `TOFU_INPUTS`' full-account token couples a worker-lane leak to
   the cluster itself; structural isolation beats procedural care. An
   hcloud firewall (ssh ingress from the operator's addresses only) is
   attached at create time. Location hel1 (same region as the cache vhost);
   IPv4 by default (included on cx servers), IPv6-only recorded as a
   possible later cost cut. TTL expiry is stamped as an **hcloud label at
   create time** (survives a cloud-init failure — the in-guest marker file
   is a copy, not the source of truth); the label contract pins key names
   AND value format — epoch seconds, because Hetzner label values reject
   `:` and ISO-8601 will not fit — shared between #194 (writer) and #269
   (reader). Golden image vs
   per-boot cloud-init is decided in #194 — the trade is the 4-minute
   token-to-cap budget against toolchain determinism (the v5 key's
   premise); snapshot ownership and refresh cadence are infra-side and
   land in #271's project setup. Workers hold no cache credentials
   (decision 3). `nau.lua` registration is its own contract: a
   machine-managed `workers` block that the provisioner/destroy verbs
   append and evict (address + host_key pin per ADR-0045 D4) —
   ephemeral IPs mean hand-editing Lua per burst is a non-starter
   (**#272**). Placement groups: out of scope, recorded so nobody adds
   them for ephemeral singletons.
6. **Worker safety net: TTL sweep timer on the workstation (#269).** Daily
   systemd user timer. Match rules, in order: labeled `nau-worker` AND
   (parseable TTL label past due OR — missing/unparseable marker — server
   age past a floor: alert at 48h, destroy at 72h). The v1 three-condition
   match inverted the risk: the forgotten VM is precisely the one whose
   marker never got written. Every destroy run also asserts
   `hcloud volume list --server X` is empty (a detached volume outlives
   its server and bills silently). Alerts go to the kuma push monitor +
   notification channel provisioned in decision 4's checklist item.
   Dry-run from landing until two weeks after the first real provision,
   then enforce (there is nothing to sweep before the first provision, so
   a calendar-based flip is untestable).

## zet-side execution checklist

No GitHub tracker for zet (private repo); this checklist is the ticket
queue. Step 0 gates the script; the guard alert precedes first publish;
the PVC "bump" is documentation, not a control (local-path has no quota)
and lands last.

0. **Anonymous-read gate.** Throwaway bucket; run the full step-0 matrix
   from decision 2 (GET, ListObjectsV2, HEAD, Range, 403-vs-404,
   cross-bucket scoping on `attic-cache`, preset-vs-raw-policy shape,
   persistence across pod restart, concurrent large-blob GET vs RSS,
   console auth, end-to-end `nau pull`). Records the rustfs policy
   dialect. If anonymous fails, switch decision 2 to the fallback and
   re-point the lane root.
1. **Provision script** `scripts/rustfs-provision-nau-cache.sh` —
   model `rustfs-provision-attic.sh` including its object-lock guard:
   idempotent (a re-run converges from any partial state and fails loudly
   before the SM writeback if any step failed); bucket `nau-cache`;
   bucket-scoped push user per decision 3; anonymous policy per step 0;
   creds written back to SM as `NAU_CACHE_S3_ACCESS_KEY` /
   `NAU_CACHE_S3_SECRET_KEY`.
2. **Digest-pin the rustfs image** (`rustfs/rustfs:1.0.0-rc.1` — the only
   non-digest-pinned image in the repo) with a dated comment; 1.0 final
   gets a dated bump plus a bucket sanity check on both caches.
3. **Disk-guard alerting** — uptime-kuma push monitor on `df` of the data
   path (below 10Gi free = alert + stop-publish signal), provisioned in
   `scripts/kuma/monitors.json` with a real notification channel. This is
   the control; the PVC size line below is not.
4. **Prune + measurement timer** `ansible/playbooks/cache-prune.yml` +
   timer — VPS-side, `attic-backup.yml` shape, `Persistent=true`: install
   `mc` on the VPS (it exists on the workstation only today); creds via a
   root-only rendered host file (not a k8s Secret read); two-pass
   two-tier prune per decision 4 under `flock`; `mc du` + `df` logged;
   object-lock guard asserted; kuma heartbeat pushed only on verified
   completion.
5. **Kuma provisioning** — add the push monitors (prune heartbeat,
   disk-guard, later the #269 sweep alert) and a notification channel to
   `scripts/kuma/monitors.json`; re-run `kuma-provision.sh`.
6. **Evacuation runbook** `scripts/cache-evacuate.sh` — mc mirror
   `nau-cache` to Hetzner Object Storage, written and tested empty
   (decision 1's trigger must be mechanical); includes its cost line.
7. **PVC comment, then deploy.** Record on `rustfs-data` that local-path
   enforces no quota and `df` is the boundary (no size bump pretense);
   deploy via `scripts/deploy.sh` phases.

## nau-side tickets

- **#270 (new): cache publish transport** — workstation uploader:
  blobs-then-manifest, skip-existing blobs, unconditional manifest re-PUT
  with bytes-compare. The real blocker: retention is meaningless without a
  writer, and build-perf 1a's output has nowhere to land until this
  exists.
- **#271 (new): worker account isolation** — dedicated Hetzner project +
  project-scoped token in SM + hcloud firewall + hel1/IPv4 placement +
  snapshot ownership decision. Blocks #194's first real provision.
- **#272 (new): worker registration into `nau.lua`** — machine-managed
  `workers` block (append on provision, evict on destroy) carrying address
  + host_key pin per ADR-0045 D4. #194 contract.
- **#269** — amended: TTL expiry as an hcloud label at create time, the
  age-floor rule for missing/unparseable markers, volume assertion, kuma
  alert channel, enforce-flip keyed to first real provision.
- **#253 (ADR-0043)** — amended: consumer miss semantics (403/404 identical,
  consecutive-403 warning, HEAD/Range expectations) and the publish side
  (or its explicit handoff to #270) must land in the ADR.
- **#194** — amended: TTL label contract with #269, `nau.lua` write via
  #272, firewall attach at create, ssh user pinning, known_hosts append
  locking, teardown-on-failure, golden-image decision, toolchain
  determinism, an explicit per-job RAM budget (cx22 is 2 vCPU/4GB
  shared-vCPU), no cache credentials on workers.
- **hcloud CLI pre-check** (rides #269): confirm `hcloud server create
  --label` support and volume-delete defaults on the installed CLI before
  the sweep script is written.
- Existing: #262 (ratification gate), #192 (host_key pin mechanics),
  build-perf 1a (v5 key — depends on #270 existing).

## Sequencing

zet checklist: 0 → 1 → 2 → 3 → 5 → 4 → 6 → 7. Steps 0-6 are
content-agnostic and land before the v5 key and ADR-0043; the guard alert
(step 3) precedes first publish; the prune timer (4) is the retention
floor the cache plan requires before publishing. Nau side: #270 gates
any real publish; #271 gates #194's first provision; #272 rides #194;
#269 lands before that first provision. #262 remains the operator gate on
the whole worker lane.

## Risks

- **Shared disk, single replica, no quota.** rustfs, attic, postgres, and
  the OS share one cx33 disk. The df guard (step 3) is the boundary; the
  PVC size is decoration. Measured: rustfs OOM-crashlooped at a 1Gi limit;
  a growing object count is the thing to watch against the 2Gi limit.
- **kuma watches from inside the burning house.** kuma runs on zet; a
  node-level death silences prune heartbeat and disk guard together. The
  workstation-side stale-heartbeat check (decision 4) is the outside
  witness.
- **NodePort exposure** binds 0.0.0.0; ufw is the only gate (existing
  posture). The anonymous policy is scoped to `nau-cache`;
  `attic-cache` stays credential-gated, and step 0 tests it stays that
  way.
- **rustfs is an rc release** holding both caches; the evacuate runbook
  (step 6) is the escape hatch, written before it is needed.
- **TTL sweep deletes by rule.** The rules are label-at-create + age floor
  + volume assertion, with dry-run until there is something real to
  sweep. Residual: a server that matches every rule but is still wanted
  means the TTL was set wrong at provision time — a #194 template bug,
  not a sweep bug.
- **Traffic**: CX33 included traffic is not unmetered; the rate-limit
  revisit (recorded position) keys off the traffic logs and the df guard.
