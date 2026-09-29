# Worker pool sizing, SKU economics, reuse — measured + reviewed (2026-09-29)

Question: with the farm live (first real cloud builds landed this week), how should
the operator size the worker pool, which Hetzner SKU, and should workers be reused
or queued? Method: a 4-seat council review of the code and constraints (unanimous
on the big calls), a jev quality baseline on the farm implementation, and a live
measured benchmark (ccx13 vs ccx23, 600 MB pack, cold/warm e2e with 2 workers,
Hetzner pricing API). Tickets: #297-#303. All benchmark servers were destroyed in
the same window; pricing pulled from the API (fsn1 shown, hel1 within rounding).

## Measured (2026-09-29, both workers freshly provisioned, pin 4.7.4 verified)

| Measurement | ccx13 (2 vCPU/8 GB) | ccx23 (4 vCPU/16 GB) |
|---|---|---|
| scp 600 MB coordinator→worker | 101.5 s (**5.9 MB/s**) | 105.0 s (**5.7 MB/s**) |
| mksquashfs pack, 600 MB incompressible, zstd 6/1M | 0.7 s | 0.5 s |
| sha256 of the 600 MB artifact | 2.0 s (~300 MB/s) | 1.7 s (~350 MB/s) |
| e2e `nau build --all`, 3×300 MB dep stages, 2 workers | cold **47.9 s**, warm **48.4 s** | (same run) |

Hetzner pricing (hourly gross, per-vCPU derived):

| SKU | vCPU/RAM | €/hr | €/vCPU-hr | €/mo cap | €/vCPU-mo |
|---|---|---|---|---|---|
| ccx13 | 2/8 | 0.0809 | 4.05¢ | 50.49 | 25.2 |
| ccx23 | 4/16 | 0.1626 | 4.07¢ | 101.49 | 25.4 |
| ccx33 | 8/32 | 0.2612 | **3.27¢** | 162.99 | **20.4** |
| ccx43 | 16/64 | 0.5216 | **3.26¢** | 325.49 | **20.3** |

## Findings

1. **The coordinator uplink is the bottleneck, not the worker.** Both SKUs pulled
   at ~6 MB/s — the same pipe. The cold e2e wall (47.9 s) is almost exactly the
   sync time for ~300 MB at that rate. Worker CPU was idle-adjacent: pack of
   incompressible data is I/O store speed, sha is 2 s. Until the uplink or the
   payload sizes change, **worker SKU barely matters for cold runs**.
2. **Placement is store-blind, so warm reruns don't pay yet** (#303). The warm
   e2e re-shipped a 300 MB payload to a worker that didn't hold it while the
   worker that DID hold an object saw that job go local: 48.4 s warm vs 47.9 s
   cold — zero warm win despite warm stores. Warm reuse is the point of keeping
   workers; placement should prefer a member already holding the closure.
3. **Per-vCPU pricing is not flat** — ccx33/ccx43 are ~20 % cheaper per vCPU than
   ccx13/ccx23. The council's flat-rate assumption was wrong in the direction
   that favors bigger boxes for sustained wide runs. It does not change the cold
   conclusion (uplink-bound), but for warm/kept fleets doing real compile work,
   ccx33 has the best €/vCPU on the line.
4. **Pack CPU scaling remains unmeasured** — the incompressible payload made pack
   an I/O test. Live logs confirm mksquashfs defaults to all cores
   ("Using 12 processors" locally, "2" on ccx13), so compressible packs scale
   with cores until zstd's thread efficiency flattens (~4-6 threads per prior
   art). Not binding today: sync dominates and pack of real trees was tens of
   seconds even on the coordinator.
5. **The ceremony race is real and now twice-proven** (#299): `nau workers issue`
   signs only *pending* publishes; run it before the guest's publish lands and it
   signs nothing, silently, and the guest starves for its cert. Any automation
   must be publish-gated (`issue --wait`).

## Council consensus (4 seats, unanimous unless noted)

- **No autoscaler, no standing/min pool, no mid-run scaling, no job queue, no
  daemon.** The terminal is the queue; ADR-0011 D5 and ADR-0040 D4 both forbid
  the daemon shape; "jobs outliving the coordinator" was already deferred.
- **Warm reuse is a TTL-window ops practice, not code**: provision with a TTL
  wider than the work session, don't destroy, delta sync comes back empty, the
  #269 sweep reclaims. `--keep` ergonomics belong on the burst path, not build.
- **Burst actuator, if built, is a wrapper verb** (`nau workers burst --type
  --count --max --ttl [--keep] -- <cmd>`): provision min(--max, ready-width,
  ceil(pending/jobs)) → publish-gated issue → wrapped build → destroy in a trap
  (failure + Ctrl-C). `nau build` stays byte-for-byte untouched. Knobs are CLI
  flags only — the workers table stays resolved runtime state; a lua-level
  `max` that can silently disable declared workers is a foot-gun.
- **Defaults**: `local_jobs` 3 (unchanged), `jobs` 2 (unchanged), fleet 2-3
  workers for a daily index, 1 worker for a single-package burst, hard ceiling
  ~4. `jobs=4` on ccx23 is an OOM hazard (link steps), not a speedup.

## Revised sizing guidance with the measured numbers

- **Cold, one-shot windows (today's pattern): 1 worker, SKU nearly irrelevant —
  the uplink gates everything.** A second worker buys nothing while ~6 MB/s
  feeds it; it doubles the bytes through the same pipe (delta dedup is
  per-worker, #303's math).
- **Warm/kept fleets doing real compile work: 2× ccx23 (jobs=2)** — the council
  default stands; ccx33 becomes interesting ONLY for warm index runs where its
  -20 %/vCPU price and halved sync bytes (one store instead of two) outweigh
  losing a failure domain. Revisit when placement is store-aware (#303) and
  phase timings ship (#302) — those decide it with data.
- **ccx43: never** (sublinear compile slope past ~8 vCPU; nothing here is wide
  enough). **ccx33: not in the default fleet** (decision point C, evidence-gated).

## Change set (merged council + measurements, ordered)

1. **Fallback launder fix** — main.rs:470-508: a config file that exists but
   fails eval must be fatal, not a silent local-only build. (#297)
2. **Deterministic SSH client identity** — `IdentitiesOnly=yes` + resolved `-i`
   (entry field > `NAU_SSH_IDENTITY` > provisioned operator key; optionally
   `-F /dev/null`); preflight names what was tried. (#298)
3. **Prebuilt pinned mksquashfs artifact** — closes an artifact-identity hazard
   (apt libzstd drift changes pack bytes for identical trees; ADR-0041 makes
   the compressor library part of identity) and removes ~3 min from every
   provision. (#300)
4. **`issue --wait`** — publish-gated cert wait with a loud timeout; makes the
   proven silent-vacuous-success fail-closed; prerequisite for any auto-issue.
   (#299)
5. **Store-aware placement** — prefer an eligible member already holding the
   node's closure (held_objects already computed in delta_sync); makes warm
   windows actually warm. (#303, new from this benchmark)
6. **Per-job phase timings** in the run summary — dispatch/sync/build/ingest;
   would have surfaced #303 without a hand-rolled benchmark. (#302, jev
   observability 5.1/10 baseline)
7. **`nau workers burst … [--keep]` + `down --all-managed`** — the only real
   feature; ceremony compression of the window the runbook §1.6 prescribes by
   hand. Blocked by #299/#300. (#301)

## Not building

Autoscaler; standing/min pool; idle detection; mid-run scaling; job queue;
worker daemon; snapshot provisioning (revisit if burst frequency goes daily
AND `--keep` windows fail); `min`/`max`/`auto` blocks in nau.lua; auto-provision
inside `nau build`; jobs=4 on 4-vCPU boxes; ccx43; folding worker object stores
into the ADR-0043 shared cache.

## Revisit triggers

- Store-aware placement shipped + phase timings (#302/#303) → re-measure ccx33
  vs 2×ccx23 on warm index runs (decision point C).
- Uplink upgrade (or coordinator colocation) → sync stops dominating and worker
  CPU (SKU, jobs per box) becomes the live question; re-run the pack benchmark
  with a COMPRESSIBLE payload (the 2026-09-29 run could not measure zstd CPU
  scaling).
- Bursts become daily-with-cold-starts and `--keep` windows fail → snapshots
  reopen (#194's recorded open decision).
- Multiple coordinators or sustained builds/hour → only then, a queue.

## jev baseline (farm implementation, 2026-09-29)

observability 5.1 · scalability 5.7 · security 5.4 · reliability 5.8 ·
changeability 5.9 · performance 6.1 · correctness 6.3 · maintainability 6.2 ·
duplication 6.7 · compatibility/cognitiveComplexity 6.4 · modularity/
abstractionQuality/testQuality 7.1 · projectStructure/consistency 7.0 ·
readability/documentation 7.3. All priorities low-severity; the weak axes map
1:1 onto tickets #298 (security), #302 (observability), #303/#301
(scalability), #297 (reliability/correctness).
