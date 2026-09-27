# Nau infra plan: the distro-facing domain structure (nau.rclb.dev)

Date: 2026-09-27. Companion to `.planning/server-infra-plan.md` (the
operator-facing build infra) and ADR-0044 (what mission images must carry).
This plan defines the PARALLEL, distro-facing surface: the domains Nau users
touch, as opposed to the zet.rclb.dev services the operator's tooling uses.
It reuses the zet cluster unchanged — same VPS, same Caddy, same tofu phase —
and adds one wildcard certificate plus static trees. No new daemons, no new
databases, no new secrets.

## Relationship to the brand domains (ADR-0013)

ADR-0013 assigned the public brand home: org `github.com/nau-os`, domains
`nauos.dev` (contingency `nau-os.dev` → `naulinux.org`), behind a blocking
trademark re-sweep before release. `nau.rclb.dev` is deliberately NOT that:
it is the operator-owned operational home on infrastructure already
controlled, usable from today, with no trademark implications. The mapping
is one decision, recorded here: **rclb.dev names are the canonical
infrastructure lanes (update_source, cache URLs baked into images and
docs); when the brand domains are registered and the trademark gate passes,
www content moves or aliases to them and the baked lane URLs either stay
(redirects) or a re-image decision is taken.** Baking operator-domain URLs
into released images couples Cassini to rclb.dev — accepted for 1.0, revisit
trigger: brand domain goes live. Domain registration itself is an operator
purchase action, not automated here.

## Domain map

| Name | Serves | Backing | Audience |
|---|---|---|---|
| `www.nau.rclb.dev` | Distro landing page: what Nau is, mission list, download links, verification instructions (SHA256SUMS + signed manifest check), pronunciation guide (ADR-0013 ships one) | Static files, Caddy `file_server` | Everyone |
| `download.nau.rclb.dev` | Mission images: `nau-<mission>-<version>-<arch>.img` + `SHA256SUMS` + signed image manifest (ADR-0044 D5), plus sysupdate transfer artifacts — the `update_source` URL baked into released images | Static files, Caddy `file_server` | Installing users; installed machines (updates) |
| `cache.nau.rclb.dev` | Public package mirror: the ADR-0033 Decision 10 export tree (`index.json`, `manifests/`, `blobs/`) for the released pool — what `shuttle pull https://…` and Nau pods consume | Static files, Caddy `file_server` | Nau users' machines |

Deliberately absent: no auth service, no API, no state. Everything under
`nau.rclb.dev` is a static file served read-only. The operator's build cache
stays on `cache.zet.rclb.dev/shuttle-cache/` — different content class
(build cache vs released pool), different audience, different lifecycle.

## Decisions

1. **Same zone, per-host certificates, no new Caddy binary.** `nau.rclb.dev`
   lives in the existing `rclb.dev` Cloudflare zone, so `*.nau.rclb.dev →
   62.238.62.155` is one DNS-only A record via the existing tofu token.
   The v1 assumption that Caddy already does DNS-01 wildcards was wrong:
   zet's Caddy is the stock Cloudsmith apt package with explicit per-host
   blocks and HTTP-01 certificates — there is no Cloudflare DNS plugin and
   no token on the box. Keep it that way: three (plus optional apex) names
   get per-host HTTP-01 certs from stock Caddy, which is what `zet`
   already does. No plugin build, no secret on the VPS, no Let's Encrypt
   wildcard rate concerns. If `https://nau.rclb.dev` should resolve, add
   the explicit A record (the wildcard does not cover the apex) and a
   vhost that 308s to www. TLS, HTTP→HTTPS, and h2 are inherited.
2. **Disk + `file_server`, not rustfs.** The read path needs no S3
   semantics (the same finding the infra plan hit for the cache lane):
   static trees served by Caddy from local directories, with native Range
   support (resumable image downloads and sysupdate transfers need it) and
   sendfile for multi-GB files. Images are few large files; the package
   mirror is a curated per-mission tree, not a growing build cache; and
   rsync publish needs zero new secrets — it rides the existing tailnet
   ssh from the workstation, the same channel `secrets-apply` already
   trusts. Prune policy per tree: `www` and `cache` are rebuildable and
   follow the curated source with `rsync --delete`; **`download` is
   append-only for released missions** — a released image is an artifact,
   not a rebuildable cache entry, so deletion from the download tree is a
   recorded policy act per mission, never a side effect of publish.
   Migration path if the trees outgrow the disk: move them to a rustfs
   bucket or Object Storage and flip the vhost to proxy — the URLs do not
   change.
3. **Publishing is rsync over the tailnet, per lane.** `www` and `download`
   publish from the repo/tree the release flow produces (#266 emits the
   media set; this plan gives it a destination directory layout);
   `cache` publishes from `shuttle export` of the released pool. All
   three are `rsync -r --delete` runs from the workstation (download
   scoped to the staging area, never over released mission dirs per
   decision 2) — idempotent, secrets-free. Each publish updates a
   freshness stamp file per tree (`<timestamp> <release-id>` lines), and
   the kuma monitors content-match the stamp, not just status 200 —
   otherwise "publish did not run" and "publish ran from a stale source"
   are indistinguishable. The publish scripts are thin wrappers (one per
   lane) so a release is one command per lane.
4. **Updates are the download lane, through a pointer file.** ADR-0044 D5
   bakes `update_source` into released images; concretely it is
   `https://download.nau.rclb.dev/missions/<mission>/` with sysupdate
   transfer artifacts alongside the images, and a stable pointer file
   (`current.json`, updated by publish) so version and directory
   reshuffles never require a re-image. Install and update share one
   tree, one domain, one certificate.
5. **Cloudflare proxy caveat.** The zone's records stay DNS-only (grey)
   for `download` and `cache` — origin serves bytes directly, honest
   bandwidth accounting; proxied caching of multi-GB `.img` files is NOT
   assumed (free-plan cacheable-object limits likely exclude them —
   verify before relying on it). `www` may go orange later. Revisit when
   download traffic is real; the CDN path (Cache Rules + tiered cache or
   Object Storage origin) is the scale-out. Bandwidth-abuse posture,
   stated: Caddy core has no rate limiter; accept until the kuma/traffic
   logs say otherwise, then add a layer-4 or application limiter.
6. **Observability and hygiene**: kuma HTTP monitors from `monitors.json`
   — landing page 200, `download` HEAD on the current `SHA256SUMS`,
   `cache` GET on `index.json`, plus the stamp content-match of decision
   3. Security headers on all three vhosts; HSTS only after every
   consumer is confirmed https-capable (sysupdate is; old `shuttle pull`
   versions must be checked before flipping it). `www` gets robots.txt +
   sitemap (#275 scope). Directory listing stays off; a checklist
   assertion proves `GET /missions/<m>/` returns the index file or 404,
   never a listing.

## zet-side execution checklist

1. **DNS** — `tofu/dns.tf`: add the `*.nau.rclb.dev` A record (DNS-only,
   `proxied = false` explicit) plus the apex `nau.rclb.dev` A record if
   the redirect vhost is wanted; `tofu apply` via the deploy pipeline's
   dns phase.
2. **Certificates + vhosts** — `Caddyfile.j2` gains per-host blocks for
   `www`/`download`/`cache` (+ the apex redirect if the record exists);
   stock Caddy obtains per-host HTTP-01 certificates exactly as it does
   for the zet subdomains — no plugin, no wildcard, no token on the box.
   Roots: `/srv/nau/{www,download,cache}`, `browse` off, security headers
   on, freshness stamp written into each root.
3. **Trees** — directory scaffolding + stamp files + the no-listing
   assertion (`GET /missions/<m>/` returns the index file or 404, never a
   listing).
4. **Publish scripts** — `scripts/nau-publish-{www,download,cache}.sh`
   (rsync over tailnet ssh; `--delete` scoped per decision 2 — download
   never deletes released mission dirs; stamp update per decision 3);
   referenced by the release flow (#266's destination) and by pool
   releases.
5. **Kuma monitors** — the three HTTP checks plus stamp content-match of
   decision 6 in `scripts/kuma/monitors.json`; re-run
   `kuma-provision.sh`.
6. **Deploy** — the standard `scripts/deploy.sh` phases (tofu → dns →
   caddy → deploy); no secrets phases needed (nothing new authenticates).

## shuttle-side tickets

- **#274 (new): publication lane wiring** — the download directory layout
  per mission (`missions/<mission>/{images,SHA256SUMS,manifest,updates}`
  plus the `current.json` pointer file of decision 4), the `update_source`
  value baked by `shuttle image --release` pointing at
  `download.nau.rclb.dev`, and the rsync publish wrapper. Rides ADR-0044
  ratification (#261) and lands with #266.
- **#275 (new): public package mirror** — `shuttle export` of the released
  pool to the `cache.nau.rclb.dev` tree: which packages a mission pins,
  export-tree freshness stamp, the publish wrapper, and confirmation that
  the signed-manifest verification machinery covers `index.json` and the
  manifest tree, not just the download lane. Decision-10 lane, public
  audience — same verification machinery, no new trust surface.
- **#276 (new): www landing + download page** — static page: mission list,
  per-arch download links, verification walkthrough (SHA256SUMS + signed
  manifest), pronunciation guide, docs links, robots.txt + sitemap.
  Content per the ADR-0013 brand rules. UI work: route through design
  when implemented, not a bare-HTML first pass.

(Note: issue numbers are assigned at creation time; the worker-template
ticket filed earlier in this session took #273.)

## Sequencing

DNS + certificate + vhosts (zet checklist 1-3) land any time — they serve
empty trees harmlessly and unblock everything else. `www` (#275) is
independent. `download` (#273) rides #261 + #266: no images exist before
the release flow emits them. `cache` (#274) needs a curated released pool,
which post-dates the first mission candidates. Nothing here gates the
worker lane or the build cache; it is downstream of both by design.

## Risks

- **One VPS serves the public distro.** Downloads and mirrors share the
  cx33 with everything else. Fine for a 1.0 with a small user count;
  the scale-outs are the CDN path (decision 5) and Object Storage origin,
  both URL-preserving. Watch: kuma monitors + traffic logs.
- **Disk scarcity, again.** Images are large and mission-count grows them
  linearly; the mirror grows with the curated pool. Mitigations: per-
  mission cleanup on `rsync --delete` (dropping a mission's images is a
  policy act), and the rustfs/Object Storage migration path if the pool
  outgrows the disk.
- **Baked URLs couple releases to rclb.dev.** Accepted for 1.0 (decision
  above); the revisit trigger is the brand domain going live, and the
  update_source indirection (one baked URL, contents re-pointable) keeps
  the escape hatch one re-image away, not a re-fleet.
- **Cloudflare assumptions unverified** — proxy caching behavior for
  multi-GB objects must be tested before anyone relies on it (decision 5
  default: DNS-only, assume origin serves everything).
