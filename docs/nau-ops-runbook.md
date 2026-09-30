# Nau operator runbook — publication lanes + worker account (issue #279)

Status: **draft for the operator — nothing here has been applied.** This
document is the authored execution pack for the operator-side steps behind
#271/#274/#275/#276/#292: the worker account, the DNS lane, the serving
config, the kuma monitors, the worker TTL sweep install, and the
release-to-flash trust chain. Every command cites
its source; no lane executes any of it. Genuinely open operator decisions
are labelled **DECISION SLOT** — there are exactly two (A and B, summarised
in §8); everything else is decided in an existing source and referenced.

Hosting context: the zet VPS was deleted and ADR-0046 re-homed the lanes
onto the Nau deployment itself (`.planning/nau-infra-plan.md`'s hosting
banner records the same). The config contracts below come from the plan
and are placement-agnostic; where an application target still depends on
the open lane-service-stack decision, this runbook says so inline instead
of inventing one.

## 0. Sources and conventions

| Ref | Source | Used for |
|---|---|---|
| PLAN | `.planning/nau-infra-plan.md` decisions 1-3, 5-6 + execution checklist | DNS, vhosts, publish/stamp model, monitor list, grey-cloud policy |
| ADR-0046 | `docs/adr/0046-nau-self-hosting.md` | lane re-homing; monitoring rebuild; latest-LTS host posture |
| #271 | `gh issue view 271` | worker account: project, token, firewall, placement, snapshot ownership, live gates |
| #269 | `gh issue view 269` | TTL sweep semantics: three-condition match, dry-run window, alert-on-failure |
| PROVIDERS | `.planning/worker-providers-plan.md` | SKU classes/prices, locations, OS contract ("latest LTS", never a codename), snapshot lifecycle |
| CACHE-SPEC | `docs/nau-cache-publish.md` | freshness stamp + keyword monitor spec (reference, not duplicated) |
| INFRA | `.planning/server-infra-plan.md` IaC row + decision 5 | TOFU_INPUTS is the full-account token; worker isolation rationale; TTL label contract |
| ZET | `~/Workspace/github.com/rbelem/zet` (READ-ONLY) | tofu/dns.tf record shape, tofu-wrapper apply sequence, monitors.json/kuma-provision.sh, `update-timer.yml` user-timer pattern |

The hcloud worker-lane token (§1) and the tofu full-account token (§2) are
DIFFERENT credentials. The worker lane never reads `TOFU_INPUTS`
(#271, INFRA D5) — that is the whole point of §1.

## 1. Worker account: isolated hcloud project (#271)

Why: `hcloud_token` in SM secret `TOFU_INPUTS` owns the cluster and can
touch DNS; a worker-lane leak must not be a cluster-lane compromise —
structural isolation beats procedural care (#271; INFRA D5).

### 1.1 Project + scoped token

1. Create a dedicated project in the Hetzner Cloud Console (projects are
   console-level; the API/token surface sits *inside* a project, so this
   step is manual). Name is free — `nau-workers` reads well.
2. In the new project: Security → API tokens → create an API token with
   **Read + Write** (the CLI needs write for server create/destroy and
   firewall attach; hcloud project tokens cannot reach resources in other
   projects — that scoping IS the #271 isolation boundary; the finer
   read/write split per resource class does not exist in hcloud).
3. Store it under a NEW key — `HETZNER_WORKER_TOKEN` is #271's example —
   never inside `TOFU_INPUTS`.

> **DECISION SLOT A — RESOLVED (2026-09-29, operator): Bitwarden SM via the
> secrets cache.** `HETZNER_WORKER_TOKEN` is a new SM item in the
> devbox-global vault; consumers (provisioner #194, sweep #269) receive it
> through the secrets cache (`/run/user/1000/devbox-secrets.sh` → env; zet's
> `scripts/bws-get` is the retrieval prior art). It is never `TOFU_INPUTS`
> and never a plaintext file.

Export it for the CLI session (the `HCLOUD_TOKEN` env var is what the
hcloud CLI reads; #269's sweep drives the same CLI):

```bash
# HETZNER_WORKER_TOKEN: Bitwarden SM item delivered by the secrets cache
# (DECISION SLOT A). HCLOUD_TOKEN is the hcloud CLI's env var:
export HCLOUD_TOKEN="$HETZNER_WORKER_TOKEN"
```

### 1.2 Firewall: ssh from the operator only

```bash
# source: #271 "firewall attached at create time; ssh ingress from the
# operator's addresses only" — PLAN checklist has no server-side firewall
# step, so this is account-side by design
hcloud firewall create --name nau-workers-fw
hcloud firewall add-rule nau-workers-fw \
    --direction in --protocol tcp --port 22 \
    --source-ips <coordinator-or-tailnet-ip>/32[,<second-ip>/32]
```

`<coordinator-or-tailnet-ip>` = the operator's coordinator/tailnet egress
addresses (operator-known values, not a source-recorded decision). The
"+ established" half of #271's rule needs no second rule: hcloud
firewalls are stateful, so return traffic for connections the server
initiates is allowed inherently. Outbound stays unrestricted (no rule
objects exist for it by default) — matches #271's scope.

### 1.3 Placement and machine classes

Placement **hel1** is the recorded decision (#271 "same region as
cache.zet.rclb.dev"; PROVIDERS §4 amend: "placement hel1 stands"; ADR-0046
neutral: #271 stands). The locality rationale named the zet cache, which
ADR-0046 re-homed — if the Nau host lands in another region, re-checking
placement before the first provision is an operator call, not a recorded
change. Classes per PROVIDERS §1, AMENDED 2026-09-29 (operator relayed
Hetzner's policy: sustained high CPU belongs on DEDICATED vCPU — shared
CX lines are not sanctioned for build workers; the post-2026-06-15
repricing note stands, and #194's `cx22` example is stale and MUST NOT
be copied):

| Class | SKU | vCPU/RAM/disk | Note |
|---|---|---|---|
| build-light | ccx13 | 2/8/80 | single-package bursts; the first live worker (2026-09-29 lane) |
| build-default | ccx23 | 4/16/160 | daily loop, index runs |
| build-aarch64 | CAX11/CAX21 | 2/4/40, 4/8/80 | **deferred** — pool is x86_64-only (operator decision 2026-09-27, PROVIDERS §1) |

- IPv4 by default (#271); post-reprice it is a separately billed resource
  (≈ €0.30/mo community figure, unit price unverified — PROVIDERS §1).
  IPv6-only is the recorded later cost cut (#271).
- CPX SKUs remain non-candidates (repriced steeply, PROVIDERS §1). No
  nested KVM on Hetzner Cloud; a kvm-capable class is a future
  dedicated-root question (PROVIDERS §1).
- Workers live ONLY while a lane uses them: provision → build → destroy
  in one window (operator directive 2026-09-29 — dedicated vCPU is too
  expensive to idle). The TTL sweep is the backstop, not the plan.
- Placement groups: out of scope, recorded so nobody adds them for
  ephemeral singletons (#271; INFRA D5).
- Worker OS: the template pins **latest Ubuntu LTS, never a codename**
  (PROVIDERS §3 — 26.04 at decision time), stock image + two tool pins;
  that template is #194/#276's artifact, not an account step. A runbook
  command below uses a throwaway image only.

### 1.4 Snapshot lifecycle layout

Ownership rule (#271): **if the golden-image route wins in #194, this
project owns snapshot build + refresh cadence.** Cadence, per PROVIDERS
§3: one snapshot per (OS, tool-pin) version, refreshed on every pin bump
(squashfs-tools 4.7.x is the pin that moves); Hetzner bills snapshots per
compressed GB-month (historically ≈ €0.012, unit price unverified —
PROVIDERS §3) — noise at template scale. When the route is confirmed,
snapshot creation rides the template server:
`hcloud image create --type snapshot --server <server> --description <os>-<tool-pin>-<date>`
— the description encodes the (OS, tool-pin) pair so the cap probe can
pin against it. Until #194
decides, no snapshots are built — per-boot cloud-init is the default
route (INFRA D5).

### 1.5 Live verification gates (#271 "Verify, live")

```bash
# 1. Project scoping — the worker token cannot see anything outside the
#    worker project (#271's "cannot see zet" gate; zet itself is gone per
#    ADR-0046 — the property is scoping, not the instance):
hcloud server list
#    → empty (the other projects' resources are invisible)

# 2. Firewall attached at create — cheapest class, throwaway image
#    (image choice is immaterial to this test; the fleet OS contract is
#    PROVIDERS §3's, owned by #194/#276):
hcloud server create --name fw-attach-test --type cx23 --location hel1 \
    --image ubuntu-24.04 --firewall nau-workers-fw \
    --ssh-key <operator-key>
hcloud firewall describe nau-workers-fw   # → applied_to: fw-attach-test

# 3. Clean destroy — server + volume (#271 gate):
hcloud volume create --name fw-attach-test-vol --size 10 \
    --location hel1 --server fw-attach-test
hcloud server delete fw-attach-test
hcloud volume delete fw-attach-test-vol
hcloud server list && hcloud volume list   # → both empty
```

### 1.6 Live worker ceremony

The operational sequence for one build window — provision → build →
destroy (§1.3's "workers live ONLY while a lane uses them"). Distilled
from two live runs (2026-09-29); every step was executed, not planned.

1. **Preflight channel.** Serve the publish front on `127.0.0.1:8477`
   (any shim that 404s unknown paths but serves the token paths works)
   and expose it ONLY via `tailscale funnel --https=8443
   127.0.0.1:8477`. The worker binary rides the same front at
   `/bin/nau-amd64`, patchelf'd first: interpreter
   `/lib64/ld-linux-x86-64.so.2`, rpath removed — unpatched, the
   nix-linked binary dies on Ubuntu with "required file not found".
2. **Provision.**
   `nau pool provision --provider hetzner --type ccx13 --location
   hel1 --count 1 --ttl 1h --file <proj>/nau.lua`. The `hcloud` CLI
   resolves ONLY inside `nix shell nixpkgs#hcloud -c ...`; the token is
   SM `HETZNER_WORKER_TOKEN` via the secrets cache (DECISION SLOT A),
   never `TOFU_INPUTS` (§1).
3. **Issue is explicit AND racy (proven live).** `nau pool issue`
   signs only identities whose publish has landed in the pending store,
   and a guest's publish lands 1-4 minutes after server create (boot +
   binary download). An issue run too early signs NOTHING and the guest
   polls its cert for the whole token window (pickup-host-cert:
   1440 × 60s). #299 productized the wait: `nau pool issue --wait`
   polls (~5s) until every published identity is signed, with a loud
   named timeout (default ceiling 600s). The manual fallback — run
   `nau pool issue`, probe the cert, repeat — still works, but probe
   the CERT (`test -s /etc/ssh/sshd_config.d/nau-host-cert.conf`), not
   just the ssh login: a login success says nothing about the cert.
4. **Workers-table gotchas.** `local_jobs` must sit OUTSIDE the
   machine-managed BEGIN/END block: inside it the validator refuses any
   line that is not its own (provision/destroy own the block); outside
   the table entirely it silently defaults to 3 and starves the worker.
5. **Build + destroy in ONE window.** Dedicated vCPU is too expensive
   to idle (operator directive, §1.3) — the TTL sweep is the backstop,
   not the plan. Destroy in the same session that built — or use
   `nau pool burst … -- <cmd>` (#301), which wraps provision → issue
   --wait → command → destroy (failure and Ctrl-C included) in one
   command; `--keep` parks the window, `nau pool down --all-managed`
   drains it later.
6. **Client identity is pinned (#298).** Provision records the resolved
   key path as the entry's `identity` field, and the executor presents
   exactly that key (`IdentitiesOnly`) — ambient `~/.ssh/config` can no
   longer hijack the channel. The PATH-wrapped `ssh`/`scp` with
   `-F <lane-ssh-config>` remains the workaround ONLY for entries
   written before the pin (legacy entries are preserved verbatim, never
   backfilled) — or set `NAU_SSH_IDENTITY` for them.
7. **The mksquashfs pin ships as a prebuilt artifact (#300).** Workers
   `curl` + sha256-verify it from `NAU_MKSQUASHFS_ARTIFACT_URL`. The
   default now RESOLVES: the pinned artifacts ride the `v0.1.0` release
   on the public repo (#305), so unauthenticated fetches succeed and
   byte-match the compiled-in consts. Funnel-front windows KEEP the
   export (e.g. `https://<funnel>/bin`, where the lane's `dist/` holds
   the pinned binaries) — the worker BINARY still rides the funnel
   regardless, and the artifact override rides along. Re-pins are
   DELIBERATE: rebuilding via `scripts/build-mksquashfs-artifact.sh`
   moves the artifacts, the SHA256SUMS, and the consts in
   `src/provision/mod.rs` in one commit. A worker that missed the pin is
   REFUSED at preflight by design — admission is fail-closed, so a bad
   or missing artifact wastes the window silently-until-preflight. If
   preflight refuses and the guests are still alive, pull
   `/var/log/cloud-init-output.log` BEFORE destroying: it is the only
   forensic for install-leg failures.

## 2. DNS: `*.nau.rclb.dev` wildcard (PLAN decision 1)

One DNS-only A record in the existing `rclb.dev` Cloudflare zone —
no new zone, no proxy, no wildcard certificate (per-host HTTP-01 in §3
instead). The record value is pinned by #279/PLAN decision 1:
**62.238.62.155**; if the Nau host's actual address differs at deploy
time, correct the record in the same apply.

Managed by tofu, exactly like every rclb.dev record: the Cloudflare
token rides SM `RCLB_DEV_CLOUDFLARE_API_KEY` (Zone:Read + Zone:DNS:Edit —
ZET `tofu/provider.tf`), the hcloud token rides SM `TOFU_INPUTS`
(ZET `scripts/deploy.sh` header). This is the full-account-token step —
NOT the §1 worker token.

Edit `tofu/dns.tf` in the zet repo (the rclb.dev zone's IaC home — its
scripts survive as the re-runnable artifact per ADR-0046), mirroring the
existing VPS-record shape (`proxied = false` explicit, ttl 600):

```hcl
# source: PLAN decision 1 + checklist 1; record shape = ZET tofu/dns.tf
resource "cloudflare_record" "nau_wildcard" {
  zone_id = data.cloudflare_zone.main.id
  name    = "*.nau"
  type    = "A"
  content = "62.238.62.155"
  proxied = false   # DNS-only grey — PLAN decision 5
  ttl     = 600
}

# OPTIONAL — apex record, only if the §3 redirect vhost is wanted
# (the wildcard does not cover the apex — PLAN decision 1):
resource "cloudflare_record" "nau_apex" {
  zone_id = data.cloudflare_zone.main.id
  name    = "nau"
  type    = "A"
  content = "62.238.62.155"
  proxied = false
  ttl     = 600
}
```

Apply via the wrapper — the same plan → apply sequence
`scripts/deploy.sh` phase_tofu runs (the pipeline's dns phase only
confirms what tofu apply wrote):

```bash
# source: ZET scripts/deploy.sh phase_tofu + PLAN checklist 1
cd ~/Workspace/github.com/rbelem/zet/tofu
./tofu-wrapper.sh init -input=false
./tofu-wrapper.sh plan -input=false -out=/tmp/tofu-plan.out
./tofu-wrapper.sh apply -input=false -auto-approve /tmp/tofu-plan.out
```

Grey-cloud policy (PLAN decision 5): `download` and `cache` stay
DNS-only permanently for now — origin serves bytes directly, honest
bandwidth accounting; proxied caching of multi-GB `.img` files is NOT
assumed. `www` may go orange later. Verify propagation:

```bash
dig +short www.nau.rclb.dev A    # → 62.238.62.155
```

## 3. Caddy vhosts: three per-host blocks (PLAN decisions 1-2)

**Stock Caddy, no plugin, per-host HTTP-01** (PLAN decision 1 — the v1
DNS-01 wildcard assumption was wrong; zet's Caddy is stock with explicit
per-host blocks; keep it that way: no plugin build, no secret on the
serving box, no wildcard rate concerns). Where it applies: PLAN checklist
2 wrote the blocks into the zet `Caddyfile.j2`; ADR-0046 D3 moves the
lanes + TLS terminator onto the Nau deployment as pod services, and the
plan's hosting banner leaves the lane service stack open. The blocks
below pin the **config contract** (hosts, roots, behaviour); the serving
stack that carries them follows the ADR — the operator applies them to
whatever terminator the Nau deployment lands, unchanged.

Prerequisites (HTTP-01 is why §2 came first): the three names resolve to
the host before first cert issuance; ports 80/443 reachable; the zone's
`*` CAA record already allows `letsencrypt.org` (ZET `tofu/dns.tf`),
so issuance is unblocked.

```caddyfile
# source: PLAN decisions 1-2 + checklist 2 (roots, browse off) +
# decision 6 (headers, no listing). TLS, HTTP→HTTPS, h2 inherited.

www.nau.rclb.dev {
	root * /srv/nau/www
	file_server
	# security headers: PLAN decision 6 requires "security headers on all
	# three vhosts" but no source pins the exact set — OPEN ITEM, decide
	# before serving real traffic. HSTS waits until every consumer is
	# confirmed https-capable (PLAN decision 6): sysupdate is; old
	# `nau pull` versions must be checked before flipping it.
	# header { ... }
}

download.nau.rclb.dev {
	root * /srv/nau/download
	# file_server gives native Range (resumable image downloads, sysupdate
	# transfers) and sendfile for multi-GB files — PLAN decision 2. No
	# `browse`: directory listing stays off (PLAN decision 6).
	file_server
	# APPEND-ONLY is a publish policy, not vhost config (PLAN decision 2):
	# a released image is an artifact; deletion is a recorded per-mission
	# act, never a publish side effect.
}

cache.nau.rclb.dev {
	root * /srv/nau/cache
	file_server
}

# OPTIONAL — only if the §2 apex record exists (PLAN decision 1):
nau.rclb.dev {
	redir https://www.nau.rclb.dev{uri} 308
}
```

Post-apply checklist (PLAN checklist 3 + decision 6):

```bash
# certificates issued per host (stock Caddy ACME, no plugin):
curl -sI https://www.nau.rclb.dev/      | head -1   # → HTTP/2 200 (once #276 content lands)
curl -sI https://download.nau.rclb.dev/ | head -1
curl -sI https://cache.nau.rclb.dev/    | head -1

# no-listing assertion — GET /missions/<m>/ returns the index file or
# 404, never a listing (PLAN decision 6):
curl -s https://download.nau.rclb.dev/missions/<m>/ -o /dev/null -w '%{http_code}\n'

# Range works (PLAN decision 2 — resumable downloads):
curl -s -r 0-0 -o /dev/null -w '%{http_code}\n' https://download.nau.rclb.dev/missions/<m>/SHA256SUMS
# → 206 once content exists
```

## 4. kuma monitors (PLAN decision 6 + CACHE-SPEC)

Four monitors + one presence check (#292). The stamp monitor is the one
that catches a silently stale tree; the others catch a dead origin — or a
half-served media set.

1. **`nau cache mirror — stamp release`** — the keyword monitor on
   `https://cache.nau.rclb.dev/freshness.stamp`. Full field spec (type,
   method, accepted status, invert, keyword semantics, alert semantics)
   is CACHE-SPEC's "Kuma content-match monitor spec" — reference it, do
   not re-derive. The keyword is the currently expected pool release-id
   (e.g. `pool-gen121`), and the operator updates it at EVERY pool
   release, right after `scripts/nau-publish-cache.sh --release-id
   <new-id> …` (CACHE-SPEC's two-command loop: publish, then update the
   keyword). A past release-id in the stamp history does NOT satisfy the
   check.
2. **cache index** — plain HTTP monitor: `GET
   https://cache.nau.rclb.dev/index.json`, accept 200 only (CACHE-SPEC
   companion + PLAN decision 6).
3. **www landing** — plain HTTP monitor: `GET
   https://www.nau.rclb.dev/`, accept 200 (PLAN decision 6).
4. **download** — `HEAD
   https://download.nau.rclb.dev/missions/<mission>/SHA256SUMS`, accept
   200 (PLAN decision 6: "HEAD on the current SHA256SUMS"; one monitor
   per released mission, `<mission>` filled from the released set).
5. **download signature presence** (#292) — `HEAD
   https://download.nau.rclb.dev/missions/<mission>/SHA256SUMS.gpg`,
   accept 200, one monitor per released mission beside monitor 4.
   Monitor 4 going green proves nothing about the signature: a vanished
   `SHA256SUMS.gpg` over a live `SHA256SUMS` is the
   monitor-green-while-channel-dead trap — the sysupdate `Verify=yes`
   path is dead while every plain-HTTP check stays green. This monitor
   checks EXISTENCE only; signature validity stays the device's job (gpg
   against the embedded `/usr/lib/systemd/import-pubring.pgp`). A
   vanished signature must page, not stay green. The kuma config is
   operator-applied (the zet `scripts/kuma/monitors.json` +
   `kuma-provision.sh` pattern, rebuilt per ADR-0046) — this check lands
   in the rebuilt monitor set; nothing in-repo to patch.

Application vehicle: monitors-as-code in the zet repo's
`scripts/kuma/monitors.json`, applied by `scripts/kuma-provision.sh`
(socket.io; UI-created monitors are never deleted by the provisioner).
Caveat from ADR-0046: the monitoring stack died with zet and must be
rebuilt — the definitions above are placement-agnostic and land wherever
the successor kuma runs.

> **DECISION SLOT B — RESOLVED (2026-09-29, operator): multi-notify
> fan-out.** Alerts go to ALL configured mechanisms — first-class kuma push
> and ntfy topics, extensible to further destinations — LANDED under #296
> alongside #287's sweep axes: the sweep's destination list is
> `NAU_SWEEP_KUMA_URLS` + `NAU_SWEEP_NTFY_URLS` +
> `NAU_SWEEP_ALERT_CMD` (the extensibility seam; a command string per
> alert, "$1" = the one-line summary). Every alert fans out to all of
> them; one destination failing is named and never silences the others
> (the run fails when it does — an unacked alert is itself alarm-worthy).
> ADR-0046's monitoring destination question is answered by the same
> design.

## 5. TTL sweep install (#269 + #287/#296 — by reference)

Artifacts live in THIS repo:

- `scripts/nau-worker-ttl-sweep` — the sweep script (POSIX sh;
  independent of nau code; fake-CLI test suite beside it,
  `nau-worker-ttl-sweep-test.sh`).
- `scripts/systemd-user/` — the workstation systemd **user** units,
  mirroring the zet repo's `update-timer.yml` pattern (systemd user
  timer, not cron; workstation-only — the credentials live there).

Install sequence (unit names as #269 lands them; the steps are the
standard user-unit path the `update-timer.yml` pattern uses — copy units
to `~/.config/systemd/user/`, then):

```bash
systemctl --user daemon-reload
systemctl --user enable --now <sweep-timer>.timer    # name per #269
systemctl --user is-active <sweep-timer>.timer       # verify
scripts/nau-worker-ttl-sweep                     # first run: dry-run IS the
                                                     # default for two weeks (#269)
```

### 5.1 Axes (#287)

The hcloud axis is ALWAYS on (the #269 v2 rules, unchanged). The four
non-hcloud axes are OPT-IN — each queries the exact `nau-worker` /
`nau-worker-ttl` (epoch-seconds expiry) tags its provider stamps at
create time, runs the SAME v2 rule engine (tag → in-guest marker copy →
48h-alert/72h-destroy age floor), and mirrors its provider's own destroy
verb and residual warnings:

| axis | enable | CLI (+creds the CLI reads from the env/config) | destroy | residuals named before/after |
|---|---|---|---|---|
| hcloud | always on | `hcloud` (`HCLOUD_TOKEN`, §1) | `server delete` — **BLOCKED** unless `volume list --server X` is empty (checked in dry-run too) | — (the gate IS the check) |
| aws | `NAU_SWEEP_AWS=1` | `aws` (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`; region from `AWS_DEFAULT_REGION`/profile — the create's `--region` discipline) | `ec2 terminate-instances` | attached volumes with `DeleteOnTermination=false` (warn, terminate proceeds); a FAILED volume check blocks |
| gcp | `NAU_SWEEP_GCP=1` | `gcloud` (ADC / `gcloud auth`; project+zone from the CLI config) | `compute instances delete --zone Z` (zone from the listing) | disks with `autoDelete` off (warn, delete proceeds); a FAILED describe blocks |
| azure | `NAU_SWEEP_AZURE=1` | `az` (`az login` state; subscription from the CLI config) | `vm delete --resource-group RG` | disks with `deleteOption != Delete` (warn, proceeds); post-delete unattached NIC + public-IP orphans (public IPs bill); a FAILED disk check blocks |
| scaleway | `NAU_SWEEP_SCW=1` | `scw` (`SCW_ACCESS_KEY`/`SCW_SECRET_KEY`; zone from `SCW_DEFAULT_ZONE`/config — the create's `-z` discipline) | `instance server delete server-id=ID` | attached volumes (a delete only DETACHES them — they keep billing; warn, proceeds); a FAILED get blocks |

Axis failure semantics: a named per-axis failure (missing binary/jq on an
enabled axis, enumerate/parse/delete API failure) alerts, counts, fails
the run (rc 1) — and NEVER blocks the other axes. An axis that is not
enabled is logged in the summary, never alerted: a provider not in use
must not page daily. Provider credential setup itself is out of scope
here (per-provider worker accounts are #271-shaped; the sweep only needs
READ+DELETE on the worker resources).

### 5.2 Alert fan-out (#296 — DECISION SLOT B resolved)

Every alert (sweep API failure, volume-blocked destroy, 48h floor,
enabled-axis skip, notify failure) fans out to ALL configured
destinations; each destination's failure is named, counted, and fails the
run — and never blocks or silences the others:

```bash
# in ~/.config/nau/worker-ttl-sweep.env (the unit's EnvironmentFile)
NAU_SWEEP_KUMA_URLS="https://kuma.example/api/push/TOKEN1 https://kuma.example/api/push/TOKEN2"
NAU_SWEEP_NTFY_URLS="https://ntfy.example/nau-workers"
NAU_SWEEP_ALERT_CMD='curl -s --data-binary "$1" https://example/hook'   # extensibility seam
```

- **kuma push** — alerts POST `status=down&msg=<alert>`; every CLEAN run
  (rc 0) sends `status=up` (the machinery-alive heartbeat a push monitor
  needs — create one push monitor per URL and the first missed sweep
  pages by itself).
- **ntfy** — alerts are POSTed as the topic message body; no clean-run
  pings (a notification channel, not a status channel).
- **`NAU_SWEEP_ALERT_CMD`** — the #269 seam, unchanged: evaluated
  once per alert with the one-line summary as `"$1"`.

Dependencies: `curl` (only when a kuma/ntfy destination is configured)
and `jq` (only for enabled non-hcloud axes).

Behaviour contract (#269, unchanged for hcloud): list workers labeled
`nau-worker`; destroy only on the three-condition match — tag AND a
parseable TTL marker AND past due (TTL markers are hcloud labels in epoch
seconds — label values reject `:` so ISO-8601 will not fit; writer is the
provisioner, reader is this sweep — INFRA D5); refuse to widen a destroy
on missing data; run in **dry-run for the first two weeks** (log what it
would destroy), then flip the flag to enforce (the two-week clock starts
at install); **alert on any provider API failure** — a skipped sweep is
the failure mode — via the §5.2 fan-out.

The sweep runs with the §1 worker token in the environment
(`HCLOUD_TOKEN` from DECISION SLOT A storage), never `TOFU_INPUTS`
(#271). TTL defaults behind the markers: 4h burst / 24h index runs /
48h-alert + 72h-destroy floor (PROVIDERS §2; owned by the writers).

## 6. Order of operations

1. §1 worker account — gates #194's first real provision (#271); needs no
   ADR-0045 ratification (account setup, no provisioning code).
2. §5 sweep install — lands BEFORE the first real provision, not after
   the first forgotten VM (#269). Dry-run window starts at install.
3. §2 DNS — lands any time; empty names harm nobody (PLAN sequencing).
4. §3 vhosts — after §2 (HTTP-01 needs the names resolving); serves
   empty trees harmlessly (PLAN sequencing).
5. §4 monitors — once the monitoring stack exists (DECISION SLOT B) and
   the lanes serve; the stamp keyword update joins the per-release
   publish loop from day one (CACHE-SPEC), and monitor 5 rides monitor
   4's per-mission set (#292).
6. §7 release-to-flash — the trust-chain procedure, the operator gate
   for "first real flash by anyone" (#292): needs §3 serving the media
   set, the ceremony keychain (§7.1), and a pinned epoch (§7.2).
7. Live verification of the cache lane (`nau ship pull` against the real
   host) waits for the Nau host to exist (CACHE-SPEC "Not proven yet") —
   do not attempt before that.

## 7. Release-to-flash: the trust-chain procedure (#292)

The operator execution pack from ceremony key to a verified, blessed
boot — the gate before anyone's first real flash. Each step cites its
contract; none of it runs automatically.

> **THE OUT-OF-BAND RULE (ADR-0033 D7) — anchors and key material travel
> OUT-OF-BAND, NEVER from the medium being verified.** `image verify`'s
> `--key` MERGES into the ANY-anchor set beside `~/.config/nau/keys/*.pub`
> (src/image/verify.rs, the ADR-0024 §4 anchor policy), so a key fetched from
> the same download lane as the manifest verifies the attacker's own manifest
> — a self-bless. Anchors come from the ceremony keychain (§7.1) or nowhere;
> the download lane serves bytes and never vouches for them.

### 7.1 Key ceremony (operator-executed — pointer)

The ceremony is ADR-0024's, executed by the operator; this runbook does
not re-derive it. The CLI surface is `nau trust
keygen|rotate|promote|revoke|list|verify` (ADR-0024 §4, landed via
#64/#51); operator anchors install under `~/.config/nau/keys/*.pub` —
the keychain `image verify` trusts by default, and the same ceremony key's
sysupdate identity bakes into the base rootfs as
`/usr/lib/systemd/import-pubring.pgp` (the device-side anchor). That
keychain is the ONLY legitimate source of `--key` files anywhere below.

### 7.1-bis The device-side update verification mechanism (#293 item 10)

What actually checks an update on the device — recorded so an operator
can audit the chain without reading systemd sources:

- `systemd-sysupdate` verifies `SHA256SUMS` through a **gpg subprocess**
  (never internal crypto): `Verify=yes` hands `SHA256SUMS` +
  `SHA256SUMS.gpg` to the guest's `gpg` with the vendor keyring
  `/usr/lib/systemd/import-pubring.pgp` as the only trust input — the
  file the build embeds BEFORE the root is hashed (§7.1), so the anchor
  is covered by the dm-verity the device boots. The guest must ship gpg
  (the build refuses to emit transfers for a gpg-less rootfs, #291).
- The signature is OpenPGP over the RAW sums bytes with an
  **EdDSALegacy (algorithm 22)** Ed25519 identity — the ceremony key's
  sysupdate identity from §7.1.
- sysupdate's SHA256SUMS parser checks every payload hash
  unconditionally; `Verify=no` would only lift the signature gate, never
  the hash checks.
- **Minimum systemd: ≥ 251** — the url-file transfer + SHA256SUMS +
  `Verify=` machinery this ride needs (cross-checked against systemd
  main by the trust-slice council: `VENDOR_KEYRING_PATH` wiring, the
  alg-22 path, the sums parser). The build's base-version gate floors
  the boot-assessment machinery at 240 (src/image/boot.rs); a base
  between the two runs updates with verification the base's systemd may
  not fully honor — recorded, not yet enforced.
- The host-side release self-check (src/image/release.rs) executes both
  halves in-process before a media set is reported: the verify-image
  device policy over the published set and the sums-signature round-trip
  against the pubring the build embeds.

### 7.2 Pin SOURCE_DATE_EPOCH — and what it does NOT move (#289)

`nau image build --release` refuses to run with the epoch unset (the CLI
refuses a release without a pinned epoch, ADR-0044 D8). Export it for the
whole release session:

```bash
# source: ADR-0044 D8; 1704067200 is examples/rebuild-compare.sh's default
export SOURCE_DATE_EPOCH=1704067200
```

**Epoch-stable anchor contract (#289): the ceremony key's identity does
NOT move with the release epoch.** The sysupdate OpenPGP identity is
minted at a fixed anchor epoch (`SYSUPDATE_OPENPGP_EPOCH`, src/sign.rs)
regardless of `SOURCE_DATE_EPOCH`, so `SHA256SUMS.gpg` is byte-identical
across release epochs and every fielded device's embedded
`import-pubring.pgp` keeps resolving the same key — a differently-epoch'd
release re-keys nobody (pinned by
`sysupdate_anchor_identity_is_epoch_stable_cross_epoch_roundtrip`). The
epoch still pins every other deterministic byte (squashfs timestamps,
UUIDs); only the anchor identity is exempted.

### 7.3 Build and sign the media set

```bash
# source: ADR-0044 D5 — named artifacts in the ADR-0033 D10 export tree;
# src/image/release.rs module doc
nau image build --release
```

Emits `nau-<mission>-<version>-<arch>.img`, the SIGNED
`nau-<mission>-<version>-<arch>.manifest.json` (Ed25519 under the
operator key id), `SHA256SUMS`, and `SHA256SUMS.gpg` (the sysupdate
detached OpenPGP signature, #267). The command prints the media set plus
its BLOCKING checklist (ADR-0044 D8) — the next step is one of them.

### 7.4 Two-machine rebuild-compare (BLOCKING before distribution)

```bash
# source: ADR-0044 D8; examples/rebuild-compare.sh
examples/rebuild-compare.sh   # byte-identity across two machines
```

A media set that has not passed this is not distributed, whatever the
build said. The ADR-0013 trademark pre-release sweep is the other
blocking checklist item.

### 7.5 Flash: documented `dd`, then verify BEFORE first boot

Write by `/dev/disk/by-id`, never raw `sdX` (ADR-0044 D6):

```bash
# source: ADR-0044 D1 (install = byte copy; the write stays documented dd)
dd if=nau-<mission>-<version>-<arch>.img \
   of=/dev/disk/by-id/<target> bs=4M conv=fsync status=progress
sync
```

Then prove the written device matches the SIGNED manifest — read-only,
unprivileged, works on real block devices (#288: refuses to guess sector
size, HOME, or device sizing). Run it on the freshly written medium,
before it boots anything:

```bash
# source: ADR-0044 D4 + #288. No --key needed with the ceremony keychain
# installed (§7.1); --key, when used, is a ceremony-keychain copy — never
# a file the download lane supplied (out-of-band rule above).
nau image verify --device /dev/disk/by-id/<target> \
    --manifest nau-<mission>-<version>-<arch>.manifest.json
```

Record the reported `verified_key_id` and roothash with the release
record.

### 7.6 First boot and bless

The flashed host's first boot runs the try-boot count (ADR-0024 §3); a
good boot is marked good by `systemd-bless-boot` (tooling staged by the
base per ADR-0027 — slots are never blessed by hand). The flash gate for
"first real flash" is: §7.4 passed byte-identity, §7.5 named the expected
key id, and the first boot blessed itself.

## 8. DECISION SLOTS (complete list)

| Slot | Question | Source of the openness |
|---|---|---|
| A — token storage/secret path | SM item name/path for `HETZNER_WORKER_TOKEN` + how consumers receive it (env injection path for #194 and #269) | #271 mandates a new SM key, leaves the concrete path open |
| B — alert destination (and monitoring placement) | Where the kuma-successor runs and where its alerts land — carries §4 monitor alerts + §5 sweep API-failure alarms | ADR-0046: monitoring died with zet, rebuild open; revisit trigger names the destination decision |

Unpinned-but-noted inline (not formal slots): the exact security-header
set (§3 — PLAN requires headers on, no source enumerates them), the
operator's source-IP list for the firewall (§1.2 — operator-known
values), and the final serving-stack placement for the §3 blocks
(ADR-0046 pod vs plan-era host Caddy — the open lane-service-stack
decision).

## 9. Traceability index

| Runbook item | Source |
|---|---|
| Worker project + Read/Write project-scoped token + new key | #271; INFRA IaC row, D5 |
| Firewall: ssh-only ingress, attach at create, stateful established | #271; hcloud firewall model |
| hel1 placement; CX23/CX33 classes; CAX deferred; IPv4/CPX/KVM notes | #271; PROVIDERS §1, §4; ADR-0046 (neutral) |
| Snapshot-per-(OS, tool-pin) lifecycle; billing caveat | #271; PROVIDERS §3 |
| `*.nau.rclb.dev` A → 62.238.62.155, DNS-only, optional apex | PLAN decision 1, 5; #279; ZET tofu/dns.tf |
| tofu apply sequence; token sourcing (TOFU_INPUTS / RCLB_DEV_CLOUDFLARE_API_KEY) | ZET deploy.sh phase_tofu, provider.tf |
| Three vhost blocks, roots, browse off, Range/sendfile, append-only note, 308 apex | PLAN decisions 1-2, 6, checklist 2 |
| Stamp keyword monitor + per-release keyword update | CACHE-SPEC (spec + two-command loop); PLAN decision 3 |
| Companion monitors (index.json, www 200, download HEAD) | PLAN decision 6; CACHE-SPEC |
| `SHA256SUMS.gpg` existence monitor (one per released mission, pages on a vanished signature) | #292 (monitor-green-while-channel-dead trap); PLAN decision 6 |
| Release-to-flash procedure; out-of-band anchor rule; epoch-stable anchor identity | #292; ADR-0033 D7; ADR-0024 §3-4; ADR-0044 D1, D4-D6, D8; ADR-0027; #267; #288; #289 (src/sign.rs `SYSUPDATE_OPENPGP_EPOCH`) |
| Sweep install, three-condition match, epoch-second labels, dry-run window, alert-on-failure | #269; INFRA D5; PROVIDERS §2; ZET update-timer.yml (pattern) |
| Sequencing and gates | PLAN sequencing; #271/#269 gates; #292 flash gate; CACHE-SPEC "Not proven yet" |
