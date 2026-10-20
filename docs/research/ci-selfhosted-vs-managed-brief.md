# Self-Managed Cloud Build Workers vs. Managed CI — Cost & Fit Brief

> **Purpose:** Decide whether the Nau daily build loop should run on self-managed
> cloud workers (ADR-0040's SSH-executor farm) or a managed CI service
> (GitHub Actions, CircleCI, Travis, GitLab CI, Buildkite) — with Sept-2026
> pricing from primary sources and the arithmetic for this repo's workload.
> **Scope note:** ADR-0040 is Accepted and mid-implementation (T4/T5 next);
> this brief prices the alternative it rejected, it does not relitigate it.
> **Companion:** `docs/adr/0040-distributed-build-workers.md`,
> `docs/nau-ops-runbook.md` §1.3 (sanctioned machine classes).
> **Date:** September 2026. All prices "as of Sept 2026" from the cited pages.
> **Method:** two parallel web-research lanes (firecrawl search/scrape);
> headline GitHub numbers independently re-verified against docs.github.com
> and the pricing-announcement thread.

---

## 1. The workload being priced

Repo facts (ADR-0040 Context; ops runbook §1.3):

- ~190 `pkgs/` recipes; the daily loop is "build the whole index."
- Linux x86_64-only pool (operator decision 2026-09-27, PROVIDERS §1).
- Each package builds in its own offline bwrap sandbox, ~10–30 min;
  toolchain bootstrap stages run for hours.
- Compute-minutes/month: 190 × 30 × (10–30 min) ≈ **57k–170k**; the
  planning band used below is **100k–170k compute-min/mo**.
- Constraint set that narrows provider choice (runbook §1.3, amended
  2026-09-29): Hetzner policy — sustained high CPU belongs on
  **dedicated vCPU** (shared CX/CPX lines not sanctioned for build
  workers); post-2026-06-15 repricing; workers live **only while a lane
  uses them** (provision → build → destroy in one window); IPv6-only as
  the recorded cost cut.

## 2. Managed CI: pricing and snap feasibility

### GitHub Actions (hosted)

| Runner | $/min | Note |
|---|---|---|
| Standard Linux 2-core | **$0.006** | cut from $0.008, effective 2026-01-01 |
| Standard Windows / macOS | $0.010 / $0.062 | |
| Larger Linux 4–64 core | $0.012–$0.162 | always billed, even public repos |
| Self-hosted runner fee | ~~$0.002/min~~ | **announced, then postponed** — see below |

Verified against [docs.github.com billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
and the [pricing announcement thread](https://github.com/orgs/community/discussions/182186):

- Standard hosted runners are **free in public repositories**; private
  repos get 2,000 min/mo (Free plan) then bill at the table above.
- The **$0.002/min self-hosted-runner fee was NOT enacted**: GitHub
  announced it, the community reaction was heavy, and the same thread
  records the walk-back — "We're **postponing** the announced billing
  change for self-hosted GitHub Actions to take time to re-evaluate."
  The billing page still says self-hosted usage is free. Treat it as
  **policy risk**, not current cost.
- Free-plan concurrency: 20 standard jobs; per-job wall-clock cap 6 h.
- **Snap feasibility: YES.** `ubuntu-*` runners are full VMs with
  systemd + sudo; Canonical's
  [`canonical/action-build`](https://github.com/canonical/action-build)
  installs snapd + LXD in the runner VM and is the Snapcraft-recommended
  path ([snapcraft forum](https://forum.snapcraft.io/t/recommended-github-actions-to-build-and-publish-snaps/36362)).
  snapd does **not** work in container executors (Codespaces/Docker),
  per [community discussion 54655](https://github.com/orgs/community/discussions/54655).

**Cost @ 100k–170k min/mo:** public repo **$0**; private-repo pricing
$0.006 × 100k–170k = **$600–$1,020/mo**.

### CircleCI

Credit = $0.0006 ([credits doc](https://circleci.com/docs/guides/plans-pricing/credits/));
Linux VM Medium = 10 credits/min ([price list](https://circleci.com/pricing/price-list/))
⇒ effective **$0.006/min**, same as GitHub standard.
Performance plan $15/mo incl. 30k credits + 5 users. No public-repo
free lunch. **Snap feasibility: NO on the default Docker executor**
(no systemd); `machine` executor is a full VM and likely workable with
nested snapd but is not officially documented by CircleCI. **Cost
@ 100k–170k: $600–$1,020/mo.**

### GitLab CI (gitlab.com SaaS runners)

Compute-minute model; Free tier 400 min/mo; Premium $29/user/mo with
10,000 min; extra minutes **$10/1,000** ([pricing](https://about.gitlab.com/pricing/),
[minutes doc](https://docs.gitlab.com/ci/pipelines/compute_minutes/)).
**Snap feasibility: NO** — SaaS shared runners are unprivileged
containers (no systemd/snapd); a self-hosted shell-executor VM is
required, which forfeits "managed." **Cost @ 100k–170k: ~$930–$1,730/mo**
— the worst per-minute of the hosted options.

### Travis CI

Usage plan $15/mo for 35k Linux credits; "unlimited concurrency" plans
from $78/mo ([pricing](https://www.travis-ci.com/pricing),
[billing docs](https://docs.travis-ci.com/user/billing-overview/)).
Per-credit price beyond 35k is not clearly published — 100k+/mo needs a
custom plan. The OSS exodus (2019–2021) never reversed; the platform is
a legacy-only choice. **Verdict: avoid.**

### Buildkite — the middle ground

**Pro $30/active-user/mo** ([pricing](https://buildkite.com/pricing));
agents run on **your** infra at **your** cost — Buildkite sells only the
control plane. 10 self-hosted agents included; +$3.50/agent/mo after.
Optional hosted agents: Linux Small 2 vCPU $0.008/min.
**Snap feasibility: YES, best-in-class** — your agents run on real VMs
with real systemd + LXD. **Cost @ 100k–170k: $30/mo + raw compute**
(~€100–300/mo on Hetzner, §3) — and GitHub's (postponed) self-hosted
fee does not apply because the fleet doesn't ride Actions.

## 3. Self-managed workers on cloud: pricing and ops reality

### Raw compute (build-worker-shaped, as of Sept 2026)

| Provider / SKU | Specs | $/mo (24/7) | Notes |
|---|---|---|---|
| **Hetzner CCX23** (dedicated vCPU) | 4/16/160 GB | **€85.99** | was €31.49 — CCX jumped ~2.7× in the [2026-06-15 repricing](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/); the repo's `build-default` class |
| **Hetzner AX42** dedicated root | ~16C/32T Ryzen, 64+ GB | **€97.30 + setup** | whole bare-metal machine; AX102 €257.30 |
| Hetzner CAX41 (ARM, shared) | 16 vCPU/32 GB | €40.99 | cheapest 16-vCPU anywhere, but **shared** line — not sanctioned for this pool (and pool is x86_64-only) |
| AWS m7i.4xlarge | 16/64 | ~$589 | spot $0.374 (~54% off); 3-yr RI −45% ([vantage.sh](https://instances.vantage.sh/aws/ec2/m7i.4xlarge)) |
| GCP n2-standard-16 | 16/64 | ~$567 | CUDs cut further ([devzero.io](https://www.devzero.io/instances/gcp/n2-standard-16)) |
| Azure D16s_v5 | 16/64 | ~$560 | ⚠ unconfirmed — pricing page JS-gated |

**Sizing check:** one CCX23 at 4 dedicated vCPU running 24/7 delivers
4 × 60 × 720 ≈ **173k compute-min/mo** — the entire planning band on one
sanctioned-class machine. Ephemeral `build-light` (ccx13) workers cover
burst; the provision→destroy directive keeps idle cost ≈ 0.

**Powered-off ≠ cheaper.** Hetzner bills a Cloud server "for as long as
it exists, regardless of whether it is turned on or not" — full price,
because resources stay allocated ([billing FAQ](https://docs.hetzner.com/cloud/billing/faq/#do-you-bill-servers-that-are-off),
[billing system](https://docs.hetzner.com/general/billing-and-account-management/billing-at-hetzner/billing-system-hetzner/)).
Only deletion stops billing; Hetzner's own guidance for long idle is
snapshot → delete → recreate later (snapshot storage beats an idle
machine). This is precisely why the runbook's provision→build→destroy
window (§1.3) is the only correct idle policy — "shut down and keep it
around" saves nothing.

### What the field learned (hard numbers)

- **[Altinity/ClickHouse](https://altinity.com/blog/ci-cd-bills-using-hetzner-cloud-github-runners-for-clickhouse-builds):**
  a ~130 compute-hour ClickHouse CI run parallelized to 5h39m wall clock
  on Hetzner for **€10–11/run**; their AWS attempt with the Terraform
  runner module produced runner theft, Lambda limits, and a **$2k
  surprise bill on a 2-day run**; they rejected ARC as "a full
  Kubernetes operator." [Part 2](https://altinity.com/blog/slash-ci-cd-bills-part-2-using-hetzner-cloud-github-runners-for-your-repository)
  covers the ongoing hygiene (runner recycling, hourly-billing rounding).
- **[TestFlows github-hetzner-runners](https://github.com/testflows/testflows-github-hetzner-runners):**
  plain-VM ephemeral-per-job runner manager (no k8s), proven at
  ClickHouse scale; claims up to 33× cheaper than hosted runners. This
  is the same shape as ADR-0040's SSH-executor coordinator.
- **[The Guardian](https://theguardian.engineering/blog/faster-cheaper-messier-lessons-from-switch-to-self-hosted-github-actions):**
  "Faster, cheaper, **messier**" — a professional team confirming the
  transferred burden (queue management, runner hygiene) is real.
- **[NixOS](https://discourse.nixos.org/t/infrastructure-announcement-the-future-of-ofborg-your-help-needed/56025),
  [builder economics](https://blog.erethon.com/blog/2025/07/31/how-nixos-is-built/):**
  hydra.nixos.org builder capacity estimated **≈ €1,500/mo**; the
  volunteer-run farm struggled to fund hands — cautionary tale for solo
  fleet maintenance.
- **Orchestration landscape Sept 2026:** GitLab's `docker+machine`
  autoscaler is **deprecated (17.5), removal slated for 20.0 (May 2027)**
  ([docs](https://docs.gitlab.com/runner/configuration/autoscale/));
  GitHub's ARC demands Kubernetes and shows real-maintainer pain
  ([scaling thread](https://github.com/actions/actions-runner-controller/discussions/1544),
  [hardening guide](https://some-natalie.dev/blog/securing-ghactions-with-arc/)).
  **There is no cheap off-the-shelf autoscaler left for non-k8s fleets;
  building the simple one is the mainstream move.**

### Security rule (non-negotiable)

GitHub's own warning: *"We recommend that you only use self-hosted
runners with private repositories… forks of your public repository can
potentially run dangerous code on your self-hosted runner machine"*
([docs](https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners);
[hardening doc](https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-self-hosted-runners)).
Any self-managed worker touching untrusted PRs must be **ephemeral,
one job per machine/lifetime, no secrets mounted** — AWS documents the
same pattern at scale
([blog](https://aws.amazon.com/blogs/devops/best-practices-working-with-self-hosted-github-action-runners-at-scale-on-aws/)).
Nau's pod-per-build + provision→destroy model already satisfies this.

## 4. Head-to-head @ 100k–170k compute-min/mo

| Path | Monthly cost | Snap-feasible? |
|---|---|---|
| GHA standard runners, **public repo** | **$0** | ✅ (canonical/action-build) |
| GHA standard, private pricing | $600–$1,020 | ✅ |
| CircleCI Linux VM Medium | $600–$1,020 | ❌ Docker / machine unverified |
| GitLab Premium + extra minutes | $930–$1,730 | ❌ SaaS runners |
| Travis | unclear, custom plan | legacy, avoid |
| Buildkite Pro + own Hetzner VMs | **$30 + ~€100–300 compute** | ✅ |
| **Self-managed Hetzner CCX23 fleet (ADR-0040 path)** | **~€86–260** | ✅ native — this *is* the farm |
| Self-managed on AWS/GCP/Azure | $430–900 (spot/RI) | via self-hosted runners; billing-surprise risk |

Wall-clock feasibility on the GHA free tier: 5.7k compute-min/day ÷
20 concurrent ≈ 4.7 h/day — fits numerically, but the **6 h per-job cap**
is a live risk for the multi-hour toolchain bootstrap stages, and 190
jobs/day churns workflows, caches, and artifact storage that the free
tier does not price.

## 5. Findings

1. **Two different questions, two answers.** For per-PR CI on a public
   repo, hosted GitHub Actions is **$0** with a documented snap path
   (canonical/action-build) — nothing self-managed beats free. For the
   **daily ~190-package loop** — the demand ADR-0040 actually serves —
   hosted CI is $600–$1,730/mo at private-repo rates, has no snapd path
   at all on CircleCI/GitLab SaaS, and caps jobs at 6 h wall clock.
2. **Self-managed wins the loop by 4–10×.** One sanctioned-class Hetzner
   CCX23 (~€86/mo) running 24/7 covers the whole 100k–170k min band;
   the ephemeral provision→destroy directive pushes real cost lower
   still. Hyperscaler self-hosting lands at $430–900/mo with spot
   interruption and billing-surprise risk (Altinity's $2k/2-day story).
3. **The postponement math can flip.** GitHub's announced $0.002/min
   self-hosted fee — currently postponed (discussion 182186) — would add
   $200–$340/mo to an *Actions*-based self-hosted fleet at this volume.
   It does not touch a Buildkite or shuttle-native fleet. If it ever
   lands, it widens the gap in favor of owning the control plane.
4. **The orchestration burden is real but already budgeted here.** The
   industry's cheap autoscalers are deprecating (GitLab) or k8s-gated
   (ARC); the surviving pattern is exactly ADR-0040's: a simple
   coordinator driving ephemeral SSH workers. For shuttle the
   coordinator is **product code**, not side-infrastructure — the
   marginal ops cost is the runbook hygiene (golden snapshot, TTL
   sweep, patch cadence) already documented in the ops runbook.
5. **Managed middle ground:** Buildkite Pro ($30/mo) buys a maintained
   control plane over the same Hetzner machines if operating the
   coordinator ever stops being worth it. Exit cost is low: workers stay
   plain VMs with a build binary + working sandbox.

## 6. Bottom line

Cheaper: **self-managed on Hetzner dedicated vCPU** for the build farm
(~€86–260/mo vs. $600–$1,730/mo managed), with the loop covered by a
single sanctioned-class machine plus ephemeral burst. Better: **also
self-managed for the farm** — snapd's systemd requirement rules out half
the managed field outright, the SSH-executor design matches the pattern
the field converged on, and it is product code. For the repo's own
per-PR CI, hosted GitHub Actions on a public repo at $0 is the rational
default, isolated from the farm entirely. Watch two prices: GitHub's
postponed self-hosted fee (policy risk) and Hetzner's repricing cadence
(CCX rose ~2.7× in June 2026; the runbook's class table already carries
the amended SKUs).

## Sources

Primary (all retrieved Sept 2026 via firecrawl):

- GitHub Actions billing & free use —
  https://docs.github.com/en/billing/concepts/product-billing/github-actions
- GitHub Actions pricing announcement + postponement of self-hosted fee —
  https://github.com/orgs/community/discussions/182186
- GitHub Actions limits — https://docs.github.com/en/actions/reference/limits
- canonical/action-build — https://github.com/canonical/action-build
- Snapcraft-recommended GitHub Actions —
  https://forum.snapcraft.io/t/recommended-github-actions-to-build-and-publish-snaps/36362
- snapd-not-in-containers — https://github.com/orgs/community/discussions/54655
- CircleCI credits — https://circleci.com/docs/guides/plans-pricing/credits/
- CircleCI price list — https://circleci.com/pricing/price-list/
- Travis pricing — https://www.travis-ci.com/pricing ; billing —
  https://docs.travis-ci.com/user/billing-overview/
- Buildkite pricing — https://buildkite.com/pricing
- GitLab compute minutes — https://docs.gitlab.com/ci/pipelines/compute_minutes/
- GitLab pricing — https://about.gitlab.com/pricing/
- Hetzner 2026-06-15 price adjustment —
  https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/
- Altinity CI-on-Hetzner parts 1 & 2 —
  https://altinity.com/blog/ci-cd-bills-using-hetzner-cloud-github-runners-for-clickhouse-builds
  ; https://altinity.com/blog/slash-ci-cd-bills-part-2-using-hetzner-cloud-github-runners-for-your-repository
- Testflows github-hetzner-runners —
  https://github.com/testflows/testflows-github-hetzner-runners
- GitLab autoscaling deprecation —
  https://docs.gitlab.com/runner/configuration/autoscale/
- GitHub self-hosted runner security warning —
  https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners
- GitHub Actions security hardening (self-hosted section) —
  https://docs.github.com/actions/security-guides/security-hardening-for-github-actions
- AWS self-hosted runners at scale —
  https://aws.amazon.com/blogs/devops/best-practices-working-with-self-hosted-github-action-runners-at-scale-on-aws/
- The Guardian self-hosting lessons —
  https://theguardian.engineering/blog/faster-cheaper-messier-lessons-from-switch-to-self-hosted-github-actions
- NixOS OfBorg future / builder economics —
  https://discourse.nixos.org/t/infrastructure-announcement-the-future-of-ofborg-your-help-needed/56025
  ; https://blog.erethon.com/blog/2025/07/31/how-nixos-is-built/
- ARC scaling discussion —
  https://github.com/actions/actions-runner-controller/discussions/1544
- m7i.4xlarge pricing — https://instances.vantage.sh/aws/ec2/m7i.4xlarge
- GCP n2-standard-16 pricing — https://www.devzero.io/instances/gcp/n2-standard-16

**Unconfirmed / flagged** (do not cite without re-checking): Azure
D16s_v5 exact rate (JS-gated pricing page); Netcup/Contabo current
prices (rate-limited); GCP/Azure committed-use percentages; Travis
per-credit price beyond 35k; CircleCI free-tier credit count (conflicting
sources); any first-party "we quit self-hosting" write-up (none found;
closest signal is the market for managed self-hosted runners).
