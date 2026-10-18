# Strands Box + Dogwood integration spec

Status: Proposed, 2026-10-10. Deferred work — architecture and plan captured
now, implementation happens later. Tickets are filed and indexed at the bottom;
each is phase-gated. Nothing here blocks or touches current farm or pod work.

## Summary

nau adopts [Strands Box](https://github.com/strands-agents/box) as the
containment-and-policy layer for two future jobs: (1) governing an agentic
ops lane on the farm (an agent that reads converge/drain logs, classifies
failures, drafts chart and policy changes), and (2) wrapping real
applications on pods under deterministic, auditable policy. The Dogwood
Local Engine — the policy core, portable Rust, no platform restriction — is
adopted first; the Box sandbox follows once upstream lands Linux x86_64.

The load-bearing rule: **the agent authors, the pipeline enforces.** Policies
are versioned, digested artifacts released through the same farm pipeline as
packages. Live policy edits are forbidden permanently.

## Background (verified 2026-10-09/10)

- Strands Box is AWS's open source sandbox engine for AI agents (developer
  preview, Apache 2.0). `box.toml` configures OS-enforced access grants;
  `policy.dw` holds Dogwood rules; operations checked by the engine are
  denied by default, and a matching `forbid` overrides a `permit`. Strands
  Shell, Monty (Python), the egress gateway, and the MCP broker route every
  operation through the embedded Dogwood Local Engine and share one event
  history, so an earlier action can gate a later one across layers.
  (Source: strands-agents/box README and the Strands Box blog, 2026-10.)
- The egress gateway checks connections and HTTP requests including method
  and path, and performs credential injection (API credentials or AWS
  SigV4) so the wrapped program never holds the underlying secrets.
- Box writes policy decision records as OTLP JSON (default
  `<box_dir>/private/telemetry/records.jsonl`). These records are the
  session corpus this spec replays.
- **Platform blocker:** Box currently supports local execution on macOS
  with Apple silicon only (README, 2026-10-09 fetch).
- Upstream Linux state: `main` carries a Linux containment backend
  (`crates/containment/src/backend/linux/namespace/` — authority, netns,
  probe, reaper, syscall, view) behind a facade that refuses every
  architecture except aarch64. Open PR #40 ("feat(containment): run Linux
  containment on x86_64", opened 2026-10-09, 14 files, +588/−65) adds an
  x86_64-only seccomp permit table under a "twin rule" (a legacy syscall
  spelling is permitted only when its modern twin already is) plus one
  scoped exception for `arch_prctl`. The PR declares a foundational-premise
  change awaiting maintainer review; its author marks the line-by-line
  review checkbox unchecked. Out of its scope: x86_64 release tarballs and
  all other architectures.
- The Dogwood Local Engine
  ([dogwood-policy/dogwood-local-engine](https://github.com/dogwood-policy/dogwood-local-engine))
  is a Rust library on crates.io (`dogwood-local-engine` 1.0,
  `dogwood-language` 1.0, edition 2024, Apache 2.0). It processes events
  incrementally, keeps durable ordered state, and survives crash/restart.
  A demo `dogwood-server` exposes two Unix sockets: control plane (edit
  the policy set) and data plane (events + verdict requests).

## Scope ruling

Box does **not** replace the nau build sandbox. The nau sandbox shapes a
static environment for reproducible builds (bind roots, `/etc/alternatives`
binds, merged build prefix, digest sidecars, claims walks). Box governs
what a dynamic program may do next. Different problem, different layer;
the build sandbox stays as it is.

Box earns its place only where autonomy or untrusted dynamism exists:
the future agentic farm-ops lane, and wrapped third-party applications
on pods. Where nau work is a "clear, unambiguous process" (charts, queue
claims), it stays a workflow — Box adds only TCB there.

## Architecture

Three planes, one direction of trust:

```
AUTHORING (shuttle repo)                ENFORCEMENT (pod, future)
  pkgs/<l>/<name>.lua                     box runtime (upstream Linux)
  policies/<app>/<name>.dw   --farm-->    + wrapped app
  driver agent opens PRs                  box.toml: OS-enforced grants
        |                                 policy.dw loaded from the
        v                                 digest-pinned payload ONLY
RELEASING (farm)                         egress gateway + interpreters
  build-request queue                      -> Dogwood Local Engine
  REPLAY GATE: candidate policy               (verdicts, event history)
    vs recorded corpora -> receipt       decision records (OTLP JSONL)
  released policy lands in the              | pulled back host-side
  nau-tree with sha3-384 sidecars           v
                                       corpora for the next gate round
```

Artifacts:

| Artifact | Home | Versioning | Integrity |
|---|---|---|---|
| Package charts | `pkgs/` | strict X.Y.Z (existing) | tree sidecars (existing) |
| Policies | `policies/<app>/<name>.dw` | strict X.Y.Z, independent of app versions | same sidecar discipline |
| Session corpora | farm-side, pulled from pods | corpus digest | receipt-carried |
| Receipts | `queue/done/*.receipt.json` | n/a | policy digest + corpus digest + verdict |

Trust invariants (numbered; referenced by tickets):

1. **Pinned policy only.** The pod loader verifies the policy payload
   digest before installing the policy set. No other writer exists.
2. **Control plane locked.** Only the loader reaches the engine's control
   plane. Upstream is explicit: a process that can edit the policy set can
   remove `forbid` rules (dogwood-local-engine README, "Securing control
   plane actions").
3. **No live edit.** Policy changes ride review + replay gate + release.
   Adaptive behavior lives in the draft-test-release cycle.
4. **Governor is versioned.** The driver agent ships as a nau package and
   has no pod write path; it opens PRs, nothing else.
5. **Clock discipline.** Temporal policies trust timestamps; the pod clock
   is secured and monitored (upstream requires it for verdict accuracy).

## Embedding duties inherited from upstream

The Local Engine README assigns the wrapper six duties. nau owns each one:

| Upstream duty | nau obligation |
|---|---|
| Capture all relevant events | per-app capture contract; undocumented gaps are spec bugs |
| Event provenance and accuracy | receipts + digests; loader authenticates event source |
| Enforce verdicts | the box runtime enforces; nau never treats a verdict as advisory |
| Restrict engine state access | state files under operator-controlled paths, ACL-tested |
| Secure control plane | invariant 2; socket restricted to the loader |
| Separate audit log with retention | decision records pulled before any teardown; engine's internal log prunes itself |

## Phases and gates

| Phase | Ticket | Depends on | Gate |
|---|---|---|---|
| 0. `nau-policy-check` spike (engine on Linux) | #369 | nothing (engine is portable) | `cargo test` green; fixture replay is verdict-stable |
| 1. Policies as first-class payloads | #371 | #369 | digest-pinned round trip; tampered payload refused; loader-only control plane tested |
| 2. Farm replay gate | #370 | #369, #371 | adversarial wrong-policy refused; receipt schema live |
| 3. Driver agent loop | #373 | #370; capture needs Box (see #372/#374) or rented Apple silicon | loop runs end to end twice; no agent pod-write path |
| 4. Upstream Linux verification + landing | #372 | PR #40 review upstream | Box suite green on real Ubuntu x86_64; epics #41 #42 #44 #47 #43 #52 tracked |
| 5. Wrapped apps on pods | #374 | #372 + upstream #41 #42 #44 #47 | curl wrapped end to end; GUI app second; browser only after #42 decision |

Phases 0–2 need no Box and no Apple hardware; they are valid regardless of
upstream's Linux timeline. Phase 3 capture can start on synthetic corpora
and move to real Box sessions when either Phase 4 lands or a short
Apple-silicon rental is justified.

## Upstream dependency map (status 2026-10-10)

| Upstream ref | What | Status |
|---|---|---|
| strands-agents/box PR #40 (closes #21) | x86_64 containment: gate + twin-rule permit table | open, premise-class, awaiting maintainer review |
| #10 | Linux at parity with macOS | planned epic |
| #41 | dynamic loader library dirs — not a file read; Node/Python die today | planned; blocks every dynamically linked wrapped app |
| #42 | JIT runtimes under write-xor-execute — V8 dies by signal in the Linux box | spike; the browser blocker; premise decision |
| #44 | filesystem semantics parity (list/deny refusals, writable-bind-reads, rw /proc) | epic |
| #47, #52 | Linux egress namespace decision; IPv6 in the box | decision + spike |
| #43 | tool and MCP leaf exec on Linux | epic |
| #46 | kernel/distro/environment matrix | nau contributes real-Ubuntu data via #372 |
| #18, #49 | aarch64 tarballs (x86_64 tarballs out of scope of PR #40) | open; farm builds from source until then |

## Risks

- **Preview churn.** Box is a developer preview; interfaces are frozen but
  the project is young (≈35 PRs). Pin commits; expect breakage; treat the
  upstream test suite as the compatibility oracle.
- **Premise-class upstream decisions.** PR #40 and spike #42 both change
  why the box is safe. They can land differently or not at all. Phases 0–2
  are deliberately insulated from both.
- **TCB growth.** Each Box adoption widens the trusted base on that host.
  Phases 0–2 add a Rust library to farm-side validation only; pod TCB
  arrives with Phase 5 and should be priced then.
- **Audit retention cost.** Decision records must outlive workers (TTL ~6h)
  and pods; retention sizing is part of #370/#374.

## Open questions (for the AWS Strands team)

1. Linux x86_64/aarch64 timeline for Box's containment layer; is the port
   path seccomp notify, landlock, or both?
2. Is wrapping a non-agent app a supported use, or does Box assume the
   workload speaks Strands Shell, Monty, or MCP? How does an arbitrary
   binary route traffic through the gateway (proxy env, per-app config)?
3. The gateway inspects HTTP method and path, so it terminates TLS. For
   arbitrary apps, is that a MITM with its own CA, and what happens with
   pinning-heavy clients (browsers, OS updaters)?
4. Is there a first-class export of a session's event stream for offline
   replay against the Local Engine, or is OTLP `records.jsonl` the corpus?
5. Does Box expose runtime control-plane policy edits, and what does AWS
   recommend for pinning the policy set to a loader-verified digest?
6. For single-tenant devices, is Box alone an adequate boundary for
   non-agent apps, or does the MicroVM-pairing advice apply there too?

## Ticket index

| # | Title | Phase |
|---|---|---|
| #369 | box: spike nau-policy-check crate embedding the Dogwood Local Engine on Linux | 0 |
| #371 | policy: policies as first-class payloads | 1 |
| #370 | farm: policy replay gate | 2 |
| #373 | policy: driver agent loop | 3 |
| #372 | box: upstream Linux verification (PR #40 on real Ubuntu) | 4 |
| #374 | box: wrapped-app deployment on pods | 5 |

## References

- Strands Box: the big picture — https://strandsagents.com/blog/strands-box-the-big-picture/
- Dogwood Local Engine announcement — https://aws.amazon.com/blogs/opensource/introducing-the-dogwood-local-engine-temporal-governance-for-agent-actions/
- Box repo — https://github.com/strands-agents/box (policy-authoring skill:
  `.agents/skills/authoring-box-policy/SKILL.md`)
- Dogwood Local Engine — https://github.com/dogwood-policy/dogwood-local-engine
- Upstream Linux work — PR #40, issues #10 #18 #21 #41–#52
- Related nau context: `docs/adr/0055-pool-front-and-funnel-lifecycle.md`
  (front/funnel lifecycle the policy payloads ride), nau-sandbox contract
  map (why the build sandbox is out of scope here).
