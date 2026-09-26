# Distributed build workers: an SSH-driven build pool with no daemons

## Status

Accepted (2026-09-26). Drafted 2026-09-24 by a planning session. Four-seat
council review on ratification day: unanimous accept-with-changes; every
required change is incorporated, the two decisive ones being the job
identity fix (Decision 6: the `v4:` closure key does not cover
environment, apps, hooks, toolchain, or compression, so keying remote
jobs on it would turn local staleness into cross-machine silent
substitution) and the v1 scope cut (Decision 8: cloud provisioning,
`speed`, and capability tokens moved out of v1; see Revisit triggers).
**Supersedes ADR-0022 Decision 4** ("No remote build farm, no remote
cache, no substituters … Parallelism is local only") for the *build
compute* axis. The remote *cache/substituter* half of that non-adoption
stands: result sharing stays on ADR-0033's lanes, and this ADR adds no
cache service. Extends the ADR-0022 addendum (ready-set scheduler, issue
#55). Compatible with ADR-0011 Decision 5 (daemon law), ADR-0039 (the
build sandbox stays offline), and ADR-0033 (peer sharing — untouched; a
Worker is not a Peer). Naming respects `CONTEXT.md`: `farm` stays the
pod bin farm (`src/farm.rs`), `builder` stays the build-script plugin
kind (ADR-0014); the machine noun introduced here is **Worker**.

## Context

ADR-0022 Decision 4 recorded "no remote build farm" when three facts held:
the trust machinery for verified transfer did not exist, the per-package
build unit had never proven portable, and the workload fit one machine.
All three changed:

1. **The compute seam exists and is small.** Inter-package parallelism
   landed behind `build_sched.rs::run_ready_set` — a ready-set scheduler
   over the `deps.rs` graph with stop-the-world failure semantics. Its
   "worker" is already an abstraction boundary (a unit that receives a
   ready package and reports success or failure); nothing pins it to a
   local thread except the current call site.
2. **The build unit is self-contained and content-addressed.**
   `snap.rs::build_snap` takes explicit paths, builds in its own tempdir
   stage and its own offline bwrap sandbox, and every build result is
   keyed by the portable closure hash `v4:<closure_sha256>`
   (`src/cache.rs`). A build therefore has a machine-independent
   identity — with a known coverage gap this ADR repairs for the remote
   path (Decision 6): the `v4:` key digests source, sources, parts,
   target, requires, and build_deps, but not environment, layout, hooks,
   apps, toolchain, icon, or compression, so two byte-different builds
   can share a `v4:` key today. Locally that is a staleness bug; a farm
   would make it a silent-substitution bug. The job manifest therefore
   carries its own identity, and remote results never alias into the
   `v4:` namespace.
3. **The trust and transfer lane landed.** ADR-0033 shipped signed
    PackageManifests, hash-verified blob transfer, and the curl-behind-
    `CommandRunner` network convention. What it distributes is content;
    what is still missing is compute — "the artifact half is done, the
    compute half is absent."

The workload outgrew the single-machine assumption in practice: ~190
`pkgs/` recipes, toolchain bootstrap stages that run for hours, and a
repo whose daily loop is "build the whole index." LAN machines idle; the
demand is burst capacity across machines the operator already controls,
not a hosted service and not provisioned fleets (provisioning is
explicitly out of v1 scope; see Alternatives and Revisit triggers).

Constraints that carry over unchanged:

- **Daemon law** (ADR-0011 D5): no privileged long-lived daemon ships.
- **Offline sandbox** (ADR-0039): `--unshare-net` is unconditional; every
  byte a build consumes arrives via a declared, content-pinned fetch
  path. On a Worker this guarantee is non-degradable (Decision 2).
- **Minimal new crates** (ADR-0033 D4 vetting ritual): no tokio, no hyper,
  no gRPC, no ssh *library* — subprocess clients only.
- **Config stays in `shuttle.lua`** (ADR-0033 owner requirement 2).
- **Stop-the-world failure semantics** (ADR-0022 addendum): a failed
  package fails the run nonzero, names the failed set, and dependents
  never start.
- **Explicit trust** (ADR-0024 posture): trust is never acquired silently.
  For SSH this is enforced, not assumed (Decision 5).

Prior-art survey (2026-09, cited in Evidence): Nix's `builders` grammar
gives the right *config shape* but couples to the store-path model; the
Bazel Remote Execution API is the wrong granularity for monolithic snap
builds and drags server infrastructure (and, for NativeLink, an
FSL-1.1 license GPL cannot take); distcc/icecc scatter single
translation units, which snap builds do not have; cargo-remote and
nixbuild.net both demonstrate that SSH alone is a sufficient and
preferred transport for CLI-driven build offload.

## Decision

1. **Supersession, stated precisely.** ADR-0022 Decision 4 is superseded
   for build *compute* only: shuttle gains remote *execution* of package
   builds. It is not superseded for caching or distribution: no remote
   cache, no substituters, no new content lane (ADR-0033's four lanes
   remain the way packages move). The trust domain widens deliberately:
   **Workers are operator-controlled machines**, and joining the pool is
   an explicit operator act — the operator's SSH access *is* the trust
   boundary, and it is pinned, not TOFU (Decision 5). This mirrors
   ADR-0024's explicit-trust posture; it acquires no trust from the
   network.

2. **A Worker is a machine, not a process.** shuttle adds no worker-side
   daemon, no listening socket, and no `shuttle workers` surface in v1.
   The Worker is any Linux machine that (a) is reachable over SSH, (b)
   has a compatible `shuttle` binary, (c) has a *functioning* sandbox —
   bwrap present and unprivileged user namespaces working, not merely
   `which bwrap` — and (d) exposes two hidden exec verbs, mirroring the
   `__eval-worker`/`__check-worker` precedent (the `__worker-*` family
   is the machine-side sibling; see Decision 9):
   - `shuttle __worker-cap` — prints a capability document (protocol
     version, arch, nproc, RAM, free disk, tool availability **with
     versions**, sandbox capability as a probed boolean, mksquashfs
     version) as JSON, then exits.
   - `shuttle __worker-job <job-file>` — executes exactly one job
     manifest: materializes the recipe slice and pinned inputs, verifies
     every sha256, sets `SOURCE_DATE_EPOCH` into its own process env
     (a Worker process inherits nothing from the coordinator), runs the
     ordinary offline-sandbox build path, and prints a result document
     (artifact paths + hashes + buffered stderr + protocol version) as
     JSON. The verb **hard-refuses** when the sandbox probe fails: the
     host's bwrap-absent degrade path (`run_direct`) is a local
     convenience and is never reachable on a Worker — a degraded fleet
     build would be an unsandboxed, host-network build with no audit
     trail, which ADR-0039 calls a grant, not a degradation.
   Both verbs are hidden from `--help` like their isolate.rs siblings.
   All state lives on the coordinator; Workers are stateless beyond
   their local cache, which they consult before building.

3. **Config: a top-level `workers = { … }` array in `shuttle.lua`.**
   Captured as a global input the way `inputs` is
   (`WorkerOk.global_inputs` precedent) — it is not per-output, so it
   is neither a stamped DSL function nor a per-snap table — and
   deep-validated Rust-side at the boundary (ADR-0014):

   ```lua
   workers = {
       { address = "ssh://rodrigo@nuci.local", jobs = 4 },
       { address = "ssh://build@edge01",       jobs = 8 },
       { address = "ssh://arm@builder-aws",    jobs = 16,
         arch = "aarch64-linux-gnu" },
   }
   ```

   Fields, v1 exactly: `address` (required, `ssh://[user@]host[:port]`;
   validated grammar — non-empty host, integer port 1-65535, host must
   not begin with `-` so it can never inject ssh options into the
   `CommandRunner`-wrapped argv, IPv6 bracket form accepted, duplicate
   addresses refused); `jobs` (max concurrent jobs on that machine,
   integer ≥ 1, default 2); `arch` (probed via `__worker-cap` at
   preflight; a declared-but-mismatched arch is a named preflight
   refusal, not a warning); `local_jobs` (the coordinator's own slot
   count, default 3 — today's `MAX_PARALLEL_BUILD_WORKERS`, now
   config-driven).
   Absent `workers = { … }` means **zero behavior change**: no sockets,
   no SSH, no new code paths — the same posture as ADR-0033's `node {}`.
   Speed-weighted placement and capability-token routing are
   deliberately absent (Revisit triggers); v1 dispatch needs no
   heuristic and no token vocabulary, and the fleet grammar stays small
   enough to validate exhaustively.

4. **The coordinator is the build, not a new role.** There is no
   coordinator verb, no coordinator process, no queue service. The
   existing `shuttle build --all` invocation *is* the coordinator when
   `workers` is declared: `build_sched.rs::run_ready_set` gains a
   `BuildExecutor` seam with two implementations:
   - `LocalExecutor` — today's in-process thread path, unchanged.
   - `SshExecutor` — drives one Worker over SSH: probe → dispatch →
     stream → collect.
   The scheduler change is honest about its true size: slots become
   executor-bound and ready nodes become executor-eligible (arch is a
   per-job property on multi-arch runs), which touches the dispatch
   loop beyond a drop-in trait; ready-set ordering, the stop-the-world
   rule, and `FailedBuilds{failed, skipped}` reporting are preserved
   exactly. The pool budget is `local_jobs + Σ worker.jobs`. Lost-Worker
   liveness is a named requirement: stop-the-world only fires when the
   executor returns `Err` in bounded time, so the SSH channel runs with
   keepalives (`ServerAliveInterval`-style) and a hung session is
   treated as a failed Worker at the keepalive deadline — a vanished
   host must fail the run, not hang it. A failed Worker is a failed
   build that names the Worker and the job; in-flight jobs on surviving
   machines finish and ingest before the run reports; dependents never
   start. No retry in v1: a re-run is the recovery path, and completed
   packages hit the cache. Note the honest limit: cache hits make
   re-runs cheap for *completed* packages, never for the one that was
   interrupted mid-build.

5. **Transport: SSH, everywhere, as the only farm protocol.** The
   coordinator drives every Worker through `CommandRunner`-wrapped
   `ssh` (the repo's one subprocess-client convention, the same lane as
   curl). Job dispatch, capability probing, content sync, and result
   collection all cross the one SSH channel — coordinator-initiated, so
   NAT direction is never a problem and no machine opens a port. There
   is no HTTP in the farm protocol; ADR-0033's serve surface is left
   untouched for what it already does (sharing and install).

6. **Content moves as content-addressed sync, hash-verified at both
   ends.** The job manifest lists the **full** closure — recipe slice
   (the `pkgs/` entries the job needs, own recipe bytes included per
   #172), lockfile pin slice (sources, build_deps, packages — ADR-0029
   submodule rules included), the closure list `{ sha256, size,
   purpose }` for every dep payload the sandbox must see, the
   `build_input_digest` (the #172 all-meta digest — the field that
   actually determines output bytes), the resolved toolchain identity,
   the minimum mksquashfs version (≥ 4.4, the SOURCE_DATE_EPOCH-respecting
   floor doctor already gates), `target` arch, `SOURCE_DATE_EPOCH`,
   and `protocol_version` — canonically serialized (sorted keys), so
   two coordinators produce the same manifest bytes for the same job.
   Transfer is a delta computed out-of-band: the Worker reports which
   blobs it already holds, by hash, over the job channel before any
   transfer, and **claims are content-verified before they are trusted**
   (re-hash the claimed blob; a mismatch is a named refusal — the
   `pull_peer.rs` precedent), because one truncated blob from a partial
   transfer must not poison every later job that would have skipped it.
   Ingest is stage → verify → commit atomic: a dead tar stream leaves
   zero store entries (same precedent). Every transferred object is
   verified against the manifest sha256 on arrival; every returned
   artifact is verified the same way on ingest.
   **Job identity is the SHA-256 of the canonical manifest bytes.**
   Remote results are ingested into the coordinator's store under that
   manifest identity — a namespace distinct from the local `v4:` cache —
   so a remote result can never silently substitute for a locally keyed
   `v4:` entry built from a different recipe revision. Unifying the two
   (a `v5` closure key folding in the meta fields `v4:` misses) is a
   recorded revisit trigger; it is deliberately not smuggled into this
   ADR because it invalidates every operator's local cache.
   v1 ships pinned sources *from the coordinator*: the Worker never
   fetches upstream, needs no upstream network, and can sit behind a
   firewall or in an air-gapped segment. Fetch-at-Worker is a recorded
   revisit trigger, not a v1 mode.

7. **Result trust is hash-level inside the operator trust domain;
    provenance is recorded, attestation is not claimed.** The
   coordinator re-hashes every returned artifact, ingests it under the
   manifest identity, and (as the ADR-0033 Decision 2 build-time minting
   follow-up lands) mints the signed PackageManifest under the operator
   key *coordinator-side* — a Worker never holds or uses a signing key.
   What this buys: the SSH channel authenticates the operator's
   machines, and transfer integrity is hash-verified at both ends.
   What it does not buy — stated at full strength: the coordinator has
   no expected output hash, so ingest verifies only the Worker's *own*
   claim about bytes it returned; a compromised Worker can **fabricate**
   content, and because ADR-0033's trust set is flat (any trusted key
   signs any package), coordinator-side signing launders those bytes
   into the entire peer/device trust domain. The interim mitigation is
   cheap and named: determinism cross-checks (rebuild the same closure
   locally, or on a second Worker, and compare hashes — the manifest
   identity makes the comparison exact). Build attestation (SLSA-lite
   provenance binding Worker identity to results via the existing
   `sign.rs` machinery) is a recorded revisit trigger; open it when
   results cross trust domains. Protocol version is a constant carried
   by the cap document, the job manifest, and the result document,
   named distinctly from `discovery.rs`'s mDNS version constant; a
   mismatch is a named refusal at preflight, never a runtime surprise.

8. **Observability reuses the scheduler's attribution patterns.** The
   scheduler-prefixed line convention extends with the Worker name
   (`[nuci] git 2.47.2 …`); `--json` build events gain `executor` and
   `worker` fields; remote failures dump the buffered stderr of the
   failed job prefixed by Worker name (the `set_buffer_child_stderr`
   pattern). Preflight failures name the exact probe that failed
   (reachability, protocol version, arch, sandbox capability, missing
   or too-old bwrap/mksquashfs, low disk) in miette's diagnostic style.

9. **Naming, normative.** `CONTEXT.md` gains: **Worker** (a machine
   shuttle drives over SSH to execute build jobs — avoid: node, peer,
   farm, builder, agent, remote), **Job manifest** (the content-addressed
   description of one package build dispatched to a Worker — avoid:
   task, work item), **Coordinator** (the `shuttle build` process
   scheduling a build across executors — avoid: master, server,
   orchestrator). Two discipline notes ride along: "Worker" already
   names two code-level things (the eval/check subprocess types in
   `isolate.rs`/`cli.rs` and the scheduler's pool threads), so
   CONTEXT.md flags the ambiguity rather than renaming working code;
   and the `__worker-*` verb family is declared machine-side, the
   sibling of the process-side `__eval-worker`/`__check-worker`
   pattern. The glossary keeps `farm` (bin symlinks) and `builder`
   (build-script plugin kind) as they are.

## Alternatives considered

- **Worker daemon with an HTTP job API (icecc / `shuttle serve`-style).**
  Rejected for v1: a new listening surface to harden (ADR-0033's wire
  grammar work shows the cost), a NAT direction problem for cloud
  Workers, and a persistence story the daemon law forbids shuttle from
  shipping. SSH exec covers LAN and cloud uniformly with zero new
  servers. Revisit if push-based scheduling at scale ever demands it.
- **Bazel Remote Execution API (REAPI) with Buildbarn/NativeLink.**
  Rejected: a snap build is one monolithic action, so REAPI's value
  (fine-grained action-graph caching) does not materialize; it requires
  running CAS/ActionCache/Execute server infrastructure — the exact
  operational burden the fleet case lacks; NativeLink is FSL-1.1
  (GPL-incompatible). Only the content-keyed result-cache idea is
  borrowed, and shuttle already has it (`v4:` closure keys).
- **gRPC or NATS as the job channel.** Rejected: new dependency trees
  into a no-async-runtime, vendored-dep-light codebase, and (for NATS)
  another always-on server. The anti-goal.
- **Coordinator-embedded HTTP serve for closure transfer** (Worker pulls
  from the coordinator). Rejected: the coordinator is frequently a NAT'd
  laptop, inverting the reachability assumption; tar-over-SSH needs no
  new listening code. The serve lane stays ADR-0033's.
- **Cloud provisioning in v1** (a `Provisioner` trait,
  `shuttle workers provision`, cloud-init user-data, per-worker
  `provision = { … }` config). Rejected for v1, on three grounds: the
  stated demand is machines the operator *already controls*; the seam
  is a whole CLI surface orthogonal to the build path with exactly one
  implementation; and host-key provenance has no clean answer (the
  provider API does not return SSH host keys, so provisioning would
  capture them by `ssh-keyscan` — an unauthenticated on-path-interceptable
  channel, TOFU with a print statement). The Provisioner returns as a
  revisit trigger with the host-key problem stated up front.
- **Worker-side fetch of pinned sources** (Worker runs the host-side
  fetch phase itself). Rejected for v1: it doubles the fetch surface
  (upstream reachability needed at every Worker), and coordinator-shipped
  sources make Workers air-gap-eligible and deterministic. Revisit for
  slow-link farms with large tarballs.
- **Rust cloud SDK crates** (`aws-sdk-ec2`, `hcloud` crate,
  `google-cloud-rust`, …). Rejected: heavy dep trees and API churn
  against the minimal-crate norm; provider CLIs behind `CommandRunner`
  deliver the same result with zero new crates where provisioning ever
  lands.
- **Jobs outliving the coordinator (`--recover`, the Launchpad model).**
  Deferred: v1 recovery is re-running the build, made cheap by cache
  hits; the queue state machine and resumable runs are a revisit trigger
  for fleet-scale farms.
- **mDNS discovery of Workers** (`_shuttle._tcp` subtype). Deferred:
  explicit addresses suffice when the operator names every machine;
  discovery confers no trust and adds a raceable surface for zero v1
  need.
- **Naming the config `farm {}` or `builders = { … }`.** Rejected:
  `farm` is the pod bin farm (`src/farm.rs`, issue #3) and `builder` is
  the build-script plugin kind (ADR-0014); reusing either would break
  the CONTEXT.md discipline the repo maintains.

## Consequences

**Positive**: the whole-index build spans machines with no new daemon,
socket, or runtime dependency; Workers need only sshd + the shuttle
binary + a working sandbox and stay stateless; trust rides pinned SSH
host keys, content hashes, and machinery ADR-0033 already shipped; the
scheduling change is honest about its size (executor-bound, arch-eligible
slots inside a scheduler that already models the boundary); remote
results cannot alias into local cache identities; config stays in the
one Lua file; absent `workers = { … }` changes nothing.

**Negative**: SSH key management is entirely the operator's job
(authorized_keys, host-key pinning; an unpinned host is a preflight
refusal); Workers discover nothing — an idle Worker is inert until a
coordinator calls, and a coordinator crash abandons in-flight jobs
(stop-the-world, by design); result trust is hash-level within the
operator's machines — a compromised Worker can fabricate content into
the signed trust domain until attestation lands (determinism
cross-checks are the interim control); the coordinator aggregates every
Worker's ingest (re-hash into the store under one cache lock) and every
dispatch tar stream, so coordinator disk and CPU scale with farm width
even though per-machine build I/O stays local; tar-over-SSH retransfers
content a shared store would dedup (acceptable at pool scale; revisit at
fleet scale); a `jobs` value too high for its machine is the operator's
own foot-gun (validated for type, not for RAM); Workers are Linux-only
and must match the target arch (no cross-compiling Workers in v1); one
flaky Worker fails the whole run — strict, consistent with ADR-0022's
failure posture, and deliberately so.

**Neutral**: the pool budget becomes config-driven (the RAM/IO sizing
caveat stays documented); mksquashfs CPU share grows with Worker count
while per-machine I/O contention stays local; the ADR-0022 stage-merge
gate on inter-part parallelism is untouched — parts stay serial
everywhere, local and remote alike.

## Revisit triggers

- **Job-identity unification**: a `v5` closure key folding environment,
  layout, hooks, apps, toolchain, icon, and compression into what `v4:`
  digests, closing the local staleness gap this ADR routes around for
  the remote path (cold cache miss on bump; forward-only ratchet).
- **Build attestation**: SLSA-lite provenance binding Worker identity to
  results via `sign.rs` — re-open when results cross trust domains
  (shared team pools, rented Workers).
- **Cloud provisioning**: the `Provisioner` seam and per-provider
  tickets — re-open with a real answer to host-key provenance (not
  keyscan), provider CLI or native-client transport, and the
  `provision = { … }` config shape.
- **Speed-weighted placement and capability-token routing** (`speed`,
  capability `requires` renamed to avoid the CONTEXT.md "Requires"
  collision) when heterogeneous farms make plain arch-eligibility
  insufficient.
- Fetch-at-Worker mode for slow-link farms and huge source tarballs.
- Worker daemon / push scheduling when Worker counts or latency make
  SSH-per-job the bottleneck.
- Native HTTP provisioning clients per provider (drop the CLI
  dependency).
- Multi-arch farms with cross-compiling Workers.
- Resumable runs (`--recover`) and jobs outliving the coordinator.
- mDNS Worker discovery for dense LANs.
- ADR-0022's stage-merge ADR remains the gate for inter-part
  parallelism; nothing here reopens it.

## Evidence

- Ready-set scheduler with stop-the-world semantics and fixed pool:
  `src/build_sched.rs:36` (`MAX_PARALLEL_BUILD_WORKERS = 3`),
  `src/build_sched.rs:62` (`run_ready_set`), homogeneous FIFO dispatch
  `:122-163`; ADR-0022 addendum (2026-09-14, issue #55).
- Self-contained build unit: `src/snap.rs:4371` (`build_snap`),
  `src/snap.rs:4592` (sandbox `run_build`), `src/snap.rs:6441`
  (`run_bwrapped`, `--unshare-net` at :6487), mksquashfs at
  :4475-4497; the bwrap-absent degrade path this ADR forbids on
  Workers: `detect_bwrap` :5541, `run_direct` fallback :5562.
- Content identity, and the gap Decision 6 routes around:
  `src/cache.rs:110-134` (`BuildClosure` → `v4:` covers source/sources/
  parts/target/requires/build_deps only), `CLOSURE_FORMAT_VERSION` at
  `cache.rs:66`; the honest superset `SnapMeta::build_input_digest` at
  `src/snap.rs:783-815`; `compression` excluded from both while
  selecting mksquashfs `-comp` (:4474-4482); canonical closure JSON at
  `cache.rs:204-226`; closure built at `src/main.rs:546`.
- Hidden exec-verb precedent: `src/isolate.rs` (`__eval-worker`,
  `__check-worker`), `src/cli.rs:16` (Command enum), `:689-697`.
- Trust + transfer machinery: `src/sign.rs` (ed25519, verify_trust_set,
  key at :114-116), `src/pkg_manifest.rs` (signed PackageManifest),
  `src/pull_peer.rs` (hash-verified staging; re-verification of claimed
  blobs :321-329; stage→verify→commit atomicity :339-345), `src/serve.rs`
  (HTTP subset — untouched by this ADR); flat trust set: ADR-0033
  :241-243, :382; ADR-0033 Decisions 2 and 7; the build-time minting
  follow-up is a dependency of coordinator-side signing here.
- Host-side fetch env: `SOURCE_DATE_EPOCH` set in the coordinator's
  process at `src/main.rs:683-684` (Workers must set their own —
  Decision 2); mksquashfs ≥ 4.4 SOURCE_DATE_EPOCH floor:
  `src/doctor.rs:1132-1205`.
- Network convention: curl behind `CommandRunner` with bounded timeouts
  (`src/oci.rs`); no `ssh` invocation exists in `src/` yet (doc-comment
  only at `snap.rs:1454`) — Decision 5's fail-closed host-key rules are
  obligations on the new code, not descriptions of existing code.
- Config precedents: marker-stamped `node()` (`src/dsl/init.lua:908`,
  `src/lua.rs:107-114`) vs global capture (`WorkerOk.global_inputs`,
  `src/isolate.rs:134-135`); `arch`/`target` naming per CONTEXT.md:46.
- Errors/logging: miette throughout; dual human/JSON in `src/output.rs`;
  per-package buffered stderr (`snap.rs set_buffer_child_stderr`).
- Prior art (2026-09): Nix distributed builds and `builders` grammar
  (nixos.org manual, nix.dev conf-file); REAPI scope and server list,
  NativeLink license (bazelbuild/remote-apis); Launchpad builder queue
  model and `snapcraft remote-build` (launchpad.readthedocs.io,
  snapcraft.io/docs); distcc/icecc granularity limits (distcc.org,
  github.com/icecc/icecream); cargo-remote SSH transport
  (github.com/rust-lang/cargo-remote); nixbuild.net SSH-only posture
  (docs.nixbuild.net).

## References

ADR-0011 (daemon law), ADR-0022 + addendum (build execution model,
ready-set scheduler), ADR-0024 (key ceremony, explicit trust),
ADR-0029 (submodule pinning), ADR-0032 (declared services — not used by
this ADR's v1; Workers need no persistence), ADR-0033 (peer sharing,
PackageManifest, config-in-Lua, dep vetting ritual), ADR-0038 (pod
isolation; the Worker is a build-farm machine, unrelated to pod
execution boundaries), ADR-0039 (offline sandbox; non-degradable on
Workers), ADR-0042 (the numbering this ADR's original draft number
yielded to pod secret sources). The 0038 numbering collision noted in
ADR-0039 resolved on 2026-09-26: the squashfs ADR renumbered to ADR-0041.
