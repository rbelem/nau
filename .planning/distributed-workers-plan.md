# Distributed build workers plan

shuttle gains an SSH-driven build pool. The coordinator is the existing `shuttle build --all` process. A Worker is a machine the operator names in a new `workers = { ... }` array in `shuttle.lua`, driven over SSH, with no daemon and no new listening socket. Cloud burst (AWS, GCP, Azure, Scaleway, Hetzner) lands behind one Provisioner seam as per-provider tickets. The feature supersedes ADR-0022 Decision 4 and is designed in `docs/adr/0040-distributed-build-workers.md`. Tickets run T0 through T10 in dependency order.

## How to read this

One box is one unit of work. Every box names the evidence that checks it. A nested box is a sub-step of the box above it. Check a box only when its evidence exists, a file, a log line, a saved run artifact, or a SHA. The body is a how-to. The appendices explain and record.

The program runs `~/.agents/skills/poteto-mode/playbooks/orchestrate.md`. Owners are AFK agents that claim a ticket issue, implement, run the gates, and open a PR. The operator merges. Ticket issue numbers are recorded in Appendix D as they are created.

Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

## Program checklist

### Arm the program

- [ ] State the protocol and this plan to the operator, then stop. Start execution only on her explicit go.
- [ ] On her go, arm a `/goal` with this exact text. "Run the plan at `.planning/distributed-workers-plan.md`, tickets T0 through T10 in dependency order, every PR verified when its unit, live, and perf boxes are all checked, owners open PRs and the operator merges, done when T10 merges and Appendix D lists every issue number."
- [ ] Read these from trunk at program start. Re-read them at every tick.
  - [ ] `git show origin/main:docs/adr/0040-distributed-build-workers.md`
  - [ ] `git show origin/main:AGENTS.md`
  - [ ] `git show origin/main:docs/agents/build-and-test.md`
  - [ ] `git show origin/main:docs/agents/git-workflow.md`
  - [ ] `~/.agents/skills/poteto-mode/playbooks/orchestrate.md`
  - [ ] `~/.agents/skills/poteto-mode/playbooks/opening-a-pr.md`
- [ ] Arm the 30-minute audit tick. A real terminal `/loop` in a local session. Never leave the cadence to memory.
- [ ] Use this tick prompt, verbatim. "Re-read the execution playbook and the armed /goal. Audit the operation against both and fix drift in this tick. Probe every active lane and judge progress by side effects only. Stand down a stuck lane and dispatch its replacement now. Then send the operator a status message, whether or not anything changed, with the queue table of ticket, owner, state, and head SHA, the verdicts since the last tick, what merged, open operator gates, and blockers."
- [ ] On the operator's hold or stand-down, send every owner a zero-writes order at once.

### Spawn owners

- [ ] Spawn one owner per ticket with the full lifecycle the execution playbook names.
- [ ] Follow this dependency graph. Start dependent work only after its parent merges.
  - [ ] T0 is first and alone. It lands the ADR, the glossary terms, and this plan on trunk.
  - [ ] T1 after T0. T2 after T1. T3 after T1.
  - [ ] T4 after T2 and T3. T5 after T4.
  - [ ] T6 after T3. T7, T8, T9, T10 after T6 and are independent of each other.
- [ ] Hold the file boundaries. T1 touches only `src/dsl/init.lua` and the eval payload struct. T2 touches only `src/build_sched.rs` and its call site in `src/main.rs`. T3 touches only `src/cli.rs` and the new `src/worker.rs`. T4 touches only `src/ssh_exec.rs` and `src/worker.rs`. T5 touches only `src/build_sched.rs`, `src/main.rs`, and `src/output.rs`. T6 touches only `src/provision.rs` and `src/cli.rs`. T7 through T10 touch only their provider module under `src/provision/`.
- [ ] Hold the review gate. T5, T6, T7, T8, T9, T10 change what the operator sees. They wait for the operator's review in chat with the lane logs and a terminal video before merge.

### PR mechanics, for every PR

- [ ] Resolve the forge once. Use `gh` for every PR operation. This repo is `rbelem/shuttle`.
- [ ] Open the PR ready, never draft, with `gh pr create --base main`.
- [ ] Run the full gate once before the PR-facing push. `env -u LD_LIBRARY_PATH devbox run -- check`, then `shuttle run --pod gate -- cargo clippy -- -D warnings`, then `shuttle run --pod gate -- cargo fmt --check`.
- [ ] Run `/stop-slop` before each commit and `/no-comments` before review.
- [ ] Triage every Bugbot and security-reviewer comment per `~/.agents/skills/poteto-mode/references/bugbot-triage.md`.
- [ ] Rebase onto current trunk before babysit and again before the merge-ready report.

### Verdict and merge, for every PR

- [ ] At the merge-ready head SHA, run the swarm per `~/.agents/skills/swarm/SKILL.md`. One gates lane. The ten live lanes from the ticket's **Verify, live** block. The perf lane from its **Verify, perf** block. One audit lane that reads the diff and the receipts and distrusts the PR body.
- [ ] Clean only when every lane is `PASS`. Findings go back to the owner. A new head gets a fresh swarm and a fresh verdict.
- [ ] The owner squash-merges its own PR after the clean verdict and the operator's click on review-gated tickets.

### Boot recipe, for every live lane

Each live lane runs in its own background agent at the PR head. Drive through direct CLI runs.

- [ ] `git fetch origin <head-branch> && git checkout <head SHA>`.
- [ ] Build once. `env -u LD_LIBRARY_PATH devbox run -- build`.
- [ ] Run the lane scenario through the built binary. Local-loopback SSH workers use `ssh://localhost` with the operator's own key; a second machine on the LAN is used where the lane names one, and when no second machine exists the lane records that fact and runs the loopback variant of the same scenario.
- [ ] Deliver input only through the CLI. Name the read-only diagnostics, `shuttle doctor`, `--json` flags, and exit codes.
- [ ] Save every run artifact, logs and JSON transcripts, to `/tmp/swarm-<ticket>/worker-<n>/<slug>.log` and return the paths with the report.

## Ratify the ADR and the vocabulary (T0)

**Depends on.** None. T0 is the root of the graph.

**Files.**

- [ ] Edit `docs/adr/0022-build-execution-model.md` to add a supersession note on Decision 4 pointing at ADR-0040.
- [ ] Edit `CONTEXT.md` to add the Worker, Job manifest, and Coordinator entries and the avoid-lists.
- [ ] Create `.planning/distributed-workers-plan.md` with this content.

**Build.**

- [ ] Land ADR-0040 as Proposed with the supersession, the ten decisions, and the evidence section unchanged from the draft.
- [ ] Add the three glossary entries with avoid-lists. Worker avoids node, peer, farm, builder, agent, remote. Job manifest avoids task, work item. Coordinator avoids master, server, scheduler, orchestrator.

**You see.**

- [ ] `docs/adr/0040-distributed-build-workers.md` on trunk with Status Proposed. `CONTEXT.md` gains three entries. ADR-0022 Decision 4 carries the supersession note.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] No code changes land, so no test cases change. Run `env -u LD_LIBRARY_PATH devbox run -- check` to prove the tree still gates clean.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run `shuttle build pkgs/h/htop.lua --all` at trunk and head. Trunk has no docs-only change, record that fact. Save `docs-parity.log`. Pass when head output equals trunk output byte for byte.
- [ ] Lane 2. ADR cross-links resolve. Open ADR-0040 and follow every file pointer to a real file or line. Save `adr-links.log`. Pass when no pointer dangles.
- [ ] Lane 3. Glossary vocabulary lands. Grep `CONTEXT.md` for Worker, Job manifest, Coordinator. Save `glossary.log`. Pass when all three entries exist with avoid-lists.
- [ ] Lane 4. Supersession note reads correctly. Read ADR-0022 Decision 4. Save `supersession.log`. Pass when the note names ADR-0040 and scopes the supersession to build compute only.
- [ ] Lane 5. Plan file parses. Run the plan checker on `.planning/distributed-workers-plan.md`. Save `plan-check.log`. Pass when the checker exits zero.
- [ ] Lane 6. ADR numbering is unique. List `docs/adr/` and confirm 0040 collides with nothing. Save `adr-list.log`. Pass when 0040 appears once.
- [ ] Lane 7. Doc gates. Run the repo doc conventions check, titles, Status sections, References sections present in ADR-0040. Save `adr-shape.log`. Pass when the shape matches the ADR-0033 template.
- [ ] Lane 8. No secrets in the new docs. Grep the diff for tokens and keys. Save `secret-scan.log`. Pass when the scan is clean.
- [ ] Lane 9. Issue tracker state. Confirm the eleven ticket issues exist and reference this plan. Save `issues.log`. Pass when every ticket T1 through T10 has an issue number recorded in Appendix D.
- [ ] Lane 10. GPL header and license hygiene on new files. Confirm no license headers were added or removed. Save `license.log`. Pass when the diff touches no license text.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Build wall clock for `shuttle build pkgs/h/htop.lua --all` at trunk and head, docs-only change expected to move nothing.
- [ ] Probe. Time the build three times at trunk and three at head, interleaved, cold stage each run.
- [ ] Baseline. Record the trunk median first.
- [ ] Rule. Head median within 5 percent of the trunk median. A larger delta is a docs-process regression and fails.

**Review gate.** None. T0 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the verdict.

## Land the workers config surface (T1)

**Depends on.** T0.

**Files.**

- [ ] Edit `src/dsl/init.lua` to add the `workers` validator.
- [ ] Edit the eval payload struct in `src/lua.rs` to carry the parsed workers table.
- [ ] Create `tests/workers_config.rs`.

**Build.**

- [ ] Top-level `workers = { ... }` array validated Lua-side. Fields address, required, `ssh://[user@]host[:port]`; jobs, default 2, minimum 1; speed, default 1.0, positive number; arch, optional GNU triplet; requires, optional string list; provision, optional table, deferred to T6.
- [ ] Eval payload gains the workers field. Absent key evaluates to an empty vector, no behavior change anywhere.
- [ ] Every malformed shape produces one named miette diagnostic that names the field.

**You see.**

- [ ] `shuttle eval` on a `shuttle.lua` with a workers table prints the payload carrying the parsed worker list. Absent the key, every existing command behaves exactly as before.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/workers_config.rs` gains the valid table, absent key, missing address, bad scheme, zero jobs, negative speed, wrong types, unknown field, duplicate address cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run `shuttle build pkgs/h/htop.lua --all` at trunk and head with no workers key. Trunk has no workers feature, record that fact and gate that head adds no behavior. Save `no-key-parity.log`. Pass when head artifacts and output equal trunk.
- [ ] Lane 2. Valid table evaluates. Run `shuttle eval` on a fixture with two workers. Save `eval-ok.log`. Pass when the payload JSON lists both addresses.
- [ ] Lane 3. Missing address. Run eval on a worker without address. Save `missing-address.log`. Pass when the diagnostic names the address field and exits nonzero.
- [ ] Lane 4. Bad scheme. Address `http://host` is refused. Save `bad-scheme.log`. Pass when the diagnostic names the ssh scheme rule.
- [ ] Lane 5. Zero jobs refused. Save `zero-jobs.log`. Pass when the diagnostic names jobs and the minimum.
- [ ] Lane 6. Wrong type. `workers = "nuci"` is refused. Save `wrong-type.log`. Pass when the diagnostic names the array shape.
- [ ] Lane 7. Unknown field refused. Save `unknown-field.log`. Pass when the diagnostic names the field.
- [ ] Lane 8. Duplicate address refused. Save `duplicate.log`. Pass when the diagnostic names the duplicate.
- [ ] Lane 9. Arch override accepted. `arch = "aarch64-linux-gnu"` parses into the payload. Save `arch-ok.log`. Pass when the payload carries the triplet.
- [ ] Lane 10. Empty table is the zero path. `workers = { }` builds htop exactly like trunk. Save `empty-table.log`. Pass when the build succeeds with no SSH and no sockets, proven by `ss -tlnp` before and after.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Eval and build wall clock with no workers key, head against trunk. The diff-added work is one table parse on an absent key and must cost nothing measurable. The end state the user waits for is the same artifact at the same time.
- [ ] Probe. Time `shuttle eval` and the htop build three times each at trunk and head, interleaved.
- [ ] Baseline. Record the trunk medians first.
- [ ] Rule. Head within 5 percent of trunk on both metrics. Absolute budget for the diff-added parse, under 1 millisecond.

**Review gate.** None. T1 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the verdict.

## Add the BuildExecutor seam to the scheduler (T2)

**Depends on.** T1.

**Files.**

- [ ] Edit `src/build_sched.rs` to add the `BuildExecutor` trait, the `LocalExecutor` impl, and config-driven pool sizing.
- [ ] Edit `src/main.rs` at the `build_all_deps` call site to pass the executor.
- [ ] Create `tests/build_sched_executors.rs`.

**Build.**

- [ ] `trait BuildExecutor` with run and cancel. `LocalExecutor` wraps today's thread body unchanged.
- [ ] Pool budget becomes local plus the sum of worker jobs from the eval payload, workers empty means today's fixed three.
- [ ] Stop-the-world semantics, ready-set ordering, and `FailedBuilds{failed, skipped}` are preserved byte for byte.
- [ ] Scheduler line prefixes gain an executor field, `local` for the local executor.

**You see.**

- [ ] With no workers key, every build behaves and reads exactly as before except the prefix now names the executor `local`.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/build_sched_executors.rs` gains pool sizing, single-executor fan-out, stop-the-world on first failure, and ordering cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure build at trunk and head. Trunk has no seam, record that fact and gate the head adds no behavior. Save `seam-parity.log`. Pass when artifact hashes and output equal trunk.
- [ ] Lane 2. Executor prefix. Run any build and read the scheduler lines. Save `prefix.log`. Pass when every line names `local`.
- [ ] Lane 3. Default pool. A six-package fan closure shows three concurrent workers in the timing log. Save `pool-default.log`. Pass when concurrency reads three.
- [ ] Lane 4. Stop-the-world holds. Inject a failing package mid-closure. Save `stop-world.log`. Pass when dependents never start and exit is nonzero naming the failed set.
- [ ] Lane 5. FailedBuilds report. Same run as lane 4. Save `failed-set.log`. Pass when failed and skipped lists match the DAG.
- [ ] Lane 6. Fan-out overlap. Time the six-package closure. Save `overlap.log`. Pass when wall clock is under the serial sum of stage times.
- [ ] Lane 7. Determinism. Run the same closure twice. Save `det-1.log` and `det-2.log`. Pass when the schedule lines match.
- [ ] Lane 8. Stress. A thirty-package synthetic closure completes with no deadlock. Save `stress.log`. Pass when the run exits zero.
- [ ] Lane 9. JSON events. Run with `--json` and pipe to jq. Save `json-events.log`. Pass when every event parses and carries the executor field.
- [ ] Lane 10. No-socket proof. `ss -tlnp` before and after a build. Save `no-socket.log`. Pass when no listener appears.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Closure build wall clock at trunk and head with no workers key. The diff-added work is one trait dispatch per job and the end state the user waits for is unchanged.
- [ ] Probe. Time the six-package closure three times at trunk and three at head, interleaved, cold stage.
- [ ] Baseline. Record the trunk median first.
- [ ] Rule. Head within 5 percent of trunk. Absolute budget for diff-added dispatch, under 1 millisecond per job.

**Review gate.** None. T2 is not review-gated.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the verdict.

## Add the hidden worker verbs (T3)

**Depends on.** T1.

**Files.**

- [ ] Edit `src/cli.rs` to add hidden `__worker-cap` and `__worker-job` verbs, hidden like `__eval-worker`.
- [ ] Create `src/worker.rs` with the job manifest types, the cap document, and both verb bodies.
- [ ] Create `tests/worker_job.rs`.

**Build.**

- [ ] `__worker-cap` prints the capability document as JSON, protocol version, arch, nproc, RAM, free disk, bwrap and mksquashfs presence, KVM presence, then exits.
- [ ] `__worker-job <job-file>` materializes the recipe slice and pinned inputs, verifies every sha256, runs the ordinary offline sandbox build path through `snap.rs::build_snap`, and prints the result document as JSON, artifact paths, hashes, and buffered stderr.
- [ ] Job manifest carries recipe slice, lockfile pin slice, closure list, target, source date epoch, protocol version. Every mismatch and every hash failure is a named miette refusal before any build runs.

**You see.**

- [ ] The two verbs appear nowhere in `--help` and produce JSON on stdout. A corrupt input is refused by name before the sandbox starts.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/worker_job.rs` gains manifest round-trip, hash verification, refusal cases, cap document shape, and a full loopback job on a tempdir stage. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run `shuttle --help` at trunk and head. Trunk hides the verbs, record that fact and gate that head still hides them. Save `help-parity.log`. Pass when neither help output names the verbs.
- [ ] Lane 2. Cap document. Run `__worker-cap` on the lane machine. Save `cap-ok.log`. Pass when the JSON carries protocol, arch, nproc, and tool flags.
- [ ] Lane 3. Tool absence. Run the cap verb with bwrap removed from PATH. Save `cap-nobwrap.log`. Pass when the bwrap flag reads false and the verb still exits zero.
- [ ] Lane 4. Happy job. Run `__worker-job` with a hello fixture manifest. Save `job-ok.log`. Pass when the result JSON hashes match the files on disk.
- [ ] Lane 5. Corrupt input. Flip one byte in a closure blob and run. Save `corrupt.log`. Pass when the refusal names the sha256 and the build never starts.
- [ ] Lane 6. Missing blob. Drop one closure file and run. Save `missing-blob.log`. Pass when the refusal names the missing hash.
- [ ] Lane 7. Offline proof. Run a job whose build script would fetch the network. Save `offline.log`. Pass when the build fails and the failure is the network hint, `--unshare-net` held.
- [ ] Lane 8. Protocol mismatch. Run a manifest with a wrong protocol version. Save `proto.log`. Pass when the refusal names the version.
- [ ] Lane 9. Buffered stderr. Run a failing job. Save `stderr-dump.log`. Pass when the result document carries the full child stderr.
- [ ] Lane 10. Two jobs in sequence. Run two different job manifests back to back. Save `two-jobs.log`. Pass when both succeed with independent result documents.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. The cap verb wall clock and the per-job overhead on top of `build_snap`, measured head against trunk. Trunk lacks the verbs, record that fact. Isolate the diff-added work, manifest parse, hash walks, JSON emit, and budget it absolutely. The end state the user waits for is the artifact at local-build speed.
- [ ] Probe. Time the cap verb twenty times, and time one hello job three times, head only, with the stage time subtracted to isolate overhead.
- [ ] Baseline. Record the stage build time from trunk `build_snap` first.
- [ ] Rule. Cap verb under 200 milliseconds. Per-job overhead under 2 percent of the stage build time.

**Review gate.** None. T3 is not review-gated. The verbs are hidden.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the verdict.

## Add the SSH transport and content sync (T4)

**Depends on.** T2 and T3.

**Files.**

- [ ] Create `src/ssh_exec.rs` with the `SshExecutor`, preflight, dispatch, delta sync, and result ingest.
- [ ] Edit `src/worker.rs` to read and write job files from the transport side.
- [ ] Create `tests/ssh_exec.rs` with a loopback harness over `ssh://localhost`.

**Build.**

- [ ] `SshExecutor` drives `ssh` through `CommandRunner` with bounded timeouts, probe, dispatch, stream, collect.
- [ ] Preflight runs `__worker-cap` and asserts protocol, arch match with the job target, tool presence, and free disk. Any failure is a named refusal naming the probe.
- [ ] Delta sync ships only objects the worker reports missing, as a tar stream over the SSH channel, and verifies every sha256 on arrival. Returned artifacts are hash-verified before cache ingest keyed `v4:<closure_sha256>`.
- [ ] Workers never fetch upstream. Pinned sources travel in the job payload.

**You see.**

- [ ] A job dispatched to `ssh://localhost` lands in the coordinator cache. A second identical job reports the cache hit and transfers nothing.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/ssh_exec.rs` gains preflight assertions, delta computation, tar round-trip, hash failure injection, and ingest cases on the loopback harness. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure locally at trunk and head with no workers key. Trunk has no transport, record that fact and gate the head adds no behavior. Save `transport-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Loopback dispatch. Dispatch one hello job to `ssh://localhost`. Save `dispatch.log`. Pass when the artifact lands and the result hashes match.
- [ ] Lane 3. Delta sync. Dispatch a second job sharing most of the closure. Save `delta.log`. Pass when the transfer log shows only the missing objects moved.
- [ ] Lane 4. Preflight names the probe. Run with mksquashfs hidden on the worker PATH. Save `preflight-tools.log`. Pass when the refusal names the mksquashfs probe and no job runs.
- [ ] Lane 5. Arch mismatch refused. Target an aarch64 job at an x86_64 worker. Save `arch-refusal.log`. Pass when the refusal names arch and nothing dispatches.
- [ ] Lane 6. Corrupt in flight. Inject a flipped byte into the tar stream with an intercepting wrapper. Save `corrupt-stream.log`. Pass when the arrival hash check names the object and the job fails.
- [ ] Lane 7. Cache ingest. Re-run the same job. Save `cache-hit.log`. Pass when the coordinator reports the `v4:` cache hit and transfers nothing.
- [ ] Lane 8. Host key change. Point the worker at a moved host key. Save `hostkey.log`. Pass when ssh refuses and the diagnostic says so plainly.
- [ ] Lane 9. Concurrency on one worker. Set jobs to 4 and dispatch six jobs. Save `concurrency.log`. Pass when at most four run at once and all six land.
- [ ] Lane 10. A second real machine. Run lane 2 against a LAN box. When none exists, record that fact and run the loopback variant. Save `second-machine.log`. Pass when the named variant completes.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Sync overhead per job, bytes moved for a shared closure, and loopback dispatch wall clock. Trunk lacks the transport, record that fact. Budget the diff-added work absolutely. The end state the user waits for is the artifact with the remote round trip visible but bounded.
- [ ] Probe. Time ten loopback dispatches, record bytes moved per job from the transfer log, and hash the closure to compute the redundancy ratio.
- [ ] Baseline. Record the local job time from trunk first.
- [ ] Rule. Per-job sync overhead under 500 milliseconds on loopback. Delta sync moves under 10 percent of the closure bytes on the second job of a shared closure.

**Review gate.** None. T4 is not review-gated. The transport has no operator-visible surface beyond T5's integration.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the verdict.

## Integrate the coordinator and the observability (T5)

**Depends on.** T4.

**Files.**

- [ ] Edit `src/main.rs` at the `build_all_deps` wiring to install the `SshExecutor` when the eval payload carries workers.
- [ ] Edit `src/build_sched.rs` for cross-executor failure semantics and placement by speed factor.
- [ ] Edit `src/output.rs` for the worker field in human lines and JSON events.
- [ ] Create `tests/coordinator_farm.rs`.

**Build.**

- [ ] `build --all` with workers dispatches ready nodes to the `SshExecutor` by capability match, then speed factor, then ready-set order.
- [ ] Failure semantics are strict and global. A lost or failed worker fails the run, names the worker and the job, in-flight jobs on surviving executors finish, dependents never start.
- [ ] JSON events gain executor and worker fields. Remote failures dump the buffered stderr prefixed by the worker name.

**You see.**

- [ ] A farm build prints scheduler lines attributed per worker, `[nuci] git 2.47.2`, and the summary names every worker that failed, if any.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/coordinator_farm.rs` gains placement order, capability filtering, worker-loss stop-the-world, and JSON field cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and at head with no workers key. Trunk lacks the feature, record that fact and gate that head adds nothing without config. Save `coord-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Farm build. Build a ten-package closure across two workers, loopback plus one LAN machine. Save `farm-build.log`. Pass when every line attributes its worker and the run exits zero.
- [ ] Lane 3. Worker loss. Kill the SSH process mid-build on one worker. Save `worker-loss.log`. Pass when the run fails nonzero, names the worker and job, survivors finish, dependents never start.
- [ ] Lane 4. Remote stderr dump. Force a remote build failure with a broken recipe. Save `remote-stderr.log`. Pass when the full stderr appears prefixed by the worker name.
- [ ] Lane 5. JSON fields. Run a farm build with `--json` through jq. Save `farm-json.log`. Pass when events carry executor and worker.
- [ ] Lane 6. Speed factor placement. Give one worker speed 2.0 and count assigned jobs. Save `placement.log`. Pass when the fast worker receives roughly twice the share.
- [ ] Lane 7. Capability filter. Target an aarch64 job at a pool with one arm worker. Save `cap-filter.log`. Pass when the job lands only on the arm worker.
- [ ] Lane 8. Cache re-run. Rebuild the same closure. Save `rerun.log`. Pass when no dispatch happens and the run exits zero from cache.
- [ ] Lane 9. Artifact equality. Compare the farm-built closure hashes to a local-only rebuild. Save `hash-equality.log`. Pass when every hash matches.
- [ ] Lane 10. The end state the user waits for. Time the ten-package farm build against a local-only run of the same closure. Save `end-state.log`. Pass when the farm run is faster.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Wall clock of the ten-package closure, trunk local-only against head farm with two workers. Trunk lacks the feature, so also isolate the diff-added coordinator work, dispatch, sync, and ingest, and budget it absolutely against the end state the user waits for.
- [ ] Probe. Time the closure three times trunk local-only and three times head farm, interleaved, cold stage each run, and record per-job coordinator overhead from the event log.
- [ ] Baseline. Record the trunk local-only median first.
- [ ] Rule. Head farm median at least 25 percent under the trunk baseline. Absolute budget for coordinator overhead, under 5 percent of the farm wall clock.

**Review gate.** The operator reviews before merge. T5 changes what every farm build looks like.

- [ ] Copy lane 2, 3, and 4 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 2. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Add the Provisioner seam and the Hetzner provider (T6)

**Depends on.** T3.

**Files.**

- [ ] Create `src/provision/mod.rs` with the `Provisioner` trait and the shared cloud-init template.
- [ ] Create `src/provision/hetzner.rs` driving the `hcloud` CLI through `CommandRunner`.
- [ ] Edit `src/cli.rs` to add the `Workers` subcommand with `provision` and `destroy`.
- [ ] Create `tests/provision_hetzner.rs`.

**Build.**

- [ ] `shuttle workers provision --provider hetzner --type cx22 --location fsn1 --count 1` creates servers, waits for cloud-init, prints the host key for pinning, and appends the worker entry to the `workers` array in `shuttle.lua`.
- [ ] Cloud-init installs the pinned shuttle binary, writes the operator authorized key, and stamps a TTL marker file.
- [ ] `shuttle workers destroy --provider hetzner --name <name>` removes the server and the config entry.
- [ ] No token, invalid token, and dry-run are all handled before any API call. Secrets never enter `shuttle.lua`.

**You see.**

- [ ] One command turns a Hetzner account into a listed worker in `shuttle.lua` that a farm build uses. The printed host key is pinned before first use.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/provision_hetzner.rs` gains CLI mocking, dry-run shape, config append, and destroy cleanup cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe. Lanes 3 through 9 run against a real Hetzner account and are skipped with a recorded reason when no `HCLOUD_TOKEN` is set.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and head. Trunk lacks the verb, record that fact and gate that head adds nothing without the subcommand. Save `prov-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Missing token. Run provision with no `HCLOUD_TOKEN`. Save `no-token.log`. Pass when the refusal names the token and no API call is made, proven by an empty hcloud debug log.
- [ ] Lane 3. Dry-run. Run provision with `--dry-run`. Save `dry-run.log`. Pass when the plan names type, location, count, and user-data hash, and no server exists after.
- [ ] Lane 4. Real provision. Provision one `cx22`. Save `real-provision.log`. Pass when cloud-init completes and `__worker-cap` over SSH succeeds.
- [ ] Lane 5. Host key pinning. Run provision a second time against the same server. Save `hostkey-pin.log`. Pass when the pinned key matches and no re-prompt happens.
- [ ] Lane 6. Config append. Read `shuttle.lua` after provisioning. Save `config-append.log`. Pass when the workers array gains the entry and the file still evaluates.
- [ ] Lane 7. End-to-end job. Build the htop closure with the provisioned worker in the pool. Save `prov-e2e.log`. Pass when the job attributes the Hetzner worker and exits zero.
- [ ] Lane 8. Invalid token. Run provision with a bad token. Save `bad-token.log`. Pass when the provider error is named and no partial state remains.
- [ ] Lane 9. TTL marker. SSH to the provisioned server and read the marker. Save `ttl-marker.log`. Pass when the marker names the TTL the cloud-init wrote.
- [ ] Lane 10. Destroy. Run destroy and list servers. Save `destroy.log`. Pass when the server is gone and the config entry is removed.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Provision wall clock, token check to cap probe success, head only. Trunk lacks the verb, record that fact. The end state the user waits for is a usable worker, so the budget covers the whole path.
- [ ] Probe. Time three fresh provision runs to cap success, recording each phase, API create, cloud-init wait, cap probe.
- [ ] Baseline. Record the first run's phase times first.
- [ ] Rule. Under 4 minutes token to cap on `cx22`, cloud-init dominating. Budget the shuttle-side overhead alone at under 15 seconds.

**Review gate.** The operator reviews before merge. T6 adds a CLI verb that spends real money.

- [ ] Copy lane 3, 4, and 10 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 4. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Add the AWS provider (T7)

**Depends on.** T6.

**Files.**

- [ ] Create `src/provision/aws.rs` driving the `aws` CLI through `CommandRunner`, `RunInstances` with spot options and user-data cloud-init.
- [ ] Create `tests/provision_aws.rs`.

**Build.**

- [ ] `shuttle workers provision --provider aws --type m5.large --region <region> --count 1 --spot` resolves an AMI, requests spot capacity at a price cap, and lands the worker in config with host-key pinning like T6.
- [ ] Spot eviction surfaces as a lost worker under T5's stop-the-world rule. No mid-flight migration.

**You see.**

- [ ] One command turns an AWS account into a listed spot worker. An eviction during a build reads as the named worker loss T5 already defines.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/provision_aws.rs` gains CLI mocking, spot option shape, price cap, and config cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe. Lanes 3 through 9 run against a real AWS account and are skipped with a recorded reason when no AWS credentials are set.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and head. Trunk lacks the provider, record that fact and gate that head adds nothing without the flag. Save `aws-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Missing credentials. Run with no AWS credentials. Save `aws-no-creds.log`. Pass when the refusal names the credential chain and no API call is made.
- [ ] Lane 3. Dry-run. Save `aws-dry-run.log`. Pass when the plan names AMI, type, spot cap, and user-data hash, and no instance exists after.
- [ ] Lane 4. Real spot provision. Save `aws-provision.log`. Pass when the spot request fulfills, cloud-init completes, and the cap probe succeeds.
- [ ] Lane 5. Price cap honored. Read the request log. Save `aws-cap.log`. Pass when the bid equals the configured cap and fulfillment respects it.
- [ ] Lane 6. Config append and pinning. Save `aws-config.log`. Pass when the entry lands and the second run skips re-pinning.
- [ ] Lane 7. End-to-end job. Save `aws-e2e.log`. Pass when the closure builds with the AWS worker attributed.
- [ ] Lane 8. Eviction. Terminate the instance mid-job. Save `aws-eviction.log`. Pass when the run fails naming the worker, matching T5 lane 3 semantics.
- [ ] Lane 9. Region override. Provision in a second region. Save `aws-region.log`. Pass when the worker lands in the named region.
- [ ] Lane 10. Destroy. Save `aws-destroy.log`. Pass when the instance is terminated and the config entry removed.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Spot provision wall clock, request to cap probe, head only. Trunk lacks the provider, record that fact. The end state the user waits for is a usable spot worker.
- [ ] Probe. Time three fresh spot provisions, recording request, fulfillment, cloud-init, cap phases.
- [ ] Baseline. Record the first run's phases first.
- [ ] Rule. Fulfillment to cap under 6 minutes on `m5.large` in the tested region. Shuttle-side overhead under 15 seconds.

**Review gate.** The operator reviews before merge. T7 spends real money and adds a provider surface.

- [ ] Copy lane 3, 4, and 8 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 4. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Add the GCP provider (T8)

**Depends on.** T6.

**Files.**

- [ ] Create `src/provision/gcp.rs` driving the `gcloud` CLI through `CommandRunner`, `instances insert` with `--metadata startup-script`.
- [ ] Create `tests/provision_gcp.rs`.

**Build.**

- [ ] `shuttle workers provision --provider gcp --type e2-standard-4 --zone <zone> --count 1` creates the instance with the startup-script cloud-init template, pins the host key, and appends the worker entry.
- [ ] Preemptible VMs ride `--preemptible`, and eviction reads as T5 worker loss.

**You see.**

- [ ] One command turns a GCP project into a listed worker, preemptible when asked.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/provision_gcp.rs` gains CLI mocking, startup-script shape, preemptible flag, and config cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe. Lanes 3 through 9 run against a real GCP project and are skipped with a recorded reason when no GCP credentials are set.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and head. Trunk lacks the provider, record that fact. Save `gcp-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Missing credentials. Save `gcp-no-creds.log`. Pass when the refusal names the credential chain and no API call is made.
- [ ] Lane 3. Dry-run. Save `gcp-dry-run.log`. Pass when the plan names type, zone, and startup-script hash, and no instance exists after.
- [ ] Lane 4. Real provision. Save `gcp-provision.log`. Pass when the instance runs, startup-script completes, and the cap probe succeeds.
- [ ] Lane 5. Preemptible flag. Provision with `--preemptible`. Save `gcp-preemptible.log`. Pass when the instance carries the flag.
- [ ] Lane 6. Config append and pinning. Save `gcp-config.log`. Pass when the entry lands and re-runs skip re-pinning.
- [ ] Lane 7. End-to-end job. Save `gcp-e2e.log`. Pass when the closure builds with the GCP worker attributed.
- [ ] Lane 8. Eviction. Stop the instance mid-job. Save `gcp-eviction.log`. Pass when the run fails naming the worker.
- [ ] Lane 9. Zone override. Provision in a second zone. Save `gcp-zone.log`. Pass when the worker lands in the named zone.
- [ ] Lane 10. Destroy. Save `gcp-destroy.log`. Pass when the instance is deleted and the config entry removed.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Provision wall clock, insert to cap probe, head only. Trunk lacks the provider, record that fact. The end state the user waits for is a usable worker.
- [ ] Probe. Time three fresh provisions, recording insert, startup-script, cap phases.
- [ ] Baseline. Record the first run's phases first.
- [ ] Rule. Insert to cap under 5 minutes on `e2-standard-4`. Shuttle-side overhead under 15 seconds.

**Review gate.** The operator reviews before merge. T8 spends real money and adds a provider surface.

- [ ] Copy lane 3, 4, and 8 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 4. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Add the Azure provider (T9)

**Depends on.** T6.

**Files.**

- [ ] Create `src/provision/azure.rs` driving the `az` CLI through `CommandRunner`, VM create with Custom Script Extension or cloud-init supported images.
- [ ] Create `tests/provision_azure.rs`.

**Build.**

- [ ] `shuttle workers provision --provider azure --type Standard_D4s_v5 --location <region> --count 1` creates the VM with the bootstrap template, pins the host key, and appends the worker entry.
- [ ] Spot VMs ride the priority flag, and eviction reads as T5 worker loss.

**You see.**

- [ ] One command turns an Azure subscription into a listed worker.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/provision_azure.rs` gains CLI mocking, bootstrap shape, spot priority, and config cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe. Lanes 3 through 9 run against a real Azure subscription and are skipped with a recorded reason when no Azure credentials are set.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and head. Trunk lacks the provider, record that fact. Save `az-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Missing credentials. Save `az-no-creds.log`. Pass when the refusal names `az login` and no API call is made.
- [ ] Lane 3. Dry-run. Save `az-dry-run.log`. Pass when the plan names size, region, and bootstrap hash, and no VM exists after.
- [ ] Lane 4. Real provision. Save `az-provision.log`. Pass when the VM runs, the extension completes, and the cap probe succeeds.
- [ ] Lane 5. Spot priority. Provision with spot. Save `az-spot.log`. Pass when the VM carries the priority.
- [ ] Lane 6. Config append and pinning. Save `az-config.log`. Pass when the entry lands and re-runs skip re-pinning.
- [ ] Lane 7. End-to-end job. Save `az-e2e.log`. Pass when the closure builds with the Azure worker attributed.
- [ ] Lane 8. Eviction. Deallocate the VM mid-job. Save `az-eviction.log`. Pass when the run fails naming the worker.
- [ ] Lane 9. Region override. Provision in a second region. Save `az-region.log`. Pass when the worker lands in the named region.
- [ ] Lane 10. Destroy. Save `az-destroy.log`. Pass when the VM and its resource group entries are gone and the config entry removed.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Provision wall clock, create to cap probe, head only. Trunk lacks the provider, record that fact. The end state the user waits for is a usable worker.
- [ ] Probe. Time three fresh provisions, recording create, extension, cap phases.
- [ ] Baseline. Record the first run's phases first.
- [ ] Rule. Create to cap under 7 minutes on `Standard_D4s_v5`. Shuttle-side overhead under 15 seconds.

**Review gate.** The operator reviews before merge. T9 spends real money and adds a provider surface.

- [ ] Copy lane 3, 4, and 8 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 4. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Add the Scaleway provider (T10)

**Depends on.** T6.

**Files.**

- [ ] Create `src/provision/scaleway.rs` driving the `scw` CLI through `CommandRunner`, server create with `user_data` cloud-init.
- [ ] Create `tests/provision_scaleway.rs`.

**Build.**

- [ ] `shuttle workers provision --provider scaleway --type GP1-S --zone fr-par-1 --count 1` creates the server with the cloud-init template, pins the host key, and appends the worker entry.

**You see.**

- [ ] One command turns a Scaleway project into a listed worker.

**Verify, unit.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] `tests/provision_scaleway.rs` gains CLI mocking, user-data shape, and config cases. Run `env -u LD_LIBRARY_PATH devbox run -- test`.

**Verify, live.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked. Ten lanes on `grok-4.6-fast-xhigh` at the PR head, per the boot recipe. Lanes 3 through 9 run against a real Scaleway project and are skipped with a recorded reason when no Scaleway credentials are set.

- [ ] Lane 1. Regression lane against trunk. Run the htop closure at trunk and head. Trunk lacks the provider, record that fact. Save `scw-parity.log`. Pass when artifacts and output equal trunk.
- [ ] Lane 2. Missing credentials. Save `scw-no-creds.log`. Pass when the refusal names the credential chain and no API call is made.
- [ ] Lane 3. Dry-run. Save `scw-dry-run.log`. Pass when the plan names type, zone, and user-data hash, and no server exists after.
- [ ] Lane 4. Real provision. Save `scw-provision.log`. Pass when the server runs, cloud-init completes, and the cap probe succeeds.
- [ ] Lane 5. User-data landed. SSH to the server and read the cloud-init record. Save `scw-userdata.log`. Pass when the template ran to completion.
- [ ] Lane 6. Config append and pinning. Save `scw-config.log`. Pass when the entry lands and re-runs skip re-pinning.
- [ ] Lane 7. End-to-end job. Save `scw-e2e.log`. Pass when the closure builds with the Scaleway worker attributed.
- [ ] Lane 8. Server loss. Terminate the server mid-job. Save `scw-loss.log`. Pass when the run fails naming the worker.
- [ ] Lane 9. Zone override. Provision in a second zone. Save `scw-zone.log`. Pass when the worker lands in the named zone.
- [ ] Lane 10. Destroy. Save `scw-destroy.log`. Pass when the server is deleted and the config entry removed.

**Verify, perf.** Tests alone are not sufficient verification. A PR is verified only when its unit, live, and perf boxes are all checked.

- [ ] Metric. Provision wall clock, create to cap probe, head only. Trunk lacks the provider, record that fact. The end state the user waits for is a usable worker.
- [ ] Probe. Time three fresh provisions, recording create, cloud-init, cap phases.
- [ ] Baseline. Record the first run's phases first.
- [ ] Rule. Create to cap under 5 minutes on `GP1-S`. Shuttle-side overhead under 15 seconds.

**Review gate.** The operator reviews before merge. T10 spends real money and adds a provider surface.

- [ ] Copy lane 3, 4, and 8 logs into the PR description as terminal screenshots.
- [ ] Record a 30 to 60 second terminal video of lane 4. Save it as the review artifact named in the PR.
- [ ] Post the screenshots and the video in chat. Stop at merge-ready. Wait for the operator's click.

**Merge.**

- [ ] Root's clean verdict at the exact head SHA.
- [ ] Bugbot triage done.
- [ ] Rebased onto current trunk after the verdict, patch-id unchanged.
- [ ] Owner squash-merges after the operator's click.

## Close the program

- [ ] Every box above is checked with its evidence.
- [ ] Appendix D lists every ticket issue number and every merged PR.
- [ ] ADR-0040 moves from Proposed to Accepted with the operator's grill on record.
- [ ] Reply to the operator with the report the execution playbook names.

## Appendix A. Prototype evidence

No prototype was run in the planning session. The design settled on ADR analysis and prior-art research, and these questions stay unproven until the named live gates run. Tar-over-SSH throughput for large closures, first measured at T4 lane 3 and the T4 perf block. Loopback SSHD availability on the operator's machines, assumed by every loopback lane, first checked at T3 lane 2, with the second-machine lane recording the fact when absent. Cloud-init shuttle install time on each provider, first measured at T6 lane 4 and T7 through T10 lane 4. Cap probe latency on a cold machine, first measured at T3 lane 2 and the T3 perf block. If T4 lane 3 shows delta sync moving over 10 percent of closure bytes on shared closures, revisit the coordinator-ships-sources decision before T5 merges.

## Appendix B. Alternatives rejected

The full ledger lives in ADR-0040's Alternatives section. The short list. Worker daemon with an HTTP job API, rejected for the daemon law and the NAT direction. REAPI with Buildbarn or NativeLink, rejected for monolithic job granularity and an FSL license GPL cannot take. gRPC or NATS, rejected for dependency trees and an always-on server. Coordinator-embedded HTTP serve, rejected for the reachability inversion. Worker-side fetch, rejected for v1 to keep workers air-gap-eligible. Rust cloud SDKs, rejected for v1 in favor of provider CLIs behind `CommandRunner`. The config names `farm` and `builders`, rejected because `farm` is the pod bin farm and `builder` is the build-script plugin kind.

## Appendix C. Risks

- One flaky worker fails the whole run. Lands in T5. The owner watches the stop-the-world lanes and the operator decides if strict is too strict after living with it. The escape hatch is removing the worker from config, not silent retries.
- Provisioned cloud VMs leak when a run dies mid-provision. Lands in T6 and every provider ticket. The TTL marker file and the destroy verb are the leash. The owner watches lane 10 of each provider.
- Host-key pinning friction on first use. Lands in T6. The printed-key flow is the operator's explicit-trust act. The owner watches lane 5.
- Protocol drift between coordinator and worker versions. Lands in T3 and T4. The constant plus preflight refusal is the guard. The owner watches lane 8 of T3.
- Large source tarballs over slow links make coordinator-ships-sources painful. Surfaces at T4 lane 3 and the T4 perf block. The recorded answer is the fetch-at-worker revisit trigger, not a v1 mode.
- hcloud, aws, gcloud, az, and scw CLI drift. Lands in T6 through T10. Each provider module wraps one CLI, so drift is one module's fix. The owners watch the dry-run lanes.
- Scheduler pool sizing multiplies RAM and IO pressure per machine. Lands in T2. The ADR-0022 sizing caveat stays documented next to the config-driven budget.

## Appendix D. Links and reading list

- Design doc. `docs/adr/0040-distributed-build-workers.md`.
- Read before editing. ADR-0022 and its addendum, ADR-0033, ADR-0039, ADR-0011 Decision 5, ADR-0029, `docs/agents/build-and-test.md`, `docs/agents/git-workflow.md`.
- Execution playbook. `~/.agents/skills/poteto-mode/playbooks/orchestrate.md`.
- Prior-art notes. Nix distributed builds and the `builders` grammar, the REAPI scope note, cargo-remote and nixbuild.net SSH posture, per-provider provisioning references, all cited in ADR-0040's Evidence section.
- Ticket issues. T0 is #188 (ready-for-human, ADR ratification). T1 is #189. T2 is #190. T3 is #191. T4 is #192. T5 is #193. T6 is #194. T7 is #195. T8 is #196. T9 is #197. T10 is #198.
