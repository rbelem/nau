# ADR-0056: Per-machine CPU limits for build children

## Status

Accepted (2026-10-19). The Worker path has not had a live-cgroup acceptance
run; see Revisit triggers.

## Context

`nau build` limits the number of local package slots, but each build child can
use all online CPUs. `make` and `mksquashfs` can therefore compete with other
work on the host. A slot limit does not impose a machine-wide CPU budget.

The limit is a percentage of the machine's online CPUs. On a 12-CPU host,
80 means 9.6 CPUs. In cgroup v2, that is `cpu.max` set to
`960000 100000`. A value of `80%` in systemd's `CPUQuota` instead means 0.8
CPU. The CLI must state the unit clearly.

Some supported hosts have no usable cgroup v2 delegation. Builds must keep
working there, with an explicit warning that they run uncapped. The mechanism
must not depend on systemd.

Moving the `nau` process into the limited cgroup would change
`std::thread::available_parallelism()`. The build code uses that value to
choose its default `MAKEFLAGS`. Keep `nau` outside the cgroup and place only
build children inside it.

## Decision

1. **Expose one CPU limit at the build boundary.** `nau build` and `nau image`
   accept `--resource-limit PERCENT|off`. `NAU_RESOURCE_LIMIT` supplies the
   value only when the flag is absent. The default is 80. A percentage must be
   an integer from 1 through 100. Invalid input names the flag or environment
   variable that supplied it. The CLI flag wins over the environment.

2. **Define the percentage against all online CPUs.** For percentage `p`,
   online CPU count `n`, and the fixed 100,000-microsecond period, the governor
   writes `p * n * 100000 / 100` as the quota. At 80 on 12 CPUs, the file reads
   `960000 100000`. At 100, it reads `1200000 100000`, not `max`. The exact
   quota can shave the end of a CPU period. `off` is the uncapped value.

3. **Share one `nau-build` cgroup per user.** Every limited build child joins
   the same cgroup, including children from concurrent `nau` processes. Each
   process records one claim with its PID, process start time, and percentage.
   The effective percentage is the minimum live claim. A lock serializes stale
   claim cleanup and writes to `cpu.max`; individual claim files remain
   separate. A PID whose process has exited or whose start time changed is
   stale. The governor creates `nau-build` beneath the highest ancestor with
   `cpu` already enabled and write access, so separate user sessions share the
   same cgroup. Claim files live under `/run/user/<uid>/nau/governors`, or
   `/run/nau/governors` as root. If the user runtime directory is absent, the
   governor uses `/tmp/nau-governors-<uid>`. It never changes
   `cgroup.subtree_control`.

4. **Join children before they execute.** `governor::spawn`,
   `governor::status`, and `governor::output` put the child in `nau-build` from
   `pre_exec`. This covers the sandbox process and host tools such as
   `mksquashfs`. The wrappers auto-configure the default when no caller has
   configured a limit. A Worker ignores `NAU_RESOURCE_LIMIT` and uses the
   value from its job manifest. `RealRunner` joins an already configured
   cgroup but does not configure one, so `nau doctor` remains uncapped.

5. **Clamp only the computed default `MAKEFLAGS`.** The default job count is
   the smaller of `available_parallelism()` and the floor of quota divided by
   period, with a minimum of one. The governor never increases the requested
   job count. A recipe's explicit `MAKEFLAGS` still wins. Recipes that hardcode
   `-j$(nproc)` keep that count and rely on cgroup throttling.

6. **Carry the limit to Workers without changing job identity.** The
   coordinator resolves the limit and writes it to `JobManifest.resource_limit`.
   The field defaults to 80 and is removed from canonical manifest bytes, so
   the execution setting does not change the job identity. A new Worker applies
   the limit to its own CPUs. An old Worker ignores the field and runs
   uncapped. The coordinator does not send a limit with `build-request submit`;
   the machine that runs the job selects it.

7. **Degrade to uncapped builds when enforcement is unavailable.** Missing
   cgroup v2, a missing CPU controller, an unwritable parent, or an unknown
   online CPU count produces a typed reason and a warning. The build continues.
   `nau doctor` reports cgroup placement availability. The build checks claim
   creation and `cpu.max` writes before its first spawn. Worker results carry an
   optional degradation reason. The governor does not move unrelated processes.
   It does not kill orphaned build processes on drop.

8. **Limit CPU only.** The governor does not set memory or I/O limits. Claims
   are per user, so separate user accounts do not share one machine-wide cap.
   An `off` build does not join a capped peer's cgroup and can raise total CPU
   use above the requested limit.

## Alternatives considered

- **Move the `nau` process into the cgroup.** Rejected because cgroup-aware
  `available_parallelism()` changes the default job count. The design
  investigation measured 12 CPUs outside a quota, 2 under a 200% quota, and 9
  under a 960% quota.
- **Use systemd `CPUQuota`.** Rejected because the limit must work without
  systemd and its percentage is easy to confuse with a percentage of the whole
  machine.
- **Change only `MAKEFLAGS`.** Rejected because `mksquashfs`, recipe commands,
  and other child processes do not all honor that variable.
- **Create one cgroup per invocation.** Rejected because concurrent
  invocations could each use the full percentage and exceed the machine
  budget.

## Consequences

**Positive.** Build children on each machine share a measurable CPU cap.
Workers apply the same percentage to their own CPUs. Operators can set the
percentage on the CLI or through one environment variable. Hosts without
usable cgroup v2 still build and report why the cap did not apply.

**Negative.** A limit of 100 still uses an exact quota and can make CFS
throttle work near each period boundary. Hardcoded parallel-job counts remain
throttled instead of shrinking. The governor cannot prevent memory pressure,
share across user accounts, or contain a concurrent `off` build.

## Revisit triggers

- Probe a real Worker with `nau __worker-job` and verify that its build child
  joins the local `nau-build` cgroup.
- Add `NAU_BUILD_JOBS` to the build sandbox and update recipes that use
  `-j$(nproc)` if users need those commands to shrink with the quota.
- Add the effective limit to `CapabilityDoc` if coordinators need to inspect
  Worker enforcement before dispatch.
- Reopen cross-user sharing only with an administrator-controlled delegation
  design.

## Evidence

The acceptance probe uses a dedicated fixture with 12 deterministic 32-MiB
files and zstd level 22. A single staged file and a 12-file set at the default
compression level did not produce throttling on the 12-CPU host. Level 15
throttled once, then produced no throttling on a repeat. Level 22 produced
`cpu.max` `960000 100000`; `nr_throttled` increased from 0 to 67, and
`throttled_usec` increased from 0 to 3878140. The default-on and `off` builds
both exited 0 and produced byte-identical snaps with SHA-256
`dbff5b69a3c1e3b6eec416e1bad5b09d5ef7ea3e331ef044b5b2ae90aa58e1e2`.

The pure limit tests and live cgroup tests cover parsing, quota math, child
membership, claim reconciliation, stale-claim recovery, and the process-call
lint. `tests/resource_governor.rs` also asserts that image packing uses the
`CommandRunner` seam.

## References

- [ADR-0005](0005-mksquashfs-subprocess.md) records the `mksquashfs`
  subprocess boundary.
- [ADR-0022](0022-build-execution-model.md) records package and build-slot
  execution.
- [ADR-0032](0032-pod-services-declarative-units.md) records hosts without a
  systemd user manager.
- [ADR-0040](0040-distributed-build-workers.md) records Worker job manifests
  and local execution.
- `crates/nau-core/src/resource_limit.rs` defines the typed limit and quota.
- `crates/nau-infra/src/governor/` implements claims, cgroups, and process
  placement.
- `scripts/resource-governor-probe.sh` verifies live throttling and snap
  byte identity.
