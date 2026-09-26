# ADR-0038: Pod isolation — whole-pod execution boundaries

Status: Draft. Council-reviewed 2026-09-22 (two-seat consensus; both seats
accepted with changes, all applied below).

## Context

A pod's environment is currently the host. `shuttle run --` executes
arbitrary commands directly (`src/confine.rs` `run_command`, fail-open by
design), unconfined apps exec directly, and ADR-0032 services run as host
systemd user units. Per-app confinement (`src/confine.rs`, fail-closed)
wraps one declared app at a time and cannot bound the environment as a
whole. The missing piece is one boundary around every process of a pod —
for environments that run agents or other code with broad permissions,
and for sideloaded payloads whose trust is only as good as their pins
(ADR-0037).

`.planning/research/sandboxing-levels.md` (2026-09-05) named the per-app
runtime levels; this ADR defines the pod-level axis.
`.planning/research/pod-isolation-backends.md` (2026-09-22) compared the
backend candidates. The field: namespace-class boundaries (bubblewrap,
OCI runtimes, nspawn) are cheap and compatible but share the host kernel;
VM-class boundaries (libkrun/smolvm, Firecracker, QEMU, crun's krun
handler) give each workload its own guest kernel but need `/dev/kvm` and
a young toolchain. Constraints that eliminate candidates outright: no
privileged daemon ever (ADR-0011 law), systemd-less hosts must work
(ADR-0032), user-level only (project context).

## Decision

Pod isolation: a pod-scoped declaration selecting the boundary every
process of the pod runs inside. Three levels, opt-in, default `host`.
The per-app levels (`unconfined`/`confined`, ADR-0016) and the pod levels
here are different axes with different vocabularies, on purpose: one
wraps a single declared app, the other wraps the whole environment.

The `sandbox` level name overlaps the glossary's flagged "sandbox"
ambiguity. It is kept because the value only ever appears as
`isolation = "sandbox"` next to the axis name, and docs always name the
level; the glossary entry carries the disambiguation rule.

- **`host`** — today's behavior, unchanged. Direct exec, host services.
- **`sandbox`** — one bubblewrap profile around every pod exec form:
  farm read-only, the pod's own store bound read-write (shells and pod
  mutations write there), host surface beyond it scoped to declared
  grants, the project
  working directory bound read-write (workspace-in is the point of a dev
  environment; the dev-container convention mounts the workspace too),
  `$HOME` **not** bound (filesystem grants restore access), private
  `/tmp`, `/proc`, `/dev`, PID/IPC unshared, `--new-session` mandatory
  (CVE-2017-5226 TIOCSTI), network denied unless granted. Fail-closed:
  missing `bwrap` or a disabled unprivileged userns is an error, same
  posture as per-app confinement — never the build sandbox's
  warn-and-degrade.
- **`machine`** — a microVM per exec form through the smolvm CLI (libkrun
  underneath): own guest kernel, hardware boundary. The pod farm and
  store mount through virtiofs, so a generation flip is visible to the
  next exec without guest restart. Network off by default. Fail-closed
  without rw `/dev/kvm` (probed as `src/boot_test.rs` already probes for
  image boot tests). v1 scope: `run` and shell forms only, machines are
  ephemeral — see contract 5.

Declared in `pod.lua` as `isolation = "<level>"` plus an isolation-scoped
network knob: `network = true` for full access, or `allow_hosts = [...]`
(machine only, mutually exclusive with `network = true`). The `sandbox`
level rejects `allow_hosts` at sync with a named error — bwrap has no
per-host mechanism, and shipping a proxy is out of scope. Filesystem,
socket, and device grants keep the shared grants vocabulary at pod scope.
The level and knobs are recorded in the lockfile and generation like
ADR-0030 env, so rollback restores the boundary too.

**Default stays `host`.** Both research docs converge on why:
deny-by-default plus fail-closed bricks existing dev pods (dev CLIs need
network, HOME, sockets), and no mainstream dev-env tool ships a
default-on boundary. Flipping pods to `sandbox` by default is a named
future decision, deliberately not settled here; nothing in the contract
forecloses it once grants ergonomics are proven.

Rejected alternatives, with reasons:

- **systemd-nspawn** — systemd-coupled; ADR-0032 requires systemd-less
  hosts to work.
- **youki / crun / libcontainer** — same isolation class as bubblewrap
  (shared kernel) with OCI rootfs assembly and cgroup delegation to own.
- **crun's krun handler** — VM-class (OCI runtime over libkrun), so it
  competes with smolvm directly; rejected on the same grounds as DIY
  OCI plumbing: rootfs assembly and runtime surface to own for no
  boundary gain over the smolvm CLI.
- **Direct libkrun embedding (`krun-sys`)** — more control, but libkrun
  2.0 `main` is ABI-unstable and no safe wrapper is maintained upstream;
  the CLI subprocess delivers the boundary now. Revisit when libkrun
  stabilizes.
- **Firecracker** — root-assisted TAP/NAT networking and a cloud-jailer
  model; wrong host.
- **gVisor/runsc** — the only KVM-free kernel-boundary option, so it
  would dodge the machine level's biggest weakness; rejected for v1
  because it drags in OCI-bundle plumbing and a runtime surface to own.
  Revisit if KVM absence blocks real adoption.
- **QEMU / crosvm / Cloud Hypervisor / microsandbox** — heavyweight,
  slow boots or the same class as the above; the constraint filter
  removes them (details in the research doc).

## Design contract

1. **Fail-closed at both new levels.** A capability gap (no `bwrap`, no
   userns, no `smolvm`, no `/dev/kvm`) blocks exec with a doctor-pointed
   error. Only `host` degrades, and only the way it does today.
2. **One grants vocabulary — after fixing its broken legs.**
   Pod-scoped filesystem grants reuse the package confinement keys.
   The sockets and devices legs of the existing per-app bwrap backend are
   **defective today**: `src/confine.rs` `bind_sockets`/`bind_devices`
   emit `--socket`/`--device`, which bubblewrap does not have (confirmed
   against the bwrap.1 option list). Devices must map to `--dev-bind`;
   sockets must map to explicit bind mounts of the granted socket paths.
   That fix is a prerequisite for this ADR's grants reuse; until it
   lands, pod `sandbox` rejects socket/device grants with a named error
   instead of emitting a broken argv. Socket grants are documented
   escalation paths (a bind-mounted D-Bus socket is host access) and the
   docs say so. Per-app `confinement` declarations compose inside the pod
   boundary at `sandbox` level. At `machine` level the VM is the only
   boundary in v1: per-app confinement inside a machine pod is rejected
   at sync (fail-closed, explicit) rather than half-honored.
   `PATH` and `LD_LIBRARY_PATH` stay computed seams (ADR-0030).
3. **Env is deny-by-default at isolated levels.** `env_clear()` plus the
   shellenv overlay plus explicitly re-injected process env. This is an
   intentional carve-out from ADR-0030's declared-replaces-inherited
   rule, which governs the `host` level: ambient inherited variables
   (tokens, sockets, proxies) are exactly what the boundary exists to
   contain. The man page states the difference.
4. **Services honor the level where the machinery exists.** `sandbox`
   pods emit ADR-0032 units whose `ExecStart` is the sandbox profile:
   `--die-with-parent` so the unit's main PID is the real service (bwrap
   does not forward signals), env re-injection after `env_clear` so the
   unit's own `Environment=` survives, and a sync-time validation error
   for `Type=notify` services without the network grant (the notify
   socket is an abstract unix socket and dies with `--unshare-net`).
   Declared, never verb-managed (ADR-0032 stands).
5. **Machine v1 is ephemeral run/shell only.** Services inside machine
   pods need the ADR-0032 portable packaged-supervisor backend, which is
   not implemented (`services.rs` bails on `portable` today); persistent
   machines, sync-tail lifecycle, and rollback semantics for a running
   guest are all deferred with it. This avoids inventing a VM supervisor
   under the no-daemon law as a side effect. Sync rejects
   `isolation = "machine"` on pods that declare services (the dependency
   named in the error) or that would launch unconfined apps — v1 machine
   covers run and shell forms only, and an app launch outside the
   boundary is a sync-time error, never silent host exec.
6. **The machine level wraps the VMM.** libkrun's own security model
   treats guest and VMM as one entity and warns that virtio-fs exposes
   mounted trees to the VMM process; the smolvm invocation therefore
   runs inside a bwrap jacket matching the sandbox profile with exactly
   two deltas: `/dev/kvm` is dev-bound read-write (a private `/dev`
   hides the device and no VM starts), and network is granted whenever
   the pod sets `network` or `allow_hosts` — the VMM proxies guest
   egress, and per-host filtering stays smolvm's job.
7. **Ephemeral shells inherit the boundary.** ADR-0036 §5 said `shell`
   "never sandboxes (fail-open)". That line is amended: `shell` inherits
   the pod's isolation level; in a `host` pod it stays fail-open as
   specified there. The throwaway farm and session root (ADR-0036
   contract 2) resolve inside the boundary like any other exec form —
   at `machine` level through the same virtiofs mount.
8. **Tooling follows the RuntimeTools pattern — with a real pin.** The
   smolvm binary is the trust root of the machine level and ships
   unsigned releases, so "whatever is on PATH" is not enough. Preferred
   path: distribute smolvm as a shuttle package through the signed
   store, so ADR-0037 pins cover the boundary tool itself. Until that
   package exists, doctor verifies the resolved `smolvm` against a
   committed pin (version + SHA-256) and fails closed on mismatch.
   Resolution keeps the standard seams: PATH scan, `SHUTTLE_SMOLVM`
   override, doctor checks per level (bwrap, userns, smolvm, KVM).
9. **Trust boundaries stay honest.** Sideload pin verification (ADR-0037)
   remains a host-side gate before anything enters a boundary; moving
   payload unpack inside the machine level is future work, noted so the
   question stops recurring.

## Consequences

**Positive**

- A real boundary exists for environments running agents or untrusted
  payloads, without dev-container bolt-ons or hand-rolled firewalling.
- No new daemon, no systemd requirement, no root: `sandbox` needs only
  bwrap; `machine` needs only smolvm and KVM access.
- The grants vocabulary stays singular — once its socket/device legs are
  repaired, the same vocabulary drives per-app confinement and pod
  isolation.
- Rollback restores the boundary; the lockfile tells the truth about
  what ran.

**Negative**

- The `sandbox` level shares the host kernel: kernel exploits stay in
  scope, and per-host network policy is impossible there. Documented,
  not fixed.
- The `machine` level inherits smolvm's youth: unsigned releases, a
  moving CLI, and a hard `/dev/kvm` dependency that nested or
  locked-down hosts lack. Contract 8's pin turns "moving" into
  "deliberate"; doctor makes the KVM gap visible before exec.
- **No TCG escape for machine-level CI.** libkrun has no
  software-virtualization fallback on Linux; image boot tests get away
  with a TCG path because they run QEMU, but machine-level e2e is
  KVM-or-skip. The gate skips cleanly (the `bwrap_gate` pattern) so CI
  without KVM stays green while testing less.
- The machine level owns a guest rootfs assembly path — new surface to
  maintain.
- Startup cost: bwrap jacket plus VM boot per `machine` exec form;
  smolvm claims <200 ms boots, which the e2e gate must confirm on real
  hardware.

## References

- `.planning/research/pod-isolation-backends.md` (2026-09-22 backend
  comparison; smolvm, libkrun, bubblewrap primary sources)
- `.planning/research/sandboxing-levels.md` (2026-09-05 per-app levels)
- ADR-0015 (pods), ADR-0016 (confinement levels), ADR-0030 (declared env
  seams; contract 3 is the carve-out), ADR-0032 (services backends incl.
  portable supervisor — contract 5 dependency), ADR-0035 (privilege
  boundary), ADR-0036 (ephemeral shells; §5 amended by contract 7),
  ADR-0037 (sideload pins; contract 8 reuse)
- `src/confine.rs` (fail-closed bwrap posture, grants dispatch, the
  defective `--socket`/`--device` legs), `src/snap.rs`
  `Confinement`/`run_bwrapped`, `src/services.rs` (portable backend
  bail-out), `src/runtime.rs` (RuntimeTools pattern), `src/boot_test.rs`
  (`kvm_available()` probe)
- Upstream: https://github.com/smol-machines/smolvm,
  https://github.com/containers/libkrun,
  https://github.com/containers/bubblewrap
