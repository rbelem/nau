# Pod Isolation Backends — Primary-Source Research

> **Purpose**: feed ADR-0038, which defines whole-pod execution isolation
> (every process of a pod — `run` forms, services, shells — inside one
> boundary). Companion to `sandboxing-levels.md` (2026-09-05), which named the
> per-app runtime confinement levels. This doc covers the pod-level axis and
> the backend candidates for it.
> **Date**: 2026-09-22
> **Method**: direct primary-source inspection (upstream READMEs, man pages,
> docs) via the librarian lane, plus shuttle's own confinement code.

## Where this axis sits

Shuttle has two named isolation axes already (CONTEXT.md flagged
ambiguities): the **build sandbox** (compile-time, bubblewrap,
`src/snap.rs` `run_bwrapped`, fail-open) and **confinement** (per-app
runtime wrapping, `src/confine.rs`, fail-closed, grants vocabulary).

A third axis is missing. Today a pod's environment is the host: `shuttle
run --` executes arbitrary commands directly (`src/confine.rs`
`run_command`, fail-open by design), services run as host systemd user
units (`src/services.rs`), and ADR-0036 shells are specified unsandboxed.
The demand signal: environments that run agents or other code with broad
permissions want one boundary around the *whole* environment — not
per-app wrapping, not hand-rolled firewall scripts, and not a bolted-on
container workflow. Per-app confinement cannot provide that; it wraps one
declared app at a time and shares the host kernel regardless.

## Comparison table (pod-level backends)

| Option | Mechanism | Privileges | Network policy | FS sharing | Embeddability | Latency | License | Fit verdict |
|---|---|---|---|---|---|---|---|---|
| bubblewrap (whole-pod profile) | namespaces + optional seccomp, shared kernel | rootless (user ns; setuid mode removed) | `--unshare-net` = loopback only; no per-host allowlist | CLI bind mounts, tmpfs root | CLI subprocess | ~10–100 ms | LGPL-2.1+ | Strong default; weakest boundary |
| youki / crun / libcontainer | namespaces + cgroups + seccomp | rootless via user ns | net ns only; networking external to runtime | OCI rootfs assembly required | youki: Rust (`libcontainer` crate); crun: C lib | 47–112 ms | Apache-2.0 / GPL-2.0 | Rejected: same isolation class as bwrap, more surface |
| systemd-nspawn | namespaces, optional seccomp | root by default; `--private-users` exists but uncommon | `--private-network`, `--port=` | binds, `--volatile`, overlay | CLI + D-Bus (`machinectl`) | sub-second | LGPL-2.1+ | Rejected: systemd-coupled (ADR-0032 requires systemd-less hosts) |
| smolvm (libkrun) | microVM per workload, own guest kernel | rootless; needs rw `/dev/kvm` | **off by default**; `--allow-host` egress allowlist; ≤64 ports | virtiofs directory mounts | CLI subprocess + containerd shim; no library API | <200 ms claimed | Apache-2.0 | Strong "machine" level; new external dep |
| libkrun direct (via `krun-sys`) | same VM, C API | same | TSI or passt/gvproxy — policy is caller's job | virtiofs/blk via API calls | C ABI dylib; safe wrapper is our job | sub-second | Apache-2.0 | Deferred: more control, more work; libkrun 2.0 `main` is ABI-unstable |
| Firecracker | KVM microVM + jailer | rw `/dev/kvm`; jailer | TAP + iptables NAT = root-side setup | ext4 images, no virtiofs | REST over unix socket | <125 ms | Apache-2.0 | Rejected: cloud-host design, root-assisted networking |
| QEMU / crosvm | full-system VMM | KVM or TCG | slirp/tap | virtiofs/9p | CLI/QMP | 15–30 s (QEMU) | GPL-2.0 / BSD | Rejected: heavyweight, slow, large device surface |

## Backend detail that constrains the design

### bubblewrap — the always-available level

Entirely unprivileged user namespaces; a private tmpfs root invisible
from the host; PID/IPC/UTS/net unshares are caller-chosen; `--unshare-net`
leaves only loopback. Seccomp is caller-supplied. What it cannot do:
per-host network allowlists, and any kernel-hardening at all — sandboxed
processes share the host kernel. Known traps: `TIOCSTI` needs
`--new-session` or seccomp (CVE-2017-5226); any bind-mounted socket (e.g.
D-Bus) is an escalation path unless filtered (xdg-dbus-proxy);
`PR_SET_NO_NEW_PRIVS` is always set. The security model is owned by
whoever builds the argv — which for shuttle is `src/confine.rs` already.
(https://raw.githubusercontent.com/containers/bubblewrap/main/README.md)

Shuttle already has a fail-closed bwrap runner honoring the grants
vocabulary (`run_bwrap`, userns probe, backend_options passthrough) and a
fail-open build runner (`run_bwrapped` → `run_direct` warn-and-degrade).
A pod-level `sandbox` profile reuses the first shape, scaled to the pod.

### smolvm — the microVM level

CLI over libkrun + a smol-machines libkrunfw fork; Linux x86_64/aarch64
requires `/dev/kvm`; also macOS/Windows. Smolfile (TOML) declares image,
net, cpus, memory, ports, volumes, env, init, user, `[network]`
allow_hosts, `[auth]` ssh_agent; unknown keys rejected. Networking is
disabled by default; `--allow-host` enforce egress allowlists (README
demonstrates a blocked `google.com` next to an allowed host).
`machine run` is ephemeral and cleaned up on exit; `create/start/stop/exec`
is persistent; `branch` forks a running machine copy-on-write;
`checkpoint`/`pack` produce portable artifacts (OCI registries for packs).
Images are OCI — including `docker save`/`podman save` archives or a bare
rootfs directory, no daemon. No documented library API: a Rust host drives
it as a subprocess (`smolvm machine run …`), plus a `smolvm-checkpoint`
crate and a containerd shim. Security model: VMM runs as the invoking
user; `--volume` paths are deliberately exposed; `/etc` and `/var/log`
blocked by default; releases carry SHA-256 checksums but are not signed.
(https://raw.githubusercontent.com/smol-machines/smolvm/main/README.md)

### libkrun — what smolvm is made of, and what it costs

A VMM library (Rust, C ABI) giving each workload its own guest kernel via
KVM (HVF on macOS). Rootless but requires rw `/dev/kvm`; **no TCG
fallback on Linux**. Two mutually exclusive network backends: vsock+TSI
(proxy through the VMM) or virtio-net via passt/gvproxy; deny-by-default
is "add no network interface", allowlisting lives in the proxy layer.
libkrun's own security model: treat guest and VMM as one entity; virtio-fs
exposes mounted trees to the VMM process, so a real sandbox is the VM
*plus* a namespace jacket around the VMM. Variants: generic, `libkrun-sev`
(AMD SEV), `libkrun-tdx` (Intel TDX). `main` is 2.0 and ABI-breaking;
production tracks `stable-*`. From Rust: `krun-sys` raw FFI; no safe
wrapper maintained upstream. (https://raw.githubusercontent.com/containers/libkrun/main/README.md)

The jacket requirement composes with what shuttle already runs: the
machine level can wrap the smolvm invocation in the same bwrap profile
the sandbox level uses. Defense in depth without new machinery.

## Precedent (what other tools chose)

- **Nix**: namespace sandbox for builds only (`sandbox = true` default on
  Linux, declared `sandbox-paths`, no new privileges); runtime is direct
  exec from the store. Build-time hermeticity, zero runtime isolation.
  (https://nix.dev/manual/nix/2.28/command-ref/conf-file.html)
- **Devbox**: inherits the Nix sandbox for builds; shells unsandboxed.
  (https://www.jetify.com/devbox/docs/)
- **Toolbx / Distrobox**: Podman containers that deliberately de-isolate —
  home, Wayland/X11 sockets, network, D-Bus shared; "no promise about
  security beyond the usual command line environment". Convenience for
  immutable distros, not isolation.
  (https://raw.githubusercontent.com/containers/toolbox/main/README.md)
- **Dev Containers**: Docker/Podman via `devcontainer.json`; borrows the
  OCI ecosystem, shared-kernel boundary, daemon required.
  (https://containers.dev/)
- **Flatpak**: bubblewrap + seccomp + portals (mediated grants) +
  xdg-dbus-proxy. The closest shipped precedent to "bwrap + policy layer".
  (https://docs.flatpak.org/en/latest/sandboxing.html)
- **Kata Containers**: VM-per-container via containerd RuntimeClass — the
  integration point smolvm's shim also targets.

Pattern across precedents: namespace-class boundaries win on cost and
compatibility and lose on kernel attack surface; VM-class boundaries win
on isolation and pay in KVM availability, a bundled guest kernel, and a
young toolchain. No mainstream dev-env tool ships a default-on VM
boundary; all treat it as opt-in.

## Constraints inherited from shuttle

- User-level only; no privileged daemon ever (ADR-0011 law, ADR-0035).
- Must work on systemd-less hosts (WSL2, Devuan, antiX, Slackware —
  ADR-0032), so nspawn-class and cgroup-manager-dependent designs are out.
- Grants are the shared vocabulary any backend honors (CONTEXT.md); a new
  backend must consume the same vocabulary, not invent a second one.
- RuntimeTools pattern for external tools: PATH resolution, doctor check,
  fail-closed or degrade-with-warning by precedent, `SHUTTLE_*` opt-out
  seam (`src/runtime.rs`).
- KVM capability probing already exists for image boot tests
  (`src/boot_test.rs` `kvm_available()`); the same probe gates the machine
  level.
- Sideloaded snap payloads are untrusted (ADR-0037 pins); the boundary
  must not weaken pin/trust gates — ideally it contains them.

## Open questions for the grill / council

1. Names for the three levels (`host` / `sandbox` / `machine`?) — must not
   collide with the flagged "sandbox" ambiguity.
2. Default level: keep `host` as default and make isolation opt-in, or
   flip pods to `sandbox` by default once it exists?
3. Network posture at isolated levels: deny-by-default with pod-scoped
   allowlists (mirrors smolvm, diverges from today's unconfined default)?
4. Does the machine level wrap the VMM in a bwrap jacket (libkrun's own
   guidance says yes)?
5. smolvm is young and unsigned-release; do we pin via doctor +
   vendoring policy, or keep it strictly optional forever?

## Sources

- bubblewrap README (user ns only, setuid removed, `--unshare-net`,
  TIOCSTI CVE, NNP, security-model ownership).
  https://raw.githubusercontent.com/containers/bubblewrap/main/README.md
- smolvm README (KVM requirement, Smolfile schema, deny-by-default net +
  allow_hosts, branch/checkpoint/pack, OCI images, security model).
  https://raw.githubusercontent.com/smol-machines/smolvm/main/README.md
- smolvm license. https://github.com/smol-machines/smolvm/blob/main/LICENSE
- libkrun README (C API, KVM/HVF, no TCG on Linux, TSI vs passt, virtiofs
  exposure, SEV/TDX variants, 2.0 ABI warning).
  https://raw.githubusercontent.com/containers/libkrun/main/README.md
- libkrunfw (bundled guest kernel). https://github.com/containers/libkrunfw
- krun-sys crate (Rust FFI). https://docs.rs/crate/krun-sys/latest
- youki README (rootless, kernel ≥5.3, 111 ms benchmark).
  https://raw.githubusercontent.com/youki-dev/youki/main/README.md
- crun README (C library use, krun handler).
  https://raw.githubusercontent.com/containers/crun/main/README.md
- systemd-nspawn man page (private-users, private-network, machinectl).
  https://www.freedesktop.org/software/systemd/man/latest/systemd-nspawn.html
- Firecracker getting-started (jailer, KVM, root TAP/NAT).
  https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/getting-started.md
- Nix manual (sandbox, sandbox-paths, allow-new-privileges).
  https://nix.dev/manual/nix/2.28/command-ref/conf-file.html
- Toolbx README (de-isolation stance).
  https://raw.githubusercontent.com/containers/toolbox/main/README.md
- Dev Containers spec. https://containers.dev/
- Flatpak sandboxing (bwrap + portals). https://docs.flatpak.org/en/latest/sandboxing.html
- xdg-dbus-proxy. https://github.com/flatpak/xdg-dbus-proxy
- KVM ENOMEM fix required by smolvm (commit 916b7f4).
  https://github.com/torvalds/linux/commit/916b7f42b3b3b539a71c204a9b49fdc4ca92cd82
- Shuttle internals: `src/confine.rs`, `src/snap.rs`, `src/services.rs`,
  `src/runtime.rs`, `src/boot_test.rs`, ADR-0015/0030/0032/0035/0036/0037,
  `.planning/research/sandboxing-levels.md`.
