# Devbox deprecation plan — gate on shuttle's own pod toolchain

Lane E1 deliverable. Goal: retire devbox+nix from this repo's dev/test gate
and CI. Endgame (per `docs/agents/build-and-test.md` "Devbox-free endgame"
and issue #102): the gate is explicit `shuttle run -- cargo …` commands
against a reconciled pod, and CI needs no nix at all.

Sources swept for this doc: `devbox.json`, `docs/agents/build-and-test.md`,
issue #102 (CLOSED — the arbitrary-command form), `src/cli.rs` (`Run` with
`trailing_var_arg`, ~line 556), `src/confine.rs:161` (`run_command` —
farm-first PATH + env overlay + transparent exec, verified real),
`install.sh` (`--skip-deps`, `SHUTTLE_SRC` override, rustup bootstrap),
`src/export.rs` (static-HTTP lane, ADR-0033 Decision 10), `src/pull_ref.rs`
/ `shuttle pull --pod` (signed-PackageManifest staging), CI (`.github/workflows/ci.yml`:
devbox-install-action on ubuntu-24.04), and a `Command::new` / tool-name
sweep over `src/` + `tests/`.

---

## 1. Tool inventory

What the devbox shell actually carries, what invokes each binary, and what
it would take to provide it without nix.

### 1a. Gate path — needed by `SHUTTLE_SYSTEMD=off cargo test` + clippy/fmt

| Binary | Who invokes it | Pool recipe? | Upstream prebuilt? | CI-buildable <2 min? |
| --- | --- | --- | --- | --- |
| `cargo`/`rustc`/`rustfmt`/`cargo-clippy` | The gate itself; via farm PATH under `shuttle run --` (confine.rs `resolve_command`) | ✅ `pkgs/r/rust.lua` (1.98.1 official dist tarball, FETCH) | ✅ static.rust-lang.org dist tarball (the recipe IS the prebuilt) | ✅ fetch+unpack+mksquashfs ≈2–3 min (borderline) |
| `cc`/`c++`/`ar` | `build.rs` (vendored Luau analyzer, 120 C++ TUs via `cc` crate); `src/snap.rs:12468+` cc probes for build_deps detection | ❌ (pool `gcc` exists but is a multi-hour source build — not for CI) | Host distro gcc/g++ (GH runners preinstall) | ✅ distro package, 0 min |
| `mksquashfs`/`unsquashfs` | `src/snap.rs:4243` (`mksquashfs` build step), `src/pod.rs:2245` store install, `src/runtime.rs` `RuntimeTools` (payload unpack), ~20 `tests/pod_*` | ❌ no `squashfs` recipe | Distro package; upstream source is small | ✅ `apt squashfs-tools`, seconds |
| `bwrap` | `src/snap.rs:5257` `run_bwrapped` hermetic build sandbox (**falls back to direct exec when absent**); `src/confine.rs:269` `run_bwrap` confined apps (**fails closed**); `tests/pod_confined.rs` `bwrap_gate()` (skips when absent) | ❌ no `bubblewrap` recipe | Distro package | ✅ `apt bubblewrap`, seconds |
| `curl` | recipe/dep fetch paths; `Command::new("curl")` ×5; test fixtures | ✅ `pkgs/c/curl.lua` | ✅ distro | ✅ preinstalled on runners |
| `tar` | source extraction (snap build path); most-invoked external binary in tests (×23) | ✅ `pkgs/t/tar.lua` | ✅ distro | ✅ preinstalled |
| `git` | git-source recipes (dep fetch), test helpers | ✅ `pkgs/g/git.lua` | ✅ distro | ✅ preinstalled |
| `python3` | interpreter-app wrapper tests (`tests/pod_wrapper.rs`, `tests/pod_deps.rs`); wrapper generation for python apps (`src/build_prefix.rs`) | ✅ `pkgs/p/python.lua` (python-build-standalone prebuilt) | ✅ | ✅ preinstalled |
| `patchelf` | `src/snap.rs:3871` `find_patchelf` — ELF interpreter/rpath repoint at pack time | ❌ | ✅ NixOS/patchelf GitHub releases ship static binaries | ✅ fetch prebuilt |
| `readelf` | `tests/pod_native_elf.rs`, `tests/pod_portable.rs` (ELF assertions) | ✅ via `pkgs/b/binutils.lua` (source build) | ✅ distro binutils | ✅ preinstalled |
| `unshare` | `src/confine.rs:514` `userns_available()` probe | n/a (util-linux) | ✅ distro | ✅ preinstalled |
| `which` | `src/snap.rs:5322` `detect_bwrap` + test helpers | n/a | ✅ distro | ✅ preinstalled |
| `sh` | shell-outs in plugin/build glue | n/a | ✅ | ✅ |

### 1b. Image / boot path — NOT in the gate (disk-image + try-boot verbs only)

These fail closed (with `shuttle doctor` hints) when absent; the gate never
touches them. They are why devbox carries qemu & co — the boot tests, not
`cargo test`.

| Binary | Who invokes it | Pool recipe? | Upstream prebuilt? | CI-buildable <2 min? |
| --- | --- | --- | --- | --- |
| `mcopy`/`mdir` (mtools) | `src/image/partition.rs`, `src/image/verity.rs`, `src/esp.rs`, `src/boot_test.rs` (ESP population) | ❌ | distro | ✅ `apt mtools` |
| `mkfs.vfat`/`mkfs.fat` | `src/image/partition.rs:1017` `which()` probe, `verity.rs` | ✅ `pkgs/d/dosfstools.lua` | distro | ✅ |
| `mkfs.ext4` | `src/image/staging.rs`, `partition.rs`, `verity.rs` | ✅ `pkgs/e/e2fsprogs.lua` | distro | ✅ |
| `parted` | `src/image/*` partition tables (×6 files) | ❌ | distro | ✅ `apt parted` |
| `sgdisk` | `src/image/verity.rs` (1 use) | ❌ | distro | ✅ `apt gdisk` |
| `ukify` | `src/image/boot.rs`, `src/image/mod.rs` UKI assembly (fail-closed preflight `src/image/mod.rs:1060`), `src/doctor.rs:218` | ❌ (no recipe exposes ukify) | systemd source ships it as a pure-python script, but the sd-stub EFI blob needs a systemd build | ❌ heavy |
| `veritysetup` | `src/image/verity.rs` + `image/mod.rs` dm-verity hashes (×8 files) | ❌ (rides `cryptsetup`) | distro | ✅ `apt cryptsetup` (binary), ❌ static source build |
| `cryptsetup` | `src/image/initramfs.rs`, `src/doctor.rs` (LUKS) | ❌ | distro | ⚠️ binary trivial; static musl build is fragile (the devbox static-pin breakage of ef63400 was exactly this family) |
| `busybox` | `src/image/staging.rs`, `image/initramfs.rs` (initramfs shell) | ❌ | ✅ static musl binaries from busybox.net | ✅ fetch prebuilt |
| `qemu-system-*` | `src/boot_test.rs` try-boot harness (`qemu_argv`, ~line 666) | ❌ | ⚠️ distro package (huge); static builds exist via third parties | ❌ apt install alone is ~500 MB, boot tests also need edk2 firmware |
| `systemctl`/`systemd-sysext`/`bootctl`/`loginctl` | `src/runtime.rs` `RuntimeTools` — **suppressed by `SHUTTLE_SYSTEMD=off`** (runtime.rs:445) | ✅ `pkgs/s/systemd.lua` (partially) | ✅ distro systemd | n/a (host provides) |
| `systemd-analyze` | `src/units.rs` unit verification (doctor path) | ❌ | ✅ distro | ✅ `apt systemd` (already on runners) |

### 1c. Lint/coverage lanes — in devbox, not in ci.yml

`ef63400` added these to the devbox shell for the CI *lanes* (manual agent
work), none wired into `.github/workflows/ci.yml`:

| Binary | Pool recipe? | Upstream prebuilt? | Migration path |
| --- | --- | --- | --- |
| `luacheck` | ❌ | via luarocks | pool `lua` + `luarocks` (both in pool) → `luarocks install luacheck`, or a wrapper recipe |
| `stylua` | ❌ | ✅ GitHub release (static rust binary) | fetch release; trivial recipe candidate |
| `cargo-llvm-cov` | ❌ | ✅ GitHub release (binstall-able) | fetch release |

---

## 2. Gap analysis

Devbox packages with **no pool recipe and no trivial on-runner story**, and
whether the gate actually needs them:

- **qemu** — no recipe, huge, needs edk2 firmware. Only `src/boot_test.rs`
  (try-boot) needs it; `SHUTTLE_SYSTEMD=off cargo test` never spawns it.
  Boot tests are a separate explicit verb, not the gate. **Not a blocker.**
- **bubblewrap / squashfs-tools / mtools / parted / gdisk / cryptsetup / ukify** —
  no recipes. bwrap + squashfs-tools are gate-relevant but are one
  `apt-get install` on any runner (seconds, distro packages — not nix).
  The image/boot set is out of the gate by design (fail-closed preflight,
  doctor reports it).
- **patchelf** — no recipe, but upstream ships a static release binary; a
  relayout recipe (the `libgcc.lua` Debian-prebuilt precedent) is ~15 lines.
- **bison/flex/autoconf/automake/gnumake** — in devbox but only consumed
  when *building pool recipes* that need them (build_deps preflight,
  `preflight_sandbox_tools`); the gate itself doesn't. Pool already has
  `autoconf`/`automake`/`make` recipes; bison/flex are recipe candidates,
  not gate blockers.
- **luacheck/stylua/cargo-llvm-cov** — no recipes; all three have prebuilt
  upstreams (see 1c). Migration is per-lane, post-gate.
- **glibc** — pool recipe is a **source build** (hours). This is the one
  hard constraint on P2: the gate pod cannot be built from recipes on a
  fresh runner, because `rust.lua` declares `requires = {glibc, libgcc}`.
  The pod content must arrive **prebuilt** (see P2 mechanism).

Net: **nothing blocks the gate.** Every gate binary is either distro-provided
(cc, tar, curl, git, python3, readelf, unshare), an apt one-liner
(mksquashfs/unsquashfs, bwrap), or the pool rust payload itself.

---

## 3. Phases

### P1 — local devbox-free gate

1. **Gate pod.** Create a dedicated pod holding the pinned toolchain:

   ```sh
   shuttle pod --name gate add rust
   shuttle pod --name gate sync
   ```

   The pool recipe (`pkgs/r/rust.lua`, official dist tarball) is the
   version pin; `shuttle.lock` in the pod root carries the resolved pin.
   Committed project declaration: check in `gate/pod.lua`
   (`pod { packages = { "rust" } }`) so the pod is reproducible; note the
   gap — **there is no `pod declare --file` verb today**, so the checked-in
   file is documentation and the bootstrap is the two `pod add`/`sync`
   commands above (a small feature follow-up could accept a decl file).

2. **System tools from the distro**, not nix:

   ```sh
   sudo apt-get install -y squashfs-tools bubblewrap   # once
   ```

3. **The gate** (replaces `devbox run -- check`):

   ```sh
   export SHUTTLE_SYSTEMD=off
   shuttle run --pod gate -- cargo build --locked
   shuttle run --pod gate -- cargo test  --locked
   shuttle run --pod gate -- cargo clippy --locked -- -D warnings
   shuttle run --pod gate -- cargo fmt --check
   ```

   `shuttle run --` resolves `cargo` farm-first (the pod's rust), children
   inherit the overlaid env (loader-lib `LD_LIBRARY_PATH` from the farm —
   this is what kills the `env -u LD_LIBRARY_PATH` ritual), and host
   distro tools (mksquashfs, bwrap, cc, git, …) resolve via the PATH
   fallback. Verified: `src/confine.rs:161` `run_command` +
   `resolve_command` (farm entries before caller PATH).

4. Update `docs/agents/build-and-test.md` gate table; devbox stays as
   fallback until P3.

Bootstrap note: building shuttle itself needs a host `cargo` + C++
toolchain (`install.sh` rustup-bootstraps cargo if absent; the vendored
Luau analyzer needs cc/c++). On any dev machine both already exist. No nix
involved.

### P2 — CI nix-free job (recommended shape)

Job on `ubuntu-24.04`, no devbox action:

1. `sudo apt-get install -y squashfs-tools bubblewrap` (runners have
   passwordless sudo; gcc/g++/curl/tar/git/python3 preinstalled).
2. Install shuttle from the checkout:
   `SHUTTLE_SRC="$GITHUB_WORKSPACE" ./install.sh --skip-deps --prefix "$HOME/.local"`
   (`--skip-deps` continues with a warning instead of dying — verified in
   `install.sh:136`; rustup bootstrap if no cargo).
3. **Payload mechanism — `shuttle export` tree shipped as a GH Actions
   artifact, pulled back via the farm's own signed protocol** (details in
   §4 below).
4. Gate: same four `SHUTTLE_SYSTEMD=off shuttle run --pod gate -- cargo …`
   commands, plus a **skip-guard**: the pod tests skip silently when
   mksquashfs/unsquashfs/bwrap are missing (`bwrap_gate()` pattern) —
   green-but-hollow. The job must grep the test output for
   `skipping: mksquashfs/unsquashfs/curl/tar/bwrap unavailable` and fail if
   it appears.
5. Transitional fallback (if the export pipeline lags): plain rustup +
   `cargo test` with no pod — nix-free but not pod-driven; acceptable only
   as a bridge, since the point of P2 is dogfooding the pull/run surface.

### P3 — devbox/nix removal

- Delete `devbox.json` + `devbox.lock`.
- Rewrite `docs/agents/build-and-test.md`: gate = the four
  `shuttle run --pod gate -- cargo …` commands; drop the
  `env -u LD_LIBRARY_PATH` ritual entirely (it existed because the pod's
  loader-lib `LD_LIBRARY_PATH` leak broke devbox's node — no devbox, no
  leak, no ritual). Update the top-level `AGENTS.md` build section to
  match.
- Lint/coverage lanes: fetch stylua + cargo-llvm-cov from their GitHub
  releases (both static rust binaries); luacheck via pool `luarocks`.
  Add relayout recipes (`libgcc.lua` prebuilt precedent) if they should be
  farm-visible.
- Local shell: nothing to migrate — the login shell is already pod-shellenv
  (`~/.bashrc.d/90-shuttle.sh`); devbox was only ever entered for the gate.
- Uninstall nix/devbox from the machine (owner-gated; see issue #96 family
  and the open dogfood uninstall ticket).

---

## 4. Payload delivery for CI — recommended mechanism

**One mechanism: `shuttle export` → GH Actions artifact → `shuttle pull`.**

- The owner's machine (or any pod-bearing machine) runs
  `shuttle export --out export-tree/` — a plain directory
  (`index.json`, signed `manifests/<pkg>.json`, content-addressed
  `blobs/<sha256>`; ADR-0033 Decision 10). Upload it with
  `actions/upload-artifact`.
- The CI job downloads the artifact, serves it on loopback
  (`python3 -m http.server --bind 127.0.0.1`), and runs
  `shuttle pull "http://127.0.0.1:<port>/<pkg>" --pod gate` for each
  package of the gate generation (rust + its requires: glibc, libgcc).

Why this one: it reuses the farm's own pull protocol with fail-closed
signature verification (no blind tarball trust), needs **zero inbound
connectivity** (artifact download + localhost), carries **prebuilt blobs**
so the glibc source-build problem never touches CI, and `export`'s
union+prune rules keep the published tree exactly the pod's generation.

Rejected alternatives: (a) on-runner `pod sync` from recipes — dead end,
glibc is a hours-long source build; (b) `shuttle serve` peer pull from the
owner's machine — CI would require an online home machine; (c) raw upstream
tarballs (rust dist tarball only) — works for rust but bypasses the pod
protocol and re-builds the snap on-runner, and doesn't generalize to the
glibc/libgcc requires chain.

---

## 5. Version policy

Devbox pins **1.97.1** (cargo/rustc/clippy/rustfmt); the pool's
`pkgs/r/rust.lua` pins **1.98.1** (official dist tarball). Devbox/nixpkgs
cannot resolve 1.98.x — **the pod version is the only unification point
that survives deprecation**.

**Recommendation: unify on the pod's 1.98.1** ("use current versions"),
via a one-time gate re-baseline:

1. Flip the devbox pin is impossible — instead flip the *gate*, not the
   pin: run the four gate commands under the gate pod (1.98.1) once,
   locally.
2. If clippy/rustfmt drift shows up (expected: new lints may trip
   `-D warnings`; formatting may differ), **fix forward** — apply the new
   suggestions once. That re-baseline is the cost of unifying.
3. If drift is somehow unmanageable, the temporary escape hatch is pinning
   the pool recipe to the 1.97.1 dist URL
   (`static.rust-lang.org/dist/<date>/rust-1.97.1-…tar.xz`) so both sides
   run 1.97.1 during transition — but flip both together and delete the
   escape hatch; carrying two toolchain versions is the drift.

Drift risks, stated plainly: clippy adds/changes lints across versions, so
a 1.97.1-clean tree may be 1.98.1-red (and vice versa when contributors run
older toolchains); rustfmt output differs at edition boundaries; CI must
pin the same pod generation as local dev (the pool pin + lockfile pin do
this) so "green locally, red in CI" never means "different rustc".

---

## 6. Risks

- **GH runner sandbox / unprivileged bwrap.** Confined-app tests need
  unprivileged user namespaces (`userns_available()` probes `unshare`,
  confine.rs:514) and the `bwrap` binary. Ubuntu 24.04 added
  AppArmor restrictions on unprivileged userns — whether the GH-hosted
  runner image keeps them disabled is **NOT-VERIFIED** from this repo;
  check `sysctl kernel.apparmor_restrict_unprivileged_userns` and
  `bwrap --ro-bind / / true` on a runner before trusting confined-test
  coverage. Failure mode is soft (tests skip via `bwrap_gate()`), which is
  exactly why the skip-guard in P2 is mandatory: without it, coverage
  silently evaporates. Package *builds* are unaffected: `run_bwrapped`
  falls back to direct execution without bwrap (snap.rs:5257).
- **Network egress.** `cargo build/test --locked` fetches ~314 locked
  crates from crates.io on a fresh runner (no vendor dir, no
  `.cargo/config.toml` in-repo — verified). Plus rustup bootstrap, apt,
  artifact download. All outbound; no inbound required anywhere in the
  plan. Offline-ness of the *test suite itself* is preserved
  (loopback fixtures per build-and-test.md).
- **Disk/time budget.** Local debug `target/` runs ~24 GB with
  incremental artifacts; CI already builds this same crate on 14 GB
  ubuntu-24.04 runners today under devbox, so the budget precedent holds —
  keep `CARGO_INCREMENTAL=0` (GH default) and don't add profiles. The rust
  payload is ~250 MB download / ~1.5 GB installed; shuttle's own release
  build (with 120 vendored C++ TUs) is a few minutes.
- **Chicken-and-egg.** Installing shuttle needs a host cargo + cc (rustup
  minimal + distro gcc) — that bootstrap stays distro/rustup-based
  forever; only the *gate* toolchain rides the pod.
- **Pod surface on CI.** Issue #101 (open) notes pod-surface mutation verbs
  fail closed without their tools; `pod sync` needs mksquashfs — apt
  covers it. `shuttle run --` itself is a transparent exec, no extra
  surface.
- **`pod declare --file` gap.** P1's checked-in `gate/pod.lua` is not yet
  loadable by a CLI verb; bootstrap remains `pod add` + `sync`. Small
  feature follow-up, non-blocking.

## 7. Status

- P1: ready to execute (pod exists on this machine's pool; commands
  verified against `src/cli.rs`/`src/confine.rs`).
- P2: prototype script at `scripts/ci-nix-free.sh` (not wired into CI;
  unverified steps carry `# NOT-VERIFIED:` markers).
- P3: blocked on P1/P2 burn-in; deletion order and doc rewrites listed
  above.
