# cc1 `libisl.so.23` failure (issue #180 item 2) — runtime evidence, wl-clipboard

## Verdict

**V1 — engine env gap in `build_prefix_env` (src/snap.rs).** The gcc payload
is complete; the defect was that `build_prefix_env` exported
`LD_LIBRARY_PATH = {prefix}/usr/lib:{prefix}/usr/lib64` only, so the gcc
driver's internally-exec'd `cc1` could never resolve `libisl.so.23` (and its
sibling DT_NEEDED `libmpc`/`libmpfr`/`libgmp`/`libzstd`), which Debian stages
under the multiarch dir `{prefix}/usr/lib/x86_64-linux-gnu/`. No PATH shim
can help: the driver execs cc1 itself and inherits the environment as-is.

**This is already fixed on this branch**: commit `1d81006`
("fix(build-env): complete the merged-prefix toolchain contract for
post-cutover rebuilds (#180)", 2026-09-24 09:01) replaced the two-entry
format string with `build_prefix_ld_library_path(prefix)`
(src/snap.rs:5691–5696), which adds
`{prefix}/usr/lib/x86_64-linux-gnu` (+ arm64/armhf triplets) to both
`LD_LIBRARY_PATH` and `LIBRARY_PATH` (the latter closing #180 item 2b via the
gcc.lua cc-shim `-L` contract). The runtime proof below was gathered against
the pre-fix environment; it doubles as verification that `1d81006` is the
correct and sufficient fix.

**Residual action item (deployment, not code):** the host-installed
`~/.local/bin/shuttle` binary (mtime 08:46) predates the fix commit (09:01)
and does not contain the new env format string (checked via `strings`). It
still fails deterministically on any `build_deps = { "gcc" }` build that
reaches cc1. Rebuild/reinstall the host shuttle from this branch to clear it.

## Named defect

- Old (defective): `("LD_LIBRARY_PATH", format!("{}/usr/lib:{}/usr/lib64", prefix, prefix))` in
  `build_prefix_env` — cc1's loader search list has no multiarch dir.
- Fix (landed, `1d81006`): `("LD_LIBRARY_PATH", build_prefix_ld_library_path(prefix))` and
  `("LIBRARY_PATH", build_prefix_ld_library_path(prefix))`, where
  `build_prefix_ld_library_path` = `{prefix}/usr/lib:{prefix}/usr/lib64:{prefix}/usr/lib/x86_64-linux-gnu:{prefix}/usr/lib/aarch64-linux-gnu:{prefix}/usr/lib/arm-linux-gnueabihf`.
- Fix location: `src/snap.rs`, `build_prefix_env` (line ~5649) +
  `build_prefix_ld_library_path` (lines 5691–5696). Recipe change: **none needed**.

## V2 ruled out — payload presence check

The amd64 gcc snap (`gcc_14.2.0_amd64.snap`, built from `pkgs/g/gcc.lua` on
this branch) was extracted with `unsquashfs`. All of cc1's runtime libs are
present and intact:

```
$ find x-gcc_14.2.0/usr/lib ... -name 'libisl*' -o -name 'libmpc*' ...
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libgmp.so.10
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libisl.so.23
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libisl.so.23.4.0
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libmpc.so.3
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libmpfr.so.6
x-gcc_14.2.0/usr/lib/x86_64-linux-gnu/libzstd.so.1
$ find x-gcc_14.2.0 -name cc1
x-gcc_14.2.0/usr/libexec/gcc/x86_64-linux-gnu/14/cc1
```

The payload also ships `usr/bin/cc` and `usr/bin/c++` (the gcc.lua shims) but
**no bare `gcc` or `clang`** — so `build_prefix_toolchain_env` (src/snap.rs:5759,
which probes `usr/bin/gcc` then `usr/bin/clang`) exports no `CC`/`CXX`, and
consumers fall back to bare `cc` on PATH; the prefix bin dir leads PATH
(issue #33), so `cc` resolves to the payload shim → `x86_64-linux-gnu-gcc-14`
→ cc1 in the prefix. That is the exact failure chain.

## Replication (bwrap namespace mirroring `run_bwrapped`)

A merged prefix (gcc + glibc + libgcc + linux-headers payload snaps overlaid)
was ro-bound at `/shuttle-build-prefix` inside a bwrap namespace built to
`run_bwrapped`'s shape: `--unshare-user --unshare-pid --unshare-ipc
--unshare-net --proc /proc --dev /dev --tmpfs /tmp`, build dir at `/build`,
`SANDBOX_RO_ROOTS` (`/usr /lib /lib64 /nix /bin /run/current-system`) ro-bound,
`--clearenv`, `PATH={prefix}/usr/bin:…` (prefix leads), `HOME=/tmp`, plus the
`build_prefix_env` vars. Then `cc -c t.c -o t.o`:

```
OLD (pre-1d81006) LD_LIBRARY_PATH=…/usr/lib:…/usr/lib64
  /shuttle-build-prefix/usr/bin/../libexec/gcc/x86_64-linux-gnu/14/cc1:
    error while loading shared libraries: libisl.so.23: cannot open shared
    object file: No such file or directory        → FAIL (exact #180 error)

NEW (1d81006) LD_LIBRARY_PATH=…/usr/lib:…/usr/lib64:…/usr/lib/x86_64-linux-gnu:…
  → PASS (compiles clean)
```

Single-variable A/B: only the `LD_LIBRARY_PATH`/`LIBRARY_PATH` values differ.

### LD_DEBUG excerpt (OLD env, cc1's loader)

```
     6: find library=libisl.so.23 [0]; searching
     6:   trying file=/shuttle-build-prefix/usr/lib/glibc-hwcaps/x86-64-v3/libisl.so.23
     6:   trying file=/shuttle-build-prefix/usr/lib/glibc-hwcaps/x86-64-v2/libisl.so.23
     6:   trying file=/shuttle-build-prefix/usr/lib/libisl.so.23
     6:   trying file=/shuttle-build-prefix/usr/lib64/glibc-hwcaps/x86-64-v3/libisl.so.23
     6:   trying file=/shuttle-build-prefix/usr/lib64/glibc-hwcaps/x86-64-v2/libisl.so.23
     6:   trying file=/shuttle-build-prefix/usr/lib64/libisl.so.23
     6:   trying file=/run/current-system/sw/share/nix-ld/lib/libisl.so.23
     ... (host nix dirs, no hit)
```

The loader is **never told about** `/shuttle-build-prefix/usr/lib/x86_64-linux-gnu/`
— where the file demonstrably lives. Search-path line: `search
path=/shuttle-build-prefix/usr/lib/...:/shuttle-build-prefix/usr/lib64/...
(LD_LIBRARY_PATH)`.

## Is wl-clipboard the same failure class as git/curl in #180?

**Yes.** All three declare gcc in `build_deps`; all three reach prefix cc1
(git/curl via make/configure and cc-rs probing `cc`; wl-clipboard via meson's
default `cc` — its recipe invokes
`$SHUTTLE_BUILD_PREFIX/usr/bin/meson setup build`, and with no `CC` exported
meson resolves bare `cc`, landing on the payload shim). One environment, one
cc1, one missing dir — the same deterministic libisl exec failure.

Two host-specific observations worth keeping in mind:

1. **The leaky-`/nix` mask.** `SANDBOX_RO_ROOTS` binds host `/nix` (and
   `/usr /lib /lib64`) read-only, and the sandbox PATH retains host entries
   canonicalized onto those roots. On this devbox host, a prefix *without*
   gcc (e.g. the pkg-config/expat dep builds of the wl-clipboard closure)
   resolves bare `gcc` to the nix-profile compiler and compiles fine — the
   defect only fires when the merged prefix itself carries gcc, which is
   exactly the `build_deps = { "gcc" }` consumer set.
2. **Host-OS variance.** The failure requires no `libisl.so.23` in the bound
   host roots — true on this NixOS host. On a Debian-family host,
   `/usr/lib/x86_64-linux-gnu/libisl.so.23` would satisfy cc1 through the
   `/usr` bind, silently masking the same engine gap. The fix makes behavior
   host-independent.

## Evidence-collection notes (honesty section)

- No kept failed tree existed and `SHUTTLE_KEEP_BUILD_DIR=1` did not reach
  shuttle through the `devbox run -- bash -c '…'` inline wrapper (the docs
  warn this wrapper re-parses quoting), so the kept-tree route was abandoned
  in favor of the direct namespace replication above — same sandbox shape,
  exact same error string, stronger evidence.
- A full `shuttle build -f pkgs/w/wl-clipboard.lua` with the host (pre-fix)
  binary was attempted: it built pkg-config, linux-headers, glibc and expat
  from source successfully (compilers resolved to the leaked nix gcc, see
  observation 1) and then aborted at expat's leak scan on a pre-existing
  `RUNPATH=/shuttle-build-prefix/usr/lib64` drift — unrelated to this issue;
  wl-clipboard's own compile was never reached, hence the replication route.
