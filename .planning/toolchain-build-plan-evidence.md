# Toolchain build plan — evidence

The verified findings and the run-by-run verification record for
[toolchain-build-plan.md](toolchain-build-plan.md). Split out because
the combined file passed the 5,000-token pre-commit budget, which
the plan keeps to the summary and the decisions.

## Verified findings


1. **The meta is stale against the deb-payload gcc, on both of its
   faces.** Inspected: the staged gcc payload carries `usr/bin/cc` and
   `usr/bin/c++` (recipe shims) plus versioned-only driver names
   (`usr/bin/gcc-15`, `usr/bin/x86_64-linux-gnu-gcc-15`) — verified
   twice, against the built `gcc_14.2.0_amd64.snap` (unsquashfs: 63
   `usr/bin` entries; exact-match grep for unversioned driver names
   returns nothing) and against the current recipe's deb set
   (`gcc-15-x86-64-linux-gnu_15.2.0-1_amd64.deb` data.tar lists only
   `x86_64-linux-gnu-gcc-15`; `gcc-15_15.2.0-1_amd64.deb` lists only
   `gcc-15`). Consequences, all read from the meta's script
   (`pkgs/t/toolchain-gcc-gnu-x86_64.lua`):
   - The symlink loop (`:145`) creates dangling `gcc/g++/cpp/c++/gcov`
     links in `toolchain/usr/bin`.
   - The same loop *clobbers the working binutils shims*: the gcc payload
     authors `ar as ld nm ranlib strip objcopy objdump readelf strings
     size addr2line` as self-locating scripts that set the multiarch
     `LD_LIBRARY_PATH` before execing the triplet binary
     (`pkgs/g/gcc.lua:491-502`) — precisely so a merged prefix works
     without the farm LD wrapper (#171 gap 3). `ln -sf
     x86_64-linux-gnu-$t` replaces each with a raw symlink that dies on
     libbfd.
   - The launchers (`:160-164`) exec `$d/usr/bin/gcc` / `$d/usr/bin/g++`,
     nonexistent after the loop, and export `$d/usr/lib:$d/usr/lib64` —
     missing `$d/usr/lib/x86_64-linux-gnu`, where cc1's deb-vendored
     DT_NEEDED (libisl, libmpc, libmpfr, libgmp, libzstd) live
     (read, `pkgs/g/gcc.lua:70-75`, `crates/nau-build/src/snap.rs:3606`).
   - The build_deps face has no bare names anywhere: a consumer's sandbox
     PATH leads with `<prefix>/usr/bin`
     (`crates/nau-build/src/snap.rs:4255`), and `build_prefix_toolchain_env`
     probes `prefix/usr/bin` for `gcc`/`g++` to export `CC`/`CXX`
     (`snap.rs:3616-3624`). The meta's bare names live nested at
     `prefix/toolchain/usr/bin`, on no PATH. So the probe's `gcc t.c`
     (read, `test-fixtures/toolchain-gcc-probe.lua:57`) fails ENOENT even
     after a launcher-only fix.
   - The probe itself is stale: it greps `16\.1\.0` (`:65-66`), the old
     from-source GCC; the recipe is 15.2.0.
   Inferred: predicate 2 fails ENOENT today; predicate 3 fails on the
   bare-name and version asserts. The meta predates the #164 deb-payload
   switch (last touched 2026-09-28, rename only; gcc switched
   2026-10-03, `e26a770`).

2. **`make.lua`'s self-entry in `build_deps` is a documented marker, not
   a defect.** Council correction, verified: read
   `crates/nau-chart/src/deps.rs:255-276` — "A seed naming the package
   itself is the self-host marker (issue #33) … the runtime closure keeps
   the entry; only the build-time view drops it". `build_dep_seeds` drops
   it (`:270`) and the scheduler filters the self-edge
   (`crates/nau-pool/src/build_sched.rs:535`), so builds order correctly.
   The only casualty is the `--order` display: `topological_sort`
   (`deps.rs:328-353`) counts the self-edge as in-degree and punts the
   stuck nodes to an arbitrary tail (measured: gmp before m4/make). Not a
   blocker; recorded as a separate display fix, out of this plan's scope.

3. **The real meta has no end-to-end test.** Read:
   `tests/pod_toolchain_meta.rs` drives fixture packages (`dep`,
   `metatool`) through the mechanism, never `toolchain-gcc-gnu-x86_64`.

4. **The gate pod carries the pieces, not the meta.** Measured:
   `nau pod --name gate list` → linux-headers 6.12.38, libgcc 14.2.0,
   rust 1.99.0, glibc 2.43, gcc 15.2.0. No `toolchain` entry; the built
   `.snap` payloads sit in the repo root (2026-09-09 / 09-26 builds) and
   were installed by sideload, not by recipe build.

5. **No published tree is reachable; no worker is provisioned.**
   Measured: no listeners on 19000/17780, `tailscale status` has no
   worker. Read: farm artifacts live on ephemeral worker VMs behind SSH
   tunnels (`nau-farm-ops` skill). Inferred: builds run locally or a pool
   window must be provisioned (`nau pool burst`).

6. **The patchelf pass breaks byte-dedupe for no benefit on the deb
   payload; the strip pass is inert.** Measured: the deb payload's ELFs
   already carry interpreter `/lib64/ld-linux-x86-64.so.2` and no
   RUNPATH; `patchelf --set-interpreter` rewrites bytes even when the
   interpreter is already correct (hash changes), while
   `strip --strip-unneeded` is byte-idempotent. The pool `m4`/`make`
   binaries DO carry nix-store interpreters (measured:
   `/nix/store/…-glibc-2.42-*/lib/ld-linux-x86-64.so.2`), so the pass is
   load-bearing for them. The fix keeps both guarantees: a conditional
   pass that touches only files whose interpreter (or RUNPATH) is
   actually wrong.

7. **The libgcc 14.2 pairing is symbol-safe with gcc 15.2 — no bump
   needed.** Council raised the risk that libstdc++ 15.2 needs
   `GCC_15.0.0` symbols from libgcc_s; measured with `readelf -V`: the
   Debian `libstdc++6_15.2.0-1` libstdc++.so.6.0.34 needs exactly
   `GCC_3.0`, `GCC_3.3`, `GCC_4.2.0`, `GCC_4.3.0` from libgcc_s.so.1,
   and the pool libgcc 14.2.0 defines up to `GCC_14.0.0` (superset). The
   council's named contingency is closed by evidence, not by bumping.

## Verification record


- 2026-10-18: every load-bearing claim verified against command output
  with TypeSafe Jev (`jev_verify`, 8/8 verified, 0 contradicted, 0
  unsupported, all at auto confidence after evidence deepening).
- Council review 2026-10-18 (single reviewer; verdict ACCEPT WITH
  CHANGES). Folded: the build_deps-face gap, the binutils-shim clobber,
  the multiarch `LD_LIBRARY_PATH`, the stale probe, the version bump, the
  `--sysroot` contingency, the assertion pattern. Refuted by measurement:
  the libgcc-bump requirement (finding 7). Corrected: finding 2's framing
  (documented #33 marker). Extended by measurement: the patchelf pass
  breaks dedupe (finding 6).
- Run 1 (2026-10-18, `scripts/toolchain-local-assemble.sh tchain`):
  10 closure payloads seeded and baselined; gcc 15.2.0 built green
  through the pod path (fetch-merge, leak scan `70 ELFs, 0 build-only
  refs`, 378 MB snap). The meta build then failed at the new fail-closed
  guard: it checked `$STAGE/usr/bin/cc`, but the payload's `usr/bin`
  comes from the merged prefix (`/nau-build-prefix`) and only lands in
  `$STAGE` after the copy — the guard read the wrong side of the copy.
  Fix: guards read `/nau-build-prefix/usr/bin/{cc,c++}`; the payload-root
  links resolve through the payload's own `toolchain/usr/bin` (so they
  are self-contained in the payload and in any merged prefix); the staged
  links point at the same-dir shims.
- Probe edit: `test-fixtures/toolchain-gcc-probe.lua` version greps move
  from the dead from-source `16.1.0` to `15.2.0`, and the stale
  "configured sysroot" comment is rewritten to the deb-payload reality.
- Run 2 (2026-10-18, `pod sync`): the meta built green (leak scan
  `402 ELFs, 4614 files, 0 build-only refs`; 97.6 MB snap, 4615 files,
  1121 symlinks) and installed as generation 1 of pod `tchain`, farm
  emitted. Predicate 1 green. `gcc --version` and `g++ --version` through
  the farm print `15.2.0 (Debian)` — the launchers and bare names work.
  Compile-and-run then failed at LINK time: `ld: cannot find
  /lib64/libc.so.6`. Root cause found by inspecting the seeded payload:
  the repo-root `glibc_2.43_amd64.snap` is the 2026-09-09 build and
  predates commit 3ebf453 (2026-09-23), which rewrote glibc's GNU ld
  scripts from absolute rootfs paths to bare sonames (the gate pod's
  rebuilt glibc carries `GROUP ( libc.so.6 … )`; the repo-root one
  carries `GROUP ( /lib64/libc.so.6 … )`). The toolchain itself is not at
  fault; the seed payload was stale. Rule adopted: seed a member only
  from a payload built AFTER the recipe's last build-affecting change
  (lint/format commits exempt) — the corrected seed uses the daily pod's
  post-fix payloads for glibc, linux-headers, libgcc, zlib, isl, mpc,
  m4, make, mpfr, gmp, plus the freshly built gcc 15.2.0.
- Run 4 (2026-10-18, corrected seed): predicates 1 and 2 GREEN —
  `gcc --version` and `g++ --version` print `15.2.0 (Debian)` through the
  farm, and in-pod compiles RUN (C prints `C_RUN_OK` exit 42; C++ prints
  `CPP_RUN_OK` exit 7, exercising libstdc++ 15.2 against libgcc 14.2 —
  the council's refuted risk stays refuted in practice). The probe build
  then failed its `gcc --version | grep 15.2.0` assert. Root cause, found
  by a scratch debug probe printing `command -v gcc`: the first cut of
  the payload-root link said `usr/bin/gcc -> ../toolchain/usr/bin/gcc`,
  which from `usr/bin/` resolves to `usr/toolchain/…` — one directory
  too shallow. The link dangled, the sandbox PATH fell through to the
  HOST's nix gcc (`gcc (GCC) 16.2.0`), and the probe compiled with the
  host compiler while asserting 15.2.0. The pod face had passed because
  it resolves through farm app wrappers, not the payload-root link —
  exactly why the two faces need separate verification. Fix: the links
  target `../../toolchain/usr/bin/{gcc,g++}` and the build fails closed
  with a `test -x` that follows the link chain — the gate this class
  deserves, since a dangling bare name does not fail loudly; a host
  compiler silently wins the PATH lookup.
- Run 5 (2026-10-18, after the depth fix): the link chain resolves
  (`usr/bin/gcc -> ../../toolchain/usr/bin/gcc -> cc`, executable), and
  **predicate 3 is GREEN** — `nau build --file
  test-fixtures/toolchain-gcc-probe.lua` merges 12 payloads and the
  probe's own assertions pass end to end (`toolchain-gcc-probe: C and C++
  builds green`). One probe correction rode along: the C++ TU originally
  referenced no libstdc++ symbol, and the Debian toolchain's default
  `--as-needed` link dropped `libstdc++.so.6` from DT_NEEDED (the earlier
  pass had been the host gcc's driver, which keeps it). The probe now
  uses `std::string`, so the assert measures the runtime chain rather
  than the driver's default flags.
- Run 6 (2026-10-18): `tests/toolchain_probe.rs` runs green with
  `NAU_TOOLCHAIN_PROBE_CACHE` set (1 passed, 9.55s, real probe build plus
  the link-resolution assertions) and prints its skip reason when the
  variable is unset (passes in 0.00s). Jev rescore of the full change
  (artifacts + this validation evidence): correctness 6.9 → 7.9, every
  other metric flat or up, zero regressions. luacheck 0 warnings, stylua
  clean.
