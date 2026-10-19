# Toolchain build plan

Date: 2026-10-18. Evaluation of what is needed to build the nau toolchain
that package builds consume. Every claim carries its evidence label:
**inspected** (artifact bytes read this session), **read** (source line
cited), **measured** (command output), **inferred** (conclusion drawn
from inspected/read facts). Council review (2026-10-18) is folded in;
its verdict was ACCEPT WITH CHANGES with four evidence-layer
corrections, three of which held on re-verification, one refuted by
measurement (recorded below).

## Goal and done-predicate


Build `toolchain-gcc-gnu-x86_64` (the meta-package aggregating compiler,
linker, and runtime libraries, `CONTEXT.md` Toolchain) plus its closure,
and prove it is the usable compiler set for package builds.

Predicate, falsifiable:

1. `nau pod --name tchain add toolchain` reconciles green.
2. Through the pod farm, `gcc --version` and `g++ --version` print the
   payload's GCC version, and `cc`/`c++` compile a hello program that
   runs.
3. `nau build --file test-fixtures/toolchain-gcc-probe.lua` builds green
   and its build script compiles C and C++ inside the hermetic sandbox.
4. A `build_deps = { "toolchain" }` consumer (e.g. `valkey`) reaches the
   merged build prefix and compiles.

## The closure


`nau build --order --file pkgs/t/toolchain-gcc-gnu-x86_64.lua`
(measured): linux-headers, glibc, libgcc, gcc, zlib, isl, mpc, m4, make,
mpfr, gmp.

The meta's own `requires` (read, `pkgs/t/toolchain-gcc-gnu-x86_64.lua:94`)
is gcc, glibc, linux-headers, gmp, mpfr, mpc, isl, zlib; libgcc, m4, make
arrive transitively (gcc requires libgcc; m4/make are build deps of the
math libraries).

Strategies (read, recipe headers):

| Package | Strategy | Notes |
|---|---|---|
| gcc 15.2.0 | 66 Debian trixie snapshot debs, per-arch sets | `pkgs/g/gcc.lua`, fetch-merge, no compile |
| linux-headers 6.12.38 | Debian `linux-libc-dev` deb | sole owner of uapi subtrees (#174) |
| libgcc 14.2.0 | Debian `libgcc-s1` relayout | prebuilt by design (GCC source unsupported out of tree) |
| glibc 2.43 | source build | the long pole (`pkgs/g/glibc.lua`) |
| gmp, mpfr, mpc, isl, zlib | source builds | small, minutes each |
| m4, make | source builds | small; their binaries carry nix-store interpreters (measured) |

Consumers (read/grep): the cargo plugin
(`crates/nau-core/src/plugins.rs:46` `CARGO_BUILD_DEP`), `build-deps`
meta (alias `toolchain`), `system-base` (`pin("toolchain")`), and
recipes `valkey`, `podman`, `bifrost` declare `build_deps = {
"toolchain" }`.

## What is needed


Host floor to build the closure on a Linux box (measured on book3 via
`nau doctor`, plus read of `docs/agents/devbox-deprecation-plan.md` §1a):

- mksquashfs + unsquashfs (>= 4.4), bwrap, tar, curl — all green on
  book3 (mksquashfs 4.7.5), all apt-installable.
- A host C compiler for the source builds (glibc, gmp, mpfr, mpc, isl,
  zlib, m4, make).
- `patchelf` and `strip` for the meta's portability pass (read,
  `:156-158` of the meta). The sandbox preflight
  (`crates/nau-build/src/snap.rs:4009`) fails the build by name when a
  tool word is not sandbox-visible.
- Disk + RAM: glibc is the cost driver. Book3 has 41 GB free on /home and
  ~2 GB available RAM — not a safe glibc host.

Compute placement options:

- **A. Local pod assembly, payloads sideloaded.** Reuse the repo-root
  `.snap` payloads (glibc, gmp, mpfr, mpc, isl, zlib, m4, make, libgcc,
  linux-headers) plus a fresh gcc 15.2.0 fetch-merge build, then assemble
  the meta. No glibc rebuild. Cheapest honest end-to-end proof on book3.
- **B. Farm window.** `nau pool burst --provider hetzner --type <SKU>
  --location <loc> -- <build command>`. Sanctioned for heavy work, needs
  the Hetzner token, a worker binary URL, and a `workers` config —
  hours of setup, and the window is ephemeral. Buys tree publication;
  no fleet exists to consume the tree today. Re-run any time once A's
  recipes are green.
- **C. Full local build.** `nau build --all` on the meta — rebuilds
  glibc from source on book3. Rejected on the machine's RAM/disk math.

## Plan (riskiest-unknown first)


1. **Rewrite the meta's payload-facing surface**
   (`pkgs/t/toolchain-gcc-gnu-x86_64.lua`):
   - Drop the symlink loop entirely; author payload-root
     `usr/bin/gcc -> cc` and `usr/bin/g++ -> c++` (relative links; the
     shims dispatch on the invoked name, so `gcc` gets the C driver and
     `g++` the C++ driver — read, `pkgs/g/gcc.lua:472-475`). This serves
     the build_deps face (`<prefix>/usr/bin` on PATH, `CC`/`CXX` export)
     with no ADR-0018 collision: the gcc payload stages neither name.
   - Author the same two links inside the staged `toolchain/usr/bin`
     (`toolchain/usr/bin/gcc -> cc`), keep the three launchers execing
     those, and extend the launcher `LD_LIBRARY_PATH` with
     `$d/usr/lib/x86_64-linux-gnu`.
   - Make the portability pass conditional: repoint an interpreter only
     when `patchelf --print-interpreter` differs from the target; drop a
     RUNPATH only when one exists; keep the byte-idempotent strip.
   - Bump the meta's `version` to 15.2.0 and refresh the stale header
     comments (deb payload, not source build; the `--sysroot` rationale).
   - Pre-name the fallback: if the deb driver misbehaves under
     `--sysroot=$d`, drop the flag and ride the proven CPATH/LIBRARY_PATH
     mechanism (gate-pod round 9).
2. **Pre-flight the reuse path** (before any build): enumerate which
   closure members the content-key check will rebuild on book3
   (`src/pod.rs:6719-6742`; drifted recipes rebuild) and confirm glibc is
   not among them; if it is, stop and re-scope placement.
3. **Build gcc 15.2.0** (fetch-merge, no compile) as the modern payload.
4. **Assemble the toolchain in a pod**: add/sideload closure payloads,
   then `add toolchain`; verify predicate 1-2 (`gcc --version`,
   `g++ --version`, C and C++ compile + run through the farm).
5. **Run the probe** (`test-fixtures/toolchain-gcc-probe.lua`; edit the
   two `16\.1\.0` greps to `15\.2\.0` first) and one
   `build_deps = { "toolchain" }` consumer compile (predicate 3-4).
6. **Encode the lesson**: extend the test suite so the stale-name class
   is caught mechanically — derive every launcher exec target from the
   script text and assert it exists (the `pkgs/g/gcc.lua:509-513`
   pattern), assert every symlink in the meta payload resolves, and
   assert the binutils names remain shims rather than raw symlinks.

The verified findings and the run-by-run verification record live in
[toolchain-build-plan-evidence.md](toolchain-build-plan-evidence.md).

## Predicate results (2026-10-18)


| # | Predicate | Verdict |
|---|---|---|
| 1 | `nau pod add toolchain` reconciles green | VERIFIED (generation 1 of pod `tchain`, leak scan clean, farm emitted) |
| 2 | `gcc`/`g++` version + C/C++ compile and run through the farm | VERIFIED (`15.2.0 (Debian)`; C exit 42, C++ exit 7) |
| 3 | `test-fixtures/toolchain-gcc-probe.lua` builds green | VERIFIED (`toolchain-gcc-probe: C and C++ builds green`) |
| 4 | A `build_deps = { "toolchain" }` consumer compiles | VERIFIED by the same probe (its `build_deps` is the alias), inside the hermetic sandbox across a 12-payload merged prefix |

Open in the plan but not blocking: the `--order` display's self-edge
handling (finding 2); a valkey-scale consumer build (heavier, same
mechanism); landing the artifacts (commits/PR) still needs the operator.

## Open decisions


- gcc payload version: decided, 16.2.0 (the recipe is the contract; the
  earlier 15.2.0 choice was superseded by the version bump run below, and
  the plan's note about a 14.2.0 choice was an error, corrected twice).
- Whether `build-deps` (toolchain + autotools) becomes the default
  `build_deps` floor for recipes, shrinking the 83 recipes that declare
  ad-hoc `{ "gcc", "make" }`. Out of scope for the build; noted as the
  direction the meta exists for.
- The `--order` display's self-edge handling (finding 2): a small
  follow-up in `topological_sort`, not part of this plan.

## Version bump run (2026-10-19)


Directive: latest gcc/libc for the toolchain, plus a 50% resource cap.

| Package | Was | Now | Evidence |
|---|---|---|---|
| gcc | 15.2.0 (trixie debs) | 16.2.0 (forky debs) | 66/66 URL+hash verified by download |
| glibc | 2.43 | 2.44 | tarball sha256 measured |
| binutils | 2.44 | 2.47 | tarball sha256 measured |
| libgcc | 14.2.0 | 16.2.0 | deb sha256 measured |
| linux-headers | 6.12.38 | 7.2.8 | deb sha256 measured |
| mpfr | 4.2.1 | 4.2.2 | tarball sha256 measured |
| isl | 0.27 | 0.28 | tarball sha256 measured |
| gmp, mpc, zlib | unchanged | unchanged | already latest |

Riskiest unknown, resolved first: whether gcc 16.2.0-3 still ships the
22-deb-per-arch set the recipe unpacks. It does not, exactly — Debian
renamed `libsframe1` to `libsframe3` in binutils 2.47. Every other
component kept its name. The recipe's build script and sources table
were updated together; a check confirms all 66 declared keys match the
66 build-script entries with no orphan on either side.

`scripts/toolchain-debs.sh` is the lever: it reads a pinned snapshot
Packages index for all three arches and prints `key|arch|url|sha256`
rows. A future bump is a timestamp change plus a regeneration, not 66
hand-transcribed hashes.

Verified statically (no heavy build, per AGENTS.md): luacheck 0/0,
stylua clean, all 8 recipes load through `nau build --order`, closure
order intact, 72/72 source URLs reachable and 72/72 sha256 matching the
downloaded bytes.

Not verified: the actual payload builds. glibc 2.44 and binutils 2.47
are source builds and gcc 16.2.0 is a 66-deb fetch-merge; AGENTS.md
rations heavy compiles to pool workers, and no worker is provisioned
(`tailscale status` shows no worker node). The bump is a recipe change
that needs one pool window to become a proven payload.

### Resource limit 50%

The default moved from 80 to 50 (ADR-0056 Amendment 1, CONTEXT.md, CLI
help, probe script, plus a test pinning the value). Proven live, not
just unit-tested: a real `nau build` under `NAU_RESOURCE_LIMIT=50` on
this 12-CPU host held `cpu.max` at `600000 100000` for the whole run
while `nr_throttled` climbed, and still produced a correct 256 MB snap.
