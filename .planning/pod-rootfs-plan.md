# Pod rootfs: the pod provides its own loader and libraries

Date: 2026-10-19. The decisions below were settled with the operator. This
document is the brief for the implementation, and the record of why each
one was chosen.

## The problem

glibc 2.44's `libc.so.6` references `__pointer_chk_guard` as
`UND@GLIBC_PRIVATE`: the symbol moved into the dynamic linker, so only a
matching glibc 2.44 loader can satisfy it. A loader from another build
cannot, and every fortify-compiled binary dies with

```
symbol lookup error: .../libc.so.6: undefined symbol:
__pointer_chk_guard, version GLIBC_PRIVATE
```

Measured 2026-10-19 with nixpkgs' own glibc 2.44 AND with a source-built
2.44, so this is a glibc-2.44 property, not a payload defect. glibc 2.43
has no such reference at all, which is why every payload built before the
2.43 to 2.44 bump works and every one built after it does not.

The pod's libc has been coming from the pod all along, through the farm's
`LD_LIBRARY_PATH`. The only broken thing is the LOADER: the pod's
`libc.so.6` was being loaded by the host's loader. Fix the loader and the
pair is matched.

## The decisions

1. **The pod owns both the libc and the loader.** The pod's glibc payload
   ships a matching pair (`usr/lib64/ld-linux-x86-64.so.2` and
   `usr/lib64/libc.so.6`). The alternative, keeping the host's loader and
   capping the pod's glibc at the host's loader generation, contradicts the
   16.2.0 bump that already shipped.

2. **A per-pod namespace, not a rewritten interpreter.** The kernel
   resolves `PT_INTERP` inside the process's mount namespace, so the
   namespace is what makes the standard FHS path reach the pod's loader.
   `LD_LIBRARY_PATH` cannot repair a mismatched interpreter, because the
   loader is chosen before any library search happens. This is why the
   loader search added to the gcc payload's `cc` shim gets the driver
   running but leaves `cc1` broken: a child process cannot inherit the
   loader its parent was started with.

3. **The farm's app wrappers and the pod's systemd services honor it.**
   The build sandbox does not. A build's products are LINKED against the
   prefix's libc and are correct; they run against the pod's libc once the
   farm gives them a namespace.

4. **Inside the namespace the pod gets its own `/usr/lib`.** The pod's
   libraries are gathered into FHS positions, so a program with a hardcoded
   absolute library path resolves to the pod's copy, not the host's. The
   host's `/usr/lib` is hidden from everything in the namespace, including
   a host tool the app invokes.

5. **The pod's libraries stay reachable by name.** The loader path keeps
   pointing at the per-package directories, so the resolution order for a
   shared soname is unchanged: higher composition layer first, then package
   name.

## Collisions

Two distinct classes, and the repo already has a rule for each.

**Two packages shipping the same binary name.** The farm's link directory
holds one link per name, so only one can be on PATH. `warn_emit_collision`
(`crates/nau-pod/src/farm.rs`) names the winner and the loser: the higher
composition layer wins, and at the same precedence the winner is
deterministic by package name. A namespace does not change this, because
the PATH is still the farm's flat directory. Measured on the daily pod
(127 packages, generation 123): zero binary names are provided by two
packages, so the case is handled and not currently exercised.

**Two packages shipping the same library file.** The build prefix's merge
fails closed: `merge_file` returns a hard error naming both packages when
the same path has different content, and identical content dedupes. That
rule applies to the pod's `/usr/lib` gather. Measured on the daily pod:
zero sonames are provided by more than one package, so the gather is clean
today. A pod that does collide must fail loudly, not silently pick one.

## What to build

**The namespace.** The farm's app wrapper gains a mount namespace in which
the pod's loader answers `/lib64/ld-linux-x86-64.so.2`. The kernel
resolves `PT_INTERP` there, so the pod's binaries start on the pod's
loader, and the pod's `libc.so.6` comes from the loader path, so the pair
matches. The loader is found by the rule the `cc` shim already uses: the
directory on the loader path that carries both a loader and a C library.

**The gather.** The pod's library set is gathered into FHS positions
(`/usr/lib`, `/usr/lib64`) inside the namespace. Reuse the merge semantics
the build prefix already implements, including the fail-closed conflict
that names both packages.

**The services.** A pod's systemd units run on the host, so they need the
same treatment: the unit gets the pod's loader bound at the FHS path. The
unit's `ExecStart` already bakes the loader path (`src/services.rs:545`).

**The reversal.** `crates/nau-pod/src/loader_libs.rs` currently excludes a
directory carrying a C library from the loader path, so the pod's libc
stays off it. That exclusion has to go: the pod's libc comes from the
loader path, and the pod's loader comes from the namespace.

## Verification

The predicates are the same ones the toolchain plan already uses, plus the
new guarantee.

1. `nau pod --name tchain16 add toolchain` reconciles green.
2. Through the farm, `gcc --version` prints 16.2.0 and a C program
   compiles and runs to exit 42, a C++ program to exit 3. This is the case
   that fails today, with `cc1` dying on `__pointer_chk_guard`.
3. A pod binary that hardcodes an absolute library path resolves to the
   pod's copy inside the namespace.
4. The toolchain's `cc1` and `cc1plus`, and the binutils shims, run inside
   the namespace on the pod's loader.
5. A pod service starts on the pod's loader.
6. `nau build --file test-fixtures/toolchain-gcc-probe.lua` still prints
   "toolchain-gcc-probe: C and C++ builds green".

## The ecosystem, for reference

Flatpak binds its runtime at `/usr` and the app at `/app` inside a
bubblewrap namespace, with `/lib` and `/lib64` symlinked into `/usr`, so
the standard interpreter path resolves to the runtime's loader. It
regenerates `/etc/ld.so.cache` from app plus runtime. The host is nearly
invisible. Snap gives each snap a mount namespace built by the setuid
`snap-confine`, with the base snap as the root filesystem and the payload
layered on top; classic confinement disables the namespace and falls back
to host libraries, which is the host-leak failure mode. OSTree provides
delivery and atomic A/B deployment, and no runtime library isolation at
all, which is left to containers on top.

The transferable lessons: the namespace is what resolves the interpreter;
ship loader and libc as an atomic matched set; prefer a namespace FHS
layout over `LD_LIBRARY_PATH` sprawl; keep a shared runtime layer separate
from app payloads; be strict by default and treat host-visible mode as an
audited exception.

## Open

- Whether the `/usr/lib` gather is per generation or per pod, and where the
  gathered tree lives on disk. A per-generation tree re-scopes on rollback
  the way the loader path already does.
- Whether the farm's namespace is entered by the wrapper or by a helper,
  and how the wrapper finds the pod's loader.
- Whether the `cc` shim's loader search stays as a fallback for contexts
  with no namespace, or is retired once the namespace exists.
