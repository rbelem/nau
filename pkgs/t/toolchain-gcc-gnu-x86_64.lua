-- toolchain-gcc-gnu-x86_64: GCC toolchain for x86_64-linux-gnu
--
-- Aliases: toolchain-gcc-glibc-x86_64, toolchain-x86_64, toolchain
-- These aliases allow shorter or alternative names for the same
-- toolchain. The default "toolchain" alias lets system-base and
-- build-deps reference this as the system's default compiler.
--
-- Requires: gcc, glibc, linux-headers, gmp, mpfr, mpc, isl, zlib
-- (transitive: libgcc, m4, make)
--
-- Two consumer faces, both served from one payload:
--
--   * build_deps consumers (ADR-0018): the merged build prefix leads
--     the sandbox PATH with <prefix>/usr/bin, and the harness probes
--     that dir for bare `gcc`/`g++` to export CC/CXX
--     (build_prefix_toolchain_env). The payload root therefore carries
--     usr/bin/gcc and usr/bin/g++ as relative links into the payload's
--     own toolchain/usr/bin, whose gcc/g++ links dispatch onto the gcc
--     payload's cc/c++ shims.
--
--   * pod apps (issue #38): `gcc`, `g++`, and the `toolchain` alias are
--     sh launchers at the toolchain/ root. The farm assembly captures
--     every payload entry under the command binary's directory, so a
--     launcher at toolchain/gcc assembles the ENTIRE staged tree beside
--     itself. Each launcher resolves its real dir at run time (readlink
--     -f through the farm symlink), execs the staged driver, and:
--       LD_LIBRARY_PATH=…   — the staged ELFs carry no RUNPATH, so
--                             cc1/cc1plus find the staged libstdc++/
--                             libgcc (usr/lib64), the pool libs
--                             (usr/lib), and the Debian multiarch dir
--                             (usr/lib/x86_64-linux-gnu — libisl,
--                             libmpfr, libgmp, libzstd, cc1's
--                             DT_NEEDED) via the launcher's environment.
--       --sysroot="$d"      — the staged tree has the prefix's shape;
--                             the driver compiles against the staged
--                             glibc and linux-headers. (Contingency if
--                             the deb driver misbehaves under a
--                             sysroot: drop the flag and ride the cc
--                             shim's LIBRARY_PATH→-L translation, the
--                             mechanism gate-pod round 9 proved.)
--
-- Payload shape: the build copies the merged build prefix (the
-- requires' payloads, /nau-build-prefix) wholesale into
-- $STAGE/toolchain/, so the tree carries the SAME layout the gcc build
-- was configured against: usr/{bin,lib,libexec,include}, usr/lib64, and
-- the runtime lib64/ (ld-linux, libc.so.6) that glibc's absolute-path
-- libc.so linker script references under a sysroot.
--
-- Bare names (#164): the gcc payload is a pure file-copy of Debian
-- forky debs — drivers are versioned (gcc-16, x86_64-linux-gnu-gcc-16)
-- and the unversioned names come from Debian alternatives this deb set
-- does not carry. The payload's own shims are `cc` and `c++` (dispatch
-- on the invoked name), so `gcc` and `g++` links onto them are authored
-- inside the staged tree, and the payload root links through that tree.
--
-- Portability pass (ticket #12), conditional: pool-built binaries (m4,
-- make) carry nix-store interpreters and must be repointed at
-- /lib64/ld-linux-x86-64.so.2; the deb payload's ELFs already carry
-- that interpreter and no RUNPATH, and a blind patchelf pass rewrites
-- their bytes — which would break the per-file content-addressing
-- dedupe with the requires' payloads (measured 2026-10-18). Only files
-- whose interpreter or RUNPATH is actually wrong are touched. strip is
-- byte-idempotent on already-stripped files and stays for payloads that
-- arrive unstripped.
--
-- The staged tree is stripped: GCC ships full -g debug info and
-- unstripped cc1/cc1plus would bloat every pod that carries this
-- package.
--
-- source: the harness requires a fetchable source whenever `build` is
-- set; the build stages nothing from it. Reuse the smallest
-- already-pinned pool tarball (dcg, from pkgs/d/dcg.lua) — the same
-- fixture pattern as test-fixtures/toolchain-*-probe.lua.
--
-- The staged payload is content-addressed per file on pod install, so
-- files byte-identical with the requires' own payloads (glibc,
-- binutils, gcc…) dedupe in the pod store — that is why the
-- portability pass is conditional.

return {
    default = snap {
        name = "toolchain-gcc-gnu-x86_64",
        version = "16.2.0",
        summary = "GCC toolchain (GNU libc, x86_64)",
        description = [[
            Complete GCC toolchain targeting x86_64-linux-gnu.
            Includes GCC C/C++ compiler, binutils (assembler, linker),
            glibc runtime, and all supporting libraries (gmp, mpfr, mpc).
            Stages a self-contained toolchain/ tree whose gcc, g++ and
            toolchain commands drive a hermetic C/C++ build from a pod
            farm, and exposes bare gcc/g++ in its payload root for
            build_deps consumers.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "meta",
        aliases = {
            "toolchain-gcc-glibc-x86_64",
            "toolchain-x86_64",
            "toolchain",
        },
        requires = {
            -- binutils is deliberately ABSENT: gcc's payload vendors the
            -- Debian binutils tool binaries and shells the plain names
            -- (ar, as, ld, ...) through LD-fixing shims (gcc.lua, #171).
            -- The pool binutils payload's own usr/bin/ar is a different
            -- binary, and ADR-0018 merge semantics make gcc + binutils
            -- in one build prefix a hard conflict — podman's toolchain
            -- build_dep could never materialize (#171 follow-up).
            "gcc",
            "glibc",
            "linux-headers",
            "gmp",
            "mpfr",
            "mpc",
            "isl",
            "zlib",
        },

        -- ADR-0018 leak scan: the staged tree carries the gcc build's
        -- recorded sysroot documentation (mkheaders.conf, configargs.h)
        -- with the prefix path as text — the same references gcc.lua
        -- silences, same rationale: load-bearing inside build sandboxes
        -- (where the prefix is bound at exactly that path), inert at
        -- pod runtime (the launchers repoint everything).
        leaks_ok = {
            "/nau-build-prefix",
            "/nau-build-prefix/usr/lib",
            "/nau-build-prefix/usr/lib64",
        },

        source = {
            url = "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/v0.14.1/dcg-x86_64-unknown-linux-musl.tar.xz",
            sha256 = "e7b39be070ad98f74a1edd59fefb8ac41865ab2aa2c5a4252eb71c5413f3f9df",
        },

        -- Stage the merged prefix whole, author the bare-name links,
        -- run the conditional portability pass, and author the three
        -- root launchers. printf lines stay single-quoted with no
        -- nesting so the sandbox preflight reads them cleanly (the
        -- go.lua pattern); $() interiors are runtime sub-commands.
        build = table.concat({
            "mkdir -p $STAGE/toolchain",
            "cp -a /nau-build-prefix/. $STAGE/toolchain/",
            -- Fail closed when the gcc payload's shim shape changes: the
            -- bare-name links below and the launchers depend on cc/c++.
            "test -x /nau-build-prefix/usr/bin/cc || { echo 'toolchain: prefix carries no cc shim — the gcc payload shape changed (see pkgs/g/gcc.lua)' >&2; exit 1; }",
            "test -x /nau-build-prefix/usr/bin/c++ || { echo 'toolchain: prefix carries no c++ shim — the gcc payload shape changed (see pkgs/g/gcc.lua)' >&2; exit 1; }",
            -- Bare names onto the dispatch shims: the payload root serves
            -- build_deps consumers (<prefix>/usr/bin leads the sandbox
            -- PATH; CC/CXX probe gcc/g++ there), the staged tree serves
            -- the launchers. Root links resolve through the payload's own
            -- toolchain/ subtree, so they are self-contained in both the
            -- payload and any merged prefix; no ADR-0018 collision, the
            -- gcc payload stages neither name.
            "mkdir -p $STAGE/usr/bin",
            "ln -sf ../../toolchain/usr/bin/gcc $STAGE/usr/bin/gcc",
            "ln -sf ../../toolchain/usr/bin/g++ $STAGE/usr/bin/g++",
            "ln -sf cc $STAGE/toolchain/usr/bin/gcc",
            "ln -sf c++ $STAGE/toolchain/usr/bin/g++",
            -- The root links must RESOLVE (two hops into the payload's own
            -- tree): a wrong relative depth is a dangling name that only
            -- surfaces as a host compiler winning the PATH lookup, so fail
            -- closed here — `test -x` follows the links.
            "test -x $STAGE/usr/bin/gcc || { echo 'toolchain: payload-root gcc link does not resolve' >&2; exit 1; }",
            "test -x $STAGE/usr/bin/g++ || { echo 'toolchain: payload-root g++ link does not resolve' >&2; exit 1; }",
            -- Conditional portability pass — see the header note. A
            -- wrong interpreter or a present RUNPATH gets repaired;
            -- already-portable files stay byte-identical (dedupe).
            'find $STAGE -type f -exec sh -c \'i=$(patchelf --print-interpreter "$1" 2>/dev/null) || exit 0; [ "$i" = /lib64/ld-linux-x86-64.so.2 ] || patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 "$1"\' _ {} \\;',
            'find $STAGE -type f -exec sh -c \'r=$(patchelf --print-rpath "$1" 2>/dev/null) || exit 0; [ -z "$r" ] || patchelf --remove-rpath "$1"\' _ {} \\;',
            "find $STAGE -type f -exec strip --strip-unneeded {} \\; 2>/dev/null || true",
            -- The staged tree must carry the bare names the launchers exec,
            -- and the shims they dispatch onto.
            "test -x $STAGE/toolchain/usr/bin/cc || { echo 'toolchain: staged tree carries no cc shim' >&2; exit 1; }",
            "test -x $STAGE/toolchain/usr/bin/gcc || { echo 'toolchain: staged tree carries no gcc link' >&2; exit 1; }",
            "test -x $STAGE/toolchain/usr/bin/g++ || { echo 'toolchain: staged tree carries no g++ link' >&2; exit 1; }",
            -- gcc driver launcher
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64:$d/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/gcc\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/gcc",
            -- g++ driver launcher
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64:$d/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/g++\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/g++",
            -- the toolchain alias as an app: cc-style face of the driver
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64:$d/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/gcc\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/toolchain",
            "chmod +x $STAGE/toolchain/gcc $STAGE/toolchain/g++ $STAGE/toolchain/toolchain",
        }, " && "),

        apps = {
            gcc = app {
                command = "toolchain/gcc",
            },
            ["g++"] = app {
                command = "toolchain/g++",
            },
            toolchain = app {
                command = "toolchain/toolchain",
            },
        },
    },
}
