-- toolchain-gcc-gnu-x86_64: GCC toolchain for x86_64-linux-gnu
--
-- Aliases: toolchain-gcc-glibc-x86_64, toolchain-x86_64, toolchain
-- These aliases allow shorter or alternative names for the same
-- toolchain. The default "toolchain" alias lets system-base and
-- build-deps reference this as the system's default compiler.
--
-- Requires: binutils, gcc, glibc, gmp, mpfr, mpc, isl, linux-headers,
--           zlib, libstdcpp
--
-- Apps (issue #38): gcc, g++, and the toolchain alias itself, so
-- `shuttle pod add toolchain` works. The apps are what make the meta
-- pod-installable in the first place: the farm exposes app commands,
-- and the commands must exist in THIS payload — a meta's requires
-- payloads never surface as another package's farm entries.
--
-- Payload shape — a self-contained toolchain tree at toolchain/:
-- the build copies the merged build prefix (the requires' payloads,
-- /shuttle-build-prefix) wholesale into $STAGE/toolchain/, so the
-- tree carries the SAME layout the gcc build was configured against:
-- usr/{bin,lib,libexec,include}, usr/lib64, and the runtime lib64/
-- (ld-linux, libc.so.6) that glibc's absolute-path libc.so linker
-- script references under a sysroot.
--
-- Launchers, not raw binaries (issue #37 assembly + #46 gap): the app
-- commands are sh scripts AT the toolchain/ root. The farm assembly
-- captures every payload entry under the command binary's directory,
-- so a launcher at toolchain/gcc assembles the ENTIRE toolchain/ tree
-- beside itself — a raw usr/bin/gcc command would assemble only the
-- usr/bin siblings and strand usr/libexec (cc1) and lib64. Each
-- launcher resolves its real dir at run time (readlink -f through the
-- farm symlink), execs the staged driver, and:
--   --sysroot="$d"      — the driver was configured with
--                         --with-sysroot=/shuttle-build-prefix, which
--                         exists only inside the build sandbox; the
--                         assembled toolchain/ has the same shape, so
--                         the launcher repoints the sysroot at itself
--                         and compiles against the staged glibc and
--                         linux-headers.
--   LD_LIBRARY_PATH=…   — the staged ELFs carry no RUNPATH (removed at
--                         build time, below), so cc1/cc1plus find the
--                         staged libstdc++/libgcc (usr/lib64) and
--                         libgmp/libmpfr/libmpc/libisl (usr/lib) via
--                         the launcher's environment instead of the
--                         host.
--
-- Portability pass (ticket #12 at payload scale): every staged ELF
-- gets its interpreter repointed at /lib64/ld-linux-x86-64.so.2 and
-- its RUNPATH dropped — a nix-toolchain build bakes /nix/store paths
-- into both, and only the app commands get the mechanical repair.
-- patchelf failures on non-ELFs are silenced; the || true keeps the
-- chain green for exactly those files.
--
-- The staged tree is stripped: GCC installs with full -g debug info
-- and unstripped cc1/cc1plus would bloat every pod that carries this
-- package. strip lives in the staged binutils, ahead on PATH.
--
-- source: the harness requires a fetchable source whenever `build` is
-- set; the build stages nothing from it. Reuse the smallest
-- already-pinned pool tarball (dcg, from pkgs/d/dcg.lua) — the same
-- fixture pattern as test-fixtures/toolchain-*-probe.lua.
--
-- The staged payload is content-addressed per file on pod install, so
-- files shared with the requires' own payloads (glibc, binutils, gcc…)
-- dedupe in the pod store — the meta adds no second copy of a byte.

return {
    default = snap {
        name = "toolchain-gcc-gnu-x86_64",
        version = "14.2.0",
        summary = "GCC toolchain (GNU libc, x86_64)",
        description = [[
            Complete GCC toolchain targeting x86_64-linux-gnu.
            Includes GCC C/C++ compiler, binutils (assembler, linker),
            glibc runtime, and all supporting libraries (gmp, mpfr, mpc).
            Stages a self-contained toolchain/ tree whose gcc, g++ and
            toolchain commands drive a hermetic C/C++ build from a pod
            farm or serve as a build_deps toolchain.
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
            "binutils", "gcc", "glibc", "linux-headers",
            "gmp", "mpfr", "mpc", "isl", "zlib", "libstdcpp",
        },

        source = {
            url = "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/v0.14.1/dcg-x86_64-unknown-linux-musl.tar.xz",
            sha256 = "e7b39be070ad98f74a1edd59fefb8ac41865ab2aa2c5a4252eb71c5413f3f9df",
        },

        -- Stage the merged prefix whole, make every staged ELF portable
        -- (ticket #12 applies to app commands mechanically; the staged
        -- cc1/cc1plus need the same treatment from the recipe), strip
        -- it, and author the three root launchers. printf lines stay
        -- single-quoted with no nesting so the sandbox preflight reads
        -- them cleanly (the go.lua pattern); $() interiors are runtime
        -- sub-commands.
        build = table.concat({
            "mkdir -p $STAGE/toolchain",
            "cp -a /shuttle-build-prefix/. $STAGE/toolchain/",
            "find $STAGE -type f -exec patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 {} + 2>/dev/null || true",
            "find $STAGE -type f -exec patchelf --remove-rpath {} + 2>/dev/null || true",
            "find $STAGE -type f -exec strip --strip-unneeded {} + 2>/dev/null || true",
            -- gcc driver launcher
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/gcc\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/gcc",
            -- g++ driver launcher
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/g++\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/g++",
            -- the toolchain alias as an app: cc-style face of the driver
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\") || exit 1' 'd=$(dirname -- \"$p\")' 'LD_LIBRARY_PATH=\"$d/usr/lib:$d/usr/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' 'export LD_LIBRARY_PATH' 'exec \"$d/usr/bin/gcc\" --sysroot=\"$d\" \"$@\"' > $STAGE/toolchain/toolchain",
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
