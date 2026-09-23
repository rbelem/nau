-- gcc: GNU Compiler Collection 14.2 (C) for x86_64 — FETCH strategy.
--
-- Issue #164: the gate pod's cargo builds die at build scripts
-- (`failed to find tool "cc"` — zstd-sys et al.) because the pod carries
-- rust but no C toolchain. The old gcc recipe here built GCC 16.1 from
-- source — hours per cold build, useless for pod dogfooding. This recipe
-- instead ports the Debian trixie binary packages (the most widely
-- exercised prebuilt GCC distribution for glibc Linux) as a pure
-- file-copy payload, the same FETCH-not-bootstrap trade rust.lua made
-- for the Rust side (ticket #24).
--
-- Sources: 20 .deb files, ALL pinned to one snapshot.debian.org archive
-- timestamp (20250815T000000Z — trixie/stable state; snapshot URLs are
-- immutable). Hashes are TOFU: each deb was fetched once from that
-- timestamp and the sha256 of the landed bytes recorded here — the same
-- values the trixie Packages index at that timestamp publishes, so the
-- pin is doubly anchored (snapshot immutability + distro metadata).
--
-- Deb set:
--   compiler      gcc-14-x86-64-linux-gnu (driver, x86_64-linux-gnu-gcc-14)
--                 + cpp-14-x86-64-linux-gnu (cc1) + gcc-14 (usr/bin/gcc-14
--                 symlink) + gcc-14-base (docs) + libgcc-14-dev (crt .o,
--                 libgcc.a, gcc include/)
--   c++ compiler  g++-14-x86-64-linux-gnu (cc1plus, x86_64-linux-gnu-
--                 c++-14) + libstdc++-14-dev (headers, static lib) +
--                 libstdc++6 (runtime) — cc-rs probes literal `c++` for
--                 C++ build scripts just like `cc` for C
--   libc headers  linux-libc-dev (asm/, linux/ — the kernel uapi only;
--                 NO libc6-dev: the pod's pool glibc payload owns libc
--                 itself and overlaying Debian's would shadow it)
--   binutils      binutils + binutils-common + binutils-x86-64-linux-gnu
--                 + libbinutils + libsframe1 + libctf0 + libctf-nobfd0
--                 + libjansson4 (as/ld/ar/nm/strip and the shared libs
--                 trixie split out of binutils: libbfd, libctf, libsframe
--                 are ld/as/ar's DT_NEEDED, libjansson4 is ld's; plain
--                 /usr/bin/ar etc. are relative symlinks to the
--                 triplet-prefixed binaries)
--   cc1 runtime   libgmp10, libmpfr6, libmpc3, libisl23, zlib1g,
--                 libzstd1 — cc1's DT_NEEDED beyond libc/libm (verified:
--                 readelf-equivalent over the extracted cc1; without
--                 these the driver runs but every compile dies loading
--                 libisl.so.23). zlib/zstd back LTO bytecode + debug
--                 sections; Debian links them shared.
--
-- Unpack: a .deb is an ar archive wrapping control.tar + data.tar; the
-- data member is what ships. No ar/dpkg-deb exists on the BUILD HOST
-- contract — but the sandbox PATH (verified live by a throwaway probe
-- snap built before this recipe existed: `command -v dpkg-deb` inside
-- bwrap) resolves the nix-profile's busybox `dpkg-deb` applet, whose
-- `-x` extracts data.tar (xz-compressed
-- for these debs) with modes and symlinks intact. Every deb extracts
-- rooted at ./usr (dpkg layout is prefix-clean), so merging is `dpkg-deb
-- -x <deb> $STAGE` per source — same target, later files dedup in
-- squashfs. $SRC/<name> is the raw deb (multi-source lands non-tarballs
-- as files, issue #41).
--
-- requires: glibc (loader + libc.so.6/libm for driver, cc1, binutils)
-- and libgcc (libgcc_s.so.1, DT_NEEDED of the driver and of produced
-- binaries at runtime). Both already ship in the gate pod.
--
-- apps: cc-rs probes the literal `cc` (C build scripts) and `c++` (C++
-- build scripts); gcc-14's binaries are triplet-named drivers, so cc and
-- c++ are declared as apps onto them and land as tree-routed launchers.
-- gcc/g++ stay exposed too. `cc` is the LIBRARY_PATH→-L shim (see build).

return {
    default = snap {
        name = "gcc",
        version = "14.2.0",
        summary = "GNU Compiler Collection 14.2 (C/C++) for x86_64 — Debian trixie payload",
        description = [[
            GCC 14.2 C/C++ compilers (drivers + cc1/cc1plus) with
            binutils, Linux kernel uapi headers, libstdc++, and cc1's
            runtime libraries, merged into a classic /usr prefix layout
            from Debian trixie binary packages (snapshot.debian.org,
            timestamp-pinned). Exposes `cc`, `c++`, `gcc` and `g++` so
            build tools that probe the toolchain by bare name (cargo
            cc-rs, configure, make) resolve it. Pairs with the pool rust
            toolchain in pods: rustc drives, this compiles the C/C++
            build scripts and native deps.
        ]],
        license = "GPL-3.0-or-later WITH GCC-exception-3.1",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc", "libgcc" },

        sources = {
            ["gcc-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "a17ef039f1ba482051c3efb5c2c24070002e60dd0bd09fd456ec31481a11b725",
            },
            ["g++-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/g++-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "c66b009fedd340520279d1af2f91d0668e9f64f0c08fe62179ca1c75e556be58",
            },
            ["libstdc++-14-dev"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++-14-dev_14.2.0-19_amd64.deb",
                sha256 = "4b962fac5f1af0bd8b1b3f97e0f47b9d8e9a79e88802143f00ebfbd78ad87a7b",
            },
            ["libstdc++6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++6_14.2.0-19_amd64.deb",
                sha256 = "ab1fa05837aa7a92aae748fd07a18a35f7d18bb4a71c4724fe2bbf0e32089de0",
            },
            ["cpp-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/cpp-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "ef274b5379f5f97fc71619d39ecc84d039d3e184570d207b909c90afaa5d79e0",
            },
            ["gcc-14"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14_14.2.0-19_amd64.deb",
                sha256 = "21500408b5019d8d29f70ce58488e2eea469a1adb4b5fd7db45e819b5efcac4e",
            },
            ["gcc-14-base"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_amd64.deb",
                sha256 = "5b6825de4263824b78c4c51f6476414f3b4e89c2ab63e81dc8b9b5501e867cf6",
            },
            ["libgcc-14-dev"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libgcc-14-dev_14.2.0-19_amd64.deb",
                sha256 = "ca6f2d36d96b19b3eb71405b0b80134d8c89380b02204a2512e5c58ceb090628",
            },
            ["linux-libc-dev"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/l/linux/linux-libc-dev_6.12.38-1_all.deb",
                sha256 = "85b85662ef28e31364d6b00b041fade0ebcf649a368cc3e7899c2e2b87b77a46",
            },
            binutils = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils_2.44-3_amd64.deb",
                sha256 = "6bc08c02539ba53b5e748142397144c499f9b20b5fa9bb56431545db124addeb",
            },
            ["binutils-common"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-common_2.44-3_amd64.deb",
                sha256 = "002da5d23f8757dee97a2c0a40e0e1d4d85a43da094488ee2ee7068d4d3691f9",
            },
            ["binutils-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-x86-64-linux-gnu_2.44-3_amd64.deb",
                sha256 = "e6741ce95ff0f7a131c8d9faa3528ccbbc453078bbc62a97da81340ed7462c53",
            },
            libbinutils = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libbinutils_2.44-3_amd64.deb",
                sha256 = "4f4664c8a8f0ad0c8631c39fab02e3d8d86ccc6f4436a1d59f059dbcb0492679",
            },
            libsframe1 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libsframe1_2.44-3_amd64.deb",
                sha256 = "38f625dfdc582717029ac3a3e97c51d994ec2e7a0e9b230c6b44e40d1276311f",
            },
            libctf0 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf0_2.44-3_amd64.deb",
                sha256 = "120cafcd93132a276fa92a8fb4cf39b23d14e5a3e348f4f5580638d71ca95ac5",
            },
            ["libctf-nobfd0"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf-nobfd0_2.44-3_amd64.deb",
                sha256 = "e280b2be3db6e584500e865c251605b95c346767d87ccb2524e44992048fc657",
            },
            libjansson4 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/j/jansson/libjansson4_2.14-2+b3_amd64.deb",
                sha256 = "60707a62fe6c1228c3389b12a13ca4efd76defc5532473e547a29e99cf7d2a6e",
            },
            libgmp10 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-3_amd64.deb",
                sha256 = "d0d0265eb01770f17afd0f7c8c0622f80479dcfbbe13653a0debeec61464e622",
            },
            libmpfr6 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-1_amd64.deb",
                sha256 = "75dddce11dabc7fc543712c33dc27b7f2ee66a111763eb5eac654d010b42cd92",
            },
            libmpc3 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-1+b3_amd64.deb",
                sha256 = "2af0a5c128e03694a41c0b011bd8a958b7297436cdb3a15ddad7866dae8c300b",
            },
            libisl23 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/i/isl/libisl23_0.27-1_amd64.deb",
                sha256 = "ac8518042e81c00de1effb72bba7e88ac4ecd488f7ea8b9e3ebc63159cb53b35",
            },
            zlib1g = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_amd64.deb",
                sha256 = "015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d",
            },
            libzstd1 = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_amd64.deb",
                sha256 = "2f6a2aeacfc925eba8b00ac9139bc4bfccf8cacb09eb93de067074b26948eef9",
            },
        },

        -- Pure file-copy: unpack each deb's data.tar into the stage,
        -- merging the dpkg ./usr trees. busybox dpkg-deb -x is the
        -- sandbox's only deb unpacker (see probe note above); -x keeps
        -- modes and relative symlinks (gcc-14 -> x86_64-linux-gnu-gcc-14,
        -- ar -> x86_64-linux-gnu-ar, ...) verbatim.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/gcc-14-x86-64-linux-gnu" "$STAGE"',
            'dpkg-deb -x "$SRC/g++-14-x86-64-linux-gnu" "$STAGE"',
            'dpkg-deb -x "$SRC/libstdc++-14-dev" "$STAGE"',
            'dpkg-deb -x "$SRC/libstdc++6" "$STAGE"',
            'dpkg-deb -x "$SRC/cpp-14-x86-64-linux-gnu" "$STAGE"',
            'dpkg-deb -x "$SRC/gcc-14" "$STAGE"',
            'dpkg-deb -x "$SRC/gcc-14-base" "$STAGE"',
            'dpkg-deb -x "$SRC/libgcc-14-dev" "$STAGE"',
            'dpkg-deb -x "$SRC/linux-libc-dev" "$STAGE"',
            'dpkg-deb -x "$SRC/binutils" "$STAGE"',
            'dpkg-deb -x "$SRC/binutils-common" "$STAGE"',
            'dpkg-deb -x "$SRC/binutils-x86-64-linux-gnu" "$STAGE"',
            'dpkg-deb -x "$SRC/libbinutils" "$STAGE"',
            'dpkg-deb -x "$SRC/libsframe1" "$STAGE"',
            'dpkg-deb -x "$SRC/libctf0" "$STAGE"',
            'dpkg-deb -x "$SRC/libctf-nobfd0" "$STAGE"',
            'dpkg-deb -x "$SRC/libjansson4" "$STAGE"',
            -- cc/c++ shims: the farm LD wrapper exports the pod's lib
            -- dirs as LIBRARY_PATH, which the driver honors for its OWN
            -- file search (startfiles, static libs) but does NOT forward
            -- to the linker as -L. rustc links via rust-lld
            -- (-fuse-ld=lld), whose defaults are the HOST root — dynamic
            -- -lc/-lm/-lstdc++ would resolve against the host, not the
            -- payload (issue #164). The shims translate LIBRARY_PATH
            -- into -L so every link searches the pod's payload dirs, and
            -- dispatch on the invoked name: c++/g++/cxx hit the C++
            -- driver (C++ link spec), everything else the C driver.
            [[cat > "$STAGE/usr/bin/cc" <<'EOF'
#!/bin/sh
d=$(dirname "$(readlink -f "$0")")
l=
ifs=$IFS; IFS=:
for p in $LIBRARY_PATH; do l="$l -L$p"; done
IFS=$ifs
case "${0##*/}" in
  c++|cxx|g++) exec "$d/x86_64-linux-gnu-c++-14" $l "$@" ;;
  *) exec "$d/x86_64-linux-gnu-gcc-14" $l "$@" ;;
esac
EOF
chmod +x "$STAGE/usr/bin/cc" && cp "$STAGE/usr/bin/cc" "$STAGE/usr/bin/c++"]],
            'dpkg-deb -x "$SRC/libgmp10" "$STAGE"',
            'dpkg-deb -x "$SRC/libmpfr6" "$STAGE"',
            'dpkg-deb -x "$SRC/libmpc3" "$STAGE"',
            'dpkg-deb -x "$SRC/libisl23" "$STAGE"',
            'dpkg-deb -x "$SRC/zlib1g" "$STAGE"',
            'dpkg-deb -x "$SRC/libzstd1" "$STAGE"',
            -- The driver must find cc1 (usr/libexec) relative to itself
            -- and as/ld on PATH; assert the spine exists so a failed
            -- extraction cannot silently produce an empty toolchain.
            'test -x "$STAGE/usr/bin/x86_64-linux-gnu-gcc-14"',
            'test -x "$STAGE/usr/bin/cc"',
            'test -x "$STAGE/usr/bin/c++"',
            'test -x "$STAGE/usr/libexec/gcc/x86_64-linux-gnu/14/cc1"',
            'test -e "$STAGE/usr/bin/as"',
            'test -e "$STAGE/usr/bin/ld"',
        }, " && "),

        apps = {
            cc = app {
                command = "usr/bin/cc",
            },
            gcc = app {
                command = "usr/bin/x86_64-linux-gnu-gcc-14",
            },
            cxx = app {
                command = "usr/bin/c++",
            },
            ["c++"] = app {
                command = "usr/bin/c++",
            },
            ["g++"] = app {
                command = "usr/bin/c++",
            },
            ar = app {
                command = "usr/bin/x86_64-linux-gnu-ar",
            },
            as = app {
                command = "usr/bin/x86_64-linux-gnu-as",
            },
            ld = app {
                command = "usr/bin/x86_64-linux-gnu-ld.bfd",
            },
            nm = app {
                command = "usr/bin/x86_64-linux-gnu-nm",
            },
            ranlib = app {
                command = "usr/bin/x86_64-linux-gnu-ranlib",
            },
            strip = app {
                command = "usr/bin/x86_64-linux-gnu-strip",
            },
            objcopy = app {
                command = "usr/bin/x86_64-linux-gnu-objcopy",
            },
            objdump = app {
                command = "usr/bin/x86_64-linux-gnu-objdump",
            },
            readelf = app {
                command = "usr/bin/x86_64-linux-gnu-readelf",
            },
            strings = app {
                command = "usr/bin/x86_64-linux-gnu-strings",
            },
            size = app {
                command = "usr/bin/x86_64-linux-gnu-size",
            },
            addr2line = app {
                command = "usr/bin/x86_64-linux-gnu-addr2line",
            },
        },
    },
}
