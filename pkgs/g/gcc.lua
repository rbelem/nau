-- gcc: GNU Compiler Collection 14.2 (C/C++) — FETCH strategy.
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
-- Issue #171: the payload now covers amd64, arm64 and armhf — one deb
-- set per Debian port, same component set each (a build_deps consumer
-- like curl advertises all three arches, so the toolchain must exist on
-- all of them). A build only ever stages its OWN arch's set: the build
-- script selects on the requested architecture (`$CONFIGURE_TARGET`
-- triplet for an explicitly targeted cross build, `uname -m` for a
-- native one — `check_cross_build` guarantees they agree, since a
-- foreign-arch build is refused without a matching target). The other
-- arches' debs still download (sources are not arch-conditional) but
-- are never unpacked into the stage.
--
-- Sources: 66 .deb files (22 per arch), ALL pinned to one
-- snapshot.debian.org archive timestamp (20250815T000000Z —
-- trixie/stable state; snapshot URLs are immutable; the same versions
-- exist for all three ports at that timestamp, binNMU levels included).
-- Hashes are TOFU: each deb's sha256 is the value the trixie Packages
-- index at that timestamp publishes for that port (doubly anchored:
-- snapshot immutability + distro metadata), spot-verified by hashing
-- the landed bytes. Source keys are the Debian binary package name;
-- where that name is arch-generic (ships every port), the snap arch is
-- appended with `_` (Debian filename convention: gcc-14_amd64,
-- libstdc++6_arm64, …); triplet-encoding names are unique per port as
-- shipped (gcc-14-x86-64-linux-gnu / gcc-14-aarch64-linux-gnu /
-- gcc-14-arm-linux-gnueabihf).
--
-- Deb set, per arch:
--   compiler      gcc-14-<triplet> (driver, <triplet>-gcc-14)
--                 + cpp-14-<triplet> (cc1) + gcc-14 (usr/bin/gcc-14
--                 symlink) + gcc-14-base (docs) + libgcc-14-dev (crt .o,
--                 libgcc.a, gcc include/)
--   c++ compiler  g++-14-<triplet> (cc1plus, driver
--                 <triplet>-g++-14) + libstdc++-14-dev (headers,
--                 static lib) + libstdc++6 (runtime) — cc-rs probes
--                 literal `c++` for C++ build scripts just like `cc`
--                 for C. None of these debs ships a `*-c++-14` binary:
--                 the shim's C++ arm must exec g++-14 (77964ae — the
--                 first cut pointed at x86_64-linux-gnu-c++-14, a file
--                 Debian never ships, and every C++ probe died ENOENT).
--   kernel uapi   NONE — the deb set must not restage owned subtrees:
--                 kernel uapi headers (asm/, linux/, asm-generic/) are
--                 owned by the pool `linux-headers` payload, which is in
--                 every merged build prefix that contains gcc (gcc
--                 requires glibc, glibc requires linux-headers — one
--                 owning payload per shared subtree, the same rule as the
--                 NO libc6-dev exclusion below; the linux-libc-dev deb
--                 used to ship asm-generic/errno.h and collided with
--                 linux-headers in the prefix merge, issue #174). A
--                 build-time assertion fails loudly if any future deb in
--                 the set reintroduces uapi paths.
--                 NO libc6-dev either: the pod's pool glibc payload owns
--                 libc itself and overlaying Debian's would shadow it
--   binutils      binutils + binutils-common + binutils-<triplet>
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
-- gcc/g++ stay exposed too. All four (cc/c++/gcc/g++) route through
-- `usr/bin/cc`, the LIBRARY_PATH→-L shim (see build) — a raw-driver app
-- bypasses the translation and links against the host, the exact #164
-- failure class the shim exists to prevent.

return {
    default = snap {
        name = "gcc",
        version = "14.2.0",
        summary = "GNU Compiler Collection 14.2 (C/C++) for amd64/arm64/armhf — Debian trixie payload",
        description = [[
            GCC 14.2 C/C++ compilers (drivers + cc1/cc1plus) with
            binutils, libstdc++, and cc1's runtime libraries, merged
            into a classic /usr prefix layout from Debian trixie binary
            packages (snapshot.debian.org, timestamp-pinned; one deb set
            per port — amd64, arm64, armhf; kernel uapi headers are
            deliberately NOT staged, the pool linux-headers payload owns
            them). Exposes `cc`, `c++`, `gcc` and `g++` so build tools
            that probe the toolchain by bare name (cargo cc-rs,
            configure, make) resolve it. Pairs with the pool rust
            toolchain in pods: rustc drives, this compiles the C/C++
            build scripts and native deps.
        ]],
        license = "GPL-3.0-or-later WITH GCC-exception-3.1",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        type = "source",
        requires = { "glibc", "libgcc" },

        sources = {
            -- ── amd64 (x86_64-linux-gnu) ──
            ["gcc-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "a17ef039f1ba482051c3efb5c2c24070002e60dd0bd09fd456ec31481a11b725",
            },
            ["g++-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/g++-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "c66b009fedd340520279d1af2f91d0668e9f64f0c08fe62179ca1c75e556be58",
            },
            ["cpp-14-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/cpp-14-x86-64-linux-gnu_14.2.0-19_amd64.deb",
                sha256 = "ef274b5379f5f97fc71619d39ecc84d039d3e184570d207b909c90afaa5d79e0",
            },
            ["binutils-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-x86-64-linux-gnu_2.44-3_amd64.deb",
                sha256 = "e6741ce95ff0f7a131c8d9faa3528ccbbc453078bbc62a97da81340ed7462c53",
            },
            ["gcc-14_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14_14.2.0-19_amd64.deb",
                sha256 = "21500408b5019d8d29f70ce58488e2eea469a1adb4b5fd7db45e819b5efcac4e",
            },
            ["gcc-14-base_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_amd64.deb",
                sha256 = "5b6825de4263824b78c4c51f6476414f3b4e89c2ab63e81dc8b9b5501e867cf6",
            },
            ["libstdc++-14-dev_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++-14-dev_14.2.0-19_amd64.deb",
                sha256 = "4b962fac5f1af0bd8b1b3f97e0f47b9d8e9a79e88802143f00ebfbd78ad87a7b",
            },
            ["libstdc++6_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++6_14.2.0-19_amd64.deb",
                sha256 = "ab1fa05837aa7a92aae748fd07a18a35f7d18bb4a71c4724fe2bbf0e32089de0",
            },
            ["libgcc-14-dev_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libgcc-14-dev_14.2.0-19_amd64.deb",
                sha256 = "ca6f2d36d96b19b3eb71405b0b80134d8c89380b02204a2512e5c58ceb090628",
            },
            -- NO linux-libc-dev here (issue #174): it ships the kernel uapi
            -- headers (usr/include/asm-generic/, linux/), which are owned
            -- by the pool linux-headers payload — staging them here made
            -- the merged build prefix fail closed on differing shared
            -- content ("usr/include/asm-generic/errno.h differs between
            -- 'linux-headers' and 'gcc'"). The build asserts the absence.
            ["binutils_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils_2.44-3_amd64.deb",
                sha256 = "6bc08c02539ba53b5e748142397144c499f9b20b5fa9bb56431545db124addeb",
            },
            ["binutils-common_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-common_2.44-3_amd64.deb",
                sha256 = "002da5d23f8757dee97a2c0a40e0e1d4d85a43da094488ee2ee7068d4d3691f9",
            },
            ["libbinutils_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libbinutils_2.44-3_amd64.deb",
                sha256 = "4f4664c8a8f0ad0c8631c39fab02e3d8d86ccc6f4436a1d59f059dbcb0492679",
            },
            ["libsframe1_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libsframe1_2.44-3_amd64.deb",
                sha256 = "38f625dfdc582717029ac3a3e97c51d994ec2e7a0e9b230c6b44e40d1276311f",
            },
            ["libctf0_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf0_2.44-3_amd64.deb",
                sha256 = "120cafcd93132a276fa92a8fb4cf39b23d14e5a3e348f4f5580638d71ca95ac5",
            },
            ["libctf-nobfd0_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf-nobfd0_2.44-3_amd64.deb",
                sha256 = "e280b2be3db6e584500e865c251605b95c346767d87ccb2524e44992048fc657",
            },
            ["libjansson4_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/j/jansson/libjansson4_2.14-2+b3_amd64.deb",
                sha256 = "60707a62fe6c1228c3389b12a13ca4efd76defc5532473e547a29e99cf7d2a6e",
            },
            ["libgmp10_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-3_amd64.deb",
                sha256 = "d0d0265eb01770f17afd0f7c8c0622f80479dcfbbe13653a0debeec61464e622",
            },
            ["libmpfr6_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-1_amd64.deb",
                sha256 = "75dddce11dabc7fc543712c33dc27b7f2ee66a111763eb5eac654d010b42cd92",
            },
            ["libmpc3_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-1+b3_amd64.deb",
                sha256 = "2af0a5c128e03694a41c0b011bd8a958b7297436cdb3a15ddad7866dae8c300b",
            },
            ["libisl23_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/i/isl/libisl23_0.27-1_amd64.deb",
                sha256 = "ac8518042e81c00de1effb72bba7e88ac4ecd488f7ea8b9e3ebc63159cb53b35",
            },
            ["zlib1g_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_amd64.deb",
                sha256 = "015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d",
            },
            ["libzstd1_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_amd64.deb",
                sha256 = "2f6a2aeacfc925eba8b00ac9139bc4bfccf8cacb09eb93de067074b26948eef9",
            },
            -- ── arm64 (aarch64-linux-gnu) — same component set, same
            -- snapshot timestamp (#171); fetched from the trixie
            -- binary-arm64 Packages index at that timestamp ──
            ["binutils_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils_2.44-3_arm64.deb",
                sha256 = "7228716cad15e78d1571f1cd4ec7141f64608790d0fbcba23a07f2eda6298272",
            },
            ["binutils-common_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-common_2.44-3_arm64.deb",
                sha256 = "f2d6b7d0b5521c4c90fc105e32819cd5268c1aa69104173b3fb856595f898249",
            },
            ["libbinutils_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libbinutils_2.44-3_arm64.deb",
                sha256 = "c51c0cc0272202d00fc3e6da8b96bfed2a428c239b689363abddd3bac6bd7a02",
            },
            ["libctf-nobfd0_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf-nobfd0_2.44-3_arm64.deb",
                sha256 = "7b1894cbd09bd59507af259ba680a1f5d3b68c6ba9e5d69508ea2d75b3f01be6",
            },
            ["libctf0_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf0_2.44-3_arm64.deb",
                sha256 = "12cb7df9eafd965c00c38a8720c5b78e7b0106390f69fe180a3b3589f407d550",
            },
            ["libsframe1_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libsframe1_2.44-3_arm64.deb",
                sha256 = "d4a90764fa79858347aaa3197bc4489404f005d9cdbea9b2ec75a607ea5ff518",
            },
            ["gcc-14_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14_14.2.0-19_arm64.deb",
                sha256 = "f4ba77903d7efc3c64c69a8a98c7efa8ea1ae4331521bb74abd76bcc43f1b576",
            },
            ["gcc-14-base_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_arm64.deb",
                sha256 = "34ee90679b018c0e64234747a4c4c0ae6b7f63541115037465a8627c2dfbc594",
            },
            ["libgcc-14-dev_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libgcc-14-dev_14.2.0-19_arm64.deb",
                sha256 = "64b8ebc7182a69aa9525df6eab5e7eb849b947e350d821549f8a8a3e9b19e5ba",
            },
            ["libstdc++-14-dev_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++-14-dev_14.2.0-19_arm64.deb",
                sha256 = "8760122d044cd8eb8c69426311d6b5ce7bb8f0f76e9cda1944d153ae878138f8",
            },
            ["libstdc++6_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++6_14.2.0-19_arm64.deb",
                sha256 = "6669b0c52a2e7c6af9adfdabce3ff6e286065cdfbc7b85280862b5f799daebee",
            },
            ["libgmp10_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-3_arm64.deb",
                sha256 = "a27bbc27f119161ea9702c8dd66f54131cdf0d2ca73000f50ea91ef2fdfef0fb",
            },
            ["libisl23_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/i/isl/libisl23_0.27-1_arm64.deb",
                sha256 = "21c490db3fa5f0a517c55090a199334da6164589772ebd922dff1e569c78515d",
            },
            ["libjansson4_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/j/jansson/libjansson4_2.14-2+b3_arm64.deb",
                sha256 = "7938472b1ddfa8b0c8f58d5f44406ae7a77a342dbb502a02f6bf292b4f853ab0",
            },
            ["libzstd1_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_arm64.deb",
                sha256 = "924540bd59fdbfa77a0604360efdaca54411a43daf11c7e002a3c64791b67448",
            },
            ["libmpc3_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-1+b3_arm64.deb",
                sha256 = "d4cfe026a624e51641c80ef2af77387185714f62f3b5c87035e62d9ed8d9eec1",
            },
            ["libmpfr6_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-1_arm64.deb",
                sha256 = "628a4ef58cc6815880f72e9d3953984a379a017e4042bc575f1fcbf3954d79ac",
            },
            ["zlib1g_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_arm64.deb",
                sha256 = "209aa5cf671e97b9eb0410844fa6df4cae2e75b0c72e7802ab6c8ece13e6ddef",
            },
            ["binutils-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-aarch64-linux-gnu_2.44-3_arm64.deb",
                sha256 = "79cbf1459118bce3535133ffbf1fd2adbd57af65271f95c829af5cfa7f474168",
            },
            ["cpp-14-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/cpp-14-aarch64-linux-gnu_14.2.0-19_arm64.deb",
                sha256 = "8e588ac3efe06f7784b08feac584c70e6965b74c045bae7e4e80bb42938f7dbe",
            },
            ["g++-14-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/g++-14-aarch64-linux-gnu_14.2.0-19_arm64.deb",
                sha256 = "411dac8f1c1d0293e58deddeb170c641ad82c56d51a95f056ee12ba02c24288b",
            },
            ["gcc-14-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-aarch64-linux-gnu_14.2.0-19_arm64.deb",
                sha256 = "5ff736a332ba5d60ad463355ed25c8c39da1281acf9155cc2f8a55fc1d478be8",
            },
            -- binary-armhf Packages index at that timestamp ──
            ["binutils_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils_2.44-3_armhf.deb",
                sha256 = "e57b61b504b6e3ddd82dc9e4fdb869b83a0eebede6271b351bd6092818e17211",
            },
            ["binutils-common_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-common_2.44-3_armhf.deb",
                sha256 = "b2ffd056e42590d15dfa0272434b2e3197e6c9a07a924b4cbb1ed71c88ccb31a",
            },
            ["libbinutils_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libbinutils_2.44-3_armhf.deb",
                sha256 = "5de313f398689cacb7ae45dcddc2fb950302f2f62c0f9c9ab5b9f3221cf6a401",
            },
            ["libctf-nobfd0_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf-nobfd0_2.44-3_armhf.deb",
                sha256 = "1fc02f7503c08091c53e30f9e9f0ee5c6e49f4cf94b1bb866c7fd995bb15b22b",
            },
            ["libctf0_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libctf0_2.44-3_armhf.deb",
                sha256 = "083df3943bdd0a39191a2f763184ab418686ec64163e89cfc5eef49149d35034",
            },
            ["libsframe1_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/libsframe1_2.44-3_armhf.deb",
                sha256 = "1cc6821b6e4619cf9a5467c473445fff23d1c87c754f0b5bad639e31609303a5",
            },
            ["gcc-14_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14_14.2.0-19_armhf.deb",
                sha256 = "d90f54385f550235c66c21f67ceccec1ce291e5fa67f44a94219c3b7718726bc",
            },
            ["gcc-14-base_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_armhf.deb",
                sha256 = "0f702fdd5e5471efda9fece892e09ce73e3447968083e1f8c341f8b66b1fb340",
            },
            ["libgcc-14-dev_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libgcc-14-dev_14.2.0-19_armhf.deb",
                sha256 = "f74912d6d0bc28058471ae7ff98f45edd8d5f6612c903116e218e56d3abbb9d0",
            },
            ["libstdc++-14-dev_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++-14-dev_14.2.0-19_armhf.deb",
                sha256 = "ee738474d840e719905280f62872a5da8c43b01b108b78a3ad10888f55f5cd46",
            },
            ["libstdc++6_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/libstdc++6_14.2.0-19_armhf.deb",
                sha256 = "9c82eecc30961a3da3e062c0dba8ce076736059f4b8e7794c803985e75aea48b",
            },
            ["libgmp10_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-3_armhf.deb",
                sha256 = "b74d0fa0aa9d1e2f7addae5d3c235fc881e1507d98559ab158362bef56877a56",
            },
            ["libisl23_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/i/isl/libisl23_0.27-1_armhf.deb",
                sha256 = "6dbb4b7620d7f220717ed710ebc8a62af5a691131edb9d6d63dbf10fec3b3b86",
            },
            ["libjansson4_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/j/jansson/libjansson4_2.14-2+b3_armhf.deb",
                sha256 = "5c5bb4cbfe1dbbd0d9af7e7fefc5276d18fb48ef9fd5caf698b084a9c0bbd1e5",
            },
            ["libzstd1_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_armhf.deb",
                sha256 = "da5238dd84fc51f782f39d435821bff556409b3dbc82d232e4e81f427fb1ca65",
            },
            ["libmpc3_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-1+b3_armhf.deb",
                sha256 = "d2efdeb151ae18e07d41b08815a9f003c2d93beec13dbcc2b23794a7e6d69665",
            },
            ["libmpfr6_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-1_armhf.deb",
                sha256 = "75b15b85c73d2703b208ac47e5d4f27b81cfbc137e1e39359bb911f8d7c0c482",
            },
            ["zlib1g_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_armhf.deb",
                sha256 = "81c55a59e1570477ecef6a449bf6dce44dad67ba4ce9e04760451d4cfe200534",
            },
            ["binutils-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/b/binutils/binutils-arm-linux-gnueabihf_2.44-3_armhf.deb",
                sha256 = "5eaf974e1374eaa2a7a288cd7fc2104048190495785bbe08e2768b0188c093f4",
            },
            ["cpp-14-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/cpp-14-arm-linux-gnueabihf_14.2.0-19_armhf.deb",
                sha256 = "f08547aa63cb983b8f518f4d937a1f73b18f464f2ac3ecdcc239c933df086e14",
            },
            ["g++-14-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/g++-14-arm-linux-gnueabihf_14.2.0-19_armhf.deb",
                sha256 = "7815d3e654ce282581f33df99dea79abad0ba3b24ba4cae537563774c4d0c729",
            },
            ["gcc-14-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/g/gcc-14/gcc-14-arm-linux-gnueabihf_14.2.0-19_armhf.deb",
                sha256 = "839169ff58363da8cdf0dc3ab7ab91865b25c7147a01fd184bca0103f488c298",
            },
        },

        -- Pure file-copy: unpack the build arch's deb set's data.tar
        -- members into the stage, merging the dpkg ./usr trees. busybox
        -- dpkg-deb -x is the sandbox's only deb unpacker (see probe note
        -- above); -x keeps modes and relative symlinks (gcc-14 ->
        -- x86_64-linux-gnu-gcc-14, ar -> x86_64-linux-gnu-ar, ...)
        -- verbatim. Arch selection: CONFIGURE_TARGET (exported by the
        -- build env for a --target cross build) else uname -m —
        -- check_cross_build has already refused any arch the host cannot
        -- honestly produce, so the two agree with the requested arch.
        -- Every case pattern carries a trailing `*`: the sandbox tool
        -- preflight resolves the first word of each command segment
        -- through PATH, and a bare pattern word like `armv7l` reads as
        -- an unresolvable tool — the wildcard marks it as a glob.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            [[a="" t="" dt=""
case "${CONFIGURE_TARGET:-$(uname -m)}" in
  aarch64*) a=arm64; t=aarch64-linux-gnu; dt=$t ;;
  arm-*|armv7*|armv8*|arm*) a=armhf; t=arm-linux-gnueabihf; dt=$t ;;
  x86_64*|amd64*) a=amd64; t=x86_64-linux-gnu; dt=x86-64-linux-gnu ;;
  *) echo "gcc payload: cannot map build arch '${CONFIGURE_TARGET:-$(uname -m)}' to a deb set" >&2; exit 1 ;;
esac
for p in \
  "gcc-14-$dt" "g++-14-$dt" "cpp-14-$dt" "binutils-$dt" \
  "gcc-14_$a" "gcc-14-base_$a" "libstdc++-14-dev_$a" "libstdc++6_$a" \
  "libgcc-14-dev_$a" "binutils_$a" "binutils-common_$a" "libbinutils_$a" \
  "libsframe1_$a" "libctf0_$a" "libctf-nobfd0_$a" "libjansson4_$a" \
  "libgmp10_$a" "libmpfr6_$a" "libmpc3_$a" "libisl23_$a" \
  "zlib1g_$a" "libzstd1_$a"
do dpkg-deb -x "$SRC/$p" "$STAGE" || exit 1; done]],
            -- Ownership lock (#174): kernel uapi headers belong to the
            -- pool linux-headers payload (transitively in every prefix
            -- carrying gcc, via glibc). No deb in this set may restage
            -- them — fail loudly instead of colliding in the prefix merge.
            'test ! -e "$STAGE/usr/include/asm-generic" || { echo "gcc payload: staged usr/include/asm-generic — kernel uapi is owned by the linux-headers payload; a deb in this set ships uapi headers (issue #174)" >&2; exit 1; }',
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
            -- Empty segments (leading/trailing colon) are skipped: a
            -- bare `-L` is an ld operator that consumes the NEXT token,
            -- not a no-op. The heredoc is UNQUOTED: $t is the build's
            -- triplet (expanded at authoring time, so the shim carries
            -- the literal driver names); \$d/\$l/... stay runtime vars.
            [[cat > "$STAGE/usr/bin/cc" <<EOF
#!/bin/sh
d=\$(dirname "\$(readlink -f "\$0")")
l=
ifs=\$IFS; IFS=:
for p in \$LIBRARY_PATH; do [ -n "\$p" ] && l="\$l -L\$p"; done
IFS=\$ifs
case "\${0##*/}" in
  c++|cxx|g++) exec "\$d/$t-g++-14" \$l "\$@" ;;
  *) exec "\$d/$t-gcc-14" \$l "\$@" ;;
esac
EOF
chmod +x "$STAGE/usr/bin/cc" && cp "$STAGE/usr/bin/cc" "$STAGE/usr/bin/c++"]],
            -- binutils tool shims: the deb set's plain /usr/bin/ar, as,
            -- ld, ... are relative symlinks to triplet binaries whose
            -- DT_NEEDED (libbfd, libopcodes, ...) live in the payload's
            -- multiarch lib dir. A pod run has the farm LD wrapper to
            -- supply it; a MERGED BUILD PREFIX (build_deps consumer,
            -- ADR-0018) has no such wrapper — libtool's first `ar` call
            -- died loading libbfd (#171 gap-3 proof). Each shim self-
            -- locates via readlink -f (works in stage, store blob and
            -- extension layouts alike), prepends its own payload's
            -- multiarch dir to LD_LIBRARY_PATH (never clobbering an
            -- existing one), and execs the triplet binary named after
            -- its own invoked name. Authored per arch ($t bakes the
            -- triplet; everything \$-escaped stays a runtime variable).
            [[for x in ar as ld nm ranlib strip objcopy objdump readelf strings size addr2line; do
  rm -f "$STAGE/usr/bin/$x"
  cat > "$STAGE/usr/bin/$x" <<EOF
#!/bin/sh
d=\$(dirname "\$(readlink -f "\$0")")
n=\${0##*/}
LD_LIBRARY_PATH="\$d/../lib/$t\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
exec "\$d/$t-\$n" "\$@"
EOF
  chmod +x "$STAGE/usr/bin/$x" || exit 1
done]],
            -- The driver must find cc1 (usr/libexec) relative to itself
            -- and as/ld on PATH; assert the spine exists so a failed
            -- extraction cannot silently produce an empty toolchain.
            'test -x "$STAGE/usr/bin/$t-gcc-14"',
            'test -x "$STAGE/usr/bin/cc"',
            'test -x "$STAGE/usr/bin/c++"',
            -- Driver existence alone leaves the 77964ae bug class open:
            -- the shim could still exec anything. Derive every exec
            -- target from the shim text itself and assert each lands
            -- executable — the shim↔payload contract, asserted.
            [[for x in $(sed -n "s/.*exec \"\$d\/\([^\"]*\)\".*/\1/p" "$STAGE/usr/bin/cc"); do test -x "$STAGE/usr/bin/$x" || exit 1; done]],
            'test -x "$STAGE/usr/libexec/gcc/$t/14/cc1"',
            -- The C++ half of the payload must land too (issue #164
            -- follow-up): cc1plus beside cc1, the g++ driver the c++
            -- shim execs, and the runtime libstdc++.so.6 in the
            -- multiarch dir the generation's loader-lib key exposes.
            'test -x "$STAGE/usr/libexec/gcc/$t/14/cc1plus"',
            'test -x "$STAGE/usr/bin/$t-g++-14"',
            'test -e "$STAGE/usr/lib/$t/libstdc++.so.6"',
            'test -e "$STAGE/usr/bin/as"',
            'test -e "$STAGE/usr/bin/ld"',
        }, " && "),

        apps = {
            cc = app {
                command = "usr/bin/cc",
            },
            -- Symmetric with g++: the shim's default arm IS the C
            -- driver, so gcc rides the same LIBRARY_PATH→-L translation
            -- instead of bypassing it via the raw triplet driver.
            gcc = app {
                command = "usr/bin/cc",
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
            -- The binutils apps are arch-neutral on purpose: the recipe
            -- is evaluated once for all arches, so an app command cannot
            -- vary per port — but the payload ships plain /usr/bin/ar,
            -- as, ld, ... (authored as self-locating shims, see build)
            -- in EVERY port, so the same command lands on the right
            -- driver per payload (#171; previously these pointed at
            -- x86_64-linux-gnu-* directly).
            ar = app {
                command = "usr/bin/ar",
            },
            as = app {
                command = "usr/bin/as",
            },
            ld = app {
                command = "usr/bin/ld",
            },
            nm = app {
                command = "usr/bin/nm",
            },
            ranlib = app {
                command = "usr/bin/ranlib",
            },
            strip = app {
                command = "usr/bin/strip",
            },
            objcopy = app {
                command = "usr/bin/objcopy",
            },
            objdump = app {
                command = "usr/bin/objdump",
            },
            readelf = app {
                command = "usr/bin/readelf",
            },
            strings = app {
                command = "usr/bin/strings",
            },
            size = app {
                command = "usr/bin/size",
            },
            addr2line = app {
                command = "usr/bin/addr2line",
            },
        },
    },
}
