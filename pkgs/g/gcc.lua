-- gcc: GNU Compiler Collection 16.2 (C/C++) — FETCH strategy.
--
-- Issue #164: the gate pod's cargo builds die at build scripts
-- (`failed to find tool "cc"` — zstd-sys et al.) because the pod carries
-- rust but no C toolchain. The old gcc recipe here built GCC from
-- source — hours per cold build, useless for pod dogfooding. This recipe
-- instead ports the Debian binary packages (the most widely exercised
-- prebuilt GCC distribution for glibc Linux) as a pure file-copy
-- payload, the same FETCH-not-bootstrap trade rust.lua made for the
-- Rust side (ticket #24).
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
-- snapshot.debian.org archive timestamp (20261001T000000Z — the
-- forky/sid state; snapshot URLs are immutable; the same versions exist
-- for all three ports at that timestamp, binNMU levels included).
-- Hashes are TOFU: each deb's sha256 is the value the forky Packages
-- index at that timestamp publishes for that port (doubly anchored:
-- snapshot immutability + distro metadata), spot-verified by hashing
-- the landed bytes. Source keys are the Debian binary package name;
-- where that name is arch-generic (ships every port), the snap arch is
-- appended with `_` (Debian filename convention: gcc-16_amd64,
-- libstdc++6_arm64, …); triplet-encoding names are unique per port as
-- shipped (gcc-16-x86-64-linux-gnu / gcc-16-aarch64-linux-gnu /
-- gcc-16-arm-linux-gnueabihf).
--
-- Regenerate the table with `scripts/toolchain-debs.sh <stamp> <suite>`
-- rather than editing hashes by hand: the script reads the pinned
-- Packages index and prints the exact `key|arch|url|sha256` rows.
--
-- Deb set, per arch:
--   compiler      gcc-16-<triplet> (driver, <triplet>-gcc-16)
--                 + cpp-16-<triplet> (cc1) + gcc-16 (usr/bin/gcc-16
--                 symlink) + gcc-16-base (docs) + libgcc-16-dev (crt .o,
--                 libgcc.a, gcc include/)
--   c++ compiler  g++-16-<triplet> (cc1plus, driver
--                 <triplet>-g++-16) + libstdc++-16-dev (headers,
--                 static lib) + libstdc++6 (runtime) — cc-rs probes
--                 literal `c++` for C++ build scripts just like `cc`
--                 for C. None of these debs ships a `*-c++-14` binary:
--                 the shim's C++ arm must exec g++-16 (77964ae — the
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
--                 + libbinutils + libsframe3 + libctf0 + libctf-nobfd0
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
-- build scripts); gcc-16's binaries are triplet-named drivers, so cc and
-- c++ are declared as apps onto them and land as tree-routed launchers.
-- gcc/g++ stay exposed too. All four (cc/c++/gcc/g++) route through
-- `usr/bin/cc`, the LIBRARY_PATH→-L shim (see build) — a raw-driver app
-- bypasses the translation and links against the host, the exact #164
-- failure class the shim exists to prevent.

return {
    default = snap {
        name = "gcc",
        version = "16.2.0",
        summary = "GNU Compiler Collection 16.2 (C/C++) for amd64/arm64/armhf — Debian forky payload",
        description = [[
            GCC 16.2 C/C++ compilers (drivers + cc1/cc1plus) with
            binutils, libstdc++, and cc1's runtime libraries, merged
            into a classic /usr prefix layout from Debian forky binary
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
            ["binutils-common_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-common_2.47-6_amd64.deb",
                sha256 = "7021cadc57e5498e1a5f60b5faa0ef1e3f646eee1160cbdb911b85f957583d69",
            },
            ["binutils-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-x86-64-linux-gnu_2.47-6_amd64.deb",
                sha256 = "d0f8cbbd9f4e97ef64f449744fa3fb2ecf22265d4af1af6a2c97d033d2f9084a",
            },
            ["binutils_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils_2.47-6_amd64.deb",
                sha256 = "67939b3141df50584241c74b0040fbf5590de75e5f815cf34e33691d166aa035",
            },
            ["cpp-16-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/cpp-16-x86-64-linux-gnu_16.2.0-3_amd64.deb",
                sha256 = "92e6be944ffb73d903f2250634b93c0b7833b78aaa9d0bf2eaddfb35c76823f0",
            },
            ["g++-16-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/g++-16-x86-64-linux-gnu_16.2.0-3_amd64.deb",
                sha256 = "06db597f0ad4218fc86d26d65f42e7d0a547d1658ddbdb33bd1be467f08898ce",
            },
            ["gcc-16-base_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-base_16.2.0-3_amd64.deb",
                sha256 = "7dcc6404b44ad8a9d58e83c1e987eecb4d6a24623a92438eeb11829ed1129635",
            },
            ["gcc-16-x86-64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-x86-64-linux-gnu_16.2.0-3_amd64.deb",
                sha256 = "25fe5f6f35efd488c544aed90f7328aeeb8692d2cbdda19c90566bd05872fe99",
            },
            ["gcc-16_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16_16.2.0-3_amd64.deb",
                sha256 = "6dcf1ec3ad5f8ffe6c5168abfe449f508a85c2907f01628e36935b994ba7417d",
            },
            ["libbinutils_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libbinutils_2.47-6_amd64.deb",
                sha256 = "f8fe0302786b835fbc362ec7cd6486a2472b68279d2e4f5b95cc8ce5a0656235",
            },
            ["libctf-nobfd0_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf-nobfd0_2.47-6_amd64.deb",
                sha256 = "d5b43ce4fb0846ee63222d36cd4473adbcce5fb12e5be9ef682797a09231a841",
            },
            ["libctf0_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf0_2.47-6_amd64.deb",
                sha256 = "fba2c384caefce9ebe3ba84a7f6714d9e1f1e4c963cf9cd070773e6f009c743e",
            },
            ["libgcc-16-dev_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libgcc-16-dev_16.2.0-3_amd64.deb",
                sha256 = "5c35cbcc5730401d8d427bec286b0515ae5aba496587cfd87e4bd7199c3e9062",
            },
            ["libgmp10_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-5+b2_amd64.deb",
                sha256 = "032743c787f0e1e644e4dcfbdb38f01be8cb150cb9633f8be5e79aba6938f349",
            },
            ["libisl23_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/i/isl/libisl23_0.28-1_amd64.deb",
                sha256 = "feec9d37a3dcdccb0c3846ff96004007c9935363df00f052e6570d35b94deb1c",
            },
            ["libjansson4_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/j/jansson/libjansson4_2.15.1-1_amd64.deb",
                sha256 = "024a1537ca17a8215c7b03c6e84ea961ae96d3ecce9cd1db6a5226c180568419",
            },
            ["libmpc3_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-3_amd64.deb",
                sha256 = "eb6113ed366a8abdea9a85040dbdfabb753a1a0637071491968cf92d4858569c",
            },
            ["libmpfr6_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-3_amd64.deb",
                sha256 = "2beaa9e1f5c842184bfdcf78bd7a3d3e123256b2b5d13a9200d4e8c4bfd15f95",
            },
            ["libsframe3_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libsframe3_2.47-6_amd64.deb",
                sha256 = "36156e7023617de2afc0600d4cc6e08691b21d5cdba749ea90509fce812c299f",
            },
            ["libstdc++-16-dev_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++-16-dev_16.2.0-3_amd64.deb",
                sha256 = "9bbc2704dd8d47fb593f7051cb01c8bdba22e13d817774f771cad854b53c4e49",
            },
            ["libstdc++6_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++6_16.2.0-3_amd64.deb",
                sha256 = "7c9e1a89e6c0b9202699957b469c06d0b86f5c97e86c1ff912b6502ddd8793b6",
            },
            ["libzstd1_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-4_amd64.deb",
                sha256 = "93e7930e4c25b918f1dd980cc1c6d4487654a248f5fa71eacb976ed7bbe954bd",
            },
            ["zlib1g_amd64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.2-3_amd64.deb",
                sha256 = "52c585b07bea72ef36df9ddd5d1937f4739d3caec057d827954baec256292651",
            },
            -- ── arm64 (aarch64-linux-gnu) ──
            ["binutils-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-aarch64-linux-gnu_2.47-6_arm64.deb",
                sha256 = "fd7ef75a2a687bbd138be2fbaeb75dcac48015b7d2becd5ff1f34b97e55a304a",
            },
            ["binutils-common_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-common_2.47-6_arm64.deb",
                sha256 = "74c813c30be16d1534fd3a0b9fea687e13be59c5c1df52d75557b518bacbca6d",
            },
            ["binutils_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils_2.47-6_arm64.deb",
                sha256 = "0c1af5d76275cb25e3e65eaba42cc5cc95cb68af43252ccff1a87a3abd3e9e46",
            },
            ["cpp-16-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/cpp-16-aarch64-linux-gnu_16.2.0-3_arm64.deb",
                sha256 = "f4cdc1228b794bfb3ac63c39002f55c52e7c8fa70b61e77ff57f018e99c53ddb",
            },
            ["g++-16-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/g++-16-aarch64-linux-gnu_16.2.0-3_arm64.deb",
                sha256 = "d333963c3e9086222b4c3ca4a505a1d13a0f990e20ff98d0883ee6e84ce9f179",
            },
            ["gcc-16-aarch64-linux-gnu"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-aarch64-linux-gnu_16.2.0-3_arm64.deb",
                sha256 = "b03c48a9d7a4a7529511a1c2e3ea3be444b17d4d3c00aa1462bb508738ae7ec9",
            },
            ["gcc-16-base_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-base_16.2.0-3_arm64.deb",
                sha256 = "c9c21cce3ac88d1e8bcf1b990c9589cb6ed7cf4cfb84d6eb7efd35a79896251a",
            },
            ["gcc-16_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16_16.2.0-3_arm64.deb",
                sha256 = "19d95fa4d877a41e090f6c08eee65d7d900ee6251e4fb077d0d92c6a1627d400",
            },
            ["libbinutils_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libbinutils_2.47-6_arm64.deb",
                sha256 = "679c6692bc3df294e8f4ea11d4288fb9bfa0485dd201bcfcc36cd86f58e57bb0",
            },
            ["libctf-nobfd0_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf-nobfd0_2.47-6_arm64.deb",
                sha256 = "1a46c6465204546b4fc1ebddfa39e87afb2b9433ddbb13560585f17a31573ea4",
            },
            ["libctf0_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf0_2.47-6_arm64.deb",
                sha256 = "7d8fea5406925d4995569c780631c1de049f52f208881cbf5bba40e353961eed",
            },
            ["libgcc-16-dev_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libgcc-16-dev_16.2.0-3_arm64.deb",
                sha256 = "209b8fb41f83790a585fe0ef8e7b35314b1c49569cccb852d3a443cf163da797",
            },
            ["libgmp10_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-5+b2_arm64.deb",
                sha256 = "ceedd3ac17447facce0de2713b6f99d711fa41e7f26cb278778840054d93b6a7",
            },
            ["libisl23_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/i/isl/libisl23_0.28-1_arm64.deb",
                sha256 = "377640feeb6c196c2f0ab8d66a454ffa285d7b16d1da850a03755a4d1377b4ea",
            },
            ["libjansson4_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/j/jansson/libjansson4_2.15.1-1_arm64.deb",
                sha256 = "c26abc792285fdbb00e82416d46e5419a17556b2afe4d57dab80bcb01eaca5ec",
            },
            ["libmpc3_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-3_arm64.deb",
                sha256 = "855b66dd52b20134276a7a643e888d33c9dda3c797efb3c96cccc40bfc060b6d",
            },
            ["libmpfr6_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-3_arm64.deb",
                sha256 = "26c79fca07f5a357e62a9efd54d35224fcaef4f7456036c47f1ee823e38731f3",
            },
            ["libsframe3_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libsframe3_2.47-6_arm64.deb",
                sha256 = "15e605b7aaaf5dd774abf4b300484fd8324ac9329d832bae234a4585b49c4965",
            },
            ["libstdc++-16-dev_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++-16-dev_16.2.0-3_arm64.deb",
                sha256 = "f83beb28da7dc3004c5f372524a8f0a5dfcd89a4a1f913bc6f73e365a7a66902",
            },
            ["libstdc++6_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++6_16.2.0-3_arm64.deb",
                sha256 = "33c35ea990a913d6e7013d6845b7f4aaed65b70ee01ceb7da86aa25129f866c6",
            },
            ["libzstd1_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-4_arm64.deb",
                sha256 = "e99e6e244d6c80f1c8e96cb68bb04bffc6848b12e3dcc5a35f6a775e4332e936",
            },
            ["zlib1g_arm64"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.2-3_arm64.deb",
                sha256 = "a77a1a137da4f6e440fa638b00a60dc3d7124e9678402ea5335bc02e75bf267e",
            },
            -- ── armhf (arm-linux-gnueabihf) ──
            ["binutils-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-arm-linux-gnueabihf_2.47-6_armhf.deb",
                sha256 = "6d72433167e6caac86efa4999d59853a45627c8de54219bcdde06e813a0bee42",
            },
            ["binutils-common_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils-common_2.47-6_armhf.deb",
                sha256 = "23c8c3dbeb9787b1399895dc57354869da78b1049e8d4ee594e7ca360cd34741",
            },
            ["binutils_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/binutils_2.47-6_armhf.deb",
                sha256 = "9ef7259475475da7ff75aab4e233d66b525e45bd4197145d6d96be782450bafc",
            },
            ["cpp-16-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/cpp-16-arm-linux-gnueabihf_16.2.0-3_armhf.deb",
                sha256 = "1fd1b47bf9f53c27f36ef2069ff5be75649da1657c0f45f9fdfa1f472dc5eed3",
            },
            ["g++-16-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/g++-16-arm-linux-gnueabihf_16.2.0-3_armhf.deb",
                sha256 = "fd24e90aec2d6c79a3fdebb3f2791abd3dcee7d759381df5e219afa00d0967ee",
            },
            ["gcc-16-arm-linux-gnueabihf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-arm-linux-gnueabihf_16.2.0-3_armhf.deb",
                sha256 = "b4da713567729b2aeab0f312e9b7f1e8b1bfbdbbca44c0002edfc1d3ec65cc8a",
            },
            ["gcc-16-base_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16-base_16.2.0-3_armhf.deb",
                sha256 = "cc6b00e400f009614ba90633fbe93885909c4d5f7749555eae0bfdf231aea18e",
            },
            ["gcc-16_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/gcc-16_16.2.0-3_armhf.deb",
                sha256 = "913bd7cf433fd6a4ab70a715b49230dd996bba61418638bcd40d54ea7b57e9ac",
            },
            ["libbinutils_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libbinutils_2.47-6_armhf.deb",
                sha256 = "2e34087f7fecf8518c8a2e945ff229363b45196c008a216061bf90728495f391",
            },
            ["libctf-nobfd0_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf-nobfd0_2.47-6_armhf.deb",
                sha256 = "95fbcd23c9b46ae8b8495e9a18312e6b4fe1dad1a89e4c6a6bb4284675178e4d",
            },
            ["libctf0_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libctf0_2.47-6_armhf.deb",
                sha256 = "2b88470d0ae86d140c6a8da8676d91f57005b465a6ce62ecf359249505d182f7",
            },
            ["libgcc-16-dev_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libgcc-16-dev_16.2.0-3_armhf.deb",
                sha256 = "bb28d47306ca4f50adf7ab1cfc9a769edd1d2c42d5dca5c6b522dd87d9688baf",
            },
            ["libgmp10_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gmp/libgmp10_6.3.0+dfsg-5+b2_armhf.deb",
                sha256 = "d144e5b4c2394a2f1f3d54eed05940ef3e8a886dffa11b9bef84df425c737830",
            },
            ["libisl23_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/i/isl/libisl23_0.28-1_armhf.deb",
                sha256 = "967e3e96bc7ee9677562aae3255831fd3acb02dee0ec2dfd020c031188d873a0",
            },
            ["libjansson4_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/j/jansson/libjansson4_2.15.1-1_armhf.deb",
                sha256 = "8aa63d9574a00d0e95990f506cdb8f2944365fd8cad7cf56137ffde3465bc4fb",
            },
            ["libmpc3_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpclib3/libmpc3_1.3.1-3_armhf.deb",
                sha256 = "b5945ebad72d73f77cfd2bc82b74fb351978dbac078f873cf4e7ae8cf9bcd516",
            },
            ["libmpfr6_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/m/mpfr4/libmpfr6_4.2.2-3_armhf.deb",
                sha256 = "6622bdb62d324c25e243699d819bc9d656da2bb5723c03369459df2edb2c7c7f",
            },
            ["libsframe3_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/b/binutils/libsframe3_2.47-6_armhf.deb",
                sha256 = "815fa241dc34cc4d3d12371066a4fabfdeef3729126f80a890001a2ee7267646",
            },
            ["libstdc++-16-dev_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++-16-dev_16.2.0-3_armhf.deb",
                sha256 = "5ed192dff321222bfb4da4f0f4408874ce41d9d2141024e2fcfd8b798eccaa61",
            },
            ["libstdc++6_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/g/gcc-16/libstdc++6_16.2.0-3_armhf.deb",
                sha256 = "42835d8c6ae00f90a4312244aca70e1b4e456557f4870c43b857a944dce1adda",
            },
            ["libzstd1_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-4_armhf.deb",
                sha256 = "3b854c205a750a873f05213365d1547b03e55b0e564250798934671953bfeed5",
            },
            ["zlib1g_armhf"] = {
                url = "https://snapshot.debian.org/archive/debian/20261001T000000Z/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.2-3_armhf.deb",
                sha256 = "70adf7e7e846b2c039f7ea932781b646a812666e04efc87e7061356143019836",
            },
        },

        -- Pure file-copy: unpack the build arch's deb set's data.tar
        -- members into the stage, merging the dpkg ./usr trees. busybox
        -- dpkg-deb -x is the sandbox's only deb unpacker (see probe note
        -- above); -x keeps modes and relative symlinks (gcc-16 ->
        -- x86_64-linux-gnu-gcc-16, ar -> x86_64-linux-gnu-ar, ...)
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
  "gcc-16-$dt" "g++-16-$dt" "cpp-16-$dt" "binutils-$dt" \
  "gcc-16_$a" "gcc-16-base_$a" "libstdc++-16-dev_$a" "libstdc++6_$a" \
  "libgcc-16-dev_$a" "binutils_$a" "binutils-common_$a" "libbinutils_$a" \
  "libsframe3_$a" "libctf0_$a" "libctf-nobfd0_$a" "libjansson4_$a" \
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
            -- CPATH is translated to -idirafter, never left at -I
            -- position: libstdc++'s cstdlib pulls the C stdlib.h via
            -- #include_next, which only searches dirs AFTER the C++
            -- headers — glibc's include root entering at -I position is
            -- unreachable by include_next and every C++ TU dies on
            -- `stdlib.h: No such file or directory` (the gen-39 shim
            -- carried this loop; the #171 triplet parameterization
            -- dropped it and the gate cargo build caught it).
            -- Empty segments (leading/trailing colon) are skipped: a
            -- bare `-L` is an ld operator that consumes the NEXT token,
            -- not a no-op. The heredoc is UNQUOTED: $t is the build's
            -- triplet (expanded at authoring time, so the shim carries
            -- the literal driver names); \$d/\$l/... stay runtime vars.
            [[cat > "$STAGE/usr/bin/cc" <<EOF
#!/bin/sh
d=\$(dirname "\$(readlink -f "\$0")")
l=
c=
ifs=\$IFS; IFS=:
for p in \$LIBRARY_PATH; do [ -n "\$p" ] && l="\$l -L\$p"; done
for p in \$CPATH; do [ -n "\$p" ] && c="\$c -idirafter \$p"; done
IFS=\$ifs
case "\${0##*/}" in
  c++|cxx|g++) exec "\$d/$t-g++-16" \$l \$c "\$@" ;;
  *) exec "\$d/$t-gcc-16" \$l \$c "\$@" ;;
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
            'test -x "$STAGE/usr/bin/$t-gcc-16"',
            'test -x "$STAGE/usr/bin/cc"',
            'test -x "$STAGE/usr/bin/c++"',
            -- Driver existence alone leaves the 77964ae bug class open:
            -- the shim could still exec anything. Derive every exec
            -- target from the shim text itself and assert each lands
            -- executable — the shim↔payload contract, asserted.
            [[for x in $(sed -n "s/.*exec \"\$d\/\([^\"]*\)\".*/\1/p" "$STAGE/usr/bin/cc"); do test -x "$STAGE/usr/bin/$x" || exit 1; done]],
            'test -x "$STAGE/usr/libexec/gcc/$t/16/cc1"',
            -- The C++ half of the payload must land too (issue #164
            -- follow-up): cc1plus beside cc1, the g++ driver the c++
            -- shim execs, and the runtime libstdc++.so.6 in the
            -- multiarch dir the generation's loader-lib key exposes.
            'test -x "$STAGE/usr/libexec/gcc/$t/16/cc1plus"',
            'test -x "$STAGE/usr/bin/$t-g++-16"',
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
