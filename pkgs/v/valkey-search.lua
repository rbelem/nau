-- valkey-search: the official vector-similarity + full-text search
-- module for Valkey — hybrid BM25/KNN queries, HNSW and FLAT indexes,
-- JSON documents — loaded at runtime with
-- `valkey-server --loadmodule .../libsearch.so`.
-- https://github.com/valkey-io/valkey-search
--
-- Pinned to the 1.2.1 release tag (tag archive sha256
-- fd4e06de…48a04, verified against the fetched bytes). Requires
-- valkey >= 9.0.1 — the pool valkey is 9.1.2.
--
-- THE un-held port (issue #109): the hold read "its build
-- initializes git submodules (gRPC, Protobuf, Abseil) a GitHub
-- tarball does not contain and the offline sandbox cannot fetch".
-- The un-hold is upstream's own --use-system-modules path:
-- submodules/CMakeLists.txt with -DWITH_SUBMODULES_SYSTEM=ON skips
-- every `git clone` and instead resolves the whole dependency
-- closure from the environment — find_program(protoc, grpc_cpp_plugin),
-- find_path(libhighwayhash.a + highwayhash/highwayhash.h),
-- find_package(benchmark), find_package(GTest CONFIG),
-- find_package(absl|protobuf|gRPC REQUIRED CONFIG) — every one of
-- which the pool now provides through this chain: abseil-cpp,
-- c-ares, googletest, google-benchmark, highwayhash, protobuf, re2,
-- grpc (each pinned to grpc 1.70.1's own dependency manifest, the
-- version valkey-search itself pins), plus libgomp (upstream
-- hardcodes -fopenmp; the proven build carries no GOMP refs — see
-- KNOWN GAPS).
--
-- Three-way comparison:
--
-- Nix:       no nixpkgs package (upstream ships a container image;
--            the module is loaded INTO valkey-server)
-- Snapcraft: no upstream snapcraft recipe
-- Shuttle:   declarative Lua — CMake source build; the module is a
--            payload FILE (usr/lib/libsearch.so), not a runnable app.
--
-- Port strategy (two-stage build, mirroring ./build.sh
-- --use-system-modules):
--
--   1. ICU from the IN-TREE source (third_party/icu/source — the
--      tarball vendors it; upstream's CMake refuses to configure
--      without the pre-built static libs): autoconf configure →
--      `make PKGDATA_MODE=static` → install into
--      $SRC/build-release/icu/install — exactly the path
--      third_party/icu/CMakeLists.txt probes
--      (${CMAKE_BINARY_DIR}/icu/install/lib/libicudata.a).
--      The tarball's configure is pre-generated, so only make is
--      needed, no autotools.
--   2. cmake -DWITH_SUBMODULES_SYSTEM=ON -DBUILD_UNIT_TESTS=OFF,
--      generator Ninja, prefix paths at the merged build prefix,
--      SAN_BUILD=no exported — build.sh sets exactly that (line 14)
--      and the CMake files read it as $ENV{SAN_BUILD} to gate the
--      benchmark probe (find_package(benchmark REQUIRED) in
--      submodules/CMakeLists.txt and linux_utils.cmake fires only
--      when it is lowercased "no"). find_program resolves
--      protoc/grpc_cpp_plugin from the prefix's usr/bin (the
--      sandbox PATH leads with it). Note: submodules/CMakeLists.txt
--      runs find_program(git REQUIRED) unconditionally even on this
--      path — pool git rides in build_deps to satisfy the probe.
--   3. The build root emits libsearch.so; staged to
--      usr/lib/libsearch.so.
--
-- BUILD_UNIT_TESTS=OFF skips valkey-search's own test binaries;
-- find_package(GTest CONFIG REQUIRED) still runs (every internal
-- static library links GTest::gtest for gtest_prod.h) — googletest
-- stays a build_dep. highwayhash/google-benchmark are static,
-- build-time-only archives by their ports' design; protobuf/grpc/
-- re2/openssl/zlib are the shared-lib runtime closure. abseil is
-- the exception in requires: the pool abseil-cpp is STATIC (its
-- port's deliberate shape), so libsearch.so carries its own baked-in
-- copy and no libabsl .so exists — it rides in requires on the grpc
-- port's precedent (payloads merge into the build prefix either
-- way), not because a runtime .so resolves.
--
-- KNOWN GAPS (declared, not resolved):
--   * libgomp: upstream still hardcodes -fopenmp on every target
--     (cmake/Modules/valkey_search.cmake), but the 1.2.1 module
--     BUILT HERE carries zero GOMP_/omp_* references and no
--     libgomp.so.1 DT_NEEDED (measured on the proven snap — no
--     OpenMP constructs survive to the runtime with the pool
--     toolchain's --as-needed). The libgomp port stays in requires
--     as belt-and-braces for a future release that does emit GOMP
--     refs; it is inert payload today.
--   * The module's generated protobuf code is produced by the pool
--     protoc 29.0/grpc 1.70.1 at BUILD time (the same
--     compiler/plugin pair upstream's container build pins) — the
--     generated stubs are not committed upstream, so this build
--     step is load-bearing, not cosmetic.
--   * The integration-test suite is not run (it drives a live
--     valkey-server + module round-trips; the pool has no test
--     harness for pod-internal daemons yet).
--   * The pool abseil is static while grpc is shared, so one
--     process holds two abseil copies when the module loads
--     (libsearch.so's own baked-in copy + libgrpc.so's embedded
--     one) — abseil's own docs call one-copy-per-process the
--     supported shape. Upstream's system-modules path expects the
--     distro shape (shared absl everywhere) where both resolve to
--     the same .so. Proving load-time behavior needs a live
--     valkey-server round-trip — same gap as the integration suite;
--     flipping pool abseil to shared is the structural fix and a
--     chain-wide change out of this port's scope.
--
-- Requires: glibc, libstdcpp, libgcc, libgomp, abseil-cpp,
-- protobuf, grpc, re2, openssl, zlib. protobuf/grpc/re2/openssl/
-- zlib are the DT_NEEDED closure; abseil rides in requires on the
-- grpc port's precedent (its pool shape is static — see above).
-- build_deps: cmake, ninja, make (ICU), git (unconditional
-- find_program probe), highwayhash, googletest, google-benchmark.
-- No apps: a loadable module is not runnable.

return {
    default = snap {
        name = "valkey-search",
        version = "1.2.1",
        summary = "Vector-similarity and full-text search module for Valkey (libsearch.so)",
        description = [[
            valkey-search adds vector similarity search (HNSW/FLAT
            KNN), hybrid BM25 + KNN queries, and JSON document
            storage to Valkey as a runtime module. Built from the
            1.2.1 release through upstream's system-modules path —
            every dependency resolved from the pool (grpc 1.70.1
            and its pinned protobuf/abseil/re2/c-ares, highwayhash,
            benchmark, gtest), no network at build time. The payload
            is the libsearch.so module file; load it with
            valkey-server --loadmodule.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/valkey-io/valkey-search/archive/refs/tags/1.2.1.tar.gz",
            sha256 = "fd4e06de95994dbc3f713c4211d535051896407e32fdf476b36a81baff148a04",
        },

        build = table.concat({
            -- Stage 1: ICU static libs from the in-tree source,
            -- build.sh's build_icu_if_needed verbatim (static data
            -- packaging, tools enabled, out-of-tree build) — the
            -- install prefix is the exact path third_party/icu/
            -- CMakeLists.txt probes relative to CMAKE_BINARY_DIR.
            "mkdir -p $SRC/build-release/icu && cd $SRC/build-release/icu",
            "$SRC/third_party/icu/source/configure --enable-static " ..
                "--disable-shared --with-data-packaging=static " ..
                "--disable-extras --disable-icuio --disable-layout " ..
                "--disable-tests --disable-samples --enable-tools " ..
                "--prefix=$SRC/build-release/icu/install " ..
                "CFLAGS=\"-O2 -fPIC\" CXXFLAGS=\"-O2 -fPIC\"",
            "make PKGDATA_MODE=static -j$(nproc)",
            "make install PKGDATA_MODE=static",
            -- Stage 2: the module itself, system-modules path.
            "cd $SRC",
            -- Sandbox gap: the pool GCC dropped the transitive
            -- <mutex> include; upstream 1.2.1 text_index.h uses
            -- std::mutex/std::lock_guard without including it, so the
            -- cold build dies at ninja ("'mutex' in namespace 'std'
            -- does not name a type"). Inject the include as line 1 —
            -- pragma-once headers tolerate an include above the guard.
            "sed -i \"1i#include <mutex>\" $SRC/src/indexes/text/text_index.h",
            -- Sandbox gap: the sandbox has no /etc/os-release, and
            -- submodules/CMakeLists.txt:7 unconditionally reads it to
            -- derive DISTRO_NAME — used ONLY for an alpine-specific
            -- sed patch on the non-system (git-clone) path, which
            -- WITH_SUBMODULES_SYSTEM never reaches. Seed the variable
            -- so the probe is a no-op instead of two configure
            -- errors. (Colon delimiters, not slashes/pipes: the
            -- sandbox tool preflight splits command segments on the
            -- sed-script pipes otherwise.)
            "sed -i \"7s:.*:set(OS_RELEASE x):\" $SRC/submodules/CMakeLists.txt",
            -- SAN_BUILD=no: build.sh exports exactly this before
            -- configure (lines 14/163); the CMake files gate the
            -- benchmark probe on lowercased $ENV{SAN_BUILD} — without
            -- it find_package(benchmark REQUIRED) silently never
            -- fires (see header).
            "SAN_BUILD=no cmake -S $SRC -B $SRC/build-release -G Ninja " ..
                "-DCMAKE_BUILD_TYPE=Release " ..
                "-DCMAKE_POLICY_VERSION_MINIMUM=3.5 " ..
                "-DBUILD_UNIT_TESTS=OFF " ..
                "-DWITH_SUBMODULES_SYSTEM=ON " ..
                "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr " ..
                "-DCMAKE_INSTALL_PREFIX=/usr",
            "cmake --build $SRC/build-release -j$(nproc)",
            "install -Dm755 $SRC/build-release/libsearch.so $STAGE/usr/lib/libsearch.so",
        }, " && "),

        type = "source",
        requires = {
            "glibc", "libstdcpp", "libgcc", "libgomp",
            "abseil-cpp", "protobuf", "grpc", "re2", "openssl", "zlib",
        },
        build_deps = {
            "cmake", "ninja", "make", "git",
            "highwayhash", "googletest", "google-benchmark",
        },

        -- ADR-0018 interim escape (libsecret precedent): the nix gcc
        -- wrapper bakes RUNPATH=/shuttle-build-prefix/usr/lib into
        -- the produced module — dead at pod runtime, visibly logged
        -- by the leak scan, pending the RUNPATH repair.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/shuttle-build-prefix",
        },
    },
}
