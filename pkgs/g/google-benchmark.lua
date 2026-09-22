-- google-benchmark: a microbenchmark support library — timing
-- harness with statistical output (median/mean/stddev, CPU time,
-- counter registration, comparisons).
-- https://github.com/google/benchmark
--
-- Pinned to grpc v1.70.1's com_github_google_benchmark pin in
-- bazel/grpc_deps.bzl: commit 12235e24652fc7f809373e7c11a5f73c5763fc4c
-- (a main-branch snapshot past v1.8.3 — valkey-search's non-system
-- path clones the v1.8.3 tag from the same line). The commit archive
-- is byte-identical to grpc's bazel-mirror pin (sha256 11f3447…692f,
-- verified against the fetched bytes).
--
-- Why this port exists: valkey-search's system-modules build runs
-- find_package(benchmark REQUIRED) (cmake/Modules/linux_utils.cmake)
-- unless SAN_BUILD is set, and its benchmark targets link
-- benchmark::benchmark_main. The config package under usr/lib/cmake/
-- benchmark is the contract.
--
-- Three-way comparison:
--
-- Nix:       pkgs.google-benchmark (cmake build)
-- Snapcraft: no upstream recipe; a pure build-time dependency
-- Shuttle:   declarative Lua — CMake source build, static archive.
--
-- Port strategy: static library (upstream default,
-- BUILD_SHARED_LIBS=OFF), its own tests and gtest wiring OFF —
-- BENCHMARK_ENABLE_TESTING=OFF (plus BENCHMARK_ENABLE_GTEST_TESTS=OFF
-- for explicitness) drops the googletest dependency entirely, so
-- this port needs no gtest at build time and stays a leaf beside
-- the googletest port rather than depending on it.
-- CMAKE_POSITION_INDEPENDENT_CODE=ON because the archive is linked
-- into shared objects (libsearch.so) — non-PIC static code cannot
-- relocate there. Version sources:
-- none (BENCHMARK_ENABLE_LIBPFM/Downloads all off). C++17 floor;
-- sandbox GCC 15.2 clears it.
--
-- KNOWN GAPS (declared, not resolved): main-branch snapshot, not a
-- release tag — the chain follows grpc's pin; a coordinated bump
-- belongs to a grpc version bump. The benchmark binaries this
-- library builds for consumers are staged per-consumer; none here.
--
-- Requires: glibc. build_deps: cmake, ninja. No apps.

return {
    default = snap {
        name = "google-benchmark",
        version = "1.8.3.post",
        summary = "Google microbenchmark support library (grpc's pinned snapshot)",
        description = [[
          A library to benchmark code snippets, similar to unit
          tests: reports wall/CPU time distributions across
          repetitions with statistical confidence, family-wide
          comparisons, and custom counters. Built from the
          main-branch snapshot grpc 1.70.1 pins (the v1.8.3 line
          valkey-search clones), as a static library with the
          benchmark CMake config package its system-modules build
          probes.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/google/benchmark/archive/12235e24652fc7f809373e7c11a5f73c5763fc4c.tar.gz",
            sha256 = "11f344710a80fd73db0fc686b4fe40867dc34d914d9cdfd7a4b416a65d1e692f",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja "
                .. "-DCMAKE_BUILD_TYPE=Release "
                .. "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr "
                .. "-DCMAKE_INSTALL_PREFIX=/usr "
                .. "-DCMAKE_INSTALL_LIBDIR=lib "
                .. "-DCMAKE_POSITION_INDEPENDENT_CODE=ON "
                .. "-DBENCHMARK_ENABLE_TESTING=OFF "
                .. "-DBENCHMARK_ENABLE_GTEST_TESTS=OFF "
                .. "-DBENCHMARK_DOWNLOAD_DEPENDENCIES=OFF "
                .. "-DBENCHMARK_ENABLE_LIBPFM=OFF",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "cmake", "ninja" },
    },
}
