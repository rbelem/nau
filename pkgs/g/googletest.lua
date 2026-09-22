-- googletest: Google's C++ testing framework (gtest + gmock).
-- https://github.com/google/googletest
--
-- Pinned to grpc v1.70.1's com_google_googletest pin in
-- bazel/grpc_deps.bzl: commit 2dd1c131950043a8ad5ab0d2dda0e0970596586a
-- (a main-branch snapshot on the 1.16 ABI, post-v1.16.0). The commit
-- archive is byte-identical to grpc's bazel-mirror pin (sha256
-- 31bf78bd…b109, verified against the fetched bytes).
--
-- Why a library-only port needs googletest at all: valkey-search's
-- cmake unconditionally runs find_package(GTest CONFIG REQUIRED)
-- (cmake/Modules/valkey_search.cmake — every internal static library
-- links GTest::gtest for gtest_prod.h inclusion), even with
-- BUILD_UNIT_TESTS=OFF. Without a system GTest config package the
-- system-modules build cannot configure.
--
-- Three-way comparison:
--
-- Nix:       pkgs.gtest (cmake build; shared or static per flag)
-- Snapcraft: no upstream recipe; a pure build-time dependency
-- Shuttle:   declarative Lua — CMake source build, static archives.
--
-- Port strategy: upstream defaults — static libraries
-- (BUILD_SHARED_LIBS=OFF default), gmock built beside gtest
-- (BUILD_GMOCK=ON default) because INSTALL_GTEST installs both
-- config packages from one configure.
-- CMAKE_POSITION_INDEPENDENT_CODE=ON because the archives link into
-- shared objects (libsearch.so) — non-PIC static code cannot
-- relocate there. C++17 floor; the sandbox GCC
-- 15.2 clears it. Installs usr/lib/libgtest*.a/libgmock*.a plus
-- usr/lib/cmake/GTest — the exact find_package(GTest CONFIG)
-- contract valkey-search consumes.
--
-- KNOWN GAPS (declared, not resolved): a main-branch snapshot, not
-- a release tag — that is precisely what grpc pins, and the chain
-- follows upstream's tested combination; a coordinated bump belongs
-- to a grpc version bump. Tests of gtest itself are not built
-- (framework self-tests ship nothing on this chain).
--
-- Requires: glibc. build_deps: cmake, ninja. No apps.

return {
    default = snap {
        name = "googletest",
        version = "0.16.0.dev",
        summary = "Google's C++ testing framework (gtest/gmock, grpc's pinned snapshot)",
        description = [[
          GoogleTest is Google's C++ testing framework: assertions,
          test fixtures, value- and type-parameterized tests, and
          mocks through GoogleMock. Built from the main-branch
          snapshot grpc 1.70.1 pins, as static libraries with the
          GTest CMake config package — the system-GTest contract the
          valkey-search module build requires even with its own test
          targets disabled.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/google/googletest/archive/2dd1c131950043a8ad5ab0d2dda0e0970596586a.tar.gz",
            sha256 = "31bf78bd91b96dd5e24fab3bb1d7f3f7453ccbaceec9afb86d6e4816a15ab109",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja "
                .. "-DCMAKE_BUILD_TYPE=Release "
                .. "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr "
                .. "-DCMAKE_INSTALL_PREFIX=/usr "
                .. "-DCMAKE_INSTALL_LIBDIR=lib "
                .. "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "cmake", "ninja" },
    },
}
