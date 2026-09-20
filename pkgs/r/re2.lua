-- re2: a fast, safe, regular-expression engine — RE2's guarantee is
-- linear-time matching with bounded memory: no exponential backtracking
-- on hostile patterns (the property that makes it the regex engine
-- grpc's own message-size/RE2 filters and gRPC C++ core use).
-- https://github.com/google/re2
--
-- Pinned to the 2022-04-01 release tag — the exact
-- com_googlesource_code_re2 pin in grpc v1.70.1's bazel/grpc_deps.bzl
-- (sha256 1ae8ccfd…50e9, verified against the fetched bytes; the tag
-- archive IS the pin). re2's release cadence is calendar-tagged and
-- its API/ABI is effectively frozen — the old tag is upstream's own
-- choice for this grpc line, not pool laziness.
--
-- Three-way comparison:
--
-- Nix:       pkgs.re2 (cmake build, shared)
-- Snapcraft: no upstream recipe; a library dependency
-- Shuttle:   declarative Lua — CMake source build, shared lib.
--
-- Port strategy: shared library (BUILD_SHARED_LIBS=ON — grpc links
-- re2 from package providers; a static libre2 would get baked into
-- libsearch.so and libgrpc.so twice). This 2022 tag builds against
-- abseil (re2 joined the abseil world in 2022-02): absl from the
-- merged prefix via CMAKE_PREFIX_PATH — the same absl 20240722.0
-- pin the rest of the chain uses; grpc's own bazel graph pairs
-- exactly these two. Installs libre2.so.10*, usr/include/re2/**,
-- the re2 CMake config package and re2.pc — the
-- -DgRPC_RE2_PROVIDER=package probe contract
-- (cmake/FindRE2.cmake uses pkg-config, then the config package).
--
-- KNOWN GAPS (declared, not resolved): none known for the build;
-- upstream's own test suite (re2/testing) is not part of the
-- install target and is not driven here.
--
-- Requires: glibc, libstdcpp, libgcc, abseil-cpp.
-- build_deps: cmake, ninja. No apps.

return {
    default = snap {
        name = "re2",
        version = "2022-04-01",
        summary = "Fast, safe regular-expression engine (grpc's pinned release)",
        description = [[
            RE2 is a regular-expression engine that runs in linear
            time with bounded memory — no backtracking, no
            catastrophic blowups on attacker-controlled patterns.
            Built from the 2022-04-01 release tag grpc 1.70.1 pins,
            as a shared library against the pool abseil, with the
            CMake/pkg-config metadata package-provider consumers
            probe for.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/google/re2/archive/refs/tags/2022-04-01.tar.gz",
            sha256 = "1ae8ccfdb1066a731bba6ee0881baad5efd2cd661acd9569b689f2586e1a50e9",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja " ..
                "-DCMAKE_BUILD_TYPE=Release " ..
                "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr " ..
                "-DCMAKE_INSTALL_PREFIX=/usr " ..
                "-DCMAKE_INSTALL_LIBDIR=lib " ..
                "-DCMAKE_POSITION_INDEPENDENT_CODE=ON " ..
                "-DBUILD_SHARED_LIBS=ON",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc", "libstdcpp", "libgcc", "abseil-cpp" },
        build_deps = { "cmake", "ninja" },

        -- ADR-0018 escape (abseil precedent): exported CMake target
        -- text embeds configure-time absolute paths under the merged
        -- build prefix; silenced by reference.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/shuttle-build-prefix",
        },
    },
}
