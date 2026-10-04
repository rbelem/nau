-- protobuf: Google's data interchange format — the wire schema
-- compiler (protoc) and the C++ runtime (libprotobuf, libprotoc)
-- the valkey-search chain compiles its generated stubs against.
-- https://github.com/protocolbuffers/protobuf
--
-- Pinned to the v29.0 release tarball — the same source grpc v1.70.1
-- pins in bazel/grpc_deps.bzl: the v29.0 tag dereferences to commit
-- 2d4414f384dc, com_google_protobuf's pin (annotated
-- "protocolbuffers/protobuf/commits/v29.0"), and this tarball is
-- content-identical to that commit's codeload archive (all 3376
-- files diff clean) — no version drift from the tested combination.
-- The release asset is preferred for pin stability: GitHub
-- regenerates codeload archives (grpc keeps a bazel mirror for
-- exactly that reason), release assets are immutable — sha256
-- 10a0d58f…e78c verified here against the fetched bytes. The
-- valkey-search 1.2.1 chain shares the pin — its header records the
-- load-bearing build-time pair "pool protoc 29.0 / grpc 1.70.1".
--
-- Three-way comparison:
--
-- Nix:       pkgs.protobuf (cmake build, abseil package provider)
-- Snapcraft: no upstream recipe; a build dependency, not a snap
-- Nau:   declarative Lua — CMake source build via the sandbox
--            toolchain.
--
-- Port strategy: upstream's cmake/README package build — shared
-- libraries (BUILD_SHARED_LIBS=ON, the distro shape grpc's
-- gRPC_PROTOBUF_PROVIDER=package mode links), tests off, and
-- protobuf_BUILD_LIBPROTOC=ON — the option default is OFF, but
-- protobuf's CMakeLists force-sets it ON whenever
-- protobuf_BUILD_PROTOC_BINARIES is on (this build keeps that
-- default), so the flag only makes the transitive state explicit;
-- it matters because grpc's package mode consumes
-- protobuf::libprotoc when it links grpc_cpp_plugin (grpc
-- cmake/protobuf.cmake:66). protobuf_ABSL_PROVIDER=package resolves
-- abseil from the pool (abseil-cpp 20240722.0, the chain's shared
-- pin) — the tarball does NOT vendor third_party/abseil-cpp (the
-- directory ships empty), so the package provider is mandatory.
-- utf8_range — the C++17 UTF-8 validity kernel libprotobuf
-- unconditionally links — ships populated in-tree
-- (third_party/utf8_range/, identical to the commit archive; neither
-- artifact shape is submodule-hollow), and cmake/utf8_range.cmake
-- FATAL_ERRORs without it. It builds from the vendored copy and
-- installs its config package alongside (utf8_range_ENABLE_INSTALL
-- follows protobuf_INSTALL).
--
-- Stages: usr/bin/protoc (the compiler valkey-search's
-- find_program resolves from the build prefix), usr/lib/lib{protobuf,
-- protobuf-lite,protoc}.so*, the generated well-known-type headers,
-- usr/lib/cmake/{protobuf,utf8_range}/** config packages, and the
-- .pc files.
--
-- KNOWN GAPS (declared, not resolved): the pool abseil is STATIC,
-- so libprotobuf.so bakes its own abseil copy in — the same shape
-- every chain consumer carries (see valkey-search.lua's KNOWN GAPS
-- for the one-copy-per-process caveat).
--
-- Requires: glibc, libstdcpp, libgcc (the C++ runtime closure),
-- zlib (protobuf_WITH_ZLIB — libz is a DT_NEEDED of libprotobuf),
-- abseil-cpp (static, baked in — rides in requires on the grpc
-- port's precedent: payloads merge into the build prefix either
-- way). build_deps: cmake, ninja.

return {
    default = snap {
        name = "protobuf",
        version = "29.0",
        summary = "Google's data interchange format (libprotobuf + protoc)",
        description = [[
            Protocol Buffers is Google's language-neutral,
            platform-neutral mechanism for serializing structured
            data. Built from the v29.0 release — the protobuf pin
            shared by grpc 1.70.1 and the valkey-search module chain
            — as shared libraries, with protoc and the CMake config
            packages consumers' find_package probes expect ship
            alongside.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/protocolbuffers/protobuf/releases/download/v29.0/protobuf-29.0.tar.gz",
            sha256 = "10a0d58f39a1a909e95e00e8ba0b5b1dc64d02997f741151953a2b3659f6e78c",
        },

        -- The sandbox PATH leads with the merged build prefix's
        -- usr/bin (snap.rs build-path contract), so pool cmake/ninja
        -- resolve as bare commands; CMAKE_PREFIX_PATH aims
        -- find_package at the prefix for the package-provider probes
        -- (absl, ZLIB).
        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja "
                .. "-DCMAKE_BUILD_TYPE=Release "
                .. "-DCMAKE_PREFIX_PATH=$NAU_BUILD_PREFIX/usr "
                .. "-DCMAKE_INSTALL_PREFIX=/usr "
                .. "-DCMAKE_INSTALL_LIBDIR=lib "
                .. "-DCMAKE_CXX_STANDARD=17 "
                .. "-DCMAKE_POSITION_INDEPENDENT_CODE=ON "
                .. "-Dprotobuf_BUILD_SHARED_LIBS=ON "
                .. "-Dprotobuf_BUILD_TESTS=OFF "
                .. "-Dprotobuf_BUILD_LIBPROTOC=ON "
                .. "-Dprotobuf_ABSL_PROVIDER=package "
                .. "-Dprotobuf_WITH_ZLIB=ON",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = {
            "glibc",
            "libstdcpp",
            "libgcc",
            "zlib",
            "abseil-cpp",
        },
        build_deps = { "cmake", "ninja" },

        -- ADR-0018 interim escape (libsecret precedent): the nix gcc
        -- wrapper bakes RUNPATH=/nau-build-prefix/usr/lib into
        -- produced shared libs — that path does not exist at pod
        -- runtime. Silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH repair.
        leaks_ok = {
            "/nau-build-prefix/usr/lib",
            "/nau-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/nau-build-prefix",
        },
    },
}
