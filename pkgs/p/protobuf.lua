-- protobuf: Protocol Buffers — Google's language-neutral data
-- serialization (libprotobuf + protoc, the C++ slice).
-- https://protobuf.dev
--
-- Pinned to grpc v1.70.1's com_google_protobuf pin in
-- bazel/grpc_deps.bzl: commit
-- 2d4414f384dc499af113b5991ce3eaa9df6dd931 — the v29.0 line
-- (version.json: protoc 29.0, cpp 5.29.0, dated 2024-11-27). The
-- commit archive is byte-identical to grpc's bazel-mirror pin
-- (sha256 cf2db029…49a5, verified against the fetched bytes). A
-- commit pin, not the v29.0 tag: upstream's grpc_deps.bzl tracks
-- this commit (which carries post-tag fixes on the 29.x branch
-- without a tag of its own), and the chain follows the tested
-- combination.
--
-- utf8_range — the C++17 UTF-8 validity kernel libprotobuf
-- unconditionally links — ships IN this tarball
-- (third_party/utf8_range/ with its own CMakeLists; the source
-- snapshot vendors it in-tree, unlike release-tag archives that
-- carry it as a git submodule and therefore empty in a GitHub
-- tarball). cmake/utf8_range.cmake builds it from there; no second
-- source input is needed.
--
-- Three-way comparison:
--
-- Nix:       pkgs.protobuf (cmake build; shared libs)
-- Snapcraft: no upstream recipe; a library/tool dependency
-- Shuttle:   declarative Lua — CMake source build, shared libs.
--
-- Port strategy: shared libraries
-- (protobuf_BUILD_SHARED_LIBS=ON — the distro shape: grpc, its
-- plugins, and libsearch.so all link libprotobuf, and static would
-- bake four copies in). absl from the merged prefix
-- (protobuf_ABSL_PROVIDER=package) matching grpc's
-- -DgRPC_ABSL_PROVIDER=package, so exactly one abseil ABI exists on
-- the chain. Tests off. zlib (compressed blob support in
-- CodedInputStream) from the package prefix via CPPFLAGS/LDFLAGS
-- probes.
--
-- Stages: usr/bin/protoc (the compiler — surfaced as an app;
-- valkey-search's system-modules path find_program's it from the
-- build prefix), usr/lib/libprotobuf.so.32* +
-- libprotobuf-lite.so.32* + libutf8_range/libutf8_validity, and the
-- protobuf/utf8_range CMake config packages + .pc files under
-- usr/lib — the find_package(protobuf REQUIRED CONFIG) contract.
--
-- KNOWN GAPS (declared, not resolved): language runtimes beyond C++
-- (Java/Python/...) are not built — the chain and the pool consume
-- C++ only; protoc's bundled well-known-type .proto files ARE
-- staged (include/google/protobuf/*.proto) so consumers can compile
-- standard imports offline.
--
-- Requires: glibc, libstdcpp, libgcc, abseil-cpp (shared absl the
-- .so files have DT_NEEDED on), zlib. build_deps: cmake, ninja.

return {
    default = snap {
        name = "protobuf",
        version = "29.0.dev",
        summary = "Protocol Buffers compiler + C++ runtime (grpc's pinned v29.0 line)",
        description = [[
            Protocol Buffers are a language-neutral, platform-neutral
            extensible mechanism for serializing structured data.
            Ships protoc (the .proto compiler) and the shared C++
            runtime (libprotobuf), built from the commit grpc 1.70.1
            pins — the 29.0 line — with abseil from the pool and the
            utf8_range kernel vendored in-tree, exactly as the
            grpc/valkey-search chain consumes them.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/protocolbuffers/protobuf/archive/2d4414f384dc499af113b5991ce3eaa9df6dd931.tar.gz",
            sha256 = "cf2db029202bb8eb1471b9bae387cc475d15d9e99c547e6906155033f81249a5",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja " ..
                "-DCMAKE_BUILD_TYPE=Release " ..
                "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr " ..
                "-DCMAKE_INSTALL_PREFIX=/usr " ..
                "-DCMAKE_INSTALL_LIBDIR=lib " ..
                "-DCMAKE_POSITION_INDEPENDENT_CODE=ON " ..
                "-Dprotobuf_BUILD_TESTS=OFF " ..
                "-Dprotobuf_BUILD_SHARED_LIBS=ON " ..
                "-Dprotobuf_ABSL_PROVIDER=package " ..
                "-Dprotobuf_BUILD_PROTOBUF_BINARIES=ON",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc", "libstdcpp", "libgcc", "abseil-cpp", "zlib" },
        build_deps = { "cmake", "ninja" },

        -- ADR-0018 escape (abseil/glib precedent): the exported
        -- protobuf CMake targets embed configure-time absolute paths
        -- under the merged build prefix; build-time consumers
        -- re-resolve them at the same mount point. Silenced by
        -- reference.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/shuttle-build-prefix",
        },

        apps = {
            protoc = app { command = "usr/bin/protoc" },
        },
    },
}
