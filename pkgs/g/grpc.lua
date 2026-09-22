-- gRPC: Google's RPC framework — HTTP/2 multiplexed,
-- protobuf-first, the transport valkey-search's client/server
-- generated stubs speak.
-- https://grpc.io
--
-- Pinned to the v1.70.1 release tag — the version valkey-search
-- 1.2.1 itself pins: its submodules/CMakeLists.txt clones
-- https://github.com/grpc/grpc branch v1.70.1 on the non-system
-- path, and the chain's every leaf pin (abseil 20240722.0, protobuf
-- 2d4414f3, re2 2022-04-01, c-ares 6360e96b, googletest 2dd1c131,
-- benchmark 12235e24) is grpc 1.70.1's own dependency manifest
-- (bazel/grpc_deps.bzl). Tag archive sha256 c4e85806…8e426,
-- verified against the fetched bytes.
--
-- Three-way comparison:
--
-- Nix:       pkgs.grpc (cmake, all package providers)
-- Snapcraft: no upstream recipe; a library/tool dependency
-- Shuttle:   declarative Lua — CMake source build, everything from
--            the pool.
--
-- Port strategy: the full package-provider sweep —
-- gRPC_{SSL,ZLIB,CARES,PROTOBUF,RE2,ABSL}_PROVIDER=package all
-- resolve through the merged build prefix (openssl, zlib, c-ares,
-- protobuf, re2, abseil-cpp pool ports), leaving only grpc's own
-- code plus its vendored third_party/upb to compile. Shared
-- libraries (BUILD_SHARED_LIBS=ON, the distro shape — libsearch.so
-- links grpc++ and a static libgrpc would bake abseil/protobuf
-- copies in twice), gRPC_INSTALL=ON so the CMake config packages
-- land (find_package(gRPC REQUIRED CONFIG) is valkey-search's
-- contract), tests off, C++20 (matches upstream's own module build
-- flags), all language plugins OFF except the C++ codegen plugin —
-- the only one the chain (and the pool) consumes.
--
-- Stages: usr/lib/lib{grpc,grpc++,gpr,address_sorting,...}.so*,
-- usr/bin/grpc_cpp_plugin (the protoc codegen plugin the
-- system-modules path find_program's), the .grpc.{h,cc} generated
-- headers, and usr/lib/cmake/grpc/**.
--
-- KNOWN GAPS (declared, not resolved): the C# extension is off
-- (mono not in the pool); only the C++ plugin is staged — plugins
-- for other languages are build-time dead weight here. The vendored
-- upb is compiled from the tarball's own third_party/upb (no
-- upb package exists or is needed — upstream does not offer a
-- package provider for it in the cmake build).
--
-- Requires: glibc, libstdcpp, libgcc, openssl (TLS via
-- gRPC_SSL_PROVIDER=package), zlib, abseil-cpp, protobuf, re2,
-- c-ares (all shared, all DT_NEEDED through the grpc libs).
-- build_deps: cmake, ninja. No apps beyond the build tool (the
-- plugin is consumed from the build prefix; it is deliberately not
-- surfaced as a pod app).

return {
    default = snap {
        name = "grpc",
        version = "1.70.1",
        summary = "Google's high-performance, open-source RPC framework (C++ core)",
        description = [[
            gRPC is an HTTP/2-based RPC framework with
            protobuf-first interface definitions, deadline/cancel
            propagation, streaming, and pluggable auth. Built from
            the v1.70.1 release — the version valkey-search pins —
            with every third-party dependency resolved from the pool
            (package providers), shared libraries, and the C++
            codegen plugin staged; the CMake config packages
            consumers' find_package probes expect ship alongside.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        -- Six hash-pinned inputs (ADR-0020 `sources` map — the DSL
        -- rejects `source` and `sources` together, so the main tree
        -- is one entry among its proto archives):
        --
        --   grpc        v1.70.1 tag tree (the pin above)
        --   envoy-api   data-plane-api @88a37373e — grpc's own
        --               download_archive pin (sha verified byte-exact
        --               against CMakeLists.txt:404)
        --   googleapis  @fe8ba054ad — same (CMakeLists.txt:424)
        --   opencensus-proto v0.3.0 — same (CMakeLists.txt:444)
        --   xds         @3a472e5248 — same (CMakeLists.txt:477)
        --   protoc-gen-validate v1.0.4 — grpc downloads this one as a
        --               .zip, which the pool's extraction gate does
        --               not carry; the pin is the same tag's tar.gz
        --               with the sha256 computed from the fetched
        --               bytes (92e29c21…a1dd)
        --
        -- The five proto archives exist ONLY to satisfy grpc's cmake
        -- `download_archive` calls (gRPC_DOWNLOAD_ARCHIVES, guarded
        -- by `NOT EXISTS third_party/<dir>`): the build script copies
        -- them into the grpc tree before configure, so the sandbox
        -- never needs the network. They are proto/header sources —
        -- nothing here is compiled into the .so files beyond protoc
        -- generated code.
        sources = {
            grpc = {
                url = "https://github.com/grpc/grpc/archive/refs/tags/v1.70.1.tar.gz",
                sha256 = "c4e85806a3a23fd2a78a9f8505771ff60b2beef38305167d50f5e8151728e426",
            },
            ["envoy-api"] = {
                url = "https://github.com/envoyproxy/data-plane-api/archive/88a37373e3cb5e1ab09e75dfb302b083168e6654.tar.gz",
                sha256 = "aed4389a9cf7777df7811185770dca7352f19a2fd68a41ae04e47071dada31eb",
            },
            googleapis = {
                url = "https://github.com/googleapis/googleapis/archive/fe8ba054ad4f7eca946c2d14a63c3f07c0b586a0.tar.gz",
                sha256 = "0513f0f40af63bd05dc789cacc334ab6cec27cc89db596557cb2dfe8919463e4",
            },
            ["opencensus-proto"] = {
                url = "https://github.com/census-instrumentation/opencensus-proto/archive/v0.3.0.tar.gz",
                sha256 = "b7e13f0b4259e80c3070b583c2f39e53153085a6918718b1c710caf7037572b0",
            },
            xds = {
                url = "https://github.com/cncf/xds/archive/3a472e524827f72d1ad621c4983dd5af54c46776.tar.gz",
                sha256 = "dc305e20c9fa80822322271b50aa2ffa917bf4fd3973bcec52bfc28dc32c5927",
            },
            ["protoc-gen-validate"] = {
                url = "https://github.com/bufbuild/protoc-gen-validate/archive/refs/tags/v1.0.4.tar.gz",
                sha256 = "92e29c2150675ce954c965bcaa559ca944704b75711533cfe03ce541dcf5a1dd",
            },
        },

        build = table.concat({
            -- Materialize the proto archives where grpc's
            -- `NOT EXISTS third_party/<dir>` download guards look for
            -- them (upstream's download_archive layout verbatim — see
            -- the sources map comment). After this, cmake's configure
            -- is fully offline.
            "mkdir -p grpc/third_party/envoy-api grpc/third_party/googleapis grpc/third_party/opencensus-proto grpc/third_party/xds grpc/third_party/protoc-gen-validate",
            "cp -r envoy-api/. grpc/third_party/envoy-api/",
            "cp -r googleapis/. grpc/third_party/googleapis/",
            "cp -r opencensus-proto/. grpc/third_party/opencensus-proto/",
            "cp -r xds/. grpc/third_party/xds/",
            "cp -r protoc-gen-validate/. grpc/third_party/protoc-gen-validate/",
            "cmake -S grpc -B grpc/build -G Ninja "
                .. "-DCMAKE_BUILD_TYPE=Release "
                .. "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr "
                .. "-DCMAKE_INSTALL_PREFIX=/usr "
                .. "-DCMAKE_INSTALL_LIBDIR=lib "
                .. "-DCMAKE_CXX_STANDARD=20 "
                .. "-DCMAKE_POSITION_INDEPENDENT_CODE=ON "
                .. "-DBUILD_SHARED_LIBS=ON "
                .. "-DgRPC_INSTALL=ON "
                .. "-DgRPC_BUILD_TESTS=OFF "
                .. "-DgRPC_BUILD_CSHARP_EXT=OFF "
                .. "-DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF "
                .. "-DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF "
                .. "-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF "
                .. "-DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF "
                .. "-DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF "
                .. "-DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF "
                .. "-DgRPC_SSL_PROVIDER=package "
                .. "-DgRPC_ZLIB_PROVIDER=package "
                .. "-DgRPC_CARES_PROVIDER=package "
                .. "-DgRPC_PROTOBUF_PROVIDER=package "
                .. "-DgRPC_RE2_PROVIDER=package "
                .. "-DgRPC_ABSL_PROVIDER=package",
            "cmake --build grpc/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install grpc/build",
        }, " && "),

        type = "source",
        requires = {
            "glibc",
            "libstdcpp",
            "libgcc",
            "openssl",
            "zlib",
            "abseil-cpp",
            "protobuf",
            "re2",
            "c-ares",
        },
        build_deps = { "cmake", "ninja" },

        -- ADR-0018 interim escape (libsecret precedent): the nix gcc
        -- wrapper bakes RUNPATH=/shuttle-build-prefix/usr/lib into
        -- produced shared libs — that path does not exist at pod
        -- runtime. Silenced here, visibly logged by the leak scan,
        -- pending the RUNPATH repair.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/shuttle-build-prefix",
        },
    },
}
