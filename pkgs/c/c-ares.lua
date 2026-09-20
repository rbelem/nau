-- c-ares: an asynchronous resolver library — the DNS engine under
-- curl, libssh and gRPC's own client channels.
-- https://c-ares.org/
--
-- Pinned to grpc v1.70.1's com_github_cares_cares pin in
-- bazel/grpc_deps.bzl: commit 6360e96b5cf8e5980c887ce58ef727e53d77243a,
-- which git ls-remote peels to the cares-1_19_1 release tag. The
-- commit archive is byte-identical to the grpc bazel-mirror pin
-- (sha256 bf26e5b2…76e3, verified against the fetched bytes), so the
-- chain builds the exact code upstream's own build matrix pins.
--
-- Three-way comparison:
--
-- Nix:       pkgs.c-ares (cmake build; shared by default)
-- Snapcraft: no upstream recipe; a library dependency, not a snap
-- Shuttle:   declarative Lua — CMake source build via the sandbox
--            toolchain, static archive.
--
-- Port strategy: static-only build (CARES_STATIC=ON,
-- CARES_SHARED=OFF) — the single consumer on the valkey-search chain
-- (grpc with -DgRPC_CARES_PROVIDER=package) embeds the archive, and
-- a static-only payload keeps every downstream runtime closure free
-- of a libcares.so entry. The CMake config package
-- (c-ares-config.cmake + libcares.pc) lands under usr/lib for
-- pkg-config/find_package probes.
--
-- Tests are off by default upstream (CARES_BUILD_TESTS falls off
-- without special flags); the tool binaries (adig, ahost) are not
-- staged — no consumer on this chain invokes them and the library is
-- the artifact.
--
-- KNOWN GAPS (declared, not resolved): pinned to the grpc pin
-- (1.19.1, Dec 2023) rather than the newest c-ares release — newer
-- 1.2x lines exist, but the chain's contract is upstream's tested
-- combination; a coordinated bump belongs to a grpc version bump.
--
-- Requires: glibc. build_deps: cmake, ninja. No apps (library port;
-- adig/ahost intentionally not staged — see above).

return {
    default = snap {
        name = "c-ares",
        version = "1.19.1",
        summary = "Asynchronous DNS resolver library (grpc's pinned c-ares)",
        description = [[
            c-ares performs DNS requests and name resolves
            asynchronously without blocking, or synchronously where a
            thread is handy. Built from the commit grpc 1.70.1 pins
            in its dependency manifest (the 1.19.1 release), as a
            static archive with the CMake/pkg-config metadata
            package-provider consumers probe for.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/c-ares/c-ares/archive/6360e96b5cf8e5980c887ce58ef727e53d77243a.tar.gz",
            sha256 = "bf26e5b25e259911914a85ae847b6d723488adb5af4f8bdeb9d0871a318476e3",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja " ..
                "-DCMAKE_BUILD_TYPE=Release " ..
                "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr " ..
                "-DCMAKE_INSTALL_PREFIX=/usr " ..
                "-DCMAKE_INSTALL_LIBDIR=lib " ..
                "-DCARES_STATIC=ON -DCARES_SHARED=OFF",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "cmake", "ninja" },
    },
}
