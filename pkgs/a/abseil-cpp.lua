-- abseil-cpp: Google's common-libraries collection (strings, time,
-- flags, synchronization, hashing — the C++ foundation the modern
-- Google stack compiles against).
-- https://github.com/abseil/abseil-cpp
--
-- Pinned to the 20240722.0 LTS release. Not an arbitrary choice: it
-- is the exact com_google_absl pin in grpc v1.70.1's
-- bazel/grpc_deps.bzl (sha256 f50e5ac3…d4ae3, verified here against
-- the fetched bytes), and abseil is ABI-frozen per release line —
-- mixing absl versions between grpc and its consumers breaks at link
-- time. The valkey-search chain (issue #109) shares this pin.
--
-- Three-way comparison:
--
-- Nix:       pkgs.abseil-cpp (cmake build; nixpkgs turns shared on)
-- Snapcraft: no upstream recipe; distros carry it as a build
--            dependency, not a user-facing snap
-- Shuttle:   declarative Lua — CMake source build via the sandbox
--            toolchain, static archives (upstream default).
--
-- Port strategy: upstream default flags — static libraries
-- (BUILD_SHARED_LIBS=OFF is abseil's default), tests off
-- (ABSL_BUILD_TESTS default OFF; googletest not needed at build
-- time), ABSL_USE_SYSTEM_FLAGS off. ABSL_PROPAGATE_CXX_STD=ON so
-- consumers compiling against the installed targets inherit the
-- C++17 requirement instead of failing their own default-std
-- builds (grpc 1.70 and valkey-search set C++20 anyway).
--
-- C++17 minimum (abseil 20240722.0's floor); the sandbox toolchain
-- is GCC 15.2 — well above. Installs ~150 static archives plus the
-- absl*/cmake config packages under usr/lib/cmake — the
-- find_package(absl REQUIRED CONFIG) contract valkey-search's
-- system-modules path (cmake/Modules/linux_utils.cmake) consumes.
--
-- KNOWN GAPS (declared, not resolved): none for the build. The
-- archives are static, so this package contributes no runtime
-- linkage of its own — consumers that link absl carry the code in
-- their own binaries; a shared-abseil variant (the distro shape,
-- smaller consumer closures) is a deliberate future flip of
-- BUILD_SHARED_LIBS with its own review of downstream NEEDED lists.
--
-- Requires: glibc (compiled against the pool libc headers).
-- build_deps: cmake, ninja (the generator).
-- No apps: a pure library port (zlib precedent).

return {
    default = snap {
        name = "abseil-cpp",
        version = "20240722.0",
        summary = "Google's C++ common libraries (abseil-cpp LTS 20240722.0)",
        description = [[
            Abseil is Google's open-source collection of C++ library
            code drawn from the heart of Google's foundation: string
            and time utilities, synchronization, hashing, flags, and
            numeric representation. Built from the 20240722.0 LTS tag
            — the abseil pin shared by grpc 1.70.1 and the
            valkey-search module chain — as static libraries with the
            CMake config packages install-side consumers need.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20240722.0.tar.gz",
            sha256 = "f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3",
        },

        -- The sandbox PATH leads with the merged build prefix's
        -- usr/bin (snap.rs build-path contract), so pool cmake/ninja
        -- resolve as bare commands; CMAKE_PREFIX_PATH aims
        -- find_package at the prefix for any package-provider probes.
        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja "
                .. "-DCMAKE_BUILD_TYPE=Release "
                .. "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr "
                .. "-DCMAKE_INSTALL_PREFIX=/usr "
                .. "-DCMAKE_INSTALL_LIBDIR=lib "
                .. "-DCMAKE_POSITION_INDEPENDENT_CODE=ON "
                .. "-DABSL_PROPAGATE_CXX_STD=ON",
            "cmake --build $SRC/build -j$(nproc)",
            "DESTDIR=$STAGE cmake --install $SRC/build",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "cmake", "ninja" },

        -- ADR-0018 escape (gcc/glib precedent, LOAD-BEARING not dead):
        -- abseil's exported CMake targets embed the absolute path of
        -- the configure-time find_library hits — glibc's librt.a
        -- under the merged prefix's lib64 — into abslTargets.cmake.
        -- Every build sandbox mounts the prefix at exactly that
        -- path, so build-time consumers resolve it; at pod runtime
        -- the file is not consulted. Silenced by reference, not by
        -- file.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
            -- Text-leak references carry the BARE prefix marker
            -- (leak_scan record() matches the reference exactly).
            "/shuttle-build-prefix",
        },
    },
}
