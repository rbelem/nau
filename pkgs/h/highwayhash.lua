-- highwayhash: Google's fast, keyed hash function (SipHash-family
-- with SIMD-optimized strong hashing on AVX2/SSE4/NEON ports).
-- https://github.com/google/highwayhash
--
-- Pinned to google/highwayhash master at commit
-- f8381f3331d9c56a9792f9b4a35f61c41108c39e — upstream ships no
-- releases (no tags; the valkey-search non-system path clones
-- `master` bare), so master HEAD at port time IS the release pin
-- here, resolved via git ls-remote and pinned by commit archive.
--
-- Why this port exists: it is the one dependency valkey-search's
-- system-modules path consumes through raw find_path, not
-- find_package (cmake/Modules/submodules/CMakeLists.txt,
-- WITH_SUBMODULES_SYSTEM=ON):
--
--   find_path(LIBHIGHWAYHASH_LIBDIR libhighwayhash.a …)
--   find_path(LIBHIGHWAYHASH_INCLUDE highwayhash/highwayhash.h …)
--
-- and it then imports the archive as an STATIC IMPORTED target. The
-- contract is literally libhighwayhash.a under a lib/ suffix and
-- highwayhash/highwayhash.h under an include root — so this port
-- stages the static archive to usr/lib and the headers to
-- usr/include/highwayhash/.
--
-- Three-way comparison:
--
-- Nix:       no nixpkgs package (upstream has no releases; distros
--            that need it vendor the tree)
-- Snapcraft: no upstream recipe
-- Shuttle:   declarative Lua — CMake source build, hand-staged
--            artifacts.
--
-- Port strategy: upstream's CMakeLists (added for exactly this
-- consumption shape) builds the static archive with -fPIC and AVX2/
-- SSE4.1 sources selected per-arch at configure time — used as-is.
-- The upstream CMake has NO install() rule (the tree predates
-- install hygiene), so the port hand-stages like the valkey port's
-- hand install: libhighwayhash.a → usr/lib, and the public headers
-- (highwayhash/*.h) → usr/include/highwayhash/ — the exact layout
-- both find_path calls above resolve. Test/benchmark binaries from
-- the CMake tree are not staged.
--
-- KNOWN GAPS (declared, not resolved): an unpinned-upstream pin —
-- master moves, and a future valkey-search release may require a
-- newer master; the commit pin holds THIS build reproducible and a
-- re-pin is a one-sha change. Header set is .h-only (the .cc
-- sources stay out of usr/include).
--
-- Requires: nothing at runtime (static archive; the hash code is
-- compiled into consumers). build_deps: cmake, ninja. No apps.

return {
    default = snap {
        name = "highwayhash",
        version = "0.15.master",
        summary = "Google's fast keyed hash (static lib for valkey-search's system-modules path)",
        description = [[
          HighwayHash is a fast, keyed hash function: strong
          (pseudo-random-ish, DoS-resistant unlike plain murmur)
          with SIMD-optimized implementations per CPU port that all
          produce identical results. Built from upstream master at
          the pinned commit as a static archive — upstream ships no
          releases — and staged with the raw libhighwayhash.a +
          highwayhash/*.h layout valkey-search's system-modules
          find_path consumes.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/google/highwayhash/archive/f8381f3331d9c56a9792f9b4a35f61c41108c39e.tar.gz",
            sha256 = "d564c621618ef734e0ae68545f59526e97dfe4912612f80b2b8b9b31b9bb02b5",
        },

        build = table.concat({
            "cmake -S $SRC -B $SRC/build -G Ninja " ..
                "-DCMAKE_BUILD_TYPE=Release " ..
                "-DCMAKE_PREFIX_PATH=$SHUTTLE_BUILD_PREFIX/usr " ..
                "-DCMAKE_INSTALL_PREFIX=/usr",
            "cmake --build $SRC/build -j$(nproc) --target highwayhash",
            -- No upstream install() rule: hand-stage the two
            -- artifacts the WITH_SUBMODULES_SYSTEM find_path probes
            -- for (see header).
            "install -Dm644 $SRC/build/libhighwayhash.a $STAGE/usr/lib/libhighwayhash.a",
            "mkdir -p $STAGE/usr/include",
            "cp -r $SRC/highwayhash $STAGE/usr/include/highwayhash",
            "find $STAGE/usr/include -name '*.cc' -delete",
        }, " && "),

        type = "source",
        requires = {},
        build_deps = { "cmake", "ninja" },
    },
}
