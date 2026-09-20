-- libgomp: the GNU OpenMP runtime (libgomp.so.1) — GOMP_* entry
-- points behind -fopenmp.
-- https://gcc.gnu.org/onlinedocs/libgomp/
--
-- Why this port exists: valkey-search's cmake hardcodes
-- -fopenmp on every target (cmake/Modules/valkey_search.cmake,
-- `target_compile_options(${TARGET} PRIVATE -fopenmp)`), so its
-- libsearch.so carries DT_NEEDED libgomp.so.1 and the module dies at
-- dlopen time without it. The pool has no libgomp provider: the full
-- gcc payload (pkgs/g/gcc.lua) does build one, but dragging a
-- compiler into a database pod's runtime tree for a single runtime
-- library is the wrong closure — this port is the libstdcpp pattern
-- (standalone target-library build from the GCC source tree)
-- applied to libgomp.
--
-- Three-way comparison:
--
-- Nix:       part of pkgs.gcc (no standalone split)
-- Snapcraft: no standalone recipe; ships inside the gcc/lib packages
-- Shuttle:   declarative Lua — the libstdcpp pattern: standalone
--            configure of gcc's libgomp/ subtree.
--
-- Port strategy: pinned to the SAME gcc 14.2 release tarball the
-- libstdcpp port already uses (one source in the pool, family
-- coherence; libgomp's GOMP_ ABI is stable and backward compatible —
-- code built against a newer libgomp runs on this). Standalone
-- sub-configure is the documented route for GCC target libraries:
-- the libgomp/ subtree configures with a plain C compiler and
-- pthreads alone (no gthr seeding — libgomp never includes gthr.h;
-- it goes straight to pthread.h). --disable-multilib; the toplevel
-- bootstrap machinery is bypassed entirely.
--
-- Installs usr/lib/libgomp.so.1* + the plugin ABI header under
-- usr/libexec? No — only the runtime library and its symlink; the
-- omp_lib Fortran modules and the plugin headers are not staged
-- (nothing on this chain compiles OpenMP sources against them —
-- consumers compile with the sandbox toolchain's own libgomp
-- headers, only the runtime .so is shared).
--
-- KNOWN GAPS (declared, not resolved): the standalone build does not
-- run upstream's test suite (make check needs the DejaGnu harness
-- the pool does not carry); the artifact is validated by its
-- consumer — valkey-search's module loads and its OpenMP thread
-- teams run (see pkgs/v/valkey-search.lua).
--
-- Requires: glibc. build_deps: none beyond the sandbox toolchain
-- (plain C). No apps.

return {
    default = snap {
        name = "libgomp",
        version = "14.2",
        summary = "GNU OpenMP runtime library (libgomp.so.1)",
        description = [[
            libgomp is the GNU implementation of the OpenMP runtime:
            thread teams, work sharing, synchronization, and device
            hooks behind GOMP_* symbols — the library every
            -fopenmp-compiled binary loads. Built standalone from the
            GCC 14.2 source tree's libgomp subtree (the libstdcpp
            port's pattern), staging only the runtime shared library.
        ]],
        license = "GPL-3.0-or-later WITH GCC-exception-3.1",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz",
            sha256 = "a7b39bc69cbf9e25826c5a60ab26477001f7c08d85cec04bc0e29cabed6f3cc9",
        },
        build = table.concat({
            -- Standalone target-library build: plain C configure,
            -- pthreads only (see header). CPPFLAGS unset guard: the
            -- sandbox exports the merged-prefix -I; harmless here,
            -- but the gcc-family convention is to keep recorded
            -- flags clean of it.
            "mkdir -p build && cd build && ../libgomp/configure --prefix=/usr --disable-multilib CPPFLAGS= && make -j$(nproc) CPPFLAGS= && make CPPFLAGS= install DESTDIR=$STAGE",
            -- libtool's .la metadata records the build-prefix paths
            -- (leak-scan text class) and no consumer on any chain
            -- resolves libraries through libtool archives — drop it.
            "find $STAGE -name '*.la' -delete",
        }, " && "),
    },
}
