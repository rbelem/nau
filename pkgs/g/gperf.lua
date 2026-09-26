-- gperf: GNU perfect hash function generator.
--
-- Pool port (issue #216): libseccomp 2.6.1's configure hard-errors
-- without gperf (AC_PROG_GPERF-style check, unconditional as_fn_error
-- "please install gperf"; src/Makefile.am regenerates syscalls.perf
-- through arch-gperf-generate). The release tarball's pre-generated
-- artifacts cover autotools regeneration only — the gperf step is a
-- separate gate, so the collection carries the tool and libseccomp
-- lists it in build_deps.
--
-- Build: plain autotools, C++ only — the gcc payload's g++ drives it;
-- the runtime carries glibc + the C++ runtime pair (zg precedent:
-- requires glibc, libstdcpp, libgcc).

return {
    default = snap {
        name = "gperf",
        version = "3.3",
        summary = "GNU perfect hash function generator",
        description = [[
            gperf generates perfect hash functions from a set of
            keywords: given an input list of keys it produces C or C++
            lookup code that recognizes every key with a single hash
            probe and no collisions. Used at build time by consumers
            such as libseccomp 2.6.x, whose configure refuses to run
            without it.
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://ftp.gnu.org/gnu/gperf/gperf-3.3.tar.gz",
            sha256 = "fd87e0aba7e43ae054837afd6cd4db03a3f2693deb3619085e6ed9d8d9604ad8",
        },

        -- The gcc payload's link driver bakes the merged build prefix into
        -- the RUNPATH (same autoconf/binutils/make class); gperf's real
        -- runtime deps are declared above, and the prefix only ever exists
        -- inside build sandboxes where gperf executes.
        leaks_ok = { "/shuttle-build-prefix/usr/lib64", "/shuttle-build-prefix/usr/lib" },
        build = table.concat({
            "./configure --prefix=/usr --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "libstdcpp", "libgcc" },
        build_deps = { "gcc", "make" },

        apps = {
            gperf = app {
                command = "usr/bin/gperf",
            },
        },
    },
}
