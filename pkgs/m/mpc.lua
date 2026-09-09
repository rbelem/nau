-- mpc: GNU MPC — complex arithmetic for GCC
--
-- Source: https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz
return {
    default = snap {
        name = "mpc",
        version = "1.3.1",
        summary = "GNU MPC — complex arithmetic for gcc",
        description = [[GNU MPC 1.3.1 is a C library for the arithmetic of complex numbers with
arbitrary precision and correct rounding. It is built on top of GMP and
MPFR and is a required dependency for GCC to perform complex arithmetic
during compilation.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "gmp", "mpfr" },
        source = { url = "https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz" },
        build = table.concat({
            "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the absolute build-time paths
            -- (dependency_libs) as gmp/mpfr; nothing consumes libtool
            -- archives at runtime, so strip them.
            "find $STAGE -name '*.la' -type f -delete",
            -- The install-info step regenerates share/info/dir; strip it so
            -- the merged build prefix stays content-identical (gmp/m4
            -- precedent).
            "find $STAGE -name 'dir' -path '*/share/info/*' -delete",
        }, " && "),
        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as libstdcpp/gmp/mpfr: the nix gcc wrapper bakes
        -- RUNPATH=/shuttle-build-prefix/usr/lib into libmpc.so (gmp/mpfr on
        -- the merged prefix via requires). Silenced, visibly logged, pending
        -- issue #22.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },
    },
}
