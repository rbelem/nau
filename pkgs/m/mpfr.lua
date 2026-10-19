-- mpfr: GNU MPFR — multiple-precision floating-point library
--
-- Source: https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz
return {
    default = snap {
        name = "mpfr",
        version = "4.2.2",
        summary = "GNU MPFR — multiple-precision floating-point",
        description = [[GNU MPFR 4.2.1 is a C library for multiple-precision floating-point
computation with correct rounding. It is based on GMP and provides a
consistent interface for high-precision floating-point arithmetic. MPFR is
a required dependency for GCC's internal computations.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "gmp" },
        source = {
            url = "https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.2.tar.xz",
            sha256 = "b67ba0383ef7e8a8563734e2e889ef5ec3c3b898a01d00fa0a6869ad81c6ce01",
        },
        build = table.concat({
            "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the absolute build-time paths
            -- (dependency_libs) as gmp; nothing consumes libtool archives
            -- at runtime, so strip them (libstdcpp/curl/gmp precedent).
            "find $STAGE -name '*.la' -type f -delete",
            -- The info index is regenerated per-package; strip it so the
            -- merged build prefix stays content-identical (gmp/m4/binutils
            -- precedent).
            "find $STAGE -name 'dir' -path '*/share/info/*' -delete",
        }, " && "),
        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22), same
        -- rationale as libstdcpp/gmp's neighbors: the nix gcc wrapper bakes
        -- RUNPATH=/nau-build-prefix/usr/lib into libmpfr.so (gmp is on
        -- the merged build prefix via requires). That path does not exist
        -- at runtime; silenced, visibly logged, pending issue #22.
        leaks_ok = {
            "/nau-build-prefix/usr/lib",
            "/nau-build-prefix/usr/lib64",
        },
    },
}
