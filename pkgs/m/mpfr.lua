-- mpfr: GNU MPFR — multiple-precision floating-point library
--
-- Source: https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz
return {
    default = snap {
        name = "mpfr",
        version = "4.2.1",
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
        source = { url = "https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
