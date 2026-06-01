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
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
