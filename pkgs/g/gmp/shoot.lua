-- gmp: GNU Multiple Precision Arithmetic Library
--
-- Source: https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
return {
    default = snap {
        name = "gmp",
        version = "6.3.0",
        summary = "GNU Multiple Precision Arithmetic Library",
        description = [[GMP 6.3.0 is a free library for arbitrary precision arithmetic, operating
on signed integers, rational numbers, and floating-point numbers. It provides
a rich set of functions with a regular interface. GMP is a required dependency
for building GCC, MPFR, and MPC.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
