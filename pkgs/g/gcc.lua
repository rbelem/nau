-- gcc: GNU Compiler Collection 14.2 for x86_64
--
-- Source: https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz
return {
    default = snap {
        name = "gcc",
        version = "14.2.0",
        summary = "GNU Compiler Collection 14.2 for x86_64",
        description = [[GCC 14.2.0 is the GNU Compiler Collection, providing front ends for C and
C++ among other languages. This build targets x86_64-linux-gnu with
multilib disabled. It depends on GMP, MPFR, MPC, and ISL for its internal
arithmetic. GCC is the standard system compiler for most Linux distributions.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "binutils", "gmp", "mpfr", "mpc", "isl", "linux-headers" },
        source = { url = "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz" },
        build = "mkdir -p build && cd build && ../configure --prefix=/usr --target=x86_64-linux-gnu --enable-languages=c,c++ --disable-multilib && make -j$(nproc) && make install DESTDIR=$STAGE",
    },
}
