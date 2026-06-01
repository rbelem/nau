-- stage1-gcc: Bootstrap stage 1 — full GCC cross-compiler from stage0
--
-- Uses the stage0 cross-compiler to build a full GCC with C and C++
-- support, optimization enabled, and all standard runtime libraries.
-- This is the "self-hosting" step: the stage0 compiler rebuilds GCC
-- with its full feature set.
--
-- Requires: stage0-gcc (provides CC/CXX cross-compiler),
--           binutils (cross-linker, assembler),
--           gmp, mpfr, mpc (arithmetic libraries),
--           isl (loop optimization), linux-headers (kernel headers)
--
-- Stage 2: Rebuild this same package using stage1 as the host
-- compiler. If stage1 and stage2 outputs are identical (or both
-- build successfully), the bootstrap is verified.
--
-- Source: https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz
return {
    default = snap {
        name = "stage1-gcc",
        version = "14.2.0",
        summary = "Bootstrap Stage 1 — full C/C++ cross-compiler from stage0",
        description = [[
            Bootstrap GCC stage 1. Uses the stage0 minimal compiler
            to build a full GCC with C and C++ support, shared
            libraries, threads, and all enabled optimizations.

            The compiler produced here is suitable for building
            system packages. For a verified bootstrap, rebuild this
            same package as stage2 using the stage1 output as host
            compiler — the result should be identical.

            Environment variables set by the build system when
            target is configured:
              CC, CXX, LD, AR, AS, RANLIB, STRIP = <target>-<tool>
              CONFIGURE_TARGET = <triplet>
              CROSS_COMPILE = <triplet>-
              HOST = <triplet>
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        target = "x86_64-linux-gnu",
        toolchain = "stage0-gcc",
        requires = {
            "stage0-gcc", "binutils",
            "gmp", "mpfr", "mpc", "isl", "linux-headers", "zlib",
        },
        source = { url = "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz" },
        build = [[
            mkdir -p build && cd build && \
            ../configure \
                --prefix=/usr \
                --target=${CONFIGURE_TARGET:-x86_64-linux-gnu} \
                --enable-languages=c,c++ \
                --disable-multilib \
                --enable-threads=posix \
                --enable-shared \
                --enable-__cxa_atexit \
                --enable-clocale=gnu \
                --enable-libstdcxx-time=yes \
                --disable-nls \
                --without-included-gettext \
                --with-system-zlib \
                --with-isl \
                CFLAGS="-O2" \
                CXXFLAGS="-O2" && \
            make -j$(nproc) && \
            make install DESTDIR=$STAGE
        ]],
    },
}
