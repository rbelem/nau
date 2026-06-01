-- stage0-gcc: Bootstrap stage 0 — minimal GCC cross-compiler
--
-- Builds a minimal C-only GCC cross-compiler using the host system's
-- existing toolchain. This is the bootstrap entry point — it breaks
-- the circular dependency by producing a working (if unoptimized)
-- cross-compiler that can then rebuild itself in stage 1.
--
-- The host x86_64-linux-gnu toolchain builds a cross-compiler targeting
-- the declared `target` triplet (e.g. x86_64-linux-gnu, aarch64-linux-gnu).
-- Only C language is enabled to minimize build time.
--
-- Stage 1: Full GCC (C/C++) built from stage0 cross-compiler.
-- Stage 2: Rebuild full GCC from stage1 (verification / bootstrap comparison).
--
-- Source: https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz
-- Upstream configure docs: https://gcc.gnu.org/install/configure.html
return {
    default = snap {
        name = "stage0-gcc",
        version = "14.2.0",
        summary = "Bootstrap Stage 0 — minimal C-only GCC cross-compiler from host",
        description = [[
            Bootstrap GCC stage 0 cross-compiler. Built from the host
            compiler with only C language support, no optimization,
            and minimal features. Once this compiler is available, use
            it to build stage1-gcc (full C/C++ toolchain).

            The `target` field controls the cross-compilation triplet.
            Change it to target other architectures.

            Usage:
              stage0  →  minimal C-only cross-compiler (this package)
              stage1  →  full C/C++ cross-compiler from stage0
              stage2  →  rebuild full compiler from stage1 (verification)
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        target = "x86_64-linux-gnu",
        requires = { "binutils", "gmp", "mpfr", "mpc", "isl", "linux-headers" },
        source = { url = "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz" },
        build = [[
            mkdir -p build && cd build && \
            ../configure \
                --prefix=/usr \
                --target=${CONFIGURE_TARGET:-x86_64-linux-gnu} \
                --enable-languages=c \
                --disable-multilib \
                --disable-libssp \
                --disable-libquadmath \
                --disable-libgomp \
                --disable-libatomic \
                --disable-libsanitizer \
                --disable-threads \
                --disable-nls \
                --disable-bootstrap \
                --with-system-zlib \
                --without-headers \
                --with-newlib \
                CFLAGS="-O0 -g0" \
                CXXFLAGS="-O0 -g0" && \
            make -j$(nproc) CFLAGS="-O0 -g0" CXXFLAGS="-O0 -g0" && \
            make install DESTDIR=$STAGE
        ]],
    },
}
