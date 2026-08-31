-- Toolchain Bootstrap Example
--
-- Demonstrates the 3-stage GCC bootstrap process using the shuttle
-- package index. The bootstrap builds a complete cross-compiler
-- toolchain starting from the host system's compiler.
--
-- Bootstrap stages:
--   1. stage0-gcc:  Host compiler → minimal C-only cross-compiler
--   2. stage1-gcc:  Stage0 compiler → full C/C++ cross-compiler
--   3. (optional)   Stage1 compiler → rebuild (verification)
--
-- Usage:
--   # Show the build order (all 20+ deps resolved)
--   shuttle build --order --file examples/packages/toolchain-bootstrap/shuttle.lua
--
--   # Build the full bootstrap
--   shuttle build --file examples/packages/toolchain-bootstrap/shuttle.lua
--
--   # Check deps for the toolchain
--   shuttle deps stage0-gcc --recursive --tree
--
-- After bootstrap, the output toolchain is at:
--   ./stage0-gcc_14.2.0_amd64.snap
--   ./stage1-gcc_14.2.0_amd64.snap
--
-- For cross-compilation targeting aarch64-linux-gnu:
--   edit pkgs/s/stage0-gcc.lua, change `target` to "aarch64-linux-gnu"
--   edit pkgs/s/stage1-gcc.lua, change `target` to "aarch64-linux-gnu"

return {
    -- Stage 0: minimal C-only cross-compiler from host compiler
    ["stage0-gcc"] = snap {
        name = "stage0-gcc",
        version = "14.2.0",
        summary = "Stage 0 — minimal C-only cross-compiler",
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

    -- Stage 1: full C/C++ cross-compiler built from stage0
    ["stage1-gcc"] = snap {
        name = "stage1-gcc",
        version = "14.2.0",
        summary = "Stage 1 — full C/C++ cross-compiler from stage0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        target = "x86_64-linux-gnu",
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
