-- gcc: GNU Compiler Collection 16.1 for x86_64
--
-- Source: https://ftp.gnu.org/gnu/gcc/gcc-16.1.0/gcc-16.1.0.tar.xz
--
-- Hermetic sandbox sysroot (issue #45): the build runs inside `run_bwrapped`,
-- which binds the merged `requires`+`build_deps` prefix read-only at
-- /shuttle-build-prefix. GCC's `fixinc.sh` step (stmp-fixinc) resolves its
-- system-header dir (`BUILD_SYSTEM_HEADER_DIR`) from `SYSTEM_HEADER_DIR`,
-- which for a configured `--target` (host != target → cross) becomes
-- `$(CROSS_SYSTEM_HEADER_DIR) = $(TARGET_SYSTEM_ROOT)$sysroot_headers_suffix
-- $(NATIVE_SYSTEM_HEADER_DIR)` (gcc/configure). With no sysroot that collapses
-- to the absolute default NATIVE_SYSTEM_HEADER_DIR=/usr/include, which does
-- NOT exist in the hermetic NixOS sandbox (run_bwrapped never binds a live
-- /usr/include — the merged prefix is the only header source). Giving gcc an
-- explicit sysroot = the merged prefix makes TARGET_SYSTEM_ROOT=/shuttle-build-prefix
-- and (sysroot_headers_suffix is empty for x86_64-linux — the driver's
-- SYSROOT_HEADERS_SUFFIX_SPEC default) BUILD_SYSTEM_HEADER_DIR resolves to
-- /shuttle-build-prefix/usr/include, where the pool linux-headers actually
-- live. Pool headers ONLY — the sysroot is the hermetic prefix, so no host
-- header can leak in.
--
-- The sysroot ALSO flips inhibit_libc off (gcc/configure: a configured
-- --with-sysroot means the target has a libc), so gcc's own libgcc and
-- libstdc++ compile against the sysroot and need the C library headers
-- (stdio.h etc.). glibc is therefore a `requires`: its payload materializes
-- into the same merged prefix, giving the gcc sysroot its libc headers and
-- libs. Not circular — pool glibc builds with the host toolchain (the
-- sandbox PATH's nix gcc), not with pool gcc.
return {
    default = snap {
        name = "gcc",
        version = "16.1.0",
        summary = "GNU Compiler Collection 16.1 for x86_64",
        description = [[GCC 16.1.0 is the GNU Compiler Collection, providing front ends for C and
C++ among other languages. This build targets x86_64-linux-gnu with
multilib disabled. It depends on GMP, MPFR, MPC, and ISL for its internal
arithmetic. GCC is the standard system compiler for most Linux distributions.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "binutils", "gmp", "mpfr", "mpc", "isl", "linux-headers", "glibc" },
        source = { url = "https://ftp.gnu.org/gnu/gcc/gcc-16.1.0/gcc-16.1.0.tar.xz" },
        build = "mkdir -p build && cd build && ../configure --prefix=/usr --target=x86_64-linux-gnu --enable-languages=c,c++ --disable-multilib --with-sysroot=/shuttle-build-prefix && make -j$(nproc) && make install DESTDIR=$STAGE",
    },
}
