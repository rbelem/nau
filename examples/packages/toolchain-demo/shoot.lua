-- toolchain-demo: Compiling with the default toolchain
--
-- Demonstrates how a source package uses the default toolchain
-- (toolchain-gcc-gnu-x86_64) to compile C/C++ code. The toolchain
-- is referenced as a dependency via the `requires` field and the
-- `toolchain` meta-package name.
--
-- The default toolchain provides:
--   - GCC 14.2 (C and C++ compiler)
--   - GNU binutils (assembler, linker, archiver)
--   - glibc (C runtime library)
--   - GMP, MPFR, MPC (arithmetic libraries)
--   - ISL (loop optimization)
--   - Linux kernel headers
--
-- Cross-compilation (for other architectures):
--   Set `target` to change the cross-compilation triplet.
--   Example: target = "aarch64-linux-gnu" for ARM64 builds.
--   The build sandbox sets CC, CXX, LD, AR to the cross-tools.
--
-- Usage:
--   shoot build --file examples/packages/toolchain-demo/shoot.lua
--   → builds hello using the default toolchain
--
--   shoot build --file examples/packages/toolchain-demo/shoot.lua --all
--   → builds all dependencies (toolchain) first, then hello
--
--   shoot build --file examples/packages/toolchain-demo/shoot.lua --order
--   → shows the full dependency tree

return {
    default = snap {
        name = "toolchain-demo",
        version = "0.1.0",
        summary = "Demonstrates building with the default toolchain",
        description = [[
            This example shows how shoot's default toolchain
            (toolchain-gcc-gnu-x86_64) is used to compile source
            packages. The toolchain includes GCC 14.2, binutils,
            glibc, and all supporting libraries.

            The `requires` field lists the toolchain as a dependency.
            The build system resolves it to the full 20+ package
            dependency graph (gcc → mpfr → gmp → ...).

            For cross-compilation, add `target = "aarch64-linux-gnu"`
            to the snap declaration. The build sandbox will set
            CC=aarch64-linux-gnu-gcc, CXX=aarch64-linux-gnu-g++,
            and all related cross-compilation environment variables.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc", "toolchain" },
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            hello = app { command = "bin/hello" },
        },
    },
}
