-- toolchain-gcc-gnu-x86_64: GCC toolchain for x86_64-linux-gnu
--
-- Aliases: toolchain-gcc-glibc-x86_64, toolchain-x86_64, toolchain
-- These aliases allow shorter or alternative names for the same
-- toolchain. The default "toolchain" alias lets system-base and
-- build-deps reference this as the system's default compiler.
--
-- Requires: binutils, gcc, glibc, gmp, mpfr, mpc, isl, linux-headers,
--           zlib, libstdcpp

return {
    default = snap {
        name = "toolchain-gcc-gnu-x86_64",
        version = "14.2.0",
        summary = "GCC toolchain (GNU libc, x86_64)",
        description = [[
            Complete GCC 14.2 toolchain targeting x86_64-linux-gnu.
            Includes GCC C/C++ compiler, binutils (assembler, linker),
            glibc runtime, and all supporting libraries (gmp, mpfr, mpc).
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        aliases = {
            "toolchain-gcc-glibc-x86_64",
            "toolchain-x86_64",
            "toolchain",
        },
        requires = {
            "binutils", "gcc", "glibc", "linux-headers",
            "gmp", "mpfr", "mpc", "isl", "zlib", "libstdcpp",
        },
    },
}
