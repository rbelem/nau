-- toolchain-clang-gnu-x86_64: Clang/LLVM toolchain for x86_64-linux-gnu
--
-- Aliases: toolchain-clang-glibc-x86_64
-- The "clang" variant for projects that prefer LLVM-based compilers.
-- Default "toolchain" alias is owned by toolchain-gcc-gnu-x86_64.
--
-- Requires: llvm, clang, lld, compiler-rt, libcxx, libcxxabi,
--           cmake, ninja, glibc, linux-headers, zlib

return {
    default = snap {
        name = "toolchain-clang-gnu-x86_64",
        version = "19.1.7",
        summary = "Clang/LLVM toolchain (GNU libc, x86_64)",
        description = [[
            Complete Clang/LLVM 19 toolchain targeting x86_64-linux-gnu.
            Includes Clang C/C++/ObjC frontend, LLVM framework, lld
            linker, compiler-rt runtime, and libc++/libc++abi libraries.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        aliases = {
            "toolchain-clang-glibc-x86_64",
        },
        requires = {
            "clang", "llvm", "lld", "compiler-rt",
            "libcxx", "libcxxabi", "cmake", "ninja",
            "glibc", "linux-headers", "zlib",
        },
    },
}
