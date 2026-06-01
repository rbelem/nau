-- compiler-rt: LLVM compiler runtime — sanitizers and builtins
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/compiler-rt-19.1.7.src.tar.xz
return {
    default = snap {
        name = "compiler-rt",
        version = "19.1.7",
        summary = "LLVM compiler runtime — sanitizers and builtins",
        description = [[Compiler-rt provides runtime libraries for LLVM-based compilers. It
includes builtins that provide low-level target-specific routines such
as soft-float operations, and sanitizer runtimes that detect bugs at
runtime including AddressSanitizer, ThreadSanitizer, and UBSan.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/compiler-rt-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
