-- lld: LLVM linker
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/lld-19.1.7.src.tar.xz
return {
    default = snap {
        name = "lld",
        version = "19.1.7",
        summary = "LLVM linker",
        description = [[LLD is a linker from the LLVM project that is a drop-in replacement
for system linkers and runs much faster. It supports ELF, Mach-O,
WebAssembly, and PE/COFF output formats, making it suitable for a
wide range of linking tasks.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/lld-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
