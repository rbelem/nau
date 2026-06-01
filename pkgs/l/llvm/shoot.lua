-- llvm: LLVM compiler framework and code generation
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/llvm-19.1.7.src.tar.xz
return {
    default = snap {
        name = "llvm",
        version = "19.1.7",
        summary = "LLVM compiler framework and code generation",
        description = [[The LLVM Project is a collection of modular and reusable compiler and
toolchain technologies. It includes the LLVM optimizer, code generators
for many architectures, and a linker infrastructure used by many
downstream projects such as Clang and Rust.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/llvm-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
