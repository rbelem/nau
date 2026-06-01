-- clang: C language family frontend for LLVM
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/clang-19.1.7.src.tar.xz
return {
    default = snap {
        name = "clang",
        version = "19.1.7",
        summary = "C language family frontend for LLVM",
        description = [[Clang is a compiler front end for the C, C++, Objective-C, and
Objective-C++ programming languages. It uses LLVM as its backend and
provides fast compilation, useful error and warning messages, and a
platform for building source-level tools.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "llvm", "cmake", "ninja" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/clang-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
