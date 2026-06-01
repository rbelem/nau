-- libcxx: LLVM C++ standard library (libc++)
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/libcxx-19.1.7.src.tar.xz
return {
    default = snap {
        name = "libcxx",
        version = "19.1.7",
        summary = "LLVM C++ standard library (libc++)",
        description = [[libc++ is an implementation of the C++ standard library, targeting
C++11 and above. It provides a high-performance, standards-conformant
implementation of the standard library headers and is the default
C++ library on macOS and many BSDs.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/libcxx-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DLIBCXX_ENABLE_SHARED=ON && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
