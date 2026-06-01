-- libcxxabi: LLVM C++ ABI library
--
-- Source: https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/libcxxabi-19.1.7.src.tar.xz
return {
    default = snap {
        name = "libcxxabi",
        version = "19.1.7",
        summary = "LLVM C++ ABI library",
        description = [[libc++abi provides the low-level runtime support for the C++ exception
handling, RTTI, and dynamic cast mechanisms. It is designed to work
with libc++ and implements the Itanium C++ ABI standard used on most
Unix-like platforms.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-19.1.7/libcxxabi-19.1.7.src.tar.xz" },
        build = "cmake -B build -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 && cmake --build build -j$(nproc) && DESTDIR=$STAGE cmake --install build",
    },
}
