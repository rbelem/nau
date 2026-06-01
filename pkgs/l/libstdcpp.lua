-- libstdcpp: GNU Standard C++ Library v3
--
-- Source: https://ftp.gnu.org/gnu/gcc/ (libstdc++ from GCC)
-- Provides the shared library for C++ standard library support.

return {
    default = snap {
        name = "libstdcpp",
        version = "14.2",
        summary = "GNU Standard C++ Library v3",
        description = [[
            libstdc++ is the GNU implementation of the C++ Standard
            Library. It provides the shared library (libstdc++.so) needed
            to run C++ applications. This package builds only the runtime
            library from the GCC source tree.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz",
        },
        build = "mkdir build && cd build && ../libstdc++-v3/configure --prefix=/usr --disable-multilib && make && make install DESTDIR=$STAGE",
    },
}
