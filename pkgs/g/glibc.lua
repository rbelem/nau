-- glibc: GNU C Library
--
-- Source: https://ftp.gnu.org/gnu/glibc/
-- Provides the GNU C Library, the core system library for Linux.

return {
    default = snap {
        name = "glibc",
        version = "2.43",
        summary = "GNU C Library",
        description = [[
            glibc is the GNU Project's implementation of the C standard
            library. It provides the system call wrappers, standard C
            functions (printf, malloc, etc.), POSIX threading (pthreads),
            dynamic linker (ld-linux), locale support, and name service
            switch (NSS). It is the foundation of all userspace programs
            on a GNU/Linux system.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "linux-headers" },
        source = {
            url = "https://ftp.gnu.org/gnu/glibc/glibc-2.43.tar.xz",
        },
        build = "mkdir build && cd build && ../configure --prefix=/usr --disable-profile --enable-kernel=5.4 && make && make install install_root=$STAGE",
    },
}
