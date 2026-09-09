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
        -- glibc's sys/mount.h unconditionally redefines OPEN_TREE_CLONE /
        -- OPEN_TREE_CLOEXEC after including <linux/mount.h> when it is
        -- visible. The pool linux-headers <linux/mount.h> (the kernel UAPI
        -- authority) already defines OPEN_TREE_CLONE, so glibc's own
        -- definition triggers `-Werror` "redefined". Guard glibc's
        -- definitions to yield to the kernel header — the same pattern the
        -- header already applies to MOUNT_ATTR_SIZE_VER0 / FSOPEN_CLOEXEC.
        build = table.concat({
            "sed -i -e '/^#define OPEN_TREE_CLONE[[:space:]]/i #ifndef OPEN_TREE_CLONE' -e '/^#define OPEN_TREE_CLOEXEC[[:space:]]/a #endif' sysdeps/unix/sysv/linux/sys/mount.h",
            "mkdir build",
            "cd build",
            "../configure --prefix=/usr --disable-profile --enable-kernel=5.4",
            "make",
            "make install install_root=$STAGE",
        }, " && "),
    },
}
