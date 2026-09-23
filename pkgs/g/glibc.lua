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
            -- The stage dir must exist before glibc's mkinstalldirs runs:
            -- its plain `mkdir` does not -p the install root (issue #164
            -- dogfood: an empty-stage pack with exit 0). Pool convention
            -- (gcc.lua) is mkdir -p first.
            "mkdir -p $STAGE/usr/lib64",
            "sed -i -e '/^#define OPEN_TREE_CLONE[[:space:]]/i #ifndef OPEN_TREE_CLONE' -e '/^#define OPEN_TREE_CLOEXEC[[:space:]]/a #endif' sysdeps/unix/sysv/linux/sys/mount.h",
            "mkdir build",
            "cd build",
            "../configure --prefix=/usr --disable-profile --enable-kernel=5.4",
            "make",
            "make install install_root=$STAGE",
            -- glibc generates its ld scripts (libc.so, libm.so, ...) with
            -- the FINAL rootfs paths baked in (/lib64/libm.so.6, ...).
            -- install_root staging keeps those absolute paths, which only
            -- resolve on the rootfs glibc was staged FOR — a payload
            -- consumer linking via -L/LIBRARY_PATH gets ENOENT from the
            -- GROUP entries instead of the payload (issue #164: the gate
            -- pod's glibc lives at extensions/glibc/usr/usr/lib64).
            -- Rewrite to bare sonames: ld/lld search the -L dirs (pod
            -- link) and their own default dirs (/lib64, /usr/lib64 —
            -- merged-root link), so bare names resolve in both contexts.
            -- Only text \"GNU ld script\" files are touched; ELF .so
            -- files are left byte-identical.
            "for f in $STAGE/usr/lib64/*.so $STAGE/usr/lib/*.so; do if [ -f \"$f\" ] && grep -q 'GNU ld script' \"$f\"; then sed -i -e 's# /lib64/# #g' -e 's# /usr/lib64/# #g' \"$f\"; fi; done",
        }, " && "),
    },
}
