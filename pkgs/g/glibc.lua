-- glibc: GNU C Library
--
-- Source: https://ftp.gnu.org/gnu/glibc/
-- Provides the GNU C Library, the core system library for Linux.

return {
    default = snap {
        name = "glibc",
        version = "2.44",
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
        -- The build tools the sandbox stages for configure/make (the
        -- build/link split, ADR-0018): glibc's configure demands bison and
        -- awk unconditionally (config.status runs awk even with
        -- pre-generated parsers in the tarball), and it needs a compiler
        -- and make to do anything at all. Every one of them requires
        -- glibc back, which used to make this declaration a hard cycle
        -- (glibc → gawk → glibc refused every daily sync, 2026-10-03). The
        -- resolver's host-scoped build view now drops an edge naming the
        -- package under construction (crates/nau-chart/src/deps/build_view.rs,
        -- issue #4), so the tools ride THIS closure without dragging the
        -- pool glibc payload into glibc's own build prefix.
        build_deps = { "gcc", "make", "bison", "gawk" },
        source = {
            url = "https://ftp.gnu.org/gnu/glibc/glibc-2.44.tar.xz",
            sha256 = "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667",
        },
        -- glibc 2.43's sys/mount.h unconditionally redefined OPEN_TREE_CLONE
        -- / OPEN_TREE_CLOEXEC after including <linux/mount.h>, which the pool
        -- linux-headers payload (the kernel UAPI authority) also defines, so
        -- `-Werror` killed the build on "redefined". 2.44 upstreamed the
        -- guard (verified against the 2.44 tree: both definitions sit behind
        -- #ifndef), so this sed is now a no-op. It stays as a guard: a
        -- backport or a downgrade that drops the guard must not resurrect a
        -- silent -Werror failure, and the pattern is idempotent.
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
