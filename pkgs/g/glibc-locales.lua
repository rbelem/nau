-- glibc-locales: precompiled locale archive for pool glibc.
--
-- Data payload package (no libraries, no apps): builds glibc's
-- localedef from the same glibc release the pool glibc package uses,
-- then compiles a minimal locale set into the standard
-- /usr/lib/locale/locale-archive so setlocale(LC_ALL, "en_US.UTF-8")
-- works in pods without a full distro locale set.
--
-- Requires: nothing. The archive is DATA, consumed by whatever pool
-- glibc the pod pairs with this package — the coupling is by pod
-- composition, not a runtime closure edge. Keeping pool glibc out of
-- `requires` is also what unblocks the build (issue #33): this package
-- builds glibc from source, and a pool glibc payload in the merged
-- build prefix would inject its installed headers (CPPFLAGS) ahead of
-- the build tree, so gen-as-const probes compile against pool glibc
-- and die (-Werror, _LIBC/stubs mismatch). The build tree must win.
-- The build itself needs only the kernel UAPI headers: a build_dep,
-- build-time only, never shipped.

return {
    default = snap {
        name = "glibc-locales",
        version = "2.43",
        summary = "Locale archive for pool glibc (en_US.UTF-8 and friends)",
        description = [[
            Precompiled glibc locale data. Builds localedef from the
            glibc 2.43 source and compiles en_US.UTF-8 and
            en_US.ISO-8859-1 into /usr/lib/locale/locale-archive.
            Install alongside the pool glibc package; C/POSIX and
            C.UTF-8 are built into libc and do not need this archive.
        ]],
        license = "LGPL-2.1-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        source = {
            url = "https://ftp.gnu.org/gnu/glibc/glibc-2.43.tar.xz",
            sha256 = "d9c86c6b5dbddb43a3e08270c5844fc5177d19442cf5b8df4be7c07cd5fa3831",
        },

        build = table.concat({
            -- Same glibc 2.43 source as the pool glibc package: guard
            -- mount.h's unconditional OPEN_TREE_CLONE / OPEN_TREE_CLOEXEC
            -- definitions so they yield to the pool linux-headers
            -- <linux/mount.h> (see pkgs/g/glibc.lua).
            "sed -i -e '/^#define OPEN_TREE_CLONE[[:space:]]/i #ifndef OPEN_TREE_CLONE' -e '/^#define OPEN_TREE_CLOEXEC[[:space:]]/a #endif' sysdeps/unix/sysv/linux/sys/mount.h",
            "mkdir build",
            "cd build && ../configure --prefix=/usr --disable-profile --enable-kernel=5.4",
            "make -j$(nproc)",
            -- Run the freshly built localedef against the source-tree
            -- locale/charmap definitions; --prefix redirects the archive
            -- write into the stage. CWD is the build tree here (the cd
            -- above persists across && segments), so localedef is
            -- ./locale/localedef, and LD_LIBRARY_PATH points the host
            -- loader at the freshly built libc — the host libc carries
            -- different GLIBC_PRIVATE symbols and cannot serve a 2.43
            -- localedef. The -i/-f definition paths are given in full
            -- ($SRC-rooted): localedef opens them as given and its
            -- I18NPATH search does not serve relative `locales/…`/
            -- `charmaps/…` names (empirical) — but I18NPATH is still
            -- required for the locale INCLUDE chain (`copy "i18n"` inside
            -- en_US resolves only through it). The build-tree DSO subdirs
            -- cover every library localedef may pull; arch-neutral, so
            -- the arm64/armhf builds need no separate handling.
            "mkdir -p $STAGE/usr/lib/locale",
            "I18NPATH=$SRC/localedata LD_LIBRARY_PATH=$SRC/build:$SRC/build/math:$SRC/build/elf:$SRC/build/dlfcn:$SRC/build/nss:$SRC/build/nis:$SRC/build/resolv ./locale/localedef --prefix=$STAGE -c -i $SRC/localedata/locales/en_US -f $SRC/localedata/charmaps/UTF-8 en_US.UTF-8",
            "I18NPATH=$SRC/localedata LD_LIBRARY_PATH=$SRC/build:$SRC/build/math:$SRC/build/elf:$SRC/build/dlfcn:$SRC/build/nss:$SRC/build/nis:$SRC/build/resolv ./locale/localedef --prefix=$STAGE -c -i $SRC/localedata/locales/en_US -f $SRC/localedata/charmaps/ISO-8859-1 en_US.ISO-8859-1",
        }, " && "),

        type = "source",
        requires = {},
        build_deps = { "linux-headers" },
    },
}
