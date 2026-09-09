-- glibc-locales: precompiled locale archive for pool glibc.
--
-- Data payload package (no libraries, no apps): builds glibc's
-- localedef from the same glibc release the pool glibc package uses,
-- then compiles a minimal locale set into the standard
-- /usr/lib/locale/locale-archive so setlocale(LC_ALL, "en_US.UTF-8")
-- works in pods without a full distro locale set.
--
-- Requires: glibc (the archive is consumed by the matching libc).

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
            "mkdir build",
            "cd build && ../configure --prefix=/usr --disable-profile --enable-kernel=5.4",
            "make -j$(nproc)",
            -- Run the freshly built localedef against the source-tree
            -- locale/charmap definitions; --prefix redirects the archive
            -- write into the stage.
            "mkdir -p $STAGE/usr/lib/locale",
            "I18NPATH=$SRC/localedata ./build/locale/localedef --prefix=$STAGE -c -i locales/en_US -f charmaps/UTF-8 en_US.UTF-8",
            "I18NPATH=$SRC/localedata ./build/locale/localedef --prefix=$STAGE -c -i locales/en_US -f charmaps/ISO-8859-1 en_US.ISO-8859-1",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
