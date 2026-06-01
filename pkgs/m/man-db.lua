-- man-db: Manual page database and viewer
--
-- Source: https://download.savannah.gnu.org/releases/man-db/
-- Provides the man command and manual page infrastructure.

return {
    default = snap {
        name = "man-db",
        version = "2.13",
        summary = "Manual page database and viewer",
        description = [[
            man-db provides the man command for reading manual pages, the
            mandb utility for building the manual page index database, and
            related tools like whatis, apropos, and manpath. Supports
            compressed manual pages and multiple manual page directories.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://download.savannah.gnu.org/releases/man-db/man-db-2.13.1.tar.xz",
        },
        build = "./configure --prefix=/usr --sysconfdir=/etc --disable-setuid && make && make install DESTDIR=$STAGE",
    },
}
