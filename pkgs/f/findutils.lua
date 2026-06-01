-- findutils: GNU find and xargs utilities
--
-- Source: https://ftp.gnu.org/gnu/findutils/
-- Provides find, xargs, locate, and updatedb.

return {
    default = snap {
        name = "findutils",
        version = "4.10",
        summary = "GNU find and xargs utilities",
        description = [[
            GNU findutils provides the basic directory searching utilities
            find and xargs. find recursively searches directories for files
            matching a given set of criteria. xargs builds and executes
            command lines from standard input. Also includes locate and
            updatedb for building file databases.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz",
        },
        build = "./configure --prefix=/usr --localstatedir=/var/lib/locate && make && make install DESTDIR=$STAGE",
    },
}
