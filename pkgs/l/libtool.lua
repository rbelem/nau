-- libtool: GNU library support script
--
-- Source: https://ftp.gnu.org/gnu/libtool/libtool-2.5.4.tar.xz
return {
    default = snap {
        name = "libtool",
        version = "2.5.4",
        summary = "GNU library support script",
        description = [[Libtool 2.5.4 provides a standardized way to build and install shared and
static libraries across different UNIX-like systems. It hides the complexity
of using shared libraries behind a consistent, portable interface, handling
differences in how various platforms build and link libraries.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "autoconf", "automake", "m4" },
        source = { url = "https://ftp.gnu.org/gnu/libtool/libtool-2.5.4.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
