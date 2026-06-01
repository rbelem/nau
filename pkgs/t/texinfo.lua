-- texinfo: GNU documentation system
--
-- Source: https://ftp.gnu.org/gnu/texinfo/texinfo-7.1.1.tar.xz
return {
    default = snap {
        name = "texinfo",
        version = "7.1.1",
        summary = "GNU documentation system",
        description = [[Texinfo 7.1.1 is the official documentation format of the GNU project.
It uses a single source file to produce output in multiple formats including
HTML, PDF, Docbook, and Info. The makeinfo tool reads Texinfo source and
generates these formats for viewing and distribution.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://ftp.gnu.org/gnu/texinfo/texinfo-7.1.1.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
