-- automake: GNU tool for generating Makefile.in files
--
-- Source: https://ftp.gnu.org/gnu/automake/automake-1.17.tar.xz
return {
    default = snap {
        name = "automake",
        version = "1.17",
        summary = "GNU tool for generating Makefile.in files",
        description = [[Automake 1.17 is a tool for automatically generating Makefile.in files from
templates. It works with Autoconf to produce portable, GNU-standard
Makefiles. Each Makefile.in is created from a Makefile.am and can be
used by configure scripts to generate platform-specific Makefiles.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://ftp.gnu.org/gnu/automake/automake-1.17.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
