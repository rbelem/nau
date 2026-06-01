-- make: GNU Make build automation tool
--
-- Source: https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz
return {
    default = snap {
        name = "make",
        version = "4.4.1",
        summary = "GNU Make build automation tool",
        description = [[GNU Make 4.4.1 is a tool which controls the generation of executables and
other non-source files from source files. It automatically determines which
pieces of a large program need to be recompiled and issues commands to
recompile them.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
