-- binutils: GNU assembler, linker, and binary utilities
--
-- Source: https://ftp.gnu.org/gnu/binutils/binutils-2.43.1.tar.xz
return {
    default = snap {
        name = "binutils",
        version = "2.43.1",
        summary = "GNU assembler, linker, and binary utilities",
        description = [[GNU Binutils 2.43.1 provides a collection of binary tools essential for
building programs. It includes the GNU assembler (as), linker (ld), and
utilities such as objdump, nm, strip, and ar for working with object files,
archives, and binaries. This build targets x86_64-linux-gnu.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        source = { url = "https://ftp.gnu.org/gnu/binutils/binutils-2.43.1.tar.xz" },
        build = "./configure --prefix=/usr --target=x86_64-linux-gnu && make && make install DESTDIR=$STAGE",
    },
}
