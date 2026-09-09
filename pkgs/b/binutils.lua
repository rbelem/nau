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
        type = "source",
        requires = {},
        source = { url = "https://ftp.gnu.org/gnu/binutils/binutils-2.43.1.tar.xz" },
        build = table.concat({
            "./configure --prefix=/usr --target=x86_64-linux-gnu --disable-gprofng --disable-werror",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- Binutils ships makeinfo-generated info pages + a regenerated
            -- share/info/dir index; in a merged build prefix dir differs
            -- across packages and conflicts (gmp/m4 precedent). Strip it so
            -- prefix merging stays content-identical.
            "find $STAGE -name 'dir' -path '*/share/info/*' -delete",
        }, " && "),
    },
}
