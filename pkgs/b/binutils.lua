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
        requires = { "glibc" },
        -- ADR-0018: no implicit host toolchain — configure died "no
        -- acceptable C compiler found in $PATH" under the pod-first
        -- sync env.
        build_deps = { "gcc", "make" },
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
            -- The triplet-prefixed tools belong to the gcc deb set in a
            -- merged prefix (gcc.lua owns the x86_64-linux-gnu tool
            -- namespace: binutils-x86-64-linux-gnu.deb IS the triplet
            -- toolchain there) — staging this source build's own copies
            -- content-conflicts with them (different builds, same
            -- paths, #215 podman prefix merge). The plain names stay;
            -- the meta's staged tree symlinks plain → prefixed, which
            -- keeps resolving against the deb payload.
            "rm -f $STAGE/usr/bin/x86_64-linux-gnu-*",
        }, " && "),

        -- The five libtool archives (libsframe/libbfd/libopcodes/libctf/
        -- libctf-nobfd .la) embed the merged build prefix in
        -- dependency_libs — the zlib-class interim escape (ADR-0018
        -- Decision 3, issue #22's portability follow-up). .la files
        -- matter only at libtool link time; runtime consumers resolve
        -- the SONAMEs through the name-preserving tree. The scan's
        -- text-leak reference is the bare prefix marker, so one entry
        -- covers all five files; ELF RUNPATH/DT_NEEDED still scan
        -- strictly.
        leaks_ok = { "/shuttle-build-prefix" },
    },
}
