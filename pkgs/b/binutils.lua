-- binutils: GNU assembler, linker, and binary utilities
--
-- Source: https://ftp.gnu.org/gnu/binutils/binutils-2.44.tar.xz
--
-- 2.43.1 -> 2.44 (issue #217): 2.43.1's vendored gnulib obstack snapshot
-- predates the _OBSTACK_SIZE_T plumbing and fails to compile against the
-- prefix gcc + pod glibc 2.43 headers (libiberty/obstack.c "unknown type
-- name"); 2.44 ships the aligned gnulib and is the payload version the
-- farm already runs.
return {
    default = snap {
        name = "binutils",
        version = "2.44",
        summary = "GNU assembler, linker, and binary utilities",
        description = [[GNU Binutils 2.44 provides a collection of binary tools essential for
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
        source = {
            url = "https://ftp.gnu.org/gnu/binutils/binutils-2.44.tar.xz",
            sha256 = "ce2017e059d63e67ddb9240e9d4ec49c2893605035cd60e92ad53177f4377237",
        },
        build = table.concat({
            -- CPPFLAGS prepend (issue #217, root cause): glibc's public
            -- usr/include/obstack.h keeps the pre-gnulib API shape (plain
            -- chunkfun member, no _OBSTACK_INTERFACE_VERSION) and the
            -- engine-exported CPPFLAGS puts the prefix include dirs ahead
            -- of libiberty's own -I./../include, so libiberty/obstack.c
            -- (gnulib v2 flavor) compiles against the wrong header on
            -- BOTH 2.43.1 and 2.44 ("unknown type name
            -- '_OBSTACK_SIZE_T'", chunkfun.plain member errors). The
            -- source tree's include dir must win the search; libiberty's
            -- Makefile takes CPPFLAGS from the environment at make time,
            -- so the recipe re-exports it with the tree include first.
            "export CPPFLAGS=\"-I$SRC/include $CPPFLAGS\"",
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
            -- 2.44's install layout inverts the 2.43.1 shape: usr/bin
            -- gets the triplet-PREFIXED names (removed above — gcc.lua's
            -- deb set owns the x86_64-linux-gnu namespace) while the
            -- real PLAIN-name binaries (nm, strip, as, ld.bfd, ...) land
            -- in a tooldir tree usr/<triplet>/bin. The plain names are
            -- this payload's actual deliverable: merge the tooldir into
            -- usr/bin, then drop the empty tooldir tree.
            "if [ -d \"$STAGE/usr/x86_64-linux-gnu/bin\" ]; then cp -a \"$STAGE/usr/x86_64-linux-gnu/bin/.\" \"$STAGE/usr/bin/\"; fi",
            "rm -rf $STAGE/usr/x86_64-linux-gnu",
        }, " && "),

        -- The five libtool archives (libsframe/libbfd/libopcodes/libctf/
        -- libctf-nobfd .la) embed the merged build prefix in
        -- dependency_libs — the zlib-class interim escape (ADR-0018
        -- Decision 3, issue #22's portability follow-up). .la files
        -- matter only at libtool link time; runtime consumers resolve
        -- the SONAMEs through the name-preserving tree. The scan's
        -- text-leak reference is the bare prefix marker, so one entry
        -- covers all five files; ELF RUNPATH/DT_NEEDED still scan
        -- strictly. libdep.so (bfd-plugins, new in the 2.44 staging) is
        -- the one staged ELF with the driver's RUNPATH bake: it is
        -- dlopened only by the plugin-capable linkers at build time, so
        -- the exact RUNPATH entry is the same build-only class.
        leaks_ok = {
            "/shuttle-build-prefix",
            "/shuttle-build-prefix/usr/lib64",
        },
    },
}
