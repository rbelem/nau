-- m4: GNU macro processor
--
-- Source: https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz
return {
    default = snap {
        name = "m4",
        version = "1.4.19",
        summary = "GNU macro processor",
        description = [[GNU M4 1.4.19 is a macro processor that copies its input to the output,
expanding macros as it goes. It has built-in functions for including files,
running shell commands, doing arithmetic, manipulating text, and more.
Autoconf and other GNU build tools depend on M4 for macro expansion.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz" },
        -- Hand-written build (not the autotools plugin) so the payload can
        -- strip the generated share/info/dir index: it differs per package
        -- (m4 vs gmp), and a merged build prefix requires identical content
        -- at shared paths (gettext/glibc precedent). m4.info pages stay.
        build = table.concat({
            -- CFLAGS -std=gnu17: m4 1.4.19's bundled gnulib gl_oset.h places
            -- __attribute__((nodiscard)) ahead of a declaration — GCC 16's
            -- C23 default ignores the attribute there and hard-errors
            -- ('expected identifier or ( before int'). Pin the gnu17 dialect
            -- (with -O2 restated, since this replaces the default CFLAGS).
            "./configure --prefix=/usr CFLAGS=\"-O2 -std=gnu17\"",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- The info index is regenerated per-package; in a merged build
            -- prefix its content differs across packages and conflicts.
            -- Strip it so prefix merging stays content-identical.
            "find $STAGE -name 'dir' -path '*/share/info/*' -delete",
        }, " && "),
    },
}
