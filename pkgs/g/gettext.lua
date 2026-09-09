-- gettext: GNU internationalization and localization library
--
-- Source: https://ftp.gnu.org/gnu/gettext/gettext-0.22.5.tar.xz
return {
    default = snap {
        name = "gettext",
        version = "0.22.5",
        summary = "GNU internationalization and localization library",
        description = [[GNU gettext 0.22.5 provides a set of tools and documentation for producing
multi-lingual messages. It includes the libintl library for use in programs
and the xgettext, msgfmt, and related tools for extracting and compiling
translation files. It is a core dependency for many GNU packages.]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = {},
        source = { url = "https://ftp.gnu.org/gnu/gettext/gettext-0.22.5.tar.xz" },
        -- --without-libpsl n/a; gettext is a plain autotools build. The
        -- usr/share/info/dir index file it installs conflicts with glibc's
        -- in the merged build prefix (ADR-0018 hard-error on differing
        -- content) and is a generated index that no pool consumer reads —
        -- strip it.
        build = table.concat({
            "./configure --prefix=/usr",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            "find $STAGE/usr/share/info -maxdepth 1 -name dir -delete",
        }, " && "),
    },
}
