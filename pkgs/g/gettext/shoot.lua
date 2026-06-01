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
        source = { url = "https://ftp.gnu.org/gnu/gettext/gettext-0.22.5.tar.xz" },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
    },
}
