-- expat: stream-oriented XML parser library.
--
-- Pool prerequisite for dbus (libdbus's XML config parser) and thus
-- for everything in the dconf chain. Release tarball with
-- pre-generated configure; sha256-pinned.
--
-- Requires: glibc

return {
    default = snap {
        name = "expat",
        version = "2.8.4",
        summary = "Stream-oriented XML parser library",
        description = [[
            Expat is a stream-oriented XML parser library written in C,
            implementing both XML 1.0 and XML Namespaces. It is the XML
            backend libdbus uses to parse its bus configuration, making
            it a pool prerequisite for dbus and its consumers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        source = {
            url = "https://github.com/libexpat/libexpat/releases/download/R_2_8_4/expat-2.8.4.tar.gz",
            sha256 = "b8ece2437692dad44d851c4532723390a5a330990007706be9c8d2b90d294f36",
        },

        build = table.concat({
            "./configure --prefix=/usr --without-xmlwf --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the configure-time prefix
            -- (/shuttle-build-prefix) and is obsolete at runtime — consumers
            -- use the .so libs and .pc pkg-config files. Strip so the build
            -- prefix cannot leak.
            "find $STAGE/usr -name '*.la' -delete",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
