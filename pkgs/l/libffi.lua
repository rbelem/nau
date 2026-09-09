-- libffi: Foreign Function Interface library.
--
-- Pool prerequisite for glib (GObject closure dispatch runs through
-- libffi). Release tarball with pre-generated configure; sha256-pinned.
--
-- Requires: glibc

return {
    default = snap {
        name = "libffi",
        version = "3.8.0",
        summary = "Foreign Function Interface library",
        description = [[
            libffi is a portable, high-level programming interface to
            various calling conventions. It allows a program to call a
            function of an arbitrary signature at run time without
            knowing the signature at compile time, and is used by
            GObject, Python, and many language runtimes for FFI.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64", "armhf" },

        source = {
            url = "https://github.com/libffi/libffi/releases/download/v3.8.0/libffi-3.8.0.tar.gz",
            sha256 = "7da3e2d9a171eb0a038f592ecad3ff2bb2550f3496d87b3b29ad0cf4430c0db4",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata embeds the configure-time prefix
            -- (/shuttle-build-prefix) and is obsolete at runtime — consumers
            -- use the .so libs and .pc pkg-config files. Strip so the build
            -- prefix cannot leak.
            "find $STAGE/usr -name '*.la' -delete",
            -- install-info's dir index conflicts in the merged build
            -- prefix (glibc ships its own usr/share/info/dir with different
            -- content — ADR-0018 identical-content rule). Dead weight in a
            -- pool payload: nothing in a pod reads info pages.
            "rm -f $STAGE/usr/share/info/dir",
        }, " && "),

        type = "source",
        requires = { "glibc" },
    },
}
