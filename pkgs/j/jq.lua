-- jq: lightweight and flexible command-line JSON processor.
--
-- Ported from the devbox global profile into a shuttle source package.
-- Built from the upstream autotools release tarball; the build sandbox
-- runs configure/make and installs into $STAGE.

return {
    default = snap {
        name = "jq",
        version = "1.8.2",
        summary = "Lightweight and flexible command-line JSON processor",
        description = [[
            jq is a lightweight and flexible command-line JSON processor.
            It is like sed for JSON data — you can use it to slice and
            filter and map and transform structured data with the same
            ease that sed, awk, grep let you filter and transform text.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-1.8.2.tar.gz",
            sha256 = "71b8d6e8f5fe81f6c6d0d110e3892251f6ce76ed095abd315e26e6e1193af3af",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-maintainer-mode",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
            -- libtool .la metadata (libonig.la, libjq.la) embeds the merged
            -- build prefix; nothing consumes them at runtime — strip
            -- (libstdcpp/curl/gmp precedent).
            "find $STAGE -name '*.la' -type f -delete",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            jq = app {
                command = "usr/bin/jq",
            },
        },
    },
}
