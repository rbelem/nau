-- jq: lightweight and flexible command-line JSON processor.
--
-- Ported from the devbox global profile into a shuttle source package.
-- Built from the upstream autotools release tarball; the build sandbox
-- runs configure/make and installs into $STAGE.

return {
    default = snap {
        name = "jq",
        version = "1.8.1",
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
            url = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz",
            sha256 = "2be64e7129cecb11d5906290eba10af694fb9e3e7f9fc208a311dc33ca837eb0",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-maintainer-mode",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
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
