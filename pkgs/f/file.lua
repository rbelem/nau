-- file: the classic "file — determine file type" utility, shipping
-- the libmagic database and the file(1) command.
--
-- Ported from the devbox global profile as a source build: the
-- upstream 5.48 release tarball from ftp.astron.com (the GitHub repo
-- publishes no release assets) is fetched, sha256-pinned, and
-- compiled with its autotools build in the build sandbox; the binary
-- and its magic database are staged into /usr.

return {
    default = snap {
        name = "file",
        version = "5.48",
        summary = "Determine file type via magic numbers",
        description = [[
            file tests each argument in an attempt to classify it:
            filesystem tests (magic number checks), language tests,
            and text tests, backed by the compiled libmagic database.
            Output is a human-readable description like "ELF 64-bit
            LSB executable" or "ASCII text".
        ]],
        license = "BSD-2-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "http://ftp.astron.com/pub/file/file-5.48.tar.gz",
            sha256 = "ed14656883b23a364b4057c05595d93252da9bc473d30106519519d0da141283",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            file = app {
                command = "usr/bin/file",
            },
        },
    },
}
