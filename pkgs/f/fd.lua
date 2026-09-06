-- fd: simple, fast and user-friendly alternative to find.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 gnu tarball is fetched, sha256-pinned, and the
-- fd binary is staged directly into usr/bin (no Rust toolchain needed
-- in the build sandbox).

return {
    default = snap {
        name = "fd",
        version = "10.4.2",
        summary = "Simple, fast and user-friendly alternative to find",
        description = [[
            fd is a program to find entries in your filesystem. It is a
            simple, fast and user-friendly alternative to find: sane
            defaults, intuitive syntax, regular-expression and
            glob-based filtering, parallel directory traversal, and
            built-in colorized output.
        ]],
        license = "Apache-2.0 OR MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/sharkdp/fd/releases/download/v10.4.2/fd-v10.4.2-x86_64-unknown-linux-gnu.tar.gz",
            sha256 = "def59805cd14b5651b68990855f426ad087f3b96881296d963910431ba3143c8",
        },

        build = table.concat({
            "install -Dm755 fd $STAGE/usr/bin/fd",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            fd = app {
                command = "usr/bin/fd",
            },
        },
    },
}
