-- tree: recursive directory listing command that produces a
-- depth-indented listing of files, with colors and gitignore-ish
-- filtering options.
--
-- Ported from the devbox global profile as a source build: the Debian
-- orig tarball (same artifact nixpkgs builds; upstream mama.indstate
-- releases no archives and the GitHub mirror ships no release assets)
-- is fetched, sha256-pinned, and compiled with its plain Makefile in
-- the build sandbox; only the binary is staged (no NLS/JSON extras).

return {
    default = snap {
        name = "tree",
        version = "2.3.2",
        summary = "Recursive directory listing, depth-indented",
        description = [[
            tree is a recursive directory listing program that produces
            a depth-indented listing of files. Colorization, TOC-style
            sorting options, HTML output, and pattern filtering are
            supported.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://deb.debian.org/debian/pool/main/t/tree/tree_2.3.2.orig.tar.gz",
            sha256 = "6b941dd6cbecfb4d3250700e4d08d8e0c251488981dd4868b90d744234300e21",
        },

        build = table.concat({
            "make -j$(nproc) CFLAGS='-O2 -pedantic -Wall'",
            "install -Dm755 tree $STAGE/usr/bin/tree",
            "install -Dm644 doc/tree.1 $STAGE/usr/share/man/man1/tree.1",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            tree = app {
                command = "usr/bin/tree",
            },
        },
    },
}
