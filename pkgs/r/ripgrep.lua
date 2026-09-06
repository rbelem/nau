-- ripgrep: recursively searches directories for a regex pattern, fast
-- replacement for grep.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- rg binary is staged directly into usr/bin (no Rust toolchain needed
-- in the build sandbox). The build runs at the tarball's STRIPPED root
-- (find_source_root): paths are relative to it, not to the tarball's
-- top-level directory.

return {
    default = snap {
        name = "ripgrep",
        version = "15.2.0",
        summary = "Recursively searches directories for a regex pattern",
        description = [[
            ripgrep (rg) recursively searches directories for a regex
            pattern while respecting your gitignore. It is fast,
            multithreaded, and supports Unicode, lookarounds, and
            replacing or listing matches across large trees.
        ]],
        license = "MIT OR Unlicense",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c",
        },

        build = table.concat({
            "install -Dm755 rg $STAGE/usr/bin/rg",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            rg = app {
                command = "usr/bin/rg",
            },
        },
    },
}
