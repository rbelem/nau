-- zoxide: a smarter cd command for your terminal, learning your habits.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- zoxide binary (at the tarball's stripped root, no Rust toolchain
-- needed in the build sandbox) is staged directly into usr/bin.

return {
    default = snap {
        name = "zoxide",
        version = "0.10.0",
        summary = "Smarter cd command that learns your habits",
        description = [[
            zoxide is a smarter cd command for your terminal. It keeps
            a frecency- and recency-ranked database of directories you
            visit and jumps to the best match for a shorthand query
            (z foo). Shell integration is available for bash, zsh,
            fish, and more via `zoxide init`.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ajeetdsouza/zoxide/releases/download/v0.10.0/zoxide-0.10.0-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "2d93385b99f3e82cf2701609a1bffcad863fbeb75aa3fe7eb6be4d29be68b1ae",
        },

        build = table.concat({
            "install -Dm755 zoxide $STAGE/usr/bin/zoxide",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            zoxide = app {
                command = "usr/bin/zoxide",
            },
        },
    },
}
