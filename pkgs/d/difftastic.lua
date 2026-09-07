-- difftastic: a structural diff tool that compares files based on
-- syntax trees (tree-sitter) instead of lines.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- difft binary (flat at the tarball root, no Rust toolchain needed in
-- the build sandbox) is staged directly into usr/bin.

return {
    default = snap {
        name = "difftastic",
        version = "0.70.0",
        summary = "Structural diff tool that understands syntax",
        description = [[
            difftastic (difft) is a structural diff tool that compares
            files according to their syntax trees, using tree-sitter
            grammars for 40+ languages. It ignores meaningless changes
            such as reformatting, showing edits that humans care about.
            Integrate with git via `git difftool --extcmd difft`.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/Wilfred/difftastic/releases/download/0.70.0/difft-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "16f65a74a3d64d0bb44d31223d56d0ccaa9ad148f520322450a0629ee21f205f",
        },

        build = table.concat({
            "install -Dm755 difft $STAGE/usr/bin/difft",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            difft = app {
                command = "usr/bin/difft",
            },
        },
    },
}
