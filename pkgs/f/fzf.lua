-- fzf: general-purpose command-line fuzzy finder.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux amd64 tarball is fetched, sha256-pinned, and the
-- fzf binary (flat at the tarball root, no Go toolchain needed in the
-- build sandbox) is staged directly into usr/bin.

return {
    default = snap {
        name = "fzf",
        version = "0.74.3",
        summary = "General-purpose command-line fuzzy finder",
        description = [[
            fzf is an interactive Unix filter for command-line usage
            that can be used with any list: files, command history,
            processes, hostnames, bookmarks, git commits. It implements
            a fuzzy-matching algorithm in Go with instant results and
            Vim-style keybindings.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/junegunn/fzf/releases/download/v0.74.3/fzf-0.74.3-linux_amd64.tar.gz",
            sha256 = "3501a595e4b5c40a6b047340a0e8f805c46fd4e61ef95ef8a136ba8c61cf6f22",
        },

        build = table.concat({
            "install -Dm755 fzf $STAGE/usr/bin/fzf",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            fzf = app {
                command = "usr/bin/fzf",
            },
        },
    },
}
