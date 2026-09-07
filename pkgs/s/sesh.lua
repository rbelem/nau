-- sesh: tmux session manager that lets you create, find, and connect
-- to sessions and zoxide-indexed directories.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux x86_64 tarball is fetched, sha256-pinned, and the
-- sesh binary (flat at the tarball's stripped root, static Go binary)
-- is staged directly into usr/bin.

return {
    default = snap {
        name = "sesh",
        version = "2.28.0",
        summary = "Smart tmux session manager",
        description = [[
            sesh is a tmux session manager for creating, finding, and
            connecting to sessions from zoxide-indexed directories, tmux
            sessions, and configured startup scripts. Pairs well with
            tmux-mode indicators and fzf pickers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/joshmedeski/sesh/releases/download/v2.28.0/sesh_Linux_x86_64.tar.gz",
            sha256 = "ac4a0b07f0be4cbb13691a197055ac82e00341e77b915d878df8ad2bcc867fda",
        },

        -- Tarball layout gotcha: this release tarball has a single
        -- top-level directory (share/), which the source-root finder
        -- (find_source_root) picks as $SRC/cwd. Resolve the binary
        -- against $SRC/.. so the build works for either layout.
        build = table.concat({
            "install -Dm755 \"$SRC/../sesh\" $STAGE/usr/bin/sesh",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            sesh = app {
                command = "usr/bin/sesh",
            },
        },
    },
}
