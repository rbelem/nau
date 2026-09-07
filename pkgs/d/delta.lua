-- delta: a syntax-highlighting pager for git, diff, and grep output.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- delta binary is staged directly into usr/bin (no Rust toolchain
-- needed in the build sandbox). The build runs at the tarball's
-- STRIPPED root (find_source_root): paths are relative to it.
--
-- Runtime note: delta is a pager normally invoked by git (as
-- core.pager); the pod does not bundle git, so configure git on the
-- host to point at the pod-farmed delta binary.

return {
    default = snap {
        name = "delta",
        version = "0.19.2",
        summary = "Syntax-highlighting pager for git and diff output",
        description = [[
            delta (git-delta) is a viewer for git diffs and grep output
            with side-by-side views, line numbering, syntax
            highlighting, word-level diff highlighting, and
            within-line styling. Configure it as git's core.pager /
            interactive.diffFilter.
        ]],
        license = "MIT OR Unlicense",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/dandavison/delta/releases/download/0.19.2/delta-0.19.2-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "f1ea01ca7728ce3462debc359f39dfc7cbbc1a63224b71fefabf92042864aa1b",
        },

        build = table.concat({
            "install -Dm755 delta $STAGE/usr/bin/delta",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            delta = app {
                command = "usr/bin/delta",
            },
        },
    },
}
