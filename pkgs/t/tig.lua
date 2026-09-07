-- tig: text-mode interface for git — browse commits, refs, diffs,
-- and stage hunks interactively.
--
-- Ported from the devbox global profile as a source build: the
-- upstream release tarball (configure pre-generated) is fetched,
-- sha256-pinned, and compiled in the build sandbox against ncurses
-- (pulled into the pod dependency closure via the requires entry).
--
-- Runtime note: tig drives git itself; the pod does not bundle git,
-- so run it inside repositories with git available on the host.

return {
    default = snap {
        name = "tig",
        version = "2.6.1",
        summary = "Text-mode interface for git",
        description = [[
            tig is an ncurses-based text-mode interface for git. It
            functions mainly as a git repository browser, but can also
            assist in staging changes for commit at chunk level and
            acts as a pager for git command output.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/jonas/tig/releases/download/tig-2.6.1/tig-2.6.1.tar.gz",
            sha256 = "5adeabdcd93aa0423d618da8b878b53482bef6e0e9e1fe224acc0f18031fe91e",
        },

        build = table.concat({
            "./configure --prefix=/usr --without-readline",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "ncurses" },

        apps = {
            tig = app {
                command = "usr/bin/tig",
            },
        },
    },
}
