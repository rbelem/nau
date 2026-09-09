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
            -- GCC 14+ turns -Wint-conversion into a hard error; tig 2.6.1 has
            -- a `return NULL` in an NCURSES_BOOL-returning path (src/io.c
            -- io_get_line) that older compilers allowed as a warning. Downgrade
            -- that diagnostic to a warning (keeping -Wall -O2) so tig builds on
            -- the pool's modern toolchain without patching upstream source.
            -- CPPFLAGS (the -I/shuttle-build-prefix include path) is handled
            -- separately by tig's Makefile via TIG_CPPFLAGS, so overriding
            -- CFLAGS on the make line does not drop the build-prefix headers.
            "./configure --prefix=/usr --without-readline",
            "make -j$(nproc) CFLAGS=\"-Wall -O2 -Wno-error=int-conversion\"",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "ncurses" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22) until the
        -- nix gcc wrapper stops baking the merged build prefix into produced
        -- binaries. The gcc wrapper emits RUNPATH=/shuttle-build-prefix/usr/lib
        -- into the tig binary; that path does not exist at runtime. Silenced
        -- here, visibly logged by the build's leak scan, pending the RUNPATH
        -- repair (issue #22's portability follow-up). Same rationale as htop.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            tig = app {
                command = "usr/bin/tig",
            },
        },
    },
}
