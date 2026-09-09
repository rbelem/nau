-- htop: interactive process viewer.
--
-- Ported from the devbox global profile as a source build: the
-- upstream release tarball (configure pre-generated — no autogen
-- needed) is fetched, sha256-pinned, and compiled in the build
-- sandbox against ncurses (pulled into the pod dependency closure via
-- the requires entry).

return {
    default = snap {
        name = "htop",
        version = "3.5.3",
        summary = "Interactive process viewer",
        description = [[
            htop is an interactive process viewer for Unix systems. It
            is a text-mode application (for console or X terminals) and
            requires ncurses. htop is similar to top but allows
            scrolling vertically and horizontally, and provides a nicer
            visual interface for managing processes.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/htop-dev/htop/releases/download/3.5.3/htop-3.5.3.tar.xz",
            sha256 = "a8b164386494cb85bb255a415a3f5f80afe7a0c4491da5d113b3a0f951087e65",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "ncurses" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22) until the
        -- nix gcc wrapper STOP baking the merged build prefix into produced
        -- binaries (separate portability work). The gcc wrapper emits
        -- RUNPATH=/shuttle-build-prefix/usr/lib into the htop binary; that
        -- path does not exist at runtime. Silenced here, visibly logged by
        -- the build's leak scan, pending the RUNPATH repair (issue #22's
        -- portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            htop = app {
                command = "usr/bin/htop",
            },
        },
    },
}
