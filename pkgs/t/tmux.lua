-- tmux: terminal multiplexer
--
-- Ported from the devbox global profile as a source build: the
-- upstream release tarball (configure pre-generated) is fetched,
-- sha256-pinned, and compiled in the build sandbox.
--
-- Runtime deps: libevent (>=2, pkg-config `libevent_core`) and ncurses
-- (pkg-config `libncurses`/`libtinfo`) — both link-time AND runtime
-- libraries, so they go in `requires` (which per ADR-0018 also
-- materializes into the merged build prefix so the build can find
-- them). utf8proc is optional and disabled to keep the payload small.
-- pkg-config is build-time-only tooling, so it goes in `build_deps`.
--
-- Requires: glibc, libevent, ncurses
-- build_deps: pkg-config

return {
    default = snap {
        name = "tmux",
        version = "3.5a",
        summary = "Terminal multiplexer",
        description = [[
            tmux is a terminal multiplexer. It lets you switch easily
            between several programs in one terminal, detach them (they
            keep running in the background) and reattach them to a
            different terminal. Built against pool ncurses and libevent.
        ]],
        license = "ISC",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/tmux/tmux/releases/download/3.5a/tmux-3.5a.tar.gz",
            sha256 = "16216bd0877170dfcc64157085ba9013610b12b082548c7c9542cc0103198951",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-utf8proc",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "libevent", "ncurses" },
        build_deps = { "pkg-config" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22) until the
        -- nix gcc wrapper stops baking the merged build prefix into produced
        -- binaries. The gcc wrapper emits RUNPATH=/shuttle-build-prefix/usr/lib
        -- into the tmux binary; that path does not exist at runtime. Silenced
        -- here, visibly logged by the build's leak scan, pending the RUNPATH
        -- repair (issue #22's portability follow-up). Same rationale as
        -- htop/tig.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            tmux = app {
                command = "usr/bin/tmux",
            },
        },
    },
}
