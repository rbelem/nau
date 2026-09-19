-- less: terminal pager (GNU less).
--
-- Ported from the devbox global profile as a source build (htop
-- pattern): the upstream release tarball (configure pre-generated) is
-- fetched, sha256-pinned, and compiled in the build sandbox against
-- ncurses from the merged prefix (pulled into the pod dependency
-- closure via the requires entry).
--
-- Why the pod ships its own less: the shellenv loader seam (#89)
-- injects the generation's ncurses into EVERY child, so the host less
-- (/run/current-system/sw/bin) loads a libncursesw without ELF version
-- info and prints "no version information available" on every git
-- log/show. A farm less links the pod ncurses natively and shadows the
-- host binary on PATH — no injected-loader path, no warning.

return {
    default = snap {
        name = "less",
        version = "704",
        summary = "Terminal pager with extensive navigation features",
        description = [[
            GNU less is a pager: a program that displays text files or
            piped output one screen at a time, with forward and backward
            movement, searching, and multiple buffers. Built against the
            pod's ncurses so the farm serves one consistent curses
            library to every pager consumer.
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://ftp.gnu.org/gnu/less/less-704.tar.gz",
            sha256 = "20a0b0a2bb2525fa53c7eee9beb854b4c9cf172eabb209af7020743547bfe9fb",
        },

        build = table.concat({
            "./configure --prefix=/usr",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc", "ncurses" },

        -- Same interim escape as htop: the nix gcc wrapper bakes a
        -- /shuttle-build-prefix RUNPATH into produced binaries (issue
        -- #22 portability follow-up).
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },

        apps = {
            less = app {
                command = "usr/bin/less",
            },
            lesskey = app {
                command = "usr/bin/lesskey",
            },
        },
    },
}
