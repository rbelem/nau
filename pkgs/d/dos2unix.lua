-- dos2unix: convert text files with DOS/Mac line endings to Unix
-- line endings and back (includes mac2unix).
--
-- Ported from the devbox global profile as a source build: the
-- upstream 7.5.5 tarball (SourceForge release artifact — the author's
-- waterlan.home.xs4all.nl site is dead) is fetched, sha256-pinned,
-- and compiled with its plain Makefile in the build sandbox; the
-- dos2unix binary is staged into usr/bin.

return {
    default = snap {
        name = "dos2unix",
        version = "7.5.5",
        summary = "Convert DOS/Mac text files to Unix format",
        description = [[
            dos2unix converts text file line endings between CRLF
            (DOS/Windows), CR (classic Mac), and LF (Unix) formats. It
            handles Unicode files, preserves file timestamps, and can
            convert in place.
        ]],
        license = "BSD-2-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.5/dos2unix-7.5.5.tar.gz",
            sha256 = "75f692b8484c8c24579a2ffd87df16b9c9428ed95497e3393a21d1ba0697ac33",
        },

        build = table.concat({
            "make -j$(nproc) ENABLE_NLS=",
            "install -Dm755 dos2unix $STAGE/usr/bin/dos2unix",
            "install -Dm755 mac2unix $STAGE/usr/bin/mac2unix",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            dos2unix = app {
                command = "usr/bin/dos2unix",
            },
            mac2unix = app {
                command = "usr/bin/mac2unix",
            },
        },
    },
}
