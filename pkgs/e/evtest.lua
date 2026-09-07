-- evtest: input device event monitor — displays /dev/input/eventX
-- events (keyboards, mice, touchpads, joysticks) live.
--
-- Ported from the devbox global profile as a source build: the Debian
-- orig tarball of evtest 1.36 (upstream freedesktop publishes no
-- release archives; the GitHub mirror ships no assets) is fetched,
-- sha256-pinned, and compiled with autotools in the build sandbox
-- (autoreconf first — the orig tarball has no generated configure).

return {
    default = snap {
        name = "evtest",
        version = "1.36",
        summary = "Input device event monitor and query tool",
        description = [[
            evtest displays information on an input device
            (/dev/input/event*) — its name, capabilities, and key and
            axis mappings — and dumps input events live, useful for
            debugging keyboards, mice, touchscreens, and joysticks.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://deb.debian.org/debian/pool/main/e/evtest/evtest_1.36.orig.tar.xz",
            sha256 = "773ea0acad767c6ab73876bcb52f244dc074b4cf1f94304ebb3cea6a4364b064",
        },

        build = table.concat({
            "autoreconf -i",
            "./configure --prefix=/usr",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            evtest = app {
                command = "usr/bin/evtest",
            },
        },
    },
}
