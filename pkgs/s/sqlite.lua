-- sqlite: small, fast, self-contained SQL database engine — the
-- sqlite3 shell CLI bundled as sqlite-autoconf.
--
-- Ported from the devbox global profile as a source build: the
-- official sqlite.org autoconf release tarball is fetched,
-- sha256-pinned, and compiled with its autotools build in the build
-- sandbox. Readline/editline are disabled (neither is in the pod).

return {
    default = snap {
        name = "sqlite",
        version = "3.53.3",
        summary = "SQL database engine (sqlite3 shell)",
        description = [[
            SQLite is a C-language library that implements a small,
            fast, self-contained, high-reliability, full-featured SQL
            database engine. This package ships the sqlite3
            command-line shell from the autoconf amalgamation for
            creating, querying, and managing SQLite database files.
        ]],
        license = "Public Domain",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://www.sqlite.org/2026/sqlite-autoconf-3530300.tar.gz",
            sha256 = "c917d7db16648ec95f714974ace5e5dcf46b7dc70e26600a0a102a3141125db0",
        },

        build = table.concat({
            "./configure --prefix=/usr --disable-readline --disable-editline --disable-static",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            sqlite3 = app {
                command = "usr/bin/sqlite3",
            },
        },
    },
}
