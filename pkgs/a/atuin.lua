-- atuin: magical shell history — sync, search and back up your shell
-- history in a SQLite database.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 gnu tarball is fetched, sha256-pinned, and the
-- atuin binary is staged directly into usr/bin (no Rust toolchain
-- needed in the build sandbox).

return {
    default = snap {
        name = "atuin",
        version = "18.19.0",
        summary = "Magical shell history — sync, search and back up",
        description = [[
            atuin replaces your existing shell history with a SQLite
            database, recording additional context (directory, host,
            exit code, duration) and providing full-text and fuzzy
            search across it, with optional end-to-end
            encrypted sync between machines.
        ]],
        license = "GPL-3.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/atuinsh/atuin/releases/download/v18.19.0/atuin-x86_64-unknown-linux-gnu.tar.gz",
            sha256 = "4d7559ada42407ee8ddc62349acf134dd297568d032c45a746a7aef8a6860648",
        },

        build = table.concat({
            "install -Dm755 atuin $STAGE/usr/bin/atuin",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            atuin = app {
                command = "usr/bin/atuin",
            },
        },
    },
}
