-- geminicommit: a CLI that writes your git commit messages with
-- Google Gemini AI (installs the `gmc` binary).
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux amd64 tarball (tfkhdyt/geminicommit) is fetched,
-- sha256-pinned, and the gmc binary (flat at the tarball root, static
-- Go binary) is staged directly into usr/bin.

return {
    default = snap {
        name = "geminicommit",
        version = "0.8.0",
        summary = "AI git commit messages via Google Gemini (gmc)",
        description = [[
            geminicommit (gmc) generates conventional commit messages
            for your staged changes using the Google Gemini API. It
            reads the staged diff, proposes a commit message, and
            commits after your confirmation.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/tfkhdyt/geminicommit/releases/download/v0.8.0/gmc-v0.8.0-linux-amd64.tar.gz",
            sha256 = "9397fa7ec146842872f01b139e5da68d3f376e06293f521d42e8a1bfe5025f6c",
        },

        build = table.concat({
            "install -Dm755 gmc $STAGE/usr/bin/gmc",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            gmc = app {
                command = "usr/bin/gmc",
            },
        },
    },
}
