-- bws: Bitwarden Secrets Manager CLI — fetch and manage secrets from
-- Bitwarden Secrets Manager from the command line and scripts.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl zip asset (bitwarden/sdk monorepo, bws tag)
-- is fetched, sha256-pinned, and extracted with python3's zipfile
-- module (no unzip tool in the build sandbox); the static bws binary
-- is staged into usr/bin.

return {
    default = snap {
        name = "bws",
        version = "2.1.0",
        summary = "Bitwarden Secrets Manager CLI",
        description = [[
            bws is the official Bitwarden Secrets Manager command-line
            interface. Authenticate with an access token to create,
            read, update, and delete projects and secrets, and to run
            templated secret injection (bws run) in scripts and CI.
        ]],
        license = "GPL-3.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/bitwarden/sdk/releases/download/bws-v2.1.0/bws-x86_64-unknown-linux-musl-2.1.0.zip",
            sha256 = "f59ee150e42b82128d437087e9bac920053c6bfddcb960d20ce9386e5ac9bba6",
        },

        build = table.concat({
            "python3 -m zipfile -e bws-x86_64-unknown-linux-musl-2.1.0.zip .",
            "install -Dm755 bws $STAGE/usr/bin/bws",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            bws = app {
                command = "usr/bin/bws",
            },
        },
    },
}
