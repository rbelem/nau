-- bitwarden-cli: the official `bw` command-line interface for the
-- Bitwarden password manager (OSS build).
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the bw-oss-linux zip asset from the bitwarden/clients cli release is
-- fetched, sha256-pinned, and extracted with python3's zipfile module
-- (no unzip tool in the build sandbox). The `bw` executable is a
-- self-contained Node.js/pkg binary (~140 MB unpacked) staged into
-- usr/bin.

return {
    default = snap {
        name = "bitwarden-cli",
        version = "2026.7.0",
        summary = "Bitwarden CLI password manager (bw)",
        description = [[
            The Bitwarden command-line interface (bw) lets you create,
            unlock, query, and edit vault items, generate passwords,
            and integrate secret retrieval into scripts and CI. This is
            the OSS build shipped by Bitwarden as bw-oss-linux.
        ]],
        license = "GPL-3.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/bitwarden/clients/releases/download/cli-v2026.7.0/bw-oss-linux-2026.7.0.zip",
            sha256 = "d867a39c28ddd56c09a1a99bdbae3afbca4c295c918d41bbdac8ca25e9bf4073",
        },

        build = table.concat({
            "python3 -m zipfile -e bw-oss-linux-2026.7.0.zip .",
            "install -Dm755 bw $STAGE/usr/bin/bw",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            bw = app {
                command = "usr/bin/bw",
            },
        },
    },
}
