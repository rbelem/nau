-- doggo: a modern command-line DNS client (like dig) written in Go,
-- supporting DoH/DoT/DoQ with human- and JSON-friendly output.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream linux x86_64 tarball is fetched, sha256-pinned, and the
-- doggo binary (flat at the tarball root, static Go binary) is staged
-- directly into usr/bin.

return {
    default = snap {
        name = "doggo",
        version = "1.3.0",
        summary = "Modern command-line DNS client (like dig)",
        description = [[
            doggo is a command-line DNS client for humans. It supports
            UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC
            transports, all common record types, and outputs plain text
            or JSON. A friendlier alternative to dig/kdig.
        ]],
        license = "GPL-3.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/mr-karan/doggo/releases/download/v1.3.0/doggo-linux-x86_64.tar.gz",
            sha256 = "c0d3f064ab40670720b30833a71e6178ed84242ea53ffb5dfab7b315dcce61c2",
        },

        build = table.concat({
            "install -Dm755 doggo $STAGE/usr/bin/doggo",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            doggo = app {
                command = "usr/bin/doggo",
            },
        },
    },
}
