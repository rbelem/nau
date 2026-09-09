-- rtk: Rust Token Killer — high-performance CLI proxy that minimizes
-- LLM token consumption for common dev commands (grep/cat/ls and
-- friends get compressed, truncation-aware output).
--
-- Cheap-tier flake port (issue #20; the flake built this from source,
-- but upstream ships static musl releases — the cheaper path). The
-- linux musl tarball is fetched, sha256-pinned, and the statically
-- linked binary is staged into usr/bin (no pool deps).

return {
    default = snap {
        name = "rtk",
        version = "0.48.0",
        summary = "Token-efficient CLI proxy for LLM consumption",
        description = [[
            rtk is a CLI proxy that intercepts common development
            commands (grep, ls, git output, file reads) and re-emits
            their output compressed and truncation-aware, drastically
            cutting the token cost of feeding tool output to LLMs.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/rtk-ai/rtk/releases/download/v0.48.0/rtk-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "e4e650fa1677c0de2f6839a6040d7b17f312d32f163c402b75af70e9e5af1a91",
        },

        -- Flat stripped tarball root: just the binary.
        build = table.concat({
            "install -Dm755 rtk $STAGE/usr/bin/rtk",
        }, " && "),

        type = "source",
        -- x86_64-unknown-linux-musl release: fully static ELF.
        requires = {},

        apps = {
            rtk = app {
                command = "usr/bin/rtk",
            },
        },
    },
}
