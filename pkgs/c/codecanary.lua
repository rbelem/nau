-- codecanary: AI-powered code review for GitHub pull requests.
--
-- Cheap-tier flake port (issue #20): the upstream GoReleaser
-- linux_amd64 tarball is fetched, sha256-pinned, and the statically
-- linked Go binary is staged into usr/bin (no pool deps).

return {
    default = snap {
        name = "codecanary",
        version = "0.6.24",
        summary = "AI-powered code review for GitHub PRs",
        description = [[
            codecanary is an AI-powered code review tool for GitHub
            pull requests: it catches bugs, security issues, and
            quality problems before they land, supports multiple LLM
            providers (Anthropic, OpenAI, OpenRouter, Grok, Claude
            CLI), and offers incremental reviews and PR integration.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/alansikora/codecanary/releases/download/v0.6.24/codecanary_0.6.24_linux_amd64.tar.gz",
            sha256 = "bc719cd2481697d9573ce1284a002e65237d06369403f86bc9f941c5decbb676",
        },

        -- Tarball root: binary plus LICENSE/README (no top-level dir),
        -- so cwd stays at the extraction root.
        build = table.concat({
            "install -Dm755 codecanary $STAGE/usr/bin/codecanary",
        }, " && "),

        type = "source",
        -- Statically linked Go binary (no DT_NEEDED entries).
        requires = {},

        apps = {
            codecanary = app {
                command = "usr/bin/codecanary",
            },
        },
    },
}
