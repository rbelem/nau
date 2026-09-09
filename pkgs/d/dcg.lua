-- dcg: Destructive Command Guard — blocks dangerous git/shell
-- commands from being executed by AI coding agents.
--
-- Cheap-tier flake port (issue #20): the upstream musl Rust release
-- tarball is fetched, sha256-pinned, and the statically linked binary
-- is staged into usr/bin (no pool deps). Upstream's LICENSE is MIT
-- with an OpenAI/Anthropic rider (bounded-use clause on training the
-- models named in the license text).

return {
    default = snap {
        name = "dcg",
        version = "0.14.1",
        summary = "Destructive Command Guard for AI coding agents",
        description = [[
            dcg is a destructive command guard: it inspects shell and
            git commands coming from AI coding agents and blocks
            dangerous operations (force pushes, history rewrites, bulk
            deletions) before they execute. Hooks into Claude Code,
            Codex, and other agent harnesses as a command pre-check.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/Dicklesworthstone/destructive_command_guard/releases/download/v0.14.1/dcg-x86_64-unknown-linux-musl.tar.xz",
            sha256 = "e7b39be070ad98f74a1edd59fefb8ac41865ab2aa2c5a4252eb71c5413f3f9df",
        },

        -- tar.xz asset with a flat stripped root: just the binary.
        build = table.concat({
            "install -Dm755 dcg $STAGE/usr/bin/dcg",
        }, " && "),

        type = "source",
        -- x86_64-unknown-linux-musl release: fully static ELF.
        requires = {},

        apps = {
            dcg = app {
                command = "usr/bin/dcg",
            },
        },
    },
}
