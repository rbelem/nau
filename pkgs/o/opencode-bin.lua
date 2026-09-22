-- opencode-bin: the open source coding agent, v2 line
-- (anomalyco/opencode) — the `opencode` CLI, packaged from the
-- upstream prebuilt binary, always latest.
--
-- This is the V2 product line (docs at opencode.ai/v2/docs), the one
-- the V2-schema config at ~/.config/opencode targets. It is NOT
-- published as GitHub release objects: GitHub releases serve the 1.x
-- line only (the reason an earlier revision of this package resolved
-- to 1.18.31 and rejected V2 configs). V2 binaries live on the CDN at
-- opencode.ai/files/bin/<version>/.
--
-- Always-latest, the Lua way: the DSL's fetch() global (eval-time HTTP
-- GET) reads upstream's own release channel — the same endpoint the
-- official install script uses — and the definition interpolates the
-- version into the CDN asset URL. Every build re-resolves; no hand
-- bumps. The source stays deliberately NOT sha256-pinned (an unpinned
-- source is shuttle's supported mode for floating content; the
-- observed hash is recorded in the lockfile and printed as a pin
-- hint). `shuttle build --offline` and `shuttle eval --offline`
-- refuse fetch() by name; `shuttle check` of this file needs network.
--
-- Asset choice: opencode-linux-x64-baseline.tar.gz — the glibc build
-- (the -musl assets are dynamically linked against ld-musl and cannot
-- run on glibc hosts), baseline variant (no AVX2 requirement — the
-- oh-my-pi precedent for bun-compiled binaries). Never strip/patchelf
-- Bun-compiled binaries: they embed their JS bytecode and corrupt
-- under ELF rewriting (oh-my-pi precedent).
--
-- requires = { glibc }: the bun-compiled glibc build's DT_NEEDED is
-- the glibc family only — the JS runtime is self-contained; LLM
-- credentials come from the environment at run time.

local channel_url = "https://opencode.ai/update/api/latest/cli/npm"
local channel_body = fetch(channel_url)
local version = string.match(channel_body, '"version":"([%w%.]+)"')
assert(version and #version > 0, "opencode-bin: could not resolve the latest v2 release from " .. channel_url)

return {
    default = snap {
        name = "opencode-bin",
        version = version,
        summary = "The open source coding agent, v2 line (opencode)",
        description = [[
            opencode is an AI coding agent built for the terminal:
            multi-model agentic coding with LSP-aware context. This is
            the v2 line: the upstream prebuilt bun-compiled baseline
            release binary, resolved to the latest v2 release at build
            time via upstream's own release channel. LLM credentials
            come from the environment at run time.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://opencode.ai/files/bin/" .. version .. "/opencode-linux-x64-baseline.tar.gz",
        },

        build = table.concat({
            "install -Dm755 opencode $STAGE/usr/bin/opencode",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            opencode = app {
                command = "usr/bin/opencode",
            },
        },
    },
}
