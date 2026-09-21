-- jev-review: local-first software-quality evaluation for AI coding
-- agents, powered by Jev (MCP stdio server).
--
-- Packaged from the local workspace checkout
-- (~/Workspace/github.com/NiazMorshed2007/jev-review, v0.1.1): the
-- esbuild bundle dist/server.js (shebang `#!/usr/bin/env node`,
-- self-contained — @modelcontextprotocol/sdk + zod are bundled in, no
-- node_modules at runtime) plus package.json. Auth is env-only at
-- runtime: JEV_API_KEY (TypeSafe direct) or OPENROUTER_API_KEY
-- (/^sk-or-/); a missing key surfaces at tool-call time, never at
-- startup, so the pod carries no secrets.
--
-- SOURCE STABILITY: shuttle build sources must be http(s) — the build
-- fetch path rejects file:// and path: URLs outright — and local-path
-- sources are not supported anywhere in the DSL. The payload tarball
-- therefore lives at ~/.local/share/shuttle/inputs/jev-review-0.1.1.tgz
-- (dist/ + package.json under a package/ top dir, sha256-pinned below)
-- and is served over loopback HTTP during builds:
--   (cd ~/.local/share/shuttle/inputs && \
--      python3 -m http.server 8921 --bind 127.0.0.1)
-- Bring the server up for `pod rebuild jev-review` AND before any full
-- plain `pod sync` — a plain sync rebuilds every non-held package, not
-- just changed ones (observed live 2026-09-20); a SCOPED reconcile
-- (`pod rebuild <other>`) skips non-selected installed packages
-- entirely (OwnScope::SkipInstalled) and needs no server.
--
-- The app is declared the anydoc.lua way: command = the in-payload
-- server.js, interpreter = "node" (issue #9/#13) — the tree wrapper
-- execs node on the extension-tree path, the only runtime-correct
-- shape for a __dirname-resolving bundle. `node` in requires covers
-- the interpreter; glibc covers node itself.
--
-- build_deps: (none).

return {
    default = snap {
        name = "jev-review",
        version = "0.1.1",
        summary = "Local-first software-quality evaluation MCP server for AI coding agents",
        description = [[
            jev-review evaluates AI coding agents' work locally and
            serves the verdicts over the Model Context Protocol on
            stdio. Powered by Jev (TypeSafe direct via JEV_API_KEY or
            OpenRouter via OPENROUTER_API_KEY). Ships the esbuild
            single-file bundle staged in place, run by the pod's node
            interpreter.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "http://127.0.0.1:8921/jev-review-0.1.1.tgz",
            sha256 = "d87e2644be09b713bd95e5dacaa3cf83f0fa934a4b5e26f0a5dc2cc3a273db1a",
        },

        -- Tarball is npm-tgz shaped (single package/ top dir): shuttle's
        -- find_source_root strips it — build cwd and $SRC are the package
        -- dir itself, so the script addresses package.json and
        -- dist/server.js flat (found live 2026-09-20).
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/jev-review",
            "mkdir -p \"$pkg/dist\"",
            "cp package.json \"$pkg/\"",
            "cp dist/server.js \"$pkg/dist/\"",
            "chmod +x \"$pkg/dist/server.js\"",
        }, " && "),

        type = "source",
        requires = { "glibc", "node" },

        apps = {
            ["jev-review"] = app {
                command = "usr/lib/node_modules/jev-review/dist/server.js",
                interpreter = "node",
            },
        },
    },
}
