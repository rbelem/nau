-- Node.js 22 LTS: JavaScript runtime built on Chrome's V8 (maintenance
-- LTS line 22), as a sibling of node.lua (current 26).
--
-- Exists for interpreter-pinned consumers that V8-current breaks:
-- @colbymchenry/codegraph hard-blocks node >= 25 at CLI startup (the
-- turboshaft WASM Zone OOM, upstream colbymchenry/codegraph#81). The app is named
-- `node22`, NOT `node`: the interpreter contract is a bare binary name
-- resolved from the calling shell's PATH at runtime, so a distinct
-- name lets codegraph pin node 22 (`interpreter = "node22"`) while a
-- pod keeps the current line as `node` — no farm collision, no
-- shadowing of the pod's own node for anything else. Consumers declare
-- this package in their `requires` (the impeccable interpreter-in-
-- requires precedent), and pods that want the owned-lifecycle version
-- compose it via `loads = { "<pod>" }` — see the codegraph pod.
--
-- Same artifact class as node.lua: official prebuilt linux-x64
-- tarball, build only relayouts into $STAGE; the #12 portability step
-- repoints the ELF interpreter/RUNPATH at build time.

return {
    default = snap {
        name = "node22",
        version = "22.23.3",
        summary = "Node.js JavaScript runtime (V8, LTS 22)",
        description = [[
            Node.js is a JavaScript runtime built on Chrome's V8
            JavaScript engine, executing JS outside the browser with an
            event-driven, non-blocking I/O model. This package ships the
            official prebuilt linux-x64 binaries of the maintenance LTS
            22 line, exposed under the distinct binary name `node22` so
            consumers can pin pre-25 V8 (codegraph's turboshaft Zone
            guard) without touching a pod's current-line node.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz",
            sha256 = "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de",
        },

        -- The tarball root is node-v<version>-linux-x64/ and $SRC points
        -- at it; only bin/ is staged. This package is a runtime
        -- interpreter: nothing compiles native addons against it
        -- (codegraph's runtime is WASM-only; zg's engine is a prebuilt
        -- ELF), and the pool node (ADR-0018) owns the build-side trees —
        -- a merged build prefix requires identical content at shared
        -- paths, so node22's include/ or lib/ would hard-conflict with
        -- node 26's (usr/include/node differs per version line).
        -- bin/node renames to bin/node22 for the same reason (two node
        -- versions staging usr/bin/node is exactly that conflict) and
        -- so the staged file mirrors the app name.
        build = table.concat({
            "mkdir -p $STAGE/usr/bin",
            "cp bin/node $STAGE/usr/bin/node22",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            -- App name `node22`, not `node`: consumers' interpreter
            -- wrappers exec this bare name, and pods keep their
            -- current-line node.lua side by side with no farm
            -- collision (see header). Only the node binary is exposed:
            -- npm/npx/corepack in the official tarball are symlinks
            -- into lib/node_modules, and the interpreter-wrapper pass
            -- rewrites the command file in place (following symlinks),
            -- so they are not safe to wrap.
            node22 = app {
                command = "usr/bin/node22",
            },
        },
    },
}
