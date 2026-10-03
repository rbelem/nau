-- Node.js: JavaScript runtime built on Chrome's V8 — ONE package, two
-- version lines selected by constraint (ADR-0047): `node` resolves the
-- current 26 line, `node@22` the maintenance LTS line. There is no
-- node22 package: two lines coexist ACROSS pods, never within one, and
-- a pod pins its line with the constraint, not a renamed sibling.
--
-- Ported from the devbox global profile into a nau source package.
-- Uses the official prebuilt linux-x64 binaries (same artifact class as
-- nixpkgs' nodejs): the build only relayouts the tarball into $STAGE;
-- the #12 portability step repoints the ELF interpreter/RUNPATH at build
-- time so the binary runs on plain hosts without the nix store.

local lines = {
    ["26"] = {
        version = "26.7.0",
        url = "https://nodejs.org/dist/v26.7.0/node-v26.7.0-linux-x64.tar.xz",
        sha256 = "982aa24dd8be4c889c6a8ab337ddff3b0896645b20f4239356e80552c16277ee",
    },
    ["22"] = {
        version = "22.23.3",
        url = "https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz",
        sha256 = "df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de",
    },
}

-- Line selection (ADR-0047 Decision 4): the pod spec's `@constraint`
-- rides the eval as the `constraint` global — nil means unconstrained,
-- which keeps the current 26 line. Selection is pure data (no fetch()),
-- so the lockfile pin `{version, constraint}` reproduces it. A
-- constraint naming no declared line REFUSES: a line dropped upstream
-- must fail the sync loud, never silently re-pin another line.
local line = constraint and constraint:match("^(%d+)") or "26"
local picked = lines[line]
if picked == nil then
    error(string.format(
        "node: constraint '@%s' selects no declared line (declared: 22, 26) — \
         refusing to pin another line; widen the constraint or drop the pin",
        tostring(line)), 2)
end

return {
    default = snap {
        name = "node",
        version = picked.version,
        summary = "Node.js JavaScript runtime (V8, line " .. line .. ")",
        description = [[
            Node.js is a JavaScript runtime built on Chrome's V8
            JavaScript engine, executing JS outside the browser with an
            event-driven, non-blocking I/O model. This package ships the
            official prebuilt linux-x64 binaries of the ]] .. line .. [[
            version line, which interpreter-based pod packages (e.g. zg,
            codegraph) exec at runtime via their `interpreter = "node"`
            app wrappers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        lines = lines,

        source = {
            url = picked.url,
            sha256 = picked.sha256,
        },

        -- The tarball root is node-v<version>-linux-x64/ and $SRC points
        -- at it; relayout bin/lib/include/share into the /usr prefix.
        -- bin/npm and bin/npx arrive as relative symlinks into
        -- lib/node_modules (corepack is no longer shipped on the
        -- current line); the interpreter-wrapper pass rewrites command
        -- files in place FOLLOWING symlinks, so an app declared on the
        -- link would clobber npm-cli.js — the staged entries are real
        -- files instead. A COPY of npm-cli.js does not work either: it
        -- requires `../lib/cli.js` anchored at its own location, which
        -- only resolves inside lib/node_modules/npm — a copy stranded
        -- in bin/ dies with MODULE_NOT_FOUND at runtime. The staged
        -- entries are therefore two-line BOOTSTRAPS that require the
        -- entry files in place; the #9 wrapper execs the bootstrap from
        -- the generation tree, every require resolves inside npm's own
        -- staged tree, and the bare `node` on PATH is the same line
        -- (ADR-0047 Decision 2).
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -r bin lib include share $STAGE/usr/",
            "rm $STAGE/usr/bin/npm $STAGE/usr/bin/npx",
            "printf '%s\\n' '#!/usr/bin/env node' \"require('../lib/node_modules/npm/bin/npm-cli.js')\" > $STAGE/usr/bin/npm",
            "printf '%s\\n' '#!/usr/bin/env node' \"require('../lib/node_modules/npm/bin/npx-cli.js')\" > $STAGE/usr/bin/npx",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            -- `node` is the ELF runtime (the #12 portability step
            -- repoints its interpreter/RUNPATH at build time). npm and
            -- npx are the staged bootstrap entries (see build):
            -- declared with `interpreter = "node"` so the #9 pass
            -- preserves each at a `.real` sibling and wraps it with an
            -- exec of the bare interpreter name — resolved from PATH at
            -- runtime (pod farm or a consumer's merged build prefix).
            -- The bare name is correct BECAUSE one pod holds one line
            -- (ADR-0047 Decision 2): the interpreter on PATH is always
            -- the same line as the staged script tree. Unsuffixed apps
            -- bind to the pod's selected line.
            node = app {
                command = "usr/bin/node",
            },
            npm = app {
                command = "usr/bin/npm",
                interpreter = "node",
            },
            npx = app {
                command = "usr/bin/npx",
                interpreter = "node",
            },
        },
    },
}
