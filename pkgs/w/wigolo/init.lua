-- wigolo: local-first web intelligence for AI agents
-- (KnockOutEZ/wigolo v0.2.1).
-- https://github.com/KnockOutEZ/wigolo
--
-- Three-way comparison:
--
-- Nix:       devbox-global's devbox.d/wigolo flake (buildNpmPackage
--            over the GitHub source, prebuilt dist/ injected from the
--            npm tarball, better-sqlite3/sqlite-vec rebuilt against
--            the matching node headers)
-- Snapcraft: no upstream snap
-- Shuttle:   declarative Lua — npm-tarball relayout (agentmemory
--            pattern), carrying a `services` declaration (ADR-0032
--            Decision 2)
--
-- Port strategy (mirrors agentmemory.lua): the npm registry tarball
-- ships prebuilt dist/ (tsup output, `bin` → dist/index.js), so the
-- build is a pure relayout into usr/lib/wigolo plus a self-locating sh
-- launcher at usr/bin/wigolo for the service entry.
--
-- KNOWN GAP (agentmemory shape): dist/ is UNBUNDLED — the compiled
-- files bare-import the npm runtime closure at runtime
-- (@anthropic-ai/sdk, @google/genai, groq-sdk, @huggingface/transformers,
-- @modelcontextprotocol/sdk, ink, @inquirer/prompts, better-sqlite3,
-- …). The tarball ships no package-lock.json and the sandbox is
-- net-unshared, so the production node_modules tree the flake installs
-- cannot be reproduced here: code paths touching those imports fail
-- until either (a) a deps.npm closure lands from a lockfile source
-- (zg.lua pattern), or (b) upstream starts shipping a lockfile — plus
-- a native-module story for better-sqlite3 (the flake rebuilds it per
-- node ABI). Flagged rather than silently assumed complete.
--
-- requires: glibc for the node runtime loader; node because both
-- entries exec the pool node runtime. build_deps: (none) — relayout
-- only.
--
-- sha256 note: the hex below was verified against the devbox-global
-- flake's npmDistHash — the flake's SRI
-- (sha256-0YS6Jl/wLdq1PyEkA1zVcqCLetjVBxjO/2IMRmNOcDI=) decodes to
-- d184ba26…7032, byte-identical to the tarball served by
-- registry.npmjs.org: both pins carry the same bytes.
--
-- require note: `lib/daemon` is the analyzer-resolvable spelling of
-- the shared service() constructor (see valkey's header).

local svc = require("lib/daemon").service

return {
    default = snap {
        name = "wigolo",
        version = "0.2.1",
        summary = "Local-first web intelligence for AI coding agents (MCP + CLI)",
        description = [[
            wigolo gives AI agents local-first web intelligence:
            search, fetch, crawl, cache, extraction, and research over
            an on-disk store, exposed as an MCP server (`wigolo serve`)
            and a CLI. Relaid out from the npm registry tarball's
            prebuilt dist/ (agentmemory pattern). NOTE: the npm runtime
            closure is not yet provisioned — see the port header.
            Declares a `wigolo` pod service (ADR-0032) with port and
            data-dir options, disabled by default.
        ]],
        license = "AGPL-3.0-only",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://registry.npmjs.org/wigolo/-/wigolo-0.2.1.tgz",
            sha256 = "d184ba265ff02ddab53f2124035cd572a08b7ad8d50718ceff620c46634e7032",
        },

        -- The tarball's top dir is package/ ($SRC descends into it).
        -- dist + package.json go to usr/lib/wigolo (package.json stays
        -- ABOVE dist/: dist files are ESM and node reads "type":
        -- "module" by walking up from the entry). The launcher resolves
        -- the payload root by three dirnames through the farm symlink
        -- chain (agentmemory pattern) — no readlink, so it works from
        -- the farm command, the merged prefix, and a store tree.
        build = table.concat({
            "pkg=$STAGE/usr/lib/wigolo",
            "mkdir -p \"$pkg\" $STAGE/usr/bin",
            "cp -r $SRC/dist $SRC/package.json \"$pkg/\"",
            "printf '%s\\n' '#!/bin/sh' 'root=$(dirname \"$(dirname \"$(dirname \"$0\")\")\")' 'exec node \"$root/usr/lib/wigolo/dist/index.js\" \"$@\"' > $STAGE/usr/bin/wigolo",
            "chmod +x $STAGE/usr/bin/wigolo",
        }, " && "),

        type = "source",
        requires = { "glibc", "node" },

        apps = {
            -- The app command is the JS entry with the interpreter
            -- wrapper (zg.lua pattern): the farm resolves node from the
            -- pod. The usr/bin/wigolo launcher exists for the service
            -- entry below.
            wigolo = app {
                command = "usr/lib/wigolo/dist/index.js",
                interpreter = "node",
            },
        },

        services = {
            wigolo = svc {
                -- The launcher execs bare `node`, which systemd's
                -- default PATH does not carry: the unit environment
                -- must resolve the pod farm's node (the interpreter
                -- wrapper above cannot serve a service command in v1).
                -- The bootstrap unit (examples/cutover/shuttle-wigolo.service)
                -- sets Environment=PATH over the generation root.
                command = "usr/bin/wigolo",
                daemon  = "simple",
                args    = { "serve", "--port", "${port}" },
                options = {
                    port     = 3333,
                    data_dir = "%h/.local/share/wigolo",
                    enabled  = false,
                },
                environment = {},
            },
        },
    },
}
