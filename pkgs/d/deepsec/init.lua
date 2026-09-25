-- deepsec: AI-powered vulnerability scanner for any codebase.
--
-- Pool port (issue #203) of devbox-global devbox.d/deepsec @
-- 23a69227e3380e6b44a7ebd93c52e023c59f17c3 (mirror-don't-bump: upstream
-- has no tags, the flake pins a main commit; version "2.3.9" mirrors
-- packages/deepsec's package.json at that rev).
--
-- Tier: npm dep-fetch (ADR-0017) over the npm REGISTRY TARBALL, not a
-- source build — this is the pnpm-vs-npm question settled. The flake
-- builds the pnpm workspace from source (vendored pnpm-lock.yaml v9,
-- pnpm_10, esbuild bundle in-sandbox) because nix has no registry
-- shortcut; the pool does: deepsec@2.3.9 IS npm-distributed and its
-- registry dist.tgz carries the prebuilt payload (dist/cli.mjs +
-- config.mjs, docs, samples; 29 files) with
-- dist.integrity/provenance and — the pin cross-check — gitHead EQUAL
-- to the flake's source rev. The build is therefore the agentmemory
-- relayout: stage dist + package.json, vendor the production-only
-- node_modules closure beside it (zg.lua tar-copy pattern; dist's
-- bare-specifier imports — the externalized agent SDKs @openai/codex,
-- @anthropic-ai/claude-agent-sdk, pi-coding-agent, @vercel/sandbox,
-- jiti — resolve via node's upward node_modules walk, the same runtime
-- shape the flake's installPhase replicates by hand).
--
-- Lockfile (recipe-local per the completed-port pattern): upstream
-- ships pnpm-lock.yaml (v6.0 in-tree; the flake vendors a pnpm-10
-- regeneration), which the pool's npm resolver cannot consume —
-- resolvers are npm/pip/cargo/go only (dep_fetch.rs). Converted to a
-- recipe-local package-lock.json the agentmemory way: `npm install
-- --package-lock-only --omit=dev --ignore-scripts` against the
-- registry tarball's package.json, generated 2026-09-25 with npm 10.9
-- / node 22 (339 lock entries; @openai/codex resolved 0.153.4 within
-- ^0.153.2, the agent binaries ride npm-alias optionalDeps with
-- per-artifact integrity). devDependencies were stripped from the
-- generator copy first — they are build-only for the source build this
-- port does not do (workspace:* protocol specifiers — @deepsec/core et
-- al — are unresolvable by npm and irrelevant without the bundler).
-- Regenerate on bump. The recipe dir records lock_sha256 beside the
-- deps_hash pin (ADR-0017 addendum 2026-09-21).
--
-- requires: node only (engines >= 22; pool node is 26; glibc arrives
-- transitively through node). The closure's native bits are the codex
-- musl agent binaries (static, alias-optional) — no glibc-dynamic
-- addons, so no libgcc.
--
-- Like the flake, only the deepsec CLI is exposed: the agent SDKs are
-- node_modules imports resolved inside the payload, not PATH spawns.

return {
    default = snap {
        name = "deepsec",
        version = "2.3.9",
        summary = "AI-powered vulnerability scanner for any codebase",
        description = [[
            deepsec scans a project for vulnerabilities with regex
            matchers, investigates candidates with an AI coding agent
            (codex / claude / pi SDKs), and produces markdown + JSON
            reports. This port ships the prebuilt npm dist payload with
            its production node_modules closure vendored recipe-locally.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://registry.npmjs.org/deepsec/-/deepsec-2.3.9.tgz",
            sha256 = "e431ea0f17a98235610666e3539fdbf14dd55fe2bdaecc5210db76a3f06e987b",
        },

        deps = {
            npm = { lock = "recipe/package-lock.json" },
        },

        -- Relayout (agentmemory pattern): the tgz's package/ top dir
        -- flattens into $SRC; dist + manifest + doc surfaces go to
        -- usr/lib/node_modules/deepsec, the production-only node_modules
        -- closure lands beside them so the externalized SDK imports
        -- resolve on the upward walk.
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/deepsec",
            'mkdir -p "$pkg"',
            'cp -r $SRC/dist $SRC/package.json "$pkg/"',
            'cp $SRC/README.md $SRC/LICENSE $SRC/NOTICE $SRC/SKILL.md "$pkg/"',
            'tar -C "$SHUTTLE_DEPS_DIR" -cf - node_modules | tar -C "$pkg" -xf -',
        }, " && "),

        type = "source",
        requires = { "node" },

        apps = {
            deepsec = app {
                command = "usr/lib/node_modules/deepsec/dist/cli.mjs",
                interpreter = "node",
            },
        },
    },
}
