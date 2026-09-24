-- codegraph: pre-indexed code knowledge graph for AI coding agents
-- (@colbymchenry/codegraph, rbelem fork with Perl grammar support).
-- https://github.com/rbelem/codegraph
--
-- Ported from devbox-global's devbox.d/codegraph flake (buildNpmPackage
-- over branch v1.6.x-perl). The flake.lock pins rev 439c2d4e (the
-- branch HEAD it resolved); this recipe pins the same rev's GitHub
-- archive tarball. The flake's SRI is a NAR-of-tree digest, so the
-- cross-check is at the rev level (skillspector precedent), not hash
-- equality.
--
-- Build: zg.lua pattern — the repo ships NO lockfile, so the npm
-- closure resolves from a RECIPE-LOCAL package-lock.json (generated
-- with the pod node's bundled npm 11, `npm install --package-lock-only
-- --ignore-scripts`; regenerate on bump). The closure INCLUDES dev
-- deps: typescript is a devDep and the sandbox build compiles with it
-- (`node node_modules/typescript/bin/tsc`), matching what the flake's
-- npmDepsHash closure carried. No exclude list: the runtime surface is
-- WASM-only (web-tree-sitter + tree-sitter-wasms grammars, no native
-- .node addons), so — unlike zg — there is nothing to prune and
-- requires stays at glibc alone.
--
-- The flake also built a python tree-sitter-perl binding; the node CLI
-- never imports it (grammars load as .wasm from tree-sitter-wasms) and
-- the pod's tree-sitter-perl (pkgs/t/tree-sitter-perl) serves the
-- python side, so it is not part of this port.
--
-- Engine gate: upstream hard-blocks node >= 25 at CLI startup
-- (src/bin/codegraph.ts — the V8 turboshaft Zone OOM guard) with
-- upstream's own override CODEGRAPH_ALLOW_UNSAFE_NODE=1; the actual
-- mitigation (--liftoff-only relaunch) runs inside the CLI either way.
-- The pod's node is 26.x, so the daily pod declares
--   env = { CODEGRAPH_ALLOW_UNSAFE_NODE = "1" }
-- per ADR-0030 (declared pod env) — shellenv and `shuttle run` both
-- overlay it, covering the MCP spawn (`codegraph serve --mcp`) and
-- interactive use alike.
--
-- requires: glibc only (the loader for the interpreter wrapper's node;
-- no ELF runtime deps of its own).
-- build_deps: node — the tsc compile needs a runtime in-sandbox; the
-- build prefix carries the pool node (ADR-0018 explicit-beats-implicit,
-- not the mirrored host PATH).

return {
    default = snap {
        name = "codegraph",
        version = "1.6.0-perl",
        summary = "Pre-indexed code knowledge graph for AI coding agents",
        description = [[
            CodeGraph gives AI coding agents a pre-indexed knowledge
            graph — symbol relationships, call graphs, and code
            structure — queried over MCP or the CLI instead of file
            scans. Built from the rbelem fork (v1.6.x-perl, restores
            the Perl grammar entries); the TypeScript is compiled in
            the sandbox with the fetched closure's own typescript and
            the WASM grammar assets are staged from the source tree.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/rbelem/codegraph/archive/439c2d4e7b13c00859de079d47c051f5260c3e95.tar.gz",
            sha256 = "f648f4c3e2f500c71b83dbefbcd8cf25ec7424d55ea40233c5628c2df4efcd2a",
        },

        deps = {
            npm = { lock = "recipe/package-lock.json" },
        },

        -- Mirror upstream's `npm run build` (tsc + copy-assets + chmod)
        -- against the mounted closure: tsc resolves imports by walking
        -- node_modules up from the source root, so the closure is
        -- linked there for the build; the SQL schema and WASM grammars
        -- are copied into dist/ the way copy-assets does.
        build = table.concat({
            'ln -s "$SHUTTLE_DEPS_DIR/node_modules" node_modules',
            "node node_modules/typescript/bin/tsc -p tsconfig.json",
            "mkdir -p dist/db dist/extraction/wasm",
            "cp src/db/schema.sql dist/db/schema.sql",
            'for w in src/extraction/wasm/*.wasm; do cp "$w" dist/extraction/wasm/; done',
            "chmod 755 dist/bin/codegraph.js",
            "mkdir -p $STAGE/usr/lib/node_modules/@colbymchenry/codegraph",
            "cp -r dist package.json $STAGE/usr/lib/node_modules/@colbymchenry/codegraph/",
            'tar -C "$SHUTTLE_DEPS_DIR" -cf - node_modules | tar -C $STAGE/usr/lib/node_modules/@colbymchenry/codegraph -xf -',
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "node" },

        apps = {
            codegraph = app {
                command = "usr/lib/node_modules/@colbymchenry/codegraph/dist/bin/codegraph.js",
                interpreter = "node",
            },
        },
    },
}
