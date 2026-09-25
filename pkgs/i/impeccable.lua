-- impeccable: design guidance for AI coding agents (pbakaus/impeccable)
-- — design skills, commands, and 44 deterministic anti-pattern detector
-- rules for AI-generated frontend design.
--
-- Port of devbox-global devbox.d/impeccable @ cli-v4.1.0 (pbakaus/
-- impeccable tag cli-v4.1.0; flake src hash
-- sha256-iVTEAA6SYMlLtIdFQkKvI1oSNzDowl1Rn665BBFpbqQ=, npm closure
-- sha256-6Ap8gATZ8KSh0tjgb/QrpzNgnSnKGo213Ukkbtmi+oU=). Same source as
-- the flake: the git tag tarball (the npm-published package differs —
-- the flake builds the git tree with a lockfile injected over bun.lock).
--
-- Architecture: the shipped CLI (cli/bin/cli.js) is an npm shim that
-- locates the Rust engine binary in order — $IMPECCABLE_BIN, the
-- @impeccable/cli-<os>-<arch> optional dependency in node_modules, the
-- ~/.impeccable version cache, then a hash-verified release download.
-- The flake's fetchNpmDeps (fetcherVersion 2) SKIPS optional deps, so
-- the flake ships no engine and downloads engine-v0.1.5 on first run.
-- This port ships the engine instead: the recipe-local lock keeps the
-- flake's exact pin @impeccable/cli-linux-x64 0.1.5, so locate()
-- resolves from the staged node_modules with zero runtime downloads
-- (pod-friendly; ADR-0017 §3 ELF repair repoints the engine at build
-- time). The flake lock's other 217 dev-flagged entries (ai SDKs,
-- puppeteer, playwright, svelte — installed unpruned by the flake's
-- dontNpmPrune) are build/test-only: the shim requires node builtins
-- plus ../../package.json, so they stay out of this closure.
--
-- package.json bin is empty upstream; the flake wraps node
-- cli/bin/cli.js directly — mirrored here via interpreter = "node"
-- (farm emitter resolves the pod runtime at emit time; no hand-rolled
-- launcher — the pod install materializes only claimed binaries).
--
-- engines: node >=22.18.0 per upstream package.json (the flake comment
-- says ">=24" but wraps nodejs_22; followed package.json's floor) —
-- pool node 26.7.0 fits.
--
-- requires: node (interpreter wrapper); glibc + libgcc for the engine
-- ELF (Rust binary, ldd'd against the system runtime). build_deps:
-- (none) — pure staging, no build.

return {
    default = snap {
        name = "impeccable",
        version = "4.1.0",
        summary = "Design guidance for AI coding agents",
        description = [[
            impeccable gives AI coding agents design taste: one skill,
            23 commands, live browser iteration, and 44 deterministic
            detector rules that catch AI-generated frontend
            anti-patterns. The package ships the npm shim plus the
            pinned Rust engine binary (@impeccable/cli-linux-x64
            0.1.5, the flake's exact pin), so no engine download ever
            happens at runtime. The npm dependency closure is declared
            via deps.npm against a recipe-local package-lock.json and
            fetched as a content-hashed pod-store entry (ADR-0017).
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/pbakaus/impeccable/archive/refs/tags/cli-v4.1.0.tar.gz",
            sha256 = "bd10f8801eb3be0a0b9ff60c47748cb6413a3681fc2e49cbdcb693c6d4f9b52a",
        },

        deps = {
            npm = { lock = "recipe/package-lock.json" },
        },

        -- Mirror the flake's installPhase: the cli/ shim dir plus
        -- package.json into lib/node_modules/impeccable, and the
        -- node_modules closure (the engine platform package) tar-copied
        -- next to them (agentmemory pattern) — createRequire from
        -- cli/bin/cli.js walks up to it and require.resolve
        -- ('@impeccable/cli-linux-x64/package.json') lands inside.
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/impeccable",
            'mkdir -p "$pkg"',
            'cp -r $SRC/cli $SRC/package.json "$pkg/"',
            'tar -C "$SHUTTLE_DEPS_DIR" -cf - node_modules | tar -C "$pkg" -xf -',
        }, " && "),

        type = "source",
        requires = { "glibc", "node", "libgcc" },

        apps = {
            impeccable = app {
                command = "usr/lib/node_modules/impeccable/cli/bin/cli.js",
                interpreter = "node",
            },
        },
    },
}
