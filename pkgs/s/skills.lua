-- skills: the vercel-labs/skills CLI — install and manage agent skills
-- across coding agents (add/list/remove/check skills in CLAUDE.md-style
-- frontmatter, tarball fetching, workspace handling).
--
-- Port of devbox-global devbox.d/skills @ v1.6.0 (vercel-labs/skills tag
-- v1.6.0, flake src hash sha256-nbRboP1tM7Jf0XcBgusg+7oPe9IwWwjRdqVO+cPagxs=,
-- pnpm closure sha256-Hyhg/7pcHT/jfT4Mz940P80nH+QmlKu6kJ2mu9iHkAY=).
--
-- Source deviation, deliberate: the flake builds the git tag (fetchFromGitHub
-- + fetchPnpmDeps with pnpm_10 pinned against the v9-format lockfile); the
-- git tree ships no dist/ — the payload is produced by obuild at publish
-- time — so this port stages the npm registry tarball (the published build
-- artifact, sha256-pinned below) instead of re-running the bundler pool-side.
-- bin/cli.mjs imports ../dist/cli.mjs; both ship in the tarball.
--
-- Dependency closure: deps.npm against a RECIPE-LOCAL package-lock.json
-- (ADR-0017 recipe-shipped lockfile; upstream ships pnpm-lock.yaml, which
-- has no npm-resolver analog). Generated from the published package.json
-- with devDependencies stripped (`npm install --package-lock-only
-- --ignore-scripts`; regenerate on bump): tar 7.5.22 / yaml 2.9.1 — fresh
-- in-range resolves of ^7.5.20 / ^2.8.3 (upstream's pnpm lock pinned
-- 7.5.20 / 2.9.0); the recipe lock plus the shuttle.lock deps_hash pin is
-- the reproducibility contract. Pure-JS closure (tar v7, yaml) — no native
-- addons, no ELF repair.
--
-- engines: node >=22.20.0 — the pool node package is 26.7.0, fits.
--
-- requires: node for the interpreter wrapper (the app command is a .mjs
-- the farm emitter wraps against the pod's node runtime); glibc rides in
-- with the node payload. build_deps: (none) — pure staging, no build.

return {
    default = snap {
        name = "skills",
        version = "1.6.0",
        summary = "The open agent skills ecosystem CLI (vercel-labs/skills)",
        description = [[
            skills installs and manages agent skills — folders with
            SKILL.md instructions — across AI coding agents (Claude
            Code, Codex, Cursor, OpenCode, and dozens more). Add skills
            from git URLs or local paths, list what is installed where,
            and check freshness. Built from the npm-published payload of
            the v1.6.0 tag; the npm dependency closure is declared via
            deps.npm against a recipe-local package-lock.json and
            fetched as a content-hashed pod-store entry (ADR-0017).
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://registry.npmjs.org/skills/-/skills-1.6.0.tgz",
            sha256 = "d8601291f5b5535bc411381d4e297690f10c0de48e01e8c7d3a78a66ef3e30e2",
        },

        deps = {
            npm = { lock = "recipe/package-lock.json" },
        },

        -- Registry tarball root (package/) flattens into $SRC: dist/,
        -- bin/, package.json. Stage the published payload into
        -- lib/node_modules/skills and tar-copy the production
        -- node_modules closure next to it (agentmemory pattern) so
        -- dist's bare imports (tar, yaml) resolve via node's upward
        -- node_modules walk. App command points at the payload-relative
        -- bin/cli.mjs (NOT a hand-rolled launcher): the pod install
        -- materializes only claimed binaries, and the farm emitter
        -- resolves the store path at emit time.
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/skills",
            'mkdir -p "$pkg"',
            'cp -r $SRC/dist $SRC/bin $SRC/package.json "$pkg/"',
            'tar -C "$SHUTTLE_DEPS_DIR" -cf - node_modules | tar -C "$pkg" -xf -',
        }, " && "),

        type = "source",
        requires = { "glibc", "node" },

        apps = {
            skills = app {
                command = "usr/lib/node_modules/skills/bin/cli.mjs",
                interpreter = "node",
            },
        },
    },
}
