-- agentmemory: persistent memory for AI coding agents (rohitg00/agentmemory).
--
-- Ported from devbox-global's devbox.d/agentmemory flake. The flake is a
-- dontBuild relayout of the npm registry tarball (pre-built dist/, no
-- TypeScript build) plus TWO runtime pieces wired around it: the
-- production-only node_modules tree (fetchNpmDeps + `npm install
-- --production --ignore-scripts`), and the embedded iii-engine binary
-- (iii-hq/iii v0.11.2, pinned because agentmemory's iii-sdk dependency
-- locks that version), PATH-wrapped so the CLI finds it.
--
-- Multi-artifact staging uses the `sources` map (issue #41): the npm
-- tarball lands at $SRC/npm (its `package/` top dir flattens) and the
-- iii release tarball at $SRC/iii. Both sha256s cross-check against the
-- flake's fetchurl SRIs (base64→hex match, verified).
--
-- KNOWN GAP (reported in the porting dossier): the npm tarball ships NO
-- package-lock.json and an UNBUNDLED dist/ (78 files, requires
-- @anthropic-ai/sdk, zod, dotenv, iii-sdk, ... at runtime), so the
-- production node_modules closure the flake installs cannot be
-- reproduced here: deps.npm needs a lockfile in the source tree (absent)
-- and the sandbox is net-unshared (no `npm install`). This package
-- stages everything else verbatim — dist, package.json, the iii config
-- surfaces (iii-config.yaml, docker-compose.yml, .env.example), plugin/,
-- and the iii binary — but `agentmemory` will fail on its first module
-- import
-- until either (a) upstream ships a package-lock.json (then add
-- deps = { npm = { lock = "package-lock.json" } } following zg.lua), or
-- (b) the DSL grows a fetch-time lockfile-generation hook mirroring the
-- flake's postPatch `npm install --package-lock-only`. Flagged rather
-- than silently shipping a half payload.
--
-- requires: glibc for both ELFs; libgcc for the iii Rust binary (ldd);
-- node because the launcher execs the pool node runtime (same runtime
-- resolution zg.lua's interpreter = "node" wrapper relies on).
--
-- build_deps: (none).

return {
    default = snap {
        name = "agentmemory",
        version = "0.9.29",
        summary = "Persistent memory for AI coding agents (iii-engine backed)",
        description = [[
            agentmemory silently captures what your AI coding agent
            does, compresses it into searchable memory, and injects the
            right context when the next session starts. Built on
            iii-engine primitives; ships the prebuilt dist payload plus
            the pinned iii v0.11.2 engine binary. NOTE: the production
            node_modules closure is not yet provisioned — see the port
            header in the package definition.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        sources = {
            npm = {
                url = "https://registry.npmjs.org/@agentmemory/agentmemory/-/agentmemory-0.9.29.tgz",
                sha256 = "31376ec03d9dfccdc8f0a0bd357de9600c13d3a41a8351b310f0ea5a78f06774",
            },
            iii = {
                url = "https://github.com/iii-hq/iii/releases/download/iii/v0.11.2/iii-x86_64-unknown-linux-gnu.tar.gz",
                sha256 = "9c83c47788b4ef4beeb65dd9bf37e94f993770cd3db874464c3ce1cdc92352cd",
            },
        },

        -- Mirror the flake's installPhase: dist + package.json + the
        -- config surfaces into lib/node_modules/@agentmemory/agentmemory
        -- (the tarball ships plugin/ too — cursor/hooks/opencode payloads
        -- behind the flake's `[ -d plugin ]` conditional — copied the
        -- same way), iii into usr/bin (its PATH-wrap, realized by the
        -- launcher below), and a self-locating sh launcher instead of
        -- makeWrapper: three-dirname resolves the payload root through
        -- the farm's symlink chain, PATH gets the payload's usr/bin (so
        -- the CLI's `iii` spawn resolves), then node runs the real
        -- in-payload cli.mjs (a store-blob copy would lose its siblings).
        build = table.concat({
            "pkg=$STAGE/usr/lib/node_modules/@agentmemory/agentmemory",
            "mkdir -p \"$pkg\" $STAGE/usr/bin",
            "cp -r $SRC/npm/dist $SRC/npm/package.json $SRC/npm/plugin \"$pkg/\"",
            "cp $SRC/npm/iii-config.yaml $SRC/npm/docker-compose.yml $SRC/npm/.env.example \"$pkg/\"",
            "install -m755 $SRC/iii/iii $STAGE/usr/bin/iii",
            "printf '%s\\n' '#!/bin/sh' 'root=$(dirname \"$(dirname \"$(dirname \"$0\")\")\")' 'PATH=\"$root/usr/bin:$PATH\"' 'exec node \"$root/usr/lib/node_modules/@agentmemory/agentmemory/dist/cli.mjs\" \"$@\"' > $STAGE/usr/bin/agentmemory",
            "chmod +x $STAGE/usr/bin/agentmemory",
        }, " && "),

        type = "source",
        requires = { "glibc", "node", "libgcc" },

        apps = {
            agentmemory = app {
                command = "usr/bin/agentmemory",
            },
        },
    },
}
