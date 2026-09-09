-- agent-browser: Vercel Labs browser automation CLI for AI agents —
-- navigate, snapshot a11y trees, click/type/screenshot via a CLI.
--
-- Cheap-tier flake port (issue #20): upstream ships the linux-x64
-- build as a raw (unarchived) Bun-compile executable. Shuttle keeps
-- non-tarball sources in place in the build dir, so the asset is
-- installed directly from its download name. Runtime note: driving a
-- real browser needs a Chromium at run time (the flake wired nixpkgs
-- chromium via AGENT_BROWSER_EXECUTABLE_PATH; hosts provide their
-- own — not a pool concern for the CLI itself). Never strip/patchelf
-- Bun-compiled binaries.

return {
    default = snap {
        name = "agent-browser",
        version = "0.37.0",
        summary = "Browser automation CLI for AI agents",
        description = [[
            agent-browser is a browser automation CLI for AI agents:
            open tabs, navigate, snapshot accessibility trees, and
            click/type/screenshot through a daemon-backed CLI designed
            for non-visual agent loops. Needs a Chromium-family browser
            on the host at run time (AGENT_BROWSER_EXECUTABLE_PATH).
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/vercel-labs/agent-browser/releases/download/v0.37.0/agent-browser-linux-x64",
            sha256 = "78e0c5a14a7fa1f3d1ae2acdbdcc94a047b435b998a8c505fcc49d7fa4935a49",
        },

        -- Raw single-file asset: no archive, so the download lands in
        -- the build dir under its asset name (cwd = build dir).
        build = table.concat({
            "install -Dm755 agent-browser-linux-x64 $STAGE/usr/bin/agent-browser",
        }, " && "),

        type = "source",
        -- Bun-compile binary: only the glibc family (libc, ld-linux,
        -- libpthread, libdl, libm) in DT_NEEDED.
        requires = { "glibc" },

        apps = {
            ["agent-browser"] = app {
                command = "usr/bin/agent-browser",
            },
        },
    },
}
