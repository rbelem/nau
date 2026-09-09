-- herdr: terminal workspace manager for AI coding agents
-- (ogulcancelik/herdr) — sessions → workspaces → tabs → panes,
-- agent-aware.
--
-- Medium-tier flake port survey (issue #25): the flake is a prebuilt
-- release fetch, not a source build — ported as a release-fetch
-- package in the #20 pattern (the cheap-tier batch missed this one).
-- The raw linux-x86_64 release asset is fetched, sha256-pinned
-- (digest cross-checked against the flake pin), and installed
-- directly (open-code-review raw-asset pattern).
--
-- requires = {}: the release binary is a static-pie ELF (fully self-
-- contained, matching the #20 static-Go-binary precedent) — nothing
-- to resolve at run time.

return {
    default = snap {
        name = "herdr",
        version = "0.9.0",
        summary = "Terminal workspace manager for AI coding agents",
        description = [[
            herdr is a terminal workspace manager (tmux replacement)
            built for coding agents: sessions, workspaces, tabs, and
            panes with agent lifecycle awareness. Ships as the
            self-contained static upstream release binary.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/ogulcancelik/herdr/releases/download/v0.9.0/herdr-linux-x86_64",
            sha256 = "4fa1a01158dd8043da92d31b270780b0dcc10603038d9b61cac4d81ab63fb71f",
        },

        build = table.concat({
            "install -Dm755 herdr-linux-x86_64 $STAGE/usr/bin/herdr",
        }, " && "),

        type = "source",
        requires = {},

        apps = {
            herdr = app {
                command = "usr/bin/herdr",
            },
        },
    },
}
