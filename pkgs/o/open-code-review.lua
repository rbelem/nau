-- open-code-review: Alibaba's AI-powered code review CLI — reviews
-- staged/committed changes or PRs and posts line-level findings.
--
-- Cheap-tier flake port (issue #20): upstream ships the linux-amd64
-- build as a raw (unarchived) executable asset. Shuttle keeps
-- non-tarball sources in place in the build dir, so the asset is
-- installed directly from its download name into usr/bin under the
-- package name. Statically linked Go (no pool deps).

return {
    default = snap {
        name = "open-code-review",
        version = "1.11.6",
        summary = "AI-powered code review CLI",
        description = [[
            open-code-review is an AI-powered code review CLI: it
            reviews staged or committed Git changes (or a PR branch
            range) against configurable review rules and emits
            line-level findings, optionally applying fixes.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/alibaba/open-code-review/releases/download/v1.11.6/opencodereview-linux-amd64",
            sha256 = "09f30595834f8297a592b51bf4707fb24728b2826a65915f1964c5563e4fb3bd",
        },

        -- Raw single-file asset: no archive, so the download lands in
        -- the build dir under its asset name (cwd = build dir).
        build = table.concat({
            "install -Dm755 opencodereview-linux-amd64 $STAGE/usr/bin/open-code-review",
        }, " && "),

        type = "source",
        -- Statically linked Go binary (no DT_NEEDED entries).
        requires = {},

        apps = {
            ["open-code-review"] = app {
                command = "usr/bin/open-code-review",
            },
        },
    },
}
