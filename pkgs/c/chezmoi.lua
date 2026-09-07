-- chezmoi: manage your dotfiles across multiple machines, securely.
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- chezmoi binary (flat at the tarball's stripped root, static Go
-- binary) is staged directly into usr/bin.

return {
    default = snap {
        name = "chezmoi",
        version = "2.70.5",
        summary = "Manage dotfiles across multiple machines",
        description = [[
            chezmoi keeps your dotfiles in a source directory, templated
            for machine-specific values, and applies them to your home
            directory with a single command. It supports encryption,
            secrets-manager integration, scripts, and diffing before
            applying changes.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/twpayne/chezmoi/releases/download/v2.70.5/chezmoi_2.70.5_linux-musl_amd64.tar.gz",
            sha256 = "4892f688c759b88ab937f1d94e06177cdd405b48022f080b8659daed2f1c2506",
        },

        -- Tarball layout gotcha: this release tarball is flat EXCEPT for
        -- a single top-level directory (completions/), which the source-
        -- root finder (find_source_root) picks as $SRC/cwd. Resolve the
        -- binary against $SRC/.. so the build works for either layout.
        build = table.concat({
            "install -Dm755 \"$SRC/../chezmoi\" $STAGE/usr/bin/chezmoi",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            chezmoi = app {
                command = "usr/bin/chezmoi",
            },
        },
    },
}
