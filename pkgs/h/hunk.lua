-- hunk: review-first terminal diff viewer for agent-authored
-- changesets.
--
-- Cheap-tier flake port (issue #20): the upstream linux-x64 release
-- tarball is fetched, sha256-pinned, and the Bun-compile binary is
-- staged into usr/bin. Only the binary ships (the tarball's
-- metadata.json and skills/ dirs are host-integration extras the
-- flake also skips). Never strip/patchelf Bun-compiled binaries: they
-- embed their JS bytecode and corrupt under ELF rewriting.

return {
    default = snap {
        name = "hunk",
        version = "0.21.1",
        summary = "Review-first terminal diff viewer",
        description = [[
            hunk is a review-first terminal diff viewer built for
            agent-authored changesets: renders unified and split diffs
            with syntax highlighting and review navigation, optimized
            for quickly judging what an AI coding agent changed.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/modem-dev/hunk/releases/download/v0.21.1/hunkdiff-linux-x64.tar.gz",
            sha256 = "c7d1e23ba4ffb6ca3330797e9f0c82dbada50e3cfe1b719f4194747f2cbca122",
        },

        -- Single top-level dir (hunkdiff-linux-x64/): the source-root
        -- finder makes it cwd, so the binary is addressed as `hunk`.
        build = table.concat({
            "install -Dm755 hunk $STAGE/usr/bin/hunk",
        }, " && "),

        type = "source",
        -- Bun-compile binary: only the glibc family (libc, ld-linux,
        -- libpthread, libdl, libm) in DT_NEEDED.
        requires = { "glibc" },

        apps = {
            hunk = app {
                command = "usr/bin/hunk",
            },
        },
    },
}
