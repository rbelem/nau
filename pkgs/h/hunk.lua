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
        version = "0.22.0",
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
            url = "https://github.com/modem-dev/hunk/releases/download/v0.22.0/hunkdiff-linux-x64.tar.gz",
            sha256 = "5f280374f2ab0fc4c48266a9909ee1b0e0c59d77dd99a340f1c26f2125d2229b",
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
