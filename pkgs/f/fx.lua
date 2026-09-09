-- fx: terminal JSON viewer and processor (Vercel Labs Go rewrite).
--
-- Cheap-tier flake port (issue #20): the upstream linux-x86_64
-- release tarball is fetched, sha256-pinned, and the static Go
-- binary is staged into usr/bin (no pool deps — CGO-free build).

return {
    default = snap {
        name = "fx",
        version = "0.0.3",
        summary = "Terminal JSON viewer and processor",
        description = [[
            fx is a terminal JSON viewer and processor: interactively
            explore, query, and transform JSON documents with
            JavaScript expressions and built-in reducers.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/vercel-labs/fx/releases/download/v0.0.3/fx-linux-x86_64.tar.gz",
            sha256 = "23d32e60233b24581b9ce1965b65bab6a46d5693a24add7817854aef3adf5bfb",
        },

        -- Tarball root carries the binary plus LICENSE/NOTICE files (no
        -- top-level dir), so cwd stays at the extraction root.
        build = table.concat({
            "install -Dm755 fx $STAGE/usr/bin/fx",
        }, " && "),

        type = "source",
        -- Statically linked Go binary (no DT_NEEDED entries).
        requires = {},

        apps = {
            fx = app {
                command = "usr/bin/fx",
            },
        },
    },
}
