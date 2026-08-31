-- jq built from source — alternate config showing the `build` field.
--
-- This demonstrates shuttle's source-fetch + build pipeline.
-- shuttle downloads the tarball, extracts it, and runs the build command
-- with $STAGE pointing to the stage directory.
--
-- Compare with:
--   Nix:       stdenv.mkDerivation { src = fetchurl { ... }; ... }
--   Snapcraft: parts: { jq: { plugin: autotools; source: ... } }
--   Shuttle:    snap { source = "...", build = "...", stage = "./stage/" }

return {
    default = snap {
        name = "jq",
        version = "1.8.1",
        summary = "Lightweight CLI JSON processor (built from source)",
        description = [[
            jq built from the upstream source tarball using
            autotools. Demonstrates the build-from-source pipeline.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",

        -- Source URL + pinned SHA-256 for reproducible builds.
        -- On first build, shuttle verifies the hash. On rebuild, the lockfile
        -- captures it so even bare URLs become pinned.
        source = {
            url = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz",
            sha256 = "300281f5a6690c9b5dc2966a6cf64d80fa6ea464d6753676a2ccac42b4b1bc8a",
        },

        -- Shell commands to build. $STAGE points to the stage directory.
        -- Runs inside the extracted source tree.
        build = table.concat({
            "./configure --prefix=/usr --disable-maintainer-mode",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },

        apps = {
            jq = app {
                command = "usr/bin/jq",
            },
        },
    },
}
