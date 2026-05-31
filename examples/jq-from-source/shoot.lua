-- jq built from source — alternate config showing the `build` field.
--
-- This demonstrates shoot's source-fetch + build pipeline.
-- shoot downloads the tarball, extracts it, and runs the build command
-- with $STAGE pointing to the stage directory.
--
-- Compare with:
--   Nix:       stdenv.mkDerivation { src = fetchurl { ... }; ... }
--   Snapcraft: parts: { jq: { plugin: autotools; source: ... } }
--   Shoot:     snap { source = "...", build = "...", stage = "./stage/" }

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

        -- Source URL — downloaded by shoot when `build` is set
        source = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz",

        -- Shell commands to build. $STAGE points to the stage directory.
        -- Runs inside the extracted source tree.
        build = table.concat({
            "./configure --prefix=/usr --disable-maintainer-mode",
            "make -j$(nproc)",
            "make install DESTDIR=$STAGE",
        }, " && "),

        architectures = { "amd64" },

        apps = {
            jq = app {
                command = "usr/bin/jq",
            },
        },
    },
}
