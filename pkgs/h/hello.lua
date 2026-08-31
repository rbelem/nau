-- Hello snap — shuttle.lua equivalent of:
--
-- Nix:       pkgs.hello (stdenv.mkDerivation { pname = "hello"; ... })
-- Snapcraft: snapcraft.yaml with autotools plugin
--
-- Per ADR-0003: shuttle.lua always returns a table of named outputs.
-- Single-snap configs return { default = { ... } }.
-- Per ADR-0004: snap(...) returns a validated table — no mutation.

return {
    default = snap {
        name = "hello",
        version = "2.10",
        summary = "GNU Hello, the \"hello world\" snap",
        description = [[
            GNU hello prints a friendly greeting.
            This is part of the snapcraft tour at https://snapcraft.io/
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",

            -- Source URL (like Nix's `src` or Snapcraft's `parts.*.source`).
        -- In v1 this is informational — binaries come from ./stage/.
        -- Future phases will add fetching and building from source.
        source = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",

        -- Per CONTEXT.md binary staging model:
        -- --stage directory (default ./stage/) contains pre-built binaries
        stage = "./stage/",

        -- Supported architectures
        architectures = { "amd64", "arm64" },
        type = "source",
        requires = { "glibc" },

        -- Apps declared in the snap
        apps = {
            hello = app {
                command = "bin/hello",
            },
        },
    },
}
