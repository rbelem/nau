-- jq: Lightweight and flexible command-line JSON processor
-- https://jqlang.github.io/jq/
--
-- Three-way comparison:
--
-- Nix:       pkgs.jq (stdenv.mkDerivation, fetchurl, autoreconfHook + bison)
-- Snapcraft: autotools plugin with source tarball
-- Shoot:     declarative Lua with composable templates
--
-- Per ADR-0003: returns a table of named outputs.
-- Single-snap configs return { default = { ... } }.

local lib = require("lib")

return {
    default = snap(merge({
        name = "jq",
        version = "1.8.1",
        summary = "Lightweight and flexible command-line JSON processor",
        description = [[
            jq is like sed for JSON data — you can use it to slice,
            filter, map and transform structured data with the same
            ease that sed, awk, grep and friends let you play with text.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        source = "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz",
        architectures = { "amd64", "arm64" },
        type = "source",
        requires = { "glibc" },
        stage = "./stage/",
        apps = {
            -- Compose from the shared CLI template, override with jq-specific values
            jq = lib.cli_app({ command = "bin/jq" }),
        },
    }, {
        -- Extra overrides can be stacked here (e.g. plugs specific to jq)
        apps = {
            jq = { plugs = { "home" } },  -- jq only needs file read access, not network
        },
    }))
}
