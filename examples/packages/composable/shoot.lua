-- composable: Merge + require demo
--
-- Demonstrates Lua module composition with `require()` and `merge()`.
-- Imports a shared base config from base.lua and overrides only the
-- fields that differ per output.
--
-- This is the Nix-inspired composability pattern (ADR-0004):
--   1. Define reusable templates in separate Lua modules
--   2. Import with `require()`
--   3. Override with `merge()` — deep merge for tables, replace for scalars
--
-- Usage:
--   shoot build --file examples/packages/composable/shoot.lua
--   → builds both web and tools snaps from the shared base
--
--   shoot build --file examples/packages/composable/shoot.lua --order
--   → shows build order

local base = require("base")

return {
    -- Web service: built from base template with service overrides
    web = snap(merge(base, {
        name = "web-svc",
        version = "1.0.0",
        summary = "Web service built from composable template",
        description = [[
            A web service snap built by merging a base template with
            service-specific overrides. The `merge()` function handles
            deep merging of nested tables and replacement of scalars.
        ]],
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            web = app {
                command = "bin/hello",
                daemon = "simple",
                plugs = { "network", "network-bind" },
            },
        },
    })),

    -- CLI tools: built from base template with CLI overrides
    tools = snap(merge(base, {
        name = "dev-tools",
        version = "0.5.0",
        summary = "Development CLI tools from composable template",
        description = [[
            A CLI tools snap built from the same base template but with
            different overrides. Shows how the same reusable template
            can produce different outputs.
        ]],
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            hello = app { command = "bin/hello" },
        },
    })),
}
