-- base.lua: Shared template for composable snaps
--
-- This module defines a base snap configuration that other configs
-- can import with `require()` and override with `merge()`.
--
-- The pattern is Nix-inspired: define reusable templates, then
-- specialize them per-snap with targeted overrides.

local base = {
    name = "unnamed",
    version = "0.0.0",
    summary = "A snap built with shuttle",
    description = "Override this with your own description.",
    grade = "stable",
    confinement = "strict",
    architectures = { "amd64" },
    type = "source",
    requires = { "glibc" },
}

-- Common app template for services
function service_template(name, command)
    return {
        [name] = {
            command = command,
            daemon = "simple",
            plugs = { "network", "network-bind" },
        },
    }
end

-- Common app template for CLI tools
function cli_template(name, command)
    return {
        [name] = {
            command = command,
            plugs = {},
        },
    }
end

return base
