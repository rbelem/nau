-- CLI app template for shoot packages.
-- Returns an app config table suitable for merge().
--
-- Usage:
--   local cli = require("pkgs.lib.cli")
--   apps = { mytool = cli.app { command = "bin/mytool" } }

local M = {}

--- Build a CLI app definition.
-- @param overrides: optional fields (command, plugs, daemon, etc.)
-- @return app config table
function M.app(overrides)
    return merge({
        command = "bin/tool",
        plugs = { "home", "network" },
    }, overrides or {})
end

return M
