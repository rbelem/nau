-- Daemon/service app template for shuttle packages.
-- Returns an app config table suitable for merge().
--
-- Usage:
--   local daemon = require("pkgs.lib.daemon")
--   apps = { myservice = daemon.app { command = "bin/myservice" } }

local M = {}

--- Build a daemon app definition.
-- @param overrides: optional fields (command, plugs, daemon, etc.)
-- @return app config table
function M.app(overrides)
    return merge({
        command = "bin/service",
        daemon = "simple",
        plugs = { "network", "network-bind" },
    }, overrides or {})
end

return M
