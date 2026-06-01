-- Desktop app template for shoot packages.
-- Returns an app config table suitable for merge().
--
-- Usage:
--   local desktop = require("pkgs.lib.desktop")
--   apps = { myapp = desktop.app { command = "bin/myapp", desktop = "myapp.desktop" } }

local M = {}

--- Build a desktop app definition.
-- @param overrides: optional fields (command, desktop, plugs, environment)
-- @return app config table
function M.app(overrides)
    return merge({
        command = "bin/desktop",
        plugs = { "desktop", "x11", "wayland", "opengl" },
        environment = {
            DISPLAY = ":0",
        },
    }, overrides or {})
end

return M
