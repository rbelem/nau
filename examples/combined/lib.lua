-- Common app templates for reusable snap compositions.
-- Each function returns an app config table suitable for merge().

local M = {}

--- A basic CLI app template.
-- @param overrides: optional fields to override (command, plugs, etc.)
function M.cli(overrides)
    return merge({
        command = "bin/app",
        plugs = {},
    }, overrides or {})
end

--- A daemon/service app template.
-- @param overrides: optional fields to override
function M.daemon(overrides)
    return merge({
        command = "bin/service",
        daemon = "simple",
        restart_condition = "on-abnormal",
        plugs = { "network", "network-bind" },
    }, overrides or {})
end

--- A desktop app template.
-- @param overrides: optional fields to override (command, desktop, plugs)
function M.desktop(overrides)
    return merge({
        command = "bin/desktop",
        plugs = { "desktop", "x11", "wayland", "opengl" },
        environment = {
            DISPLAY = ":0",
        },
    }, overrides or {})
end

return M
