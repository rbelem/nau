-- Shared templates for CLI tools packaged as snaps.
-- Demonstrates Phase 7 composability: require + merge.
--
-- Each function returns a partial snap config table.
-- Compose with: merge(template, overrides)

local M = {}

--- A standard CLI app: user invokes the tool from the terminal.
-- @param overrides: override fields like command, plugs, etc.
function M.cli_app(overrides)
    return merge({
        command = "bin/tool",
        plugs = { "home", "network" },
    }, overrides or {})
end

return M
