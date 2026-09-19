-- Daemon/service templates for shuttle packages.
-- app() returns an app config table, service() a service definition —
-- both suitable for merge().
--
-- Usage:
--   local daemon = require("pkgs.lib.daemon")
--   apps = { myapp = daemon.app { command = "bin/myapp" } }
--   services = { mysvc = daemon.service { command = "bin/mysvc" } }

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

--- Build a service definition (ADR-0032 Decision 2): NixOS-style
-- options with defaults, emitted through a service backend. `daemon`
-- is simple | notify | forking (oneshot is out of scope for v1);
-- `options.enabled` defaults to false — declaring never starts
-- anything (NixOS `enable` semantics).
-- @param overrides: optional fields (command, daemon, args, options,
--   after, environment, backend_options)
-- @return service config table
function M.service(overrides)
    return merge({
        command = "bin/service",
        daemon = "simple",
        args = {},
        options = { enabled = false },
        after = {},
        environment = {},
        backend_options = {},
    }, overrides or {})
end

return M
