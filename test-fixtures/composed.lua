-- Compose a snap config using require + merge.
-- Per Phase 7: require returns a table, merge deep-merges it.

local base = require("common")

return {
    default = snap(merge(base, {
        name = "my-composed-app",
        version = "1.0.0",
        description = "Built from a shared template",
    })),
}
