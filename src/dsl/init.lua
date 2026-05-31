-- shoot DSL — injected globals for snap declarations
--
-- Per ADR-0002: Lua DSL is the schema source of truth.
-- These functions validate arguments at eval time.
-- Rust receives pre-validated tables.
--
-- Per ADR-0004: Functions return validated tables.
-- User assembles output table explicitly and returns it.

--- Validate that a value is a string.
local function check_string(val, label, field)
    if val ~= nil and type(val) ~= "string" then
        error(string.format(
            "snap(): field '%s' must be a string, got %s", field, type(val)
        ), 2)
    end
end

--- Validate that a value is a table.
local function check_table(val, label, field)
    if val ~= nil and type(val) ~= "table" then
        error(string.format(
            "snap(): field '%s' must be a table, got %s", field, type(val)
        ), 2)
    end
end

--- Validate that a value is a table of strings (array).
local function check_string_array(val, label, field)
    check_table(val, label, field)
    if val ~= nil then
        for i, v in ipairs(val) do
            if type(v) ~= "string" then
                error(string.format(
                    "snap(): %s[%d] must be a string, got %s", field, i, type(v)
                ), 2)
            end
        end
    end
end

--- Declare a snap output.
-- @param opts table with snap metadata fields
-- @return the validated opts table
-- @usage snap { name = "my-snap", version = "1.0", apps = { ... } }
function snap(opts)
    if type(opts) ~= "table" then
        error("snap(): expected a table, got " .. type(opts), 2)
    end

    -- Required fields
    local required_fields = { "name", "version" }
    for _, field in ipairs(required_fields) do
        if opts[field] == nil then
            error(string.format("snap(): missing required field '%s'", field), 2)
        end
        if type(opts[field]) ~= "string" then
            error(string.format(
                "snap(): field '%s' must be a string, got %s", field, type(opts[field])
            ), 2)
        end
    end

    -- Optional string fields
    local string_fields = {
        "summary", "description", "license", "grade", "confinement",
        "source", "stage", "build",
    }
    for _, field in ipairs(string_fields) do
        check_string(opts[field], "snap", field)
    end

    -- Optional table fields
    check_string_array(opts.architectures, "snap", "architectures")
    check_table(opts.plugs, "snap", "plugs")
    check_table(opts.slots, "snap", "slots")

    -- apps: table mapping string -> app definition
    check_table(opts.apps, "snap", "apps")
    if opts.apps ~= nil then
        for name, app_def in pairs(opts.apps) do
            if type(app_def) ~= "table" then
                error(string.format(
                    "snap(): apps['%s'] must be an app table, got %s",
                    name, type(app_def)
                ), 2)
            end
        end
    end

    -- Set defaults
    if opts.grade == nil then opts.grade = "stable" end
    if opts.confinement == nil then opts.confinement = "strict" end

    return opts
end

--- Declare an app within a snap.
-- @param opts table with app fields
-- @return the validated opts table
-- @usage app { command = "bin/hello" }
function app(opts)
    if type(opts) ~= "table" then
        error("app(): expected a table, got " .. type(opts), 2)
    end

    if opts.command == nil then
        error("app(): missing required field 'command'", 2)
    end
    if type(opts.command) ~= "string" then
        error(string.format(
            "app(): field 'command' must be a string, got %s", type(opts.command)
        ), 2)
    end

    -- Optional type checks
    if opts.daemon ~= nil and type(opts.daemon) ~= "string" then
        error(string.format(
            "app(): field 'daemon' must be a string, got %s", type(opts.daemon)
        ), 2)
    end
    check_string_array(opts.plugs, "app", "plugs")
    check_string_array(opts.slots, "app", "slots")
    check_table(opts.environment, "app", "environment")

    return opts
end

--- Deep-merge two tables. Returns a new table — neither input is mutated.
-- For each key in `overrides`:
--   - If both values are tables, recurse.
--   - Otherwise the override value wins.
-- Arrays are replaced, not merged element-by-element.
-- @param base  The base table (may be nil)
-- @param overrides  The overriding table (may be nil)
-- @return a new merged table
-- @usage local cfg = merge(require("common"), { name = "my-snap" })
--- Check if a table is used as an array (keys are 1..n consecutive integers).
local function _is_array(t)
    local count = #t
    if count == 0 then return false end
    for k in pairs(t) do
        if type(k) ~= "number" or k < 1 or k > count or math.floor(k) ~= k then
            return false
        end
    end
    return true
end

function merge(base, overrides)
    if base == nil then return overrides end
    if overrides == nil then return base end

    local result = {}
    -- Copy base keys
    for k, v in pairs(base) do
        result[k] = v
    end
    -- Apply overrides
    for k, v in pairs(overrides) do
        if type(result[k]) == "table" and type(v) == "table" and not _is_array(v) then
            -- Both are dict-like tables: deep merge
            result[k] = merge(result[k], v)
        else
            -- Arrays and scalars: replace outright
            result[k] = v
        end
    end
    return result
end
