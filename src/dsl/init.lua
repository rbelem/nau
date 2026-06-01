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

    local valid_types = { "source", "meta", "store" }

    -- Optional string fields
    local string_fields = {
        "summary", "description", "license", "grade", "confinement",
        "stage", "build", "type", "target", "toolchain",
    }
    -- Validate type field against known values
    if opts.type ~= nil then
        local found = false
        for _, t in ipairs(valid_types) do
            if opts.type == t then found = true; break end
        end
        if not found then
            error("snap(): 'type' must be one of: source, meta, store", 2)
        end
    end
    for _, field in ipairs(string_fields) do
        check_string(opts[field], "snap", field)
    end

    -- source: string (legacy) or table { url, sha256? }
    if opts.source ~= nil then
        if type(opts.source) == "table" then
            if type(opts.source.url) ~= "string" then
                error("snap(): source.url must be a string, got " .. type(opts.source.url), 2)
            end
            if opts.source.sha256 ~= nil and type(opts.source.sha256) ~= "string" then
                error("snap(): source.sha256 must be a string, got " .. type(opts.source.sha256), 2)
            end
        elseif type(opts.source) ~= "string" then
            error("snap(): source must be a string or table, got " .. type(opts.source), 2)
        end
    end

    -- Optional table fields
    check_string_array(opts.architectures, "snap", "architectures")
    check_string_array(opts.aliases, "snap", "aliases")
    check_string_array(opts.requires, "snap", "requires")
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

--- Pin a snap from the Snap Store by name, optionally fixing revision
-- and content hash for reproducibility.
-- @param name  The snap name (e.g. "core22", "pc-kernel")
-- @param opts  (optional) table with `revision` (number) and/or `sha3_384` (string)
-- @return a pin table consumable by image()
-- @usage pin("core22", { revision = 1847, sha3_384 = "abc..." })
--- Declare a system image composed from multiple snaps.
-- @param opts table with fields:
--   name, version, base (required)
--   kernel (pin table, optionally merged with params/modules),
--   gadget, snaps (optional arrays of pins)
--   bootloader (table with type, timeout),
--   disk (table with label, partitions, swap),
--   sysctl (array of "key=value" strings)
-- @return the validated opts table
-- @usage image {
--     name = "my-system",
--     version = "1.0.0",
--     base = pin("core22"),
--     kernel = merge(pin("pc-kernel"), { params = { "quiet" } }),
--     gadget = pin("pc-gadget"),
--     snaps = { pin("lxd") },
--     bootloader = { type = "systemd-boot", timeout = 3 },
--     disk = {
--         label = "gpt",
--         partitions = {
--             { name = "boot", size = "512M", fs = "vfat", mount = "/boot" },
--             { name = "root", size = "0", fs = "btrfs", mount = "/" },
--         },
--         swap = { size = "8G" },
--     },
-- }
function image(opts)
    if type(opts) ~= "table" then
        error("image(): expected a table, got " .. type(opts), 2)
    end

    -- Required fields
    local required = { "name", "version", "base" }
    for _, f in ipairs(required) do
        if opts[f] == nil then
            error(string.format("image(): missing required field '%s'", f), 2)
        end
    end

    -- Type checks
    if type(opts.name) ~= "string" then
        error("image(): 'name' must be a string, got " .. type(opts.name), 2)
    end
    if type(opts.version) ~= "string" then
        error("image(): 'version' must be a string, got " .. type(opts.version), 2)
    end

    -- Optional fields: kernel, gadget, snaps
    if opts.kernel ~= nil and type(opts.kernel) ~= "table" then
        error("image(): 'kernel' must be a pin table, got " .. type(opts.kernel), 2)
    end
    if opts.gadget ~= nil and type(opts.gadget) ~= "table" then
        error("image(): 'gadget' must be a pin table, got " .. type(opts.gadget), 2)
    end
    if opts.snaps ~= nil then
        if type(opts.snaps) ~= "table" then
            error("image(): 'snaps' must be an array, got " .. type(opts.snaps), 2)
        end
        for i, s in ipairs(opts.snaps) do
            if type(s) ~= "table" then
                error(string.format("image(): snaps[%d] must be a pin, got %s", i, type(s)), 2)
            end
        end
    end

    -- Optional kernel config fields (merged with kernel pin table)
    if opts.kernel ~= nil then
        if opts.kernel.params ~= nil then
            check_string_array(opts.kernel.params, "image", "kernel.params")
        end
        if opts.kernel.modules ~= nil then
            check_string_array(opts.kernel.modules, "image", "kernel.modules")
        end
        if opts.kernel.modprobe_config ~= nil and type(opts.kernel.modprobe_config) ~= "string" then
            error("image(): 'kernel.modprobe_config' must be a string, got " .. type(opts.kernel.modprobe_config), 2)
        end
    end

    -- Optional bootloader config
    if opts.bootloader ~= nil then
        if type(opts.bootloader) ~= "table" then
            error("image(): 'bootloader' must be a table, got " .. type(opts.bootloader), 2)
        end
        if opts.bootloader.type ~= nil and type(opts.bootloader.type) ~= "string" then
            error("image(): 'bootloader.type' must be a string, got " .. type(opts.bootloader.type), 2)
        end
        if opts.bootloader.timeout ~= nil and type(opts.bootloader.timeout) ~= "number" then
            error("image(): 'bootloader.timeout' must be a number, got " .. type(opts.bootloader.timeout), 2)
        end
    end

    -- Optional disk layout
    if opts.disk ~= nil then
        if type(opts.disk) ~= "table" then
            error("image(): 'disk' must be a table, got " .. type(opts.disk), 2)
        end
        if opts.disk.label ~= nil and type(opts.disk.label) ~= "string" then
            error("image(): 'disk.label' must be a string, got " .. type(opts.disk.label), 2)
        end
        if opts.disk.partitions ~= nil then
            if type(opts.disk.partitions) ~= "table" then
                error("image(): 'disk.partitions' must be a table, got " .. type(opts.disk.partitions), 2)
            end
            for i, p in ipairs(opts.disk.partitions) do
                if type(p) ~= "table" then
                    error(string.format("image(): disk.partitions[%d] must be a table, got %s", i, type(p)), 2)
                end
                check_string(p.name, "image", string.format("disk.partitions[%d].name", i))
                check_string(p.size, "image", string.format("disk.partitions[%d].size", i))
                check_string(p.fs, "image", string.format("disk.partitions[%d].fs", i))
                check_string(p.mount, "image", string.format("disk.partitions[%d].mount", i))
                if p.options ~= nil then
                    check_string_array(p.options, "image", string.format("disk.partitions[%d].options", i))
                end
            end
        end
        if opts.disk.swap ~= nil then
            if type(opts.disk.swap) ~= "table" then
                error("image(): 'disk.swap' must be a table, got " .. type(opts.disk.swap), 2)
            end
            if opts.disk.swap.size ~= nil and type(opts.disk.swap.size) ~= "string" then
                error("image(): 'disk.swap.size' must be a string, got " .. type(opts.disk.swap.size), 2)
            end
        end
    end

    -- Optional sysctl entries (array of "key=value" strings)
    if opts.sysctl ~= nil then
        check_string_array(opts.sysctl, "image", "sysctl")
    end

    return opts
end

--- Look up a snap in the package index and return a pin table.
-- The index file (package-index.json) contains pre-resolved snap pins
-- and source definitions for common snaps.
-- @param name  The snap name in the index
-- @return a pin table consumable by image() or snap()
-- @usage index("core22")
-- @usage index("hello") -- source-based snap
function index(name)
    if type(name) ~= "string" then
        error("index(): expected a string name, got " .. type(name), 2)
    end
    -- Return a proxy table; Rust handles the actual lookup.
    -- This function is replaced by the Rust implementation at init time.
    return { name = name, _index = true }
end

function pin(name, opts)
    if type(name) ~= "string" then
        error("pin(): expected a string name, got " .. type(name), 2)
    end

    local result = { name = name }

    if opts ~= nil then
        if type(opts) ~= "table" then
            error("pin(): opts must be a table, got " .. type(opts), 2)
        end
        if opts.revision ~= nil then
            if type(opts.revision) ~= "number" then
                error("pin(): revision must be a number, got " .. type(opts.revision), 2)
            end
            result.revision = opts.revision
        end
        if opts.sha3_384 ~= nil then
            if type(opts.sha3_384) ~= "string" then
                error("pin(): sha3_384 must be a string, got " .. type(opts.sha3_384), 2)
            end
            result.sha3_384 = opts.sha3_384
        end
        -- Pass through all extra fields (e.g. params, modules for kernel pins)
        for k, v in pairs(opts) do
            if k ~= "revision" and k ~= "sha3_384" then
                result[k] = v
            end
        end
    end

    return result
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
