-- shuttle DSL — injected globals for snap declarations
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

--- Validate a `confined` grants table (ADR-0016, ticket #11).
-- A table with optional `backend` (string), `filesystem` (array of
-- strings), `network` (boolean), `sockets`/`devices` (arrays of strings),
-- and `backend_options` (table of raw strings). Absent/`nil` = unconfined.
local function check_confinement(val, label)
    if val == nil then return end
    check_table(val, label, "confined")
    if val == nil then return end
    if val.backend ~= nil then
        if type(val.backend) ~= "string" or (val.backend ~= "bwrap" and val.backend ~= "apparmor") then
            error(string.format(
                "%s(): confined.backend must be 'bwrap' or 'apparmor', got %s",
                label, tostring(val.backend)), 3)
        end
    end
    if val.network ~= nil and type(val.network) ~= "boolean" then
        error(string.format(
            "%s(): confined.network must be a boolean, got %s",
            label, type(val.network)), 3)
    end
    check_string_array(val.filesystem, label, "confined.filesystem")
    check_string_array(val.sockets, label, "confined.sockets")
    check_string_array(val.devices, label, "confined.devices")
    if val.backend_options ~= nil then
        check_table(val.backend_options, label, "confined.backend_options")
        for k, v in pairs(val.backend_options) do
            if type(v) ~= "string" then
                error(string.format(
                    "%s(): confined.backend_options['%s'] must be a string, got %s",
                    label, tostring(k), type(v)), 3)
            end
        end
    end
end

--- Validate a plugs/slots map: name → bare interface string (back-compat)
--- or table with required string `interface` plus string-valued attributes.
local function check_plug_map(val, field)
    check_table(val, "snap", field)
    if val == nil then return end
    for name, def in pairs(val) do
        if type(def) == "string" then
            -- bare interface name (back-compat)
        elseif type(def) == "table" then
            if type(def.interface) ~= "string" then
                error(string.format(
                    "snap(): %s['%s'].interface must be a string, got %s",
                    field, name, type(def.interface)), 2)
            end
            for k, v in pairs(def) do
                if k ~= "interface" and type(v) ~= "string" then
                    error(string.format(
                        "snap(): %s['%s'].%s must be a string, got %s",
                        field, name, k, type(v)), 2)
                end
            end
        else
            error(string.format(
                "snap(): %s['%s'] must be a string or table, got %s",
                field, name, type(def)), 2)
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

    -- Required fields. With adopt-info, snapd takes version (and
    -- summary/description) from the adopted part's metadata, so version
    -- is optional; name is always required.
    local required_fields = { "name" }
    if opts.adopt_info == nil then
        table.insert(required_fields, "version")
    end
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

    -- "source"/"meta"/"store" are shuttle build classifications (not
    -- emitted to snap.yaml); "app"/"base"/"gadget"/"kernel"/"snapd" are
    -- the snapd snap types (emitted except "app", the default).
    local valid_types = { "source", "meta", "store",
                          "app", "base", "gadget", "kernel", "snapd" }

    -- Optional string fields
    local string_fields = {
        "summary", "description", "license", "grade", "confinement",
        "stage", "build", "type", "target", "toolchain",
        "icon", "compression", "adopt_info",
    }
    -- Validate type field against known values
    if opts.type ~= nil then
        local found = false
        for _, t in ipairs(valid_types) do
            if opts.type == t then found = true; break end
        end
        if not found then
            error("snap(): 'type' must be one of: source, meta, store, app, base, gadget, kernel, snapd", 2)
        end
    end
    -- compression: only what both snapd-era tooling and mksquashfs accept
    if opts.compression ~= nil then
        local valid_compressions = { "xz", "lzo" }
        local found = false
        for _, c in ipairs(valid_compressions) do
            if opts.compression == c then found = true; break end
        end
        if not found then
            error("snap(): 'compression' must be one of: xz, lzo", 2)
        end
    end
    for _, field in ipairs(string_fields) do
        check_string(opts[field], "snap", field)
    end

    -- confined (ADR-0016, ticket #11): grants vocabulary for a confined
    -- package. A table with backend/filesystem/network/sockets/devices/
    -- backend_options, all validated for type below.
    check_confinement(opts.confined, "snap")

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
    check_string_array(opts.build_deps, "snap", "build_deps")
    check_string_array(opts.leaks_ok, "snap", "leaks_ok")

    -- plugs/slots: name → interface string (back-compat) or attribute
    -- table with required string `interface` (typed form)
    check_plug_map(opts.plugs, "plugs")
    check_plug_map(opts.slots, "slots")

    -- environment: global env vars, string → string map
    if opts.environment ~= nil then
        check_table(opts.environment, "snap", "environment")
        for k, v in pairs(opts.environment) do
            if type(v) ~= "string" then
                error(string.format(
                    "snap(): environment['%s'] must be a string, got %s",
                    k, type(v)), 2)
            end
        end
    end

    -- layout: target path → exactly one of bind/bind_file/symlink/tmpfs
    if opts.layout ~= nil then
        check_table(opts.layout, "snap", "layout")
        local layout_kinds = { "bind", "bind_file", "symlink", "tmpfs" }
        for target, entry in pairs(opts.layout) do
            if type(entry) ~= "table" then
                error(string.format(
                    "snap(): layout['%s'] must be a table, got %s",
                    target, type(entry)), 2)
            end
            local count = 0
            for _, kind in ipairs(layout_kinds) do
                if entry[kind] ~= nil then
                    count = count + 1
                    if kind == "tmpfs" then
                        local v = entry.tmpfs
                        if type(v) == "boolean" and v ~= true then
                            error(string.format(
                                "snap(): layout['%s'].tmpfs must be true or a table with optional string 'size', got %s",
                                target, tostring(v)), 2)
                        elseif type(v) == "table" then
                            if v.size ~= nil and type(v.size) ~= "string" then
                                error(string.format(
                                    "snap(): layout['%s'].tmpfs.size must be a string, got %s",
                                    target, type(v.size)), 2)
                            end
                        elseif type(v) ~= "table" and type(v) ~= "boolean" then
                            error(string.format(
                                "snap(): layout['%s'].tmpfs must be true or a table with optional string 'size', got %s",
                                target, type(v)), 2)
                        end
                    elseif type(entry[kind]) ~= "string" then
                        error(string.format(
                            "snap(): layout['%s'].%s must be a string, got %s",
                            target, kind, type(entry[kind])), 2)
                    end
                end
            end
            if count ~= 1 then
                error(string.format(
                    "snap(): layout['%s'] must have exactly one of bind, bind_file, symlink, tmpfs (got %d)",
                    target, count), 2)
            end
        end
    end

    -- hooks: hook name → script path (copied to meta/hooks/<name> at build)
    if opts.hooks ~= nil then
        check_table(opts.hooks, "snap", "hooks")
        for name, script in pairs(opts.hooks) do
            if type(script) ~= "string" then
                error(string.format(
                    "snap(): hooks['%s'] must be a string script path, got %s",
                    name, type(script)), 2)
            end
        end
    end

    -- parts: multi-part builds. Mutually exclusive with `build` (a snap has
    -- either one command or named parts, never both). Each part needs a
    -- non-empty string `build` command and may list `after` dependencies.
    -- Lua tables don't preserve order, so execution order is derived from
    -- `after` at build time: a part runs once all its `after` parts are
    -- done; parts with no `after` are runnable immediately.
    --
    -- plugin (ADR-0014): a part may select a built-in builder plugin
    -- instead of a raw command. `build` and `plugin` are mutually exclusive
    -- per part (a plugin IS the build). Plugin options go in `options`;
    -- per ADR-0014 Decision 3, Lua only checks that the plugin is a known
    -- name (registry injected as `shuttle_plugins` by the Rust prelude) and
    -- that options are a table — deep option validation lives in Rust at
    -- the plugin boundary and produces named errors.
    if opts.parts ~= nil then
        if opts.build ~= nil then
            error("snap(): 'build' and 'parts' are mutually exclusive — move the command into parts['<name>'].build", 2)
        end
        if type(opts.parts) ~= "table" then
            error("snap(): 'parts' must be a table, got " .. type(opts.parts), 2)
        end
        local names = {}
        local count = 0
        for name, part in pairs(opts.parts) do
            count = count + 1
            names[name] = true
            if type(part) ~= "table" then
                error(string.format(
                    "snap(): parts['%s'] must be a table, got %s", name, type(part)), 2)
            end
            if part.plugin ~= nil then
                if part.build ~= nil then
                    error(string.format(
                        "snap(): parts['%s'] must have exactly one of 'build' or 'plugin'", name), 2)
                end
                if type(part.plugin) ~= "string" or part.plugin == "" then
                    error(string.format(
                        "snap(): parts['%s'].plugin must be a non-empty string, got %s",
                        name, type(part.plugin)), 2)
                end
                if part.options ~= nil and type(part.options) ~= "table" then
                    error(string.format(
                        "snap(): parts['%s'].options must be a table, got %s",
                        name, type(part.options)), 2)
                end
                local known = shuttle_plugins
                if known ~= nil and known[part.plugin] ~= true then
                    local available = {}
                    for plugin_name in pairs(known) do
                        available[#available + 1] = plugin_name
                    end
                    table.sort(available)
                    error(string.format(
                        "snap(): parts['%s'].plugin must be one of: %s (got '%s')",
                        name, table.concat(available, ", "), part.plugin), 2)
                end
            elseif type(part.build) ~= "string" or part.build == "" then
                error(string.format(
                    "snap(): parts['%s'].build must be a non-empty string, got %s",
                    name, type(part.build)), 2)
            end
            if part.after ~= nil then
                if type(part.after) ~= "table" then
                    error(string.format(
                        "snap(): parts['%s'].after must be an array of part names, got %s",
                        name, type(part.after)), 2)
                end
                for i, dep in ipairs(part.after) do
                    if type(dep) ~= "string" then
                        error(string.format(
                            "snap(): parts['%s'].after[%d] must be a string, got %s",
                            name, i, type(dep)), 2)
                    end
                end
            end
        end
        if count == 0 then
            error("snap(): 'parts' must not be empty", 2)
        end
        -- `after` references must name existing parts
        for name, part in pairs(opts.parts) do
            for _, dep in ipairs(part.after or {}) do
                if not names[dep] then
                    error(string.format(
                        "snap(): parts['%s'].after references unknown part '%s'",
                        name, dep), 2)
                end
            end
        end
        -- The `after` graph must be acyclic; report the cycle path.
        local IN_PROGRESS, DONE = 1, 2
        local state = {}
        local path = {}
        local function visit(n)
            state[n] = IN_PROGRESS
            table.insert(path, n)
            for _, dep in ipairs(opts.parts[n].after or {}) do
                if state[dep] == IN_PROGRESS then
                    local cycle, seen = {}, false
                    for _, step in ipairs(path) do
                        if step == dep then seen = true end
                        if seen then table.insert(cycle, step) end
                    end
                    table.insert(cycle, dep)
                    error("snap(): circular dependency in parts: " .. table.concat(cycle, " -> "), 2)
                end
                if state[dep] == nil then
                    visit(dep)
                end
            end
            table.remove(path)
            state[n] = DONE
        end
        for name in pairs(opts.parts) do
            if state[name] == nil then
                visit(name)
            end
        end
    end

    -- inputs: table of name → { url } (package source, inspired by Nix inputs)
    if opts.inputs ~= nil then
        if type(opts.inputs) ~= "table" then
            error("snap(): 'inputs' must be a table, got " .. type(opts.inputs), 2)
        end
        for name, input_def in pairs(opts.inputs) do
            if type(input_def) ~= "table" then
                error(string.format("snap(): inputs['%s'] must be a table, got %s", name, type(input_def)), 2)
            end
            if type(input_def.url) ~= "string" then
                error(string.format("snap(): inputs['%s'].url must be a string", name), 2)
            end
        end
    end

    -- deps: dependency-closure resolvers (ADR-0017, issue #13).
    -- `deps = { npm = { lock = "package-lock.json" } }` or
    -- `deps = { pip = { lock = "requirements.lock", index = "https://..." } }`.
    -- Coexists with `source` (hybrid) or stands alone with it; the
    -- lockfile resolves from the source tree, so `source` is required.
    if opts.deps ~= nil then
        if type(opts.deps) ~= "table" then
            error("snap(): 'deps' must be a table, got " .. type(opts.deps), 2)
        end
        local resolvers = {}
        for eco, resolver in pairs(opts.deps) do
            if eco ~= "npm" and eco ~= "pip" then
                error(string.format(
                    "snap(): deps: unknown resolver '%s' (supported: npm, pip)", eco), 2)
            end
            if type(resolver) ~= "table" then
                error(string.format("snap(): deps['%s'] must be a table, got %s", eco, type(resolver)), 2)
            end
            if type(resolver.lock) ~= "string" or #resolver.lock == 0 then
                error(string.format(
                    "snap(): deps.%s: field 'lock' is required (lockfile path relative to the source root)", eco), 2)
            end
            if resolver.index ~= nil and type(resolver.index) ~= "string" then
                error(string.format("snap(): deps.%s.index must be a string", eco), 2)
            end
            table.insert(resolvers, eco)
        end
        if #resolvers == 0 then
            error("snap(): deps must name at least one resolver: npm or pip", 2)
        end
        if opts.source == nil then
            error("snap(): 'deps' requires 'source' — the lockfile resolves from the package source tree", 2)
        end
    end

    -- floating: opt-in float mode (ADR-0017, issue #13). Locked (default,
    -- false) never re-fetches a cached closure; floating re-resolves on
    -- every sync, records the new hash, and stays hash-verified.
    if opts.floating ~= nil and type(opts.floating) ~= "boolean" then
        error("snap(): 'floating' must be a boolean, got " .. type(opts.floating), 2)
    end

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
    if opts.interpreter ~= nil and type(opts.interpreter) ~= "string" then
        error(string.format(
            "app(): field 'interpreter' must be a string, got %s", type(opts.interpreter)
        ), 2)
    end
    -- confined (ADR-0016, ticket #11): per-app confinement override.
    check_confinement(opts.confined, "app")

    -- Unknown fields are rejected, not silently dropped: anything this
    -- schema doesn't know would otherwise vanish between the DSL and the
    -- emitted snap.yaml (e.g. a template emitting `restart_condition`).
    -- This list must match the Rust-side conversion in snap.rs exactly.
    local known_fields = {
        command = true,
        daemon = true,
        plugs = true,
        slots = true,
        environment = true,
        desktop = true,
        interpreter = true,
        confined = true,
    }
    local unknown = {}
    for k in pairs(opts) do
        if not known_fields[k] then
            table.insert(unknown, k)
        end
    end
    table.sort(unknown)
    if #unknown > 0 then
        local list = {}
        for _, k in ipairs(unknown) do
            table.insert(list, string.format("'%s'", k))
        end
        error(string.format(
            "app(): unknown field%s %s (valid fields: command, daemon, plugs, slots, environment, desktop, interpreter, confined)",
            #unknown == 1 and "" or "s",
            table.concat(list, ", ")
        ), 2)
    end

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
-- @param opts  (optional) table with `revision` (number), `sha3_384`
--              (string), and — for image() kernel/gadget entries only —
--              `channel` (string, ADR-0019: pins the store channel,
--              skipping base-track derivation and the declared-base check)
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
    -- ADR-0019 escape hatch: an explicit `channel` opt on the kernel or
    -- gadget pin skips base-track derivation and the declared-base check
    -- (the override is recorded in the build output).
    if opts.kernel ~= nil and opts.kernel.channel ~= nil and type(opts.kernel.channel) ~= "string" then
        error("image(): 'kernel.channel' must be a string, got " .. type(opts.kernel.channel), 2)
    end
    if opts.gadget ~= nil and opts.gadget.channel ~= nil and type(opts.gadget.channel) ~= "string" then
        error("image(): 'gadget.channel' must be a string, got " .. type(opts.gadget.channel), 2)
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
        if opts.disk.ab ~= nil and type(opts.disk.ab) ~= "boolean" then
            error("image(): 'disk.ab' must be a boolean, got " .. type(opts.disk.ab), 2)
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

    -- Optional sysupdate payload source (ADR-0011 step d)
    if opts.update_source ~= nil and type(opts.update_source) ~= "string" then
        error("image(): 'update_source' must be a string URL, got " .. type(opts.update_source), 2)
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
