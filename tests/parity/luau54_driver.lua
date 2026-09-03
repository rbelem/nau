-- Lua 5.4 reference side of the ADR-0010 dual-eval parity gate (tests/eval_parity.rs).
--
-- Mirrors the `shuttle __eval-worker` child environment (src/isolate.rs) on a
-- plain Lua 5.4 interpreter so every corpus definition can be evaluated
-- through BOTH backends and compared at the post-eval data level:
--
--   1. loads the exact prelude the parent ships (dsl::prelude(), incl.
--      shuttle_plugins);
--   2. replaces the prelude's index() stub with a faithful port of the Rust
--      callback from build_worker_lua (find-by-name-or-alias over the shipped
--      index data + arch pin selection);
--   3. routes print() to stderr (child stdout is the protocol channel);
--   4. installs an IPC-equivalent require(): same rejection rules and
--      name→path candidates as SourceResolver::resolve over the roots the
--      test ships (entry dir + pkgs/), with module cache + cycle detection;
--   5. evaluates the entry and serializes the outcome exactly like the
--      worker's lua_to_json / extract_inputs_json (array detection, depth
--      cap, cycle + non-finite + unsupported-type errors, inputs→{url} map).
--
-- Prints ONE line to stdout:
--   RESULT:{"ok":true,"outputs":{...},"global_inputs":{...}}  on success
--   RESULT:{"ok":false}                                       on eval failure
-- Diagnostics text is intentionally not emitted: error formatting differs
-- between VMs and is not part of the parity contract.

-- ── JSON encoding (mirrors isolate::lua_to_json) ──

local MAX_JSON_DEPTH = 128

local function json_escape_string(s)
  local out = s:gsub('[%z\1-\31\\"]', function(c)
    if c == '"' then return '\\"' end
    if c == '\\' then return '\\\\' end
    if c == '\b' then return '\\b' end
    if c == '\f' then return '\\f' end
    if c == '\n' then return '\\n' end
    if c == '\r' then return '\\r' end
    if c == '\t' then return '\\t' end
    return string.format('\\u%04x', string.byte(c))
  end)
  return '"' .. out .. '"'
end

local function json_number(n)
  if n ~= n or n == math.huge or n == -math.huge then
    return nil, "non-finite number"
  end
  if math.type(n) == "integer" then
    return string.format("%d", n)
  end
  local s = string.format("%.14g", n)
  if tonumber(s) ~= n then
    s = string.format("%.17g", n)
  end
  return s
end

-- forward declaration for the recursive walk
local json_value

local function json_table(t, depth, seen)
  if depth > MAX_JSON_DEPTH then
    return nil, "table nesting too deep"
  end
  if seen[t] then
    return nil, "circular table reference"
  end
  seen[t] = true
  local entries = {}
  local k, v = next(t)
  while k ~= nil do
    -- Worker (lua_to_json::table_entries) accepts string and integer keys
    -- only; a float key is `unsupported table key type number`.
    if type(k) ~= "string" and math.type(k) ~= "integer" then
      seen[t] = nil
      return nil, "unsupported table key type " .. type(k)
    end
    entries[#entries + 1] = { k, v }
    k, v = next(t, k)
  end
  local is_array = #entries > 0
  if is_array then
    for i, e in ipairs(entries) do
      if math.type(e[1]) ~= "integer" or e[1] ~= i then
        is_array = false
        break
      end
    end
  end
  local buf = {}
  if is_array then
    for _, e in ipairs(entries) do
      local s, err = json_value(e[2], depth + 1, seen)
      if not s then
        seen[t] = nil
        return nil, err
      end
      buf[#buf + 1] = s
    end
    seen[t] = nil
    return "[" .. table.concat(buf, ",") .. "]"
  end
  for _, e in ipairs(entries) do
    local key
    if type(e[1]) == "string" then
      key = json_escape_string(e[1])
    else
      key = string.format("%d", e[1]) -- integer keys stringify like the worker's i.to_string()
    end
    local s, err = json_value(e[2], depth + 1, seen)
    if not s then
      seen[t] = nil
      return nil, err
    end
    buf[#buf + 1] = key .. ":" .. s
  end
  seen[t] = nil
  return "{" .. table.concat(buf, ",") .. "}"
end

json_value = function(v, depth, seen)
  if depth > MAX_JSON_DEPTH then
    return nil, "table nesting too deep"
  end
  local tv = type(v)
  if v == nil then
    return "null"
  elseif tv == "boolean" then
    return tostring(v)
  elseif tv == "number" then
    return json_number(v)
  elseif tv == "string" then
    return json_escape_string(v)
  elseif tv == "table" then
    return json_table(v, depth, seen)
  end
  return nil, "unsupported value type " .. tv
end

local function json_encode(v)
  local s, err = json_value(v, 0, {})
  if not s then
    return nil, err
  end
  return s
end

-- ── Worker environment ports ──

-- Port of build_worker_lua's index() callback: find-by-name-or-alias over
-- the shipped index data, then entry_to_lua_table ({name, revision?,
-- sha3_384?}) with the request's arch.
local function make_index(index_data, arch)
  return function(name)
    if type(name) ~= "string" then
      error("index(): expected a string name, got " .. type(name), 2)
    end
    local snaps = (index_data and index_data.snaps) or {}
    local found
    for _, e in ipairs(snaps) do
      if e.name == name then
        found = e
        break
      end
    end
    if not found then
      for _, e in ipairs(snaps) do
        for _, a in ipairs(e.aliases or {}) do
          if a == name then
            found = e
            break
          end
        end
        if found then
          break
        end
      end
    end
    if not found then
      error("snap '" .. name .. "' not found in package index")
    end
    local t = { name = found.name }
    local pin = found.pins and found.pins[arch]
    if pin then
      t.revision = pin.revision
      t.sha3_384 = pin["sha3-384"]
    end
    return t
  end
end

-- Port of install_require + SourceResolver::resolve: same rejection rules,
-- same dot→slash name mapping, same {root}/{rel}.lua and
-- {root}/{rel}/init.lua candidates over the shipped roots, module result
-- cache, cycle detection.
local function make_require(roots)
  local loaded = {}
  local cached = {}
  local loading = {}

  local function resolve(name)
    if name == "" then
      return nil, "rejected empty module name"
    end
    if #name > 4096 then
      return nil, "rejected oversized module name"
    end
    if name:sub(1, 1) == "/" then
      return nil, "rejected absolute path"
    end
    for seg in name:gmatch("[^/]+") do
      if seg == ".." then
        return nil, "rejected traversal path"
      end
    end
    local rel = name:gsub("%.", "/")
    if rel:sub(1, 1) == "/" then
      return nil, "rejected absolute path"
    end
    for _, root in ipairs(roots) do
      local candidates = {
        root .. "/" .. rel .. ".lua",
        root .. "/" .. rel .. "/init.lua",
      }
      for _, cand in ipairs(candidates) do
        local f = io.open(cand, "r")
        if f then
          local content = f:read("*a")
          f:close()
          return content
        end
      end
    end
    return nil, string.format("source %q not found in allowlisted roots", name)
  end

  return function(name)
    if type(name) ~= "string" then
      error("bad argument #1 to 'require' (string expected, got " .. type(name) .. ")", 2)
    end
    if cached[name] then
      return loaded[name]
    end
    if loading[name] then
      error("circular require of '" .. name .. "'")
    end
    loading[name] = true
    local content, err = resolve(name)
    if not content then
      loading[name] = nil
      error("require '" .. name .. "': " .. err)
    end
    local f, load_err = load(content, "=" .. name)
    if not f then
      loading[name] = nil
      error("require '" .. name .. "': " .. load_err)
    end
    local v = f()
    loading[name] = nil
    loaded[name] = v
    cached[name] = true
    return v
  end
end

-- Port of extract_inputs_json: the global `inputs` table becomes
-- {name = {url = ...}}; everything else about the input is discarded, and
-- malformed entries are fatal (matching the worker).
local function extract_inputs_json()
  local value = rawget(_G, "inputs")
  if value == nil then
    return {}
  end
  if type(value) ~= "table" then
    error("'inputs' must be a table, got " .. type(value))
  end
  local out = {}
  local k, v = next(value)
  while k ~= nil do
    if type(k) ~= "string" then
      error("inputs entry: key must be a string")
    end
    if type(v) ~= "table" then
      error("inputs['" .. k .. "'] must be a table, got " .. type(v))
    end
    if type(v.url) ~= "string" then
      error("inputs['" .. k .. "']: missing 'url'")
    end
    out[k] = { url = v.url }
    k, v = next(value, k)
  end
  return out
end

-- ── Main ──

local function run()
  local R = dofile(arg[1])

  -- 1. prelude (dsl::prelude() output shipped verbatim).
  local prelude_f = assert(load(R.prelude, "=init.lua"))
  prelude_f()

  -- 2. print → stderr (child stdout is the protocol channel).
  print = function(...)
    local parts = {}
    for i = 1, select("#", ...) do
      local v = select(i, ...)
      parts[i] = type(v) == "string" and v or type(v)
    end
    io.stderr:write(table.concat(parts, "\t"), "\n")
  end

  -- 3. index() override — the Rust callback analog.
  rawset(_G, "index", make_index(R.index_data, R.arch))

  -- 4. require over allowlisted roots.
  rawset(_G, "require", make_require(R.roots))

  -- 5. inputs extraction happens even before the result-table check in the
  --    worker (run_worker order: eval → inputs → table check → outputs).
  local entry_f = assert(load(R.entry, "@" .. R.entry_label))
  local result = entry_f()
  local global_inputs = extract_inputs_json()
  if type(result) ~= "table" then
    error("must return a table of outputs, got " .. type(result))
  end

  -- Outputs: iterate with string keys; a non-string key aborts iteration
  -- (mlua pairs::<String, _> conversion error semantics); each value that
  -- fails to serialize is skipped (warn-and-continue).
  local outputs = {}
  local k, v = next(result)
  while k ~= nil do
    if type(k) ~= "string" then
      break
    end
    local s, err = json_value(v, 0, {})
    if s then
      outputs[k] = s
    end
    k, v = next(result, k)
  end

  -- Compose the outcome line with pre-encoded per-output JSON fragments.
  local parts = {}
  for key, frag in pairs(outputs) do
    parts[#parts + 1] = json_escape_string(key) .. ":" .. frag
  end
  local inputs_frag = {}
  for name, input in pairs(global_inputs) do
    inputs_frag[#inputs_frag + 1] =
      json_escape_string(name) .. ':{' .. json_escape_string("url") .. ':' .. json_escape_string(input.url) .. '}'
  end
  io.write(
    "RESULT:{\"ok\":true,\"outputs\":{",
    table.concat(parts, ","),
    "},\"global_inputs\":{",
    table.concat(inputs_frag, ","),
    "}}\n"
  )
end

local ok, err = pcall(run)
if not ok then
  io.write("RESULT:{\"ok\":false}\n")
  io.stderr:write("driver: ", tostring(err), "\n")
end
