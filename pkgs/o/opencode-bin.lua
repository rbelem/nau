-- opencode-bin: the open source coding agent, v2 line
-- (anomalyco/opencode) — the `opencode` CLI, packaged from the
-- upstream prebuilt binary. Resolves latest by default; a pod
-- constraint (`opencode@2.0.21`) pins an exact release.
--
-- This is the V2 product line (docs at opencode.ai/v2/docs), the one
-- the V2-schema config at ~/.config/opencode targets. It is NOT
-- published as GitHub release objects: GitHub releases serve the 1.x
-- line only (the reason an earlier revision of this package resolved
-- to 1.18.31 and rejected V2 configs). V2 binaries live on the CDN at
-- opencode.ai/files/bin/<version>/, and the v2 npm package is the
-- scoped @opencode/cli (the unscoped `opencode-ai` is the retired 1.x
-- line — its registry doc does not carry 2.0.0+).
--
-- Version resolution (ADR-0052 Decision 3): unconstrained, the DSL's
-- fetch() global (eval-time HTTP GET) reads upstream's own release
-- channel — the same endpoint the official install script uses — and
-- the definition interpolates the version into the CDN asset URL.
-- Every build re-resolves; no hand bumps. A pod constraint selects
-- instead: the `constraint` global (ADR-0047 Decision 4) must name a
-- release in the registry listing — validated WITHOUT a channel
-- fetch, so the lockfile pin {version, constraint} reproduces it —
-- and is adopted verbatim; an unknown one is a loud refusal, never a
-- silent pin.
--
-- versions() (ADR-0052 Decision 1): the packager-implemented listing
-- behind `nau chart versions`. One fetch of the npm registry doc for
-- @opencode/cli (~1.8 MB, under the 8 MiB fetch() body cap — the
-- unscoped opencode-ai doc is ~25 MB and would NOT fit, and the
-- abbreviated install-v1 form needs an Accept header fetch() cannot
-- send). Keys shaped like plain X.Y.Z triples are the stable v2
-- releases; the doc also carries 0.0.0-dev/-beta/-reserved entries
-- that drop out by construction. Sorted newest first by a numeric-
-- aware pure-Lua comparator. Listing-only: it never feeds build
-- resolution.
--
-- The source stays deliberately NOT sha256-pinned (an unpinned
-- source is nau's supported mode for floating content; the
-- observed hash is recorded in the lockfile and printed as a pin
-- hint). `nau build --offline` and `nau eval --offline`
-- refuse fetch() by name; `nau chart versions` and a constrained
-- eval of this file need network.
--
-- Asset choice: opencode-linux-x64-baseline.tar.gz — the glibc build
-- (the -musl assets are dynamically linked against ld-musl and cannot
-- run on glibc hosts), baseline variant (no AVX2 requirement — the
-- oh-my-pi precedent for bun-compiled binaries). Never strip/patchelf
-- Bun-compiled binaries: they embed their JS bytecode and corrupt
-- under ELF rewriting (oh-my-pi precedent).
--
-- requires = { glibc }: the bun-compiled glibc build's DT_NEEDED is
-- the glibc family only — the JS runtime is self-contained; LLM
-- credentials come from the environment at run time.

local channel_url = "https://opencode.ai/update/api/latest/cli/npm"
local registry_url = "https://registry.npmjs.org/@opencode%2fcli"

-- Newest-first semver order (ADR-0052 Decision 1): numeric-aware on
-- dot-separated segments (2.0.10 > 2.0.9), a numeric segment outranks
-- a non-numeric one at the same position, missing segments count as
-- older. Total and strict: equal versions are not "newer".
local function semver_newer(a, b)
    local as, bs = {}, {}
    for seg in string.gmatch(a, "[^.]+") do as[#as + 1] = seg end
    for seg in string.gmatch(b, "[^.]+") do bs[#bs + 1] = seg end
    for i = 1, math.max(#as, #bs) do
        local x, y = as[i], bs[i]
        if x == nil then return false end
        if y == nil then return true end
        local xn, yn = tonumber(x), tonumber(y)
        if xn and yn then
            if xn ~= yn then return xn > yn end
        elseif xn then
            return true
        elseif yn then
            return false
        elseif x ~= y then
            return x > y
        end
    end
    return false
end

-- The upstream release listing: one registry fetch, keeping only the
-- keys shaped like plain X.Y.Z triples (the stable v2 line), deduped
-- (the versions and time maps repeat keys), sorted newest first.
local function upstream_versions()
    local body = fetch(registry_url)
    local seen, list = {}, {}
    for v in string.gmatch(body, '"(%d+%.%d+%.%d+)":') do
        if not seen[v] then
            seen[v] = true
            list[#list + 1] = v
        end
    end
    table.sort(list, semver_newer)
    return list
end

-- Resolution (ADR-0052 Decision 3): nil constraint keeps the channel
-- default; a set constraint is the selector — validated against the
-- listing (a registry fetch, NOT the channel) and adopted verbatim.
local function resolve_version()
    if constraint == nil then
        local channel_body = fetch(channel_url)
        local latest = string.match(channel_body, '"version":"([%w%.]+)"')
        assert(latest and #latest > 0, "opencode-bin: could not resolve the latest v2 release from " .. channel_url)
        return latest
    end
    local pinned = tostring(constraint)
    for _, v in ipairs(upstream_versions()) do
        if v == pinned then
            return pinned
        end
    end
    error(string.format(
        "opencode-bin: constraint '@%s' names no upstream release — \
         refusing to pin a different version; run \
         `nau chart versions pkgs/o/opencode-bin.lua` for the listing",
        pinned), 2)
end

local version = resolve_version()

return {
    default = snap {
        name = "opencode-bin",
        version = version,
        summary = "The open source coding agent, v2 line (opencode)",
        description = [[
            opencode is an AI coding agent built for the terminal:
            multi-model agentic coding with LSP-aware context. This is
            the v2 line: the upstream prebuilt bun-compiled baseline
            release binary, resolved at build time via upstream's own
            release channel (latest by default; a pod constraint pins
            an exact release). LLM credentials
            come from the environment at run time.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        versions = function()
            return upstream_versions()
        end,

        source = {
            url = "https://opencode.ai/files/bin/" .. version .. "/opencode-linux-x64-baseline.tar.gz",
        },

        build = table.concat({
            "install -Dm755 opencode $STAGE/usr/bin/opencode",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            opencode = app {
                command = "usr/bin/opencode",
            },
        },
    },
}
