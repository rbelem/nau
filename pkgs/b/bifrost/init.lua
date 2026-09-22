-- bifrost: the AI gateway (maximhq/bifrost, framework/v1.7.2).
-- https://docs.getbifrost.ai
--
-- Three-way comparison:
--
-- Nix:       no nixpkgs package; upstream ships a flake for dev only
-- Snapcraft: no upstream snap
-- Shuttle:   declarative Lua — Go source build via the go module
--            resolver, carrying a `services` declaration (ADR-0032
--            Decision 2)
--
-- Build entry (resolved against the framework/v1.7.2 tree): the server
-- binary is the `bifrost-http` package of the `transports` module —
-- upstream's `make build` native branch runs `cd transports &&
-- CGO_ENABLED=1 GOWORK=off go build -ldflags "-w -s -X main.Version=v…"
-- -trimpath -tags sqlite_static ./bifrost-http`. This port mirrors that
-- command verbatim, with the tag-derived version pinned. CGO rides the
-- pool toolchain build_dep (bare `gcc` on the merged build prefix
-- PATH): go-sqlite3's sqlite_static amalgamation needs a real C
-- compiler — the gap gojq.lua's header recorded (issue #40) is closed
-- by the toolchain package landing.
--
-- KNOWN GAP: the web UI. bifrost-http's main.go has `//go:embed
-- all:ui`, but the embedded ui/ directory is a Node/Next.js build
-- artifact (make build-ui → npm) that neither the source tarball nor
-- an offline sandbox can produce. The build drops a one-line
-- placeholder index.html so the embed compiles; the gateway API is
-- fully functional, the bundled UI serves the placeholder. Completing
-- it needs an npm-closure story for the ui/ workspace (the agentmemory
-- gap shape, upstream-side).
--
-- The deps closure is transports/go.mod + transports/go.sum (the
-- sibling core/framework/plugins modules resolve from the Go proxy at
-- their pinned versions at FETCH time — no go.work in the tarball;
-- setup-workspace generates one for dev only).
--
-- Serve flags verified against transports/bifrost-http/main.go: -port
-- (default 8080, the flag package accepts --port spelling too).
--
-- require note: `lib/daemon` is the analyzer-resolvable spelling of
-- the shared service() constructor (see valkey's header; the ADR-0032
-- sketch's dotted form has no resolvable root under the gate's module
-- mapping).

local svc = require("lib/daemon").service

return {
    default = snap {
        name = "bifrost",
        version = "1.7.2",
        summary = "AI gateway — fast, centralized LLM access with observability",
        description = [[
            Bifrost is a high-performance AI gateway: one OpenAI-style
            endpoint fanning out to multiple providers (OpenAI,
            Anthropic, Bedrock, Vertex, and more) with load balancing,
            fallbacks, semantic caching, governance, and observability.
            Ships the bifrost-http server binary built from the
            framework/v1.7.2 tag and declares a `bifrost` pod service
            (ADR-0032) with a port option, disabled by default. NOTE:
            the embedded web UI is a placeholder in this port — see the
            port header.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/maximhq/bifrost/archive/refs/tags/framework/v1.7.2.tar.gz",
            sha256 = "6a79f8203b471eeb22fda21294f6dafb065696063ab1bddf69410bf6e873e88d",
        },

        deps = {
            go = { mods = "transports/go.mod", sum = "transports/go.sum" },
        },

        -- Offline Go wiring per gojq.lua (issue #40): writable GOMODCACHE
        -- on the sandbox tmpfs, file:// GOPROXY over the mounted,
        -- hash-verified module closure, GOSUMDB off (go.sum pins all).
        -- The UI placeholder satisfies `//go:embed all:ui` (needs a
        -- non-empty dir); printf stays single-quoted, no nesting.
        build = table.concat({
            "mkdir -p $STAGE/usr/bin $SRC/transports/bifrost-http/ui",
            "printf '%s\\n' '<!doctype html><title>bifrost</title><p>bifrost API is running; web UI is not bundled in this port.</p>' > $SRC/transports/bifrost-http/ui/index.html",
            "export GOMODCACHE=/tmp/shuttle-go-cache",
            'export GOPROXY="file://$SHUTTLE_DEPS_DIR/cache/download"',
            "export GOFLAGS=-mod=mod GOSUMDB=off GOPATH=/tmp/shuttle-go-cache",
            'mkdir -p "$GOMODCACHE"',
            'cd $SRC/transports && CGO_ENABLED=1 GOWORK=off go build -ldflags "-w -s -X main.Version=v1.7.2" -trimpath -tags sqlite_static -o $STAGE/usr/bin/bifrost ./bifrost-http',
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "go", "toolchain" },

        apps = {
            bifrost = app {
                command = "usr/bin/bifrost",
                plugs = { "home", "network", "network-bind" },
            },
        },

        services = {
            bifrost = svc {
                command = "usr/bin/bifrost",
                daemon = "simple",
                args = { "--port", "${port}" },
                options = {
                    port = 8080,
                    enabled = false,
                },
                environment = {},
            },
        },
    },
}
