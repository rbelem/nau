-- gojq: Pure Go implementation of jq (JSON query language).
--
-- Go source build via the go module resolver (issue #40, ADR-0017
-- extension): the module closure pinned by go.sum (7 modules) is fetched
-- from GOPROXY at FETCH time (outside the sandbox, which stays
-- net-unshared), every .mod/.zip verified against the go.sum dirhash, and
-- materialized into the Go module cache layout. The sandbox build wires a
-- writable GOMODCACHE on /tmp plus a file:// GOPROXY onto the mounted
-- closure, so `go build ./cmd/gojq` is fully offline.
--
-- CGO_ENABLED=0: the only "requires" is the runtime C library, which Go
-- (pure mode) links statically — no pool C deps, no merged build prefix.
--
-- Note (issue #40 consumer decision): bifrost, the designated stop-recorded
-- driver, is genuinely blocked on pool CGO/pkg-config infrastructure (its
-- CGO sqlite path needs a working sandbox C cross-toolchain + pkg-config,
-- and its UI embed needs a separate npm build) — NOT on the go resolver.
-- gojq is the demonstrable real consumer: a real, published Go toolchain
-- module closure resolved from proxy.golang.org at fetch time.

return {
    default = snap {
        name = "gojq",
        version = "0.12.17",
        summary = "Pure Go implementation of jq (JSON query language)",
        description = [[
            gojq is a pure Go implementation of jq, a command-line JSON
            processing tool. It supports jq filters, streaming input, and
            JSONL/CSV output. Source build via the go module resolver
            (deps.go, issue #40) resolving the pinned module closure
            offset from proxy.golang.org; CGO_ENABLED=0 yields a static
            binary.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/itchyny/gojq/archive/refs/tags/v0.12.17.tar.gz",
            sha256 = "86b8393d04cb40db09a8de96199f358c1e49bbd7d1ace5c95496cc7cc4102b3b",
        },

        deps = {
            go = { mods = "go.mod" },
        },

        -- Go offline wiring (issue #40): a writable GOMODCACHE on the
        -- sandbox's /tmp tmpfs plus a file:// GOPROXY pointing at the
        -- mounted, hash-verified module cache download dir. GOSUMDB=off
        -- keeps the sumdb unreachable (go.sum pins everything).
        build = table.concat({
            "export GOMODCACHE=/tmp/shuttle-go-cache",
            "export GOPROXY=\"file://$SHUTTLE_DEPS_DIR/cache/download\"",
            "export GOFLAGS=-mod=mod GOSUMDB=off GOPATH=/tmp/shuttle-go-cache",
            "mkdir -p \"$GOMODCACHE\"",
            "go build -o $STAGE/gojq ./cmd/gojq",
        }, " && "),

        type = "source",
        requires = {},

        apps = {
            gojq = app {
                command = "gojq",
            },
        },
    },
}
