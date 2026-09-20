-- gum: TUI dialogs and script prompts — a tool for glamorous shell
-- scripts (charmbracelet/gum v2.0.1, released 2026-09-11; GitHub's
-- latest stable tag).
-- https://github.com/charmbracelet/gum
--
-- Replaces zenity as the pool's dialog tool (issue #21): zenity 4.x
-- is hard-blocked on gtk4/libadwaita (see pkgs/z/zenity.lua KNOWN
-- GAPS), while gum needs only a TTY — msg, confirm, input, spinner,
-- progress, choose/filter, and friends all render in the terminal.
--
-- Three-way comparison:
--
-- Nix:       pkgs.gum (buildGoModule over the tag tree; pure Go,
--            CGO-free)
-- Snapcraft: no upstream snapcraft recipe in the gum repo (distributions
--            ship the goreleaser RPM/DEB assets)
-- Shuttle:   declarative Lua — Go source build via the pool go
--            toolchain. NO services declaration: gum is an interactive
--            CLI invoked by scripts, not a daemon.
--
-- Port strategy: unlike podman's release tree, gum's tarball ships NO
-- vendor/ directory (0 vendored files; only go.mod + go.sum), so the
-- podman -mod=vendor recipe does not apply — the build resolves the
-- module closure with the go deps resolver (gojq precedent, issue
-- #40 / ADR-0017 extension): go.sum's 30-module closure is fetched at
-- FETCH time, every zip verified against its h1: dirhash, and the
-- sandbox build reads it offline through a file:// GOPROXY on
-- $SHUTTLE_DEPS_DIR.
--
-- go.mod declares `module charm.land/gum/v2` with `go 1.26.7`; the
-- pool go 1.27.1 satisfies it, pinned locally with GOTOOLCHAIN=local
-- (podman's hermeticity convention — no toolchain download, keeping
-- the no-network property explicit alongside GOSUMDB=off).
--
-- CGO_ENABLED=0: the tree has zero cgo imports (verified — no `import
-- "C"` in the v2.0.1 sources), so the single `gum` binary links
-- fully static with no runtime C library — `requires` is empty.
--
-- The main package lives at the tree root (main.go/gum.go — there is
-- no cmd/ layout); `go build .` produces the one binary. ldflags pin
-- the version into main.Version (gum falls back to "unknown (built
-- from source)" without it) — the bifrost -X main.Version pattern.
-- Upstream's release builds run through the charmbracelet/meta
-- goreleaser include; -s -w + -trimpath mirror its shape.
--
-- Man pages are skipped (the man/ roff sources are generated through
-- muesli/roff tooling; cosmetic — `gum --help` carries the content).
-- Shell completions likewise (gum completion prints them on demand).
--
-- KNOWN GAPS (declared, not resolved): gum is TERMINAL-ONLY — there
-- are no graphical (X11/Wayland) dialogs. Scripts that must render a
-- GUI dialog outside a terminal have no pool replacement while zenity
-- stays blocked on gtk4/libadwaita. Under non-TTY stdout gum degrades
-- per-command (e.g. choose/filter pass input through), which is
-- upstream behavior, not a port defect.
--
-- Requires: nothing (static pure-Go binary). build_deps: go (module
-- closure resolver + build toolchain).

return {
    default = snap {
        name = "gum",
        version = "2.0.1",
        summary = "A tool for glamorous shell scripts (TUI dialogs)",
        description = [[
            gum lets shell scripts present polished terminal dialogs —
            messages, confirmations, text input, spinners, progress
            bars, choose/filter pickers, and styled text — replacing
            graphical zenity prompts with a pure-Go TUI. Built from
            the v2.0.1 release tree with the pool Go toolchain; the
            single static binary needs no runtime libraries.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/charmbracelet/gum/archive/refs/tags/v2.0.1.tar.gz",
            sha256 = "2cbc41662ff6c8df30ff3f6c133d4276db72a6f9b3df7eb942f1a798bcbf3d80",
        },

        -- No vendor/ tree in the tarball: resolve the go.sum-pinned
        -- module closure at fetch time (gojq pattern, issue #40).
        deps = {
            go = { mods = "go.mod" },
        },

        -- Offline resolver wiring (issue #40): writable GOMODCACHE on
        -- the sandbox's /tmp tmpfs plus a file:// GOPROXY onto the
        -- mounted, hash-verified module closure. GOSUMDB=off keeps the
        -- sumdb unreachable (go.sum pins everything); GOTOOLCHAIN=local
        -- pins the pool go (1.27.1 >= go.mod's 1.26.7); HOME and
        -- caches under /tmp (sandbox home is not writable — podman
        -- precedent). The final command builds the root main package —
        -- gum has no cmd/ layout.
        build = table.concat({
            "mkdir -p $STAGE/usr/bin",
            "export HOME=/tmp GOCACHE=/tmp/shuttle-go-gocache GOPATH=/tmp/shuttle-go-gopath GOMODCACHE=/tmp/shuttle-go-gopath/pkg/mod",
            "export GOFLAGS=\"-trimpath -mod=mod\" GOPROXY=\"file://$SHUTTLE_DEPS_DIR/cache/download\" GOSUMDB=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0",
            "cd $SRC && go build -ldflags \"-s -w -X main.Version=2.0.1\" -o $STAGE/usr/bin/gum .",
        }, " && "),

        type = "source",
        requires = {},
        build_deps = { "go" },

        apps = {
            gum = app {
                command = "usr/bin/gum",
                -- No plugs (zenity parity): gum's dialogs are
                -- TTY/stdin-stdout only — it opens no files itself.
                -- Under the pool's systemd backend the home plug
                -- degrades to ProtectHome=read-only anyway
                -- (ADR-0011), so declaring it would buy nothing but a
                -- permanent warning.
            },
        },
    },
}
