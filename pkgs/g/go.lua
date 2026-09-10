-- go: The Go programming language toolchain (compiler, linker, gofmt).
--
-- Ticket #24 — pool toolchain package, dual-use: pod-installable for
-- daily use AND consumable as a build_dep by other packages (the merged
-- build prefix puts usr/bin first on the sandbox PATH, so a bare `go`
-- resolves inside a consumer's hermetic build).
--
-- Port strategy — FETCH, not source bootstrap: Go ships official,
-- self-contained prebuilt linux-amd64 toolchains on go.dev/dl; the
-- toolchain bootstraps itself from bundled sources, so a from-source
-- build in the sandbox would only re-derive the identical tree at real
-- cost. The upstream tarball is fetched, sha256-pinned (go.dev/dl
-- publishes the digest alongside the download), and the GOROOT tree is
-- staged whole at usr/lib/go — building Go programs needs the bundled
-- src/ and pkg/ trees next to the compiler, so only-bin staging (the
-- gh.lua pattern) would break every consumer build.
--
-- GOROOT discovery survives relayout and prefix rebinding: the go
-- binary resolves its root relative to /proc/self/exe, so the usr/bin
-- wrappers (which exec ../lib/go/bin/go relative to their own location)
-- land GOROOT at usr/lib/go wherever the payload is unpacked, including
-- the read-only merged build prefix and a pod store tree.
--
-- requires = {}: the toolchain binaries are fully static ELF (no cgo),
-- matching the #20 static-Go-binary precedent.

return {
    default = snap {
        name = "go",
        version = "1.27.1",
        summary = "The Go programming language — compiler, linker, gofmt",
        description = [[
            The official Go toolchain for linux/amd64: the go command
            (build, test, install, modules), the gc compiler and linker,
            gofmt, and the complete standard-library source tree. Staged
            as a self-contained GOROOT at usr/lib/go, with sh wrappers
            for `go`/`gofmt` in usr/bin so pod installs expose them and
            build_deps consumers invoke them by bare name in the
            hermetic sandbox.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://go.dev/dl/go1.27.1.linux-amd64.tar.gz",
            sha256 = "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
        },

        -- $SRC is the extracted GOROOT root (the harness descends into
        -- the tarball's single top-level `go/` dir). Stage it whole at
        -- usr/lib/go. usr/bin/{go,gofmt} are tiny sh wrappers, NOT
        -- symlinks: the pack step's stage copy dereferences symlinks
        -- (fs::copy), and a materialized copy at usr/bin/go would make
        -- the go binary locate GOROOT at usr/ (exe-relative) and die
        -- with "binary is trimmed". A wrapper resolves its sibling at
        -- run time, so it works in the merged build prefix, a pod tree,
        -- and any payload root.
        build = table.concat({
            "mkdir -p $STAGE/usr/lib $STAGE/usr/bin",
            "cp -a $SRC $STAGE/usr/lib/go",
            -- Wrappers resolve $0 through symlinks before deriving the
            -- toolchain path: the farm exposes the app as a symlink
            -- (current/go -> apps/go/usr/lib/go/go), so a bare `dirname $0`
            -- points at the farm dir, not the GOROOT. readlink -f gives the
            -- real script path; its dirname is where bin/ and the GOROOT
            -- src/pkg trees live. Three single-substitution lines (no
            -- nesting) so the preflight PATH probe does not mis-split them.
            --
            -- usr/bin wrappers: build-time PATH exposure (a build_deps
            -- consumer invokes bare `go`/`gofmt` in the merged prefix).
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/../lib/go/bin/go\" \"$@\"' > $STAGE/usr/bin/go",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/../lib/go/bin/gofmt\" \"$@\"' > $STAGE/usr/bin/gofmt",
            -- GOROOT-root launchers: the farm app commands. The app
            -- assembly (issue #37) captures only the command binary's
            -- parent directory, so a command under usr/lib/go/bin would
            -- hardlink the trimmed go/gofmt binaries alone and strand the
            -- GOROOT src/pkg trees — go then dies "binary is trimmed and
            -- GOROOT is not set". A launcher AT usr/lib/go makes the
            -- assembly root usr/lib/go, so the whole GOROOT ships beside
            -- the binary and the resolved script dir is the GOROOT root.
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/go\" \"$@\"' > $STAGE/usr/lib/go/go",
            "printf '%s\\n' '#!/bin/sh' 'p=$(readlink -f -- \"$0\")' 'd=$(dirname -- \"$p\")' 'exec \"$d/bin/gofmt\" \"$@\"' > $STAGE/usr/lib/go/gofmt",
            "chmod +x $STAGE/usr/bin/go $STAGE/usr/bin/gofmt $STAGE/usr/lib/go/go $STAGE/usr/lib/go/gofmt",
        }, " && "),

        type = "source",
        requires = {},

        apps = {
            -- command is the GOROOT-root launcher (usr/lib/go/go), not the
            -- bare usr/lib/go/bin/go: the go binary resolves GOROOT relative
            -- to /proc/self/exe, so a farm symlink straight at the trimmed
            -- binary (or an assembly of just usr/lib/go/bin) dies with
            -- "cannot find GOROOT directory: binary is trimmed and GOROOT is
            -- not set". The launcher execs $(dirname $0)/bin/go, so the
            -- assembly rooted at usr/lib/go carries the GOROOT trees and the
            -- binary lands GOROOT at the assembled usr/lib/go. (Supersedes
            -- the interim usr/bin-wrapper app command, which left the farm
            -- assembly without the usr/lib/go tree — issue #46's gap.)
            go = app {
                command = "usr/lib/go/go",
            },
            gofmt = app {
                command = "usr/lib/go/gofmt",
            },
        },
    },
}
