-- valkey: the open source (Redis-compatible) in-memory data store.
-- https://valkey.io
--
-- Three-way comparison:
--
-- Nix:       pkgs.valkey (stdenv.mkDerivation over the release tarball,
--            jemalloc by default on Linux)
-- Snapcraft: no upstream snapcraft recipe; the Redis snap's core
--            make-plugin shape is the precedent
-- Shuttle:   declarative Lua — source build via the pool toolchain,
--            carrying a `services` declaration (ADR-0032 Decision 2)
--
-- Source build (issue #108): `make valkey-server valkey-cli` against
-- the pinned 9.1.2 release tarball; the two binaries are hand-installed
-- to usr/bin (upstream's `install` target also drops redis-server/cli
-- compat symlinks and needs PREFIX staging — nothing here consumes
-- them). MALLOC=libc skips the bundled jemalloc build: it trades
-- fragmentation behavior for a single-toolchain hermetic build with no
-- deps/ submake in the sandbox; revisit if a memory-profile argument
-- ever lands. BUILD_TLS=no keeps openssl out of the closure (no pool
-- consumer speaks TLS to a loopback pod service).
--
-- The valkey-search module is ported (pkgs/v/valkey-search.lua,
-- issue #109): libsearch.so builds offline through upstream's
-- system-modules path over the pool grpc chain, and the service
-- below wires it via the ${extensions} reference. The module loads
-- only when the pod actually includes the valkey-search package
-- (adding it pulls libsearch.so plus its grpc/protobuf closure);
-- until then the loadmodule path simply does not exist — the
-- service stays `enabled = false` by default, and flipping it on
-- without the package fails visibly at start, not silently.
--
-- The shared templates come in via slash-form requires (the analyzer's
-- dot→slash module mapping has no root where `pkgs.lib.X` resolves;
-- `lib/X` hits the pkgs/ root directly, toolchain.lua precedent):
-- lib/daemon's service() is the ADR-0032 Decision 2 constructor.

local cli = require("lib/cli")
local svc = require("lib/daemon").service

return {
    default = snap {
        name = "valkey",
        version = "9.1.2",
        summary = "Persistent key-value database (Redis-compatible), in-memory storage",
        description = [[
            Valkey is a high-performance, Redis-compatible in-memory
            data structure server: strings, hashes, lists, sets,
            sorted sets, streams, and pub/sub over a RESP protocol,
            with replication and Lua scripting. This package ships the
            valkey-server daemon and the valkey-cli client, built from
            the release tarball, and declares a `valkey` pod service
            (ADR-0032) with port and data-dir options, disabled by
            default.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/valkey-io/valkey/archive/refs/tags/9.1.2.tar.gz",
            sha256 = "19c23908e7d57e8d91ef85b41f5646307582f10f4f0fb999bbf89ed24ec9c983",
        },

        -- The top Makefile forwards every target to src/ (where the
        -- explicit valkey-server/valkey-cli targets live); MALLOC and
        -- BUILD_TLS flow through MAKEFLAGS to that sub-make.
        build = table.concat({
            "make -C $SRC MALLOC=libc BUILD_TLS=no valkey-server valkey-cli",
            "install -Dm755 $SRC/src/valkey-server $STAGE/usr/bin/valkey-server",
            "install -Dm755 $SRC/src/valkey-cli $STAGE/usr/bin/valkey-cli",
        }, " && "),

        type = "source",
        requires = { "glibc" },
        build_deps = { "toolchain" },

        apps = {
            ["valkey-server"] = app {
                command = "usr/bin/valkey-server",
                plugs = { "network", "network-bind" },
            },
            ["valkey-cli"] = cli.app {
                command = "usr/bin/valkey-cli",
            },
        },

        services = {
            valkey = svc {
                command = "usr/bin/valkey-server",
                daemon = "simple",
                args = {
                    "--port",
                    "${port}",
                    "--dir",
                    "${data_dir}",
                    -- The valkey-search module (pkgs/v/valkey-search.lua
                    -- stages usr/lib/libsearch.so; extensions merge
                    -- payloads under a second usr level — blesh/
                    -- hermes-desktop precedent). Loads when the pod
                    -- includes the valkey-search package.
                    "--loadmodule",
                    "${extensions}/valkey-search/usr/usr/lib/libsearch.so",
                },
                options = {
                    port = 6379,
                    data_dir = "%h/.local/share/shuttle/valkey/%p",
                    enabled = false,
                },
                environment = {},
            },
        },
    },
}
