-- multi-output: One file, multiple snaps
--
-- Demonstrates the multi-output structure: a single shuttle.lua declares
-- multiple snaps, each with its own name, version, apps, and build
-- configuration. Build them all at once or select specific outputs.
--
-- The Lua multi-output pattern (ADR-0003) maps keys to named outputs:
--   return { server = snap { ... }, cli    = snap { ... } }
--
-- Usage:
--   shuttle build --file examples/packages/multi-output/shuttle.lua
--   → builds both server and cli snaps
--
--   shuttle build --file examples/packages/multi-output/shuttle.lua server
--   → builds only the server snap
--
--   shuttle build --file examples/packages/multi-output/shuttle.lua --order
--   → shows build order for all outputs

return {
    -- Server daemon snap
    server = snap {
        name = "my-server",
        version = "0.1.0",
        summary = "Example server daemon snap",
        description = [[
            An example server snap built from source. Demonstrates
            daemon apps with the 'simple' daemon type, which snapd
            manages as a systemd service.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        -- Simulated server build (hello as a stand-in)
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            server = app {
                command = "bin/hello",
                daemon = "simple",
                plugs = { "network", "network-bind" },
            },
        },
    },

    -- CLI tool snap
    cli = snap {
        name = "my-cli",
        version = "0.2.0",
        summary = "Example CLI tool snap",
        description = [[
            An example CLI snap built from source. Shows a basic
            command-line app with no daemon, suitable for scripting.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64", "arm64" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            cli = app {
                command = "bin/hello",
                plugs = { "network" },
            },
        },
    },
}
