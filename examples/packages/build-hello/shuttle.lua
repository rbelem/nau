-- build-hello: Building a single source package from scratch
--
-- Demonstrates building the GNU Hello package from source using the
-- DSL's source + build fields. The package is fetched from the GNU
-- FTP server, configured, compiled, and assembled into a .snap.
--
-- Usage:
--   shuttle build --file examples/packages/build-hello/shuttle.lua
--   → produces hello_2.10_amd64.snap
--
--   shuttle build --file examples/packages/build-hello/shuttle.lua --order
--   → shows build order (requires glibc)

return {
    default = snap {
        name = "hello",
        version = "2.10",
        summary = "GNU Hello, built from source with shuttle",
        description = [[
            GNU hello prints a friendly greeting. This example shows
            how shuttle builds a package entirely from source — fetch,
            configure, make, install, and snap — in one command.
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc" },
        source = {
            url = "http://ftp.gnu.org/gnu/hello/hello-2.10.tar.gz",
        },
        build = "./configure --prefix=/usr && make && make install DESTDIR=$STAGE",
        apps = {
            hello = app { command = "bin/hello" },
        },
    },
}
