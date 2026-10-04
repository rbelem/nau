-- cua: the Cua CLI — sandboxes, local runtimes, images, Spaces.
--
-- Prebuilt release binary port (the codecanary/chezmoi shape): the
-- upstream cua-sdk release ships a per-platform CLI tarball whose
-- Linux x64 payload is a single flat `cua` executable (151 MB,
-- dynamically linked against glibc only — libgcc_s/libpthread/libm/
-- libdl/libc; verified with ldd against the pinned bytes). Staged
-- straight into usr/bin.
--
-- `cua` drives gVisor sandboxes (`cua sb`), the cua daemon, Spaces
-- hosts, and installs the cua-driver MCP server for coding agents.

return {
    default = snap {
        name = "cua",
        version = "0.3.1",
        summary = "Cua CLI: sandboxes, local runtimes, and Spaces from the command line",
        description = [[
            The `cua` command from trycua/cua: create and run gVisor
            sandboxes (`cua sb`), manage local runtimes and images, host
            this machine for Spaces, and install the cua-driver MCP
            server into coding agents. The agent-facing entry point of
            the Cua computer-use stack on Linux.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/trycua/cua/releases/download/cua-sdk-v0.3.1/cua-cli-0.3.1-linux-x64.tar.gz",
            sha256 = "c5b3de47a8fca33e6f943c682dd3f243d7696a795d7f267119f2625617e46be3",
        },

        -- Tarball is a single flat `cua` binary (no top-level dir), so
        -- cwd stays at the extraction root.
        build = table.concat({
            "install -Dm755 cua $STAGE/usr/bin/cua",
            'test -x "$STAGE/usr/bin/cua"',
        }, " && "),

        type = "source",
        -- glibc loader/libc/libm/libpthread/libdl + libgcc_s.so.1
        -- (ldd over the pinned tarball; no X11 on the CLI itself).
        requires = { "glibc", "libgcc" },

        apps = {
            cua = app {
                command = "usr/bin/cua",
            },
        },
    },
}
