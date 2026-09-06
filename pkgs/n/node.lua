-- Node.js: JavaScript runtime built on Chrome's V8 (LTS line 22).
--
-- Ported from the devbox global profile into a shuttle source package.
-- Uses the official prebuilt linux-x64 binaries (same artifact class as
-- nixpkgs' nodejs): the build only relayouts the tarball into $STAGE;
-- the #12 portability step repoints the ELF interpreter/RUNPATH at build
-- time so the binary runs on plain hosts without the nix store.

return {
    default = snap {
        name = "node",
        version = "22.23.2",
        summary = "Node.js JavaScript runtime (V8, LTS 22)",
        description = [[
            Node.js is a JavaScript runtime built on Chrome's V8
            JavaScript engine, executing JS outside the browser with an
            event-driven, non-blocking I/O model. This package ships the
            official prebuilt linux-x64 binaries of the LTS 22 line,
            which interpreter-based pod packages (e.g. zg) exec at
            runtime via their `interpreter = "node"` app wrappers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.xz",
            sha256 = "d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307",
        },

        -- The tarball root is node-v<version>-linux-x64/ and $SRC points
        -- at it; relayout bin/lib/include/share into the /usr prefix.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -r bin lib include share $STAGE/usr/",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            -- Only the node binary is exposed: npm/npx/corepack in the
            -- official tarball are symlinks into lib/node_modules, and
            -- the interpreter-wrapper pass rewrites the command file in
            -- place (following symlinks), so they are not safe to wrap.
            node = app {
                command = "usr/bin/node",
            },
        },
    },
}
