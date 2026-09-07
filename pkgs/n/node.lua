-- Node.js: JavaScript runtime built on Chrome's V8 (current line 26).
--
-- Ported from the devbox global profile into a shuttle source package.
-- Uses the official prebuilt linux-x64 binaries (same artifact class as
-- nixpkgs' nodejs): the build only relayouts the tarball into $STAGE;
-- the #12 portability step repoints the ELF interpreter/RUNPATH at build
-- time so the binary runs on plain hosts without the nix store.

return {
    default = snap {
        name = "node",
        version = "26.7.0",
        summary = "Node.js JavaScript runtime (V8, current 26)",
        description = [[
            Node.js is a JavaScript runtime built on Chrome's V8
            JavaScript engine, executing JS outside the browser with an
            event-driven, non-blocking I/O model. This package ships the
            official prebuilt linux-x64 binaries of the current 26 line,
            which interpreter-based pod packages (e.g. zg) exec at
            runtime via their `interpreter = "node"` app wrappers.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://nodejs.org/dist/v26.7.0/node-v26.7.0-linux-x64.tar.xz",
            sha256 = "982aa24dd8be4c889c6a8ab337ddff3b0896645b20f4239356e80552c16277ee",
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
