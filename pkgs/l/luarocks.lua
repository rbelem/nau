-- luarocks: package manager for Lua modules.
--
-- Pool port for the wayland/lua tooling lane (issue #23). Built
-- against the pool lua (headers + interpreter resolved through the
-- merged build prefix via --with-lua), installed with the usual
-- DESTDIR staging.
--
-- The upstream generated launcher bakes absolute install paths
-- (/usr/share/lua/5.4), which exist neither at build sandbox runtime
-- nor in a pod store — so the build replaces it with a self-locating
-- launcher (the hermes-agent pattern): it resolves the staged module
-- tree relative to the running script, which the pod's interpreter
-- wrapper passes as the extension-tree path
-- ($PODROOT/active/extensions/luarocks/usr/bin/luarocks.real).
--
-- Runtime: luarocks needs `lua` (same pod, farm PATH) to run rocks'
-- build hooks and `unzip` to unpack them; remote rock fetching also
-- wants a downloader (curl/wget) which is deliberately not required —
-- the smoke contract is the CLI itself.
--
-- Requires: glibc, lua, unzip
-- build_deps: none (ships a configure script)

return {
    default = snap {
        name = "luarocks",
        version = "3.13.0",
        summary = "Package manager for Lua modules",
        description = [[
            LuaRocks is the package manager for Lua modules: it builds
            and installs "rocks" (pure-Lua modules and C extensions)
            into the versioned Lua module paths. Consumes the pool lua
            interpreter and headers for both its own runtime and the
            rocks it builds.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/luarocks/luarocks/archive/refs/tags/v3.13.0.tar.gz",
            sha256 = "71adfead6966e2912034b8fb8103dd343c3adc6c91a276f1d209eebbaefe3a15",
        },

        -- The launcher is emitted with printf, not a heredoc: the sandbox
        -- tool preflight tokenizes the build command per segment and would
        -- probe heredoc terminator lines as missing sandbox commands (the
        -- meson.lua caveat). The lua source is double-quote-only so every
        -- line survives as a single-quoted printf argument.
        build = table.concat({
            "./configure --prefix=/usr --with-lua=$SHUTTLE_BUILD_PREFIX/usr",
            "make",
            "make install DESTDIR=$STAGE",
            "printf '%s\\n' " ..
                "'#!/usr/bin/env lua' " ..
                "'-- Self-locating luarocks launcher (pool port): resolves the' " ..
                "'-- staged module tree relative to the running script, which the' " ..
                "'-- pod interpreter wrapper passes as the extension-tree path.' " ..
                "'local dir = arg[0]:match(\"^(.*)[/]\") or \".\"' " ..
                "'local root = dir .. \"/../share/lua/5.4\"' " ..
                "'package.path = root .. \"/?.lua;\" .. root .. \"/?/init.lua;\" .. package.path' " ..
                "'package.cpath = root .. \"/?.so;\" .. package.cpath' " ..
                "'local cfg = require(\"luarocks.core.cfg\")' " ..
                "'local loader = require(\"luarocks.loader\")' " ..
                "'local cmd = require(\"luarocks.cmd\")' " ..
                "'local description = \"LuaRocks main command-line interface\"' " ..
                "'local commands = {' " ..
                "'   init = \"luarocks.cmd.init\",' " ..
                "'   pack = \"luarocks.cmd.pack\",' " ..
                "'   unpack = \"luarocks.cmd.unpack\",' " ..
                "'   build = \"luarocks.cmd.build\",' " ..
                "'   install = \"luarocks.cmd.install\",' " ..
                "'   search = \"luarocks.cmd.search\",' " ..
                "'   list = \"luarocks.cmd.list\",' " ..
                "'   remove = \"luarocks.cmd.remove\",' " ..
                "'   make = \"luarocks.cmd.make\",' " ..
                "'   download = \"luarocks.cmd.download\",' " ..
                "'   path = \"luarocks.cmd.path\",' " ..
                "'   show = \"luarocks.cmd.show\",' " ..
                "'   new_version = \"luarocks.cmd.new_version\",' " ..
                "'   lint = \"luarocks.cmd.lint\",' " ..
                "'   write_rockspec = \"luarocks.cmd.write_rockspec\",' " ..
                "'   purge = \"luarocks.cmd.purge\",' " ..
                "'   doc = \"luarocks.cmd.doc\",' " ..
                "'   upload = \"luarocks.cmd.upload\",' " ..
                "'   config = \"luarocks.cmd.config\",' " ..
                "'   which = \"luarocks.cmd.which\",' " ..
                "'   test = \"luarocks.cmd.test\",' " ..
                "'}' " ..
                "'cmd.run_command(description, commands, \"luarocks.cmd.external\", table.unpack(arg))' " ..
                "> $STAGE/usr/bin/luarocks",
            -- luarocks-admin gets the same self-locating launcher: the
            -- generated one bakes the build prefix into absolute paths.
            "printf '%s\\n' " ..
                "'#!/usr/bin/env lua' " ..
                "'-- Self-locating luarocks-admin launcher (pool port): see usr/bin/luarocks.' " ..
                "'local dir = arg[0]:match(\"^(.*)[/]\") or \".\"' " ..
                "'local root = dir .. \"/../share/lua/5.4\"' " ..
                "'package.path = root .. \"/?.lua;\" .. root .. \"/?/init.lua;\" .. package.path' " ..
                "'package.cpath = root .. \"/?.so;\" .. package.cpath' " ..
                "'local cfg = require(\"luarocks.core.cfg\")' " ..
                "'local loader = require(\"luarocks.loader\")' " ..
                "'local cmd = require(\"luarocks.cmd\")' " ..
                "'local description = \"LuaRocks repository administration interface\"' " ..
                "'local commands = {' " ..
                "'   make_manifest = \"luarocks.admin.cmd.make_manifest\",' " ..
                "'   add = \"luarocks.admin.cmd.add\",' " ..
                "'   remove = \"luarocks.admin.cmd.remove\",' " ..
                "'   refresh_cache = \"luarocks.admin.cmd.refresh_cache\",' " ..
                "'}' " ..
                "'cmd.run_command(description, commands, \"luarocks.admin.cmd.external\", table.unpack(arg))' " ..
                "> $STAGE/usr/bin/luarocks-admin",
            "chmod +x $STAGE/usr/bin/luarocks $STAGE/usr/bin/luarocks-admin",
            -- The staged default config embeds the configure-time
            -- --with-lua prefix; point it at the install prefix instead
            -- (same build-prefix scrub as the launchers above).
            "sed -i \"s|$SHUTTLE_BUILD_PREFIX|/usr|g\" $STAGE/etc/luarocks/config-5.4.lua",
        }, " && "),

        type = "source",
        requires = { "glibc", "lua", "unzip" },

        apps = {
            luarocks = app {
                command = "usr/bin/luarocks",
                interpreter = "lua",
            },
            ["luarocks-admin"] = app {
                command = "usr/bin/luarocks-admin",
                interpreter = "lua",
            },
        },
    },
}
