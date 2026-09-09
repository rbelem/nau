-- lua: Lua 5.4 interpreter and bytecode compiler.
--
-- Pool port for the luarocks lane (issue #23): the interpreter
-- (usr/bin/lua), the compiler (usr/bin/luac), the C API headers, and
-- the versioned module paths (share/lua/5.4, lib/lua/5.4) luarocks
-- installs rocks into. Plain make build — lua ships no configure
-- script; the `src/all` target is invoked directly so SYSCFLAGS/
-- SYSLIBS can point the readline editline support at the merged build
-- prefix (the top-level `linux` target hardcodes /usr paths).
--
-- The interpreter links readline (libtinfo under it), so ncurses is
-- required directly — the closure stays resolvable regardless of how
-- the readline package declares its own deps.
--
-- Requires: glibc, ncurses, readline

return {
    default = snap {
        name = "lua",
        version = "5.4.8",
        summary = "Lua 5.4 programming language interpreter",
        description = [[
            Lua is a powerful, efficient, lightweight, embeddable
            scripting language. This package ships the lua interpreter,
            the luac compiler, the C API headers, and the versioned
            module paths (share/lua/5.4, lib/lua/5.4) used by luarocks.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://www.lua.org/ftp/lua-5.4.8.tar.gz",
            sha256 = "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
        },

        -- Direct src/all invocation: the top-level `linux` target would
        -- re-pass its own SYSCFLAGS/SYSLIBS (hardcoded /usr include and
        -- lib paths) to the sub-make, overriding ours. -DLUA_USE_LINUX
        -- turns on dlopen + readline editline in lua.c; the prefix -I/-L
        -- flags resolve readline against the merged build prefix.
        -- -ltinfow: the pool ncurses is widec-only (libtinfow), and the
        -- pool readline.so leaves the terminfo symbols undefined for the
        -- final link.
        build = table.concat({
            "make -C src all SYSCFLAGS=\"-DLUA_USE_LINUX -DLUA_USE_READLINE -I$SHUTTLE_BUILD_PREFIX/usr/include\" SYSLIBS=\"-Wl,-E -ldl -L$SHUTTLE_BUILD_PREFIX/usr/lib -lreadline -ltinfow\"",
            "make install INSTALL_TOP=$STAGE/usr",
        }, " && "),

        type = "source",
        requires = { "glibc", "ncurses", "readline" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22): the
        -- nix gcc wrapper bakes the merged build prefix into produced
        -- ELFs' RUNPATH — observed as both usr/lib and usr/lib64 forms
        -- (paths that do not exist at runtime). Silenced here, visibly
        -- logged by the leak scan, pending the RUNPATH repair. Same
        -- rationale as htop.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
        },

        apps = {
            lua = app {
                command = "usr/bin/lua",
            },
            luac = app {
                command = "usr/bin/luac",
            },
        },
    },
}
