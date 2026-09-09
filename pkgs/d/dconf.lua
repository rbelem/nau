-- dconf: GSettings backend — key/value configuration storage.
--
-- Pool port for GSettings consumers. Meson build driven by pool
-- tooling through the merged build prefix (ADR-0018 Decision 2):
-- glib is the runtime library (libdconf, the dconf CLI, and the
-- dconf-service D-Bus activator all link it), dbus is build-time
-- only — meson reads the session-services install dir from dbus-1.pc;
-- the service itself talks to the bus through glib's gdbus, never
-- libdbus.
--
-- Probes disabled for hermeticity: bash-completion (hard
-- bash-completion.pc probe), man pages (xsltproc), and the vala
-- client vapi (hard vapigen.pc probe). systemd unit dir falls back
-- to ${prefix}/lib/systemd/user when the systemd.pc probe fails.
--
-- Requires: glibc, glib
-- build_deps: dbus (dbus-1.pc metadata), meson (pulls python
-- transitively), ninja, pkg-config

return {
    default = snap {
        name = "dconf",
        version = "0.49.0",
        summary = "GSettings backend — low-level configuration storage",
        description = [[
            dconf is a simple key/value configuration storage backend
            for GSettings: a client library (libdconf), the dconf CLI
            for reading and writing keys, and a D-Bus service that
            serializes writes into the binary dconf database. Consumers
            configure GSettings with
            G_SETTINGS_BACKEND=dconf after installing this package.
        ]],
        license = "LGPL-2.1-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://download.gnome.org/sources/dconf/0.49/dconf-0.49.0.tar.xz",
            sha256 = "16a47e49a58156dbb96578e1708325299e4c19eea9be128d5bd12fd0963d6c36",
        },

        build = table.concat({
            -- Pool meson/ninja/pkg-config live in the merged build
            -- prefix; the sandbox does not extend PATH to it, and the
            -- sandbox tool preflight only accepts PATH-resolved bare
            -- command words, so every tool is invoked by its explicit
            -- $SHUTTLE_BUILD_PREFIX path. HOME keeps cmake-method
            -- dependency lookups alive (no /etc in the sandbox, so no
            -- passwd entry).
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            -- gio-2.0.pc advertises its tools at /usr/bin/... (the install
            -- prefix path), which does not exist in the sandbox — the tools
            -- live in the merged build prefix. meson's gnome module checks
            -- machine-file binary entries BEFORE the pkg-config variable,
            -- so a native file overrides every gio-2.0 tool variable at
            -- once (dconf reads gio_querymodules and gdbus_codegen).
            "printf '[binaries]\\ngdbus-codegen = '\\''%s'\\''\\ngio = '\\''%s'\\''\\ngio-querymodules = '\\''%s'\\''\\nglib-compile-schemas = '\\''%s'\\''\\nglib-compile-resources = '\\''%s'\\''\\ngdbus = '\\''%s'\\''\\ngresource = '\\''%s'\\''\\ngsettings = '\\''%s'\\''\\n' \"$SHUTTLE_BUILD_PREFIX/usr/bin/gdbus-codegen\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gio\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gio-querymodules\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-compile-schemas\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-compile-resources\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gdbus\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gresource\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gsettings\" > gio-tools-native.ini",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "--native-file gio-tools-native.ini " ..
                "-Dbash_completion=false -Dman=false -Dvapi=false",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "glib" },
        build_deps = { "dbus", "meson", "ninja", "pkg-config" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22/#19)
        -- until the nix gcc wrapper stops baking the merged build prefix
        -- into produced binaries: produced ELFs carry
        -- RUNPATH=/shuttle-build-prefix/usr/lib (that path does not exist
        -- at runtime). Silenced here, visibly logged by the build's leak
        -- scan, pending the RUNPATH repair. Same rationale as htop.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },
    },
}
