-- libsecret: freedesktop secret service client library.
--
-- Pool port for credential-store consumers. Meson build driven by
-- pool tooling through the merged build prefix (ADR-0018 Decision 2):
-- glib is the runtime library (libsecret-1 and the secret-tool CLI
-- link it). The Secret Service protocol runs over D-Bus through
-- glib's gdbus, so no dbus package is needed at build or runtime.
--
-- Probes disabled for hermeticity: crypto backend (libgcrypt/gnutls
-- would both need new pool packages — transport encryption is
-- optional), man pages (xsltproc), gtk-doc/gi-docgen, gobject
-- introspection (gobject-introspection not in pool), the vala vapi
-- (needs vapigen), and bash completion. pam and tpm2 are off by
-- default upstream and stay off.
--
-- Requires: glibc, glib
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "libsecret",
        version = "0.21.7",
        summary = "freedesktop Secret Service API client library",
        description = [[
            libsecret is a client library for the freedesktop Secret
            Service API: storing, retrieving, and organizing password
            collections over D-Bus, plus the secret-tool CLI for
            scripting the same operations. Consumers link
            libsecret-1 (pkg-config libsecret-1) with glib.
        ]],
        license = "LGPL-2.1-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://download.gnome.org/sources/libsecret/0.21/libsecret-0.21.7.tar.xz",
            sha256 = "6b452e4750590a2b5617adc40026f28d2f4903de15f1250e1d1c40bfd68ed55e",
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
            -- gio-2.0.pc / glib-2.0.pc advertise their tools at /usr/bin/...
            -- (the install prefix path), which does not exist in the
            -- sandbox — the tools live in the merged build prefix. meson's
            -- gnome module checks machine-file binary entries BEFORE the
            -- pkg-config variable, so a native file overrides the gio-2.0
            -- and glib-2.0 tool variables (libsecret reads gdbus_codegen
            -- and glib_mkenums via the gnome module).
            "printf '[binaries]\\ngdbus-codegen = '\\''%s'\\''\\ngio = '\\''%s'\\''\\ngio-querymodules = '\\''%s'\\''\\nglib-compile-schemas = '\\''%s'\\''\\nglib-compile-resources = '\\''%s'\\''\\ngdbus = '\\''%s'\\''\\ngresource = '\\''%s'\\''\\ngsettings = '\\''%s'\\''\\nglib-mkenums = '\\''%s'\\''\\nglib-genmarshal = '\\''%s'\\''\\ngobject-query = '\\''%s'\\''\\n' \"$SHUTTLE_BUILD_PREFIX/usr/bin/gdbus-codegen\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gio\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gio-querymodules\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-compile-schemas\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-compile-resources\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gdbus\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gresource\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gsettings\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-mkenums\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-genmarshal\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/gobject-query\" > gio-tools-native.ini",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "--native-file gio-tools-native.ini " ..
                "-Dcrypto=disabled -Dmanpage=false -Dgtk_doc=false " ..
                "-Dintrospection=false -Dvapi=false -Dbash_completion=disabled",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "glib" },
        build_deps = { "meson", "ninja", "pkg-config" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22/#19)
        -- until the nix gcc wrapper stops baking the merged build prefix
        -- into produced binaries: produced ELFs carry
        -- RUNPATH=/shuttle-build-prefix/usr/lib (that path does not exist
        -- at runtime). Silenced here, visibly logged by the build's leak
        -- scan, pending the RUNPATH repair. Same rationale as htop.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },
    },
}
