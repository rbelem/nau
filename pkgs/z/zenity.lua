-- zenity: GNOME dialog tool — display messages/entries/progress from
-- shell scripts.
--
-- nixpkgs-only port (devbox.json entry "zenity": "latest"; no local
-- flake): upstream GNOME meson recipe, built with the pool meson
-- tooling through the merged build prefix, following dconf's pattern
-- (ADR-0018 Decision 2). Pinned to the newest stable release tarball,
-- zenity 4.2.2 (LATEST-IS in download.gnome.org/sources/zenity/4.2/).
--
-- Meson probes disabled for hermeticity: manpage (help2man runs the
-- zenity binary to generate the page — impossible in the sandbox).
-- webkitgtk is left at its upstream default (false). The i18n tools
-- (msgfmt et al.) resolve from the merged prefix via PATH; the gnome
-- module's glib tools are overridden through a native file because the
-- pool glib.pc advertises them at /usr/bin (the install prefix path,
-- which does not exist in the sandbox) — zenity uses
-- glib-compile-resources (gnome.compile_resources) and glib-mkenums
-- (gnome.mkenums_simple).
--
-- KNOWN GAPS (declared, not resolved): the runtime closure needs gtk4
-- and libadwaita (meson hard-requires libadwaita-1 >= 1.2; zenity 4.x
-- has no gtk3 fallback), and `gnome.yelp()` hard-requires itstool for
-- the help pages with no meson option to disable them — none of
-- gtk4/libadwaita/itstool exist in the pool yet. This package cannot
-- build or run until those land in the pool.
--
-- Requires: glibc, glib, gtk4 (not yet in pool), libadwaita (not yet in pool)
-- build_deps: meson (pulls python transitively), ninja, pkg-config,
-- gettext (msgfmt for i18n.gettext and the desktop-file merge)

return {
    default = snap {
        name = "zenity",
        version = "4.2.2",
        summary = "Display dialogs from shell scripts (GNOME)",
        description = [[
            zenity lets shell scripts present graphical dialogs —
            messages, questions, text entry, file selection, progress,
            calendars, color pickers, forms, and notifications — via a
            simple command-line interface. Built against GTK4 and
            libadwaita (zenity 4.x).
        ]],
        license = "LGPL-2.1-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://download.gnome.org/sources/zenity/4.2/zenity-4.2.2.tar.xz",
            sha256 = "019186a996096ef4fc356e21577b5673f5baa3a29ac8e3d608b753371c18018d",
        },

        build = table.concat({
            -- Pool meson/ninja/pkg-config live in the merged build
            -- prefix; the sandbox does not extend PATH to it, and the
            -- sandbox tool preflight only accepts PATH-resolved bare
            -- command words, so every tool is invoked by its explicit
            -- $SHUTTLE_BUILD_PREFIX path (or via the PATH export for
            -- meson-internal find_program calls, e.g. msgfmt). HOME
            -- keeps cmake-method dependency lookups alive (no /etc in
            -- the sandbox, so no passwd entry).
            'export PATH="$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH"',
            "export HOME=/tmp",
            -- glib's .pc advertises its tools at /usr/bin/... (the
            -- install prefix path), which does not exist in the sandbox
            -- — the tools live in the merged build prefix. meson's
            -- gnome module checks machine-file binary entries BEFORE
            -- the pkg-config variable, so a native file overrides every
            -- glib tool variable zenity uses at once
            -- (glib-compile-resources, glib-mkenums).
            "printf '[binaries]\\nglib-compile-resources = '\\''%s'\\''\\nglib-mkenums = '\\''%s'\\''\\n' \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-compile-resources\" \"$SHUTTLE_BUILD_PREFIX/usr/bin/glib-mkenums\" > zenity-tools-native.ini",
            '"$SHUTTLE_BUILD_PREFIX/usr/bin/meson" setup build --prefix=/usr '
                .. "--native-file zenity-tools-native.ini "
                .. "-Dmanpage=false -Dwebkitgtk=false",
            '"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja" -C build',
            'DESTDIR=$STAGE "$SHUTTLE_BUILD_PREFIX/usr/bin/ninja" -C build install',
        }, " && "),

        type = "source",
        requires = { "glibc", "glib", "gtk4", "libadwaita" },
        build_deps = { "meson", "ninja", "pkg-config", "gettext" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22/#19)
        -- until the nix gcc wrapper stops baking the merged build prefix
        -- into produced binaries: produced ELFs carry
        -- RUNPATH=/shuttle-build-prefix/usr/lib (that path does not exist
        -- at runtime). Silenced here, visibly logged by the build's leak
        -- scan, pending the RUNPATH repair. Same rationale as dconf.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
        },

        apps = {
            zenity = app {
                command = "usr/bin/zenity",
            },
        },
    },
}
