-- xkeyboard-config: XKB configuration data (keymaps, rules, symbols).
--
-- Pool port for the wtype lane (issue #23): the compiled-in default
-- dataset libxkbcommon reads when clients compile a keymap (wtype's
-- virtual-keyboard protocol needs one to type). Pure data: rules,
-- symbols, compat, geometry files plus the X11 path symlink.
--
-- Probes disabled for hermeticity: NLS translations (msgfmt). The man
-- page needs xsltproc, which the sandbox lacks — absent tools are
-- skipped upstream, which is exactly what we want.
--
-- Requires: nothing (data only)
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "xkeyboard-config",
        version = "2.48",
        summary = "X keyboard configuration data",
        description = [[
            xkeyboard-config provides the X Keyboard Extension (XKB)
            configuration database — keyboard models, layouts, variants,
            options, and the rules files that tie them together.
            libxkbcommon-based clients (e.g. wtype) compile keymaps from
            this dataset at runtime via the compiled-in default rules.
        ]],
        license = "MIT AND HPND-sell-variant AND X11-distribute-modifications-variant",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://www.x.org/releases/individual/data/xkeyboard-config/xkeyboard-config-2.48.tar.xz",
            sha256 = "b77041324f0109f77161ee43743fe04baa485866af8460d31e476ad3f7648fd5",
        },

        build = table.concat({
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr -Dnls=false",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
            -- The meson install adds a usr/share/X11/xkb -> absolute
            -- /usr/share/xkeyboard-config-2 compatibility symlink; the snap
            -- packer's recursive copy follows stage symlinks, and this one
            -- points outside the stage. Drop it: consumers that need the
            -- X11 spelling (libxkbcommon's compiled-in config root) are
            -- pointed at the real dataset path explicitly.
            "rm -f $STAGE/usr/share/X11/xkb",
            "rmdir $STAGE/usr/share/X11",
        }, " && "),

        type = "source",
        requires = {},
        build_deps = { "meson", "ninja", "pkg-config" },
    },
}
