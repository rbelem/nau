-- xkbcommon: keyboard keymap compiler and support library.
--
-- Pool port for the wtype lane (issue #23): libxkbcommon compiles XKB
-- keymaps without an X server — wtype uses it to build the keymap it
-- hands the compositor's virtual-keyboard device.
--
-- Probes disabled for hermeticity: tools (xkbcli pulls wayland/x11
-- deps), xkbregistry (libxml2 + uuid), the x11 library (xcb), docs,
-- and bash completion. Tests are self-contained (no gtest since the
-- bundled harness) and build fine. bison >= 3.6 is a build tool
-- resolved from the host PATH inside the sandbox (devbox provision),
-- like make/gcc for the autotools ports — not a pool package.
--
-- Requires: glibc, xkeyboard-config (the runtime keymap dataset —
--           libxkbcommon's compiled-in default rules resolve there)
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "xkbcommon",
        version = "1.13.2",
        summary = "Keyboard keymap compiler and support library",
        description = [[
            libxkbcommon is a keyboard keymap compiler and support
            library: it parses the XKB configuration dataset (rules,
            symbols, compat, types, keycodes) into keymaps usable
            without an X server. Wayland clients (wtype) use it to
            create the keymaps they share with compositors.
        ]],
        license = "MIT AND MIT-0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/xkbcommon/libxkbcommon/archive/refs/tags/xkbcommon-1.13.2.tar.gz",
            sha256 = "acc4d5f7c3cbba5f9f8d08d8bdbeede84ecede46792f47929aa9321873385528",
        },

        build = table.concat({
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            -- xkb-config-root pins the compiled-in default dataset path:
            -- xkeyboard-config ships its rules under share/xkeyboard-config-2
            -- (the X11/xkb compat alias is not shipped — the snap packer's
            -- recursive copy follows stage symlinks, and out-of-stage links
            -- break it).
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "-Denable-tools=false -Denable-x11=false -Denable-wayland=false " ..
                "-Denable-xkbregistry=false -Denable-docs=false " ..
                "-Denable-bash-completion=false " ..
                "-Dxkb-config-root=/usr/share/xkeyboard-config-2",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),
        type = "source",
        requires = { "glibc", "xkeyboard-config" },
        build_deps = { "meson", "ninja", "pkg-config" },

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
    },
}
