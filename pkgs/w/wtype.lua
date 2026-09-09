-- wtype: Wayland virtual keyboard typing tool.
--
-- Pool port for the wayland tooling lane (issue #23): types Unicode
-- text into the focused Wayland surface through the
-- virtual-keyboard-unstable-v1 protocol. Builds against the pool
-- wayland stack; the protocol XML it compiles is bundled upstream (no
-- wayland-protocols needed). libxkbcommon builds the keymap handed to
-- the compositor; the keymap dataset itself comes from
-- xkeyboard-config (runtime data, resolved by libxkbcommon's
-- compiled-in default rules).
--
-- Runtime note: the binary links libwayland-client/-cursor and
-- libxkbcommon; XKB_CONFIG_ROOT points at the pod-installed
-- xkeyboard-config dataset when running confined.
--
-- Requires: glibc, wayland, xkbcommon (pulls xkeyboard-config
--           transitively), xkeyboard-config
-- build_deps: meson (pulls python transitively), ninja, pkg-config,
--             wayland (scanner + client/cursor libs at build time)

return {
    default = snap {
        name = "wtype",
        version = "0.4",
        summary = "Wayland virtual keyboard typing tool",
        description = [[
            wtype types text on Wayland compositors by creating a
            virtual keyboard device (zwlr_virtual_keyboard_v1) and
            sending key events compiled through xkbcommon. The Wayland
            analog of xdotool type.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/atx/wtype/archive/refs/tags/v0.4.tar.gz",
            sha256 = "da91786d828b6a6e29b884bc510473939eda052658ebef87d7bdeafa6a8746f9",
        },

        build = table.concat({
            -- Same load-bearing PATH export as wl-clipboard: meson
            -- resolves wayland-scanner with a bare find_program against
            -- the sandbox PATH; the merged build prefix's scanner (from
            -- the wayland build_dep) becomes visible through the export.
            -- LD_LIBRARY_PATH covers the scanner's libexpat (its build
            -- RUNPATH is stripped at install). Upstream's VERSION probe
            -- runs git describe only when git is found; in the tarball
            -- (no repo) the command fails soft (meson run_command
            -- check:false) and the tag version is baked instead.
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export LD_LIBRARY_PATH=\"$SHUTTLE_BUILD_PREFIX/usr/lib:$SHUTTLE_BUILD_PREFIX/usr/lib64\"",
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "wayland", "xkbcommon", "xkeyboard-config" },
        build_deps = { "meson", "ninja", "pkg-config", "wayland" },

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
            wtype = app {
                command = "usr/bin/wtype",
            },
        },
    },
}
