-- libx11: X11 client-side library (libX11.so.6) + locale/XErrorDB data.
--
-- The Xlib runtime for the cua-driver X11 chain (hard DT_NEEDED of the
-- driver binary and libcua_driver_sdk.so). Deb-seam port: BOTH trixie
-- debs land in this one payload — libx11-6 (the library) and libx11-data
-- (usr/share/X11: XErrorDB and the locale/ dataset libX11's compiled-in
-- XLOCALEDIR resolves at runtime; without it every XOpenDisplay with
-- locale set dies on a missing XLC_LOCALE). Same pinned snapshot
-- timestamp as the gcc chart (see libxau.lua for the pattern).
--
-- Ownership: this payload owns usr/share/X11 — no other pool package
-- stages it (xkeyboard-config owns usr/share/xkeyboard-config-2, its
-- own subtree).

return {
    default = snap {
        name = "libx11",
        version = "1.8.12",
        summary = "X11 client-side library (libX11.so.6) with locale and XErrorDB data",
        description = [[
            Xlib: the classic X11 client-side library. Opens the
            display connection (over libxcb), renders text with the
            i18n locale database, and reports protocol errors via
            XErrorDB. Pool payload: Debian trixie libx11-6 +
            libx11-data, unpacked into the classic /usr layout
            (multiarch lib dir + share/X11 data).
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc", "libxcb" },

        sources = {
            ["libx11-6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libx11/libx11-6_1.8.12-1_amd64.deb",
                sha256 = "b5a3fd3bf8c8fd0364bfb9bea00dcba7fc301229bd02dded084632d31f5b0fb3",
            },
            ["libx11-data"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libx11/libx11-data_1.8.12-1_all.deb",
                sha256 = "c54f87069888f80ba4da586da6147d74c7598ccdd8b90906dbc4271fa414c738",
            },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libx11-6" "$STAGE"',
            'dpkg-deb -x "$SRC/libx11-data" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libX11.so.6"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libX11.so.6.4.0"',
            -- Data spine: locale map + error DB, the two files Xlib
            -- reads unconditionally on XOpenDisplay paths.
            'test -e "$STAGE/usr/share/X11/locale/compose.dir"',
            'test -e "$STAGE/usr/share/X11/locale/C/XLC_LOCALE"',
            'test -e "$STAGE/usr/share/X11/XErrorDB"',
        }, " && "),
    },
}
