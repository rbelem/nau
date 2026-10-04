-- libxi: X11 XInput extension library (libXi.so.6).
--
-- Top of the cua-driver X11 chain: the driver binary and its SDK
-- library hard-link libXi for input-device events (pointer/keyboard
-- synthesis and state). Deb-seam port at the same pinned snapshot
-- timestamp as the gcc chart (see libxau.lua for the pattern).

return {
    default = snap {
        name = "libxi",
        version = "1.8.2",
        summary = "X11 XInput extension library (libXi.so.6)",
        description = [[
            Xi: client-side support for the X11 XInput extension —
            extended input device queries and event selection for
            pointers, keyboards, and touch. Pool payload: Debian
            trixie libxi6, unpacked into the classic multiarch lib
            dir.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc", "libx11", "libxext" },

        sources = {
            ["libxi6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libxi/libxi6_1.8.2-1_amd64.deb",
                sha256 = "093d0903f35bb7a9f6815180ee040e6951fecf9b66c128cd72f064710210606e",
            },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libxi6" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXi.so.6"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXi.so.6.1.0"',
        }, " && "),
    },
}
