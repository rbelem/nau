-- libxdmcp: X Display Manager Control Protocol library (libXdmcp.so.6).
--
-- Bottom of the cua-driver X11 chain beside libxau: libxcb links both
-- for XDMCP and Xauth support. Deb-seam port at the same pinned
-- snapshot timestamp as the gcc chart (see libxau.lua for the pattern).

return {
    default = snap {
        name = "libxdmcp",
        version = "1.1.5",
        summary = "X11 Display Manager Control Protocol library (libXdmcp.so.6)",
        description = [[
            Xdmcp: the X Display Manager Control Protocol library.
            Handles display-manager authentication handshakes for X11
            sessions. Pool payload: Debian trixie libxdmcp6, unpacked
            into the classic multiarch lib dir.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc" },

        sources = {
            ["libxdmcp6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libxdmcp/libxdmcp6_1.1.5-1_amd64.deb",
                sha256 = "0740dc760916b2008b45417a42a8fd7dd5de370fb57d31373f15034cda8acf0b",
            },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libxdmcp6" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXdmcp.so.6"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXdmcp.so.6.0.0"',
        }, " && "),
    },
}
