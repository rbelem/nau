-- libxcb: X protocol C binding (libxcb.so.1).
--
-- Middle of the cua-driver X11 chain: libX11 links libxcb for the
-- wire protocol, and libxcb links libxau/libxdmcp. Deb-seam port at
-- the same pinned snapshot timestamp as the gcc chart (see libxau.lua
-- for the pattern).

return {
    default = snap {
        name = "libxcb",
        version = "1.17.0",
        summary = "X protocol C binding (libxcb.so.1)",
        description = [[
            libxcb: the X protocol C-language binding. Replaces Xlib
            with a thin, thread-safe layer over the X wire protocol;
            libX11's transport on modern systems. Pool payload: Debian
            trixie libxcb1, unpacked into the classic multiarch lib
            dir.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc", "libxau", "libxdmcp" },

        sources = {
            ["libxcb1"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libxcb/libxcb1_1.17.0-2+b1_amd64.deb",
                sha256 = "5c222a72d11b866447da31693254f738430726e3e065a384e82687b2fd2f978b",
            },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libxcb1" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libxcb.so.1"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libxcb.so.1.1.0"',
        }, " && "),
    },
}
