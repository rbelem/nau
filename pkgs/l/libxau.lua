-- libxau: X authorization library (libXau.so.6) — Debian trixie payload.
--
-- Bottom of the cua-driver X11 chain: libxcb links libXau for Xauth
-- cookie handling. Deb-seam port (the gcc-chart pattern): the trixie
-- binary package is fetched, sha256-pinned against the trixie Packages
-- index at one snapshot timestamp, and data.tar merges into the stage
-- via busybox dpkg-deb -x. Same timestamp as the gcc chart
-- (20250815T000000Z — snapshot URLs immutable, trixie/stable state).

return {
    default = snap {
        name = "libxau",
        version = "1.0.11",
        summary = "X11 authorisation library (libXau.so.6)",
        description = [[
            Xau: the X authority management library. Manages X11
            authorization records (Xauthority cookies) on behalf of
            libxcb and Xlib clients. Pool payload: Debian trixie
            libxau6, unpacked into the classic multiarch lib dir.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc" },

        sources = {
            ["libxau6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libxau/libxau6_1.0.11-1_amd64.deb",
                sha256 = "689a9f0e0ba3e2c65431f864871e303ee904de69dd28abfc462663fae030227f",
            },
        },

        -- A .deb is an ar archive wrapping data.tar; busybox dpkg-deb
        -- -x (the sandbox's deb unpacker, gcc-chart probe) extracts the
        -- dpkg layout rooted at ./usr with modes and symlinks intact.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libxau6" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXau.so.6"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXau.so.6.0.0"',
        }, " && "),
    },
}
