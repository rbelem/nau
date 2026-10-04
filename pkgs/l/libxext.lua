-- libxext: X11 miscellaneous extensions library (libXext.so.6).
--
-- Part of the cua-driver X11 chain: libXi links libXext for the X
-- generic event extension. Deb-seam port at the same pinned snapshot
-- timestamp as the gcc chart (see libxau.lua for the pattern).

return {
    default = snap {
        name = "libxext",
        version = "1.3.4",
        summary = "X11 miscellaneous extensions library (libXext.so.6)",
        description = [[
            Xext: client-side support for the common X11 extensions
            (shared memory pixmaps, shape, double-buffering, the
            generic event extension libXi consumes). Pool payload:
            Debian trixie libxext6, unpacked into the classic
            multiarch lib dir.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        type = "source",
        requires = { "glibc", "libx11" },

        sources = {
            ["libxext6"] = {
                url = "https://snapshot.debian.org/archive/debian/20250815T000000Z/pool/main/libx/libxext/libxext6_1.3.4-1+b3_amd64.deb",
                sha256 = "fc618ec40465e5ce48622606299cb47833efc3fb235ba15543b81f850722f443",
            },
        },

        build = table.concat({
            "mkdir -p $STAGE/usr",
            'dpkg-deb -x "$SRC/libxext6" "$STAGE"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXext.so.6"',
            'test -e "$STAGE/usr/lib/x86_64-linux-gnu/libXext.so.6.4.0"',
        }, " && "),
    },
}
