-- wayland-protocols: Wayland protocol definitions (data only).
--
-- Pool port for the wayland tooling lane (issue #23): the stable,
-- staging, and unstable protocol XML files consumers compile into
-- protocol glue with wayland-scanner. Pure data: no libraries, no
-- binaries — a build-time-only dependency for wayland tool builds
-- (wl-clipboard reads its pkgdatadir to locate the XML files).
--
-- Requires: nothing (XML + pkg-config metadata only)
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "wayland-protocols",
        version = "1.49",
        summary = "Wayland protocol definitions",
        description = [[
            wayland-protocols contains protocol definitions (stable,
            staging, unstable) that extend the core Wayland protocol.
            The XML files are compiled into client/server glue code by
            wayland-scanner at build time; consumers locate them via
            the wayland-protocols pkg-config pkgdatadir variable.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://gitlab.freedesktop.org/-/project/2891/uploads/7ed597f0cad076a17fe36f8860596f8c/wayland-protocols-1.49.tar.xz",
            sha256 = "ec4c8f74942d6dff7ace8b4ce4764f0ef9ff618a935d974ea77edee2ad240b14",
        },

        build = table.concat({
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            -- -Dtests=false: the tests run protocol XML validation through
            -- wayland-scanner, which they make a REQUIRED dependency (the
            -- data install itself needs nothing) — and this package is
            -- consumed before the wayland package exists in the pool.
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr -Dtests=false",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = {},
        build_deps = { "meson", "ninja", "pkg-config" },
    },
}
