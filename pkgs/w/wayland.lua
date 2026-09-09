-- wayland: protocol library for compositors and their clients.
--
-- Pool port for the wayland tooling lane (issue #23): libwayland
-- (client/server/cursor), the wayland-scanner protocol compiler, and
-- the wayland.xml core protocol. Consumers (wl-clipboard, wtype) list
-- this package in build_deps (scanner + dev headers are build-time)
-- and in requires (libwayland-client is linked into their binaries).
--
-- Probes disabled for hermeticity: tests (libxml2/C++), the DTD
-- validation (libxml2), and documentation (graphviz/docbook). expat
-- feeds the scanner; libffi feeds the core wire protocol.
--
-- Requires: glibc, expat, libffi
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "wayland",
        version = "1.26.0",
        summary = "Wayland protocol library and scanner",
        description = [[
            Wayland is a protocol for a compositor to communicate with
            its clients. This package ships the core protocol libraries
            (libwayland-client, libwayland-server, libwayland-cursor),
            the wayland-scanner protocol compiler, and the core
            wayland.xml protocol definition. Client tools link
            libwayland-client (pkg-config wayland-client) and use the
            scanner with protocol XML definitions at build time.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://gitlab.freedesktop.org/-/project/121/uploads/5f5d2e19a230e8b8250d9a7c2f280846/wayland-1.26.0.tar.xz",
            sha256 = "64176eaa46e4969903e286f8e5ef8331affc17fdf03ac9b58381d2b23162b7a3",
        },

        build = table.concat({
            -- Pool meson/ninja/pkg-config live in the merged build
            -- prefix; the sandbox does not extend PATH to it, so every
            -- tool is invoked by its explicit $SHUTTLE_BUILD_PREFIX
            -- path. The PATH export additionally puts the prefix's
            -- python3 on it for wayland's embed.py codegen helper and
            -- keeps HOME alive for meson's method lookups (no /etc in
            -- the sandbox, so no passwd entry).
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "-Dtests=false -Ddocumentation=false -Ddtd_validation=false",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "expat", "libffi" },
        build_deps = { "meson", "ninja", "pkg-config" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22): the
        -- nix gcc wrapper bakes the merged build prefix into produced
        -- ELFs' RUNPATH — observed as both usr/lib and usr/lib64 forms
        -- (paths that do not exist at runtime). Silenced here, visibly
        -- logged by the leak scan, pending the RUNPATH repair. Same
        -- rationale as htop/libsecret.
        leaks_ok = {
            "/shuttle-build-prefix/usr/lib",
            "/shuttle-build-prefix/usr/lib64",
        },
    },
}
