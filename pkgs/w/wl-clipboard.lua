-- wl-clipboard: Wayland clipboard utilities (wl-copy, wl-paste).
--
-- Pool port for the wayland tooling lane (issue #23). Builds against
-- the pool wayland stack: libwayland-client is the runtime link,
-- wayland-scanner + wayland-protocols are build-time-only (protocol
-- glue is generated into the binary).
--
-- Requires: glibc, wayland (libwayland-client is linked into the
--           binaries — build deps stay out of the runtime closure)
-- build_deps: meson (pulls python transitively), ninja, pkg-config,
--             wayland, wayland-protocols

return {
    default = snap {
        name = "wl-clipboard",
        version = "2.3.0",
        summary = "Wayland clipboard utilities",
        description = [[
            wl-clipboard provides two command-line Wayland clipboard
            utilities: wl-copy to copy stdin into the Wayland clipboard
            (and primary selection) and wl-paste to print the clipboard
            contents to stdout. Works against any compositor exposing
            the standard Wayland data-control or primary-selection
            protocols.
        ]],
        license = "GPL-3.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/bugaevc/wl-clipboard/archive/refs/tags/v2.3.0.tar.gz",
            sha256 = "b4dc560973f0cd74e02f817ffa2fd44ba645a4f1ea94b7b9614dacc9f895f402",
        },

        build = table.concat({
            -- The PATH export is load-bearing for more than convenience:
            -- wl-clipboard's meson resolves wayland-scanner with a bare
            -- find_program, which only sees the sandbox PATH. The merged
            -- build prefix's wayland-scanner (from the wayland
            -- build_dep) becomes visible through the export.
            -- LD_LIBRARY_PATH: the prefix scanner strips its build-tree
            -- RUNPATH at install (meson rpath cleanup), so its libexpat
            -- dependency needs the prefix lib dirs at exec time.
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export LD_LIBRARY_PATH=\"$SHUTTLE_BUILD_PREFIX/usr/lib:$SHUTTLE_BUILD_PREFIX/usr/lib64\"",
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "wayland" },
        build_deps = { "meson", "ninja", "pkg-config", "wayland", "wayland-protocols" },

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
            ["wl-copy"] = app {
                command = "usr/bin/wl-copy",
            },
            ["wl-paste"] = app {
                command = "usr/bin/wl-paste",
            },
        },
    },
}
