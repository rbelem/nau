-- dbus: D-Bus message bus daemon, libdbus, and the dev metadata
-- (dbus-1.pc) meson-based ports like dconf resolve service dirs from.
--
-- Ported to the official release tarball: dbus 1.16 removed the
-- autotools build system, so a GitLab archive (raw repo snapshot) has
-- no ./configure — the release tarball ships meson.build. Meson build
-- driven by pool tooling through the merged build prefix (ADR-0018
-- Decision 2); expat is libdbus's XML backend and the only runtime
-- library dependency.
--
-- Probes disabled for hermeticity: selinux, apparmor, systemd,
-- modular_tests (would want glib in the build prefix), and the four
-- doc generators (xsltproc/doxygen/ducktype/qt-help). inotify stays
-- on (kernel syscalls, no package needed).
--
-- Requires: glibc, expat
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "dbus",
        version = "1.16.2",
        summary = "D-Bus message bus daemon and utilities",
        description = [[
            D-Bus is a message bus system, a simple way for applications to
            talk to one another. In addition to interprocess communication,
            D-Bus helps coordinate process lifecycle and provides a uniform
            mechanism for launching services. Built with pool meson and
            expat; consumers such as dconf only need its dbus-1.pc metadata
            at build time.
        ]],
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },
        type = "source",
        requires = { "glibc", "expat" },
        build_deps = { "meson", "ninja", "pkg-config" },
        source = {
            url = "https://dbus.freedesktop.org/releases/dbus/dbus-1.16.2.tar.xz",
            sha256 = "0ba2a1a4b16afe7bceb2c07e9ce99a8c2c3508e5dec290dbb643384bd6beb7e2",
        },
        build = table.concat({
            -- Pool meson/ninja/pkg-config live in the merged build
            -- prefix; the sandbox does not extend PATH to it, and the
            -- sandbox tool preflight only accepts PATH-resolved bare
            -- command words, so every tool is invoked by its explicit
            -- $SHUTTLE_BUILD_PREFIX path. HOME keeps cmake-method
            -- dependency lookups alive (no /etc in the sandbox, so no
            -- passwd entry).
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "--sysconfdir=/etc --localstatedir=/var " ..
                "-Dselinux=disabled -Dapparmor=disabled -Dsystemd=disabled " ..
                "-Dmodular_tests=disabled " ..
                "-Dxml_docs=disabled -Ddoxygen_docs=disabled " ..
                "-Dducktype_docs=disabled -Dqt_help=disabled",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22/#19)
        -- until the nix gcc wrapper stops baking the merged build prefix
        -- into produced binaries: produced ELFs carry
        -- RUNPATH=/shuttle-build-prefix/usr/lib (that path does not exist
        -- at runtime). Silenced here, visibly logged by the build's leak
        -- scan, pending the RUNPATH repair. Same rationale as htop.
        leaks_ok = { "/shuttle-build-prefix/usr/lib" },
    },
}
