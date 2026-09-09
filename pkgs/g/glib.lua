-- glib: GLib core libraries (glib, gobject, gio, gmodule, gthread).
--
-- Pool base for meson-based GNOME ports (dconf, libsecret, and any
-- GSettings consumer). Meson build driven entirely by pool tooling
-- through the merged build prefix (ADR-0018 Decision 2): meson, ninja
-- and pkg-config are build-time-only build_deps; libffi (GObject
-- closures), pcre2 (GRegex) and zlib (gresource/gzlib) are link-time
-- AND runtime requires.
--
-- The build prepends the prefix bin dir to PATH so the pool
-- meson/ninja/pkg-config/python are the ones invoked, and pkg-config
-- resolves pool .pc files through the PKG_CONFIG_PATH /
-- PKG_CONFIG_SYSROOT_DIR the sandbox already exports.
--
-- Probes disabled for hermeticity (no pool package, auto-detection
-- would reach past the sandbox or add payload weight): selinux,
-- libmount, sysprof, nls (xgettext), libelf, introspection
-- (gobject-introspection), man pages, documentation, tests, dtrace,
-- systemtap, glib_debug. xattr stays on (pool glibc headers carry
-- sys/xattr.h).
--
-- Requires: glibc, libffi, pcre2, zlib
-- build_deps: meson (pulls python transitively), ninja, pkg-config

return {
    default = snap {
        name = "glib",
        version = "2.88.3",
        summary = "GLib core libraries (glib, gobject, gio)",
        description = [[
            GLib is the low-level core library that forms the basis of
            GTK and GNOME: the glib utility layer (event loop, data
            structures, GRegex), the gobject type system, and the gio
            I/O layer. This pool package builds the libraries plus the
            glib-compile-schemas / glib-compile-resources /
            gdbus-codegen tooling that meson-based pool ports need at
            build time.
        ]],
        license = "LGPL-2.1-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://download.gnome.org/sources/glib/2.88/glib-2.88.3.tar.xz",
            sha256 = "ab24d24e698dfa1e408b7bcdb508f4aafc906185a8b8ce72fdf79bbbdc9b383b",
        },

        build = table.concat({
            -- Pool meson/ninja/pkg-config live in the merged build
            -- prefix; the sandbox does not extend PATH to it, and the
            -- sandbox tool preflight only accepts PATH-resolved bare
            -- command words, so every tool is invoked by its explicit
            -- $SHUTTLE_BUILD_PREFIX path.
            "export PATH=\"$SHUTTLE_BUILD_PREFIX/usr/bin:$PATH\"",
            -- The sandbox does not bind /etc, so getpwuid cannot resolve
            -- the build user and HOME is unset — cmake's dependency
            -- lookups (meson's cmake method, used for the optional
            -- bash-completion probe) abort with "Could not determine
            -- home directory". /tmp need not exist; it is only a string
            -- for ~ expansion.
            "export HOME=/tmp",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/meson\" setup build --prefix=/usr " ..
                "-Dselinux=disabled -Dlibmount=disabled -Dsysprof=disabled " ..
                "-Dnls=disabled -Dman-pages=disabled -Ddocumentation=false " ..
                "-Dtests=false -Dinstalled_tests=false -Dlibelf=disabled " ..
                "-Dintrospection=disabled -Ddtrace=disabled -Dsystemtap=disabled " ..
                "-Dglib_debug=disabled",
            "\"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build",
            "DESTDIR=$STAGE \"$SHUTTLE_BUILD_PREFIX/usr/bin/ninja\" -C build install",
        }, " && "),

        type = "source",
        requires = { "glibc", "libffi", "pcre2", "zlib" },
        build_deps = { "meson", "ninja", "pkg-config" },

        -- Interim leak-scan escape (ADR-0018 Decision 3, issue #22/#19)
        -- until the nix gcc wrapper stops baking the merged build prefix
        -- into produced binaries: the ELFs that link libffi carry
        -- RUNPATH=/shuttle-build-prefix/usr/lib64 (libffi's
        -- toolexeclibdir ${libdir}/../lib64 — that path does not exist at
        -- runtime). Silenced here, visibly logged by the build's leak
        -- scan, pending the RUNPATH repair (issue #22's portability
        -- follow-up). Same rationale as htop/tmux/tig.
        leaks_ok = { "/shuttle-build-prefix/usr/lib64" },
    },
}
