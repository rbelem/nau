-- meson: build system (pure-Python) for pool meson-based ports.
--
-- Staged, not pip-installed: the release tarball carries the
-- `mesonbuild` package directory, which is copied into the pool
-- python's site-packages and wrapped with a tiny `meson` launcher.
-- A pip install would need setuptools plus network for the build
-- backend, which the hermetic build sandbox does not have.
--
-- The launcher resolves python through PATH: the merged build prefix's
-- bin dir leads the sandbox PATH (issue #33), and meson is a
-- build-time-only tool — consumers list it in `build_deps` together with
-- python (pulled transitively), so bare `python3` is the pool python.
-- site-packages path pins pool python 3.12.
--
-- Requires: glibc (python), python

return {
    default = snap {
        name = "meson",
        version = "1.12.0",
        summary = "Fast and user-friendly build system",
        description = [[
            Meson is a build system designed for speed and usability.
            This pool package stages the mesonbuild Python package and
            a `meson` launcher against the pool python (3.12) so other
            pool packages can consume it as a build dependency
            (build_deps) and drive meson-based builds (glib, dconf,
            libsecret) inside the hermetic sandbox.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/mesonbuild/meson/releases/download/1.12.0/meson-1.12.0.tar.gz",
            sha256 = "88afe0c20e52030218924ac37d0c81c59b4b5f3ae3752c8c6d7470c7d365886c",
        },

        -- The launcher resolves python by bare name (PATH carries the
        -- merged build prefix's bin dir first — issue #33), so no build
        -- prefix marker text ships in the payload. The launcher runs
        -- mesonmain as a module (-m; its __main__ guard calls main) so
        -- no inline python is needed.
        build = table.concat({
            "mkdir -p $STAGE/usr/lib/python3.12/site-packages $STAGE/usr/bin",
            "cp -r $SRC/mesonbuild $STAGE/usr/lib/python3.12/site-packages/",
            "printf '%s\\n' '#!/bin/sh' 'exec python3 -m mesonbuild.mesonmain \"$@\"' > $STAGE/usr/bin/meson",
            "chmod +x $STAGE/usr/bin/meson",
        }, " && "),

        type = "source",
        requires = { "glibc", "python" },
    },
}
