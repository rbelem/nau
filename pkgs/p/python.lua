-- Python: CPython 3.14 interpreter (python-build-standalone).
--
-- Ported from the devbox global profile's python3 as a shuttle source
-- package. Uses Astral's python-build-standalone install_only archive —
-- the same prebuilt CPython distribution uv installs — so the build only
-- relayouts the tarball into $STAGE. The staged bin/ tree carries the
-- stdlib (lib/python3.14/), so the interpreter app gets the tree wrapper:
-- CPython resolves its stdlib relative to its own path and a flat store
-- blob would strand it.

return {
    default = snap {
        name = "python",
        version = "3.14.7",
        summary = "CPython 3.14 interpreter (python-build-standalone)",
        description = [[
            CPython, the reference Python interpreter, from Astral's
            python-build-standalone prebuilt distribution (the same
            artifact uv installs). Interpreter-based pod packages
            (e.g. whichllm) exec it at runtime via their
            `interpreter = "python3"` app wrappers; wheels staged into
            lib/python3.14/site-packages are handed to those apps
            through PYTHONPATH by their wrappers.
        ]],
        license = "PSF-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/astral-sh/python-build-standalone/releases/download/20260901/cpython-3.14.7%2B20260901-x86_64-unknown-linux-gnu-install_only.tar.gz",
            sha256 = "0ab3305457051cd3e7c031857e005f1bda17c218a1990567dacaaac6dd1d14f0",
        },

        -- The tarball root is python/ and $SRC points at it; relayout
        -- bin/lib/include/share into the /usr prefix.
        build = table.concat({
            "mkdir -p $STAGE/usr",
            "cp -r bin lib include share $STAGE/usr/",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            python3 = app {
                command = "usr/bin/python3",
            },
        },
    },
}
