-- uv: an extremely fast Python package and project manager, written
-- in Rust (pip/pyenv/pipx/virtualenv replacement from Astral).
--
-- Ported from the devbox global profile as a prebuilt release binary:
-- the upstream x86_64 musl tarball is fetched, sha256-pinned, and the
-- uv/uvx binaries are staged directly into usr/bin (no Rust toolchain
-- needed in the build sandbox). The build runs at the tarball's
-- STRIPPED root (find_source_root): paths are relative to it.

return {
    default = snap {
        name = "uv",
        version = "0.12.3",
        summary = "Fast Python package and project manager",
        description = [[
            uv is an extremely fast Python package installer, resolver,
            and virtual environment manager written in Rust. It is a
            drop-in replacement for common pip/pip-tools/pipx/poetry/
            virtualenv workflows, with a global cache and lockfile
            support (uv lock / uv sync). Includes uvx for running tools
            in ephemeral environments.
        ]],
        license = "MIT OR Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/astral-sh/uv/releases/download/0.12.3/uv-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "0643b9fb8c9fb27458e709ce6ff939695013c41975ff7b02d3f3b138d8d4bdb3",
        },

        build = table.concat({
            "install -Dm755 uv $STAGE/usr/bin/uv",
            "install -Dm755 uvx $STAGE/usr/bin/uvx",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            uv = app {
                command = "usr/bin/uv",
            },
            uvx = app {
                command = "usr/bin/uvx",
            },
        },
    },
}
