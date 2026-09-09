-- pi: minimal terminal coding agent (AI assistant with read, bash,
-- edit, write tools) from earendil-works.
--
-- Cheap-tier flake port (issue #20): the upstream linux-x64 release
-- tarball is fetched, sha256-pinned, and staged as a prebuilt
-- Bun-compile binary. Layout note (mirrors the flake): the binary
-- resolves runtime data (theme, assets, export templates) relative to
-- its own directory, reads its version from a sibling package.json
-- (without it the update nag fires), and CHANGELOG.md feeds the
-- changelog command — so those all ship beside the binary in usr/bin.
-- Never strip/patchelf Bun-compiled binaries: they embed their JS
-- bytecode and corrupt under ELF rewriting.
--
-- Known caveat (farm/run layout): the pod content store keeps files
-- as individual content-addressed blobs and `shuttle run`/the farm
-- exec the lone command blob, so the usr/bin siblings exist in the
-- snap payload but not beside the executed blob. Effect: `pi
-- --version` falls back to 0.0.0 (update nag) and themes use
-- built-in defaults. Same sibling-resolution class as
-- git-credential-manager's libSkiaSharp.so (commit 2e78cb6); waits on
-- a farm/run tree-assembly fix, not a package-side fix.

return {
    default = snap {
        name = "pi",
        version = "0.85.1",
        summary = "Minimal terminal coding agent",
        description = [[
            pi is a minimal terminal coding agent: an AI assistant with
            read, bash, edit, and write tools that works directly in
            your project directory. Ships as a Bun-compiled self-
            contained binary with its theme and export-template data
            resolved relative to the executable.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/earendil-works/pi/releases/download/v0.85.1/pi-linux-x64.tar.gz",
            sha256 = "494e498f47d74d21f40b3386f6a5e921a3d49531a169cab55bbdaca0ea1fe25a",
        },

        -- Single top-level dir (pi/): the source-root finder makes it
        -- cwd, so all paths below are relative to pi/.
        build = table.concat({
            "install -Dm755 pi $STAGE/usr/bin/pi",
            "cp -r theme assets export-html $STAGE/usr/bin/",
            "install -Dm644 package.json $STAGE/usr/bin/package.json",
            "install -Dm644 CHANGELOG.md $STAGE/usr/bin/CHANGELOG.md",
        }, " && "),

        type = "source",
        -- Bun-compile binary: only the glibc family (libc, ld-linux,
        -- libpthread, libdl, libm) in DT_NEEDED.
        requires = { "glibc" },

        apps = {
            pi = app {
                command = "usr/bin/pi",
            },
        },
    },
}
