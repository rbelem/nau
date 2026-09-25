-- fuse-overlayfs: FUSE implementation of the overlay filesystem —
-- the storage driver rootless podman falls back to when the kernel
-- cannot serve overlayfs inside a user namespace.
--
-- Pool port (issue #215, podman rootless stack — hybrid design
-- prebuilt member). Cheap release-fetch tier (dcg.lua pattern): the
-- upstream release binary is fetched, sha256-pinned, and staged into
-- usr/bin — no pool deps, no build toolchain at all (readelf on the
-- pinned asset: Type EXEC, no PT_INTERP, no DT_NEEDED — fully
-- self-contained).
--
-- Checksum cross-verified against the upstream SHA256SUMS release
-- asset (downloaded, line grepped — exact match):
--   56b0ae0aeb8abb308b068af2f137ed8d1bd239f4f27e21672ff0def861eea1e8
--     fuse-overlayfs-x86_64 (pinned below)
-- License note: the repo COPYING is the bare GPLv2 text, but
-- src/main.rs carries SPDX-License-Identifier: GPL-2.0-or-later —
-- the -or-later form is what upstream ships (the spec's GPL-3.0
-- hedge did not survive the LICENSE check). The asset lands in $SRC
-- under its URL basename (bare-binary fetch, no tarball to strip).

return {
    default = snap {
        name = "fuse-overlayfs",
        version = "1.18",
        summary = "FUSE overlay filesystem for rootless containers",
        description = [[
            fuse-overlayfs provides an overlay filesystem in userspace
            via FUSE: layered mounts with upper- and lowerdirs just
            like kernel overlayfs. Rootless podman uses it as the
            storage driver when overlayfs itself cannot be mounted in
            a user namespace, so image layers still stack without
            root. Requires FUSE available at run time.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/containers/fuse-overlayfs/releases/download/v1.18/fuse-overlayfs-x86_64",
            sha256 = "56b0ae0aeb8abb308b068af2f137ed8d1bd239f4f27e21672ff0def861eea1e8",
        },

        -- Bare binary (no tarball): install it under its URL basename.
        build = table.concat({
            "install -Dm755 fuse-overlayfs-x86_64 $STAGE/usr/bin/fuse-overlayfs",
        }, " && "),

        type = "source",
        -- Static ELF (no PT_INTERP, no DT_NEEDED) — fully
        -- self-contained.
        requires = {},

        apps = {
            ["fuse-overlayfs"] = app {
                command = "usr/bin/fuse-overlayfs",
            },
        },
    },
}
