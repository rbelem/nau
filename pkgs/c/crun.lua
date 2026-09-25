-- crun: OCI container runtime — the process spawner podman hands
-- containers off to (the runc replacement, lighter and C-based).
--
-- Pool port (issue #215, podman rootless stack — hybrid design
-- prebuilt member). Cheap release-fetch tier (dcg.lua pattern): the
-- upstream release binary is fetched, sha256-pinned, and staged into
-- usr/bin — no pool deps, no build toolchain at all (the "compiler
-- gate irrelevant" tier; readelf on the pinned asset: Type EXEC, no
-- PT_INTERP, no DT_NEEDED — fully self-contained).
--
-- The disable-systemd variant is pinned deliberately: sd_notify
-- readiness handoff is meaningless inside a user pod, and dropping
-- it keeps the binary off libsystemd entirely.
--
-- Checksum cross-verified against the upstream CHECKSUMS release
-- asset (downloaded, line grepped — exact match):
--   e7b059390e27d0f283e1debbe89d9c5847870f3d8325f31ccd954533fdd6ea78
--     crun-1.30.1-linux-amd64-disable-systemd (pinned below)
-- The asset lands in $SRC under its URL basename (bare-binary fetch,
-- no tarball to strip).

return {
    default = snap {
        name = "crun",
        version = "1.30.1",
        summary = "Lightweight OCI container runtime",
        description = [[
            crun is a fast, low-memory OCI container runtime written in
            C: it creates and runs the container processes podman asks
            for (namespaces, cgroups, pivot_root). This is the
            disable-systemd build — inside a user pod there is no
            systemd to notify, so the variant is strictly smaller with
            no functional loss for the podman rootless stack.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/containers/crun/releases/download/1.30.1/crun-1.30.1-linux-amd64-disable-systemd",
            sha256 = "e7b059390e27d0f283e1debbe89d9c5847870f3d8325f31ccd954533fdd6ea78",
        },

        -- Bare binary (no tarball): install it under its URL basename.
        build = table.concat({
            "install -Dm755 crun-1.30.1-linux-amd64-disable-systemd $STAGE/usr/bin/crun",
        }, " && "),

        type = "source",
        -- Static ELF (no PT_INTERP, no DT_NEEDED) — fully
        -- self-contained.
        requires = {},

        apps = {
            crun = app {
                command = "usr/bin/crun",
            },
        },
    },
}
