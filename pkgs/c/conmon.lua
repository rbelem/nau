-- conmon: container monitor — the shim podman leaves behind per
-- container: it detaches the runtime from the client session,
-- forwards stdio, and watches the container process.
--
-- Pool port (issue #215, podman rootless stack — hybrid design
-- prebuilt member). Cheap release-fetch tier (dcg.lua pattern): the
-- upstream conmon.amd64 release asset is fetched, sha256-pinned, and
-- staged into usr/bin — no pool deps, no build toolchain at all
-- (readelf on the pinned asset: Type EXEC, no PT_INTERP, no
-- DT_NEEDED — fully self-contained).
--
-- Checksum: download-verified only — upstream publishes no CHECKSUMS
-- asset for the v2.2.1 release (bsk.lua carries the same
-- download-only precedent), so the pin below is the sha256 of a
-- fresh fetch of the exact URL, re-verified at authoring time. The
-- asset lands in $SRC under its URL basename (bare-binary fetch, no
-- tarball to strip).

return {
    default = snap {
        name = "conmon",
        version = "2.2.1",
        summary = "OCI container runtime monitor",
        description = [[
            conmon is the per-container monitor podman and CRI-O spawn
            around the runtime: it daemonizes the container away from
            the calling session, relays stdio, records the exit code,
            and forwards the journal. Without it no podman container
            survives its launching client, so it is a required member
            of the podman rootless stack.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/containers/conmon/releases/download/v2.2.1/conmon.amd64",
            sha256 = "1d97294c14c43d477e0a0826e9cd0f2a2af373ddfafe6f10252e8a3c43f32be6",
        },

        -- Bare binary (no tarball): install it under its URL basename.
        build = table.concat({
            "install -Dm755 conmon.amd64 $STAGE/usr/bin/conmon",
        }, " && "),

        type = "source",
        -- Static ELF (no PT_INTERP, no DT_NEEDED) — fully
        -- self-contained.
        requires = {},

        apps = {
            conmon = app {
                command = "usr/bin/conmon",
            },
        },
    },
}
