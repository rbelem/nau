-- passt: user-mode networking for namespaces — unprivileged
-- connectivity that plugs a namespace's tap into the host's sockets.
-- pasta (Pack A Subtle Tap Abstraction) is its namespace-connecting
-- mode and the name podman actually invokes for rootless networks;
-- passt and pasta are the SAME binary — this recipe installs it
-- under both names.
--
-- Pool port (issue #215, podman rootless stack — hybrid design
-- prebuilt member). Cheap release-fetch tier (dcg.lua pattern): the
-- upstream builds/ binary is fetched, sha256-pinned, and staged into
-- usr/bin — no pool deps, no build toolchain at all (readelf on the
-- pinned asset: Type EXEC, no PT_INTERP, no DT_NEEDED — fully
-- self-contained).
--
-- Versioning: passt does not tag every build, so the version field
-- is the upstream build stamp g21550f5 (the binary itself reports
-- "pasta 2026_07_28.f8df3f1-16-g21550f5"). URL note: the spec'd
-- https://passt.top/builds/g21550f5/x86_64/pasta 404s — builds/ has
-- no per-stamp directory for this stamp — so the pin targets
-- https://passt.top/builds/latest/x86_64/pasta, which currently
-- serves exactly that g21550f5 build. latest/ is a moving symlink,
-- so this pin is a point-in-time snapshot; a future upstream build
-- WILL break the checksum and force a re-pin (re-verify the
-- --version stamp when that happens).
--
-- Checksum: download-verified only (sha256 of a fresh fetch of the
-- exact URL, re-verified at authoring time; passt.top publishes no
-- checksum asset — bsk.lua carries the same download-only
-- precedent):
--   8b4a289328e2d37aa21a0dfb860197b5993724c6bb2595c3ab6977b2fc20e25c
-- License note: passt/pasta sources carry
-- SPDX-License-Identifier: GPL-2.0-or-later (pasta.c, tcp.c, util.c
-- spot-checked); a historical dual GPL-2.0-or-later AND BSD-2-Clause
-- claim exists in older trees, but the license field pins the
-- -or-later form. The asset lands in $SRC under its URL basename,
-- "pasta" (bare-binary fetch, no tarball to strip).

return {
    default = snap {
        name = "passt",
        version = "g21550f5",
        summary = "User-mode networking for namespaces (passt/pasta)",
        description = [[
            passt provides network connectivity to virtual machines and
            namespaces without any privileges on the host: it adapts a
            tap device to the host's socket API. Its pasta mode plugs
            an existing namespace into the outside world and is the
            default user-mode network backend for rootless podman.
            Installed under both names (passt and pasta) since they
            are one binary with two entry behaviors.
        ]],
        license = "GPL-2.0-or-later",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://passt.top/builds/latest/x86_64/pasta",
            sha256 = "8b4a289328e2d37aa21a0dfb860197b5993724c6bb2595c3ab6977b2fc20e25c",
        },

        -- Bare binary (no tarball): lands in $SRC as "pasta". One
        -- binary, two installed names — podman invokes pasta; the
        -- passt name stays available for VM/qemu use.
        build = table.concat({
            "install -Dm755 pasta $STAGE/usr/bin/pasta",
            "cp $STAGE/usr/bin/pasta $STAGE/usr/bin/passt",
        }, " && "),

        type = "source",
        -- Static ELF (no PT_INTERP, no DT_NEEDED) — fully
        -- self-contained.
        requires = {},

        apps = {
            pasta = app {
                command = "usr/bin/pasta",
            },
            passt = app {
                command = "usr/bin/passt",
            },
        },
    },
}
