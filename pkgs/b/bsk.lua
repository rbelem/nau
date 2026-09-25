-- bsk: BrowserSkill CLI — lets AI agents drive your already logged-in
-- browser via a local daemon + extension bridge.
--
-- Pool port (issue #205) of devbox-global devbox.d/bsk @ cli-v0.3.0
-- (flake pin version = "0.3.0", mirror-don't-bump). Cheap release-fetch
-- tier (dcg.lua pattern): the upstream musl static-pie release tarball
-- is fetched, sha256-pinned, and the binary staged into usr/bin — no
-- pool deps, no build toolchain at all (the ticket's "compiler gate
-- irrelevant" tier; readelf: no PT_INTERP, verified on the pinned
-- asset).
--
-- Checksums cross-verified against the flake's GitHub release API
-- assets[].digest SRI set (base64 → hex), the x86_64 entry additionally
-- download-verified for this recipe:
--   x86_64-unknown-linux-musl  sha256-DrK0Cv+VWJjSHBrfxwo9bITalzCzm2/U1cEkVydNAmA=
--     = 0eb2b40aff955898d21c1adfc70a3d6c84da9730b39b6fd4d5c12457274d0260 (pinned below)
--   aarch64-unknown-linux-musl sha256-YMYfdAroIKCFQl5l6RTqDWjCHOh/cDiimjcv2NY4lts=
--     = 60c61f740ae820a085425e65e914ea0d68c21ce87f7038a29a372fd8d63896db
-- The pool index is amd64-only today; the aarch64 digest is recorded
-- here so a future per-arch source map inherits the full pin set. No
-- recipe-local ecosystem lockfile applies — the release digest set IS
-- the pin (issue #205).
--
-- Post-cutover note: the daemon + extension bridge talks to the host's
-- logged-in browser; this port covers the binary, not a services story
-- for the daemon.

return {
    default = snap {
        name = "bsk",
        version = "0.3.0",
        summary = "BrowserSkill CLI — browser automation bridge for AI agents",
        description = [[
            bsk lets AI agents drive your already logged-in browser via
            a local daemon plus an extension bridge: visit pages, fill
            forms, scrape data, click through flows, and regression-test
            UIs against the browser session you are signed into.
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/Tencent/BrowserSkill/releases/download/cli-v0.3.0/bsk-v0.3.0-x86_64-unknown-linux-musl.tar.gz",
            sha256 = "0eb2b40aff955898d21c1adfc70a3d6c84da9730b39b6fd4d5c12457274d0260",
        },

        -- tar.gz asset with a flat stripped root: just the binary.
        build = table.concat({
            "install -Dm755 bsk $STAGE/usr/bin/bsk",
        }, " && "),

        type = "source",
        -- x86_64-unknown-linux-musl release: static-pie ELF (no
        -- PT_INTERP, no DT_NEEDED) — fully self-contained.
        requires = {},

        apps = {
            bsk = app {
                command = "usr/bin/bsk",
            },
        },
    },
}
