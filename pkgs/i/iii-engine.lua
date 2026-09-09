-- iii-engine: runtime for agentmemory and iii-based apps
-- (iii-hq/iii) — function triggers, state management, streams, and
-- WebSocket-based coordination.
--
-- Medium-tier flake port survey (issue #25): the flake is a prebuilt
-- release fetch, not a source build — ported as a release-fetch
-- package in the #20 pattern (the cheap-tier batch missed this one).
-- The upstream x86_64-unknown-linux-gnu release tarball is fetched,
-- sha256-pinned (digest cross-checked against both the iii-engine and
-- agentmemory flake pins — same artifact), and the `iii` binary is
-- staged into usr/bin.
--
-- Runtime deps (ldd): the glibc family plus libgcc_s.so.1 — the gnu
-- target triple's usual unwinder companion. NOTE: pool libgcc lands
-- with the #34 lane — merge order libgcc → iii-engine, or resolution
-- of this package fails on a tree without it (same pattern as
-- rust.lua's libgcc note).

return {
    default = snap {
        name = "iii-engine",
        version = "0.11.2",
        summary = "iii runtime — function triggers, state, streams, WebSockets",
        description = [[
            iii-engine is the runtime that powers agentmemory and other
            iii-based applications: function triggers, state
            management, streams, and WebSocket-based coordination.
            Ships as the self-contained upstream release binary.
        ]],
        license = "Apache-2.0",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/iii-hq/iii/releases/download/iii/v0.11.2/iii-x86_64-unknown-linux-gnu.tar.gz",
            sha256 = "9c83c47788b4ef4beeb65dd9bf37e94f993770cd3db874464c3ce1cdc92352cd",
        },

        -- Flat tarball root: the `iii` binary at the source root.
        build = table.concat({
            "install -Dm755 iii $STAGE/usr/bin/iii",
        }, " && "),

        type = "source",
        requires = { "glibc", "libgcc" },

        apps = {
            iii = app {
                command = "usr/bin/iii",
            },
        },
    },
}
