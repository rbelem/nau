-- hermes-desktop: the Hermes Agent desktop app (Electron).
--
-- Upstream publishes no Linux desktop artifact (the `hermes desktop`
-- subcommand is source-checkout-only; the product page ships macOS/
-- Windows installers only), so this package consumes a VENDORED build:
-- the electron-builder `linux-unpacked` tree assembled from upstream's
-- own npm-workspace pipeline at tag v2026.8.31 (app 0.17.0, electron
-- 40.10.2, node-pty rebuilt against the Electron ABI), attached to a
-- rbelem/shuttle release and pinned here by sha256. The self-contained
-- tree carries its own electron runtime — the build just stages it and
-- drops in a launcher. The launcher wires HERMES_DESKTOP_HERMES to the
-- sibling pod `hermes` (the farm exposes them side by side — the same
-- backend seam upstream's nix wrapper uses, resolved farm-relative so
-- the GUI always drives the pod's pinned agent), and reproduces
-- upstream's Linux sandbox fallback: with apparmor's unprivileged-userns
-- restriction and no working userns, Electron runs --no-sandbox.

return {
    default = snap {
        name = "hermes-desktop",
        version = "0.17.0",
        summary = "The Hermes Agent desktop app — memory, skills, agents, outside the terminal",
        description = [[
            Native desktop UI for the Hermes agent: chat, projects,
            artifacts, terminals, git review. Shares config, keys,
            sessions, and skills with the pod's `hermes` CLI backend.
            Vendored linux-x64 electron build (see header).
        ]],
        license = "MIT",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/rbelem/shuttle/releases/download/hermes-desktop-v0.17.0/hermes-desktop-0.17.0-linux-x64.tar.gz",
            sha256 = "b4a9206bc0d8ad801197cee3e8b57e82f47eb30078b28c0d93a02e8af5e96c25",
        },

        build = table.concat({
            "mkdir -p $STAGE/usr/bin $STAGE/usr/lib/hermes-desktop",
            "cp -r $SRC/. $STAGE/usr/lib/hermes-desktop/",
            -- The launcher (one printf per shuttle's sandbox tool
            -- preflight, which reads heredoc bodies as command words).
            -- Resolves the pod root from its own store blob (the farm
            -- links flat file blobs — the whichllm tree-wrapper trick)
            -- and wires HERMES_DESKTOP_HERMES to the sibling pod
            -- `hermes` through the stable `current` farm link (the
            -- same backend seam upstream's nix wrapper uses). Mirrors
            -- upstream's Linux sandbox fallback: with apparmor's
            -- unprivileged-userns restriction and no working userns,
            -- Electron runs --no-sandbox.
            "printf '%s\\n' "
                .. "'#!/usr/bin/env bash' "
                .. "'set -e' "
                .. "'SCRIPT=\"$(readlink -f \"$0\")\"' "
                .. "'PODROOT=\"$(dirname \"$(dirname \"$(dirname \"$SCRIPT\")\")\")\"' "
                .. "'export HERMES_DESKTOP_HERMES=\"${HERMES_DESKTOP_HERMES:-$PODROOT/current/hermes}\"' "
                .. "'export ELECTRON_IS_DEV=0' "
                .. "'if [ ! -x \"$HERMES_DESKTOP_HERMES\" ]; then' "
                .. "'    echo \"hermes-desktop: pod backend not found at $HERMES_DESKTOP_HERMES\" >&2' "
                .. "'    exit 1' "
                .. "'fi' "
                .. "'APP=\"$PODROOT/active/extensions/hermes-desktop/usr/usr/lib/hermes-desktop/Hermes\"' "
                .. "'LIBS=\"$(dirname \"$APP\")/libs\"' "
                .. "'export LD_LIBRARY_PATH=\"$LIBS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"' "
                .. "'if [ \"$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)\" = \"1\" ] && ! unshare --user --map-root-user true 2>/dev/null; then' "
                .. "'    exec \"$APP\" --no-sandbox \"$@\"' "
                .. "'fi' "
                .. "'exec \"$APP\" \"$@\"' "
                .. "> $STAGE/usr/bin/hermes-desktop",
            "chmod +x $STAGE/usr/bin/hermes-desktop",
        }, " && "),

        type = "source",
        requires = { "glibc" },

        apps = {
            ["hermes-desktop"] = app {
                command = "usr/bin/hermes-desktop",
            },
        },
    },
}
