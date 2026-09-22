-- blesh: bash line editor (ble.sh)
--
-- Ported from devbox-global's devbox.d/blesh flake. The nix build was a
-- dontBuild relayout of the upstream release tarball into share/blesh
-- plus a `blesh-share` bin script printing the share path, so the shell
-- rc keeps working verbatim: `source -- $(blesh-share)/ble.sh`.
--
-- Same shape here, minus the nix store path. The release tarball is
-- pinned (v0.4.0-devel3 — the version the flake's metadata already
-- claims) instead of the `nightly` tag, which upstream rebuilds
-- continuously and would rot the pinned sha256 on the next cold build.
-- The `_package.bash` marker keeps ble.sh's self-update hook behaving
-- exactly as under the flake (package-managed: updates refused).
--
-- `blesh-share` resolves its own store blob (the farm links the payload
-- file directly) with the same three-dirname derivation the #13
-- interpreter tree wrappers use, then prints the bundled share dir.
-- No requires: ble.sh is pure bash + coreutils at runtime and sources
-- through the user's shell, not through a farm exec.
--
-- Requires: (none)
-- build_deps: (none)

return {
    default = snap {
        name = "blesh",
        version = "0.4.0-devel3",
        summary = "Bash Line Editor — release build",
        description = [[
            ble.sh is a line editor for bash: enhanced completion,
            syntax highlighting, vi/emacs modes, autosuggestion. Ships
            the share tree in the package payload; `blesh-share` prints
            its path for `source -- $(blesh-share)/ble.sh`.
        ]],
        license = "BSD-3-Clause",
        grade = "stable",
        confinement = "strict",
        architectures = { "amd64" },

        source = {
            url = "https://github.com/akinomyoga/ble.sh/releases/download/v0.4.0-devel3/ble-0.4.0-devel3.tar.xz",
            sha256 = "c8612ee612bc6b10dbfd6e85c6cbdfd7caf152a12d1f9de22ea0a9d735b3080c",
        },

        -- Tarball root is ble-0.4.0-devel3/; $SRC points inside it.
        build = table.concat({
            "mkdir -p $STAGE/usr/share/blesh/lib $STAGE/usr/bin",
            "cp -r . $STAGE/usr/share/blesh/",
            "cat > $STAGE/usr/share/blesh/lib/_package.bash <<'EOF'",
            "_ble_base_package_type=nix",
            "",
            "function ble/base/package:nix/update {",
            "  echo 'ble.sh is installed by the shuttle pod. Update the pool package.' >&2",
            "  return 1",
            "}",
            "EOF",
            "cat > $STAGE/usr/bin/blesh-share <<'EOF'",
            "#!/bin/sh",
            "# The farm symlinks this app at its content-addressed store",
            "# blob, so the share tree is reached through the pod root:",
            "# dirname x3 of the blob path is <podroot> (the same",
            "# derivation the pod's python3 wrapper uses), and the",
            "# generation's extension tree mirrors the payload layout.",
            "# `active` flips on rollback, so the printed path always",
            "# names the running generation.",
            'SCRIPT="$(readlink -f "$0")"',
            'PODROOT="$(dirname "$(dirname "$(dirname "$SCRIPT")")")"',
            'echo "$PODROOT/active/extensions/blesh/usr/usr/share/blesh"',
            "EOF",
            "chmod +x $STAGE/usr/bin/blesh-share",
        }, "\n"),

        type = "source",

        apps = {
            ["blesh-share"] = app {
                command = "usr/bin/blesh-share",
            },
        },
    },
}
