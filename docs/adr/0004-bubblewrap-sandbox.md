# Bubblewrap sandbox for source builds

Source builds (`type = "source"`) execute inside a bubblewrap sandbox by default: `--unshare-user --unshare-pid --unshare-ipc --unshare-net`, with the build directory mounted at `/build` and system paths (`/usr`, `/lib`, `/nix`) mounted read-only. This isolates build processes from the host filesystem without requiring Docker or root. Falls back to direct execution when `bwrap` is unavailable. The alternative (Docker/podman) adds a container runtime dependency; the alternative (no sandbox) risks host contamination from build scripts.
