# Standalone CLI — not a Snapcraft preprocessor

`shoot` is a standalone CLI that generates `.snap` packages directly via `mksquashfs`. It never depends on Snapcraft, nor does it produce intermediate YAML for Snapcraft to consume. This avoids Snapcraft's versioning, plugin system, and CI coupling — at the cost of reimplementing snap metadata assembly (the `meta/snap.yaml` schema, SquashFS packaging, app/plug/slot declarations) from scratch.
